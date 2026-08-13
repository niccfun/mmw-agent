// Package guardbootstrap installs the closed Agent Guard during the first
// upgrade from a legacy Agent release. Later upgrades replace both binaries in
// one transaction; this bootstrap is the compatibility path for hosts whose
// old self-updater only knew about mmw-agent.
package guardbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mmw-agent/internal/selfupdate"
)

const (
	defaultSocket    = "/run/mmwx-guard-agent/guard.sock"
	defaultBinary    = "/usr/local/bin/mmwx-guardd"
	defaultStateDir  = "/var/lib/mmwx-guard"
	defaultManifest  = "/usr/local/share/mmwx-guard/agent.manifest"
	defaultSystemd   = "/etc/systemd/system"
	guardServiceName = "mmwx-guard-agent.service"
)

type Config struct {
	SocketPath    string
	BinaryPath    string
	StateDir      string
	ManifestPath  string
	SystemdDir    string
	DownloadBases []string
	HTTPClient    *http.Client
	Verify        func(string, string) error
	RunSystemctl  func(context.Context, ...string) error
	WaitForSocket func(context.Context, string) error
}

// EnsureDefault makes a signed Guard available without replacing its state
// directory. It is intentionally only used by release builds that require the
// Guard and are not running in Docker (the Docker image already bundles it).
func EnsureDefault(ctx context.Context) error {
	cfg := Config{
		SocketPath:    defaultSocket,
		BinaryPath:    defaultBinary,
		StateDir:      defaultStateDir,
		ManifestPath:  defaultManifest,
		SystemdDir:    defaultSystemd,
		DownloadBases: defaultDownloadBases(),
		HTTPClient:    &http.Client{Timeout: 3 * time.Minute},
		Verify:        selfupdate.VerifyFile,
		RunSystemctl: func(ctx context.Context, args ...string) error {
			cmd := exec.CommandContext(ctx, "systemctl", args...)
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
			}
			return nil
		},
		WaitForSocket: waitForSocket,
	}
	return Ensure(ctx, cfg)
}

func Ensure(ctx context.Context, cfg Config) error {
	if socketReady(cfg.SocketPath) {
		return nil
	}
	// systemd ordering waits for the Guard process to start, not for its Unix
	// socket to be bound. Avoid an unnecessary download/restart on every normal
	// boot when the existing Guard is only a few milliseconds behind the Agent.
	if _, err := os.Stat(cfg.BinaryPath); err == nil && cfg.WaitForSocket != nil {
		readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = cfg.WaitForSocket(readyCtx, cfg.SocketPath)
		cancel()
		if err == nil {
			return nil
		}
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("Agent Guard does not support %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if cfg.BinaryPath == defaultBinary && os.Geteuid() != 0 {
		return errors.New("Agent Guard bootstrap requires root")
	}
	if cfg.SystemdDir == defaultSystemd {
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			return errors.New("Agent Guard bootstrap requires systemd; reinstall the Agent on this host")
		}
	}
	if cfg.Verify == nil || cfg.RunSystemctl == nil || cfg.WaitForSocket == nil || cfg.HTTPClient == nil {
		return errors.New("incomplete Agent Guard bootstrap configuration")
	}

	name := "mmwx-guardd-linux-" + runtime.GOARCH
	tmpDir, err := os.MkdirTemp("", "mmwx-guard-bootstrap-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	binTmp := filepath.Join(tmpDir, name)
	sigTmp := binTmp + ".sig"
	manifestTmp := filepath.Join(tmpDir, "agent.manifest")
	if err := downloadSignedPair(ctx, cfg.HTTPClient, cfg.DownloadBases, name, binTmp, sigTmp, cfg.Verify); err != nil {
		return err
	}
	if err := downloadFromBases(ctx, cfg.HTTPClient, cfg.DownloadBases, "mmw-agent-linux-"+runtime.GOARCH+".manifest", manifestTmp, 64<<10); err != nil {
		return fmt.Errorf("download signed Agent release manifest: %w", err)
	}
	if err := os.Chmod(binTmp, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.BinaryPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return err
	}
	hadBinary := false
	backupPath := ""
	if _, err := os.Stat(cfg.BinaryPath); err == nil {
		hadBinary = true
		backupPath = cfg.BinaryPath + ".bootstrap-backup"
		if err := copyFile(cfg.BinaryPath, backupPath, 0o755); err != nil {
			return fmt.Errorf("backup Agent Guard: %w", err)
		}
	}
	rollback := func() {
		if hadBinary {
			_ = os.Rename(backupPath, cfg.BinaryPath)
		} else {
			_ = os.Remove(cfg.BinaryPath)
		}
	}
	if err := installAtomic(binTmp, cfg.BinaryPath); err != nil {
		return fmt.Errorf("install Agent Guard: %w", err)
	}
	if cfg.ManifestPath == "" {
		cfg.ManifestPath = defaultManifest
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ManifestPath), 0o755); err != nil {
		rollback()
		return err
	}
	if err := copyFile(manifestTmp, cfg.ManifestPath, 0o644); err != nil {
		rollback()
		return err
	}
	if err := writeSystemdUnits(cfg); err != nil {
		rollback()
		return err
	}
	if err := cfg.RunSystemctl(ctx, "daemon-reload"); err != nil {
		rollback()
		return err
	}
	if err := cfg.RunSystemctl(ctx, "enable", "--now", guardServiceName); err != nil {
		rollback()
		return err
	}
	if err := cfg.WaitForSocket(ctx, cfg.SocketPath); err != nil {
		rollback()
		if hadBinary {
			_ = cfg.RunSystemctl(context.Background(), "restart", guardServiceName)
		}
		return fmt.Errorf("Agent Guard did not become ready: %w", err)
	}
	if err := verifyAgentGuardHealth(ctx, cfg.SocketPath); err != nil {
		rollback()
		if hadBinary {
			_ = cfg.RunSystemctl(context.Background(), "restart", guardServiceName)
		}
		return fmt.Errorf("Agent Guard health check failed: %w", err)
	}
	_ = os.Remove(backupPath)
	return nil
}

func verifyAgentGuardHealth(ctx context.Context, socket string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var health struct {
		OK             bool   `json:"ok"`
		Role           string `json:"role"`
		CallerVerified bool   `json:"caller_verified"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&health); err != nil {
		return err
	}
	if !health.OK || health.Role != "agent" || !health.CallerVerified {
		return errors.New("unexpected Guard role or health status")
	}
	return nil
}

func defaultDownloadBases() []string {
	var values []string
	if base := strings.TrimSpace(os.Getenv("MMWX_GUARD_DOWNLOAD_BASE")); base != "" {
		values = append(values, base)
	}
	values = append(values, "https://dl.miaomiaowux.com/mmwx-guard")
	if licenseServer := strings.TrimSpace(os.Getenv("MMWX_LICENSE_SERVER")); licenseServer != "" {
		values = append(values, strings.TrimRight(licenseServer, "/")+"/downloads")
	}
	values = append(values,
		"https://github.com/iluobei/mmw-agent/releases/latest/download",
		"https://gh-proxy.com/https://github.com/iluobei/mmw-agent/releases/latest/download",
		"https://license.miaomiaowux.com/downloads",
	)
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimRight(strings.TrimSpace(value), "/")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func downloadSignedPair(ctx context.Context, client *http.Client, bases []string, name, binPath, sigPath string, verify func(string, string) error) error {
	var lastErr error
	for _, base := range bases {
		if err := downloadFile(ctx, client, strings.TrimRight(base, "/")+"/"+name, binPath, 128<<20); err != nil {
			lastErr = err
			continue
		}
		if err := downloadFile(ctx, client, strings.TrimRight(base, "/")+"/"+name+".sig", sigPath, 4096); err != nil {
			lastErr = err
			continue
		}
		if err := verify(binPath, sigPath); err != nil {
			lastErr = fmt.Errorf("verify Guard from %s: %w", base, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("download signed Agent Guard: %w", lastErr)
}

func downloadFromBases(ctx context.Context, client *http.Client, bases []string, name, target string, limit int64) error {
	var lastErr error
	for _, base := range bases {
		if err := downloadFile(ctx, client, strings.TrimRight(base, "/")+"/"+name, target, limit); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("download %s: %w", name, lastErr)
}

func downloadFile(ctx context.Context, client *http.Client, url, path string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(resp.Body, limit+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written == 0 || written > limit {
		return fmt.Errorf("invalid download size %d for %s", written, url)
	}
	return nil
}

func installAtomic(source, target string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".mmwx-guardd-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}

func copyFile(source, target string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, mode)
}

func writeSystemdUnits(cfg Config) error {
	service := fmt.Sprintf(`[Unit]
Description=MMWX Agent Authorization Guard
After=network-online.target
Wants=network-online.target
Before=mmw-agent.service

[Service]
Type=simple
ExecStart=%s --role agent --socket %s --state-dir %s --manifest %s
Restart=always
RestartSec=3
RuntimeDirectory=mmwx-guard-agent
RuntimeDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, cfg.BinaryPath, cfg.SocketPath, cfg.StateDir, cfg.ManifestPath)
	servicePath := filepath.Join(cfg.SystemdDir, guardServiceName)
	if err := os.WriteFile(servicePath, []byte(service), 0o644); err != nil {
		return fmt.Errorf("write Agent Guard service: %w", err)
	}
	dropinDir := filepath.Join(cfg.SystemdDir, "mmw-agent.service.d")
	if err := os.MkdirAll(dropinDir, 0o755); err != nil {
		return err
	}
	dropin := fmt.Sprintf(`[Unit]
Requires=%s
After=%s

[Service]
Environment="MMWX_ACTION_GUARD=required"
Environment="MMWX_GUARD_SOCKET=%s"
`, guardServiceName, guardServiceName, cfg.SocketPath)
	if err := os.WriteFile(filepath.Join(dropinDir, "action-guard.conf"), []byte(dropin), 0o644); err != nil {
		return fmt.Errorf("write Agent Guard service dependency: %w", err)
	}
	return nil
}

func socketReady(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

func waitForSocket(ctx context.Context, path string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if socketReady(path) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
