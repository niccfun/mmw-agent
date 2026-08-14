// Package guardbootstrap installs the closed Agent Guard during the first
// upgrade from a legacy Agent release. Later upgrades replace both binaries in
// one transaction; this bootstrap is the compatibility path for hosts whose
// old self-updater only knew about mmw-agent.
package guardbootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mmw-agent/internal/guardclient"
	"mmw-agent/internal/selfupdate"
	"mmw-agent/internal/version"
)

const (
	defaultSocket    = "/run/mmwx-guard-agent/guard.sock"
	defaultBinary    = "/usr/local/bin/mmwx-guardd-agent"
	defaultStateDir  = "/var/lib/mmwx-guard"
	defaultManifest  = "/usr/local/share/mmwx-guard/agent.manifest"
	defaultSystemd   = "/etc/systemd/system"
	defaultOpenRCDir = "/etc/init.d"
	guardServiceName = "mmwx-guard-agent.service"
	guardOpenRCName  = "mmwx-guard-agent"
	initSystemd      = "systemd"
	initOpenRC       = "openrc"
)

type Config struct {
	SocketPath    string
	BinaryPath    string
	StateDir      string
	ManifestPath  string
	SystemdDir    string
	OpenRCDir     string
	InitSystem    string
	DownloadBases []string
	ManifestBases []string
	TempDir       string
	Now           func() time.Time
	StaleMaxAge   time.Duration
	HTTPClient    *http.Client
	Verify        func(string, string) error
	VerifyHealth  func(context.Context, string) error
	RunSystemctl  func(context.Context, ...string) error
	RunOpenRC     func(context.Context, string, ...string) error
	WaitForSocket func(context.Context, string) error
}

// EnsureDefault makes a signed Guard available without replacing its state
// directory. It is intentionally only used by release builds that require the
// Guard and are not running in Docker (the Docker image already bundles it).
func EnsureDefault(ctx context.Context) error {
	initSystem := ""
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, lookupErr := exec.LookPath("systemctl"); lookupErr == nil {
			initSystem = initSystemd
		}
	}
	if initSystem == "" {
		if _, err := exec.LookPath("rc-service"); err == nil {
			if _, updateErr := exec.LookPath("rc-update"); updateErr == nil {
				initSystem = initOpenRC
			}
		}
	}
	if initSystem == "" {
		return errors.New("Agent Guard requires systemd or OpenRC; reinstall the Agent after installing an init system")
	}
	cfg := Config{
		SocketPath:    defaultSocket,
		BinaryPath:    defaultBinary,
		StateDir:      defaultStateDir,
		ManifestPath:  defaultManifest,
		SystemdDir:    defaultSystemd,
		OpenRCDir:     defaultOpenRCDir,
		InitSystem:    initSystem,
		DownloadBases: defaultDownloadBases(),
		ManifestBases: releaseManifestBases(version.Version),
		HTTPClient:    &http.Client{Timeout: 3 * time.Minute},
		Verify:        selfupdate.VerifyFile,
		VerifyHealth:  verifyAgentGuardHealth,
		RunSystemctl: func(ctx context.Context, args ...string) error {
			cmd := exec.CommandContext(ctx, "systemctl", args...)
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
			}
			return nil
		},
		RunOpenRC: func(ctx context.Context, command string, args ...string) error {
			cmd := exec.CommandContext(ctx, command, args...)
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("%s %s: %w: %s", command, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
			}
			return nil
		},
		WaitForSocket: waitForSocket,
	}
	return Ensure(ctx, cfg)
}

func Ensure(ctx context.Context, cfg Config) error {
	tempDir := cfg.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	staleMaxAge := cfg.StaleMaxAge
	if staleMaxAge <= 0 {
		staleMaxAge = 30 * time.Minute
	}
	// A previous process can be killed by its service manager while bootstrapping
	// Guard, so Go defers are not guaranteed to run. Bound disk usage before any
	// health/download work without touching a currently active bootstrap dir.
	cleanupErr := cleanupStaleBootstrapDirs(tempDir, now(), staleMaxAge)

	initSystem := cfg.InitSystem
	if initSystem == "" {
		// Preserve the systemd default for tests and callers created before
		// OpenRC support was added.
		initSystem = initSystemd
	}
	verifyHealth := cfg.VerifyHealth
	if verifyHealth == nil {
		verifyHealth = verifyAgentGuardHealth
	}
	if socketReady(cfg.SocketPath) && verifyHealth(ctx, cfg.SocketPath) == nil {
		return nil
	}
	// systemd ordering waits for the Guard process to start, not for its Unix
	// socket to be bound. Avoid an unnecessary download/restart on every normal
	// boot when the existing Guard is only a few milliseconds behind the Agent.
	if _, err := os.Stat(cfg.BinaryPath); err == nil && cfg.WaitForSocket != nil {
		readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = cfg.WaitForSocket(readyCtx, cfg.SocketPath)
		cancel()
		if err == nil && verifyHealth(ctx, cfg.SocketPath) == nil {
			return nil
		}
	}
	if cleanupErr != nil {
		return fmt.Errorf("cleanup stale Agent Guard bootstrap directories: %w", cleanupErr)
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("Agent Guard does not support %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if cfg.BinaryPath == defaultBinary && os.Geteuid() != 0 {
		return errors.New("Agent Guard bootstrap requires root")
	}
	if initSystem == initSystemd && cfg.SystemdDir == defaultSystemd {
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			return errors.New("Agent Guard bootstrap requires a running systemd instance")
		}
	}
	if initSystem == initOpenRC && cfg.OpenRCDir == "" {
		cfg.OpenRCDir = defaultOpenRCDir
	}
	if initSystem != initSystemd && initSystem != initOpenRC {
		return fmt.Errorf("unsupported Agent Guard init system %q", initSystem)
	}
	if cfg.Verify == nil || cfg.WaitForSocket == nil || cfg.HTTPClient == nil ||
		(initSystem == initSystemd && cfg.RunSystemctl == nil) ||
		(initSystem == initOpenRC && cfg.RunOpenRC == nil) {
		return errors.New("incomplete Agent Guard bootstrap configuration")
	}

	name := "mmwx-guardd-agent-linux-" + runtime.GOARCH
	tmpDir, err := os.MkdirTemp(tempDir, "mmwx-guard-bootstrap-*")
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
	manifestBases := cfg.ManifestBases
	if len(manifestBases) == 0 {
		manifestBases = cfg.DownloadBases
	}
	if err := downloadFromBases(ctx, cfg.HTTPClient, manifestBases, "mmw-agent-linux-"+runtime.GOARCH+".manifest", manifestTmp, 64<<10); err != nil {
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
	if cfg.ManifestPath == "" {
		cfg.ManifestPath = defaultManifest
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
	hadManifest := false
	manifestBackupPath := cfg.ManifestPath + ".bootstrap-backup"
	if _, err := os.Stat(cfg.ManifestPath); err == nil {
		hadManifest = true
		if err := copyFile(cfg.ManifestPath, manifestBackupPath, 0o644); err != nil {
			return fmt.Errorf("backup Agent manifest: %w", err)
		}
	} else {
		_ = os.Remove(manifestBackupPath)
	}
	rollback := func() {
		if hadBinary {
			_ = copyFile(backupPath, cfg.BinaryPath, 0o755)
		} else {
			_ = os.Remove(cfg.BinaryPath)
		}
		if hadManifest {
			_ = copyFile(manifestBackupPath, cfg.ManifestPath, 0o644)
		} else {
			_ = os.Remove(cfg.ManifestPath)
		}
		_ = os.Remove(backupPath)
		_ = os.Remove(manifestBackupPath)
	}
	if err := installAtomic(binTmp, cfg.BinaryPath); err != nil {
		rollback()
		return fmt.Errorf("install Agent Guard: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ManifestPath), 0o755); err != nil {
		rollback()
		return err
	}
	if err := copyFile(manifestTmp, cfg.ManifestPath, 0o644); err != nil {
		rollback()
		return err
	}
	if err := writeInitFiles(cfg, initSystem); err != nil {
		rollback()
		return err
	}
	if err := startGuardService(ctx, cfg, initSystem); err != nil {
		rollback()
		return err
	}
	if err := cfg.WaitForSocket(ctx, cfg.SocketPath); err != nil {
		rollback()
		if hadBinary {
			_ = restartGuardService(context.Background(), cfg, initSystem)
		}
		return fmt.Errorf("Agent Guard did not become ready: %w", err)
	}
	if err := verifyHealth(ctx, cfg.SocketPath); err != nil {
		rollback()
		if hadBinary {
			_ = restartGuardService(context.Background(), cfg, initSystem)
		}
		return fmt.Errorf("Agent Guard health check failed: %w", err)
	}
	_ = os.Remove(backupPath)
	_ = os.Remove(manifestBackupPath)
	return nil
}

func cleanupStaleBootstrapDirs(root string, now time.Time, maxAge time.Duration) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "mmwx-guard-bootstrap-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < maxAge {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func writeInitFiles(cfg Config, initSystem string) error {
	if initSystem == initOpenRC {
		return writeOpenRCService(cfg)
	}
	return writeSystemdUnits(cfg)
}

func startGuardService(ctx context.Context, cfg Config, initSystem string) error {
	if initSystem == initOpenRC {
		if err := cfg.RunOpenRC(ctx, "rc-update", "add", guardOpenRCName, "default"); err != nil {
			return err
		}
		// mmw-agent declares a hard dependency on the Guard. A normal OpenRC
		// restart cascades through reverse dependencies and kills the Agent that
		// is currently performing this bootstrap/upgrade. --nodeps limits the
		// operation to Guard; the caller verifies its socket before continuing.
		return cfg.RunOpenRC(ctx, "rc-service", "--nodeps", guardOpenRCName, "restart")
	}
	if err := cfg.RunSystemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	return cfg.RunSystemctl(ctx, "enable", "--now", guardServiceName)
}

func restartGuardService(ctx context.Context, cfg Config, initSystem string) error {
	if initSystem == initOpenRC {
		return cfg.RunOpenRC(ctx, "rc-service", "--nodeps", guardOpenRCName, "restart")
	}
	return cfg.RunSystemctl(ctx, "restart", guardServiceName)
}

func verifyAgentGuardHealth(ctx context.Context, socket string) error {
	health, err := guardclient.NewForSocket(socket).Health(ctx)
	if err != nil {
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

// releaseManifestBases returns immutable locations for the manifest matching
// the Agent binary that is currently executing. Using the mutable "latest"
// manifest can never repair an older Agent: Guard correctly rejects its hash,
// causing an endless bootstrap/restart loop.
func releaseManifestBases(agentVersion string) []string {
	tag := strings.TrimSpace(agentVersion)
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	return []string{
		"https://dl.miaomiaowux.com/mmw-agent/releases/" + tag,
		"https://github.com/iluobei/mmw-agent/releases/download/" + tag,
		"https://gh-proxy.com/https://github.com/iluobei/mmw-agent/releases/download/" + tag,
	}
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
	if _, err := os.Stat(servicePath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(servicePath, []byte(service), 0o644); err != nil {
			return fmt.Errorf("write Agent Guard service: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect Agent Guard service: %w", err)
	}
	dropinDir := filepath.Join(cfg.SystemdDir, "mmw-agent.service.d")
	if err := os.MkdirAll(dropinDir, 0o755); err != nil {
		return err
	}
	dropin := fmt.Sprintf(`[Unit]
Wants=%s
After=%s

[Service]
Environment="MMWX_GUARD_SOCKET=%s"
`, guardServiceName, guardServiceName, cfg.SocketPath)
	if err := os.WriteFile(filepath.Join(dropinDir, "action-guard.conf"), []byte(dropin), 0o644); err != nil {
		return fmt.Errorf("write Agent Guard service dependency: %w", err)
	}
	return nil
}

func writeOpenRCService(cfg Config) error {
	if err := os.MkdirAll(cfg.OpenRCDir, 0o755); err != nil {
		return fmt.Errorf("create OpenRC service directory: %w", err)
	}
	servicePath := filepath.Join(cfg.OpenRCDir, guardOpenRCName)
	service := fmt.Sprintf(`#!/sbin/openrc-run
name="MMWX Agent Authorization Guard"
description="MMWX Agent Authorization Guard"
command=%q
command_args=%q
supervisor="supervise-daemon"
respawn_delay=3
respawn_max=0
export MMWX_GUARD_SOCKET=%q

depend() {
    need net
    before mmw-agent
}

start_pre() {
    checkpath --directory --mode 0750 %q
    checkpath --directory --mode 0700 %q
}
`, cfg.BinaryPath,
		"--role agent --socket "+cfg.SocketPath+" --state-dir "+cfg.StateDir+" --manifest "+cfg.ManifestPath,
		cfg.SocketPath, filepath.Dir(cfg.SocketPath), cfg.StateDir)
	if err := os.WriteFile(servicePath, []byte(service), 0o755); err != nil {
		return fmt.Errorf("write Agent Guard OpenRC service: %w", err)
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
