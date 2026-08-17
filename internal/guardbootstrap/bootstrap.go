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
	SocketPath      string
	BinaryPath      string
	StateDir        string
	ManifestPath    string
	SystemdDir      string
	OpenRCDir       string
	InitSystem      string
	DownloadBases   []string
	ManifestBases   []string
	TempDir         string
	Now             func() time.Time
	StaleMaxAge     time.Duration
	HTTPClient      *http.Client
	Verify          func(string, string) error
	VerifyManifest  func(context.Context, string, string, string) error
	AgentBinaryPath string
	VerifyHealth    func(context.Context, string) error
	RunSystemctl    func(context.Context, ...string) error
	RunOpenRC       func(context.Context, string, ...string) error
	WaitForSocket   func(context.Context, string) error
}

func healthyExistingGuard(ctx context.Context, socket string, verify func(context.Context, string) error) bool {
	if !socketReady(socket) {
		return false
	}
	healthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return verify(healthCtx, socket) == nil
}

// EnsureDefault makes a signed Guard available without replacing its state
// directory. It is intentionally only used by release builds that require the
// Guard and are not running in Docker (the Docker image already bundles it).
func EnsureDefault(ctx context.Context) error {
	// OpenVZ and other minimal containers may run Guard under the install
	// script's supervisor without systemd/OpenRC. Accept an already healthy
	// default Guard before requiring an init system for bootstrap/repair.
	if healthyExistingGuard(ctx, defaultSocket, verifyAgentGuardHealth) {
		return nil
	}

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
		SocketPath:     defaultSocket,
		BinaryPath:     defaultBinary,
		StateDir:       defaultStateDir,
		ManifestPath:   defaultManifest,
		SystemdDir:     defaultSystemd,
		OpenRCDir:      defaultOpenRCDir,
		InitSystem:     initSystem,
		DownloadBases:  defaultDownloadBases(),
		ManifestBases:  releaseManifestBases(version.Version),
		HTTPClient:     &http.Client{Timeout: 3 * time.Minute},
		Verify:         selfupdate.VerifyFile,
		VerifyManifest: verifyAgentManifest,
		VerifyHealth:   verifyAgentGuardHealth,
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
		err = waitForHealthyGuard(readyCtx, cfg.SocketPath, cfg.WaitForSocket, verifyHealth)
		cancel()
		if err == nil {
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
	// Use one bounded staging directory instead of a new random directory on
	// every attempt. A SIGKILL/service restart cannot run defer; with MkdirTemp
	// that left one full Guard binary per attempt in /tmp. Recreating the fixed
	// directory removes the interrupted attempt before downloading again.
	tmpDir, err := prepareBootstrapDir(tempDir)
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
	if err := os.MkdirAll(filepath.Dir(cfg.BinaryPath), 0o755); err != nil {
		return err
	}
	// /tmp is commonly mounted noexec on hardened hosts. Keep downloads in the
	// bounded temporary directory, but execute a second signature-verified copy
	// from the final binary's filesystem, which must be executable for Guard to
	// run after installation anyway.
	verifyGuard, err := createSiblingExecutable(binTmp, cfg.BinaryPath)
	if err != nil {
		return fmt.Errorf("stage Agent Guard for manifest verification: %w", err)
	}
	defer os.Remove(verifyGuard)
	if err := cfg.Verify(verifyGuard, sigTmp); err != nil {
		return fmt.Errorf("verify staged Agent Guard: %w", err)
	}
	verifyManifest := cfg.VerifyManifest
	if verifyManifest == nil {
		verifyManifest = verifyAgentManifest
	}
	agentBinaryPath := cfg.AgentBinaryPath
	if agentBinaryPath == "" {
		// Verify the exact inode executing this process. The on-disk path may have
		// been atomically replaced by an older updater while this Agent is still
		// running; /proc/<pid>/exe remains a readable handle to the real caller.
		agentBinaryPath = fmt.Sprintf("/proc/%d/exe", os.Getpid())
	}
	manifestBases := cfg.ManifestBases
	if len(manifestBases) == 0 {
		manifestBases = cfg.DownloadBases
	}
	if err := downloadVerifiedManifestFromBases(ctx, cfg.HTTPClient, manifestBases,
		"mmw-agent-linux-"+runtime.GOARCH+".manifest", manifestTmp, 64<<10,
		verifyGuard, agentBinaryPath, verifyManifest); err != nil {
		return fmt.Errorf("download signed Agent release manifest: %w", err)
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
	guardInitPath, agentDependencyPath := bootstrapInitPaths(cfg, initSystem)
	guardInitSnapshot, err := snapshotBootstrapFile(guardInitPath)
	if err != nil {
		_ = os.Remove(backupPath)
		_ = os.Remove(manifestBackupPath)
		return fmt.Errorf("backup Agent Guard init file: %w", err)
	}
	agentDependencySnapshot, err := snapshotBootstrapFile(agentDependencyPath)
	if err != nil {
		_ = guardInitSnapshot.cleanup()
		_ = os.Remove(backupPath)
		_ = os.Remove(manifestBackupPath)
		return fmt.Errorf("backup Agent Guard dependency file: %w", err)
	}
	initFilesAttempted := false
	rollback := func() (bool, error) {
		var restoreErrs []error
		if hadBinary {
			if err := installAtomic(backupPath, cfg.BinaryPath); err != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("restore Agent Guard binary: %w", err))
			}
		} else {
			if err := os.Remove(cfg.BinaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				restoreErrs = append(restoreErrs, fmt.Errorf("remove new Agent Guard binary: %w", err))
			}
		}
		if hadManifest {
			if err := installAtomicMode(manifestBackupPath, cfg.ManifestPath, 0o644); err != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("restore Agent manifest: %w", err))
			}
		} else {
			if err := os.Remove(cfg.ManifestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				restoreErrs = append(restoreErrs, fmt.Errorf("remove new Agent manifest: %w", err))
			}
		}
		if initFilesAttempted {
			if err := guardInitSnapshot.restore(); err != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("restore Agent Guard init file: %w", err))
			}
			// Keep the normalized Wants= drop-in while restoring an existing
			// systemd Guard. Reintroducing a legacy Requires= dependency here would
			// make the restart below terminate the Agent running this rollback.
			if initSystem != initSystemd || !hadBinary {
				if err := agentDependencySnapshot.restore(); err != nil {
					restoreErrs = append(restoreErrs, fmt.Errorf("restore Agent Guard dependency file: %w", err))
				}
			}
		}
		if err := errors.Join(restoreErrs...); err != nil {
			// Keep both backups for manual recovery when automatic restoration did
			// not complete successfully.
			return false, err
		}
		var cleanupErrs []error
		for _, path := range []string{
			backupPath, manifestBackupPath,
			guardInitSnapshot.backup, agentDependencySnapshot.backup,
		} {
			if path == "" {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("remove bootstrap backup %s: %w", path, err))
			}
		}
		return true, errors.Join(cleanupErrs...)
	}
	rollbackFailure := func(cause error, serviceAttempted bool) error {
		var serviceErrs []error
		if serviceAttempted {
			stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := stopGuardService(stopCtx, cfg, initSystem); err != nil {
				serviceErrs = append(serviceErrs, fmt.Errorf("stop failed Agent Guard before rollback: %w", err))
			}
			cancel()
			if !hadBinary {
				disableCtx, disableCancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := disableGuardService(disableCtx, cfg, initSystem); err != nil {
					serviceErrs = append(serviceErrs, fmt.Errorf("disable failed Agent Guard before rollback: %w", err))
				}
				disableCancel()
			}
		}
		restored, rollbackErr := rollback()
		if serviceAttempted && restored {
			serviceCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if initSystem == initSystemd {
				if err := cfg.RunSystemctl(serviceCtx, "daemon-reload"); err != nil {
					serviceErrs = append(serviceErrs, fmt.Errorf("reload restored Agent Guard service: %w", err))
				}
			}
			if hadBinary {
				err := restartGuardService(serviceCtx, cfg, initSystem)
				if err != nil {
					serviceErrs = append(serviceErrs, fmt.Errorf("restart restored Agent Guard: %w", err))
				}
			}
			cancel()
		}
		if rollbackErr != nil {
			rollbackErr = fmt.Errorf("rollback Agent Guard bootstrap: %w", rollbackErr)
		}
		return errors.Join(cause, rollbackErr, errors.Join(serviceErrs...))
	}
	if err := installAtomic(verifyGuard, cfg.BinaryPath); err != nil {
		return rollbackFailure(fmt.Errorf("install Agent Guard: %w", err), false)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ManifestPath), 0o755); err != nil {
		return rollbackFailure(err, false)
	}
	if err := installAtomicMode(manifestTmp, cfg.ManifestPath, 0o644); err != nil {
		return rollbackFailure(err, false)
	}
	initFilesAttempted = true
	if err := writeInitFiles(cfg, initSystem); err != nil {
		return rollbackFailure(err, false)
	}
	if err := startGuardService(ctx, cfg, initSystem); err != nil {
		return rollbackFailure(err, true)
	}
	if err := waitForHealthyGuard(ctx, cfg.SocketPath, cfg.WaitForSocket, verifyHealth); err != nil {
		return rollbackFailure(fmt.Errorf("Agent Guard did not become healthy: %w", err), true)
	}
	_ = os.Remove(backupPath)
	_ = os.Remove(manifestBackupPath)
	_ = guardInitSnapshot.cleanup()
	_ = agentDependencySnapshot.cleanup()
	return nil
}

func prepareBootstrapDir(root string) (string, error) {
	path := filepath.Join(root, "mmwx-guard-bootstrap")
	if err := os.RemoveAll(path); err != nil {
		return "", fmt.Errorf("remove previous Agent Guard bootstrap directory: %w", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", fmt.Errorf("create Agent Guard bootstrap directory: %w", err)
	}
	return path, nil
}

func createSiblingExecutable(source, installedPath string) (string, error) {
	dir := filepath.Dir(installedPath)
	placeholder, err := os.CreateTemp(dir, ".mmwx-guard-verify-*")
	if err != nil {
		return "", err
	}
	path := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := installAtomic(source, path); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

type bootstrapFileSnapshot struct {
	path    string
	backup  string
	existed bool
	mode    os.FileMode
}

func snapshotBootstrapFile(path string) (bootstrapFileSnapshot, error) {
	snapshot := bootstrapFileSnapshot{path: path}
	if path == "" {
		return snapshot, nil
	}
	snapshot.backup = path + ".bootstrap-backup"
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(snapshot.backup)
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	snapshot.existed = true
	snapshot.mode = info.Mode().Perm()
	if err := copyFile(path, snapshot.backup, snapshot.mode); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (snapshot bootstrapFileSnapshot) restore() error {
	if snapshot.path == "" {
		return nil
	}
	if snapshot.existed {
		return installAtomicMode(snapshot.backup, snapshot.path, snapshot.mode)
	}
	if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (snapshot bootstrapFileSnapshot) cleanup() error {
	if snapshot.backup == "" {
		return nil
	}
	if err := os.Remove(snapshot.backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func bootstrapInitPaths(cfg Config, initSystem string) (string, string) {
	if initSystem == initOpenRC {
		return filepath.Join(cfg.OpenRCDir, guardOpenRCName), ""
	}
	return filepath.Join(cfg.SystemdDir, guardServiceName),
		filepath.Join(cfg.SystemdDir, "mmw-agent.service.d", "action-guard.conf")
}

func cleanupStaleBootstrapDirs(root string, now time.Time, maxAge time.Duration) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// The fixed staging directory belongs to an interrupted earlier Agent
		// process and is safe to remove immediately. Legacy random directories use
		// the age guard below for compatibility with an in-flight old Agent.
		if entry.Name() == "mmwx-guard-bootstrap" {
			if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(entry.Name(), "mmwx-guard-bootstrap-") {
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
	if err := cfg.RunSystemctl(ctx, "enable", guardServiceName); err != nil {
		return err
	}
	// enable --now is a no-op for an already active service. Bootstrap reaches
	// this path specifically when the running Guard rejected the current Agent,
	// so it must restart to load the newly installed binary and manifest.
	return cfg.RunSystemctl(ctx, "restart", guardServiceName)
}

func restartGuardService(ctx context.Context, cfg Config, initSystem string) error {
	if initSystem == initOpenRC {
		return cfg.RunOpenRC(ctx, "rc-service", "--nodeps", guardOpenRCName, "restart")
	}
	return cfg.RunSystemctl(ctx, "restart", guardServiceName)
}

func stopGuardService(ctx context.Context, cfg Config, initSystem string) error {
	if initSystem == initOpenRC {
		return cfg.RunOpenRC(ctx, "rc-service", "--nodeps", guardOpenRCName, "stop")
	}
	return cfg.RunSystemctl(ctx, "stop", guardServiceName)
}

func disableGuardService(ctx context.Context, cfg Config, initSystem string) error {
	if initSystem == initOpenRC {
		return cfg.RunOpenRC(ctx, "rc-update", "del", guardOpenRCName, "default")
	}
	return cfg.RunSystemctl(ctx, "disable", guardServiceName)
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

func downloadVerifiedManifestFromBases(
	ctx context.Context,
	client *http.Client,
	bases []string,
	name, target string,
	limit int64,
	guardBinary, agentBinary string,
	verify func(context.Context, string, string, string) error,
) error {
	var lastErr error
	for _, base := range bases {
		url := strings.TrimRight(base, "/") + "/" + name
		if err := downloadFile(ctx, client, url, target, limit); err != nil {
			lastErr = err
			continue
		}
		if err := verify(ctx, guardBinary, target, agentBinary); err != nil {
			lastErr = fmt.Errorf("verify Agent manifest from %s: %w", base, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("download %s: %w", name, lastErr)
}

func verifyAgentManifest(ctx context.Context, guardBinary, manifestPath, agentBinary string) error {
	cmd := exec.CommandContext(ctx, guardBinary,
		"--role", "agent", "--manifest", manifestPath,
		"--verify-manifest-for", agentBinary)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForHealthyGuard(
	ctx context.Context,
	socket string,
	waitForSocket func(context.Context, string) error,
	verifyHealth func(context.Context, string) error,
) error {
	if err := waitForSocket(ctx, socket); err != nil {
		return fmt.Errorf("wait for socket: %w", err)
	}
	var lastErr error
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		lastErr = verifyHealth(attemptCtx, socket)
		cancel()
		if lastErr == nil {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("%w; last health error: %v", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
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
	return installAtomicMode(source, target, 0o755)
}

func installAtomicMode(source, target string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return writeAtomicFile(target, data, mode)
}

func writeAtomicFile(target string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".mmwx-guardd-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
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
	if err := migrateLegacyAgentGuardDependency(filepath.Join(cfg.SystemdDir, "mmw-agent.service")); err != nil {
		return err
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

func migrateLegacyAgentGuardDependency(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Agent systemd service: %w", err)
	}
	const legacy = "Requires=" + guardServiceName
	const replacement = "Wants=" + guardServiceName
	lines := strings.Split(string(data), "\n")
	changed := false
	for index, line := range lines {
		if line != legacy {
			continue
		}
		lines[index] = replacement
		changed = true
	}
	if !changed {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect Agent systemd service mode: %w", err)
	}
	if err := writeAtomicFile(path, []byte(strings.Join(lines, "\n")), info.Mode().Perm()); err != nil {
		return fmt.Errorf("migrate legacy Agent Guard systemd dependency: %w", err)
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
