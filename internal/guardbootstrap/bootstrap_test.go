package guardbootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDownloadSignedPairFallsBackAfterSignatureVerificationFailure(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".sig" {
			_, _ = w.Write([]byte("bad-signature"))
			return
		}
		_, _ = w.Write([]byte("bad-guard"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == ".sig" {
			_, _ = w.Write([]byte("good-signature"))
			return
		}
		_, _ = w.Write([]byte("good-guard"))
	}))
	defer good.Close()

	dir := t.TempDir()
	binPath, sigPath := filepath.Join(dir, "guard"), filepath.Join(dir, "guard.sig")
	verify := func(binary, signature string) error {
		gotBinary, _ := os.ReadFile(binary)
		gotSignature, _ := os.ReadFile(signature)
		if string(gotBinary) != "good-guard" || string(gotSignature) != "good-signature" {
			return errors.New("signature rejected")
		}
		return nil
	}
	if err := downloadSignedPair(context.Background(), good.Client(), []string{bad.URL, good.URL}, "mmwx-guardd-agent-linux-amd64", binPath, sigPath, verify); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(binPath); string(got) != "good-guard" {
		t.Fatalf("fallback binary = %q", got)
	}
}

func TestDownloadVerifiedManifestFallsBackAfterCallerMismatch(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("manifest-for-another-agent"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("manifest-for-current-agent"))
	}))
	defer good.Close()

	target := filepath.Join(t.TempDir(), "agent.manifest")
	var verified []string
	verify := func(_ context.Context, guardBinary, manifestPath, agentBinary string) error {
		if guardBinary != "/staged/guard" || agentBinary != "/current/mmw-agent" {
			t.Fatalf("unexpected verification paths guard=%q agent=%q", guardBinary, agentBinary)
		}
		manifest, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		verified = append(verified, string(manifest))
		if string(manifest) != "manifest-for-current-agent" {
			return errors.New("release manifest does not authorize the supplied executable")
		}
		return nil
	}
	if err := downloadVerifiedManifestFromBases(context.Background(), good.Client(),
		[]string{bad.URL, good.URL}, "mmw-agent-linux-amd64.manifest", target, 64<<10,
		"/staged/guard", "/current/mmw-agent", verify); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, []string{"manifest-for-another-agent", "manifest-for-current-agent"}) {
		t.Fatalf("verified manifests = %#v", verified)
	}
	manifest, err := os.ReadFile(target)
	if err != nil || string(manifest) != "manifest-for-current-agent" {
		t.Fatalf("selected manifest = %q, err=%v", manifest, err)
	}
}

func TestReleaseManifestBasesArePinnedToRunningAgentVersion(t *testing.T) {
	bases := releaseManifestBases("0.5.1")
	if len(bases) < 2 {
		t.Fatalf("manifest bases = %#v", bases)
	}
	for _, base := range bases {
		if !strings.Contains(base, "v0.5.1") || strings.Contains(base, "/latest/") {
			t.Fatalf("manifest base is not immutable: %q", base)
		}
	}
}

func TestCleanupStaleBootstrapDirsPreservesRecentAndUnrelatedEntries(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	stale := filepath.Join(root, "mmwx-guard-bootstrap-stale")
	recent := filepath.Join(root, "mmwx-guard-bootstrap-active")
	interruptedFixed := filepath.Join(root, "mmwx-guard-bootstrap")
	unrelated := filepath.Join(root, "another-temp-dir")
	for _, path := range []string{stale, recent, interruptedFixed, unrelated} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(stale, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(recent, now.Add(-5*time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(unrelated, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaleBootstrapDirs(root, now, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale bootstrap directory still exists: %v", err)
	}
	if _, err := os.Stat(interruptedFixed); !os.IsNotExist(err) {
		t.Fatalf("fixed bootstrap residue still exists: %v", err)
	}
	for _, path := range []string{recent, unrelated} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("preserved directory %s: %v", path, err)
		}
	}
}

func TestPrepareBootstrapDirReusesInterruptedStagingDirectory(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "mmwx-guard-bootstrap")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "abandoned-guard"), []byte("large partial download"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := prepareBootstrapDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != staging {
		t.Fatalf("staging path = %q, want %q", got, staging)
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("interrupted bootstrap files were not cleared: %+v", entries)
	}
}

func TestEnsureInstallsGuardWithoutReplacingState(t *testing.T) {
	guard := []byte("signed-guard")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case "mmwx-guardd-agent-linux-amd64", "mmwx-guardd-agent-linux-arm64":
			_, _ = w.Write(guard)
		case "mmwx-guardd-agent-linux-amd64.sig", "mmwx-guardd-agent-linux-arm64.sig":
			_, _ = w.Write([]byte("signature"))
		case "mmw-agent-linux-amd64.manifest", "mmw-agent-linux-arm64.manifest":
			_, _ = w.Write([]byte("signed-manifest"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(stateDir, "identity.key")
	if err := os.WriteFile(identity, []byte("existing-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	var systemctl [][]string
	var signatureVerified []string
	var healthServer *http.Server
	cfg := Config{
		SocketPath:    filepath.Join(root, "guard.sock"),
		BinaryPath:    filepath.Join(root, "bin", "mmwx-guardd"),
		StateDir:      stateDir,
		ManifestPath:  filepath.Join(root, "share", "agent.manifest"),
		SystemdDir:    filepath.Join(root, "systemd"),
		TempDir:       root,
		DownloadBases: []string{server.URL},
		HTTPClient:    server.Client(),
		Verify: func(bin, sig string) error {
			signatureVerified = append(signatureVerified, bin)
			got, err := os.ReadFile(bin)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(got, guard) {
				t.Fatalf("unexpected guard binary %q", got)
			}
			_, err = os.Stat(sig)
			return err
		},
		VerifyManifest: func(_ context.Context, guardBinary, manifestPath, agentBinary string) error {
			if filepath.Dir(guardBinary) != filepath.Join(root, "bin") ||
				!strings.HasPrefix(filepath.Base(guardBinary), ".mmwx-guard-verify-") {
				t.Fatalf("unexpected staged Guard path %q", guardBinary)
			}
			wantAgent := fmt.Sprintf("/proc/%d/exe", os.Getpid())
			if agentBinary != wantAgent {
				t.Fatalf("running Agent path = %q, want %q", agentBinary, wantAgent)
			}
			if executable, err := os.ReadFile(agentBinary); err != nil || len(executable) == 0 {
				t.Fatalf("running Agent inode is not readable: size=%d err=%v", len(executable), err)
			}
			manifest, err := os.ReadFile(manifestPath)
			if err != nil {
				return err
			}
			if string(manifest) != "signed-manifest" {
				return fmt.Errorf("unexpected manifest %q", manifest)
			}
			return nil
		},
		VerifyHealth: func(context.Context, string) error { return nil },
		RunSystemctl: func(_ context.Context, args ...string) error {
			systemctl = append(systemctl, append([]string(nil), args...))
			return nil
		},
		WaitForSocket: func(_ context.Context, socket string) error {
			listener, err := net.Listen("unix", socket)
			if err != nil {
				return err
			}
			healthServer = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"ok":true,"role":"agent","caller_verified":true}`))
			})}
			go func() { _ = healthServer.Serve(listener) }()
			return nil
		},
	}
	defer func() {
		if healthServer != nil {
			_ = healthServer.Close()
		}
	}()
	if err := os.MkdirAll(cfg.SystemdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(cfg.BinaryPath); !reflect.DeepEqual(got, guard) {
		t.Fatalf("installed guard = %q", got)
	}
	if got, _ := os.ReadFile(identity); string(got) != "existing-identity" {
		t.Fatalf("Guard identity was replaced: %q", got)
	}
	if len(signatureVerified) != 2 || signatureVerified[0] == signatureVerified[1] ||
		filepath.Dir(signatureVerified[1]) != filepath.Dir(cfg.BinaryPath) {
		t.Fatalf("Guard signature verification paths = %#v", signatureVerified)
	}
	if leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(cfg.BinaryPath), ".mmwx-guard-verify-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("executable verification staging was not cleaned: paths=%#v err=%v", leftovers, err)
	}
	if len(systemctl) != 3 || !reflect.DeepEqual(systemctl[0], []string{"daemon-reload"}) ||
		!reflect.DeepEqual(systemctl[1], []string{"enable", guardServiceName}) ||
		!reflect.DeepEqual(systemctl[2], []string{"restart", guardServiceName}) {
		t.Fatalf("unexpected systemctl calls: %#v", systemctl)
	}
	service, err := os.ReadFile(filepath.Join(cfg.SystemdDir, guardServiceName))
	if err != nil || len(service) == 0 {
		t.Fatalf("service not installed: %v", err)
	}
}

func TestHealthyExistingGuardAcceptsSupervisorManagedSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "guard.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	called := false
	if !healthyExistingGuard(context.Background(), socket, func(context.Context, string) error {
		called = true
		return nil
	}) {
		t.Fatal("healthy supervisor-managed Guard socket was rejected")
	}
	if !called {
		t.Fatal("Guard health verifier was not called")
	}
}

func TestEnsureReturnsWhenSocketAlreadyReady(t *testing.T) {
	// A regular file is deliberately not accepted as a ready Unix socket.
	path := filepath.Join(t.TempDir(), "guard.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if socketReady(path) {
		t.Fatal("regular file treated as Guard socket")
	}
}

func TestWaitForHealthyGuardRetriesAfterStaleSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waitCalls, healthCalls := 0, 0
	err := waitForHealthyGuard(ctx, "/run/stale.sock", func(context.Context, string) error {
		waitCalls++
		return nil
	}, func(context.Context, string) error {
		healthCalls++
		if healthCalls < 3 {
			return errors.New("dial unix: connection refused")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if waitCalls != 1 || healthCalls != 3 {
		t.Fatalf("wait calls=%d health calls=%d", waitCalls, healthCalls)
	}
}

func TestEnsureRollsBackGuardWhenStartFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("new-guard-or-manifest"))
	}))
	defer server.Close()
	root := t.TempDir()
	bin := filepath.Join(root, "bin", "mmwx-guardd")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("old-guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "share", "agent.manifest")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("old-manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		SocketPath:     filepath.Join(root, "missing.sock"),
		BinaryPath:     bin,
		StateDir:       filepath.Join(root, "state"),
		ManifestPath:   manifestPath,
		SystemdDir:     filepath.Join(root, "systemd"),
		TempDir:        root,
		DownloadBases:  []string{server.URL},
		HTTPClient:     server.Client(),
		Verify:         func(_, _ string) error { return nil },
		VerifyManifest: func(context.Context, string, string, string) error { return nil },
		RunSystemctl:   func(context.Context, ...string) error { return nil },
		WaitForSocket:  func(context.Context, string) error { return context.DeadlineExceeded },
	}
	if err := os.MkdirAll(cfg.SystemdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(context.Background(), cfg); err == nil {
		t.Fatal("expected Guard readiness failure")
	}
	got, err := os.ReadFile(bin)
	if err != nil || string(got) != "old-guard" {
		t.Fatalf("Guard rollback failed: got=%q err=%v", got, err)
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil || string(manifest) != "old-manifest" {
		t.Fatalf("manifest rollback failed: got=%q err=%v", manifest, err)
	}
}

func TestEnsureAtomicallyRollsBackRunningGuardAfterHealthFailure(t *testing.T) {
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep executable unavailable")
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true executable unavailable")
	}
	newGuard, err := os.ReadFile(sleepPath)
	if err != nil {
		t.Fatal(err)
	}
	oldGuard, err := os.ReadFile(truePath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Ext(r.URL.Path) {
		case ".sig":
			_, _ = w.Write([]byte("signature"))
		case ".manifest":
			_, _ = w.Write([]byte("manifest"))
		default:
			_, _ = w.Write(newGuard)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	bin := filepath.Join(root, "bin", "mmwx-guardd")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, oldGuard, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "share", "agent.manifest")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("old-manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	var running *exec.Cmd
	restarts := 0
	waitCalls := 0
	var systemctl [][]string
	cfg := Config{
		SocketPath:     filepath.Join(root, "guard.sock"),
		BinaryPath:     bin,
		StateDir:       filepath.Join(root, "state"),
		ManifestPath:   manifestPath,
		SystemdDir:     filepath.Join(root, "systemd"),
		TempDir:        root,
		DownloadBases:  []string{server.URL},
		HTTPClient:     server.Client(),
		Verify:         func(_, _ string) error { return nil },
		VerifyManifest: func(context.Context, string, string, string) error { return nil },
		VerifyHealth:   func(context.Context, string) error { return errors.New("caller mismatch") },
		RunSystemctl: func(_ context.Context, args ...string) error {
			systemctl = append(systemctl, append([]string(nil), args...))
			if !reflect.DeepEqual(args, []string{"restart", guardServiceName}) {
				return nil
			}
			restarts++
			if restarts == 1 {
				running = exec.Command(bin, "30")
				return running.Start()
			}
			if running != nil && running.Process != nil {
				_ = running.Process.Kill()
				_ = running.Wait()
			}
			return nil
		},
		WaitForSocket: func(context.Context, string) error {
			waitCalls++
			if waitCalls == 1 {
				return errors.New("old Guard socket unavailable")
			}
			return nil
		},
	}
	defer func() {
		if running != nil && running.Process != nil {
			_ = running.Process.Kill()
			_ = running.Wait()
		}
	}()
	if err := os.MkdirAll(cfg.SystemdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := Ensure(ctx, cfg); err == nil || !strings.Contains(err.Error(), "caller mismatch") {
		t.Fatalf("Ensure error = %v", err)
	}
	got, err := os.ReadFile(bin)
	if err != nil || !reflect.DeepEqual(got, oldGuard) {
		t.Fatalf("running Guard rollback failed: size=%d err=%v", len(got), err)
	}
	if restarts != 2 {
		t.Fatalf("Guard restart count = %d, want 2", restarts)
	}
	wantSystemctl := [][]string{
		{"daemon-reload"},
		{"enable", guardServiceName},
		{"restart", guardServiceName},
		{"stop", guardServiceName},
		{"daemon-reload"},
		{"restart", guardServiceName},
	}
	if !reflect.DeepEqual(systemctl, wantSystemctl) {
		t.Fatalf("systemctl calls = %#v, want %#v", systemctl, wantSystemctl)
	}
}

func TestEnsureStopsAndDisablesFreshGuardAfterHealthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("signed-asset"))
	}))
	defer server.Close()

	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var systemctl [][]string
	cfg := Config{
		SocketPath:     filepath.Join(root, "guard.sock"),
		BinaryPath:     filepath.Join(root, "bin", "mmwx-guardd"),
		StateDir:       filepath.Join(root, "state"),
		ManifestPath:   filepath.Join(root, "share", "agent.manifest"),
		SystemdDir:     filepath.Join(root, "systemd"),
		TempDir:        root,
		DownloadBases:  []string{server.URL},
		HTTPClient:     server.Client(),
		Verify:         func(_, _ string) error { return nil },
		VerifyManifest: func(context.Context, string, string, string) error { return nil },
		VerifyHealth: func(context.Context, string) error {
			cancel()
			return errors.New("fresh Guard health rejected")
		},
		RunSystemctl: func(_ context.Context, args ...string) error {
			systemctl = append(systemctl, append([]string(nil), args...))
			return nil
		},
		WaitForSocket: func(context.Context, string) error { return nil },
	}
	if err := os.MkdirAll(cfg.SystemdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := Ensure(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), "fresh Guard health rejected") {
		t.Fatalf("Ensure error = %v", err)
	}
	wantSystemctl := [][]string{
		{"daemon-reload"},
		{"enable", guardServiceName},
		{"restart", guardServiceName},
		{"stop", guardServiceName},
		{"disable", guardServiceName},
		{"daemon-reload"},
	}
	if !reflect.DeepEqual(systemctl, wantSystemctl) {
		t.Fatalf("systemctl calls = %#v, want %#v", systemctl, wantSystemctl)
	}
	for _, path := range []string{
		cfg.BinaryPath,
		cfg.ManifestPath,
		filepath.Join(cfg.SystemdDir, guardServiceName),
		filepath.Join(cfg.SystemdDir, "mmw-agent.service.d", "action-guard.conf"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fresh Guard artifact %s survived rollback: %v", path, err)
		}
	}
}

func TestEnsureCombinesStartAndRollbackFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("new-signed-asset"))
	}))
	defer server.Close()

	root := t.TempDir()
	bin := filepath.Join(root, "bin", "mmwx-guardd")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("old-guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "share", "agent.manifest")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("old-manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	var systemctl [][]string
	cfg := Config{
		SocketPath:     filepath.Join(root, "guard.sock"),
		BinaryPath:     bin,
		StateDir:       filepath.Join(root, "state"),
		ManifestPath:   manifestPath,
		SystemdDir:     filepath.Join(root, "systemd"),
		TempDir:        root,
		DownloadBases:  []string{server.URL},
		HTTPClient:     server.Client(),
		Verify:         func(_, _ string) error { return nil },
		VerifyManifest: func(context.Context, string, string, string) error { return nil },
		RunSystemctl: func(_ context.Context, args ...string) error {
			systemctl = append(systemctl, append([]string(nil), args...))
			if reflect.DeepEqual(args, []string{"restart", guardServiceName}) {
				if err := os.Remove(bin + ".bootstrap-backup"); err != nil {
					return err
				}
				return errors.New("new Guard start failed")
			}
			return nil
		},
		WaitForSocket: func(context.Context, string) error { return errors.New("old Guard unavailable") },
	}
	if err := os.MkdirAll(cfg.SystemdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := Ensure(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "new Guard start failed") ||
		!strings.Contains(err.Error(), "restore Agent Guard binary") {
		t.Fatalf("combined Ensure error = %v", err)
	}
	wantSystemctl := [][]string{
		{"daemon-reload"},
		{"enable", guardServiceName},
		{"restart", guardServiceName},
		{"stop", guardServiceName},
	}
	if !reflect.DeepEqual(systemctl, wantSystemctl) {
		t.Fatalf("systemctl calls = %#v, want %#v", systemctl, wantSystemctl)
	}
}

func TestVerifyAgentGuardHealthRejectsWrongRole(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "guard.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"role":"master"}`))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	if err := verifyAgentGuardHealth(context.Background(), socket); err == nil {
		t.Fatal("master Guard accepted as Agent Guard")
	}
}

func TestWriteSystemdUnitsPreservesExistingGuardArguments(t *testing.T) {
	root := t.TempDir()
	servicePath := filepath.Join(root, guardServiceName)
	existing := []byte("[Service]\nExecStart=/old/guard --license-server https://license.example\n")
	if err := os.WriteFile(servicePath, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		SocketPath:   filepath.Join(root, "guard.sock"),
		BinaryPath:   filepath.Join(root, "guard"),
		StateDir:     filepath.Join(root, "state"),
		ManifestPath: filepath.Join(root, "manifest"),
		SystemdDir:   root,
	}
	if err := writeSystemdUnits(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, existing) {
		t.Fatalf("existing Guard service was overwritten: %q", got)
	}
	dropin, err := os.ReadFile(filepath.Join(root, "mmw-agent.service.d", "action-guard.conf"))
	if err != nil {
		t.Fatalf("Agent drop-in was not installed: %v", err)
	}
	if !strings.Contains(string(dropin), "Wants="+guardServiceName) ||
		strings.Contains(string(dropin), "Requires="+guardServiceName) {
		t.Fatalf("Guard maintenance must not cascade-stop Agent:\n%s", dropin)
	}
}

func TestWriteSystemdUnitsMigratesOnlyLegacyGuardRequires(t *testing.T) {
	root := t.TempDir()
	agentServicePath := filepath.Join(root, "mmw-agent.service")
	agentService := `[Unit]
Requires=mmwx-guard-agent.service
Requires=network-online.target
Requires=mmwx-guard-agent.service another.service
After=network.target
`
	if err := os.WriteFile(agentServicePath, []byte(agentService), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		SocketPath:   filepath.Join(root, "guard.sock"),
		BinaryPath:   filepath.Join(root, "guard"),
		StateDir:     filepath.Join(root, "state"),
		ManifestPath: filepath.Join(root, "manifest"),
		SystemdDir:   root,
	}
	if err := writeSystemdUnits(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(agentServicePath)
	if err != nil {
		t.Fatal(err)
	}
	want := `[Unit]
Wants=mmwx-guard-agent.service
Requires=network-online.target
Requires=mmwx-guard-agent.service another.service
After=network.target
`
	if string(got) != want {
		t.Fatalf("migrated Agent service:\n%s\nwant:\n%s", got, want)
	}
	info, err := os.Stat(agentServicePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("Agent service mode = %v", info.Mode().Perm())
	}
}

func TestEnsureInstallsAndStartsOpenRCGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("signed-asset"))
	}))
	defer server.Close()

	root := t.TempDir()
	var calls [][]string
	cfg := Config{
		SocketPath:     filepath.Join(root, "run", "guard.sock"),
		BinaryPath:     filepath.Join(root, "bin", "mmwx-guardd"),
		StateDir:       filepath.Join(root, "state"),
		ManifestPath:   filepath.Join(root, "share", "agent.manifest"),
		OpenRCDir:      filepath.Join(root, "init.d"),
		InitSystem:     initOpenRC,
		TempDir:        root,
		DownloadBases:  []string{server.URL},
		HTTPClient:     server.Client(),
		Verify:         func(_, _ string) error { return nil },
		VerifyManifest: func(context.Context, string, string, string) error { return nil },
		VerifyHealth:   func(context.Context, string) error { return nil },
		RunOpenRC: func(_ context.Context, command string, args ...string) error {
			calls = append(calls, append([]string{command}, args...))
			return nil
		},
		WaitForSocket: func(_ context.Context, socket string) error {
			if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
				return err
			}
			listener, err := net.Listen("unix", socket)
			if err != nil {
				return err
			}
			t.Cleanup(func() { _ = listener.Close() })
			return nil
		},
	}
	if err := Ensure(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	wantCalls := [][]string{
		{"rc-update", "add", guardOpenRCName, "default"},
		{"rc-service", "--nodeps", guardOpenRCName, "restart"},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("unexpected OpenRC calls: %#v", calls)
	}
	service, err := os.ReadFile(filepath.Join(cfg.OpenRCDir, guardOpenRCName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service), "supervisor=\"supervise-daemon\"") ||
		!strings.Contains(string(service), "before mmw-agent") {
		t.Fatalf("invalid OpenRC service:\n%s", service)
	}
}
