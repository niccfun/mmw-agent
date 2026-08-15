package guardbootstrap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	unrelated := filepath.Join(root, "another-temp-dir")
	for _, path := range []string{stale, recent, unrelated} {
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
	for _, path := range []string{recent, unrelated} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("preserved directory %s: %v", path, err)
		}
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
	var healthServer *http.Server
	cfg := Config{
		SocketPath:    filepath.Join(root, "guard.sock"),
		BinaryPath:    filepath.Join(root, "bin", "mmwx-guardd"),
		StateDir:      stateDir,
		ManifestPath:  filepath.Join(root, "share", "agent.manifest"),
		SystemdDir:    filepath.Join(root, "systemd"),
		DownloadBases: []string{server.URL},
		HTTPClient:    server.Client(),
		Verify: func(bin, sig string) error {
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
	if len(systemctl) != 2 || !reflect.DeepEqual(systemctl[0], []string{"daemon-reload"}) ||
		!reflect.DeepEqual(systemctl[1], []string{"enable", "--now", guardServiceName}) {
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
		SocketPath:    filepath.Join(root, "missing.sock"),
		BinaryPath:    bin,
		StateDir:      filepath.Join(root, "state"),
		ManifestPath:  manifestPath,
		SystemdDir:    filepath.Join(root, "systemd"),
		DownloadBases: []string{server.URL},
		HTTPClient:    server.Client(),
		Verify:        func(_, _ string) error { return nil },
		RunSystemctl:  func(context.Context, ...string) error { return nil },
		WaitForSocket: func(context.Context, string) error { return context.DeadlineExceeded },
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

func TestEnsureInstallsAndStartsOpenRCGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("signed-asset"))
	}))
	defer server.Close()

	root := t.TempDir()
	var calls [][]string
	cfg := Config{
		SocketPath:    filepath.Join(root, "run", "guard.sock"),
		BinaryPath:    filepath.Join(root, "bin", "mmwx-guardd"),
		StateDir:      filepath.Join(root, "state"),
		ManifestPath:  filepath.Join(root, "share", "agent.manifest"),
		OpenRCDir:     filepath.Join(root, "init.d"),
		InitSystem:    initOpenRC,
		DownloadBases: []string{server.URL},
		HTTPClient:    server.Client(),
		Verify:        func(_, _ string) error { return nil },
		VerifyHealth:  func(context.Context, string) error { return nil },
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
