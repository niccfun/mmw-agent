package licenselease

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"mmw-agent/internal/guardclient"
)

type fakeGuard struct {
	mu          sync.Mutex
	status      guardclient.SlotStatus
	activated   int
	refreshed   int
	released    int
	refreshFail bool
}

func (f *fakeGuard) Enabled() bool { return true }

func (f *fakeGuard) SlotStatus(context.Context) (guardclient.SlotStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, nil
}

func (f *fakeGuard) ActivateSlot(_ context.Context, delivery guardclient.SlotDelivery) (guardclient.SlotStatus, error) {
	if delivery.Reservation == "" || delivery.LicenseServerURL == "" {
		return guardclient.SlotStatus{}, errors.New("invalid reservation")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activated++
	f.status = guardclient.SlotStatus{
		Authorized: true, Renewable: true, ServerHash: "server", SlotID: 7, Generation: 3,
		ExpiresAt: time.Now().Add(time.Hour).Unix(), Features: []string{"limiter"},
	}
	return f.status, nil
}

func (f *fakeGuard) RefreshSlot(context.Context) (guardclient.SlotStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshed++
	if f.refreshFail {
		f.status = guardclient.SlotStatus{}
		return guardclient.SlotStatus{}, errors.New("license unavailable")
	}
	f.status.ExpiresAt = time.Now().Add(time.Hour).Unix()
	return f.status, nil
}

func (f *fakeGuard) ReleaseSlot(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released++
	f.status = guardclient.SlotStatus{}
	return nil
}

func TestManagerDelegatesSlotAuthorityToGuard(t *testing.T) {
	fake := &fakeGuard{}
	statePath := filepath.Join(t.TempDir(), "legacy-agent-license.json")
	if err := os.WriteFile(statePath, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := New("ignored", statePath, "ignored", fake)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Authorized() {
		t.Fatal("open Agent unexpectedly owns quota authority")
	}
	if err := manager.HandleDelivery(Delivery{Reservation: "signed-reservation", LicenseServerURL: "https://license.example"}); err != nil {
		t.Fatal(err)
	}
	if !manager.Authorized() || !manager.HasFeature("limiter") || manager.NeedsLease() {
		t.Fatal("Guard status was not applied")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("legacy open-Agent lease state was not removed")
	}
	if err := manager.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	if manager.Authorized() || !manager.NeedsLease() {
		t.Fatal("released Guard slot remained authorized")
	}
}

func TestManagerRejectsMissingGuard(t *testing.T) {
	if _, err := New("", "", "", nil); err == nil {
		t.Fatal("manager accepted a missing Guard")
	}
}

func TestManagerRequestsNewReservationAfterGraceIsExhausted(t *testing.T) {
	fake := &fakeGuard{refreshFail: true, status: guardclient.SlotStatus{
		Authorized: false, Renewable: true, SlotID: 1, Generation: 1, ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	}}
	manager, err := New("", filepath.Join(t.TempDir(), "state"), "", fake)
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.nextRefresh = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.refreshIfNeeded(t.Context())
	if !manager.NeedsLease() {
		t.Fatal("exhausted Guard grace did not request a fresh reservation")
	}
}

func TestManagerReleasesSlotSignedForPreviousTokenOnStartup(t *testing.T) {
	fake := &fakeGuard{status: guardclient.SlotStatus{
		Authorized: true, Renewable: true, ServerHash: hashServerToken("old-token"),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}}
	manager, err := New("identity", filepath.Join(t.TempDir(), "state"), "new-token", fake)
	if err != nil {
		t.Fatal(err)
	}
	if fake.released != 1 {
		t.Fatalf("stale slot release count = %d, want 1", fake.released)
	}
	if !manager.NeedsLease() || manager.Authorized() {
		t.Fatal("manager did not request a replacement lease after stale slot release")
	}
}

func TestManagerReleasesSlotWhenServerTokenRotates(t *testing.T) {
	fake := &fakeGuard{status: guardclient.SlotStatus{
		Authorized: true, Renewable: true, ServerHash: hashServerToken("old-token"),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}}
	manager, err := New("identity", filepath.Join(t.TempDir(), "state"), "old-token", fake)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdateServerToken("new-token"); err != nil {
		t.Fatal(err)
	}
	if fake.released != 1 {
		t.Fatalf("rotated-token slot release count = %d, want 1", fake.released)
	}
	if manager.ServerHash() != hashServerToken("new-token") || !manager.NeedsLease() {
		t.Fatal("manager retained the previous token slot after rotation")
	}
}
