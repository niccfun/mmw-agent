package licenselease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"mmw-agent/internal/guardclient"
)

type Delivery struct {
	Reservation      string `json:"reservation"`
	LicenseServerURL string `json:"license_server_url"`
	ExpiresAt        int64  `json:"reservation_expires_at"`
}

type Manager struct {
	mu            sync.RWMutex
	guard         guardAuthority
	statePath     string
	status        guardclient.SlotStatus
	serverHash    string
	nextRefresh   time.Time
	lastEffective bool
	onChange      func(bool)
}

type guardAuthority interface {
	Enabled() bool
	SlotStatus(context.Context) (guardclient.SlotStatus, error)
	ActivateSlot(context.Context, guardclient.SlotDelivery) (guardclient.SlotStatus, error)
	RefreshSlot(context.Context) (guardclient.SlotStatus, error)
	ReleaseSlot(context.Context) error
}

func New(_ string, statePath, serverToken string, guard guardAuthority) (*Manager, error) {
	if guard == nil || !guard.Enabled() {
		return nil, errors.New("Agent Guard is required for authoritative server slots")
	}
	m := &Manager{guard: guard, statePath: statePath, serverHash: hashServerToken(serverToken)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if status, err := guard.SlotStatus(ctx); err == nil {
		if m.slotMatchesToken(status) {
			m.applyStatus(status)
		} else if err := guard.ReleaseSlot(ctx); err != nil {
			return nil, errors.New("release stale authoritative slot: " + err.Error())
		}
	}
	return m, nil
}

func (m *Manager) Required() bool { return true }

func (m *Manager) UpdateServerToken(token string) error {
	newHash := hashServerToken(token)
	m.mu.Lock()
	m.serverHash = newHash
	status := m.status
	m.mu.Unlock()
	if m.slotMatchesToken(status) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.guard.ReleaseSlot(ctx); err != nil {
		return errors.New("release stale authoritative slot: " + err.Error())
	}
	m.applyStatus(guardclient.SlotStatus{})
	_ = os.Remove(m.statePath)
	return nil
}

func (m *Manager) Status() guardclient.SlotStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Manager) ServerHash() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.serverHash
}

func (m *Manager) slotMatchesToken(status guardclient.SlotStatus) bool {
	if status.ServerHash == "" {
		return !status.Authorized && !status.Renewable && status.SlotID == 0
	}
	return status.ServerHash == m.ServerHash()
}

func hashServerToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) SetAuthorizationHandler(fn func(bool)) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

func (m *Manager) Authorized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status.Authorized && m.status.ExpiresAt > time.Now().Unix()
}

func (m *Manager) NeedsLease() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.status.Authorized && !m.status.Renewable
}

func (m *Manager) HasFeature(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.status.Authorized || m.status.ExpiresAt <= time.Now().Unix() {
		return false
	}
	for _, feature := range m.status.Features {
		if feature == name {
			return true
		}
	}
	return false
}

func (m *Manager) HandleDelivery(delivery Delivery) error {
	if delivery.Reservation == "" || delivery.LicenseServerURL == "" {
		return errors.New("invalid server slot reservation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	status, err := m.guard.ActivateSlot(ctx, guardclient.SlotDelivery{
		Reservation: delivery.Reservation, LicenseServerURL: delivery.LicenseServerURL,
	})
	if err != nil {
		return err
	}
	m.applyStatus(status)
	// The Guard owns the only persistent lease. Remove legacy open-Agent state
	// so neither reservations nor signed leases remain reusable from this file.
	_ = os.Remove(m.statePath)
	return nil
}

func (m *Manager) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.refreshIfNeeded(ctx)
			}
		}
	}()
}

func (m *Manager) refreshIfNeeded(ctx context.Context) {
	m.mu.RLock()
	due := m.status.Renewable && (m.nextRefresh.IsZero() || !time.Now().Before(m.nextRefresh))
	m.mu.RUnlock()
	if !due {
		m.notifyIfChanged()
		return
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	status, err := m.guard.RefreshSlot(refreshCtx)
	if err != nil {
		// Re-read Guard state so an exhausted grace period transitions back to
		// NeedsLease. Otherwise a cached renewable=true could suppress new
		// reservations forever after a prolonged outage.
		if current, statusErr := m.guard.SlotStatus(refreshCtx); statusErr == nil {
			m.applyStatus(current)
		}
		m.mu.Lock()
		m.nextRefresh = time.Now().Add(30 * time.Second)
		m.mu.Unlock()
		m.notifyIfChanged()
		return
	}
	m.applyStatus(status)
}

func (m *Manager) Release(ctx context.Context) error {
	if err := m.guard.ReleaseSlot(ctx); err != nil {
		return err
	}
	m.applyStatus(guardclient.SlotStatus{})
	_ = os.Remove(m.statePath)
	return nil
}

func (m *Manager) applyStatus(status guardclient.SlotStatus) {
	m.mu.Lock()
	m.status = status
	if status.ExpiresAt > 0 {
		remaining := time.Until(time.Unix(status.ExpiresAt, 0))
		if remaining <= 0 {
			m.nextRefresh = time.Now()
		} else {
			m.nextRefresh = time.Now().Add(remaining / 3)
		}
	}
	effective := status.Authorized && status.ExpiresAt > time.Now().Unix()
	changed := effective != m.lastEffective
	m.lastEffective = effective
	fn := m.onChange
	m.mu.Unlock()
	if changed && fn != nil {
		fn(effective)
	}
}

func (m *Manager) notifyIfChanged() {
	effective := m.Authorized()
	m.mu.Lock()
	if effective == m.lastEffective {
		m.mu.Unlock()
		return
	}
	m.lastEffective = effective
	fn := m.onChange
	m.mu.Unlock()
	if fn != nil {
		fn(effective)
	}
}
