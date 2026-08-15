package embedded

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/core"

	mydispatcher "mmw-agent/internal/dispatcher"
	"mmw-agent/internal/limiter"
)

func TestLimiterConfigPersistsAndReplaysTrackingBeforeStart(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	ex := New(configPath)
	target := limiter.New()
	ex.mu.Lock()
	ex.dispatcher = &mydispatcher.Dispatcher{Limiter: target}
	ex.instance = &core.Instance{}
	ex.mu.Unlock()

	cfg := LimiterConfig{
		InboundTag: "inbound-a", Generation: "generation-1", ExpectedCount: 1,
		Users: []limiter.UserInfo{{
			Email: "alice@example.com", DeviceLimit: 1,
			ConnGroup: "alice|10", ConnStatGroup: "alice|20",
		}},
		Enforce: false,
	}
	if !ex.ApplyLimiterConfig(cfg) {
		t.Fatal("tracking config did not become ready")
	}
	firstOK, first := target.AcquireConn("inbound-a", "alice@example.com")
	secondOK, second := target.AcquireConn("inbound-a", "alice@example.com")
	if !firstOK || !secondOK {
		t.Fatal("tracking-only config unexpectedly enforced the paid connection limit")
	}
	target.ReleaseConn(first)
	target.ReleaseConn(second)

	statePath := configPath + ".limiter-state.json"
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("limiter state mode = %o, want 600", info.Mode().Perm())
	}

	reloaded := New(configPath)
	if reloaded.LimiterGeneration() != "generation-1" || len(reloaded.limiterConfigs) != 1 {
		t.Fatal("persisted limiter generation was not reloaded")
	}
	preStartLimiter := limiter.New()
	applyLimiterConfigs(preStartLimiter, cloneLimiterConfigs(reloaded.limiterConfigs))
	ok, lease := preStartLimiter.AcquireConn("inbound-a", "alice@example.com")
	if !ok || lease.QuotaGroup != "alice|10" || lease.StatGroup != "alice|20" {
		t.Fatalf("pre-start replay did not restore connection identity: %+v", lease)
	}
	preStartLimiter.ReleaseConn(lease)
}

func TestReplayLimiterConfigsPromotesCachedLimitsAfterLease(t *testing.T) {
	ex := New(filepath.Join(t.TempDir(), "config.json"))
	target := limiter.New()
	ex.mu.Lock()
	ex.dispatcher = &mydispatcher.Dispatcher{Limiter: target}
	ex.instance = &core.Instance{}
	ex.mu.Unlock()
	ex.ApplyLimiterConfig(LimiterConfig{
		InboundTag: "inbound-a", Generation: "g", ExpectedCount: 1,
		Users:   []limiter.UserInfo{{Email: "alice", DeviceLimit: 1, ConnGroup: "alice|1"}},
		Enforce: false,
	})
	if got := ex.ReplayLimiterConfigs(true); got != 1 {
		t.Fatalf("replayed configs = %d, want 1", got)
	}
	ok, lease := target.AcquireConn("inbound-a", "alice")
	if !ok {
		t.Fatal("first connection was rejected")
	}
	if ok, _ := target.AcquireConn("inbound-a", "alice"); ok {
		t.Fatal("cached connection limit was not promoted after lease activation")
	}
	target.ReleaseConn(lease)
}
