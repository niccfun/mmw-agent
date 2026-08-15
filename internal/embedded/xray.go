package embedded

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	feature_outbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
	xproxy "github.com/xtls/xray-core/proxy"

	mydispatcher "mmw-agent/internal/dispatcher"
	"mmw-agent/internal/limiter"
)

type LimiterConfig struct {
	InboundTag     string               `json:"inbound_tag"`
	NodeLimit      uint64               `json:"node_limit"`
	Users          []limiter.UserInfo   `json:"users"`
	AutoSpeedRules []AutoSpeedLimitRule `json:"auto_speed_rules,omitempty"`
	Generation     string               `json:"generation,omitempty"`
	ExpectedCount  int                  `json:"expected_count,omitempty"`
	Enforce        bool                 `json:"enforce"`
}

type EmbeddedXray struct {
	configPath        string
	instance          *core.Instance
	dispatcher        *mydispatcher.Dispatcher
	statsManager      stats.Manager
	speedMonitor      *SpeedMonitor
	limiterConfigs    map[string]LimiterConfig
	limiterGeneration string
	limiterExpected   int
	limiterReceived   map[string]struct{}
	limiterReady      bool
	mu                sync.RWMutex
}

func New(configPath string) *EmbeddedXray {
	e := &EmbeddedXray{
		configPath: configPath, speedMonitor: NewSpeedMonitor(),
		limiterConfigs: make(map[string]LimiterConfig), limiterReceived: make(map[string]struct{}),
	}
	e.loadLimiterState()
	return e
}

type limiterState struct {
	Generation string                   `json:"generation"`
	Expected   int                      `json:"expected"`
	Configs    map[string]LimiterConfig `json:"configs"`
}

func (e *EmbeddedXray) limiterStatePath() string {
	return e.configPath + ".limiter-state.json"
}

func (e *EmbeddedXray) loadLimiterState() {
	data, err := os.ReadFile(e.limiterStatePath())
	if err != nil {
		return
	}
	var state limiterState
	if json.Unmarshal(data, &state) != nil || len(state.Configs) == 0 {
		return
	}
	e.limiterGeneration = state.Generation
	e.limiterExpected = state.Expected
	e.limiterConfigs = state.Configs
	for tag := range state.Configs {
		e.limiterReceived[tag] = struct{}{}
	}
	log.Printf("[EmbeddedXray] Loaded %d persisted limiter configs (generation=%s)", len(state.Configs), state.Generation)
}

func (e *EmbeddedXray) persistLimiterStateLocked() {
	state := limiterState{Generation: e.limiterGeneration, Expected: e.limiterExpected, Configs: cloneLimiterConfigs(e.limiterConfigs)}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	path := e.limiterStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		_ = os.Rename(tmp, path)
	}
}

func (e *EmbeddedXray) GetSpeedMonitor() *SpeedMonitor {
	return e.speedMonitor
}

func (e *EmbeddedXray) Start() (retErr error) {
	// xray-core 内部偶发 panic(端口冲突 / 配置异常等)。没有 recover 时整个 agent 进程被带崩,
	// 主控看到 "connection reset by peer";加 recover 后返回 error,handler 正常回 500。
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("xray start panicked: %v", r)
		}
	}()
	pbConfig, err := buildCoreConfig(e.configPath)
	if err != nil {
		return err
	}

	instance, err := e.safeNewInstance(pbConfig)
	if err != nil {
		return err
	}

	var d *mydispatcher.Dispatcher
	if feature := instance.GetFeature(mydispatcher.Type()); feature != nil {
		d, _ = feature.(*mydispatcher.Dispatcher)
	}
	if d == nil || d.Limiter == nil {
		instance.Close()
		return fmt.Errorf("embedded dispatcher limiter is unavailable")
	}

	// Rehydrate the newly-created dispatcher before instance.Start opens any
	// inbound listener. This removes the restart window where connections were
	// accepted without identity, counting, or limiter state.
	e.mu.Lock()
	e.dispatcher = d
	configs := cloneLimiterConfigs(e.limiterConfigs)
	e.limiterReady = false
	e.mu.Unlock()
	applyLimiterConfigs(d.Limiter, configs)
	e.installVisionLimiterHook()

	if err := e.safeInstanceStart(instance); err != nil {
		e.mu.Lock()
		if e.dispatcher == d {
			e.dispatcher = nil
		}
		e.mu.Unlock()
		instance.Close()
		return err
	}

	e.mu.Lock()
	e.instance = instance
	e.statsManager, _ = instance.GetFeature(stats.ManagerType()).(stats.Manager)
	e.limiterReady = len(configs) > 0 && e.limiterConfigCompleteLocked()
	e.mu.Unlock()

	e.speedMonitor.SetLimiter(d.Limiter)
	for _, cfg := range configs {
		if len(cfg.AutoSpeedRules) > 0 {
			e.speedMonitor.UpdateRules(cfg.AutoSpeedRules)
		}
	}

	log.Printf("[EmbeddedXray] Started successfully (limiter configs=%d, connection_count_ready=%v)", len(configs), e.ConnectionCountReady())
	return nil
}

func (e *EmbeddedXray) installVisionLimiterHook() {
	xproxy.SetVisionLimiterHook(func(email string, rawConn xnet.Conn) xnet.Conn {
		l := e.GetLimiter()
		if l == nil {
			log.Printf("[VisionLimiter] %s: skip (limiter not ready)", email)
			return nil
		}
		bucket := l.LookupBucketByEmail(email)
		if bucket == nil {
			return nil
		}
		return limiter.NewRateLimitedConn(rawConn, bucket)
	})
}

func (e *EmbeddedXray) safeNewInstance(pbConfig *core.Config) (inst *core.Instance, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xray core.New panicked: %v", r)
		}
	}()
	inst, err = core.New(pbConfig)
	return
}

// safeInstanceStart 把 instance.Start 包在 recover 里 — xray-core 启动期 panic 不再带崩 agent 进程。
func (e *EmbeddedXray) safeInstanceStart(inst *core.Instance) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xray instance.Start panicked: %v", r)
		}
	}()
	return inst.Start()
}

func (e *EmbeddedXray) Stop() (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("xray stop panicked: %v", r)
		}
	}()
	e.mu.Lock()
	instance := e.instance
	e.instance = nil
	e.dispatcher = nil
	e.statsManager = nil
	e.limiterReady = false
	e.mu.Unlock()

	if instance != nil {
		return instance.Close()
	}
	return nil
}

func (e *EmbeddedXray) Restart() error {
	log.Printf("[EmbeddedXray] Restarting...")
	if err := e.Stop(); err != nil {
		log.Printf("[EmbeddedXray] Stop error: %v", err)
	}
	// Wait for OS to release listener ports (metrics, gRPC API)
	time.Sleep(500 * time.Millisecond)

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		lastErr = e.Start()
		if lastErr == nil {
			return nil
		}
		log.Printf("[EmbeddedXray] Start attempt %d failed: %v", attempt, lastErr)
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	return lastErr
}

func (e *EmbeddedXray) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.instance != nil
}

func (e *EmbeddedXray) GetLimiter() *limiter.Limiter {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.dispatcher != nil {
		return e.dispatcher.Limiter
	}
	return nil
}

func cloneLimiterConfigs(source map[string]LimiterConfig) map[string]LimiterConfig {
	out := make(map[string]LimiterConfig, len(source))
	for tag, cfg := range source {
		cfg.Users = append([]limiter.UserInfo(nil), cfg.Users...)
		cfg.AutoSpeedRules = append([]AutoSpeedLimitRule(nil), cfg.AutoSpeedRules...)
		out[tag] = cfg
	}
	return out
}

func effectiveLimiterConfig(cfg LimiterConfig) LimiterConfig {
	if cfg.Enforce {
		return cfg
	}
	cfg.NodeLimit = 0
	cfg.AutoSpeedRules = nil
	cfg.Users = append([]limiter.UserInfo(nil), cfg.Users...)
	for i := range cfg.Users {
		cfg.Users[i].SpeedLimit = 0
		cfg.Users[i].DeviceLimit = 0
	}
	return cfg
}

func applyLimiterConfigs(target *limiter.Limiter, configs map[string]LimiterConfig) {
	if target == nil {
		return
	}
	for _, stored := range configs {
		cfg := effectiveLimiterConfig(stored)
		target.SyncInboundLimiter(cfg.InboundTag, cfg.NodeLimit, cfg.Users)
	}
}

func (e *EmbeddedXray) limiterConfigCompleteLocked() bool {
	expected := e.limiterExpected
	if expected <= 0 {
		expected = 1
	}
	return len(e.limiterReceived) >= expected
}

// ApplyLimiterConfig caches the full control-plane config outside the Xray
// instance. When enforce=false it still applies identity/group data with all
// limits zero, keeping connection statistics independent from the paid limiter.
func (e *EmbeddedXray) ApplyLimiterConfig(cfg LimiterConfig) bool {
	if cfg.InboundTag == "" {
		return false
	}
	e.mu.Lock()
	if cfg.Generation != "" && cfg.Generation != e.limiterGeneration {
		e.limiterGeneration = cfg.Generation
		e.limiterExpected = cfg.ExpectedCount
		e.limiterReceived = make(map[string]struct{})
	}
	if cfg.ExpectedCount > 0 {
		e.limiterExpected = cfg.ExpectedCount
	}
	e.limiterReceived[cfg.InboundTag] = struct{}{}
	e.limiterConfigs[cfg.InboundTag] = cfg
	if e.limiterConfigCompleteLocked() {
		for tag := range e.limiterConfigs {
			if _, current := e.limiterReceived[tag]; !current {
				delete(e.limiterConfigs, tag)
			}
		}
	}
	e.persistLimiterStateLocked()
	d := e.dispatcher
	running := e.instance != nil
	e.limiterReady = false
	e.mu.Unlock()

	if d == nil || d.Limiter == nil {
		return false
	}
	effective := effectiveLimiterConfig(cfg)
	d.Limiter.SyncInboundLimiter(effective.InboundTag, effective.NodeLimit, effective.Users)
	e.speedMonitor.SetLimiter(d.Limiter)
	if len(effective.AutoSpeedRules) > 0 {
		e.speedMonitor.UpdateRules(effective.AutoSpeedRules)
	}
	e.mu.Lock()
	e.limiterReady = running && e.limiterConfigCompleteLocked()
	ready := e.limiterReady
	e.mu.Unlock()
	return ready
}

// ReplayLimiterConfigs promotes cached tracking-only configs after lease
// activation, or restores them into a replacement dispatcher after restart.
func (e *EmbeddedXray) ReplayLimiterConfigs(enforce bool) int {
	e.mu.Lock()
	for tag, cfg := range e.limiterConfigs {
		cfg.Enforce = enforce
		e.limiterConfigs[tag] = cfg
	}
	e.persistLimiterStateLocked()
	configs := cloneLimiterConfigs(e.limiterConfigs)
	d := e.dispatcher
	running := e.instance != nil
	e.limiterReady = false
	e.mu.Unlock()
	if d == nil || d.Limiter == nil {
		return 0
	}
	applyLimiterConfigs(d.Limiter, configs)
	e.speedMonitor.SetLimiter(d.Limiter)
	for _, cfg := range configs {
		if cfg.Enforce && len(cfg.AutoSpeedRules) > 0 {
			e.speedMonitor.UpdateRules(cfg.AutoSpeedRules)
		}
	}
	e.mu.Lock()
	e.limiterReady = running && len(configs) > 0 && e.limiterConfigCompleteLocked()
	e.mu.Unlock()
	return len(configs)
}

func (e *EmbeddedXray) ConnectionCountReady() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.instance != nil && e.limiterReady
}

func (e *EmbeddedXray) LimiterGeneration() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.limiterGeneration
}

func (e *EmbeddedXray) UpdateLimiter(tag string, users []limiter.UserInfo) {
	l := e.GetLimiter()
	if l == nil {
		return
	}
	l.UpdateInboundLimiter(tag, users)
}

func (e *EmbeddedXray) GetOnlineUsers(tag string) map[string][]string {
	l := e.GetLimiter()
	if l == nil {
		return nil
	}
	return l.GetOnlineUsers(tag)
}

// AddUser adds a user to an inbound handler.
func (e *EmbeddedXray) AddUser(inboundTag string, user *protocol.User) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	ctx := context.Background()
	handler, err := ibm.GetHandler(ctx, inboundTag)
	if err != nil {
		return err
	}

	op := &command.AddUserOperation{User: user}
	return op.ApplyInbound(ctx, handler)
}

// RemoveUser removes a user from an inbound handler.
func (e *EmbeddedXray) RemoveUser(inboundTag string, email string) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	ctx := context.Background()
	handler, err := ibm.GetHandler(ctx, inboundTag)
	if err != nil {
		return err
	}

	op := &command.RemoveUserOperation{Email: email}
	return op.ApplyInbound(ctx, handler)
}

// AddInbound adds a new inbound handler from a core.InboundHandlerConfig.
func (e *EmbeddedXray) AddInbound(config *core.InboundHandlerConfig) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	rawHandler, err := core.CreateObject(instance, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(feature_inbound.Handler)
	if !ok {
		return errInvalidHandler
	}
	return ibm.AddHandler(context.Background(), handler)
}

// RemoveInbound removes an inbound handler by tag.
func (e *EmbeddedXray) RemoveInbound(tag string) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	return ibm.RemoveHandler(context.Background(), tag)
}

// ListInbounds returns all inbound handler tags.
func (e *EmbeddedXray) ListInbounds() []string {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return nil
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	handlers := ibm.ListHandlers(context.Background())
	tags := make([]string, 0, len(handlers))
	for _, h := range handlers {
		tags = append(tags, h.Tag())
	}
	return tags
}

// AddOutbound adds a new outbound handler.
func (e *EmbeddedXray) AddOutbound(config *core.OutboundHandlerConfig) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	obm := instance.GetFeature(feature_outbound.ManagerType()).(feature_outbound.Manager)
	rawHandler, err := core.CreateObject(instance, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(feature_outbound.Handler)
	if !ok {
		return errInvalidHandler
	}
	return obm.AddHandler(context.Background(), handler)
}

// RemoveOutbound removes an outbound handler by tag.
func (e *EmbeddedXray) RemoveOutbound(tag string) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	obm := instance.GetFeature(feature_outbound.ManagerType()).(feature_outbound.Manager)
	return obm.RemoveHandler(context.Background(), tag)
}

// GetTraffic returns a counter value by name pattern (e.g. "user>>>email>>>traffic>>>uplink").
func (e *EmbeddedXray) GetTraffic(name string) int64 {
	e.mu.RLock()
	sm := e.statsManager
	e.mu.RUnlock()
	if sm == nil {
		return 0
	}
	c := sm.GetCounter(name)
	if c == nil {
		return 0
	}
	return c.Value()
}

var (
	errNotRunning     = &EmbeddedError{"xray instance not running"}
	errInvalidHandler = &EmbeddedError{"created object is not a valid handler"}
)

type EmbeddedError struct {
	msg string
}

func (e *EmbeddedError) Error() string { return e.msg }
