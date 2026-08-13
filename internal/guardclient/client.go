package guardclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Mode string

const (
	ModeOff      Mode = "off"
	ModeOptional Mode = "optional"
	ModeRequired Mode = "required"
)

type AttestationRequest struct {
	Action      string `json:"action"`
	PayloadHash string `json:"payload_hash"`
	ServerHash  string `json:"server_hash"`
}

type Attestation struct {
	Version         int    `json:"version"`
	ID              string `json:"id"`
	Role            string `json:"role"`
	Action          string `json:"action"`
	PayloadHash     string `json:"payload_hash"`
	ServerHash      string `json:"server_hash"`
	ChallengeID     string `json:"challenge_id,omitempty"`
	FrontendKeyHash string `json:"frontend_key_hash,omitempty"`
	IssuedAt        int64  `json:"issued_at"`
	ExpiresAt       int64  `json:"expires_at"`
	PublicKey       string `json:"public_key"`
	Signature       string `json:"signature"`
}

type ConsumeRequest struct {
	Grant            string `json:"grant"`
	Action           string `json:"action"`
	PayloadHash      string `json:"payload_hash"`
	ServerHash       string `json:"server_hash"`
	LicenseServerURL string `json:"license_server_url"`
}

type SlotDelivery struct {
	Reservation      string `json:"reservation"`
	LicenseServerURL string `json:"license_server_url"`
}

type SlotStatus struct {
	Authorized bool     `json:"authorized"`
	Renewable  bool     `json:"renewable,omitempty"`
	ServerHash string   `json:"server_hash,omitempty"`
	SlotID     int64    `json:"slot_id,omitempty"`
	Generation int64    `json:"generation,omitempty"`
	ExpiresAt  int64    `json:"expires_at,omitempty"`
	Features   []string `json:"features,omitempty"`
}

type Health struct {
	OK             bool   `json:"ok"`
	Role           string `json:"role"`
	Version        string `json:"version"`
	CallerVerified bool   `json:"caller_verified"`
}

type Client struct {
	mode Mode
	http *http.Client
}

func NewFromEnv() *Client {
	mode := Mode(strings.ToLower(strings.TrimSpace(os.Getenv("MMWX_ACTION_GUARD"))))
	switch mode {
	case ModeOff, ModeOptional, ModeRequired:
	default:
		mode = ModeOff
	}
	socket := strings.TrimSpace(os.Getenv("MMWX_GUARD_SOCKET"))
	if socket == "" {
		socket = "/run/mmwx-guard/guard.sock"
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{mode: mode, http: &http.Client{Transport: transport, Timeout: 20 * time.Second}}
}

// NewForSocket is used by integration tests and local packaging checks. The
// production path remains environment-driven so the open Agent cannot choose
// a remote substitute for the local Guard.
func NewForSocket(mode Mode, socket string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{mode: mode, http: &http.Client{Transport: transport, Timeout: 20 * time.Second}}
}

func (c *Client) Enabled() bool  { return c != nil && c.mode != ModeOff }
func (c *Client) Required() bool { return c != nil && c.mode == ModeRequired }

func (c *Client) Health(ctx context.Context) (Health, error) {
	var result Health
	err := c.call(ctx, http.MethodGet, "/v1/health", nil, &result)
	return result, err
}

func (c *Client) Attest(ctx context.Context, request AttestationRequest) (Attestation, error) {
	var result Attestation
	err := c.call(ctx, http.MethodPost, "/v1/attestations", request, &result)
	return result, err
}

func (c *Client) Consume(ctx context.Context, request ConsumeRequest) error {
	return c.call(ctx, http.MethodPost, "/v1/grants/consume", request, nil)
}

func (c *Client) ActivateSlot(ctx context.Context, delivery SlotDelivery) (SlotStatus, error) {
	var result SlotStatus
	err := c.call(ctx, http.MethodPost, "/v1/slots/activate", delivery, &result)
	return result, err
}

func (c *Client) RefreshSlot(ctx context.Context) (SlotStatus, error) {
	var result SlotStatus
	err := c.call(ctx, http.MethodPost, "/v1/slots/refresh", map[string]any{}, &result)
	return result, err
}

func (c *Client) ReleaseSlot(ctx context.Context) error {
	return c.call(ctx, http.MethodPost, "/v1/slots/release", map[string]any{}, nil)
}

func (c *Client) SlotStatus(ctx context.Context) (SlotStatus, error) {
	var result SlotStatus
	err := c.call(ctx, http.MethodGet, "/v1/slots/status", nil, &result)
	return result, err
}

func (c *Client) call(ctx context.Context, method, path string, request, response any) error {
	if !c.Enabled() {
		return errors.New("Action Guard 未启用")
	}
	var body []byte
	var err error
	if request != nil {
		body, err = json.Marshal(request)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Action Guard 不可用: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var result struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &result)
		if result.Error == "" {
			result.Error = strings.TrimSpace(string(data))
		}
		return errors.New(result.Error)
	}
	if response != nil && json.Unmarshal(data, response) != nil {
		return errors.New("Action Guard 返回无效响应")
	}
	return nil
}
