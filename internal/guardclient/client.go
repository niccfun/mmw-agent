package guardclient

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
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

type SlotCapabilities struct {
	LeaseIdentity bool `json:"lease_identity"`
}

type SlotStatus struct {
	Authorized     bool             `json:"authorized"`
	Renewable      bool             `json:"renewable,omitempty"`
	ServerHash     string           `json:"server_hash,omitempty"`
	LicenseKeyHash string           `json:"license_key_hash,omitempty"`
	SlotID         int64            `json:"slot_id,omitempty"`
	Generation     int64            `json:"generation,omitempty"`
	ExpiresAt      int64            `json:"expires_at,omitempty"`
	Features       []string         `json:"features,omitempty"`
	Capabilities   SlotCapabilities `json:"capabilities,omitempty"`
}

type Health struct {
	OK             bool   `json:"ok"`
	Role           string `json:"role"`
	Version        string `json:"version"`
	CallerVerified bool   `json:"caller_verified"`
}

type Client struct {
	socket string
	http   *http.Client
	secure *secureState
}

func NewFromEnv() *Client {
	socket := strings.TrimSpace(os.Getenv("MMWX_GUARD_SOCKET"))
	if socket == "" {
		socket = "/run/mmwx-guard-agent/guard.sock"
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{
		socket: socket, http: &http.Client{Transport: transport, Timeout: 20 * time.Second},
		secure: newSecureState("agent"),
	}
}

// NewForSocket is used by integration tests and local packaging checks. The
// production path only permits changing the local Unix Socket path; Guard is
// mandatory and cannot be downgraded through configuration.
func NewForSocket(socket string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{
		socket: socket, http: &http.Client{Transport: transport, Timeout: 20 * time.Second},
		secure: newSecureState("agent"),
	}
}

func (c *Client) Enabled() bool  { return c != nil }
func (c *Client) Required() bool { return c != nil }

func (c *Client) Health(ctx context.Context) (Health, error) {
	var result Health
	err := c.call(ctx, http.MethodPost, "/v1/secure-health", nil, &result)
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
	return c.secureCall(ctx, method, path, request, response)
}
