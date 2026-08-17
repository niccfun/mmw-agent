package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"mmw-agent/internal/config"
	"mmw-agent/internal/guardclient"
	"mmw-agent/internal/licenselease"
)

type leaseCapabilityGuard struct {
	status guardclient.SlotStatus
}

func (g *leaseCapabilityGuard) Enabled() bool { return true }

func (g *leaseCapabilityGuard) SlotStatus(context.Context) (guardclient.SlotStatus, error) {
	return g.status, nil
}

func (g *leaseCapabilityGuard) ActivateSlot(context.Context, guardclient.SlotDelivery) (guardclient.SlotStatus, error) {
	return g.status, nil
}

func (g *leaseCapabilityGuard) RefreshSlot(context.Context) (guardclient.SlotStatus, error) {
	return g.status, nil
}

func (g *leaseCapabilityGuard) ReleaseSlot(context.Context) error { return nil }

func TestAuthLeaseIdentityCapabilityTracksGuardStatus(t *testing.T) {
	for _, tt := range []struct {
		name         string
		capable      bool
		identity     string
		wantIdentity string
	}{
		{name: "legacy Guard test.3", capable: false, identity: "", wantIdentity: ""},
		{name: "new Guard", capable: true, identity: "license-key-hash", wantIdentity: "license-key-hash"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := clientWithGuardStatus(t, tt.capable, tt.identity)
			capabilities := client.agentCapabilities(true)
			if got := capabilities["lease_identity"]; got != tt.capable {
				t.Fatalf("auth lease_identity = %v, want %v", got, tt.capable)
			}
			if got := client.agentLeaseIdentity(); got != tt.wantIdentity {
				t.Fatalf("auth lease identity = %q, want %q", got, tt.wantIdentity)
			}
		})
	}
}

func TestHeartbeatLeaseIdentityCapabilityTracksGuardStatus(t *testing.T) {
	modes := []struct {
		name                string
		includeLeaseCapable bool
	}{
		{name: "websocket", includeLeaseCapable: false},
		{name: "http", includeLeaseCapable: true},
	}
	for _, tt := range []struct {
		name     string
		capable  bool
		identity string
	}{
		{name: "legacy Guard test.3", capable: false},
		{name: "new Guard", capable: true, identity: "license-key-hash"},
	} {
		for _, mode := range modes {
			t.Run(tt.name+"/"+mode.name, func(t *testing.T) {
				client := clientWithGuardStatus(t, tt.capable, tt.identity)
				client.setLastLeaseRequestID("lease-request-7")
				payload := map[string]any{}
				client.addAgentLeasePayload(payload, mode.includeLeaseCapable)
				if got := payload["agent_lease_identity_capable"]; got != tt.capable {
					t.Fatalf("heartbeat identity capability = %v, want %v", got, tt.capable)
				}
				if got := payload["agent_lease_identity"]; got != tt.identity {
					t.Fatalf("heartbeat identity = %q, want %q", got, tt.identity)
				}
				gotLeaseCapable, present := payload["agent_lease_capable"]
				if present != mode.includeLeaseCapable {
					t.Fatalf("agent_lease_capable presence = %v, want %v", present, mode.includeLeaseCapable)
				}
				if present && gotLeaseCapable != true {
					t.Fatalf("heartbeat Guard lease capability = %v, want true", gotLeaseCapable)
				}
				if got := payload["agent_lease_ack_id"]; got != "lease-request-7" {
					t.Fatalf("heartbeat lease ACK id = %v", got)
				}
				if got := payload["agent_lease_request_id_capable"]; got != true {
					t.Fatalf("heartbeat request-id capability = %v", got)
				}
			})
		}
	}
}

func TestAgentAdvertisesLeaseRequestIDCapability(t *testing.T) {
	client := clientWithGuardStatus(t, false, "")
	if !client.agentCapabilities(true)["lease_request_id"] {
		t.Fatal("Agent must advertise request-id ACK support")
	}
}

func TestHTTPHeartbeatReportsStructuredLeaseActivationFailure(t *testing.T) {
	client := clientWithGuardStatus(t, true, "license-key-hash")
	client.setLastLeaseFailure("lease-request-9", &guardclient.RequestError{
		Message: "license service rejected request: too many requests",
		Code:    "rate_limited", StatusCode: 429, UpstreamStatus: 429,
		RetryAfter: 11 * time.Second,
	})
	payload := map[string]any{}
	client.addAgentLeasePayload(payload, true)
	failure, ok := payload["agent_lease_failure"].(*agentLeaseFailure)
	if !ok {
		t.Fatalf("agent_lease_failure type = %T", payload["agent_lease_failure"])
	}
	if failure.RequestID != "lease-request-9" || failure.Code != "rate_limited" ||
		failure.UpstreamStatus != 429 || failure.RetryAfter != 11 {
		t.Fatalf("unexpected lease failure: %#v", failure)
	}

	client.setLastLeaseRequestID("lease-request-10")
	payload = map[string]any{}
	client.addAgentLeasePayload(payload, true)
	if _, present := payload["agent_lease_failure"]; present {
		t.Fatal("successful activation did not clear previous failure")
	}
}

func clientWithGuardStatus(t *testing.T, capable bool, identity string) *Client {
	t.Helper()
	const token = "server-token"
	sum := sha256.Sum256([]byte(token))
	manager, err := licenselease.New("", filepath.Join(t.TempDir(), "legacy-state"), token, &leaseCapabilityGuard{
		status: guardclient.SlotStatus{
			Authorized: true, Renewable: true,
			ServerHash: hex.EncodeToString(sum[:]), LicenseKeyHash: identity,
			SlotID: 1, Generation: 1, ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Capabilities: guardclient.SlotCapabilities{LeaseIdentity: capable},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(&config.Config{Token: token})
	client.SetLeaseManager(manager)
	return client
}
