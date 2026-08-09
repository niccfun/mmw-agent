package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateUniqueInboundClientsRejectsDuplicateEmail(t *testing.T) {
	cfg := map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": "in-1",
			"settings": map[string]interface{}{
				"clients": []interface{}{
					map[string]interface{}{"email": "alice", "id": "one"},
					map[string]interface{}{"email": "alice", "id": "two"},
				},
			},
		}},
	}
	if err := validateUniqueInboundClients(cfg); err == nil || !strings.Contains(err.Error(), "duplicate email") {
		t.Fatalf("expected duplicate email error, got %v", err)
	}
}

func TestValidateUniqueInboundClientsRejectsDuplicateCredential(t *testing.T) {
	cfg := map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": "in-1",
			"settings": map[string]interface{}{
				"clients": []interface{}{
					map[string]interface{}{"email": "alice", "id": "same"},
					map[string]interface{}{"email": "bob", "id": "same"},
				},
			},
		}},
	}
	if err := validateUniqueInboundClients(cfg); err == nil || !strings.Contains(err.Error(), "duplicate credential") {
		t.Fatalf("expected duplicate credential error, got %v", err)
	}
}

func TestConfigTransactionMetadataRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "txn", "meta.json")
	want := &xrayConfigTxnMeta{
		OperationID: "package-test-1",
		ConfigPath:  "/tmp/config.json",
		OldHash:     "old",
		NewHash:     "new",
		State:       "prepared",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := saveConfigTxnMeta(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfigTxnMeta(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.OperationID != want.OperationID || got.State != want.State || got.OldHash != want.OldHash || got.NewHash != want.NewHash {
		t.Fatalf("metadata mismatch: %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("metadata mode=%o, want 600", info.Mode().Perm())
	}
}
