package handler

import (
	"encoding/json"
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

func TestUpdateListenPortYAMLDefaultIsIdempotent(t *testing.T) {
	original := []byte("master_url: https://master.example\ntoken: secret\n")
	got, changed := updateListenPortYAML(original, 0)
	if changed {
		t.Fatal("default port without an explicit key must be a no-op")
	}
	if string(got) != string(original) {
		t.Fatalf("config changed: %q", got)
	}
}

func TestUpdateListenPortYAMLPreservesCredentials(t *testing.T) {
	original := []byte("master_url: https://master.example\ntoken: secret\nlisten_port: \"24680\"\nrecovery_url: http://master:12889\n")
	got, changed := updateListenPortYAML(original, 0)
	if !changed {
		t.Fatal("expected explicit port removal")
	}
	text := string(got)
	if strings.Contains(text, "listen_port:") {
		t.Fatalf("listen_port was not removed: %s", text)
	}
	for _, want := range []string{"token: secret", "master_url: https://master.example", "recovery_url: http://master:12889"} {
		if !strings.Contains(text, want) {
			t.Fatalf("lost config field %q: %s", want, text)
		}
	}
}

func TestAtomicWriteConfigReplacesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("token: old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteConfig(path, []byte("token: new\nmaster_url: https://master.example\n")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "token: new\nmaster_url: https://master.example\n" {
		t.Fatalf("unexpected config: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRemoveInboundRoutingReferences(t *testing.T) {
	config := map[string]interface{}{
		"routing": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"inboundTag": []interface{}{"old-in"}, "outboundTag": "drop"},
				map[string]interface{}{"inboundTag": []interface{}{"old-in", "keep-in"}, "outboundTag": "direct"},
				map[string]interface{}{"inboundTag": "old-in", "outboundTag": "proxy"},
				map[string]interface{}{"domain": []interface{}{"example.com"}, "outboundTag": "direct"},
			},
		},
	}

	if changed := removeInboundRoutingReferences(config, "old-in"); changed != 3 {
		t.Fatalf("removed references = %d, want 3", changed)
	}
	rules := config["routing"].(map[string]interface{})["rules"].([]interface{})
	if len(rules) != 2 {
		t.Fatalf("remaining rules = %d, want 2: %#v", len(rules), rules)
	}
	tags := rules[0].(map[string]interface{})["inboundTag"].([]interface{})
	if len(tags) != 1 || tags[0] != "keep-in" {
		t.Fatalf("multi-inbound rule was not narrowed correctly: %#v", tags)
	}
	if _, ok := rules[1].(map[string]interface{})["domain"]; !ok {
		t.Fatalf("unrelated routing rule was removed: %#v", rules[1])
	}
}

func TestRemoveInboundFromConfDir(t *testing.T) {
	dir := t.TempDir()
	single := filepath.Join(dir, "single.json")
	if err := os.WriteFile(single, []byte(`{"tag":"old-in","protocol":"vless","port":443}`), 0644); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle.json")
	bundleJSON := `{
  "inbounds": [
    {"tag":"old-in","protocol":"vless","port":8443},
    {"tag":"keep-in","protocol":"vmess","port":9443}
  ],
  "routing": {"rules": [
    {"inboundTag":["old-in","keep-in"],"outboundTag":"direct"}
  ]}
}`
	if err := os.WriteFile(bundle, []byte(bundleJSON), 0644); err != nil {
		t.Fatal(err)
	}

	routingChanged, err := removeInboundFromConfDir(dir, "", "old-in")
	if err != nil {
		t.Fatal(err)
	}
	if !routingChanged {
		t.Fatal("confdir routing reference was not reported as changed")
	}
	if _, err := os.Stat(single); !os.IsNotExist(err) {
		t.Fatalf("single-inbound fragment still exists: %v", err)
	}
	content, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]interface{})
	if len(inbounds) != 1 || inbounds[0].(map[string]interface{})["tag"] != "keep-in" {
		t.Fatalf("confdir inbounds not cleaned: %#v", inbounds)
	}
	rules := config["routing"].(map[string]interface{})["rules"].([]interface{})
	tags := rules[0].(map[string]interface{})["inboundTag"].([]interface{})
	if len(tags) != 1 || tags[0] != "keep-in" {
		t.Fatalf("confdir route not narrowed: %#v", tags)
	}
}
