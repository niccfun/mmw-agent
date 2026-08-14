package guardclient

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type secureTestSession struct {
	id             string
	clientToServer []byte
	serverToClient []byte
	clientMAC      []byte
	serverMAC      []byte
	received       uint64
	sent           uint64
}

func TestActionGuardCannotBeDisabledByEnvironment(t *testing.T) {
	t.Setenv("MMWX_ACTION_GUARD", "off")
	t.Setenv("MMWX_GUARD_SOCKET", "/tmp/mmwx-agent-test-guard.sock")

	client := NewFromEnv()
	if !client.Enabled() || !client.Required() {
		t.Fatal("current releases must always require Agent Guard")
	}
	if client.socket != "/tmp/mmwx-agent-test-guard.sock" {
		t.Fatalf("socket = %q", client.socket)
	}
}

func TestHealthUsesAuthenticatedEncryptedSession(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "guard.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	var session *secureTestSession
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		var request sessionRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		clientRaw, _ := base64.RawURLEncoding.DecodeString(request.ClientPublicKey)
		clientPublic, _ := ecdh.X25519().NewPublicKey(clientRaw)
		serverPrivate, _ := ecdh.X25519().GenerateKey(rand.Reader)
		shared, _ := serverPrivate.ECDH(clientPublic)
		clientNonce, _ := base64.RawURLEncoding.DecodeString(request.ClientNonce)
		serverNonce := make([]byte, 32)
		_, _ = rand.Read(serverNonce)
		callerHash, _ := currentExecutableSHA256()
		now := time.Now().Unix()
		response := sessionResponse{
			Version: secureProtocolVersion, SessionID: "test-session", Role: "agent",
			ServerPublicKey:        base64.RawURLEncoding.EncodeToString(serverPrivate.PublicKey().Bytes()),
			ServerNonce:            base64.RawURLEncoding.EncodeToString(serverNonce),
			GuardPublicKey:         base64.RawURLEncoding.EncodeToString(identity.Public().(ed25519.PublicKey)),
			CallerExecutableSHA256: callerHash, IssuedAt: now, ExpiresAt: now + 300,
		}
		response.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity, sessionResponseMessage(request, response)))
		keys := deriveSessionKeys(shared, clientNonce, serverNonce)
		session = &secureTestSession{
			id: response.SessionID, clientToServer: keys[:32], serverToClient: keys[32:64],
			clientMAC: keys[64:96], serverMAC: keys[96:128],
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("POST /v1/secure-health", func(w http.ResponseWriter, r *http.Request) {
		if session == nil {
			http.Error(w, "session missing", http.StatusUnauthorized)
			return
		}
		var envelope secureEnvelope
		if json.NewDecoder(r.Body).Decode(&envelope) != nil || envelope.Sequence != session.received+1 {
			http.Error(w, "bad envelope", http.StatusUnauthorized)
			return
		}
		if _, err := openSecureEnvelope(envelope, session.clientToServer, session.clientMAC,
			secureAAD("request", r.Method, r.URL.Path, 0, session.id, envelope.Sequence, envelope.Timestamp)); err != nil {
			http.Error(w, "bad mac", http.StatusUnauthorized)
			return
		}
		session.received = envelope.Sequence
		session.sent++
		plaintext := []byte(`{"ok":true,"role":"agent","version":"1.2.3","caller_verified":true}`)
		timestamp := time.Now().Unix()
		result, _ := sealSecureEnvelope(session.id, session.sent, timestamp, plaintext,
			session.serverToClient, session.serverMAC,
			secureAAD("response", r.Method, r.URL.Path, http.StatusOK, session.id, session.sent, timestamp))
		w.Header().Set("X-MMWX-Guard-Secure", "v1")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.Remove(socket)
	})

	client := NewForSocket(socket)
	result, err := client.Health(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Role != "agent" || result.Version != "1.2.3" || !result.CallerVerified {
		t.Fatalf("unexpected health result: %#v", result)
	}
	if session == nil || session.received != 1 || session.sent != 1 {
		t.Fatalf("secure envelope was not exchanged: %#v", session)
	}
}

func TestSecureEnvelopeRejectsTampering(t *testing.T) {
	key := make([]byte, 32)
	macKey := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, key)
	_, _ = io.ReadFull(rand.Reader, macKey)
	aad := secureAAD("request", http.MethodPost, "/v1/test", 0, "session", 1, time.Now().Unix())
	envelope, err := sealSecureEnvelope("session", 1, time.Now().Unix(), []byte("secret"), key, macKey, aad)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Ciphertext[0] == 'A' {
		envelope.Ciphertext = "B" + envelope.Ciphertext[1:]
	} else {
		envelope.Ciphertext = "A" + envelope.Ciphertext[1:]
	}
	if _, err := openSecureEnvelope(envelope, key, macKey, aad); err == nil {
		t.Fatal("tampered ciphertext passed message authentication")
	}
}
