package guardclient

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	secureProtocolVersion = 1
	secureClockSkew       = 60 * time.Second
	secureBodyLimit       = 1 << 20
)

var errSecureSessionRejected = errors.New("secure Guard session rejected")

type secureState struct {
	mu             sync.Mutex
	expectedRole   string
	guardPublicKey ed25519.PublicKey
	session        *clientSession
}

type clientSession struct {
	id               string
	expiresAt        int64
	clientToServer   []byte
	serverToClient   []byte
	clientMAC        []byte
	serverMAC        []byte
	sentSequence     uint64
	receivedSequence uint64
}

type sessionRequest struct {
	Version         int    `json:"version"`
	ClientPublicKey string `json:"client_public_key"`
	ClientNonce     string `json:"client_nonce"`
	Timestamp       int64  `json:"timestamp"`
}

type sessionResponse struct {
	Version                int    `json:"version"`
	SessionID              string `json:"session_id"`
	Role                   string `json:"role"`
	ServerPublicKey        string `json:"server_public_key"`
	ServerNonce            string `json:"server_nonce"`
	GuardPublicKey         string `json:"guard_public_key"`
	CallerExecutableSHA256 string `json:"caller_executable_sha256"`
	IssuedAt               int64  `json:"issued_at"`
	ExpiresAt              int64  `json:"expires_at"`
	Signature              string `json:"signature"`
}

type secureEnvelope struct {
	Version    int    `json:"version"`
	SessionID  string `json:"session_id"`
	Sequence   uint64 `json:"sequence"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	MAC        string `json:"mac"`
}

func newSecureState(expectedRole string) *secureState {
	return &secureState{expectedRole: expectedRole}
}

func (c *Client) secureCall(ctx context.Context, method, path string, request, response any) error {
	if c.secure == nil {
		c.secure = newSecureState("agent")
	}
	c.secure.mu.Lock()
	defer c.secure.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.secure.session == nil || c.secure.session.expiresAt <= time.Now().Unix()+5 {
			if err := c.startSecureSessionLocked(ctx); err != nil {
				return fmt.Errorf("Action Guard 不可用 (%s): %w", c.socket, err)
			}
		}
		err := c.secureRoundTripLocked(ctx, method, path, request, response)
		if errors.Is(err, errSecureSessionRejected) && attempt == 0 {
			c.secure.session = nil
			continue
		}
		return err
	}
	return errSecureSessionRejected
}

func (c *Client) startSecureSessionLocked(ctx context.Context) error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return err
	}
	request := sessionRequest{
		Version:         secureProtocolVersion,
		ClientPublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		ClientNonce:     base64.RawURLEncoding.EncodeToString(clientNonce), Timestamp: time.Now().Unix(),
	}
	body, _ := json.Marshal(request)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/sessions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpRequest)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, secureBodyLimit))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("会话协商返回 %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var result sessionResponse
	if json.Unmarshal(data, &result) != nil || result.Version != secureProtocolVersion || result.Role != c.secure.expectedRole ||
		result.SessionID == "" || !withinSecureClockSkew(result.IssuedAt) || result.ExpiresAt <= result.IssuedAt || result.ExpiresAt > result.IssuedAt+600 {
		return errors.New("Action Guard 会话响应无效")
	}
	guardPublicKey, err := decodeFixedURLBase64(result.GuardPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return errors.New("Action Guard 身份密钥无效")
	}
	signature, err := decodeFixedURLBase64(result.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(guardPublicKey), sessionResponseMessage(request, result), signature) {
		return errors.New("Action Guard 会话签名校验失败")
	}
	if len(c.secure.guardPublicKey) > 0 && subtle.ConstantTimeCompare(c.secure.guardPublicKey, guardPublicKey) != 1 {
		return errors.New("Action Guard 身份在进程运行期间发生变化")
	}
	callerHash, err := currentExecutableSHA256()
	if err != nil || subtle.ConstantTimeCompare([]byte(callerHash), []byte(result.CallerExecutableSHA256)) != 1 {
		return errors.New("Action Guard 调用者绑定校验失败")
	}
	serverPublicRaw, err := decodeFixedURLBase64(result.ServerPublicKey, 32)
	if err != nil {
		return errors.New("Action Guard 临时密钥无效")
	}
	serverPublic, err := ecdh.X25519().NewPublicKey(serverPublicRaw)
	if err != nil {
		return err
	}
	serverNonce, err := decodeFixedURLBase64(result.ServerNonce, 32)
	if err != nil {
		return errors.New("Action Guard nonce 无效")
	}
	shared, err := privateKey.ECDH(serverPublic)
	if err != nil {
		return err
	}
	keys := deriveSessionKeys(shared, clientNonce, serverNonce)
	c.secure.guardPublicKey = append(ed25519.PublicKey(nil), guardPublicKey...)
	c.secure.session = &clientSession{
		id: result.SessionID, expiresAt: result.ExpiresAt,
		clientToServer: keys[0:32], serverToClient: keys[32:64],
		clientMAC: keys[64:96], serverMAC: keys[96:128],
	}
	return nil
}

func (c *Client) secureRoundTripLocked(ctx context.Context, method, path string, request, response any) error {
	session := c.secure.session
	var plaintext []byte
	var err error
	if request != nil {
		plaintext, err = json.Marshal(request)
		if err != nil {
			return err
		}
	}
	session.sentSequence++
	timestamp := time.Now().Unix()
	envelope, err := sealSecureEnvelope(session.id, session.sentSequence, timestamp, plaintext,
		session.clientToServer, session.clientMAC,
		secureAAD("request", method, path, 0, session.id, session.sentSequence, timestamp))
	if err != nil {
		return err
	}
	body, _ := json.Marshal(envelope)
	httpRequest, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpRequest)
	if err != nil {
		c.secure.session = nil
		return fmt.Errorf("Action Guard 不可用: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, secureBodyLimit))
	if err != nil {
		c.secure.session = nil
		return err
	}
	if resp.Header.Get("X-MMWX-Guard-Secure") != "v1" {
		if resp.StatusCode == http.StatusUnauthorized {
			return errSecureSessionRejected
		}
		return fmt.Errorf("Action Guard 返回未签名响应: %s", strings.TrimSpace(string(data)))
	}
	var responseEnvelope secureEnvelope
	if json.Unmarshal(data, &responseEnvelope) != nil || responseEnvelope.Version != secureProtocolVersion ||
		responseEnvelope.SessionID != session.id || responseEnvelope.Sequence != session.receivedSequence+1 ||
		!withinSecureClockSkew(responseEnvelope.Timestamp) {
		c.secure.session = nil
		return errors.New("Action Guard 加密响应无效")
	}
	decrypted, err := openSecureEnvelope(responseEnvelope, session.serverToClient, session.serverMAC,
		secureAAD("response", method, path, resp.StatusCode, session.id, responseEnvelope.Sequence, responseEnvelope.Timestamp))
	if err != nil {
		c.secure.session = nil
		return errors.New("Action Guard 响应认证失败")
	}
	session.receivedSequence = responseEnvelope.Sequence
	if resp.StatusCode != http.StatusOK {
		return parseRequestError(resp.StatusCode, resp.Header.Get("Retry-After"), decrypted, time.Now())
	}
	if response != nil && json.Unmarshal(decrypted, response) != nil {
		return errors.New("Action Guard 返回无效响应")
	}
	return nil
}

func sessionResponseMessage(request sessionRequest, response sessionResponse) []byte {
	return []byte("mmwx-guard-ipc-session-v1\n" + strconv.Itoa(response.Version) + "\n" + response.SessionID + "\n" +
		response.Role + "\n" + request.ClientPublicKey + "\n" + request.ClientNonce + "\n" + strconv.FormatInt(request.Timestamp, 10) + "\n" +
		response.ServerPublicKey + "\n" + response.ServerNonce + "\n" + response.GuardPublicKey + "\n" +
		response.CallerExecutableSHA256 + "\n" + strconv.FormatInt(response.IssuedAt, 10) + "\n" + strconv.FormatInt(response.ExpiresAt, 10))
}

func deriveSessionKeys(shared, clientNonce, serverNonce []byte) []byte {
	saltInput := append(append([]byte("mmwx-guard-ipc-salt-v1\n"), clientNonce...), serverNonce...)
	salt := sha256.Sum256(saltInput)
	extract := hmac.New(sha256.New, salt[:])
	_, _ = extract.Write(shared)
	return hkdfExpand(extract.Sum(nil), []byte("mmwx-guard-ipc-keys-v1"), 128)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	result := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(result) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		result = append(result, previous...)
	}
	return result[:length]
}

func sealSecureEnvelope(sessionID string, sequence uint64, timestamp int64, plaintext, encryptionKey, macKey, aad []byte) (secureEnvelope, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return secureEnvelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return secureEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return secureEnvelope{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	envelope := secureEnvelope{
		Version: secureProtocolVersion, SessionID: sessionID, Sequence: sequence, Timestamp: timestamp,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	envelope.MAC = base64.RawURLEncoding.EncodeToString(computeMAC(macKey, aad, envelope.Nonce, envelope.Ciphertext))
	return envelope, nil
}

func openSecureEnvelope(envelope secureEnvelope, encryptionKey, macKey, aad []byte) ([]byte, error) {
	providedMAC, err := base64.RawURLEncoding.DecodeString(envelope.MAC)
	if err != nil || !hmac.Equal(providedMAC, computeMAC(macKey, aad, envelope.Nonce, envelope.Ciphertext)) {
		return nil, errors.New("message authentication failed")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid secure nonce")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func computeMAC(key, aad []byte, nonce, ciphertext string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(aad)
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(nonce))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(ciphertext))
	return mac.Sum(nil)
}

func secureAAD(direction, method, path string, status int, sessionID string, sequence uint64, timestamp int64) []byte {
	return []byte("mmwx-guard-ipc-envelope-v1\n" + direction + "\n" + method + "\n" + path + "\n" +
		strconv.Itoa(status) + "\n" + sessionID + "\n" + strconv.FormatUint(sequence, 10) + "\n" + strconv.FormatInt(timestamp, 10))
}

func decodeFixedURLBase64(value string, size int) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("expected %d bytes", size)
	}
	return raw, nil
}

func withinSecureClockSkew(timestamp int64) bool {
	delta := time.Now().Unix() - timestamp
	if delta < 0 {
		delta = -delta
	}
	return delta <= int64(secureClockSkew/time.Second)
}

func currentExecutableSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
