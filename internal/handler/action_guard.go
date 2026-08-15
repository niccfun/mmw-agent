package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"mmw-agent/internal/guardclient"
)

func (h *ManageHandler) HandleActionGuardAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeActionGuardError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.actionGuard == nil || !h.actionGuard.Enabled() {
		writeActionGuardError(w, http.StatusServiceUnavailable, "Agent Action Guard 未启用")
		return
	}
	var request guardclient.AttestationRequest
	if json.NewDecoder(r.Body).Decode(&request) != nil || request.ServerHash != h.currentServerHash() {
		writeActionGuardError(w, http.StatusBadRequest, "Action Guard 请求与当前服务器不匹配")
		return
	}
	attestation, err := h.actionGuard.Attest(r.Context(), request)
	if err != nil {
		writeActionGuardError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, attestation)
}

func (h *ManageHandler) HandleActionGuardStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeActionGuardError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	expected := h.currentServerHash()
	if h.leaseManager == nil {
		writeActionGuardError(w, http.StatusServiceUnavailable, "Agent authoritative slot manager 未启用")
		return
	}
	status := h.leaseManager.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"expected_server_hash": expected,
		"slot":                 status,
		"matches":              status.ServerHash != "" && status.ServerHash == expected,
		"needs_lease":          h.leaseManager.NeedsLease(),
	})
}

func (h *ManageHandler) HandleActionGuardConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeActionGuardError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.actionGuard == nil || !h.actionGuard.Enabled() {
		writeActionGuardError(w, http.StatusServiceUnavailable, "Agent Action Guard 未启用")
		return
	}
	var request guardclient.ConsumeRequest
	if json.NewDecoder(r.Body).Decode(&request) != nil || request.ServerHash != h.currentServerHash() || strings.TrimSpace(request.Grant) == "" {
		writeActionGuardError(w, http.StatusBadRequest, "ActionGrant 与当前服务器不匹配")
		return
	}
	if err := h.actionGuard.Consume(r.Context(), request); err != nil {
		writeActionGuardError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func hashServerToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func writeActionGuardError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
