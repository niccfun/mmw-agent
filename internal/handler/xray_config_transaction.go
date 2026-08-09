package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"mmw-agent/internal/constants"
)

const xrayConfigTxnDirName = ".mmwx-config-transactions"

var configTxnIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)

type xrayConfigTxnRequest struct {
	Action              string `json:"action"`
	OperationID         string `json:"operation_id"`
	Config              string `json:"config,omitempty"`
	ExpectedCurrentHash string `json:"expected_current_hash,omitempty"`
}

type xrayConfigTxnMeta struct {
	OperationID string    `json:"operation_id"`
	ConfigPath  string    `json:"config_path"`
	OldHash     string    `json:"old_hash"`
	NewHash     string    `json:"new_hash"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func configContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func configTxnPaths(configPath, operationID string) (dir, meta, staged, backup string) {
	dir = filepath.Join(filepath.Dir(configPath), xrayConfigTxnDirName, operationID)
	return dir, filepath.Join(dir, "meta.json"), filepath.Join(dir, "candidate.json"), filepath.Join(dir, "previous.json")
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mmwx-txn-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func loadConfigTxnMeta(path string) (*xrayConfigTxnMeta, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta xrayConfigTxnMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func saveConfigTxnMeta(path string, meta *xrayConfigTxnMeta) error {
	meta.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0600)
}

// HandleXrayConfigTransaction implements a durable, idempotent whole-config
// transaction. prepare only validates and stages; activate atomically replaces
// config and verifies Xray can restart; rollback restores the exact previous
// bytes. The operation is serialized with every inbound/config mutation.
func (h *ManageHandler) HandleXrayConfigTransaction(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req xrayConfigTxnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	req.OperationID = strings.TrimSpace(req.OperationID)
	if !configTxnIDPattern.MatchString(req.OperationID) {
		writeError(w, http.StatusBadRequest, "invalid operation_id")
		return
	}

	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()

	configPath := h.findXrayConfigPath()
	if configPath == "" {
		configPath = constants.DefaultXrayConfigPaths[0]
	}
	dir, metaPath, stagedPath, backupPath := configTxnPaths(configPath, req.OperationID)

	switch req.Action {
	case "prepare":
		h.prepareXrayConfigTransaction(w, r, req, configPath, dir, metaPath, stagedPath, backupPath)
	case "activate":
		h.activateXrayConfigTransaction(w, configPath, metaPath, stagedPath, backupPath)
	case "rollback":
		h.rollbackXrayConfigTransaction(w, configPath, metaPath, backupPath)
	case "commit":
		meta, err := loadConfigTxnMeta(metaPath)
		if err != nil {
			writeError(w, http.StatusNotFound, "transaction not found")
			return
		}
		if meta.State != "activated" && meta.State != "committed" {
			writeError(w, http.StatusConflict, "only an activated transaction can be committed")
			return
		}
		current, _ := os.ReadFile(configPath)
		if configContentHash(current) != meta.NewHash {
			writeError(w, http.StatusConflict, "active config does not match transaction")
			return
		}
		meta.State = "committed"
		if err := saveConfigTxnMeta(metaPath, meta); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = os.Remove(backupPath)
		_ = os.Remove(stagedPath)
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "state": meta.State, "new_hash": meta.NewHash})
	case "abort":
		meta, err := loadConfigTxnMeta(metaPath)
		if err != nil {
			writeError(w, http.StatusNotFound, "transaction not found")
			return
		}
		if meta.State == "activated" {
			writeError(w, http.StatusConflict, "activated transaction must be rolled back")
			return
		}
		if err := os.RemoveAll(dir); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "state": "aborted"})
	case "status":
		meta, err := loadConfigTxnMeta(metaPath)
		if err != nil {
			writeError(w, http.StatusNotFound, "transaction not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "transaction": meta})
	default:
		writeError(w, http.StatusBadRequest, "action must be prepare, activate, rollback, commit, abort, or status")
	}
}

func (h *ManageHandler) prepareXrayConfigTransaction(w http.ResponseWriter, r *http.Request, req xrayConfigTxnRequest, configPath, dir, metaPath, stagedPath, backupPath string) {
	if strings.TrimSpace(req.Config) == "" {
		writeError(w, http.StatusBadRequest, "config is required")
		return
	}
	if existing, err := loadConfigTxnMeta(metaPath); err == nil {
		candidateHash := configContentHash([]byte(req.Config))
		if existing.NewHash == candidateHash && (existing.State == "prepared" || existing.State == "activated") {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "state": existing.State, "old_hash": existing.OldHash, "new_hash": existing.NewHash, "idempotent": true})
			return
		}
		writeError(w, http.StatusConflict, "operation_id already exists with different config")
		return
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(req.Config), &parsed); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON config")
		return
	}
	dedupeTaggedArrayInPlace(parsed, "inbounds")
	dedupeTaggedArrayInPlace(parsed, "outbounds")
	if err := validateUniqueInboundClients(parsed); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	candidate, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot normalize config")
		return
	}
	if testErr, output, method := runXrayTest(r.Context(), h.xrayMode, candidate); testErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "message": fmt.Sprintf("xray config test failed: %v", testErr), "output": output, "method": method})
		return
	}

	current, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read current config: %v", err))
		return
	}
	oldHash := configContentHash(current)
	if req.ExpectedCurrentHash != "" && !strings.EqualFold(req.ExpectedCurrentHash, oldHash) {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "message": "current config changed", "current_hash": oldHash})
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := writeFileAtomic(backupPath, current, 0600); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("write backup: %v", err))
		return
	}
	if err := writeFileAtomic(stagedPath, candidate, 0600); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("write candidate: %v", err))
		return
	}
	now := time.Now().UTC()
	meta := &xrayConfigTxnMeta{OperationID: req.OperationID, ConfigPath: configPath, OldHash: oldHash, NewHash: configContentHash(candidate), State: "prepared", CreatedAt: now, UpdatedAt: now}
	if err := saveConfigTxnMeta(metaPath, meta); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("write metadata: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "state": meta.State, "old_hash": meta.OldHash, "new_hash": meta.NewHash})
}

func validateUniqueInboundClients(config map[string]interface{}) error {
	inbounds, _ := config["inbounds"].([]interface{})
	for _, rawInbound := range inbounds {
		inbound, _ := rawInbound.(map[string]interface{})
		if inbound == nil {
			continue
		}
		tag, _ := inbound["tag"].(string)
		settings, _ := inbound["settings"].(map[string]interface{})
		if settings == nil {
			continue
		}
		seenEmail := map[string]bool{}
		seenCredential := map[string]bool{}
		for _, key := range []string{"clients", "users", "accounts"} {
			entries, _ := settings[key].([]interface{})
			for _, rawEntry := range entries {
				entry, _ := rawEntry.(map[string]interface{})
				if entry == nil {
					continue
				}
				if email := strings.TrimSpace(fmt.Sprint(entry["email"])); email != "" && email != "<nil>" {
					if seenEmail[email] {
						return fmt.Errorf("inbound %s contains duplicate email %s", tag, email)
					}
					seenEmail[email] = true
				}
				identity := ""
				for _, identityKey := range []string{"id", "password", "user"} {
					if value := strings.TrimSpace(fmt.Sprint(entry[identityKey])); value != "" && value != "<nil>" {
						identity = identityKey + ":" + value
						break
					}
				}
				if identity != "" {
					if seenCredential[identity] {
						return fmt.Errorf("inbound %s contains duplicate credential %s", tag, identity)
					}
					seenCredential[identity] = true
				}
			}
		}
	}
	return nil
}

func (h *ManageHandler) activateXrayConfigTransaction(w http.ResponseWriter, configPath, metaPath, stagedPath, backupPath string) {
	meta, err := loadConfigTxnMeta(metaPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}
	if meta.State == "activated" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "state": meta.State, "new_hash": meta.NewHash, "idempotent": true})
		return
	}
	if meta.State != "prepared" {
		writeError(w, http.StatusConflict, "transaction is not prepared")
		return
	}
	current, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if configContentHash(current) != meta.OldHash {
		writeError(w, http.StatusConflict, "current config changed after prepare")
		return
	}
	candidate, err := os.ReadFile(stagedPath)
	if err != nil || configContentHash(candidate) != meta.NewHash {
		writeError(w, http.StatusConflict, "candidate config missing or changed")
		return
	}
	if err := writeFileAtomic(configPath, candidate, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("activate config: %v", err))
		return
	}
	if err := h.RestartXray(); err != nil {
		backup, readErr := os.ReadFile(backupPath)
		rollbackErr := readErr
		if readErr == nil {
			rollbackErr = writeFileAtomic(configPath, backup, 0644)
		}
		if rollbackErr == nil {
			rollbackErr = h.RestartXray()
		}
		meta.State = "prepared"
		_ = saveConfigTxnMeta(metaPath, meta)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "message": fmt.Sprintf("activate failed: %v", err), "rolled_back": rollbackErr == nil, "rollback_error": fmt.Sprint(rollbackErr)})
		return
	}
	meta.State = "activated"
	if err := saveConfigTxnMeta(metaPath, meta); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist activated state: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "state": meta.State, "new_hash": meta.NewHash})
}

func (h *ManageHandler) rollbackXrayConfigTransaction(w http.ResponseWriter, configPath, metaPath, backupPath string) {
	meta, err := loadConfigTxnMeta(metaPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil || configContentHash(backup) != meta.OldHash {
		writeError(w, http.StatusConflict, "previous config missing or changed")
		return
	}
	current, _ := os.ReadFile(configPath)
	if configContentHash(current) != meta.OldHash {
		if err := writeFileAtomic(configPath, backup, 0644); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("restore config: %v", err))
			return
		}
		if err := h.RestartXray(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("restart restored xray: %v", err))
			return
		}
	}
	meta.State = "rolled_back"
	if err := saveConfigTxnMeta(metaPath, meta); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "state": meta.State, "old_hash": meta.OldHash})
}
