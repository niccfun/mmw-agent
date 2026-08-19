package xrayctl

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"mmw-agent/internal/discovery"
	"mmw-agent/internal/util"
)

// RepairReferencedPrivateKeyPermissions migrates keys written by older Agents
// as root:root 0600 before an external Xray restart. Invalid/unrelated config
// fragments are ignored; any referenced key that exists must be repairable.
func RepairReferencedPrivateKeyPermissions() error {
	paths := discovery.Discover()
	files := make([]string, 0, 8)
	if paths.ConfigPath != "" {
		files = append(files, paths.ConfigPath)
	}
	if paths.ConfDir != "" {
		entries, _ := os.ReadDir(paths.ConfDir)
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
				files = append(files, filepath.Join(paths.ConfDir, entry.Name()))
			}
		}
	}
	keyPaths := make(map[string]struct{})
	for _, configPath := range files {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		var config any
		if json.Unmarshal(raw, &config) != nil {
			continue
		}
		collectKeyFiles(config, keyPaths)
	}
	if len(keyPaths) == 0 {
		return nil
	}
	uid, gid, err := xrayRuntimeIdentity()
	if err != nil {
		return err
	}
	for keyPath := range keyPaths {
		if err := util.CertPathSafe(keyPath); err != nil {
			continue
		}
		resolved, err := filepath.EvalSymlinks(keyPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := util.CertPathSafe(resolved); err != nil {
			continue
		}
		if err := os.Chown(resolved, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", resolved, err)
		}
		if err := os.Chmod(resolved, 0o600); err != nil {
			return fmt.Errorf("chmod %s: %w", resolved, err)
		}
	}
	return nil
}

func collectKeyFiles(value any, paths map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "keyFile" {
				if path, ok := child.(string); ok && filepath.IsAbs(path) {
					paths[path] = struct{}{}
				}
			}
			collectKeyFiles(child, paths)
		}
	case []any:
		for _, child := range typed {
			collectKeyFiles(child, paths)
		}
	}
}

// WriteCertificatePair installs TLS material atomically. When Xray consumes
// the key, ownership follows the running process (preferred) or xray.service's
// configured User/Group. This keeps the private key at 0600 without making it
// unreadable to a non-root external Xray service.
func WriteCertificatePair(certPath, keyPath string, certPEM, keyPEM []byte, forXray bool) error {
	uid, gid := os.Geteuid(), os.Getegid()
	if forXray {
		var err error
		uid, gid, err = xrayRuntimeIdentity()
		if err != nil {
			return fmt.Errorf("resolve Xray service identity: %w", err)
		}
	}
	if err := writeAtomicOwned(certPath, certPEM, 0o644, os.Geteuid(), os.Getegid()); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := writeAtomicOwned(keyPath, keyPEM, 0o600, uid, gid); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

func xrayRuntimeIdentity() (int, int, error) {
	for _, pid := range discovery.FindXrayPIDs() {
		info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
		if err != nil {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			return int(stat.Uid), int(stat.Gid), nil
		}
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		// Non-systemd Xray installations normally run as root. If a process is
		// active its actual identity was already discovered above.
		return os.Geteuid(), os.Getegid(), nil
	}
	userValue, err := systemdProperty("User")
	if err != nil {
		// Embedded/container deployments may ship a systemctl client without a
		// running systemd or xray.service. They run Xray inside the root Agent.
		return os.Geteuid(), os.Getegid(), nil
	}
	if userValue == "" || userValue == "root" {
		return 0, 0, nil
	}
	account, err := user.Lookup(userValue)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %q: %w", userValue, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q: %w", account.Uid, err)
	}
	gidValue, err := systemdProperty("Group")
	if err != nil {
		return 0, 0, err
	}
	if gidValue == "" {
		gidValue = account.Gid
	} else if group, lookupErr := user.LookupGroup(gidValue); lookupErr == nil {
		gidValue = group.Gid
	}
	gid, err := strconv.Atoi(gidValue)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q: %w", gidValue, err)
	}
	return uid, gid, nil
}

func systemdProperty(name string) (string, error) {
	output, err := exec.Command("systemctl", "show", "xray.service", "--property="+name, "--value").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl show xray.service %s: %s (%w)", name, strings.TrimSpace(string(output)), err)
	}
	return strings.TrimSpace(string(output)), nil
}

func writeAtomicOwned(target string, data []byte, mode os.FileMode, uid, gid int) (err error) {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".mmwx-cert-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if err = tmp.Chown(uid, gid); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, target); err != nil {
		return err
	}
	return nil
}
