package handler

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"mmw-agent/internal/constants"
)

const nginxCommandTimeout = 20 * time.Second

func nginxCombinedOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nginxCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func nginxRun(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nginxCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

type nginxRuntime struct {
	Installed  bool   `json:"installed"`
	Running    bool   `json:"running"`
	Version    string `json:"version,omitempty"`
	Binary     string `json:"binary,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	ConfigDir  string `json:"config_dir,omitempty"`
	PIDPath    string `json:"pid_path,omitempty"`
	Manager    string `json:"manager"`
	CanManage  bool   `json:"can_manage"`
	ManagedDir string `json:"managed_dir,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

var nginxVersionPattern = regexp.MustCompile(`nginx version:\s*nginx/([^\s]+)`)

func parseNginxVersionOutput(output string) string {
	if match := nginxVersionPattern.FindStringSubmatch(output); len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func findNginxBinary() string {
	for _, bin := range constants.NginxBinarySearchPaths {
		if p, err := exec.LookPath(bin); err == nil {
			return p
		}
	}
	return ""
}

func commandExists(name string) bool { _, err := exec.LookPath(name); return err == nil }

func detectNginxManager() string {
	initScript := fileExecutable("/etc/init.d/nginx")
	switch {
	case commandExists("systemctl") && isSystemdRunning() && systemdNginxUnitExists():
		return "systemd"
	case commandExists("rc-service") && initScript:
		return "openrc"
	case commandExists("service") && initScript:
		return "sysv"
	case initScript:
		return "initd"
	case commandExists("supervisorctl"):
		out, err := nginxCombinedOutput("supervisorctl", "status", "nginx")
		if err == nil && !strings.Contains(strings.ToLower(string(out)), "no such process") {
			return "supervisor"
		}
		fallthrough
	default:
		return "command"
	}
}

func systemdNginxUnitExists() bool {
	out, err := nginxCombinedOutput("systemctl", "show", "nginx.service", "--property=LoadState", "--value")
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state != "" && state != "not-found"
}

func isSystemdRunning() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

func fileExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func nginxIncludedServerDir(configPath, config string) string {
	includeRE := regexp.MustCompile(`(?m)^[\t ]*include[\t ]+([^;#]+);`)
	for _, match := range includeRE.FindAllStringSubmatch(config, -1) {
		pattern := strings.Trim(strings.TrimSpace(match[1]), `"'`)
		if strings.Contains(pattern, "$") {
			continue
		}
		clean := filepath.Clean(pattern)
		base := filepath.Base(filepath.Dir(clean))
		if base != "servers" && base != "conf.d" && base != "sites-enabled" {
			continue
		}
		dir := filepath.Dir(clean)
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(configPath), dir)
		}
		return filepath.Clean(dir)
	}
	return ""
}

func nginxHTTPBlockEnd(config string) (int, bool) {
	match := regexp.MustCompile(`(?m)^[\t ]*http[\t ]*\{`).FindStringIndex(config)
	if match == nil {
		return 0, false
	}
	open := strings.Index(config[match[0]:match[1]], "{") + match[0]
	depth := 0
	var quote byte
	escaped, comment := false, false
	for i := open; i < len(config); i++ {
		c := config[i]
		if comment {
			if c == '\n' {
				comment = false
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '#':
			comment = true
		case '"', '\'':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func addNginxManagedInclude(config string) (string, error) {
	end, ok := nginxHTTPBlockEnd(config)
	if !ok {
		return "", fmt.Errorf("nginx 主配置缺少 http 块")
	}
	prefix := config[:end]
	if !strings.HasSuffix(prefix, "\n") {
		prefix += "\n"
	}
	return prefix + "    include servers/*.conf;\n" + config[end:], nil
}

func ensureNginxManagedConfig() error {
	rt := inspectNginxRuntime()
	if !rt.Installed {
		return fmt.Errorf("nginx not installed")
	}
	if rt.CanManage {
		return nil
	}
	if filepath.Clean(rt.Binary) != filepath.Join(constants.NginxPrimaryPrefixDir, "sbin", "nginx") {
		return fmt.Errorf("现有 Nginx 配置未包含可管理目录，拒绝自动修改外部安装: %s", rt.ConfigPath)
	}
	if rt.ConfigPath == "" {
		return fmt.Errorf("无法确定 nginx 主配置路径")
	}
	original, err := os.ReadFile(rt.ConfigPath)
	if err != nil {
		return fmt.Errorf("读取 nginx 主配置: %w", err)
	}
	updated, err := addNginxManagedInclude(string(original))
	if err != nil {
		return err
	}
	managedDir := filepath.Join(filepath.Dir(rt.ConfigPath), "servers")
	if err := os.MkdirAll(managedDir, 0755); err != nil {
		return fmt.Errorf("创建 nginx servers 目录: %w", err)
	}
	mode := os.FileMode(0644)
	if info, statErr := os.Stat(rt.ConfigPath); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(rt.ConfigPath, []byte(updated), mode); err != nil {
		return fmt.Errorf("更新 nginx 主配置: %w", err)
	}
	if err := nginxTest(); err != nil {
		_ = os.WriteFile(rt.ConfigPath, original, mode)
		return fmt.Errorf("自动加入 servers/*.conf 后配置校验失败，已回滚: %w", err)
	}
	if rt.Running {
		if err := nginxReload(); err != nil {
			_ = os.WriteFile(rt.ConfigPath, original, mode)
			_ = nginxReload()
			return fmt.Errorf("重载 nginx 失败，已回滚: %w", err)
		}
	}
	return nil
}

func inspectNginxRuntime() nginxRuntime {
	bin := findNginxBinary()
	rt := nginxRuntime{Binary: bin, Manager: "none"}
	if bin == "" {
		return rt
	}
	out, err := nginxCombinedOutput(bin, "-V")
	if err != nil {
		rt.Reason = fmt.Sprintf("检测到残留 Nginx 文件但无法执行: %s", bin)
		return rt
	}
	rt.Installed = true
	rt.Manager = detectNginxManager()
	flags := string(out)
	rt.Version = parseNginxVersionOutput(flags)
	value := func(name string) string {
		re := regexp.MustCompile(`--` + regexp.QuoteMeta(name) + `=([^\s]+)`)
		if match := re.FindStringSubmatch(flags); len(match) == 2 {
			return match[1]
		}
		return ""
	}
	rt.ConfigPath = value("conf-path")
	if rt.ConfigPath == "" {
		for _, candidate := range constants.DefaultNginxConfigPaths {
			if _, err := os.Stat(candidate); err == nil {
				rt.ConfigPath = candidate
				break
			}
		}
	}
	if rt.ConfigPath != "" {
		rt.ConfigDir = filepath.Dir(rt.ConfigPath)
		if data, err := os.ReadFile(rt.ConfigPath); err == nil {
			rt.ManagedDir = nginxIncludedServerDir(rt.ConfigPath, string(data))
			rt.CanManage = rt.ManagedDir != ""
			if !rt.CanManage {
				rt.Reason = "nginx 主配置未 include servers/*.conf"
			}
		}
	}
	rt.PIDPath = value("pid-path")
	rt.Running = nginxIsActive()
	return finalizeNginxRuntime(rt, isSystemdRunning())
}

func finalizeNginxRuntime(rt nginxRuntime, systemdHost bool) nginxRuntime {
	// MMWX 在 systemd 主机上的完整安装一定带 nginx.service。用户手动删除 unit
	// 和进程后，即使遗留 /usr/local/nginx/sbin/nginx，也不能继续显示为“已安装”。
	if rt.Installed && systemdHost && rt.Manager == "command" && !rt.Running {
		rt.Installed = false
		rt.CanManage = false
		rt.ManagedDir = ""
		rt.Reason = fmt.Sprintf("Nginx 服务和进程均不存在，仅检测到残留文件: %s", rt.Binary)
	}
	return rt
}

func nginxManagedServerDir() string {
	if dir := inspectNginxRuntime().ManagedDir; dir != "" {
		return dir
	}
	if confDir := detectNginxConfDirFromBinary(); confDir != "" {
		return filepath.Join(confDir, "servers")
	}
	return filepath.Join(constants.NginxPrimaryPrefixDir, "servers")
}

func nginxIsActive() bool {
	if commandExists("pgrep") && nginxRun("pgrep", "-x", "nginx") == nil {
		return true
	}
	switch detectNginxManager() {
	case "systemd":
		return nginxRun("systemctl", "is-active", "--quiet", "nginx") == nil
	case "openrc":
		return nginxRun("rc-service", "nginx", "status") == nil
	case "sysv":
		return nginxRun("service", "nginx", "status") == nil
	case "initd":
		return nginxRun("/etc/init.d/nginx", "status") == nil
	case "supervisor":
		out, err := nginxCombinedOutput("supervisorctl", "status", "nginx")
		return err == nil && strings.Contains(string(out), "RUNNING")
	default:
		return false
	}
}

func runNginxServiceAction(action string) error {
	var name string
	var args []string
	switch detectNginxManager() {
	case "systemd":
		name, args = "systemctl", []string{action, "nginx"}
	case "openrc":
		name, args = "rc-service", []string{"nginx", action}
	case "sysv":
		name, args = "service", []string{"nginx", action}
	case "initd":
		name, args = "/etc/init.d/nginx", []string{action}
	case "supervisor":
		name, args = "supervisorctl", []string{action, "nginx"}
	default:
		return fmt.Errorf("no service manager")
	}
	command := strings.Join(append([]string{name}, args...), " ")
	log.Printf("[NginxManager] manager=%s action=%s command=%q", detectNginxManager(), action, command)
	out, err := nginxCombinedOutput(name, args...)
	if err != nil {
		return fmt.Errorf("%s: %s: %w", command, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func nginxTest() error {
	bin := findNginxBinary()
	if bin == "" {
		return fmt.Errorf("nginx not installed")
	}
	out, err := nginxCombinedOutput(bin, "-t")
	if err != nil {
		return fmt.Errorf("nginx -t: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func nginxReload() error {
	if err := nginxTest(); err != nil {
		return err
	}
	if bin := findNginxBinary(); bin != "" && nginxIsActive() {
		log.Printf("[NginxManager] manager=command action=reload command=%q", bin+" -s reload")
		if out, err := nginxCombinedOutput(bin, "-s", "reload"); err == nil {
			return nil
		} else if serviceErr := runNginxServiceAction("reload"); serviceErr == nil {
			return nil
		} else {
			return fmt.Errorf("nginx reload: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	return nginxStart()
}

func nginxStart() error {
	if nginxIsActive() {
		return nil
	}
	if err := nginxTest(); err != nil {
		return err
	}
	if err := runNginxServiceAction("start"); err == nil {
		return nil
	}
	bin := findNginxBinary()
	if bin == "" {
		return fmt.Errorf("nginx not installed")
	}
	out, err := nginxCombinedOutput(bin)
	log.Printf("[NginxManager] manager=command action=start command=%q", bin)
	if err != nil {
		return fmt.Errorf("start nginx command: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func nginxStop() error {
	if !nginxIsActive() {
		return nil
	}
	if bin := findNginxBinary(); bin != "" {
		if err := exec.Command(bin, "-s", "quit").Run(); err == nil {
			return nil
		}
	}
	return runNginxServiceAction("stop")
}

// installNginxPackage is the minimal-init fallback for NAT/Alpine images where
// the full MMWX installer cannot reach its systemctl step. It intentionally
// uses argv commands rather than a shell and only runs after the normal
// installer failed without leaving an nginx binary behind.
func installNginxPackage() error {
	var commands [][]string
	switch {
	case commandExists("apk"):
		commands = [][]string{{"apk", "add", "--no-cache", "nginx"}}
	case commandExists("apt-get"):
		commands = [][]string{{"apt-get", "update"}, {"apt-get", "install", "-y", "nginx"}}
	case commandExists("dnf"):
		commands = [][]string{{"dnf", "install", "-y", "nginx"}}
	case commandExists("yum"):
		commands = [][]string{{"yum", "install", "-y", "nginx"}}
	case commandExists("pacman"):
		commands = [][]string{{"pacman", "-Sy", "--noconfirm", "nginx"}}
	default:
		return fmt.Errorf("no supported package manager")
	}
	for _, args := range commands {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
		}
	}
	if findNginxBinary() == "" {
		return fmt.Errorf("package manager completed but nginx binary was not found")
	}
	return nil
}
