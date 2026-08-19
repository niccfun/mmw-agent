package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mmw-agent/internal/constants"
)

func TestNginxIncludedServerDir(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		config     string
		want       string
	}{
		{
			name:       "relative managed servers",
			configPath: "/usr/local/nginx/nginx.conf",
			config:     "http {\n    include servers/*.conf;\n}\n",
			want:       "/usr/local/nginx/servers",
		},
		{
			name:       "absolute distro confd",
			configPath: "/etc/nginx/nginx.conf",
			config:     "http {\n include /etc/nginx/conf.d/*.conf;\n}\n",
			want:       "/etc/nginx/conf.d",
		},
		{
			name:       "sites enabled is manageable",
			configPath: "/etc/nginx/nginx.conf",
			config:     "http {\n include /etc/nginx/sites-enabled/*;\n}\n",
			want:       "/etc/nginx/sites-enabled",
		},
		{
			name:       "commented include is ignored",
			configPath: "/usr/local/nginx/nginx.conf",
			config:     "http {\n # include servers/*.conf;\n}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want != "" {
				want = filepath.Clean(want)
			}
			if got := nginxIncludedServerDir(tt.configPath, tt.config); got != want {
				t.Fatalf("managed dir = %q, want %q", got, want)
			}
		})
	}
}

func TestParseNginxVersionOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "standard version output",
			output: "nginx version: nginx/1.31.3\nbuilt by gcc 14.2.0\n",
			want:   "1.31.3",
		},
		{
			name:   "version with build suffix",
			output: "nginx version: nginx/1.27.4-custom\n",
			want:   "1.27.4-custom",
		},
		{
			name:   "unrelated output",
			output: "command not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseNginxVersionOutput(tt.output); got != tt.want {
				t.Fatalf("version = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddNginxManagedIncludeTargetsHTTPBlock(t *testing.T) {
	original := `events {}
http {
    map $http_upgrade $connection_upgrade {
        default upgrade;
    }
    server { listen 80; }
}
stream {
    server { listen 443; }
}
`
	updated, err := addNginxManagedInclude(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(updated, "include servers/*.conf;") != 1 {
		t.Fatalf("managed include count = %d", strings.Count(updated, "include servers/*.conf;"))
	}
	httpEnd := strings.Index(updated, "}\nstream")
	includeAt := strings.Index(updated, "include servers/*.conf;")
	if includeAt < 0 || httpEnd < 0 || includeAt > httpEnd {
		t.Fatalf("managed include was not inserted inside http block:\n%s", updated)
	}
	if dir := nginxIncludedServerDir("/usr/local/nginx/nginx.conf", updated); dir != "/usr/local/nginx/servers" {
		t.Fatalf("inserted config not detected, dir=%q", dir)
	}
}

func TestInspectNginxRuntimeRejectsUnusableResidualBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nginx")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	previous := constants.NginxBinarySearchPaths
	constants.NginxBinarySearchPaths = []string{path}
	t.Cleanup(func() { constants.NginxBinarySearchPaths = previous })

	runtime := inspectNginxRuntime()
	if runtime.Installed {
		t.Fatalf("unusable residual binary must not be installed: %+v", runtime)
	}
	if runtime.Binary != path || !strings.Contains(runtime.Reason, "残留") {
		t.Fatalf("residual diagnostic missing: %+v", runtime)
	}
}

func TestFinalizeNginxRuntimeTreatsMissingSystemdUnitAsResidual(t *testing.T) {
	runtime := finalizeNginxRuntime(nginxRuntime{
		Installed:  true,
		Running:    false,
		Binary:     "/usr/local/nginx/sbin/nginx",
		Manager:    "command",
		CanManage:  true,
		ManagedDir: "/usr/local/nginx/servers",
	}, true)
	if runtime.Installed || runtime.CanManage || runtime.ManagedDir != "" {
		t.Fatalf("systemd orphan must be reported as not installed: %+v", runtime)
	}
	if !strings.Contains(runtime.Reason, "服务和进程均不存在") {
		t.Fatalf("orphan reason missing: %+v", runtime)
	}

	running := finalizeNginxRuntime(nginxRuntime{Installed: true, Running: true, Manager: "command"}, true)
	if !running.Installed {
		t.Fatal("a running manually managed nginx must remain installed")
	}
}
