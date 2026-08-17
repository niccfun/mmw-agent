package handler

import (
	"os"
	"testing"
	"time"
)

func TestClassifyNginxWebsite(t *testing.T) {
	info := fakeWebsiteInfo{}
	managed := classifyNginxWebsite("/tmp/example.com.conf", info, "# MMWX-WEBSITE v1\n# mmwx-site-type: proxy\n# mmwx-site-value-b64: aHR0cDovLzEyNy4wLjAuMTozMDAw\nserver { server_name example.com;\n location / {\n proxy_pass http://127.0.0.1:3000;\n }\n}")
	if !managed.Managed || managed.Type != "proxy" || managed.Value != "http://127.0.0.1:3000" || managed.Protected {
		t.Fatalf("unexpected managed classification: %+v", managed)
	}
	legacy := classifyNginxWebsite("/tmp/old.example.com.conf", info, "server {\n listen 127.0.0.1:8001 ssl;\n server_name old.example.com;\n location / {\n root /srv/site;\n }\n}")
	if !legacy.Managed || !legacy.Legacy || legacy.Type != "static" {
		t.Fatalf("unexpected legacy classification: %+v", legacy)
	}
	protected := classifyNginxWebsite("/tmp/mixed.example.com.conf", info, "# MMWX-WEBSITE v1\nserver {\n server_name mixed.example.com;\n location / { root /srv/site; }\n location /ws { proxy_pass http://127.0.0.1:1; }\n}")
	if !protected.Protected {
		t.Fatalf("mixed config must be protected: %+v", protected)
	}
}

func TestClassifyNginxWebsiteResolvesProxyPassVariable(t *testing.T) {
	info := fakeWebsiteInfo{}
	content := `server {
    server_name g.2ha.me;
    set $website 127.0.0.1:5555;
    location / {
        proxy_pass http://$website;
    }
}`
	got := classifyNginxWebsite("/tmp/g.2ha.me.conf", info, content)
	if got.Type != "proxy" || got.Value != "http://127.0.0.1:5555" {
		t.Fatalf("unexpected website: %+v", got)
	}
}

func TestClassifyNginxWebsiteAllowsCleanupAfterLastWSSNode(t *testing.T) {
	info := fakeWebsiteInfo{}
	active := classifyNginxWebsite("/tmp/wss.example.com.conf", info, `# MMWX-WSS v1
server {
    server_name wss.example.com;
    location = /ws/random {
        if ($http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:11000;
    }
    location / { return 404; }
}`)
	if !active.Managed || !active.Protected || active.Reason != "配置仍承载 WSS 节点，请先删除对应节点" {
		t.Fatalf("active WSS config must remain protected: %+v", active)
	}

	empty := classifyNginxWebsite("/tmp/wss.example.com.conf", info, `# MMWX-WSS v1
server {
    server_name wss.example.com;
    location / { return 404; }
}`)
	if !empty.Managed || empty.Protected {
		t.Fatalf("empty generated WSS config should be removable: %+v", empty)
	}
}

func TestClassifyNginxWebsiteRecognizesLegacyGeneratedWSS(t *testing.T) {
	info := fakeWebsiteInfo{}
	legacy := classifyNginxWebsite("/tmp/wss.example.com.conf", info, `# 自动生成,妙妙屋X WSS 入站 nginx 反代配置。多个 WSS 入站合并渲染。
server {
    server_name wss.example.com;
    location / { return 404; }
}`)
	if !legacy.Managed || legacy.Protected {
		t.Fatalf("legacy empty WSS config should be removable: %+v", legacy)
	}
}

type fakeWebsiteInfo struct{}

func (fakeWebsiteInfo) Name() string       { return "site.conf" }
func (fakeWebsiteInfo) Size() int64        { return 100 }
func (fakeWebsiteInfo) Mode() os.FileMode  { return 0o644 }
func (fakeWebsiteInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (fakeWebsiteInfo) IsDir() bool        { return false }
func (fakeWebsiteInfo) Sys() any           { return nil }
