#!/usr/bin/env bash
# 手动升级 mmw-agent 到 GitHub release(默认 latest,可指定版本如 v0.1.4)。
#
# 适用场景:UI "升级"按钮卡住、agent 进程没换、需要绕过卡死 handler 强制刷新。
#
# 用法:
#   bash upgrade-agent.sh              # 升级到 GitHub latest
#   bash upgrade-agent.sh v0.1.4       # 升级到指定 tag
#
# 兼容:当前联合 Agent Guard 升级要求 systemd；Docker 请更新镜像。
#
# 失败兜底:
#   - 下载失败 → 退出,不动现有 binary
#   - 替换前自动备份到 /usr/local/bin/mmw-agent.bak-<timestamp>,启动失败可手动回滚
#
set -euo pipefail

REPO="iluobei/mmw-agent"
BIN="/usr/local/bin/mmw-agent"
GUARD_BIN="/usr/local/bin/mmwx-guardd"
TARGET="${1:-latest}"
BAK=""

err() { echo "[ERROR] $*" >&2; exit 1; }
log() { echo "[$(date +%H:%M:%S)] $*"; }

# 必须 root(写 /usr/local/bin + 控制服务)
[ "$(id -u)" = 0 ] || err "请用 root 运行"

# 1. 探测架构
ARCH=$(uname -m)
case $ARCH in
    x86_64)        ARCH_NAME="amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *) err "不支持的架构: $ARCH" ;;
esac
log "架构: $ARCH_NAME"

# 2. 解析目标版本 path(URL 前缀由镜像链各自接上)
if [ "$TARGET" = "latest" ]; then
    PATH_SUFFIX="releases/latest/download/mmw-agent-linux-${ARCH_NAME}"
    GUARD_PATH_SUFFIX="releases/latest/download/mmwx-guardd-linux-${ARCH_NAME}"
    log "目标: GitHub latest"
else
    # 允许带或不带 v 前缀
    case "$TARGET" in v*) TAG="$TARGET" ;; *) TAG="v$TARGET" ;; esac
    PATH_SUFFIX="releases/download/${TAG}/mmw-agent-linux-${ARCH_NAME}"
    GUARD_PATH_SUFFIX="releases/download/${TAG}/mmwx-guardd-linux-${ARCH_NAME}"
    log "目标: $TAG"
fi

# 3. 下载到临时位置(--max-time 防止网络卡死无限等)
# 镜像链 — GitHub 优先,失败再自动降级到 CDN 代理。纯 v6 机器直连 github 会"network is unreachable"
# (release binary 重定向到无 AAAA 的 objects.githubusercontent.com),会快速失败后降级到
# gh-proxy 反代兜底。
MIRRORS=(
    "https://github.com/${REPO}/${PATH_SUFFIX}"
    "https://gh-proxy.com/https://github.com/${REPO}/${PATH_SUFFIX}"
)
GUARD_MIRRORS=(
    "https://dl.miaomiaowux.com/mmwx-guard/mmwx-guardd-linux-${ARCH_NAME}"
    "https://github.com/${REPO}/${GUARD_PATH_SUFFIX}"
    "https://gh-proxy.com/https://github.com/${REPO}/${GUARD_PATH_SUFFIX}"
    "https://license.miaomiaowux.com/downloads/mmwx-guardd-linux-${ARCH_NAME}"
)
TMP="$(mktemp /tmp/mmw-agent-new.XXXXXX)"
GUARD_TMP="$(mktemp /tmp/mmwx-guardd-new.XXXXXX)"
MANIFEST_TMP="$(mktemp /tmp/mmw-agent-new-manifest.XXXXXX)"
trap 'rm -f "$TMP" "$TMP.sig" "$GUARD_TMP" "$GUARD_TMP.sig" "$MANIFEST_TMP"' EXIT
download_ok=0
for URL in "${MIRRORS[@]}"; do
    log "下载 $URL ..."
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --connect-timeout 10 --max-time 180 -o "$TMP" "$URL"; then
            download_ok=1; break
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --connect-timeout=10 --read-timeout=180 -O "$TMP" "$URL"; then
            download_ok=1; break
        fi
    else
        err "没有 curl/wget,无法下载"
    fi
    log "  → 该镜像失败,尝试下一个..."
done
[ "$download_ok" = "1" ] || err "所有镜像均下载失败(GitHub + gh-proxy 全部不可达)"
SIZE=$(du -h "$TMP" | cut -f1)
NEW_MD5=$(md5sum "$TMP" | awk '{print $1}')
log "下载完成: $SIZE, md5=$NEW_MD5"

# 3b. 签名校验:下载同名 .sig,用【已装】agent 的内嵌公钥验签(私钥离线,主控/本仓库都没有)。
#     - rc=0  通过 → 继续
#     - rc=1  新版 agent 明确判定签名不匹配 → 中止(防被篡改/MITM 的二进制)
#     - 其它  当前是旧版 agent(不支持 __verify-update)或拿不到 .sig → 警告后继续(过渡期兼容)
SIG="$TMP.sig"
sig_ok=0
for URL in "${MIRRORS[@]}"; do
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 60 -o "$SIG" "${URL}.sig" && { sig_ok=1; break; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q --connect-timeout=10 --read-timeout=60 -O "$SIG" "${URL}.sig" && { sig_ok=1; break; }
    fi
done
if [ "$sig_ok" = 1 ] && [ -x "$BIN" ] && command -v timeout >/dev/null 2>&1; then
    log "校验签名..."
    set +e
    VOUT=$(timeout 15 "$BIN" __verify-update "$TMP" "$SIG" 2>&1); VRC=$?
    set -e
    if [ "$VRC" = 0 ]; then
        log "✅ 签名校验通过"
    elif [ "$VRC" = 1 ]; then
        err "签名校验失败(二进制与签名不匹配,拒绝升级): $VOUT"
    else
        log "[WARN] 无法验签(rc=$VRC,可能当前为旧版 agent 不支持),按原流程继续"
    fi
else
    log "[WARN] 未获取到 .sig 或环境不支持,跳过验签"
fi

# Guard 与 Agent 必须作为同一个升级单元。任何一个下载/验签失败都不替换现有文件。
guard_download_ok=0
for URL in "${GUARD_MIRRORS[@]}"; do
    log "下载 Agent Guard $URL ..."
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --connect-timeout 10 --max-time 180 -o "$GUARD_TMP" "$URL" && \
           curl -fsSL --connect-timeout 10 --max-time 60 -o "$GUARD_TMP.sig" "${URL}.sig" && \
           "$BIN" __verify-update "$GUARD_TMP" "$GUARD_TMP.sig"; then
            guard_download_ok=1; break
        fi
    elif wget -q --connect-timeout=10 --read-timeout=180 -O "$GUARD_TMP" "$URL" && \
         wget -q --connect-timeout=10 --read-timeout=60 -O "$GUARD_TMP.sig" "${URL}.sig" && \
         "$BIN" __verify-update "$GUARD_TMP" "$GUARD_TMP.sig"; then
        guard_download_ok=1; break
    fi
done
[ "$guard_download_ok" = "1" ] || err "Agent Guard 或签名下载失败，未替换任何二进制"
if ! "$BIN" __verify-update "$GUARD_TMP" "$GUARD_TMP.sig"; then
    err "Agent Guard 签名校验失败，未替换任何二进制"
fi
manifest_download_ok=0
for URL in "${MIRRORS[@]}"; do
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 60 -o "$MANIFEST_TMP" "${URL}.manifest" && { manifest_download_ok=1; break; }
    else
        wget -q --connect-timeout=10 --read-timeout=60 -O "$MANIFEST_TMP" "${URL}.manifest" && { manifest_download_ok=1; break; }
    fi
done
[ "$manifest_download_ok" = "1" ] || err "Agent 发布签名清单下载失败，未替换任何二进制"

# 4. 与现有 binary 对比;一样就不动
agent_changed=1
if [ -f "$BIN" ]; then
    OLD_MD5=$(md5sum "$BIN" | awk '{print $1}')
    if [ "$OLD_MD5" = "$NEW_MD5" ]; then
        agent_changed=0
        log "Agent 已是目标版本，仍继续检查并升级 Agent Guard"
    else
        BAK="${BIN}.bak-$(date +%s)"
        cp "$BIN" "$BAK"
        log "已备份: $BAK (md5=$OLD_MD5)"
    fi
fi

# 4b. 先升级并验证 Guard；状态目录不动，保留设备身份与租约。失败时回滚 Guard，Agent 不变。
[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 || err "联合升级要求 systemd，请重新运行 Agent 安装命令"
mkdir -p /var/lib/mmwx-guard /etc/systemd/system/mmw-agent.service.d
mkdir -p /usr/local/share/mmwx-guard
install -m 0644 "$MANIFEST_TMP" /usr/local/share/mmwx-guard/agent.manifest
chmod 0700 /var/lib/mmwx-guard
cat > /etc/systemd/system/mmwx-guard-agent.service <<'EOF'
[Unit]
Description=MMWX Agent Authorization Guard
After=network-online.target
Wants=network-online.target
Before=mmw-agent.service
[Service]
Type=simple
ExecStart=/usr/local/bin/mmwx-guardd --role agent --socket /run/mmwx-guard-agent/guard.sock --state-dir /var/lib/mmwx-guard --manifest /usr/local/share/mmwx-guard/agent.manifest
Restart=always
RestartSec=3
RuntimeDirectory=mmwx-guard-agent
RuntimeDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/mmw-agent.service.d/action-guard.conf <<'EOF'
[Unit]
Requires=mmwx-guard-agent.service
After=mmwx-guard-agent.service
[Service]
Environment="MMWX_ACTION_GUARD=required"
Environment="MMWX_GUARD_SOCKET=/run/mmwx-guard-agent/guard.sock"
EOF
GUARD_BAK="${GUARD_BIN}.upgrade-backup"
GUARD_HAD_OLD=0
if [ -f "$GUARD_BIN" ]; then cp -p "$GUARD_BIN" "$GUARD_BAK"; GUARD_HAD_OLD=1; else rm -f "$GUARD_BAK"; fi
rollback_guard() {
    if [ "$GUARD_HAD_OLD" = "1" ] && [ -f "$GUARD_BAK" ]; then
        mv -f "$GUARD_BAK" "$GUARD_BIN"
        systemctl restart mmwx-guard-agent >/dev/null 2>&1 || true
    else
        systemctl disable --now mmwx-guard-agent >/dev/null 2>&1 || true
        rm -f "$GUARD_BIN" /etc/systemd/system/mmwx-guard-agent.service /etc/systemd/system/mmw-agent.service.d/action-guard.conf
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
}
chmod 0755 "$GUARD_TMP"
mv -f "$GUARD_TMP" "${GUARD_BIN}.new"
mv -f "${GUARD_BIN}.new" "$GUARD_BIN"
systemctl daemon-reload
if ! systemctl enable --now mmwx-guard-agent >/dev/null 2>&1 || ! systemctl restart mmwx-guard-agent; then
    rollback_guard
    err "Agent Guard 启动失败，已回滚；Agent 未替换"
fi
for _ in $(seq 1 50); do [ -S /run/mmwx-guard-agent/guard.sock ] && break; sleep .1; done
if [ ! -S /run/mmwx-guard-agent/guard.sock ]; then
    rollback_guard
    err "Agent Guard 未就绪，已回滚；Agent 未替换"
fi
guard_health_ok=0
if "$BIN" __guard-health /run/mmwx-guard-agent/guard.sock >/dev/null 2>&1; then
    guard_health_ok=1
elif command -v curl >/dev/null 2>&1 && \
     curl -fsS --max-time 5 --unix-socket /run/mmwx-guard-agent/guard.sock http://localhost/v1/health | grep -q '"role":"agent"'; then
    # Compatibility for an older installed Agent that lacks __guard-health.
    guard_health_ok=1
fi
if [ "$guard_health_ok" != "1" ]; then
    rollback_guard
    err "Agent Guard 健康检查失败，已回滚；Agent 未替换"
fi
rm -f "$GUARD_TMP.sig"
log "✅ Agent Guard 已升级，设备身份与租约已保留"

# 5. 原子替换(避免 "text file busy" — 旧进程占着 inode 不能直接 cp 覆盖)
chmod +x "$TMP"
if [ "$agent_changed" = "1" ]; then
    if ! cp "$TMP" "${BIN}.new" || ! chmod 0755 "${BIN}.new" || ! mv -f "${BIN}.new" "$BIN"; then
        rm -f "${BIN}.new"
        rollback_guard
        err "Agent 替换失败，Agent Guard 已回滚"
    fi
    rm -f "$TMP"
else
    rm -f "$TMP"
fi
rm -f "$GUARD_BAK"
rm -f "$TMP.sig" "$GUARD_TMP" "$GUARD_TMP.sig"
trap - EXIT
log "Agent 与 Guard 联合升级已完成"

# 6. 重启服务 — 顺序探测,谁活跃用谁
restarted=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 \
   && systemctl list-unit-files mmw-agent.service >/dev/null 2>&1; then
    log "systemd 模式: systemctl restart mmw-agent"
    systemctl restart mmw-agent
    restarted=1
elif command -v rc-service >/dev/null 2>&1 \
     && rc-service --exists mmw-agent 2>/dev/null; then
    log "OpenRC 模式: rc-service mmw-agent restart"
    rc-service mmw-agent restart
    restarted=1
elif pgrep -f "/usr/local/bin/mmw-agent" >/dev/null 2>&1; then
    # 裸 nohup 模式 — kill 老进程,新 binary 需要用户原命令再启
    log "[WARN] 检测到非 systemd/OpenRC 模式 mmw-agent 进程,本脚本不自动重启"
    log "[WARN] 请你手动:pkill -f /usr/local/bin/mmw-agent && nohup /usr/local/bin/mmw-agent -c <config> &"
else
    log "[WARN] 未检测到 mmw-agent 进程或服务,二进制已替换但需要手动启动"
fi

# 7. 验证
sleep 3
if [ $restarted -eq 1 ]; then
    if pgrep -f "/usr/local/bin/mmw-agent" >/dev/null 2>&1; then
        log "✅ 升级完成,agent 正在运行"
    else
        log "[ERROR] agent 进程未起来,查看 journalctl -u mmw-agent / /var/log/mmw-agent.log 排查"
        if [ -n "$BAK" ]; then
            log "[ERROR] 回滚命令: mv $BAK $BIN && systemctl restart mmw-agent"
        fi
        exit 1
    fi
fi

log "done"
