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
GUARD_BIN="/usr/local/bin/mmwx-guardd-agent"
TARGET="${1:-latest}"
AGENT_ASSET_BASE="${MMWX_AGENT_ASSET_BASE:-}"
GUARD_DOWNLOAD_BASE="${MMWX_GUARD_DOWNLOAD_BASE:-}"
GUARD_RELEASE="${MMWX_GUARD_RELEASE:-}"
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
    GUARD_PATH_SUFFIX="releases/latest/download/mmwx-guardd-agent-linux-${ARCH_NAME}"
    log "目标: latest（R2 CDN 优先，GitHub 回退）"
else
    # 允许带或不带 v 前缀
    case "$TARGET" in v*) TAG="$TARGET" ;; *) TAG="v$TARGET" ;; esac
    PATH_SUFFIX="releases/download/${TAG}/mmw-agent-linux-${ARCH_NAME}"
    GUARD_PATH_SUFFIX="releases/download/${TAG}/mmwx-guardd-agent-linux-${ARCH_NAME}"
    log "目标: $TAG"
fi

# 3. 下载到临时位置(--max-time 防止网络卡死无限等)
# latest 使用 R2 CDN 第一优先，避免批量升级集中请求 GitHub。指定历史版本时
# 使用不可变 CDN 路径；老版本尚未回填时自动回退 GitHub。
if [ "$TARGET" = "latest" ]; then
    CDN_AGENT_URL="https://dl.miaomiaowux.com/mmw-agent/mmw-agent-linux-${ARCH_NAME}"
else
    CDN_AGENT_URL="https://dl.miaomiaowux.com/mmw-agent/releases/${TAG}/mmw-agent-linux-${ARCH_NAME}"
fi
MIRRORS=(
    "$CDN_AGENT_URL"
    "https://github.com/${REPO}/${PATH_SUFFIX}"
    "https://gh-proxy.com/https://github.com/${REPO}/${PATH_SUFFIX}"
)
GUARD_MIRRORS=(
    "https://dl.miaomiaowux.com/mmwx-guard/mmwx-guardd-agent-linux-${ARCH_NAME}"
    "https://github.com/${REPO}/${GUARD_PATH_SUFFIX}"
    "https://gh-proxy.com/https://github.com/${REPO}/${GUARD_PATH_SUFFIX}"
    "https://license.miaomiaowux.com/downloads/mmwx-guardd-agent-linux-${ARCH_NAME}"
)
if [ -n "$AGENT_ASSET_BASE" ]; then
    MIRRORS=("${AGENT_ASSET_BASE%/}/mmw-agent-linux-${ARCH_NAME}")
fi
if [ -n "$GUARD_DOWNLOAD_BASE" ]; then
    guard_asset_base="${GUARD_DOWNLOAD_BASE%/}"
    if [ -n "$GUARD_RELEASE" ]; then
        guard_asset_base="$guard_asset_base/releases/$GUARD_RELEASE"
    fi
    GUARD_MIRRORS=("$guard_asset_base/mmwx-guardd-agent-linux-${ARCH_NAME}")
fi
# 不使用 /tmp：部分系统将其设为 noexec，磁盘或 tmpfs 过小时 curl 还会以
# code 23 失败。专用目录同时容纳 Agent、Guard、签名和回滚工作空间。
STAGING_DIR="/var/lib/mmw-agent-update"
mkdir -p "$STAGING_DIR"
chmod 0700 "$STAGING_DIR"
AVAILABLE_KB=$(df -Pk "$STAGING_DIR" | awk 'NR==2 {print $4}')
case "$AVAILABLE_KB" in ''|*[!0-9]*) err "无法检查升级暂存目录可用空间: $STAGING_DIR" ;; esac
[ "$AVAILABLE_KB" -ge 131072 ] || err "升级暂存空间不足: $STAGING_DIR 仅剩 $((AVAILABLE_KB / 1024)) MB，至少需要 128 MB"
TMP="$(mktemp "$STAGING_DIR/mmw-agent-new.XXXXXX")"
GUARD_TMP="$(mktemp "$STAGING_DIR/mmwx-guardd-new.XXXXXX")"
MANIFEST_TMP="$(mktemp "$STAGING_DIR/mmw-agent-new-manifest.XXXXXX")"
trap 'rm -f "$TMP" "$TMP.sig" "$GUARD_TMP" "$GUARD_TMP.sig" "$MANIFEST_TMP"' EXIT
download_ok=0
for URL in "${MIRRORS[@]}"; do
    log "下载 $URL ..."
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --connect-timeout 10 --max-time 180 -o "$TMP" "$URL" && \
           curl -fsSL --connect-timeout 10 --max-time 60 -o "$TMP.sig" "${URL}.sig" && \
           curl -fsSL --connect-timeout 10 --max-time 60 -o "$MANIFEST_TMP" "${URL}.manifest"; then
            download_ok=1; break
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --connect-timeout=10 --read-timeout=180 -O "$TMP" "$URL" && \
           wget -q --connect-timeout=10 --read-timeout=60 -O "$TMP.sig" "${URL}.sig" && \
           wget -q --connect-timeout=10 --read-timeout=60 -O "$MANIFEST_TMP" "${URL}.manifest"; then
            download_ok=1; break
        fi
    else
        err "没有 curl/wget,无法下载"
    fi
    log "  → 该镜像失败,尝试下一个..."
done
[ "$download_ok" = "1" ] || err "所有镜像均下载失败(CDN + GitHub + gh-proxy 均不可用；若出现 curl (23)，请检查磁盘空间和目录写权限)"
SIZE=$(du -h "$TMP" | cut -f1)
NEW_MD5=$(md5sum "$TMP" | awk '{print $1}')
log "下载完成: $SIZE, md5=$NEW_MD5"

# 3b. 签名校验:二进制、.sig 和 manifest 已从同一镜像取得，避免 CDN 发布
#     切换期间混用不同版本。用【已装】agent 的内嵌公钥验签。
#     - rc=0  通过 → 继续
#     - rc=1  新版 agent 明确判定签名不匹配 → 中止(防被篡改/MITM 的二进制)
#     - 其它  当前是旧版 agent(不支持 __verify-update)或拿不到 .sig → 警告后继续(过渡期兼容)
SIG="$TMP.sig"
if [ -s "$SIG" ] && [ -x "$BIN" ] && command -v timeout >/dev/null 2>&1; then
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
chmod 0755 "$TMP" "$GUARD_TMP"
if ! "$GUARD_TMP" --role agent --manifest "$MANIFEST_TMP" --verify-manifest-for "$TMP"; then
    err "Agent 二进制与官方签名清单不匹配，未替换任何二进制"
fi

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
INIT_SYSTEM=""
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    INIT_SYSTEM="openrc"
else
    err "联合升级要求 systemd 或 OpenRC，请重新运行 Agent 安装命令"
fi
AGENT_WAS_ACTIVE=0
if [ "$INIT_SYSTEM" = "systemd" ]; then
    if systemctl is-active --quiet mmw-agent; then AGENT_WAS_ACTIVE=1; fi
    mkdir -p /etc/systemd/system/mmw-agent.service.d
    GUARD_UNIT="/etc/systemd/system/mmwx-guard-agent.service"
    AGENT_DROPIN="/etc/systemd/system/mmw-agent.service.d/action-guard.conf"
else
    if rc-service mmw-agent status >/dev/null 2>&1; then AGENT_WAS_ACTIVE=1; fi
    GUARD_UNIT="/etc/init.d/mmwx-guard-agent"
    AGENT_DROPIN="/etc/init.d/mmw-agent"
fi
mkdir -p /var/lib/mmwx-guard
mkdir -p /usr/local/share/mmwx-guard
MANIFEST_BAK="/usr/local/share/mmwx-guard/agent.manifest.upgrade-backup"
GUARD_UNIT_BAK="${GUARD_UNIT}.upgrade-backup"
AGENT_DROPIN_BAK="${AGENT_DROPIN}.upgrade-backup"
MANIFEST_HAD_OLD=0
GUARD_UNIT_HAD_OLD=0
AGENT_DROPIN_HAD_OLD=0
if [ -f /usr/local/share/mmwx-guard/agent.manifest ]; then
    cp -p /usr/local/share/mmwx-guard/agent.manifest "$MANIFEST_BAK"
    MANIFEST_HAD_OLD=1
else
    rm -f "$MANIFEST_BAK"
fi
if [ -f "$GUARD_UNIT" ]; then cp -p "$GUARD_UNIT" "$GUARD_UNIT_BAK"; GUARD_UNIT_HAD_OLD=1; else rm -f "$GUARD_UNIT_BAK"; fi
if [ -f "$AGENT_DROPIN" ]; then cp -p "$AGENT_DROPIN" "$AGENT_DROPIN_BAK"; AGENT_DROPIN_HAD_OLD=1; else rm -f "$AGENT_DROPIN_BAK"; fi
install -m 0644 "$MANIFEST_TMP" /usr/local/share/mmwx-guard/agent.manifest
chmod 0700 /var/lib/mmwx-guard
if [ "$INIT_SYSTEM" = "systemd" ]; then
cat > /etc/systemd/system/mmwx-guard-agent.service <<'EOF'
[Unit]
Description=MMWX Agent Authorization Guard
After=network-online.target
Wants=network-online.target
Before=mmw-agent.service
[Service]
Type=simple
ExecStart=/usr/local/bin/mmwx-guardd-agent --role agent --socket /run/mmwx-guard-agent/guard.sock --state-dir /var/lib/mmwx-guard --manifest /usr/local/share/mmwx-guard/agent.manifest
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
Wants=mmwx-guard-agent.service
After=mmwx-guard-agent.service
[Service]
Environment="MMWX_GUARD_SOCKET=/run/mmwx-guard-agent/guard.sock"
EOF
# v0.5.3 等旧安装器把 Guard 写进了主 unit 的 Requires=。drop-in 的
# Wants= 不会覆盖它，重启 Guard 仍会级联停止正在执行升级的 Agent。
# 在 daemon-reload 前清理这个遗留强依赖，只保留上面的软依赖与顺序。
if [ -f /etc/systemd/system/mmw-agent.service ]; then
    sed -i 's/^Requires=mmwx-guard-agent\.service$/Wants=mmwx-guard-agent.service/' /etc/systemd/system/mmw-agent.service
fi
else
cat > /etc/init.d/mmwx-guard-agent <<'EOF'
#!/sbin/openrc-run
name="MMWX Agent Authorization Guard"
description="MMWX Agent Authorization Guard"
command="/usr/local/bin/mmwx-guardd-agent"
command_args="--role agent --socket /run/mmwx-guard-agent/guard.sock --state-dir /var/lib/mmwx-guard --manifest /usr/local/share/mmwx-guard/agent.manifest"
supervisor="supervise-daemon"
respawn_delay=3
respawn_max=0
export MMWX_GUARD_SOCKET="/run/mmwx-guard-agent/guard.sock"
depend() { need net; before mmw-agent; }
start_pre() {
    checkpath --directory --mode 0750 /run/mmwx-guard-agent
    checkpath --directory --mode 0700 /var/lib/mmwx-guard
}
EOF
chmod 0755 /etc/init.d/mmwx-guard-agent
if ! grep -q '^export MMWX_GUARD_SOCKET=' /etc/init.d/mmw-agent; then
    sed -i '/^respawn_max=/a export MMWX_GUARD_SOCKET="/run/mmwx-guard-agent/guard.sock"' /etc/init.d/mmw-agent
    if ! grep -q '^export MMWX_GUARD_SOCKET=' /etc/init.d/mmw-agent; then
        sed -i '/^depend()/i export MMWX_GUARD_SOCKET="/run/mmwx-guard-agent/guard.sock"' /etc/init.d/mmw-agent
    fi
fi
sed -i 's/depend() { need net; }/depend() { need net mmwx-guard-agent; }/' /etc/init.d/mmw-agent
fi
GUARD_BAK="${GUARD_BIN}.upgrade-backup"
GUARD_HAD_OLD=0
if [ -f "$GUARD_BIN" ]; then cp -p "$GUARD_BIN" "$GUARD_BAK"; GUARD_HAD_OLD=1; else rm -f "$GUARD_BAK"; fi
rollback_guard() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl stop mmwx-guard-agent >/dev/null 2>&1 || true
    else
        rc-service -D mmwx-guard-agent stop >/dev/null 2>&1 || true
    fi
    if [ "$GUARD_HAD_OLD" = "1" ] && [ -f "$GUARD_BAK" ]; then
        cp -p "$GUARD_BAK" "$GUARD_BIN"
    else
        rm -f "$GUARD_BIN"
    fi
    if [ "$MANIFEST_HAD_OLD" = "1" ] && [ -f "$MANIFEST_BAK" ]; then
        cp -p "$MANIFEST_BAK" /usr/local/share/mmwx-guard/agent.manifest
    else
        rm -f /usr/local/share/mmwx-guard/agent.manifest
    fi
    if [ "$GUARD_UNIT_HAD_OLD" = "1" ] && [ -f "$GUARD_UNIT_BAK" ]; then cp -p "$GUARD_UNIT_BAK" "$GUARD_UNIT"; else rm -f "$GUARD_UNIT"; fi
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        # Keep Wants= so restarting the restored Guard cannot kill the Agent or
        # this rollback transaction through an old Requires= dependency.
        rm -f "$AGENT_DROPIN_BAK"
    elif [ "$AGENT_DROPIN_HAD_OLD" = "1" ] && [ -f "$AGENT_DROPIN_BAK" ]; then
        cp -p "$AGENT_DROPIN_BAK" "$AGENT_DROPIN"
    else
        rm -f "$AGENT_DROPIN"
    fi
    if [ "$INIT_SYSTEM" = "systemd" ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
    if [ "$GUARD_HAD_OLD" = "1" ]; then
        if [ "$INIT_SYSTEM" = "systemd" ]; then systemctl restart mmwx-guard-agent >/dev/null 2>&1 || true; else rc-service -D mmwx-guard-agent restart >/dev/null 2>&1 || true; fi
    else
        if [ "$INIT_SYSTEM" = "systemd" ]; then systemctl disable mmwx-guard-agent >/dev/null 2>&1 || true; else rc-update del mmwx-guard-agent default >/dev/null 2>&1 || true; fi
    fi
    if [ "$AGENT_WAS_ACTIVE" = "1" ]; then
        if [ "$INIT_SYSTEM" = "systemd" ]; then systemctl restart mmw-agent >/dev/null 2>&1 || true; else rc-service mmw-agent restart >/dev/null 2>&1 || true; fi
    fi
}
mv -f "$GUARD_TMP" "${GUARD_BIN}.new"
mv -f "${GUARD_BIN}.new" "$GUARD_BIN"
guard_start_ok=0
if [ "$INIT_SYSTEM" = "systemd" ]; then
    systemctl daemon-reload
    if systemctl enable --now mmwx-guard-agent >/dev/null 2>&1 && systemctl restart mmwx-guard-agent; then guard_start_ok=1; fi
else
    rc-update add mmwx-guard-agent default >/dev/null 2>&1 || true
    if rc-service -D mmwx-guard-agent restart; then guard_start_ok=1; fi
fi
if [ "$guard_start_ok" != "1" ]; then
    rollback_guard
    rm -f "$BAK"
    err "Agent Guard 启动失败，已回滚；Agent 未替换"
fi
for _ in $(seq 1 50); do [ -S /run/mmwx-guard-agent/guard.sock ] && break; sleep .1; done
if [ ! -S /run/mmwx-guard-agent/guard.sock ]; then
    rollback_guard
    rm -f "$BAK"
    err "Agent Guard 未就绪，已回滚；Agent 未替换"
fi
rm -f "$GUARD_TMP.sig"
log "✅ Agent Guard 已启动，精确调用方清单已离线验证"

# 5. 原子替换(避免 "text file busy" — 旧进程占着 inode 不能直接 cp 覆盖)
chmod +x "$TMP"
if [ "$agent_changed" = "1" ]; then
    if ! cp "$TMP" "${BIN}.new" || ! chmod 0755 "${BIN}.new" || ! mv -f "${BIN}.new" "$BIN"; then
        rm -f "${BIN}.new"
        rollback_guard
        rm -f "$BAK"
        err "Agent 替换失败，Agent Guard 已回滚"
    fi
    rm -f "$TMP"
else
    rm -f "$TMP"
fi
rm -f "$TMP.sig" "$GUARD_TMP" "$GUARD_TMP.sig"
log "Agent 与 Guard 已替换，等待联合启动验证"

# 6. 重启服务 — 顺序探测,谁活跃用谁
restarted=0
if [ "$INIT_SYSTEM" = "systemd" ]; then
    log "systemd 模式: systemctl restart mmw-agent"
    if ! systemctl restart mmw-agent; then
        if [ -n "$BAK" ] && [ -f "$BAK" ]; then cp -p "$BAK" "$BIN"; fi
        rollback_guard
        systemctl restart mmw-agent >/dev/null 2>&1 || true
        err "Agent 重启失败，已恢复旧 Agent、Guard 与调用方清单"
    fi
    restarted=1
elif rc-service --exists mmw-agent 2>/dev/null; then
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
    agent_active=0
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        if systemctl is-active --quiet mmw-agent; then agent_active=1; fi
    elif rc-service mmw-agent status >/dev/null 2>&1; then
        agent_active=1
    fi
    if [ "$agent_active" != "1" ] || \
       ! "$BIN" __guard-health /run/mmwx-guard-agent/guard.sock >/dev/null 2>&1; then
        log "[ERROR] Agent/Guard 联合启动验证失败，正在成套回滚"
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl stop mmw-agent >/dev/null 2>&1 || true
        else
            rc-service mmw-agent stop >/dev/null 2>&1 || true
        fi
        if [ -n "$BAK" ] && [ -f "$BAK" ]; then cp -p "$BAK" "$BIN"; fi
        rollback_guard
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl restart mmw-agent >/dev/null 2>&1 || true
        else
            rc-service mmw-agent restart >/dev/null 2>&1 || true
        fi
        err "升级失败，已恢复旧 Agent、Guard 与调用方清单"
    fi
    log "✅ 升级完成，Agent 正在运行且 Guard 加密会话验证通过"
fi

rm -f "$BAK" "$GUARD_BAK" "$MANIFEST_BAK" "$GUARD_UNIT_BAK" "$AGENT_DROPIN_BAK"
trap - EXIT
log "done"
