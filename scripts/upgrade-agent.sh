#!/usr/bin/env bash
# 手动升级 mmw-agent 到 GitHub release(默认 latest,可指定版本如 v0.1.4)。
#
# 适用场景:UI "升级"按钮卡住、agent 进程没换、需要绕过卡死 handler 强制刷新。
#
# 用法:
#   bash upgrade-agent.sh              # 升级到 GitHub latest
#   bash upgrade-agent.sh v0.1.4       # 升级到指定 tag
#
# 兼容:支持 systemd / OpenRC；无 init 的 OpenVZ 容器由安装脚本的 supervisor 托管。Docker 请更新镜像。
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

# 与 internal/selfupdate 使用同一离线 Ed25519 根公钥。当前 Agent 缺失或旧版
# 不支持 __verify-update 时，由 OpenSSL 完成引导验签，不能让待升级文件自证。
UPDATE_PUBLIC_KEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA3aGta5gVWH1jVUInTJopAT7xB8soc4A8FgGEgHrVq6k=
-----END PUBLIC KEY-----'

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
VERIFY_PUBKEY="$(mktemp "$STAGING_DIR/update-public-key.XXXXXX")"
printf '%s\n' "$UPDATE_PUBLIC_KEY_PEM" > "$VERIFY_PUBKEY"
chmod 0600 "$VERIFY_PUBKEY"
trap 'rm -f "$TMP" "$TMP.sig" "$GUARD_TMP" "$GUARD_TMP.sig" "$MANIFEST_TMP" "$VERIFY_PUBKEY"' EXIT

# 优先复用已安装 Agent 的验签实现；缺失、损坏或版本过旧时，回退到系统
# OpenSSL。后者直接使用固定根公钥，避免首次修复时依赖不存在的 $BIN。
verify_update_file() {
    local file="$1" sig="$2" verifier rc
    for verifier in "$BIN" /usr/local/bin/agent-mmwx /usr/local/bin/mmwx-agent; do
        [ -x "$verifier" ] || continue
        # 更早的 Agent 会忽略未知参数并直接启动常驻进程。先检查能力标记，
        # 避免把验签探测拖到 timeout，也避免短暂启动第二个 Agent 实例。
        if ! grep -aFq '__verify-update' "$verifier" 2>/dev/null; then
            continue
        fi
        set +e
        if command -v timeout >/dev/null 2>&1; then
            timeout 15 "$verifier" __verify-update "$file" "$sig" >/dev/null 2>&1
        else
            "$verifier" __verify-update "$file" "$sig" >/dev/null 2>&1
        fi
        rc=$?
        set -e
        if [ "$rc" = 0 ]; then
            return 0
        fi
        log "[WARN] 已安装 Agent 无法完成验签($verifier, rc=$rc)，尝试 OpenSSL"
    done
    if command -v openssl >/dev/null 2>&1 && \
       openssl pkeyutl -verify -pubin -inkey "$VERIFY_PUBKEY" -rawin \
           -in "$file" -sigfile "$sig" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 极简 OpenVZ/ARM 镜像可能没有 OpenSSL，而旧 Agent 又尚未提供
# __verify-update。此时先通过系统包管理器补齐可信的系统验签器。
ensure_signature_verifier() {
    local verifier
    for verifier in "$BIN" /usr/local/bin/agent-mmwx /usr/local/bin/mmwx-agent; do
        if [ -x "$verifier" ] && grep -aFq '__verify-update' "$verifier" 2>/dev/null; then
            return 0
        fi
    done
    if command -v openssl >/dev/null 2>&1; then
        return 0
    fi
    log "未检测到可用验签器，正在根据系统包管理器安装 OpenSSL..."
    if command -v apt-get >/dev/null 2>&1; then
        log "使用 apt-get 安装 OpenSSL (Debian/Ubuntu)"
        apt-get update -qq >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y openssl || true
    elif command -v dnf >/dev/null 2>&1; then
        log "使用 dnf 安装 OpenSSL (RHEL/Fedora/Oracle Linux)"
        dnf install -y openssl || true
    elif command -v microdnf >/dev/null 2>&1; then
        log "使用 microdnf 安装 OpenSSL (极简 RHEL/Oracle Linux)"
        microdnf install -y openssl || true
    elif command -v yum >/dev/null 2>&1; then
        log "使用 yum 安装 OpenSSL (CentOS/RHEL/Oracle Linux)"
        yum install -y openssl || true
    elif command -v apk >/dev/null 2>&1; then
        log "使用 apk 安装 OpenSSL (Alpine)"
        apk add --no-cache openssl || true
    elif command -v pacman >/dev/null 2>&1; then
        log "使用 pacman 安装 OpenSSL (Arch Linux)"
        pacman -Sy --noconfirm openssl || true
    elif command -v zypper >/dev/null 2>&1; then
        log "使用 zypper 安装 OpenSSL (openSUSE/SLES)"
        zypper -n install openssl || true
    elif command -v xbps-install >/dev/null 2>&1; then
        log "使用 xbps-install 安装 OpenSSL (Void Linux)"
        xbps-install -Sy openssl || true
    else
        err "无法识别系统包管理器，请手动安装 openssl 后重试"
    fi
    command -v openssl >/dev/null 2>&1 || \
        err "OpenSSL 自动安装失败，请检查软件源或手动安装 openssl 后重试"
}

ensure_signature_verifier

# CDN 边缘节点偶尔会在 TLS/HTTP2 连接阶段提前断开。每个文件在切换镜像前
# 原地重试三次；不使用较新的 curl --retry-all-errors，兼容旧发行版。
download_file() {
    local url="$1" output="$2" max_time="$3" attempt
    for attempt in 1 2 3; do
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL --connect-timeout 10 --max-time "$max_time" -o "$output" "$url"; then
                return 0
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -q --connect-timeout=10 --read-timeout="$max_time" -O "$output" "$url"; then
                return 0
            fi
        else
            err "没有 curl/wget,无法下载"
        fi
        if [ "$attempt" -lt 3 ]; then
            log "  → 下载中断，2 秒后重试($attempt/3)..."
            sleep 2
        fi
    done
    return 1
}
download_ok=0
for URL in "${MIRRORS[@]}"; do
    log "下载 $URL ..."
    if download_file "$URL" "$TMP" 180 && \
       download_file "${URL}.sig" "$TMP.sig" 60 && \
       download_file "${URL}.manifest" "$MANIFEST_TMP" 60; then
        if verify_update_file "$TMP" "$TMP.sig"; then
            download_ok=1
            break
        fi
        log "  → 该镜像的 Agent 与签名不匹配，可能正在发布切换，尝试下一个..."
        continue
    fi
    log "  → 该镜像失败,尝试下一个..."
done
[ "$download_ok" = "1" ] || err "所有镜像均下载或验签失败(CDN + GitHub + gh-proxy；若出现 curl (23)，请检查磁盘空间和目录写权限)"
SIZE=$(du -h "$TMP" | cut -f1)
NEW_MD5=$(md5sum "$TMP" | awk '{print $1}')
log "下载完成: $SIZE, md5=$NEW_MD5"

# 3b. 签名校验:二进制、.sig 和 manifest 已从同一镜像取得，避免 CDN 发布
#     切换期间混用不同版本。验签失败时 fail closed，不替换现有文件。
SIG="$TMP.sig"
[ -s "$SIG" ] || err "Agent 签名文件为空，拒绝升级"
log "校验 Agent 签名..."
verify_update_file "$TMP" "$SIG" || err "所有镜像的 Agent 签名校验均失败，未替换任何二进制"
log "✅ Agent 签名校验通过"

# Guard 与 Agent 必须作为同一个升级单元。任何一个下载/验签失败都不替换现有文件。
guard_download_ok=0
for URL in "${GUARD_MIRRORS[@]}"; do
    log "下载 Agent Guard $URL ..."
    if download_file "$URL" "$GUARD_TMP" 180 && \
       download_file "${URL}.sig" "$GUARD_TMP.sig" 60 && \
       verify_update_file "$GUARD_TMP" "$GUARD_TMP.sig"; then
        guard_download_ok=1; break
    fi
    log "  → 该 Guard 镜像失败，尝试下一个..."
done
[ "$guard_download_ok" = "1" ] || err "Agent Guard 或签名下载失败，未替换任何二进制"
if ! verify_update_file "$GUARD_TMP" "$GUARD_TMP.sig"; then
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
    INIT_SYSTEM="direct"
fi
AGENT_WAS_ACTIVE=0
if [ "$INIT_SYSTEM" = "systemd" ]; then
    if systemctl is-active --quiet mmw-agent; then AGENT_WAS_ACTIVE=1; fi
    mkdir -p /etc/systemd/system/mmw-agent.service.d
    GUARD_UNIT="/etc/systemd/system/mmwx-guard-agent.service"
    AGENT_DROPIN="/etc/systemd/system/mmw-agent.service.d/action-guard.conf"
elif [ "$INIT_SYSTEM" = "openrc" ]; then
    if rc-service mmw-agent status >/dev/null 2>&1; then AGENT_WAS_ACTIVE=1; fi
    GUARD_UNIT="/etc/init.d/mmwx-guard-agent"
    AGENT_DROPIN="/etc/init.d/mmw-agent"
else
    if pgrep -f "^/usr/local/bin/mmw-agent( |$)" >/dev/null 2>&1 ||
       pgrep -f "^/bin/sh /usr/local/bin/mmw-agent-supervisor.sh$" >/dev/null 2>&1; then
        AGENT_WAS_ACTIVE=1
    fi
    GUARD_UNIT="/usr/local/bin/mmwx-guard-agent-supervisor.sh"
    AGENT_DROPIN="/usr/local/bin/mmw-agent-supervisor.sh"
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
elif [ "$INIT_SYSTEM" = "openrc" ]; then
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
else
cat > "$GUARD_UNIT" <<'EOF'
#!/bin/sh
SOCKET="/run/mmwx-guard-agent/guard.sock"
mkdir -p /run/mmwx-guard-agent /var/lib/mmwx-guard
chmod 0750 /run/mmwx-guard-agent
chmod 0700 /var/lib/mmwx-guard
while true; do
    rm -f "$SOCKET"
    /usr/local/bin/mmwx-guardd-agent --role agent --socket "$SOCKET" --state-dir /var/lib/mmwx-guard --manifest /usr/local/share/mmwx-guard/agent.manifest
    echo "[supervisor] mmwx-guardd-agent exited, restarting in 3s..."
    sleep 3
done
EOF
chmod 0755 "$GUARD_UNIT"
cat > "$AGENT_DROPIN" <<'EOF'
#!/bin/sh
export MMWX_GUARD_SOCKET="/run/mmwx-guard-agent/guard.sock"
while true; do
    while [ ! -S "$MMWX_GUARD_SOCKET" ]; do sleep 1; done
    /usr/local/bin/mmw-agent -c /etc/mmw-agent/config.yaml
    echo "[supervisor] mmw-agent exited, restarting in 5s..."
    sleep 5
done
EOF
chmod 0755 "$AGENT_DROPIN"
if [ ! -f /etc/rc.local ]; then
    printf '#!/bin/sh\nexit 0\n' > /etc/rc.local
    chmod 0755 /etc/rc.local
fi
if ! grep -q "mmwx-guard-agent-supervisor.sh" /etc/rc.local; then
    sed -i '/^exit 0/i nohup /usr/local/bin/mmwx-guard-agent-supervisor.sh >/var/log/mmwx-guard-agent.log 2>\&1 </dev/null \&' /etc/rc.local
fi
if ! grep -q "mmw-agent-supervisor.sh" /etc/rc.local; then
    sed -i '/^exit 0/i nohup /usr/local/bin/mmw-agent-supervisor.sh >/dev/null 2>\&1 </dev/null \&' /etc/rc.local
fi
fi
GUARD_BAK="${GUARD_BIN}.upgrade-backup"
GUARD_HAD_OLD=0
if [ -f "$GUARD_BIN" ]; then cp -p "$GUARD_BIN" "$GUARD_BAK"; GUARD_HAD_OLD=1; else rm -f "$GUARD_BAK"; fi
stop_direct_guard() {
    if [ -f /run/mmwx-guard-agent-supervisor.pid ]; then
        guard_supervisor_pid=$(cat /run/mmwx-guard-agent-supervisor.pid 2>/dev/null || true)
        case "$guard_supervisor_pid" in *[!0-9]*|"") ;; *) kill "$guard_supervisor_pid" 2>/dev/null || true ;; esac
    fi
    pkill -f "^/bin/sh /usr/local/bin/mmwx-guard-agent-supervisor.sh$" 2>/dev/null || true
    pkill -f "^/usr/local/bin/mmwx-guardd-agent " 2>/dev/null || true
    rm -f /run/mmwx-guard-agent-supervisor.pid /run/mmwx-guard-agent/guard.sock
}
start_direct_guard() {
    nohup /usr/local/bin/mmwx-guard-agent-supervisor.sh >/var/log/mmwx-guard-agent.log 2>&1 </dev/null &
    echo $! > /run/mmwx-guard-agent-supervisor.pid
}
restart_direct_agent() {
    pkill -f "^/bin/sh /usr/local/bin/mmw-agent-supervisor.sh$" 2>/dev/null || true
    pkill -f "^/usr/local/bin/mmw-agent( |$)" 2>/dev/null || true
    nohup /usr/local/bin/mmw-agent-supervisor.sh >/dev/null 2>&1 </dev/null &
}
rollback_guard() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl stop mmwx-guard-agent >/dev/null 2>&1 || true
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rc-service -D mmwx-guard-agent stop >/dev/null 2>&1 || true
    else
        stop_direct_guard
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
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl restart mmwx-guard-agent >/dev/null 2>&1 || true
        elif [ "$INIT_SYSTEM" = "openrc" ]; then
            rc-service -D mmwx-guard-agent restart >/dev/null 2>&1 || true
        elif [ -x "$GUARD_UNIT" ]; then
            start_direct_guard
        fi
    else
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl disable mmwx-guard-agent >/dev/null 2>&1 || true
        elif [ "$INIT_SYSTEM" = "openrc" ]; then
            rc-update del mmwx-guard-agent default >/dev/null 2>&1 || true
        fi
    fi
    if [ "$AGENT_WAS_ACTIVE" = "1" ]; then
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl restart mmw-agent >/dev/null 2>&1 || true
        elif [ "$INIT_SYSTEM" = "openrc" ]; then
            rc-service mmw-agent restart >/dev/null 2>&1 || true
        elif [ -x "$AGENT_DROPIN" ]; then
            restart_direct_agent
        fi
    fi
}
mv -f "$GUARD_TMP" "${GUARD_BIN}.new"
mv -f "${GUARD_BIN}.new" "$GUARD_BIN"
guard_start_ok=0
if [ "$INIT_SYSTEM" = "systemd" ]; then
    systemctl daemon-reload
    if systemctl enable --now mmwx-guard-agent >/dev/null 2>&1 && systemctl restart mmwx-guard-agent; then guard_start_ok=1; fi
elif [ "$INIT_SYSTEM" = "openrc" ]; then
    rc-update add mmwx-guard-agent default >/dev/null 2>&1 || true
    if rc-service -D mmwx-guard-agent restart; then guard_start_ok=1; fi
else
    stop_direct_guard
    start_direct_guard
    guard_start_ok=1
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
elif [ "$INIT_SYSTEM" = "openrc" ]; then
    log "OpenRC 模式: rc-service mmw-agent restart"
    rc-service mmw-agent restart
    restarted=1
else
    log "OpenVZ/direct 模式: 重启 Agent supervisor"
    restart_direct_agent
    restarted=1
fi

# 7. 验证
sleep 3
if [ $restarted -eq 1 ]; then
    agent_active=0
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        if systemctl is-active --quiet mmw-agent; then agent_active=1; fi
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        if rc-service mmw-agent status >/dev/null 2>&1; then agent_active=1; fi
    elif pgrep -f "^/usr/local/bin/mmw-agent( |$)" >/dev/null 2>&1; then
        agent_active=1
    fi
    if [ "$agent_active" != "1" ] || \
       ! "$BIN" __guard-health /run/mmwx-guard-agent/guard.sock >/dev/null 2>&1; then
        log "[ERROR] Agent/Guard 联合启动验证失败，正在成套回滚"
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl stop mmw-agent >/dev/null 2>&1 || true
        elif [ "$INIT_SYSTEM" = "openrc" ]; then
            rc-service mmw-agent stop >/dev/null 2>&1 || true
        else
            pkill -f "^/bin/sh /usr/local/bin/mmw-agent-supervisor.sh$" 2>/dev/null || true
            pkill -f "^/usr/local/bin/mmw-agent( |$)" 2>/dev/null || true
        fi
        if [ -n "$BAK" ] && [ -f "$BAK" ]; then cp -p "$BAK" "$BIN"; fi
        rollback_guard
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl restart mmw-agent >/dev/null 2>&1 || true
        elif [ "$INIT_SYSTEM" = "openrc" ]; then
            rc-service mmw-agent restart >/dev/null 2>&1 || true
        elif [ -x "$AGENT_DROPIN" ]; then
            restart_direct_agent
        fi
        err "升级失败，已恢复旧 Agent、Guard 与调用方清单"
    fi
    log "✅ 升级完成，Agent 正在运行且 Guard 加密会话验证通过"
fi

rm -f "$BAK" "$GUARD_BAK" "$MANIFEST_BAK" "$GUARD_UNIT_BAK" "$AGENT_DROPIN_BAK"
trap - EXIT
log "done"
