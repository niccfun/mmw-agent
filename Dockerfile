# mmw-agent Docker 镜像 — embedded xray + 内置 nginx,host 网络模式。
#
# Build:
#   本地:docker build --build-context xray-core-fork=../xray-core-vision-limiter \
#          --build-context guard-bin=../guard-dist \
#          --build-context guard-src=../mmwx-guardd -t mmw-agent:test .
#   CI:  workflow 先 clone fork 到 ../xray-core-vision-limiter,再用 --build-context 同上
#
# 为什么需要 --build-context xray-core-fork:
# go.mod 用相对路径 replace github.com/xtls/xray-core => ../xray-core-vision-limiter,
# build context 默认只含 Dockerfile 所在目录,看不到父级 fork 目录。
# buildkit 的 --build-context 把 fork 作为附加 context 引入,Dockerfile 内 COPY --from 解构。

# ─── Stage 1: backend builder ───
FROM golang:1.26-bookworm AS builder

# 多架构:GitHub Actions buildx 会注入 TARGETOS/TARGETARCH
ARG TARGETOS
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# 把 xray-core fork 放到 ../xray-core-vision-limiter,跟 go.mod replace 路径匹配
COPY --from=xray-core-fork . /build/xray-core-vision-limiter

# mmw-agent 源码本体
WORKDIR /build/mmw-agent
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# 编译 — CGO 关 (纯静态;主控也是这个配置),embedded xray-core 是 Go 库静态链接进来
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/mmw-agent ./cmd/mmw-agent

FROM golang:1.26-bookworm AS guard-builder
ARG TARGETARCH
COPY --from=guard-src . /src
COPY --from=guard-bin . /guard-dist
COPY --from=builder /out/mmw-agent /caller/mmw-agent
WORKDIR /src
RUN guard="/guard-dist/mmwx-guardd-agent-linux-${TARGETARCH:-amd64}" \
    && test -s "$guard" && test -s "$guard.sig" \
    && chmod 0755 /caller/mmw-agent \
    && /caller/mmw-agent __verify-update /guard-dist/version.json /guard-dist/version.json.sig \
    && /caller/mmw-agent __verify-update "$guard" "$guard.sig" \
    && install -D -m 0755 "$guard" /out/mmwx-guardd
RUN --mount=type=secret,id=release_manifest_private_key \
    key="$(cat /run/secrets/release_manifest_private_key)" \
    && go run ./cmd/mmwx-manifest -role agent -binary /caller/mmw-agent \
      -private-key "$key" -version docker -goos linux -goarch "${TARGETARCH:-amd64}" \
      -out /out/agent.manifest

# ─── Stage 2: runtime ───
# Final stage - 用 nginx 官方 Docker base(mainline-bookworm),跟主控 Dockerfile + install-nginx.sh 同款
# "最新 nginx mainline"语义。该镜像默认编译 --with-http_v3_module + 静态链 QuicTLS,完整支持 listen ... quic。
# debian:bookworm-slim apt 装的 nginx 1.22.x 不带 HTTP/3 模块,会导致 WSS / Reality 入站若用上 quic
# 指令时 nginx 启动报 "invalid parameter quic"。base 仍是 debian bookworm 系列,其它 apt 包正常装。
FROM nginx:mainline-bookworm

ARG TARGETARCH

# nginx 由 base image 预装(WSS / Reality 入站要用):二进制 /usr/sbin/nginx 跟 apt 装的同位置,
# 配置 /etc/nginx/* 路径不变,现有 /usr/local/nginx/* symlink 链路零改动
# (跟主控 Dockerfile 完全对称做法 — agent 代码里所有 /usr/local/nginx/sbin/nginx 路径直接 work)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    wget \
    curl \
    bash \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/nginx/sbin \
              /etc/nginx/cert \
              /etc/nginx/servers \
              /etc/nginx/stream_servers \
              /etc/nginx/html \
              /usr/local/etc/xray \
    && ln -sfn /usr/sbin/nginx           /usr/local/nginx/sbin/nginx \
    && ln -sfn /etc/nginx/nginx.conf     /usr/local/nginx/nginx.conf \
    && ln -sfn /etc/nginx/cert           /usr/local/nginx/cert \
    && ln -sfn /etc/nginx/servers        /usr/local/nginx/servers \
    && ln -sfn /etc/nginx/stream_servers /usr/local/nginx/stream_servers \
    && ln -sfn /etc/nginx/html           /usr/local/nginx/html

COPY --from=guard-builder /out/mmwx-guardd /usr/local/bin/mmwx-guardd
COPY --from=guard-builder /out/agent.manifest /usr/local/share/mmwx-guard/agent.manifest
RUN chmod 0755 /usr/local/bin/mmwx-guardd

COPY --from=builder /out/mmw-agent /usr/local/bin/mmw-agent

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 默认配置:
#  - DOCKER=1 让 agent 代码 isDocker() 识别容器环境
#  - MMWX_XRAY_MODE=embedded 强制 embedded(无外部 xray binary 可装,只能这条路)
#  - MMWX_REQUIRE_HOST_NETWORK=1 entrypoint 启动时强制检查 host 网络,bridge 模式拒启
ENV DOCKER=1 \
    MMWX_XRAY_MODE=embedded \
    MMWX_REQUIRE_HOST_NETWORK=1 \
    MMWX_GUARD_SOCKET=/run/mmwx-guard-agent/guard.sock

VOLUME ["/etc/mmw-agent", "/usr/local/etc/xray", "/etc/nginx/cert", "/etc/nginx/servers", "/var/lib/mmwx-guard"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/mmw-agent"]
