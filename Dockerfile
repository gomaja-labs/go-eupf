# The toolchain stage is shared by the application build and CI. Override only
# GO_VERSION for the minimum-Go CI job; clang stays identical in both builds.
ARG GO_VERSION=1.27.4
FROM golang:${GO_VERSION}-bookworm AS toolchain
ARG BUILD_UID=10001
ARG BUILD_GID=10001
RUN apt-get update \
    && apt-get install --no-install-recommends -y clang-14 llvm-14 gcc-multilib libbpf-dev \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g "${BUILD_GID}" build \
    && useradd -m -u "${BUILD_UID}" -g build build \
    && mkdir /app \
    && chown build:build /app /go
ENV BPF2GO_CC=clang-14 BPF2GO_STRIP=llvm-strip-14
USER build
WORKDIR /app

FROM toolchain AS builder
COPY --chown=build:build go.mod go.sum ./
RUN go mod download
COPY --chown=build:build cmd cmd
ARG BPF_ENABLE_LOG=0
RUN BPF_CFLAGS="" \
    && if [ "$BPF_ENABLE_LOG" = "1" ]; then BPF_CFLAGS="$BPF_CFLAGS -DENABLE_LOG"; fi \
    && BPF_CFLAGS=$BPF_CFLAGS go generate -v ./cmd/...
RUN CGO_ENABLED=0 go build -v -o bin/eupf ./cmd/

# Tests compile as the unprivileged build user. Only test executables, mounts,
# and the integration server run through sudo in a private network namespace.
FROM toolchain AS development
COPY --from=golangci/golangci-lint:v2.15.0 /usr/bin/golangci-lint /usr/local/bin/golangci-lint
USER root
RUN apt-get update \
    && apt-get install --no-install-recommends -y sudo python3-venv tcpdump iproute2 procps \
    && rm -rf /var/lib/apt/lists/* \
    && echo 'build ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/build \
    && python3 -m venv /opt/py \
    && /opt/py/bin/pip install --no-cache-dir pytest==9.2.0 scapy==2.8.0
ENV PATH=/opt/py/bin:/lint-tools:${PATH}
USER build

FROM toolchain AS cli-builder
COPY --chown=build:build go.mod go.sum ./
RUN go mod download
COPY --chown=build:build cli cli
RUN CGO_ENABLED=0 go build -o bin/eupf ./cli/app

FROM alpine:3.24.4 AS cli
RUN apk add --no-cache bash bash-completion
WORKDIR /root
ENV PATH=/root:${PATH}
COPY --from=cli-builder /app/bin/eupf ./eupf
RUN ./eupf completion bash > /usr/share/bash-completion/completions/eupf \
    && echo 'source /usr/share/bash-completion/bash_completion' >> /root/.bashrc
CMD ["bash", "-c", "while true; do sleep 60; done"]

FROM alpine:3.24.4 AS runtime
LABEL org.opencontainers.image.source="https://github.com/gomaja-labs/go-eupf"
COPY --from=builder /app/bin/ /app/bin/
COPY --from=builder /app/cmd/docs/swagger.* /app/
COPY --from=builder /app/cmd/ebpf/zeroentrypoint_bpf.o /app/
COPY entrypoint.sh /app/bin/entrypoint.sh
RUN apk add --no-cache libcap \
    && setcap cap_net_admin,cap_net_raw,cap_sys_resource,cap_bpf,cap_perfmon,cap_dac_override=ep /app/bin/eupf \
    && apk del libcap
ENTRYPOINT ["sh", "/app/bin/entrypoint.sh"]
