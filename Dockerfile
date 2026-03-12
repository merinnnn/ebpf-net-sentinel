ARG UBUNTU_VERSION=20.04
ARG GO_VERSION=1.21

FROM golang:${GO_VERSION}-bookworm AS netmon_builder

WORKDIR /src/ebpf_core/cmd/netmon

COPY ebpf_core/cmd/netmon/ ./
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/netmon .

FROM ubuntu:${UBUNTU_VERSION} AS live_monitor_app

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETSENTINEL_REPO_ROOT=/opt/netsentinel \
    NETSENTINEL_DATA_DIR=/opt/netsentinel/data \
    NETSENTINEL_APP_CACHE_DIR=/opt/netsentinel/data/app \
    NETSENTINEL_DISABLE_EXTERNAL_FONTS=true \
    NETSENTINEL_GENERATE_MOCK_LIVE_RUN=false \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    PATH=/opt/zeek/bin:${PATH}

WORKDIR /opt/netsentinel

LABEL org.opencontainers.image.title="live-monitor-app"
LABEL org.opencontainers.image.description="Container image for the NetSentinel Live Monitor App"

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    tini \
    && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r /tmp/requirements.txt

COPY app /opt/netsentinel/app
COPY docker /opt/netsentinel/docker
COPY ubuntu /opt/netsentinel/ubuntu
COPY ebpf_core/Makefile /opt/netsentinel/ebpf_core/Makefile
COPY ebpf_core/bpf /opt/netsentinel/ebpf_core/bpf

RUN mkdir -p /opt/netsentinel/data /opt/netsentinel/ebpf_core/bin
COPY --from=netmon_builder /out/netmon /opt/netsentinel/ebpf_core/bin/netmon

RUN chmod +x docker/entrypoint.sh docker/install_live_deps.sh
RUN /opt/netsentinel/docker/install_live_deps.sh

EXPOSE 8501

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/netsentinel/docker/entrypoint.sh"]
CMD ["live-monitor-app"]
