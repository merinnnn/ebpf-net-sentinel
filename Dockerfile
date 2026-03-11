ARG UBUNTU_VERSION=20.04

FROM ubuntu:${UBUNTU_VERSION} AS live

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
    PATH=/opt/zeek/bin:/usr/local/go/bin:${PATH}

WORKDIR /opt/netsentinel

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    gnupg \
    iproute2 \
    jq \
    procps \
    software-properties-common \
    sudo \
    tini \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-venv \
    python3.11-distutils \
    && curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
    && python3.11 /tmp/get-pip.py \
    && ln -sf /usr/bin/python3.11 /usr/local/bin/python3 \
    && ln -sf /usr/bin/python3.11 /usr/local/bin/python \
    && rm -f /tmp/get-pip.py \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r /tmp/requirements.txt

COPY . .

RUN chmod +x docker/entrypoint.sh docker/install_live_deps.sh
RUN /opt/netsentinel/docker/install_live_deps.sh

EXPOSE 8501

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/netsentinel/docker/entrypoint.sh"]
CMD ["live-monitor"]
