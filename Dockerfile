ARG UBUNTU_VERSION=22.04

FROM ubuntu:${UBUNTU_VERSION} AS base

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
    python3 \
    python3-pip \
    python3-setuptools \
    python3-venv \
    python-is-python3 \
    sudo \
    tini \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r /tmp/requirements.txt

COPY . .

RUN chmod +x docker/entrypoint.sh docker/install_live_deps.sh

EXPOSE 8501

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/netsentinel/docker/entrypoint.sh"]
CMD ["streamlit"]


FROM base AS app


FROM base AS live

RUN /opt/netsentinel/docker/install_live_deps.sh
