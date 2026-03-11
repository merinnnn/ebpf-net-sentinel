ARG UBUNTU_VERSION=20.04

FROM ubuntu:${UBUNTU_VERSION} AS live

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CONDA_DIR=/opt/conda \
    NETSENTINEL_REPO_ROOT=/opt/netsentinel \
    NETSENTINEL_DATA_DIR=/opt/netsentinel/data \
    NETSENTINEL_APP_CACHE_DIR=/opt/netsentinel/data/app \
    NETSENTINEL_DISABLE_EXTERNAL_FONTS=true \
    NETSENTINEL_GENERATE_MOCK_LIVE_RUN=false \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    PATH=/opt/conda/bin:/opt/zeek/bin:/usr/local/go/bin:${PATH}

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
    sudo \
    tini \
    && curl -fsSL https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh -o /tmp/miniforge.sh \
    && bash /tmp/miniforge.sh -b -p "${CONDA_DIR}" \
    && rm -f /tmp/miniforge.sh \
    && "${CONDA_DIR}/bin/conda" install -y python=3.11 pip \
    && "${CONDA_DIR}/bin/conda" clean -afy \
    && ln -sf "${CONDA_DIR}/bin/python" /usr/local/bin/python3 \
    && ln -sf "${CONDA_DIR}/bin/python" /usr/local/bin/python \
    && ln -sf "${CONDA_DIR}/bin/pip" /usr/local/bin/pip \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r /tmp/requirements.txt

COPY . .

RUN chmod +x docker/entrypoint.sh docker/install_live_deps.sh
RUN /opt/netsentinel/docker/install_live_deps.sh

EXPOSE 8501

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/netsentinel/docker/entrypoint.sh"]
CMD ["live-monitor"]
