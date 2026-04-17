FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ── Build dependencies ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    autoconf \
    automake \
    libtool \
    flex \
    bison \
    libpcap-dev \
    libwrap0-dev \
    libgmp-dev \
    libcurl4-openssl-dev \
    libbluetooth-dev \
    pkg-config \
    # Runtime tools
    tcpdump \
    python3 \
    python3-pip \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Build argus sensor (5.0) ──────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/openargus/argus.git && \
    cd argus && \
    autoreconf -fvi && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# ── Build argus clients (5.0) ─────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/openargus/clients.git && \
    cd clients && \
    autoreconf -fvi && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# ── Python tools for post-processing ─────────────────────────────────────────
RUN pip3 install --no-cache-dir pandas numpy

WORKDIR /app

COPY argus.conf       /etc/argus.conf
COPY extract.sh       /app/extract.sh
COPY compare_features.py /app/compare_features.py

RUN chmod +x /app/extract.sh

# Directories for mounted volumes
RUN mkdir -p /pcaps /output

CMD ["/bin/bash"]