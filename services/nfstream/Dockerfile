FROM python:3.11-slim

# ── System dependencies required by nfstream / nDPI ──────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-dev \
    autoconf \
    automake \
    libtool \
    pkg-config \
    flex \
    bison \
    gettext \
    libjson-c-dev \
    libpcap-dev \
    libpcap0.8 \
    libusb-1.0-0-dev \
    libbluetooth-dev \
    libnl-genl-3-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nfstream_producer.py .

CMD ["python", "-u", "nfstream_producer.py"]