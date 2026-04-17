FROM python:3.11-slim

# ── System dependencies required by nfstream/nDPI ────────────────────────────
# These mirror exactly what you installed manually on the host
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools for nDPI compilation
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    flex \
    bison \
    gettext \
    git \
    # nDPI runtime dependencies
    libjson-c-dev \
    libpcap-dev \
    libusb-1.0-0-dev \
    libbluetooth-dev \
    libnl-genl-3-dev \
    # libdbus optional but avoids warnings
    libdbus-glib-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ───────────────────────────────────────────────────────
# Install nfstream first (heaviest, most complex build)
# Pin to 6.5.3 — the last fully stable release before 6.6.0 introduced
# a cffi 2.x dependency that conflicts with Python 3.11 on Debian slim
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        nfstream==6.5.3 \
        kafka-python-ng==2.2.3 \
        pandas==2.2.2

COPY nfs_producer.py .

# The container must run as root for AF_PACKET capture.
# We grant only the two capabilities actually needed rather than
# running with --privileged (which would expose the entire host).
# These are set in docker-compose.yml via cap_add, not here.

CMD ["python", "-u", "nfs_producer.py"]
