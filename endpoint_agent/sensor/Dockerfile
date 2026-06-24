# Endpoint NFStream sensor — mirrors services/nfstream/Dockerfile but builds
# from the snapshot under app/ (populated by package.sh so the bundle is
# self-contained and shippable to a remote endpoint with no repo checkout).
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-dev autoconf automake libtool pkg-config flex bison gettext \
    libjson-c-dev libpcap-dev libpcap0.8 libusb-1.0-0-dev libbluetooth-dev \
    libnl-genl-3-dev iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/nfstream_producer.py .

CMD ["python", "-u", "nfstream_producer.py"]
