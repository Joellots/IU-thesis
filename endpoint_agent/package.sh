#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# package.sh — produce a self-contained, shippable bundle tarball.
# Snapshots the canonical NFStream sensor (services/nfstream) into sensor/app/ so
# the bundle builds on a remote endpoint with no repo checkout, then tars it.
#
#   ./package.sh            → dist/soar-endpoint-agent.tar.gz
# On the endpoint:  tar xzf soar-endpoint-agent.tar.gz && cd endpoint_agent
#                   sudo ./install.sh --manager-host <ip> --kafka-broker <host:port>
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$BUNDLE_DIR/.." && pwd)"
SRC="$REPO_DIR/services/nfstream"

[ -f "$SRC/nfstream_producer.py" ] || { echo "canonical sensor not found at $SRC"; exit 1; }

echo "[package] snapshotting $SRC → sensor/app/ (single source of truth)…"
mkdir -p "$BUNDLE_DIR/sensor/app"
cp "$SRC/nfstream_producer.py" "$SRC/requirements.txt" "$BUNDLE_DIR/sensor/app/"

echo "[package] making scripts executable…"
chmod 0755 "$BUNDLE_DIR"/install.sh "$BUNDLE_DIR"/uninstall.sh "$BUNDLE_DIR"/package.sh
chmod 0755 "$BUNDLE_DIR"/active-response/bin/soar-*

mkdir -p "$REPO_DIR/dist"
TARBALL="$REPO_DIR/dist/soar-endpoint-agent.tar.gz"
echo "[package] writing $TARBALL …"
tar -C "$REPO_DIR" \
    --exclude='endpoint_agent/sensor/.env' \
    --exclude='endpoint_agent/dist' \
    -czf "$TARBALL" endpoint_agent

echo "[package] done → $TARBALL"
echo "          ship it, then on the endpoint:"
echo "          tar xzf soar-endpoint-agent.tar.gz && cd endpoint_agent && sudo ./install.sh --manager-host <ip> --kafka-broker <host:port>"
