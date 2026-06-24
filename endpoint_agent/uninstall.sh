#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# uninstall.sh — remove the SOAR endpoint bundle from THIS host:
#   stop+remove the sensor, flush any SOAR firewall state, remove the AR scripts,
#   and (optionally) the Wazuh agent. Run as root.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
PURGE_WAZUH="no"
[ "${1:-}" = "--purge-wazuh" ] && PURGE_WAZUH="yes"

log() { printf '\n\033[1;36m[uninstall]\033[0m %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)."; exit 1; }

# ── 1. Sensor ─────────────────────────────────────────────────────────────────
if [ -f "$BUNDLE_DIR/sensor/docker-compose.yml" ] && command -v docker >/dev/null 2>&1; then
  log "Stopping the NFStream sensor…"
  ( cd "$BUNDLE_DIR/sensor" && docker compose down -v 2>/dev/null ) || true
fi

# ── 2. Flush SOAR firewall state (block sets + isolate chain) ─────────────────
log "Flushing any SOAR firewall state…"
nft list table inet soar >/dev/null 2>&1 && nft delete table inet soar 2>/dev/null || true
if command -v ipset >/dev/null 2>&1; then
  iptables -D OUTPUT  -m set --match-set soar_block dst -j DROP 2>/dev/null || true
  iptables -D FORWARD -m set --match-set soar_block dst -j DROP 2>/dev/null || true
  ipset destroy soar_block 2>/dev/null || true
fi
if command -v iptables >/dev/null 2>&1; then
  for ch in INPUT OUTPUT FORWARD; do
    while iptables -D "$ch" -j SOAR_ISOLATE 2>/dev/null; do :; done
  done
  iptables -F SOAR_ISOLATE 2>/dev/null || true
  iptables -X SOAR_ISOLATE 2>/dev/null || true
fi

# ── 3. Active-Response scripts ────────────────────────────────────────────────
log "Removing the Active-Response scripts…"
rm -f /var/ossec/active-response/bin/soar-block \
      /var/ossec/active-response/bin/soar-unblock \
      /var/ossec/active-response/bin/soar-isolate \
      /var/ossec/active-response/bin/soar-unisolate \
      /var/ossec/active-response/lib/soar-ar-common.sh \
      /var/ossec/active-response/soar-ar.env 2>/dev/null || true

# ── 4. Wazuh agent (optional) ─────────────────────────────────────────────────
if [ "$PURGE_WAZUH" = "yes" ]; then
  log "Purging wazuh-agent…"
  systemctl disable --now wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control stop 2>/dev/null || true
  if command -v apt-get >/dev/null 2>&1; then apt-get remove --purge -y wazuh-agent 2>/dev/null || true; fi
else
  log "Leaving wazuh-agent installed (pass --purge-wazuh to remove it). Restarting it…"
  systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart 2>/dev/null || true
fi

log "Teardown complete."
