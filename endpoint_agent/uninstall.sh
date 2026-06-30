#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# uninstall.sh — remove the SOAR endpoint bundle from THIS host. Scope is
# composable so it mirrors install.sh's --no-sensor / --no-wazuh modes.
#
#   sudo ./uninstall.sh                 # sensor + AR + firewall flush; restart wazuh
#   sudo ./uninstall.sh --sensor-only   # ONLY tear down the sensor (wazuh + AR untouched)
#   sudo ./uninstall.sh --no-sensor     # remove AR (+ wazuh action), leave the sensor
#   sudo ./uninstall.sh --no-wazuh      # don't touch wazuh at all (no restart, no purge)
#   sudo ./uninstall.sh --purge-wazuh   # also apt-purge the agent + remove repo/key
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"

REMOVE_SENSOR="yes"     # tear down the NFStream sensor container
REMOVE_AR="yes"         # remove AR scripts + flush SOAR firewall state (coupled)
WAZUH_ACTION="restart"  # restart | purge | none

usage() {
  cat <<EOF
Usage: sudo ./uninstall.sh [scope]

  (default)        remove sensor + AR scripts + flush firewall, then restart wazuh
  --sensor-only    remove ONLY the sensor; leave AR, firewall and wazuh untouched
  --no-sensor      keep the sensor; remove AR + apply the wazuh action
  --keep-ar        keep the AR scripts + firewall state
  --no-wazuh       leave the wazuh agent completely untouched (no restart/purge)
  --purge-wazuh    apt-purge wazuh-agent and remove its apt repo + signing key
  -h, --help       this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --sensor-only) REMOVE_SENSOR="yes"; REMOVE_AR="no"; WAZUH_ACTION="none"; shift ;;
    --no-sensor)   REMOVE_SENSOR="no"; shift ;;
    --keep-ar)     REMOVE_AR="no"; shift ;;
    --no-wazuh)    WAZUH_ACTION="none"; shift ;;
    --purge-wazuh) WAZUH_ACTION="purge"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "unknown option: $1"; usage; exit 1 ;;
  esac
done

log() { printf '\n\033[1;36m[uninstall]\033[0m %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)."; exit 1; }

# ── 1. Sensor ─────────────────────────────────────────────────────────────────
if [ "$REMOVE_SENSOR" = "yes" ]; then
  if [ -f "$BUNDLE_DIR/sensor/docker-compose.yml" ] && command -v docker >/dev/null 2>&1; then
    log "Stopping the NFStream sensor…"
    ( cd "$BUNDLE_DIR/sensor" && docker compose down -v 2>/dev/null ) || true
  else
    log "Sensor compose not found / docker absent — nothing to stop."
  fi
fi

# ── 2. Flush SOAR firewall state + Active-Response scripts (coupled) ──────────
if [ "$REMOVE_AR" = "yes" ]; then
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

  log "Removing the Active-Response scripts…"
  rm -f /var/ossec/active-response/bin/soar-block \
        /var/ossec/active-response/bin/soar-unblock \
        /var/ossec/active-response/bin/soar-isolate \
        /var/ossec/active-response/bin/soar-unisolate \
        /var/ossec/active-response/lib/soar-ar-common.sh \
        /var/ossec/active-response/soar-ar.env 2>/dev/null || true
fi

# ── 3. Wazuh agent ────────────────────────────────────────────────────────────
case "$WAZUH_ACTION" in
  purge)
    log "Purging wazuh-agent…"
    systemctl disable --now wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control stop 2>/dev/null || true
    command -v apt-get >/dev/null 2>&1 && apt-get remove --purge -y wazuh-agent 2>/dev/null || true
    # Symmetric cleanup of the apt repo + signing key so install/uninstall fully reverse each
    # other. (install.sh re-imports the key and re-writes the repo, so a later reinstall is fine.)
    log "Removing the Wazuh apt repo + signing key…"
    rm -f /etc/apt/sources.list.d/wazuh.list \
          /usr/share/keyrings/wazuh.gpg /usr/share/keyrings/wazuh.gpg~ 2>/dev/null || true
    command -v apt-get >/dev/null 2>&1 && apt-get update -y 2>/dev/null || true ;;
  restart)
    log "Leaving wazuh-agent installed (restarting it). Use --purge-wazuh to remove, --no-wazuh to leave as-is."
    systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart 2>/dev/null || true ;;
  none)
    log "Wazuh agent left completely untouched." ;;
esac

log "Teardown complete."
