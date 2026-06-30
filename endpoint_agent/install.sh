#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — provision THIS host as a SOAR endpoint: NFStream SENSOR (feeds the
# detection pipeline) + Wazuh AGENT (ACTUATOR for SOAR-ordered block/isolate).
#
# Run as root on a fresh Debian/Ubuntu VM:
#   sudo ./install.sh --manager-host 172.31.80.148 --kafka-broker 172.31.87.134:9094
#
# Idempotent-ish: safe to re-run. See uninstall.sh to tear it all down.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Defaults (override via flags or env) ──────────────────────────────────────
MANAGER_HOST="${MANAGER_HOST:-}"
KAFKA_BROKER="${KAFKA_BROKER:-}"
AGENT_NAME="${AGENT_NAME:-$(hostname -s 2>/dev/null || hostname)}"
INTERFACE="${INTERFACE:-}"                       # empty → capture "any"
REGISTRATION_PASSWORD="${REGISTRATION_PASSWORD:-}"
ENROLL_PORT="${ENROLL_PORT:-1515}"               # authd enrollment
COMMS_PORT="${COMMS_PORT:-1516}"                 # agent comms (→ manager 1514)
WAZUH_VERSION="${WAZUH_VERSION:-4.14.5-1}"
BLOCK_TTL="${BLOCK_TTL:-3600}"
# Capture filter (kernel BPF). Default = all TCP (any port) so we never miss encrypted C2 on
# an unforeseen port; the sensor then forwards only TLS/QUIC-classified flows (ENCRYPTED_ONLY),
# keeping plaintext (SSH/HTTP/pipeline) out of the model. Override with --bpf for a custom set.
BPF_FILTER="${BPF_FILTER:-tcp}"
ENCRYPTED_ONLY="${ENCRYPTED_ONLY:-true}"
DEPLOY_SENSOR="yes"
DEPLOY_WAZUH="yes"
QUERY_AGENT_ID="no"

usage() {
  cat <<EOF
Usage: sudo ./install.sh --manager-host <ip> --kafka-broker <host:port> [options]

Required:
  --manager-host <ip>        Wazuh manager / SOAR host (enrollment + comms target)
  --kafka-broker <host:port> Detection host's external Kafka listener (sensor → raw_flows)

Options:
  --agent-name <name>        Wazuh agent name = host_id   (default: $AGENT_NAME)
  --interface <iface>        Capture interface            (default: any)
  --bpf <filter>             kernel capture filter (default: all TCP; sensor keeps only TLS/QUIC)
  --registration-password <pw>  authd shared password (if the manager requires one)
  --enroll-port <port>       authd enrollment port        (default: $ENROLL_PORT)
  --comms-port <port>        agent comms port             (default: $COMMS_PORT)
  --wazuh-version <ver>      wazuh-agent apt version      (default: $WAZUH_VERSION)
  --block-ttl <seconds>      auto-expiry for soar-block   (default: $BLOCK_TTL)
  --no-sensor                skip the NFStream sensor (Wazuh agent only)
  --no-wazuh                 skip the Wazuh agent (sensor only; --manager-host not needed)
  --agent-id                 print this host's enrolled Wazuh agent id and exit
  -h, --help                 this help

Modes:
  full (default)             sensor + Wazuh agent + Active-Response
  --no-wazuh                 sensor only      (re)deploys just the NFStream sensor
  --no-sensor                Wazuh agent only (agent + AR, no sensor)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --manager-host)          MANAGER_HOST="$2"; shift 2 ;;
    --kafka-broker)          KAFKA_BROKER="$2"; shift 2 ;;
    --agent-name)            AGENT_NAME="$2"; shift 2 ;;
    --interface)             INTERFACE="$2"; shift 2 ;;
    --bpf)                   BPF_FILTER="$2"; shift 2 ;;
    --registration-password) REGISTRATION_PASSWORD="$2"; shift 2 ;;
    --enroll-port)           ENROLL_PORT="$2"; shift 2 ;;
    --comms-port)            COMMS_PORT="$2"; shift 2 ;;
    --wazuh-version)         WAZUH_VERSION="$2"; shift 2 ;;
    --block-ttl)             BLOCK_TTL="$2"; shift 2 ;;
    --no-sensor)             DEPLOY_SENSOR="no"; shift ;;
    --no-wazuh)              DEPLOY_WAZUH="no"; shift ;;
    --agent-id)              QUERY_AGENT_ID="yes"; shift ;;
    -h|--help)               usage; exit 0 ;;
    *) echo "unknown option: $1"; usage; exit 1 ;;
  esac
done

log() { printf '\n\033[1;36m[install]\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m[install] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# This host's enrolled Wazuh agent id (field 1 of client.keys), empty if not enrolled.
current_agent_id() { awk 'NR==1{print $1}' /var/ossec/etc/client.keys 2>/dev/null; }

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo)."

# --agent-id: pure query, no install. Print the id and exit (non-zero if not enrolled).
if [ "$QUERY_AGENT_ID" = "yes" ]; then
  id="$(current_agent_id)"
  [ -n "$id" ] && { echo "$id"; exit 0; } || die "not enrolled (no /var/ossec/etc/client.keys) — install with Wazuh first."
fi

# --manager-host is only needed when we actually deploy/enrol the Wazuh agent.
[ "$DEPLOY_WAZUH" = "no" ] || [ -n "$MANAGER_HOST" ] || { usage; die "--manager-host is required (omit it only with --no-wazuh)."; }
[ "$DEPLOY_SENSOR" = "no" ] || [ -n "$KAFKA_BROKER" ] || { usage; die "--kafka-broker is required (or pass --no-sensor)."; }
[ "$DEPLOY_SENSOR" = "no" ] && [ "$DEPLOY_WAZUH" = "no" ] && die "nothing to do: --no-sensor and --no-wazuh both set."

# ── 1. Wazuh agent (the actuator) ─────────────────────────────────────────────
if [ "$DEPLOY_WAZUH" = "yes" ]; then
  command -v apt-get >/dev/null 2>&1 || die "this installer targets Debian/Ubuntu (apt). For RHEL, adapt the repo step."
  log "Installing wazuh-agent $WAZUH_VERSION (manager $MANAGER_HOST)…"
  if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
  fi
  # Always (re)write the repo ENABLED before update. The post-install step below comments it
  # out to pin the version; on a reinstall that left-behind '#deb' line would make apt unable
  # to locate wazuh-agent — so we must re-enable it here regardless of the keyring's presence.
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -y
  WAZUH_MANAGER="$MANAGER_HOST" WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y "wazuh-agent=$WAZUH_VERSION" || die "wazuh-agent install failed (version pin? try --wazuh-version)."
  # keep the agent from auto-upgrading past the manager's version
  sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list 2>/dev/null || true

  log "Pointing comms at $MANAGER_HOST:$COMMS_PORT …"
  # set the manager address + comms port in the <client><server> block
  sed -i "0,/<address>.*<\/address>/s//<address>$MANAGER_HOST<\/address>/" /var/ossec/etc/ossec.conf
  sed -i "0,/<port>1514<\/port>/s//<port>$COMMS_PORT<\/port>/" /var/ossec/etc/ossec.conf

  log "Enrolling at $MANAGER_HOST:$ENROLL_PORT as '$AGENT_NAME' …"
  PW_ARGS=()
  [ -n "$REGISTRATION_PASSWORD" ] && PW_ARGS=(-P "$REGISTRATION_PASSWORD")
  /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p "$ENROLL_PORT" -A "$AGENT_NAME" "${PW_ARGS[@]}" \
    || die "enrollment failed — check the manager authd (:$ENROLL_PORT) and the registration password."

  # ── 2. Active-Response scripts (the vetted allowlist) ───────────────────────
  log "Installing the four Active-Response scripts (root:wazuh, 0750)…"
  install -d -m 0750 /var/ossec/active-response/bin /var/ossec/active-response/lib
  install -m 0750 "$BUNDLE_DIR"/active-response/bin/soar-block \
                  "$BUNDLE_DIR"/active-response/bin/soar-unblock \
                  "$BUNDLE_DIR"/active-response/bin/soar-isolate \
                  "$BUNDLE_DIR"/active-response/bin/soar-unisolate \
                  /var/ossec/active-response/bin/
  install -m 0640 "$BUNDLE_DIR"/active-response/lib/soar-ar-common.sh /var/ossec/active-response/lib/
  cat > /var/ossec/active-response/soar-ar.env <<EOF
# Written by install.sh — read by the SOAR Active-Response scripts.
MANAGER_HOST=$MANAGER_HOST
MANAGER_PORTS="$COMMS_PORT $ENROLL_PORT 1514 55000"
SOAR_BLOCK_TTL=$BLOCK_TTL
SOAR_FW_BACKEND=auto
EOF
  chmod 0640 /var/ossec/active-response/soar-ar.env
  chown root:wazuh /var/ossec/active-response/bin/soar-* \
                   /var/ossec/active-response/lib/soar-ar-common.sh \
                   /var/ossec/active-response/soar-ar.env

  log "Starting wazuh-agent…"
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable --now wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control start

  AGENT_ID="$(current_agent_id)"
  log "Enrolled as agent_id=${AGENT_ID:-unknown} name=$AGENT_NAME"
else
  # sensor-only: recover the id from the existing enrolment so the sensor still
  # stamps the right agent_id (env override wins if explicitly supplied).
  AGENT_ID="${AGENT_ID:-$(current_agent_id)}"
  [ -n "$AGENT_ID" ] && log "Reusing enrolled agent_id=$AGENT_ID (from client.keys)" \
                     || log "No Wazuh enrolment found — sensor flows will carry an empty agent_id."
fi

# ── 3. NFStream sensor (the sensor) ───────────────────────────────────────────
if [ "$DEPLOY_SENSOR" = "yes" ]; then
  command -v docker >/dev/null 2>&1 || die "docker is required for the sensor (install Docker, or use --no-sensor)."

  # Populate the sensor build context from the bundle snapshot, or the repo.
  if [ ! -f "$BUNDLE_DIR/sensor/app/nfstream_producer.py" ]; then
    if [ -f "$BUNDLE_DIR/../services/nfstream/nfstream_producer.py" ]; then
      mkdir -p "$BUNDLE_DIR/sensor/app"
      cp "$BUNDLE_DIR/../services/nfstream/nfstream_producer.py" \
         "$BUNDLE_DIR/../services/nfstream/requirements.txt" "$BUNDLE_DIR/sensor/app/"
    else
      die "sensor/app not populated and repo source not found — run ./package.sh first."
    fi
  fi

  HOST_IP="${HOST_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')}"
  log "Deploying the NFStream sensor → Kafka $KAFKA_BROKER (host_ip=$HOST_IP)…"
  cat > "$BUNDLE_DIR/sensor/.env" <<EOF
KAFKA_BROKER=$KAFKA_BROKER
TOPIC=raw_flows
INTERFACE=$INTERFACE
BPF_FILTER=$BPF_FILTER
ENCRYPTED_ONLY=$ENCRYPTED_ONLY
IDLE_TIMEOUT=15
ACTIVE_TIMEOUT=120
AGENT_ID=${AGENT_ID:-}
HOST_ID=$AGENT_NAME
HOST_IP=$HOST_IP
EOF
  ( cd "$BUNDLE_DIR/sensor" && docker compose up -d --build )
  log "Sensor running (container soar_endpoint_sensor)."
fi

roles="$([ "$DEPLOY_SENSOR" = yes ] && echo SENSOR)$([ "$DEPLOY_SENSOR" = yes ] && [ "$DEPLOY_WAZUH" = yes ] && echo " + ")$([ "$DEPLOY_WAZUH" = yes ] && echo ACTUATOR)"
log "Done. This host is now: ${roles:-(nothing deployed)}."
[ -n "${AGENT_ID:-}" ] && echo "      agent_id=$AGENT_ID  (query anytime:  sudo ./install.sh --agent-id)"
echo   "      Verify:  /var/ossec/bin/wazuh-control status ; docker logs -f soar_endpoint_sensor"
