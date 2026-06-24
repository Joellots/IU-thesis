#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# detctl — single control surface for the Aegis *detection engine* + endpoint agent.
#
#   ./scripts/detctl.sh <command> [args]
#
# Wraps the docker-compose stack, the dataset-replay simulation, the data/model
# utilities, and the Wazuh endpoint agent (Active-Response). Counterpart to the
# SOAR side's soarctl.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# Seamless first run: Compose needs .env (env_file) — create it from the template.
if [ ! -f .env ] && [ -f .env.example ]; then
  cp .env.example .env
  echo "[detctl] created .env from .env.example — review it before a cross-machine deploy."
fi

DC="docker compose -f docker-compose.yml"
SIM="-f docker-compose.sim.yml"
PG="docker exec -e PAGER=cat postgres psql -U user -d soar"
PIPELINE=(kafka postgres inference translator dashboard dashboard-web)   # always-on
AR_BIN="/var/ossec/active-response/bin"
ISO_CHAIN="SOAR_ISOLATE"

detctl_py() {            # prefer a project venv, else $DETCTL_PY, else python3
  for p in "$REPO/.venv/bin/python" "$REPO/venv/bin/python"; do
    [ -x "$p" ] && { echo "$p"; return; }
  done
  echo "${DETCTL_PY:-python3}"
}

usage() {
  cat <<EOF
detctl — Aegis detection engine + endpoint agent

STACK            up [svc]  down  reset  build [svc]  restart [svc]  status  logs [svc]  config
SIMULATION       sim [AGENT_ID]   replay
INSPECT (DB)     alerts   approvals   psql
DATA & MODEL     dataset [args]   eval [args]   fetch-pcaps [args]   fetch-mta [args]
ENDPOINT AGENT   agent <status|blocks|ar-log [-f]|block <ip>|unblock <ip>|isolate|unisolate|install [args]|uninstall|package>

Examples:
  ./scripts/detctl.sh reset                 # clean DB + bring the pipeline up
  ./scripts/detctl.sh sim 001               # replay AS this host's Wazuh agent 001
  ./scripts/detctl.sh approvals             # pending SOAR block/isolate actions
  ./scripts/detctl.sh agent status          # Wazuh agent + AR scripts + enforced blocks
  ./scripts/detctl.sh agent block 8.8.8.8   # manually add a reversible endpoint block
  ./scripts/detctl.sh agent isolate         # manually isolate this endpoint
  ./scripts/detctl.sh agent ar-log -f       # watch Active-Response executions
  ./scripts/detctl.sh agent unisolate       # recover if the host got isolated

URLs: dashboard(htmx) :8080 · dashboard(React) :3000 · kafka-ui :8081
EOF
}

# ── Endpoint-agent subcommands ────────────────────────────────────────────────
agent_cmd() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status)
      echo "── Wazuh agent ──"; sudo /var/ossec/bin/wazuh-control status 2>/dev/null | grep -iE 'agentd|execd' || echo "(agent not installed)"
      sudo grep -E 'status=|last_keepalive' /var/ossec/var/run/wazuh-agentd.state 2>/dev/null
      echo "── AR scripts ──"; sudo bash -c "ls $AR_BIN/soar-* 2>/dev/null" || echo "(soar-* AR scripts not installed)"
      echo "── Enforced blocks (nft) ──"; sudo nft list table inet soar 2>/dev/null | grep -E 'elements|drop' || echo "(none)"
      echo "── Isolated? ──"; sudo iptables -L "$ISO_CHAIN" -n >/dev/null 2>&1 && echo "ISOLATED (run: detctl agent unisolate)" || echo "no" ;;
    blocks)   sudo nft list table inet soar 2>/dev/null || echo "(no blocks enforced)" ;;
    ar-log)   sudo tail ${1:-} /var/ossec/logs/active-responses.log ;;
    block)
      [ -n "${1:-}" ] || { echo "usage: detctl agent block <ip>"; return 1; }
      printf '{"command":"add","parameters":{"extra_args":["%s"]}}' "$1" | sudo "$AR_BIN/soar-block" ;;
    unblock)
      [ -n "${1:-}" ] || { echo "usage: detctl agent unblock <ip>"; return 1; }
      printf '{"command":"delete","parameters":{"extra_args":["%s"]}}' "$1" | sudo "$AR_BIN/soar-unblock" ;;
    isolate)
      printf '{"command":"add","parameters":{}}' | sudo "$AR_BIN/soar-isolate" ;;
    unisolate)
      for ch in INPUT OUTPUT FORWARD; do while sudo iptables -D "$ch" -j "$ISO_CHAIN" 2>/dev/null; do :; done; done
      sudo iptables -F "$ISO_CHAIN" 2>/dev/null; sudo iptables -X "$ISO_CHAIN" 2>/dev/null
      echo "un-isolated (SOAR_ISOLATE chain removed)" ;;
    install)   sudo "$REPO/endpoint_agent/install.sh" "$@" ;;
    uninstall) sudo "$REPO/endpoint_agent/uninstall.sh" "$@" ;;
    package)   "$REPO/endpoint_agent/package.sh" ;;
    *) echo "agent: unknown '$sub' (status|blocks|ar-log|block|unblock|isolate|unisolate|install|uninstall|package)"; return 1 ;;
  esac
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  # ── stack ──
  up|start)   if [ "$#" -eq 0 ]; then $DC up -d "${PIPELINE[@]}"; else $DC up -d "$@"; fi ;;
  down|stop)  $DC down ;;
  reset)      $DC down -v; $DC up -d --build "${PIPELINE[@]}"; echo "reset: fresh DB + pipeline up." ;;
  build)      $DC build "$@" ;;
  restart)    $DC restart "$@" ;;
  status|ps)  $DC ps ;;
  logs)       $DC logs -f "$@" ;;
  config)     $DC $SIM config >/dev/null && echo "compose config valid" ;;

  # ── simulation ──
  sim)
    $DC $SIM up -d --build "${PIPELINE[@]}"; sleep 3
    if [ -n "${1:-}" ]; then
      echo "replay-as-endpoint: stamping agent_id=$1 onto every flow"
      SIM_AGENT_ID="$1" $DC $SIM up -d producer
    else
      $DC $SIM up -d producer
    fi
    echo "replaying — 'detctl logs producer' · 'detctl alerts' · 'detctl approvals'" ;;
  replay)     $DC up -d producer; echo "continuous replay (LOOP=true)." ;;

  # ── inspect ──
  alerts)
    $PG -c "SELECT pred_label, count(*) n,
              count(*) FILTER (WHERE mapping_status='mapped') mapped,
              count(*) FILTER (WHERE observables @> '[{\"type\":\"ja3\"}]') has_ja3,
              count(*) FILTER (WHERE agent_id IS NOT NULL) with_endpoint,
              round(avg(mapping_confidence)::numeric,3) avg_conf
            FROM alerts GROUP BY pred_label ORDER BY pred_label;" ;;
  approvals)
    $PG -c "SELECT to_regclass('public.soar_pending_approvals')" 2>/dev/null | grep -q soar_pending_approvals \
      && $PG -c "SELECT id, action_type, target_value, agent_id, status,
                   round(extract(epoch FROM (expires_ts-now()))/60) AS mins_left
                 FROM soar_pending_approvals WHERE status='pending' ORDER BY id DESC LIMIT 30;" \
      || echo "(soar_pending_approvals not present — the SOAR orchestrator hasn't created it yet)" ;;
  psql)       docker exec -it postgres psql -U user -d soar ;;

  # ── data & model (host python) ──
  dataset)    "$(detctl_py)" utils/build_training_dataset.py "$@" ;;
  eval)       "$(detctl_py)" utils/nfstream_model_eval.py "$@" ;;
  fetch-pcaps) "$(detctl_py)" utils/fetch_pcaps.py "$@" ;;
  fetch-mta)  "$(detctl_py)" utils/fetch_mta_pcaps.py "$@" ;;

  # ── endpoint agent ──
  agent)      agent_cmd "$@" ;;

  help|-h|--help) usage ;;
  *) echo "detctl: unknown command '$cmd'"; echo; usage; exit 1 ;;
esac
