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
SIMULATION       sim [AGENT_ID]   replay   pcap-replay <list|all|--family|--class|--malicious-only|...> (--help)
METRICS          sim-harvest <begin [--reset] | end | render | all>
INSPECT (DB)     alerts   approvals   psql
DATA & MODEL     dataset [args]   eval [args]   fetch-pcaps [args]   fetch-mta [args]
ENDPOINT AGENT   agent <status|blocks|ar-log [-f]|block <ip>|unblock <ip>|isolate|unisolate|install [args]|uninstall|package>

Examples:
  ./scripts/detctl.sh reset                 # clean DB + bring the pipeline up
  ./scripts/detctl.sh sim-harvest begin     # watermark BEFORE a simulation run
  ./scripts/detctl.sh sim 001               # replay AS this host's Wazuh agent 001
  ./scripts/detctl.sh sim-harvest all       # AFTER: capture metrics + render figures
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

# ── Detection-side metric harvest (non-destructive) ───────────────────────────
# Splits by image: data phases need psycopg2 (dashboard image), figures need
# matplotlib (inference image). Repo isn't mounted in the running containers, so
# we spin one-off containers with a bind mount. Images/network resolved from the
# live stack so this survives a differently-named deploy dir.
img_of() { docker inspect -f '{{.Config.Image}}' "$1" 2>/dev/null || echo "$2"; }

sim_harvest_cmd() {
  local sub="${1:-}"; shift || true
  local dash inf dburl
  dash="$(img_of dashboard dev-dashboard)"; inf="$(img_of inference dev-inference)"
  dburl="${DATABASE_URL:-postgresql://user:pass@postgres:5432/soar}"
  local RUN=(docker run --rm -i --user "$(id -u):$(id -g)" -v "$REPO:/work" -w /work)
  local data=("${RUN[@]}" --network dev_net -e DATABASE_URL="$dburl" "$dash" python utils/sim_harvest.py)
  local figs=("${RUN[@]}" -e MPLCONFIGDIR=/tmp/mpl "$inf" python utils/sim_harvest.py render)
  case "$sub" in
    begin|end) "${data[@]}" "$sub" "$@" ;;
    render)    "${figs[@]}" ;;
    all)       "${data[@]}" end "$@" && "${figs[@]}" ;;
    *) echo "sim-harvest: begin [--reset] | end | render | all"; return 1 ;;
  esac
}

# ── Malware PCAP replay (real malicious flows + documented IOCs) ──────────────
# Reads a PCAP through NFStream (PCAP_FILE mode) → flows (with SNI/JA3) → live Kafka.
# No packets hit the wire. Flows are stamped with THIS endpoint's identity so SOAR
# attributes them here. IOCs per pcaps/mta/ioc_manifest.json (domains/IPs → real
# threat-intel hits for the Cortex/MISP/URLhaus auto-block path).
pcap_replay_cmd() {
  local MTA="$REPO/pcaps/mta" MAN="$REPO/pcaps/mta/ioc_manifest.json"
  local SENV="$REPO/endpoint_agent/sensor/.env"
  local img="soar-endpoint-sensor:latest"   # the freshly-built sensor image (fixed tag)
  local AID HID HIP
  AID=$(grep -E '^AGENT_ID=' "$SENV" 2>/dev/null | cut -d= -f2)
  HID=$(grep -E '^HOST_ID='  "$SENV" 2>/dev/null | cut -d= -f2)
  HIP=$(grep -E '^HOST_IP='  "$SENV" 2>/dev/null | cut -d= -f2)

  # selection + options
  local MODE="" FAMILY="" CLASS="" LIMIT="" DELAY=0 LOOP=1 DURATION="" MALONLY=0 DRY=0 DO_LIST=0
  local FILES=()
  while [ $# -gt 0 ]; do
    case "$1" in
      list)             DO_LIST=1; shift ;;
      all)              MODE=all; shift ;;
      --family)         FAMILY="$2"; MODE="${MODE:-filter}"; shift 2 ;;
      --class)          CLASS="$2"; MODE="${MODE:-filter}"; shift 2 ;;
      --file)           FILES+=("$2"); MODE=files; shift 2 ;;
      --limit)          LIMIT="$2"; shift 2 ;;
      --delay)          DELAY="$2"; shift 2 ;;
      --loop)           LOOP="$2"; shift 2 ;;
      --duration)       DURATION="$2"; shift 2 ;;
      --malicious-only) MALONLY=1; shift ;;
      --agent-id)       AID="$2"; shift 2 ;;
      --host-ip)        HIP="$2"; shift 2 ;;
      --dry-run)        DRY=1; shift ;;
      -h|--help)
        printf '%s\n' \
          "pcap-replay — replay malware pcaps (NFStream → Kafka): real flows + manifest IOCs" \
          "  select: list | all | --family <F> | --class <exfil|c2_beaconing> | --file <f> (repeatable) | <f.pcap>" \
          "  opts:   --limit N  --delay SEC  --loop <N|inf>  --duration SEC" \
          "          --malicious-only  --agent-id ID  --host-ip IP  --dry-run"
        return 0 ;;
      *.pcap)           FILES+=("$1"); MODE=files; shift ;;
      *) echo "pcap-replay: unknown arg '$1' (try --help)"; return 1 ;;
    esac
  done
  if [ "$DO_LIST" = 1 ] || { [ -z "$MODE" ] && [ "${#FILES[@]}" -eq 0 ]; }; then
    "$(detctl_py)" - "$MAN" "$FAMILY" "$CLASS" <<'PY'
import json,sys
m=json.load(open(sys.argv[1])); fam,cls=sys.argv[2],sys.argv[3]
rows=[(k,v) for k,v in sorted(m.items())
      if (not fam or v.get('family','').lower()==fam.lower())
      and (not cls or v.get('class','').lower()==cls.lower())]
print(f"{len(rows)} pcap(s) — file | family | class | #IOCs:")
for k,v in rows:
    n=len(v.get('malicious_domains',[]))+len(v.get('malicious_ips',[]))
    print(f"  {k:42s} {v.get('family','?'):12s} {v.get('class','?'):12s} {n}")
PY
    echo ""; echo "e.g.:  detctl pcap-replay --family Lumma --malicious-only --delay 5"
    return 0
  fi

  local SELECTED=()
  if [ "$MODE" = files ]; then
    SELECTED=("${FILES[@]}")
    [ -n "$LIMIT" ] && SELECTED=("${SELECTED[@]:0:$LIMIT}")
  else
    mapfile -t SELECTED < <("$(detctl_py)" - "$MAN" "$FAMILY" "$CLASS" "${LIMIT:-0}" <<'PY'
import json,sys
m=json.load(open(sys.argv[1])); fam,cls,lim=sys.argv[2],sys.argv[3],int(sys.argv[4])
out=[k for k,v in sorted(m.items())
     if (not fam or v.get('family','').lower()==fam.lower())
     and (not cls or v.get('class','').lower()==cls.lower())]
print("\n".join(out[:lim] if lim>0 else out))
PY
)
  fi
  [ "${#SELECTED[@]}" -eq 0 ] && { echo "no pcaps matched the selection."; return 1; }
  echo "selection: ${#SELECTED[@]} pcap(s)  loop=$LOOP delay=${DELAY}s malicious-only=$MALONLY dry=$DRY"
  echo "identity:  agent_id=${AID:-?} host_ip=${HIP:-?}"

  iocs_for() {
    "$(detctl_py)" - "$MAN" "$1" <<'PY'
import json,sys
v=json.load(open(sys.argv[1])).get(sys.argv[2],{})
print(",".join(v.get('malicious_domains',[])+v.get('malicious_ips',[])))
PY
  }
  run_pcap() {
    local f="$1"; [ -f "$MTA/$f" ] || { echo "  ! no such pcap: $f"; return 1; }
    local ioc=""; [ "$MALONLY" = 1 ] && ioc="$(iocs_for "$f")"
    if [ "$DRY" = 1 ]; then echo "  [dry] $f  ioc-filter=${ioc:-none}"; return 0; fi
    echo "  ▶ $f"
    docker run --rm -i --network dev_net \
      -e PCAP_FILE="/pcaps/$f" -e KAFKA_BROKER=kafka:9092 -e TOPIC=raw_flows \
      -e ENCRYPTED_ONLY="${ENCRYPTED_ONLY:-true}" -e IOC_ALLOWLIST="$ioc" \
      -e AGENT_ID="$AID" -e HOST_ID="$HID" -e HOST_IP="$HIP" \
      -v "$MTA:/pcaps:ro" "$img" 2>&1 | grep -iE 'complete|error' | tail -2
  }

  local start iter=0; start=$(date +%s)
  while :; do
    iter=$((iter+1))
    if [ "$LOOP" != 1 ] || [ -n "$DURATION" ]; then echo "── pass $iter ──"; fi
    for f in "${SELECTED[@]}"; do
      run_pcap "$f"
      if [ "$DRY" = 0 ] && [ "${DELAY:-0}" != 0 ]; then sleep "$DELAY"; fi
    done
    if [ -n "$DURATION" ]; then
      [ $(( $(date +%s) - start )) -ge "$DURATION" ] && break
    elif [ "$LOOP" = inf ]; then :; else
      [ "$iter" -ge "${LOOP:-1}" ] && break
    fi
  done
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

  # ── metrics harvest ──
  sim-harvest|harvest) sim_harvest_cmd "$@" ;;

  # ── malware pcap replay ──
  pcap-replay|pcap)    pcap_replay_cmd "$@" ;;

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
