#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# detctl — control the XAI *detection* stack.
# Counterpart to the SOAR side's soarctl. Wraps `docker compose` for the
# detection pipeline and adds simulation / alert-inspection helpers.
#
#   ./scripts/detctl.sh <command> [args]
#
# Detection stack (docker-compose.yml): kafka, postgres, inference, translator,
# producer, nfstream, dashboard, kafka-ui. The SOAR orchestrator runs elsewhere
# (SOAR machine) and reads this stack's Postgres `alerts` table.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

DC="docker compose -f docker-compose.yml"
SIM="-f docker-compose.sim.yml"

# Always-on pipeline (consumers + infra). The producer is the replay source and
# is started on demand by `sim` / `replay`.
PIPELINE=(kafka postgres inference translator)

usage() {
  cat <<EOF
detctl — control the XAI detection stack

Usage: ./scripts/detctl.sh <command> [args]

Lifecycle:
  up [svc...]      Start services (default: ${PIPELINE[*]})
  down             Stop + remove containers (KEEPS the alerts DB volume)
  reset            down -v (wipe alerts DB; re-applies schema.sql) then build + start pipeline
  build [svc...]   Build images
  restart [svc...] Restart services
  status | ps      Container states
  logs [svc]       Follow logs (all, or one service)
  config           Validate the compose config

Traffic:
  sim              Replay a FINITE batch from training_dataset.csv (docker-compose.sim.yml)
  replay           Continuous replay (base producer, LOOP=true)

Inspect:
  alerts           Summary of the alerts table (counts, mapping_status, ja3 coverage)
  psql             Open a psql shell on the alerts DB (soar)

Services: ${PIPELINE[*]} producer nfstream dashboard kafka-ui   (dashboard UI :8080, kafka-ui :8081)
EOF
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  up|start)
    if [ "$#" -eq 0 ]; then $DC up -d "${PIPELINE[@]}"; else $DC up -d "$@"; fi ;;
  down|stop)   $DC down ;;
  reset)
    $DC down -v
    $DC up -d --build "${PIPELINE[@]}"
    echo "reset: fresh alerts DB + pipeline up. './scripts/detctl.sh sim' to send flows." ;;
  build)       $DC build "$@" ;;
  restart)     $DC restart "$@" ;;
  status|ps)   $DC ps ;;
  logs)        $DC logs -f "$@" ;;
  config)      $DC $SIM config >/dev/null && echo "compose config valid" ;;

  sim)
    $DC $SIM up -d --build "${PIPELINE[@]}"
    sleep 3
    $DC $SIM up -d producer
    echo "replaying a finite batch — './scripts/detctl.sh logs producer' to watch, './scripts/detctl.sh alerts' to inspect" ;;
  replay)
    $DC up -d producer
    echo "producer replaying continuously (LOOP=true) — 'docker compose stop producer' to halt" ;;

  alerts)
    read -r -d '' Q <<'SQL' || true
SELECT pred_label,
       count(*)                                                          AS n,
       count(*) FILTER (WHERE mapping_status='mapped')                   AS mapped,
       count(*) FILTER (WHERE mapping_status='unmapped_heuristic')       AS heuristic,
       count(*) FILTER (WHERE observables @> '[{"type":"ja3"}]')         AS has_ja3,
       round(avg(mapping_confidence)::numeric, 3)                        AS avg_conf
FROM alerts GROUP BY pred_label ORDER BY pred_label;
SQL
    $DC exec -T postgres psql -U user -d soar -c "$Q" ;;
  psql)        $DC exec postgres psql -U user -d soar ;;

  help|-h|--help) usage ;;
  *) echo "detctl: unknown command '$cmd'"; echo; usage; exit 1 ;;
esac
