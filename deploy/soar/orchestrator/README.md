# SOAR Orchestrator (SOAR-side stack)

The orchestrator runs **on this (SOAR) machine**, alongside the vendored
TheHive/Cortex/MISP/Shuffle stacks under `deploy/soar/`. It is **decoupled from
the detection stack** — the detection `docker-compose.yml` no longer ships it.

It:
- consumes the detection-side Kafka `alert.translated` pointer event from
  `SOAR_ALERT_EVENTS_TOPIC` for low-latency triggers,
- reads the **detection Postgres `alerts` contract cross-machine**
  (`DATABASE_URL → <DETECTION_HOST_IP>:5432/soar`) as the source of truth and
  polling fallback/replay path, and
- drives the **local** SOAR stack (TheHive/Cortex/MISP/Shuffle) over the host's
  published ports.

## Start it (single command)

```bash
scripts/soarctl.sh start orchestrator --build      # build + up -d
scripts/soarctl.sh status orchestrator
scripts/soarctl.sh logs orchestrator --tail 100 -f
scripts/soarctl.sh stop orchestrator
scripts/soarctl.sh destroy orchestrator --yes
```

Or standalone, without soarctl:

```bash
docker compose -f deploy/soar/orchestrator/docker-compose.yml up -d --build
```

> `orchestrator` is intentionally **not** part of the `core`/`all` groups — start
> it explicitly once the local SOAR stack and the detection DB are reachable.

## Configuration

All config lives in **`services/soar_orchestrator/.env`** (used as the compose
`env_file`). The endpoints are already pointed at the right hosts:

| Setting | Value | Reached via |
|---|---|---|
| `DATABASE_URL` | `…@172.31.87.134:5432/soar` | detection host (cross-machine) |
| `KAFKA_BROKER` | `<DETECTION_HOST_IP>:9094` | detection Kafka external listener |
| `SOAR_ALERT_EVENTS_TOPIC` | `soar_alert_events` | thin `alert.translated` pointer events |
| `ENABLE_KAFKA_TRIGGER` | `true` | set `false` to use polling-only fallback/replay |
| `THEHIVE_BASE_URL` | `http://172.31.80.148:9000/thehive` | this host's published port |
| `CORTEX_BASE_URL` | `http://172.31.80.148:9001/cortex` | this host's published port |
| `SHUFFLE_BASE_URL` | `http://172.31.80.148:3001` | this host's published port |
| `MISP_URL` | `http://host.docker.internal:8088` | `extra_hosts` host-gateway |
| `SOAR_CALLBACK_BASE_URL` | `http://172.31.80.148:8200` | Shuffle → orchestrator callback |
| `ORCHESTRATOR_DRY_RUN` | `false` | live stack (set `true` only when the stack is down) |

The local SOAR services are reached by the **host LAN IP** (their published
ports), so the orchestrator does **not** need to join the vendored stacks'
Docker networks. MISP is the one exception, reached via `host.docker.internal`.

Kafka is not the source of truth. It only wakes the orchestrator with an `alert_id`; the
orchestrator then fetches the complete row from Postgres and claims it in
`soar_orchestrator_bookkeeping`. Duplicate Kafka messages or polling replays are skipped by
that primary-key claim before any TheHive case or Shuffle action is created.

For cross-machine Kafka, make sure the detection broker's advertised external listener is
reachable from the SOAR machine. If Kafka advertises `localhost:9094`, remote consumers may
connect to the bootstrap address and then fail when the broker redirects them to localhost.
Use a detection-host IP/DNS value for the external advertised listener when running across
machines. In this repo's detection `docker-compose.yml`, set
`KAFKA_EXTERNAL_ADVERTISED_HOST=<DETECTION_HOST_IP>` before recreating Kafka.

## Ports & HTTP endpoints (`api_server.py`, port 8200)

- `POST /soar/shuffle-result` — Shuffle callback (records action outcomes).
- `POST /soar/feedback` — interim Step-6 analyst feedback.
- `POST /soar/approve` — **dashboard approval loop** (token-gated via `SOAR_APPROVAL_TOKEN`):
  approve → real Wazuh AR on the endpoint, reject → logged. `GET /soar/pending-approvals`
  lists the queue.
- `9100` — Prometheus metrics scrape target.

## Real response actions (enforcement)

- **Notify → Slack** (`SLACK_WEBHOOK_URL`); **block/isolate → Wazuh on-demand AR**
  (`WAZUH_API_URL/USER/PASSWORD`, manager at `deploy/soar/wazuh-manager`). Auto-block fires
  immediately; gated block/isolate fire on approval via `/soar/approve`. Endpoint flows carry
  `agent_id` (else endpoint enforcement is skipped). See `SOAR_WORKFLOW_SPEC.md` §6/§7.2/§9.

## Resilience

`api_server` (8200) and metrics (9100) start **before** the DB connection and
stay up regardless of DB state. The DB connection **retries with capped
exponential backoff** at boot and **reconnects** on loss instead of crashing —
important because the Postgres is cross-machine and transient unavailability is
expected. Tunable via `DB_RECONNECT_BACKOFF_START_SEC` / `DB_RECONNECT_BACKOFF_MAX_SEC`.

## Coordination dependency (cross-machine DB)

The detection Postgres must **publish `5432`** (`ports: ["5432:5432"]`) and
firewall it to this host for the cross-machine read to work. This is durable on
the detection side (published in its compose + firewalled), so
`DATABASE_URL → 172.31.87.134:5432` is stable. If you ever see the orchestrator
logging `db_connect_retry`, check that the detection DB is up and the port is
reachable from this host (`nc -vz 172.31.87.134 5432`).
