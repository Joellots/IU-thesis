# Aegis (SOAR side)

Trust-aware automated response for malicious HTTPS traffic detected by machine
learning. This repository is the SOAR half of *Real-Time Detection and
Automated Response Framework for Malicious HTTPS Traffic Using Machine Learning
and SOAR Integration* — an MSc thesis at Innopolis University (2026),
co-developed by Okore Joel Chidike and Isaac Womoakor.

Aegis runs across two repositories on two hosts. The detection half captures
encrypted flows, classifies them without decrypting anything, explains each
prediction, and writes alerts into a shared PostgreSQL table. This repository
reads that table and carries each alert the rest of the way: severity banding,
threat-intel enrichment through Cortex and MISP, a TheHive case with the
ATT&CK mapping and its trust score attached, an authoritative decision matrix,
a human approval gate for anything disruptive, and real endpoint enforcement
through Wazuh Active Response. The `alerts` table is the contract between the
two sides; [context/SYSTEM_OVERVIEW.md](context/SYSTEM_OVERVIEW.md) covers
both halves and the handoff.

## Pipeline

```
PostgreSQL alerts (written by the detection host)
  → orchestrator: parse → severity band → Cortex + MISP enrichment
  → TheHive case (observables, ATT&CK techniques, mapping-trust score)
  → decision matrix → notify / gated block-isolate approval
  → Wazuh Active Response on the endpoint → analyst feedback loop
```

Nothing disruptive is fully automatic: block and isolate actions wait in a
pending-approvals table until an analyst approves them from the detection-side
dashboard, which calls back into this host's approval API (port 8200). Every
step is bookkept in Postgres, and the orchestrator exposes Prometheus metrics
on port 9100.

## Running it

Requires Linux x86-64, Docker with Compose v2 (`docker compose`), and RAM to
taste: TheHive + Cortex + MISP + Shuffle together want ~8 GB; the optional full
Wazuh SIEM adds 2–4 GB more and is deliberately excluded from the default
targets. The complete clone-to-running runbook is
[deploy/soar/README.md](deploy/soar/README.md); in short:

```bash
git clone <this-repo> soar && cd soar
cp services/soar_orchestrator/.env.example services/soar_orchestrator/.env
# edit: API keys, detection-host DATABASE_URL, shared SOAR_APPROVAL_TOKEN
#       (this one file configures everything)

# fetch the vendored third-party stacks (gitignored; see the runbook §2)
scripts/soarctl.sh doctor all          # verify dirs / compose files / .env
scripts/soarctl.sh start core          # TheHive+Cortex, MISP, Shuffle
scripts/soarctl.sh start wazuh-manager # the enforcement channel
python3 scripts/setup_soar_integrations.py   # one-time: orgs, users, analyzers
scripts/soarctl.sh start orchestrator
```

`soarctl.sh` is the operator CLI for the whole stack — actions
(`start stop restart recreate destroy cleanup status logs config doctor`)
across targets (`thehive misp shuffle wazuh-manager orchestrator core all`),
best-effort across multiple targets with a failure summary at the end. It
also absorbs the sharp edges: Shuffle's swap/permission preparation, the MISP
compose project-name mismatch, and missing-`.env` preflights with actionable
errors.

Our own infrastructure (`deploy/soar/orchestrator/`,
`deploy/soar/wazuh-manager/`, `services/soar_orchestrator/`) is committed.
The vendored upstream stacks (TheHive/Cortex, MISP, Shuffle, full Wazuh) are
not — fetch them locally per the runbook.

## Two-machine setup

The flow sensor, classifier, XAI layer, translator, and the analyst dashboard
live in the detection repo on the first host. To wire this host to it:

1. On the detection host: expose Postgres (`5432`) and Kafka (`9094`) to this
   host, set `SOAR_APPROVAL_URL=http://<this-host>:8200` and a shared
   `SOAR_APPROVAL_TOKEN`.
2. In this repo's `services/soar_orchestrator/.env`: point `DATABASE_URL` at
   `…@<detection-host>:5432/soar`, `KAFKA_BROKER` at `<detection-host>:9094`,
   set the same `SOAR_APPROVAL_TOKEN`, and fill in the TheHive/Cortex/MISP
   keys that `setup_soar_integrations.py` provisions.
3. Optionally install the detection repo's endpoint agent on a host to make it
   a sensor and Wazuh Active-Response actuator — that is the endpoint this
   side's approved block/isolate actions land on.

## Simulation & evaluation

- [prompts/SOAR_HEADSUP_PROMPT.md](prompts/SOAR_HEADSUP_PROMPT.md) — official
  simulation runbook (pre-flight, live C2 arm, PCAP replay arm, approval step,
  harvest).
- [prompts/SOAR_METRICS_PROMPT.md](prompts/SOAR_METRICS_PROMPT.md) —
  instrumentation (Phase A) and harvest (Phase B) for the evaluation engineer.

`utils/soar_metrics_harvest.py` reads the live database non-destructively and
writes the `report/eval/` artifacts (metrics.json, summary, CSVs, plots):

```bash
DATABASE_URL=<url> python3 utils/soar_metrics_harvest.py --since-id <watermark>

# Authoritative 2026-06-25 run — reproduces the committed report/eval/ numbers:
DATABASE_URL=<url> python3 utils/soar_metrics_harvest.py \
  --since-id 0 --before-ts '2026-06-25T14:09:34Z' \
  --log report/eval/orchestrator_run.log
```

The `--before-ts` bound scopes the harvest to the observation window (17 done
cases, median MTTR 542 s); omitting it includes the post-simulation backlog
drain and inflates MTTR to ~1 743 s.

**Before every run:** the timing columns (`enriched_ts`, `case_created_ts`,
`ar_executed_ts`) are added with `ALTER TABLE … ADD COLUMN IF NOT EXISTS` and
are lost whenever the detection side resets the schema
(`sim-harvest begin --reset`). Re-apply them first:

```bash
sudo docker exec soar_orchestrator python3 -c "
import os, psycopg2
conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()
cur.execute('ALTER TABLE soar_orchestrator_bookkeeping ADD COLUMN IF NOT EXISTS enriched_ts TIMESTAMPTZ, ADD COLUMN IF NOT EXISTS case_created_ts TIMESTAMPTZ')
cur.execute('ALTER TABLE soar_pending_approvals ADD COLUMN IF NOT EXISTS ar_executed_ts TIMESTAMPTZ')
conn.commit()
print('done')
"
```

## Layout

```
services/soar_orchestrator/  the orchestrator: severity, enrichment, case
                             automation, decision matrix, approval API (8200),
                             Wazuh response, metrics (9100), tests
deploy/soar/                 compose stacks — ours (orchestrator, wazuh-manager)
                             committed; vendored TheHive/MISP/Shuffle/Wazuh fetched
scripts/                     soarctl.sh operator CLI, setup_soar_integrations.py,
                             TheHive/Cortex maintenance utilities
utils/                       soar_metrics_harvest.py evaluation harvester
context/                     SYSTEM_OVERVIEW, SOAR_WORKFLOW_SPEC (authoritative),
                             SOAR_FRAMEWORK_CONTEXT deep dive
prompts/                     simulation and metrics runbooks
report/eval/                 artifacts from the official 2026-06-25 evaluation run
```

## Notes

- `wazuh-manager` (in `core`'s companion target and `all`) is the lean
  enforcement channel. The `wazuh` target is the full SIEM — heavy and
  optional; start it explicitly and only if the host has the memory.
- Cortex enrichment is capped at `CORTEX_MAX_CONCURRENT` (default 2) jobs in
  flight across all orchestrator workers — the semaphore is held from job
  launch until the report returns, which keeps enrichment latency flat as the
  alert backlog grows. Raise `CORTEX_PRE_CASE_TOTAL_BUDGET_SEC` before raising
  the cap.
- `ORCHESTRATOR_DRY_RUN=true` runs the orchestrator against the alerts table
  without touching TheHive/Cortex/MISP/Wazuh — useful before the stacks are up.
- Secrets (TheHive/Cortex/MISP API keys, `SOAR_APPROVAL_TOKEN`,
  `DATABASE_URL`) live only in `services/soar_orchestrator/.env`, which is
  gitignored; every variable is documented in
  [.env.example](services/soar_orchestrator/.env.example).
- After recreating Postgres or Kafka on the detection side, restart the
  orchestrator (`scripts/soarctl.sh restart orchestrator`) — a live swap
  leaves its connections stale.

## Documentation

[context/SYSTEM_OVERVIEW.md](context/SYSTEM_OVERVIEW.md) describes both halves
of Aegis and the `alerts`-table contract between them.
[context/SOAR_WORKFLOW_SPEC.md](context/SOAR_WORKFLOW_SPEC.md) is the
authoritative workflow: every step, the decision matrix, the Shuffle handoff
payload, and the Wazuh enforcement channel.
[context/SOAR_FRAMEWORK_CONTEXT.md](context/SOAR_FRAMEWORK_CONTEXT.md) is the
SOAR-side deep dive (architecture, contracts, rationale, limitations).
[deploy/soar/README.md](deploy/soar/README.md) is the deployment runbook.

## License

MIT, matching the detection repo. Authors: Okore Joel Chidike and Isaac
Womoakor, supervised by Dr Andrei Petrovski, Innopolis University.
