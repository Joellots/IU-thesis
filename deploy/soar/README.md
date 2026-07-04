# SOAR half — deployment runbook

Stand up the SOAR machine and wire it to a detection machine running the other repo. The two
halves are **separate repos on separate machines** that meet at the shared PostgreSQL `alerts`
table + a thin Kafka trigger. This repo is the SOAR half: orchestrator → severity → Cortex/MISP
enrichment → TheHive cases → Shuffle (record) → Slack notify + **Wazuh endpoint block/isolate**
with a dashboard approval loop.

> Goal: `git clone` → `cp .env.example .env` (fill keys + detection host + shared token) →
> obtain the vendored stacks → `soarctl start core && soarctl start wazuh-manager &&
> soarctl start orchestrator` → the full loop works against a detection host running this repo.

---

## 1. Prerequisites
- Docker + Docker Compose v2; this host on the same network as the detection host.
- ~8 GB RAM free (TheHive+ES, Cortex, MISP, Shuffle+OpenSearch, Wazuh manager). A **swap file**
  is recommended (the box is memory-tight). `soarctl` uses `sudo docker` by default
  (`SOAR_USE_SUDO=0` if your user is in the `docker` group).
- A **detection machine** running the detection repo, reachable from here, with Postgres `5432`
  and Kafka `9094` published + firewalled to this host (see §6).

## 2. Obtain the vendored stacks (third-party, not committed)
The upstream SOAR tools are **gitignored** (large; each has its own config/secrets). Fetch each
into the path `soarctl` expects, then configure it per its upstream docs:

| Target path | Upstream | Notes |
|---|---|---|
| `deploy/soar/thehive/testing/` | StrangeBee TheHive 5 + Cortex docker (testing) | needs its own `.env` (UID/GID, ES password) |
| `deploy/soar/misp/` | `github.com/MISP/misp-docker` | needs its own `.env` (from its `template.env`) |
| `deploy/soar/shuffle/` | `github.com/Shuffle/Shuffle` | generates its own config on first run |
| `deploy/soar/wazuh/` (optional) | `github.com/wazuh/wazuh-docker` | only for the full SIEM; **not needed** — we use the manager-only stack below |

Our own infra is committed and ready: `deploy/soar/orchestrator/` and
`deploy/soar/wazuh-manager/` (manager-only Wazuh — no indexer/dashboard, ~0.7 GB).

## 3. Configure — edit ONE file
```bash
cp services/soar_orchestrator/.env.example services/soar_orchestrator/.env
```
In `.env`, find-and-replace the two host placeholders and fill the secrets:
- `<DETECTION_HOST>` → the detection machine's LAN IP/DNS (Postgres + Kafka).
- `<SOAR_HOST>` → **this** machine's LAN IP/DNS (TheHive/Cortex/MISP/Shuffle/Wazuh published ports).
- `SOAR_APPROVAL_TOKEN` → `openssl rand -base64 32`; put the **same value** in the detection
  side's `.env` (the dashboard sends it to `/soar/approve`).
- TheHive/Cortex/MISP/Shuffle API keys, `THEHIVE_ORGANISATION` (the key's org), `WAZUH_API_PASSWORD`.
- Keep `SEVERITY_HIGH_THRESHOLD` aligned with the detection translator (this deployment: **0.80**).

The orchestrator reads only this `.env`; no IPs are hardcoded elsewhere. The Wazuh manager's API
password is set separately (see §5.4) and must equal `WAZUH_API_PASSWORD`.

## 4. Bring it up
```bash
scripts/soarctl.sh start core            # TheHive + Cortex + MISP + Shuffle
scripts/soarctl.sh start wazuh-manager   # manager-only Wazuh (AR enforcement channel)
scripts/soarctl.sh start orchestrator    # the SOAR brain (build + up -d)
scripts/soarctl.sh status all            # health
```
`orchestrator` and the full `wazuh` SIEM are intentionally NOT in `core`/`all`. The orchestrator
starts its HTTP API (`:8200`) + metrics (`:9100`) immediately and **retries the DB with backoff**,
so a not-yet-reachable detection Postgres won't crash it.

## 5. One-time setup
**5.1 Cortex analyzers** — activate them (and inject any Tier-1 keys from `.env`):
```bash
set -a; source <(grep -E '^[A-Za-z_]+=' services/soar_orchestrator/.env); set +a
python3 scripts/setup_soar_integrations.py --skip-thehive-config
```
**5.2 TheHive org** — the API key's org must equal `THEHIVE_ORGANISATION` (else 401). Create the
org/user in TheHive and use that key.
**5.3 Shuffle workflow** — import `services/soar_orchestrator/shuffle/soar_response_actions.workflow.json`
into Shuffle; set `SHUFFLE_WORKFLOW_ID` + `SHUFFLE_API_KEY` in `.env`. (Gate retired — Shuffle just
records; the orchestrator owns enforcement + approval.)
**5.4 Wazuh manager API password** — set it for the manager and match it in `.env`:
```bash
echo 'WAZUH_MANAGER_API_PASSWORD=<same as WAZUH_API_PASSWORD>' > deploy/soar/wazuh-manager/.env  # gitignored
```
**5.5 Wazuh AR commands** — already registered: `deploy/soar/wazuh-manager/config/ossec.conf`
defines `<command>`/`<active-response>` for `soar-block`/`unblock`/`isolate`/`unisolate` (bound to
unused rule ids so they only dispatch via the API, never auto-fire). It's mounted into the manager
on boot.
**5.6 Endpoint agent** — built on the **detection** repo (`endpoint_agent/`): NFStream sensor +
Wazuh agent + the four AR scripts. Enroll it to this manager at `<SOAR_HOST>:1515` (comms `:1516`).

## 6. Cross-machine checklist (detection side must do)
- **Postgres**: publish `5432` (`ports: ["5432:5432"]`) + firewall to `<SOAR_HOST>`. Point our
  `DATABASE_URL` at `<DETECTION_HOST>:5432`.
- **Kafka**: publish `9094` and advertise the **external** listener as the detection **LAN IP**,
  not `localhost` (`KAFKA_EXTERNAL_ADVERTISED_HOST=<DETECTION_HOST>`), or our consumer connects to
  the bootstrap then fails on a `localhost` redirect. Point our `KAFKA_BROKER` at `<DETECTION_HOST>:9094`.
- **Shared token**: the detection dashboard's `SOAR_APPROVAL_TOKEN` must equal ours.
- **Severity bands**: align the translator's `severity_label` to our `SEVERITY_HIGH/MEDIUM_THRESHOLD`.
- The dashboard posts to `http://<SOAR_HOST>:8200/soar/approve` (**plain HTTP**, not https).

## 7. Wazuh Active-Response — operational notes (hard-won)
- The dispatcher sends the **active-response NAME** `soar-block0` to `PUT /active-response`
  (registered command + Wazuh's `0` timeout suffix). `soar-block` → 1652 "not defined";
  `!soar-block` → HTTP 200 but never relays. The dispatcher also treats `affected_items: []` as a
  failure (200 alone ≠ delivered).
- A **newly-registered AR needs an agent restart** to pick up the merged config (`merged.mg`).
- AR scripts **read one line from stdin** (the JSON event) — not `cat`/loop; the target IP arrives
  under `.parameters.extra_args`.
- On a **container-host**, `soar-isolate` must spare the Docker bridges + the agent↔manager channel
  (else you sever the host's own containers / lock the agent out).
- Agent AR must be **enabled in the agent's own `ossec.conf`** (`<active-response><disabled>no`) —
  "execd running" is not the same as "AR enabled".
- Verify delivery on the manager: remoted's `sent_breakdown.ar` counter increments per relayed
  command (`GET /manager/daemons/stats?daemons_list=wazuh-remoted`).

## 8. Robustness (already built in)
The orchestrator **reconnects to Postgres with capped backoff** (`connect_with_retry`) and
**re-creates the Kafka consumer** on failure, always running the Postgres polling fallback. A
transient cross-machine outage pauses processing but **does not drop alerts** — unprocessed rows
are claimed on the next successful poll (idempotent via `soar_orchestrator_bookkeeping`).

## 9. Verify the loop
- `scripts/soarctl.sh logs orchestrator -f` → `orchestrator_started`, then per alert
  `case_created` / `shuffle_dispatched` / `approvals_parked`.
- High + confirmed-IOC on a managed endpoint → auto `soar-block0` on the agent.
- High (no confirmation) / isolate → a `soar_pending_approvals` row → dashboard Approve →
  `POST /soar/approve` → real Wazuh AR. Check the agent's `/var/ossec/logs/active-responses.log`.
