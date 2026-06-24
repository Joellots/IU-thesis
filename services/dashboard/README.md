# Aegis Dashboard

FastAPI + Jinja2 + htmx analyst UI over the shared PostgreSQL `alerts` table.

| Route | Purpose |
|---|---|
| `GET /` | alert queue (live-polled) |
| `GET /alert/{id}` | alert detail + XAI annotation |
| `POST /decision` | Step-6 analyst verdict on an alert |
| `GET /metrics` | pipeline statistics (JSON) |
| **`GET /approvals`** | **Analyst Approvals** — pending gated SOAR actions |
| `GET /approvals/live` | htmx fragment of the pending list |
| `POST /approvals/decide` | relay an approve/reject decision to the orchestrator |

## Analyst Approvals (SOAR gated-action loop)

When the SOAR orchestrator decides a **block** or **isolate** that needs human
approval (and the host has a Wazuh agent), it parks a row in the SOAR-owned Postgres
table `soar_pending_approvals` (created at runtime by the orchestrator — **not** in
`schema.sql`). The dashboard:

1. **Reads** `soar_pending_approvals WHERE status='pending'` (joined to `alerts` for the
   endpoint identity `host_id`/`agent_id`/`host_ip` + flow context), and renders each as a
   card showing the action, target host, target IP (for block), severity, MITRE TTPs, intel
   verdict, a deep-link to the TheHive case, and a countdown to `expires_ts`.
   *It never writes any `soar_*` table.* If the orchestrator hasn't created the table yet,
   the panel simply shows "no pending approvals".
2. On **Approve / Reject**, POSTs the decision to the orchestrator's API (cross-machine,
   on the SOAR host). **All enforcement (the real Wazuh Active-Response) happens SOAR-side**
   — the dashboard only conveys the analyst's decision and the bearer token.
   - `409` (already decided / expired) → the next poll refreshes the list.
   - `401` → surfaced as a config error (bad/missing token).
   - `404` → unknown id; `200` → shows the outcome (incl. the `ar_result` from Wazuh).
   - Reject prompts for an optional reason (sent as the `note`).

### Configuration (env)

| Var | Meaning | Default |
|---|---|---|
| `SOAR_APPROVAL_URL` | orchestrator base URL (its `/soar/approve` is called) | `https://172.31.80.148:8200` |
| **`SOAR_APPROVAL_TOKEN`** | **shared bearer secret** — required (this endpoint can isolate a host) | *(unset)* |
| `SOAR_APPROVAL_VERIFY_TLS` | verify the SOAR host's TLS cert (`true` for a real cert) | `false` |
| `SOAR_APPROVAL_TIMEOUT` | HTTP timeout (seconds) | `10` |
| `DASHBOARD_ANALYST` | analyst name attached to decisions (no login yet) | `dashboard-analyst` |

**The token is a secret — do NOT hard-code it.** Put it in the gitignored repo-root `.env`
(docker-compose interpolates it into the dashboard service); its value comes from the SOAR
side's `.env` (`SOAR_APPROVAL_TOKEN`). Example `.env` line:

```
SOAR_APPROVAL_TOKEN=<paste-from-SOAR-.env>
```

### Networking

- The **dashboard container** must reach the **SOAR host on :8200** (outbound) — it is on the
  `net` bridge (NAT egress is enough to reach the SOAR LAN IP).
- **Analyst browsers** must reach the SOAR host for the TheHive **case deep-links** (`case_url`).
- If the orchestrator serves plain HTTP (not HTTPS) on :8200, set `SOAR_APPROVAL_URL` to the
  `http://…:8200` form; for a self-signed HTTPS cert, leave `SOAR_APPROVAL_VERIFY_TLS=false`.
