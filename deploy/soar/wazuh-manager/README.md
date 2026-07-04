# Wazuh Manager (manager-only) — SOAR enforcement channel

Wazuh is used here **only** as the agent-management + **on-demand Active-Response (AR)**
relay — not as a SIEM. This deploys the **manager only** (no `wazuh-indexer`, no
`wazuh-dashboard`), because this host is memory-tight and the full stack would OOM. The
manager alone runs in ~370MB.

## What it's for
The SOAR orchestrator decides a `block`/`isolate` action (per the §5 matrix, after the
approval gate for gated actions), then calls the **Wazuh REST API on demand**:

```
POST https://<SOAR_HOST>:55000/security/user/authenticate   (basic auth → JWT)
PUT  https://<SOAR_HOST>:55000/active-response?agents_list=<agent_id>
     {"command": "soar-block0", "arguments": ["<malicious_ip>"]}
```

The manager relays it to the target agent over the agent→manager channel, and the agent runs
the **pre-registered, vetted** AR script locally. No rule and no triggering log are required —
the API call is the trigger.

## Run
```bash
scripts/soarctl.sh start wazuh-manager      # or: docker compose -f deploy/soar/wazuh-manager/docker-compose.yml up -d
scripts/soarctl.sh status wazuh-manager
scripts/soarctl.sh logs   wazuh-manager --tail 50
```

## Ports (published on the SOAR host)
| Port | Purpose |
|---|---|
| `1515` | agent enrollment (authd) |
| `1516` → 1514 | agent communication (1514 is taken by tenzir on this host) |
| `55000` | Wazuh REST API (SOAR posts `PUT /active-response` here) |

## Credentials
API user `wazuh-wui`, password set via `API_PASSWORD` in the compose (**change it**). The same
value goes into the orchestrator `.env` as `WAZUH_API_PASSWORD` (with `WAZUH_API_URL`,
`WAZUH_API_USER`, `WAZUH_VERIFY_TLS`) when we build the `wazuh_response.py` dispatcher.

## Status — wired end-to-end
1. **AR command registration — DONE.** `config/ossec.conf` registers `<command>` +
   `<active-response>` for the four commands (bound to unused rule ids so they only dispatch
   via the API, never auto-fire from logs). Mounted into the manager.
2. **The dispatcher — DONE.** `services/soar_orchestrator/wazuh_response.py` authenticates
   and `PUT /active-response`. Wired into the orchestrator: **auto-block** (High + confirmed
   IOC) fires immediately; **gated block/isolate** are parked in `soar_pending_approvals` and
   fired on analyst approval via `POST /soar/approve` (the dashboard loop).
3. **The endpoint agent** ({NFStream sensor + Wazuh agent + AR scripts}) is built on the
   **detection side** (`endpoint_agent/`) and enrolled to this manager (`<SOAR_HOST>:1515`).

The agent's AR script filenames and the manager's registered `<command>` names are
**`soar-block`, `soar-unblock`, `soar-isolate`, `soar-unisolate`**. **The SOAR API `command`
field, however, must be the active-response NAME — the registered name + Wazuh's timeout
suffix `0` — i.e. `soar-block0`** (as it appears in the agent's `merged.mg`). Verified live:
`soar-block` → 1652 "command not defined"; `!soar-block` → HTTP 200 but never relayed;
`soar-block0` → "sent to agent". The dispatcher (`wazuh_response.py`) sends the `0` names.

## Verify on first real dispatch
Until an agent is enrolled, every dispatch safely **skips** (no `agent_id` to route to). When
an endpoint enrolls and a confirmed-malicious flow from it is processed, the first
`PUT /active-response` confirms the command format; check the agent's
`/var/ossec/logs/active-responses.log` for the script run.
