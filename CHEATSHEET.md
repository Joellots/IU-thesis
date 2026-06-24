# Aegis — Operator Cheatsheet

Single-page reference for driving the **detection engine** and the **endpoint agent**.
Almost everything is wired into **`detctl`** (`./scripts/detctl.sh`); raw equivalents are
shown where useful. The SOAR half (orchestrator, TheHive/Cortex/MISP/Shuffle, Wazuh manager)
runs on the **SOAR host** and is driven there by `soarctl`.

```
detection host  172.31.87.134   ← this repo: pipeline + Postgres :5432 + Kafka :9094 + dashboards
SOAR host       172.31.80.148   ← orchestrator :8200 · TheHive :9000 · Wazuh mgr 1515/1516/55000
```
URLs: **dashboard (React)** http://172.31.87.134:3000 · **dashboard (htmx)** :8080 · **kafka-ui** :8081

---

## detctl — one command for everything
```
./scripts/detctl.sh <command> [args]
```
| Group | Commands |
|---|---|
| **Stack** | `up [svc]` · `down` · `reset` · `build [svc]` · `restart [svc]` · `status` · `logs [svc]` · `config` |
| **Simulation** | `sim [AGENT_ID]` · `replay` |
| **Inspect (DB)** | `alerts` · `approvals` · `psql` |
| **Data & model** | `dataset [args]` · `eval [args]` · `fetch-pcaps [args]` · `fetch-mta [args]` |
| **Endpoint agent** | `agent status\|blocks\|ar-log [-f]\|unblock <ip>\|unisolate\|install [args]\|uninstall\|package` |

---

## 1. Run the stack
```bash
./scripts/detctl.sh reset          # clean DB (wipes alerts) + rebuild + start pipeline
./scripts/detctl.sh up             # start pipeline (kafka,postgres,inference,translator,dashboard,dashboard-web)
./scripts/detctl.sh status         # container states
./scripts/detctl.sh logs translator
./scripts/detctl.sh down           # stop (keeps the DB volume)
```
Services: `kafka producer nfstream inference translator postgres dashboard dashboard-web kafka-ui`.

## 2. Simulate traffic (dataset replay)
```bash
./scripts/detctl.sh sim            # finite batch from training_dataset.csv (docker-compose.sim.yml)
./scripts/detctl.sh sim 001        # REPLAY-AS-ENDPOINT: stamp this host's Wazuh agent id 001
                                   #   → flows carry agent_id/host_id/host_ip → SOAR routes
                                   #     block/isolate back to THIS host (verifiable locally)
./scripts/detctl.sh replay         # continuous replay (LOOP=true)
```
The replay-as-endpoint identity is taken from `.env` (`SIM_HOST_ID`, `SIM_HOST_IP`) + the
`AGENT_ID` arg. The dataset is **not** modified — identity is injected by the producer.

## 3. Inspect the alerts & SOAR approvals
```bash
./scripts/detctl.sh alerts         # per-class counts, mapping, JA3, endpoint-identity, avg confidence
./scripts/detctl.sh approvals      # pending SOAR block/isolate actions (soar_pending_approvals)
./scripts/detctl.sh psql           # psql shell on the `soar` DB
```

## 4. Data & model utilities (host Python; needs the ML deps / a venv)
```bash
./scripts/detctl.sh dataset --output data/ --min-packets 4 --encrypted-only --balance   # build training set
./scripts/detctl.sh eval --benign pcaps/benign/*.pcap --malicious pcaps/malicious/*.pcap \
                         --model models/mapper --output /tmp/eval/ --encrypted-only      # evaluate the mapper
./scripts/detctl.sh fetch-mta --out pcaps/mta/ --jobs 4                                   # fetch MTA captures
```
(`detctl` uses a `./.venv` or `./venv` if present, else `python3`; override with `DETCTL_PY`.)

---

## 5. Endpoint agent (Wazuh Active-Response) — `endpoint_agent/`
Turns a host into a SENSOR (feeds `raw_flows`) + ACTUATOR (`soar-block`/`unblock`/`isolate`/`unisolate`).

### Provision a host
```bash
sudo ./endpoint_agent/install.sh --manager-host 172.31.80.148 --kafka-broker 172.31.87.134:9094 \
     --agent-name "$(hostname -s)"
./scripts/detctl.sh agent package      # → dist/soar-endpoint-agent.tar.gz (ship to a bare host)
sudo ./scripts/detctl.sh agent uninstall            # teardown (add --purge-wazuh to remove the agent)
```

### Operate / verify the actuator on this host
```bash
./scripts/detctl.sh agent status       # agent connected? AR scripts? enforced blocks? isolated?
./scripts/detctl.sh agent blocks       # the nft `soar_block` set (currently DROPped IPs)
./scripts/detctl.sh agent ar-log -f    # watch Active-Response executions live
./scripts/detctl.sh agent unblock 1.2.3.4
./scripts/detctl.sh agent unisolate    # RECOVERY: remove the SOAR_ISOLATE chain
```

### The end-to-end block demo (this host = agent 001)
1. `./scripts/detctl.sh reset` then `./scripts/detctl.sh sim 001`
2. `./scripts/detctl.sh approvals` → note a **block** with a **public** target IP
3. Approve it in the React dashboard (:3000 → Approvals) — orchestrator → Wazuh API → this agent
4. `./scripts/detctl.sh agent ar-log` → `soar-ar: program=soar-block status=ok blocked <ip>`
   and `./scripts/detctl.sh agent blocks` shows the nft DROP. 

---

## 6. Gotchas & troubleshooting (hard-won)
- **AR scripts read ONE stdin line, not `cat`.** Wazuh execd keeps the pipe open; `cat` hangs
  the script and blocks execd for *all* later commands. (`soar-ar-common.sh` uses `read -r -t 5`.)
- **New AR ⇒ restart the agent.** execd loads `ar.conf` at start; after the manager registers a
  new command, `sudo /var/ossec/bin/wazuh-control restart` so execd picks it up.
- **Don't `isolate` agent 001 (this host).** Isolate now spares the Docker bridges
  (`docker0`/`docker_gwbridge`/`br+`, so the detection stack survives) but still cuts the host's
  own external traffic — including your SSH/SSM session. Only approve **blocks** here; isolate
  from a different machine. Recovery: `./scripts/detctl.sh agent unisolate`.
- **Block targets:** the script refuses private/RFC1918/loopback/manager IPs (safety) — use a
  **public** IP to see enforcement. Blocks auto-expire after `SOAR_BLOCK_TTL` (1h).
- **`[SSL: WRONG_VERSION_NUMBER]` on approve:** the orchestrator's `/soar/approve` is plain HTTP;
  set `SOAR_APPROVAL_URL=http://172.31.80.148:8200` in the gitignored root `.env`.
- **AR debug:** `echo execd.debug=2 >> /var/ossec/etc/local_internal_options.conf`,
  `wazuh-control restart`, watch `/var/ossec/logs/ossec.log` for `wazuh-execd … Executing command`.
  Remove the line + restart afterwards.

## 7. Secrets / config (gitignored root `.env`)
`SOAR_APPROVAL_TOKEN` (shared), `SOAR_APPROVAL_URL`, `SIM_HOST_ID`, `SIM_HOST_IP`,
`KAFKA_EXTERNAL_ADVERTISED_HOST=172.31.87.134`. Never commit `.env`.
