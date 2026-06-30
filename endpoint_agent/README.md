# SOAR Endpoint Agent Bundle

A shippable bundle that turns any experimentation VM/host into both:

- a **SENSOR** — an NFStream probe that captures the host's live traffic, extracts
  the model's flow features, stamps the host's **endpoint identity**, and publishes
  to the detection pipeline's Kafka `raw_flows` topic; and
- an **ACTUATOR** — a Wazuh agent with four vetted Active-Response scripts that the
  SOAR orchestrator can trigger on demand to **block / isolate** the host.

The same endpoint that *generates* a flow is where a response is *enforced* — closing
the SOAR loop on the endpoint, Wazuh-active-response style.

```
  THIS endpoint ──nfstream flows (raw_flows)──▶ detection pipeline ──alerts──▶ SOAR orchestrator
        ▲                                                                               │
        └──────────── Wazuh manager  ◀── PUT /active-response {!soar-block, [ip]} ◀─────┘
                       (relays to this agent → runs soar-block locally)
```

## How response routing works (the new contract field)

For the SOAR side to send a block to the *right* host, each alert must carry the
endpoint's identity. The sensor stamps **`agent_id`** (Wazuh agent id), **`host_id`**
(agent name), and **`host_ip`** onto every flow; these propagate
`inference → translator → PostgreSQL alerts` (new nullable columns) and populate the
SOAR §7.1 handoff `endpoint:{host_id, ip, source}` object. The orchestrator maps that
to the Wazuh agent and calls:

```
PUT https://<MANAGER_HOST>:55000/active-response?agents_list=<agent_id>
    {"command":"!soar-block","arguments":["<malicious_ip>"]}
```

The manager relays it to this agent, whose `execd` runs the pre-registered local
script. **No Wazuh rule or triggering log is involved — the API call is the trigger.**
(Replay/in-stack flows leave the identity columns NULL; the change is fully additive.)

## What's in the bundle

```
endpoint_agent/
  install.sh                     one-command provisioner (sensor + agent + AR scripts)
  uninstall.sh                   teardown (add --purge-wazuh to remove the agent too)
  package.sh                     build a shippable tarball (snapshots the sensor source)
  active-response/
    bin/{soar-block,soar-unblock,soar-isolate,soar-unisolate}   the vetted allowlist
    lib/soar-ar-common.sh        STDIN parse + SAFETY validation + firewall backend
  sensor/
    Dockerfile, docker-compose.yml, .env.example                the NFStream sensor
    app/                         sensor source snapshot (filled by package.sh)
```

## Provision a new endpoint

**Option A — from the repo (detection host or a checkout):**
```bash
cd endpoint_agent
sudo ./install.sh --manager-host 172.31.80.148 --kafka-broker 172.31.87.134:9094 \
                  --agent-name web-vm-01 --interface eth0
```

**Option B — ship to a bare endpoint:**
```bash
./package.sh                                   # → dist/soar-endpoint-agent.tar.gz
scp dist/soar-endpoint-agent.tar.gz user@endpoint:
# on the endpoint:
tar xzf soar-endpoint-agent.tar.gz && cd endpoint_agent
sudo ./install.sh --manager-host 172.31.80.148 --kafka-broker 172.31.87.134:9094
```

### install.sh options
| Flag | Meaning | Default |
|---|---|---|
| `--manager-host <ip>` | Wazuh manager / SOAR host (**required**) | — |
| `--kafka-broker <host:port>` | detection host's external Kafka listener (**required** unless `--no-sensor`) | — |
| `--agent-name <name>` | Wazuh agent name = `host_id` | hostname |
| `--interface <iface>` | capture interface | `any` |
| `--registration-password <pw>` | authd shared password (if the manager requires one) | — |
| `--enroll-port` / `--comms-port` | authd / agent-comms ports | `1515` / `1516` |
| `--wazuh-version <ver>` | apt version (match the manager, 4.14.x) | `4.14.5-1` |
| `--block-ttl <secs>` | auto-expiry for `soar-block` | `3600` |
| `--no-sensor` / `--no-wazuh` | install only one half | both |

Requirements: root, Debian/Ubuntu (apt), Docker (for the sensor), `python3` (used by
the AR scripts for safe JSON parsing).

## The Active-Response scripts (safety centerpiece)

Four executables in `/var/ossec/active-response/bin/` named **exactly** as the
manager's `<command>`s expect. They take **no arbitrary command from the wire** — only
a validated IP argument; the action is fixed by which script ran.

| Script | Action | Reversible |
|---|---|---|
| `soar-block` | host-local **egress DROP** to a public IP (nftables/ipset/iptables), auto-expires after TTL | `soar-unblock` (and the TTL) |
| `soar-unblock` | remove a block | — |
| `soar-isolate` | drop **all** host traffic **except** the agent↔manager channel, loopback, and the **Docker bridges** (so a container-host's stack survives) | `soar-unisolate` |
| `soar-unisolate` | restore connectivity | — |

**Wazuh 4.x I/O:** each script reads a JSON object on STDIN; the action is `.command`
(`add`/`delete`) and the target IP arrives under `.parameters.extra_args`. On a stateful
`delete` (e.g. a manager timeout) `soar-block`/`soar-isolate` reverse themselves.

**Hard safety guarantees (in `soar-ar-common.sh`):**
- **Strict validation** — the target must be a syntactically valid IP (`ipaddress`).
- **Own-infra/RFC1918 denylist** — private, loopback, link-local, multicast, reserved,
  unspecified, **and the manager host** are **refused** (never block our own infra, the
  gateway, or loopback). Refusals are logged and exit cleanly (no agent retry storm).
- **Isolate keeps the manager channel + Docker bridges alive** — loopback, `MANAGER_HOST`
  on the enrollment/comms/API ports, and the interfaces in `SOAR_KEEP_IFACES`
  (default `docker0 docker_gwbridge br+`) survive, so the host stays manageable *and* a
  container-host's own stack (kafka/postgres/inference/…) keeps running. Set `SOAR_KEEP_IFACES=`
  empty for a strict total isolate. Isolate **refuses** if `MANAGER_HOST` is unset (fail-safe).
- **Every action is logged** to `/var/ossec/logs/active-responses.log` with its command id.
- **Firewall backend** auto-detected: nftables (set with native `timeout`) → ipset+iptables
  (set `timeout`) → plain iptables (detached expiry). Override with `SOAR_FW_BACKEND`.

Config lives in `/var/ossec/active-response/soar-ar.env` (written by the installer):
`MANAGER_HOST`, `MANAGER_PORTS`, `SOAR_BLOCK_TTL`, `SOAR_FW_BACKEND`, `SOAR_KEEP_IFACES`.

## Operational notes (verified live, 2026-06)

The block path is verified end-to-end (dashboard approve → orchestrator → Wazuh manager API →
this agent → `soar-block` → nft DROP + `active-responses.log`). Three things matter:

- **AR scripts read ONE stdin line, not to EOF.** Wazuh's `execd` writes one JSON line and keeps
  the pipe open (stateful AR sends a later `delete` on the same fd). `cat` would hang the script
  forever, and a single-threaded `execd` then blocks on the stuck child — so **no** subsequent AR
  runs. The scripts use `IFS= read -r -t 5`. (Manual `echo|script` tests pass regardless because
  they close the pipe — this only bites under real `execd`.)
- **Register a new AR ⇒ restart the agent.** `execd` loads the AR list (`ar.conf`) at startup;
  after the *manager* registers a new `<command>`, run `wazuh-control restart` on the agent so
  `execd` picks it up, else it silently ignores the inbound command.
- **Isolate on a host that is *also* the detection stack:** the Docker bridges are spared (above)
  so the containers keep talking, but the host's **own** external traffic is still cut — including
  your SSH/SSM session. Isolate such a host from *another* machine; recover with `soar-unisolate`
  (or `detctl agent unisolate`).

## Verify

```bash
./scripts/detctl.sh agent status             # agent connected? AR scripts? enforced blocks? isolated?
./scripts/detctl.sh agent ar-log -f          # watch soar-* invocations live
./scripts/detctl.sh agent blocks             # the nft soar_block set (currently DROPped IPs)
```
End-to-end (this host = the agent): `detctl sim <agent_id>` → approve a **public-IP block** in the
dashboard → `active-responses.log` shows `soar-ar: program=soar-block status=ok blocked <ip>` and
`agent blocks` shows the nft DROP. (Manager-side AR registration + the orchestrator dispatcher are
SOAR-side; both are wired and verified.)

## Teardown

```bash
sudo ./uninstall.sh                # remove sensor + AR scripts, flush firewall state, keep the agent
sudo ./uninstall.sh --purge-wazuh  # also remove the Wazuh agent
```

## Scope / boundaries

- This bundle delivers the **agent half**: the sensor, the four named AR executables,
  and the `agent_id`/`host_id` contract field.
- The **manager-side** AR `<command>`/`<active-response>` registration and the
  orchestrator's `PUT /active-response` dispatcher are **SOAR-side** (handled separately).
- The schema change is **additive/nullable** — existing dataset-replay runs are unaffected.
