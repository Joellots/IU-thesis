# IU-thesis — Aegis

**Explainable ML for Malicious Encrypted Traffic Detection and Trust-Aware SOAR Integration.**

> **Cross-system context — read `context/SYSTEM_OVERVIEW.md` first.** The project spans two
> machines in separate repos (this **detection** half and the **SOAR** half); `SYSTEM_OVERVIEW.md`
> describes both halves and the `alerts`-table contract between them. This repo is the detection
> half — NFStream capture → inference → XAI → translator → the shared PostgreSQL `alerts` table.

Key docs: `context/SYSTEM_OVERVIEW.md` (whole project), `context/context.md` (detection-side
detail), `context/SOAR_WORKFLOW_SPEC.md` (SOAR workflow + contract),
`context/DETECTION_FRAMEWORK_CONTEXT.md` (full detection reference + Appendix A methodology),
**[`CHEATSHEET.md`](CHEATSHEET.md)** (operator commands).

---

## Quickstart (single machine — detection demo)

**Prerequisites:** Linux **x86-64**, **Docker** + **Docker Compose v2** (`docker compose`),
~8 GB free RAM. No GPU. (ARM/Apple-Silicon may struggle with the NFStream native build.)

```bash
git clone <this-repo> aegis && cd aegis
cp .env.example .env            # defaults run a single-machine demo as-is
./scripts/detctl.sh up          # build + start pipeline + dashboards (first build ~5–10 min)
./scripts/detctl.sh sim         # replay labelled flows → alerts
#   React http://localhost:3000   ·   htmx :8080   ·   kafka-ui :8081
```
`detctl` auto-creates `.env` from the template if you skip the `cp`. Full command surface:
[CHEATSHEET.md](CHEATSHEET.md).

**Shipped so this runs out of the box:** `models/mapper` (≈50 MB trained mapper) and
`data/training_dataset.csv` (≈6 MB labelled replay set). The 1.9 GB raw `data/dataset.csv` is
**not** shipped — rebuild datasets with `detctl dataset`.

## Full closed loop (two machines)

The SOAR cases / Cortex enrichment / **gated block-isolate approvals** and endpoint enforcement
need the **separate SOAR repo** on a second host, wired to this one:

1. **Detection host `.env`:** set `KAFKA_EXTERNAL_ADVERTISED_HOST` to this host's LAN IP (not
   `localhost`), `SIM_HOST_IP` to this host, `SOAR_APPROVAL_URL=http://<SOAR_HOST>:8200`, and a
   `SOAR_APPROVAL_TOKEN` (`openssl rand -base64 32`). **Publish + firewall Postgres `:5432` and
   Kafka `:9094` to the SOAR host.** Then `detctl up`.
2. **SOAR host (other repo):** point its `DATABASE_URL` at `…@<DETECTION_HOST>:5432/soar` and
   `KAFKA_BROKER` at `<DETECTION_HOST>:9094`, set the **same** `SOAR_APPROVAL_TOKEN`, start the orchestrator.
3. **Endpoint agent (optional):** `endpoint_agent/install.sh` on any host to make it a sensor +
   Wazuh Active-Response actuator — see [endpoint_agent/README.md](endpoint_agent/README.md).

The end-to-end block demo is in [CHEATSHEET.md](CHEATSHEET.md) §5. All config lives in the
gitignored `.env` — template + per-var docs in **[`.env.example`](.env.example)**.

## Deployment notes & gotchas
- **First build is slow** (inference compiles SHAP/LIME/XGBoost; the React app runs `npm install`).
- `detctl reset` wipes the alerts DB + rebuilds; `detctl up` preserves it. Postgres + Kafka use
  `restart: unless-stopped` (survive reboots).
- **After recreating Kafka or Postgres**, `detctl restart inference translator` — a live broker/DB
  swap leaves their connections stale.
- **Ports:** 3000/8080/8081 (UIs), 5432 (Postgres), 9092/9094 (Kafka). For two-machine, 5432 + 9094
  must reach the SOAR host.
- **Secrets:** the only secret is `SOAR_APPROVAL_TOKEN`; `.env` is gitignored. **`models/mapper`
  (~50 MB)** is at GitHub's size-warning threshold — track with Git LFS if you prefer.
- The shipped dataset is *derived flow features* (malware-traffic-analysis.net + CTU), not raw
  PCAPs; swap your own `data/training_dataset.csv` (same columns) to replay different traffic.
