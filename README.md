# Aegis (detection side)

Real-time detection of malicious HTTPS traffic using machine learning on flow
metadata, with the explanation carried forward as evidence for an automated
response loop. This repository is the detection and explainability half of my
MSc thesis at Innopolis University (2026), *Real-Time Detection and Automated
Response Framework for Malicious HTTPS Traffic Using Machine Learning and SOAR
Integration*.

Aegis runs across two repositories on two hosts. This one captures encrypted
flows, classifies them from behavioural metadata without decrypting anything,
explains each prediction, maps the explanation to MITRE ATT&CK techniques, and
writes alerts into a shared PostgreSQL table. The SOAR half — a separate repo,
co-developed with Isaac Womoakor — reads that table and handles threat-intel
enrichment, the analyst approval workflow, and endpoint response. The `alerts`
table is the contract between the two sides; [SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md)
covers both halves and the handoff.

## Pipeline

```
NFStream sensor → Kafka (raw_flows) → inference (XGBoost + XAI)
              → translator (features → ATT&CK, severity) → PostgreSQL alerts → dashboard
```

Detection never decrypts traffic. Classification uses statistical and
protocol-level flow features; the two-tier XAI layer attaches the features most
responsible for each decision, and the translator turns those into an
empirically validated technique mapping with a separate confidence score.

## Running it (single machine)

Requires Linux x86-64, Docker with Compose v2 (`docker compose`), and about 8 GB
of free RAM. No GPU. The first build takes 5–10 minutes because inference
compiles SHAP/LIME/XGBoost and the React dashboard installs its dependencies.

```bash
git clone <this-repo> aegis && cd aegis
cp .env.example .env          # the defaults run a self-contained demo
./scripts/detctl.sh up        # build and start the pipeline + dashboards
./scripts/detctl.sh sim       # replay labelled flows and watch alerts appear
```

Dashboards come up on http://localhost:3000 (React), :8080 (htmx), and :8081
(kafka-ui). `detctl` writes a `.env` from the template if you skip the copy.
The full command list is in [CHEATSHEET.md](CHEATSHEET.md).

The trained mapper (`models/mapper`, ~50 MB) and a small labelled replay set
(`data/training_dataset.csv`, ~6 MB) are committed so the demo works without any
extra downloads. The 1.9 GB raw `data/dataset.csv` is not committed; rebuild
datasets with `detctl dataset`.

## Two-machine setup

The cases, Cortex enrichment, gated block/isolate approvals, and endpoint
enforcement live in the SOAR repo on a second host. To wire the two together:

1. On this host, point `KAFKA_EXTERNAL_ADVERTISED_HOST` and `SIM_HOST_IP` at the
   host's LAN IP, set `SOAR_APPROVAL_URL=http://<soar-host>:8200` and a shared
   `SOAR_APPROVAL_TOKEN`, then expose Postgres (`5432`) and Kafka (`9094`) to the
   SOAR host and run `detctl up`.
2. On the SOAR host, set its `DATABASE_URL` to `…@<this-host>:5432/soar`,
   `KAFKA_BROKER` to `<this-host>:9094`, the same `SOAR_APPROVAL_TOKEN`, and start
   the orchestrator.
3. Optionally install the endpoint agent (`endpoint_agent/install.sh`) on a host
   to turn it into a sensor and Wazuh Active-Response actuator. See
   [endpoint_agent/README.md](endpoint_agent/README.md).

The end-to-end block/isolate demo is in [CHEATSHEET.md](CHEATSHEET.md), §5.

## Layout

    services/        the pipeline: nfstream, producer, inference, translator, dashboard(s)
    scripts/         detctl.sh — build/run/sim/harvest operator CLI
    utils/           detection evaluation and simulation-metrics harvesters
    model_training/  notebooks and scripts for training the classifier and mapper
    models/          shipped trained mapper
    endpoint_agent/  installable sensor + Wazuh Active-Response actuator
    data/  pcaps/    labelled demo dataset and capture sources

## Notes

- `detctl reset` wipes the alerts database and rebuilds; `detctl up` keeps it.
  Postgres and Kafka use `restart: unless-stopped`, so they survive reboots.
- After recreating Kafka or Postgres, run `detctl restart inference translator`;
  a live broker or database swap leaves their connections stale.
- The only secret is `SOAR_APPROVAL_TOKEN`. `.env` is gitignored; every variable
  is documented in [.env.example](.env.example).
- `models/mapper` sits near GitHub's file-size warning; use Git LFS if that
  bothers you.

## Documentation

[SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md) describes both halves of Aegis and the
`alerts`-table contract between them. [CHEATSHEET.md](CHEATSHEET.md) covers the
day-to-day operator commands.

## License

MIT — see [LICENSE](LICENSE). Author: Okore Joel Chidike, supervised by
Dr Andrei Petrovski, Innopolis University.
