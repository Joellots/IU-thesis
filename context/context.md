# XAI-SOAR Thesis Project — Detection-side Context

**Author:** Joel C. Okore, MSc Computer Science, Innopolis University
**Supervisor:** Dr Andrei Petrovski
**Last updated:** 2026-06-16. **For the whole-project picture (both halves) and the cross-half
contract, see [`context/SYSTEM_OVERVIEW.md`](SYSTEM_OVERVIEW.md).** This file is the
detection-side detail.

Thesis: **"Explainable Machine Learning for Malicious Encrypted Traffic Detection and
Trust-Aware SOAR Integration."** Two deliverables: (1) a conference paper (USBEREIT 2026,
accepted with minor corrections); (2) a proof-of-concept SOAR pipeline operationalising the
models. The SOAR half is co-developed with **Isaac Womoakor** on a separate machine/repo.

---

## Current State (one-liner)

The classifier has been **retrained on NFStream features**, the dataset rebuilt, and the
**feature→MITRE mapping validated and made live** — the thesis's three core technical results
are done. Remaining detection-side work is small (JA3 observable wiring, Phase-4 literature
grounding) plus the end-to-end demo and thesis writing.

---

## What's Done

- **Retrained model — `models/mapper`** (joblib dict: `rf_best`, `xgb_rt`, `xxgb` EBM,
  `scaler_rt`, `scaler_best`, `REALTIME_SAFE_FEATURES` (29), `BEST_FEATURES` (9), `target_cols`).
  Trained on NFStream-extracted features. **In-domain held-out F1 ≈ 0.97.** The old
  CICFlowMeter→NFStream distribution-shift problem (old mapper scored ~0.52 F1 on NFStream
  features) is solved. Notebook: `model_training/retrain_nfstream_model.ipynb`.
- **Training dataset — `data/training_dataset.csv`**: 11,822 flows, balanced 1:1, from **~25
  real Windows-malware families** (2022–2025, malware-traffic-analysis.net) over TLS + benign
  (CTU-Normal + the malware captures' own host background → no capture-origin confound).
  Per-flow IOC-labelled. Built by `utils/build_training_dataset.py` (+ `utils/fetch_mta_pcaps.py`).
- **Two detection classes** (the only TLS-observable malicious behaviours):
  **C2 beaconing → T1071/T1071.001/T1573** and **Exfiltration → T1041/T1048.002.**
- **Feature→MITRE mapping VALIDATED + LIVE — the headline result.**
  `services/translator/feature_mitre_map.py` (`fmm-2.0.0`), `feature → class → TTP`. Signatures
  validated by **four methods** (statistics + SHAP-binary + SHAP-3class + EBM-exact) with
  **90–100% bootstrap stability**; end-to-end **87.5% TTP-assignment accuracy** vs true labels.
  Emits live `mapping_confidence` (calibrated 0–1) + `mapping_status`
  (`mapped`/`unmapped_heuristic`/`unmapped`) with a tunable ambiguity-margin gate
  (`MAPPING_CLASS_MARGIN`, default 0.60). Notebook: `model_training/feature_mitre_validation.ipynb`.
- **Independent eval of the retrained mapper** (`utils/nfstream_model_eval.py --encrypted-only
  --balance`, on legacy out-of-distribution captures): ROC-AUC 0.977, F1-macro 0.80, malicious
  precision 0.99, FP rate ~0.5% — the over-flagging problem is gone; strong cross-era generalisation.

---

## Validated mapping (the contribution, in brief)

| Class → TTPs | Signature (4 methods agree) | Direction | Stability | End-to-end |
|---|---|---|---|---|
| C2 beaconing → T1071/.001/T1573 | TCP payload length, TCP window size, IP packet length | **HIGH** | 98–100% | F1 0.93, ~0.99 conf |
| Exfiltration → T1041/T1048.002 | inter-arrival / inter-packet timing | **LOW** | 90–100% | weaker (documented limit) |

`translate()` aggregates the malicious-pushing XAI top-k features into a weighted class vote
(confidence × |contribution|), assigns the dominant class's TTPs, and sets `mapping_confidence`
= contribution-weighted mean stability. Exfil is a documented limitation (minority class +
signature overlap). **Bonus result:** the validation process caught a wrong link in the prior
hand-asserted map (low-IAT→C2; it's actually exfil's signature).

---

## In Progress / Remaining (detection side)

- **JA3 observable wiring** — NFStream 6.6.0 exposes `client_fingerprint` (JA3) /
  `server_fingerprint` (JA3S). Wire them into the producer + the translator's
  `extract_observables()` as `{type: "ja3", …}` so Cortex/MISP can correlate. *Currently only
  ip/domain/url are extracted.* (The SOAR side is already coded to route `ja3`.)
- **Phase 4 — literature grounding** for the mapping (`citation` placeholders in
  `CLASS_TTP_MAP`). The empirical validation is complete; this adds prior-work citations per link.
- **End-to-end pipeline validation** — full stack on live/replayed traffic to the dashboard
  (latency, TTP-assignment rate, Tier-2 trigger rate).
- **SOAR integration** (separate machine, Isaac+Joel) — orchestrator + Shuffle against the
  shared `alerts` contract; see `SYSTEM_OVERVIEW.md` + `services/soar_orchestrator/SOAR_WORKFLOW_SPEC.md`.

---

## Key Decisions & Rationale

| Decision | Choice | Rationale |
|---|---|---|
| Feature extraction | NFStream 6.6.0 | Reproducible, Python-native. Cite Aouini & Pekar 2022, *Computer Networks* 204:108719. |
| Argus — rejected | — | PCAP-replay jitter DSR → `sintpkt=0.0`; IAT broken in file-replay mode. |
| Retrain on NFStream features | Done | Old dpkt/scapy-trained mapper collapsed (0.52 F1) under the extractor shift; retrained = 0.97. |
| Detection scope | C2 + exfil only | In TLS traffic, malicious behaviour reduces to these two; lateral movement/scan are unencrypted, ransomware-impact is non-network (probe: 1/7209 east-west flows was TLS). Documented finding. |
| Training data source | Real Windows malware (MTA) | CIC-AndMal (Android) rejected — platform mismatch + would confound model (learns platform, not maliciousness). MTA = Windows + HTTPS-C2 + real. |
| Encrypted filter | TLS-protocol detection | NFStream `application_name ~ TLS/SSL/QUIC` (Zeek-equivalent) catches TLS on non-standard ports — port-only missed ~⅔ of malicious. |
| Mapping structure | feature → class → TTP | Aggregates XAI evidence into a behavioural class, then assigns TTPs; cleaner + carries a per-alert confidence. |
| Model serialisation | joblib (`models/mapper`, no extension) | `joblib.load("models/mapper")`. |
| Kafka | `apache/kafka:3.7.0` KRaft; client `kafka-python-ng==2.2.3` | Single-node; the ng fork works on Python 3.12. |

---

## Gotchas / Lessons

- **All 4 TTL features are dead** — NFStream 6.6.0 exposes no TTL attributes (`[a for a in
  dir(flow) if 'ttl' in a]` → `[]`). Dropped from the feature set (29, not 33).
- **`piat_list` epoch bug [FIXED]** — `on_init` seeded the absolute timestamp; corrupted
  `median_piat_ms` (~5e10 ms). Fixed (seed `[]`, median guard `>=1`); verified 99.5% nonzero.
- **Real encrypted *malicious* flows are sparse in public data** — infection captures are
  mostly the victim host's benign background + a few C2 flows; HTTPS exfil especially
  (~5–10 flows/capture). Hence MTA aggregation (86 captures) + the "exfil is a minority class"
  finding. This is a defensible thesis observation, not a tooling gap.
- **Mapping labelling is IOC-completeness-dependent** — a flow is malicious iff it matches a
  capture's *published* IOCs (IP/SNI); a C2 endpoint missing from the IOC file is mislabelled
  benign. Thesis caveat.
- **`models/mapper` is the retrained model** (≈50 MB). Any `./mapper` at repo root is a stray —
  use `models/mapper`.

---

## Relevant Files

**Pipeline services**
- `docker-compose.yml` — 8-service stack (kafka, nfstream, producer, inference, translator, postgres, dashboard, kafka-ui).
- `services/nfstream/nfstream_producer.py` — live/PCAP capture → `ExtendedFlowFeatures` plugin → `NFSTREAM_TO_MODEL` mapping → Kafka `raw_flows` + CSV. (TTL fix applied; std_ttl flagged.)
- `services/inference/inference_service.py` (+ `explain_instance.py`) — loads `mapper`, runs two-tier XAI, publishes `alerts` with `top_k_json`.
- `services/translator/translator_service.py` — consumes `alerts`, calls `translate()`, extracts `observables`, writes PostgreSQL `alerts` (incl. `mapping_*`).
- `services/translator/feature_mitre_map.py` — **`fmm-2.0.0`**: `FEATURE_CLASS_MAP` + `CLASS_TTP_MAP` + `translate()` (class voting + margin gate) + `compute_severity()` (advisory).
- `services/dashboard/main.py` + `schema.sql` — analyst UI + the shared `alerts` schema (the contract).
- `services/soar_orchestrator/` — SOAR module (co-owned; see `SOAR_WORKFLOW_SPEC.md`).

**Models & data**
- `models/mapper` — retrained joblib dict (29 `REALTIME_SAFE_FEATURES`, 9 `BEST_FEATURES`).
- `data/training_dataset.csv` — the labelled training set (gitignored); `data/dataset.csv` — producer replay source.
- `pcaps/mta/ioc_manifest.json` — pins the dataset (the only tracked file under `pcaps/`).

**Utilities & notebooks**
- `utils/build_training_dataset.py` — builds the labelled NFStream training set (`CAPTURE_MANIFEST` + MTA `ioc_manifest.json`; `--encrypted-only --balance --per-class-cap …`).
- `utils/fetch_mta_pcaps.py` — batch-downloads MTA captures by date, auto-parses published IOCs → `ioc_manifest.json`.
- `utils/fetch_pcaps.py` — catalogued PCAP downloader (CTU-13/IoT-23/CTU-Normal/ransomware).
- `utils/nfstream_model_eval.py` — evaluate the mapper on PCAPs (`--encrypted-only --balance --min-packets --max-flows-per-pcap`).
- `model_training/retrain_nfstream_model.ipynb` — clean retraining notebook (loads dataset, trains RF/XGB/EBM, saves mapper).
- `model_training/feature_mitre_validation.ipynb` — mapping validation (stats + SHAP×2 + EBM + bootstrap stability + end-to-end).
- `model_training/usbereit-xai-MAIN-reference.ipynb` — original research notebook (reference).

**`BEST_FEATURES` (retrained, 9)** — TCP-payload-length + window/payload-change centric:
```
max/std/min/mean_Length_of_TCP_payload, Length_of_TCP_payload,
Change_values_of_TCP_windows_length_per_session,
The_times_of_change_of_payload_per_session,
max_Interval_of_arrival_time_of_forward_traffic,
max_Time_difference_between_packets_per_session
```

---

## How to Run / Test (from `~/dev/`, `source .env/bin/activate`)

```bash
# Docker stack
docker compose up --build                        # full 8-service stack (dashboard :8080, kafka-ui :8081)

# Retrain (notebook) or evaluate the mapper
python3 utils/nfstream_model_eval.py \
    --benign pcaps/benign/*.pcap --malicious pcaps/malicious/*.pcap \
    --model models/mapper --output /tmp/eval/ --encrypted-only --balance --min-packets 4

# Rebuild the training dataset
python3 utils/build_training_dataset.py --output data/ --min-packets 4 --encrypted-only --balance

# Fetch more MTA captures
python3 utils/fetch_mta_pcaps.py --out pcaps/mta/ --jobs 4
```

---

## Docker Stack (reference)

8 services in `docker-compose.yml`; bridge network `net`; Kafka KRaft.

| Service | container | Role |
|---|---|---|
| kafka | `kafka` | KRaft broker; 9092 internal / 9094 external |
| producer | `producer` | replays `data/dataset.csv` → `raw_flows` |
| nfstream | `xai_nfstream` | live/PCAP capture → features → `raw_flows` (`network_mode: host`) |
| inference | `inference` | mapper inference + XAI → `alerts` |
| translator | `translator` | XAI→MITRE (`fmm-2.0.0`) + observables → PostgreSQL |
| postgres | `postgres` | shared `alerts` store (the SOAR contract; not yet port-published for cross-machine) |
| dashboard | `dashboard` | FastAPI + htmx analyst UI (`:8080`) |
| kafka-ui | `kafka_ui` | dev Kafka inspector (`:8081`) |

> Cross-machine note: the SOAR orchestrator (other machine) reads this PostgreSQL. To enable
> that, publish `postgres` 5432 + firewall to the SOAR host, and point the orchestrator's
> `DATABASE_URL` at this machine's IP.

---

## Thesis Writing Remaining

- **Methods/Results:** the retraining (extractor distribution-shift), the dataset (MTA, encrypted-malicious sparsity finding), and the **validated feature→class→TTP mapping** (4-method + bootstrap + 87.5% end-to-end) — the headline.
- **SOAR chapter:** architecture, the `alerts` contract + mapping-confidence trust gate, pipeline eval metrics, limitations.
- **Related Work:** cite Aouini & Pekar 2022 (NFStream); the Composed dataset paper (source benchmarks).
- **Limitations:** exfil minority/overlap; IOC-completeness labelling; single-deployment scope.
- **Open Qs for supervisor:** human evaluation of annotation quality vs automated TTP accuracy; submission-deadline alignment.
