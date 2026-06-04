# XAI-SOAR Thesis Project — Context for Claude Code
**Author:** Joel C. Okore, MSc Computer Science, Innopolis University
**Supervisor:** Dr Andrei Petrovski
**Date:** May 2026

---

## 1. Project Overview

Thesis title: **"Explainable Machine Learning for Malicious Encrypted Traffic Detection and Trust-Aware SOAR Integration"**

The thesis proposes and implements an end-to-end pipeline for detecting malicious encrypted network traffic using explainable ML, and integrating those explanations into a Security Orchestration, Automation and Response (SOAR) workflow. The work has two major components:

1. **A conference paper** — accepted at USBEREIT 2026 with minor corrections. Covers dataset, feature engineering, three ML models (RF, XGBoost, EBM), a two-tier XAI pipeline, feature selection analysis, and security semantic mapping of top features. Full LaTeX source is available.

2. **A proof-of-concept SOAR pipeline** — a containerised Docker Compose stack that operationalises the paper's findings into a running system.

---

## 2. Repository Structure

```
~/dev/                                  # Working directory (ubuntu@ip-172-31-83-119)
├── README.md
├── aggregated_flows.csv                # Top-level flow output (also in services/nfstream/output/)
├── context/
│   └── claude_code_context.md         # This file — project context for Claude Code
├── docker-compose.yml                  # Main stack (6 services)
├── eval_results/                       # Output from utils/nfstream_model_eval.py
│   ├── extracted_features.csv
│   └── per_flow_predictions.csv
├── models/
│   └── mapper                          # Serialised model mapper — joblib dict (see Section 4)
├── pcaps/                              # PCAP files for evaluation and testing
│   ├── benign.pcap
│   └── malicious.pcap
├── requirements.txt                    # Top-level Python dependencies
├── services/
│   ├── dashboard/
│   │   ├── Dockerfile
│   │   ├── main.py                     # FastAPI + Jinja2 + htmx analyst UI
│   │   ├── requirements.txt
│   │   ├── schema.sql                  # PostgreSQL schema
│   │   └── templates/
│   │       ├── _alert_rows.html
│   │       ├── detail.html
│   │       └── index.html
│   ├── inference/
│   │   ├── Dockerfile
│   │   ├── explain_instance.py         # Ported from research notebook
│   │   ├── inference_service.py        # Loads models, runs explain_instance()
│   │   └── requirements.txt
│   ├── nfstream/
│   │   ├── Dockerfile
│   │   ├── nfstream_producer.py        # Live capture → feature extraction → Kafka
│   │   ├── output/
│   │   │   └── aggregated_flows.csv    # Volume-mounted CSV output from live capture
│   │   └── requirements.txt            # nfstream==6.6.0, kafka-python-ng, pandas
│   ├── producer/
│   │   ├── Dockerfile
│   │   ├── producer.py                 # Streams dataset CSV → raw_flows topic
│   │   └── requirements.txt
│   └── translator/
│       ├── Dockerfile
│       ├── feature_mitre_map.py        # Feature → ATT&CK TTP dictionary
│       ├── requirements.txt
│       └── translator_service.py       # XAI → MITRE mapping, severity, PostgreSQL
└── utils/
    ├── nfstream_model_eval.py          # Evaluate trained models on NFStream-extracted PCAPs
    ├── test_kafka.py                   # Kafka connectivity test script
    └── usbereit-xai-for-encrypted-https-traffic-anomaly-detection-MAIN.ipynb
                                        # Research notebook — model training, SHAP analysis,
                                        # feature selection. Use this if retraining is needed.
```

**Notes on structure:**
- The `docker-compose.argus.yml` and `services/argus/` directory from earlier experiments are no longer present — Argus was evaluated and rejected (see Section 11).
- Kafka has no dedicated service subdirectory — it runs from the official `confluentinc/cp-kafka` image configured entirely in `docker-compose.yml`.
- The model mapper file is named `mapper` (no `.joblib` extension) — load with `joblib.load("models/mapper")`.
- `utils/nfstream_model_eval.py` was moved from the project root. Path references inside the script may need updating — the script writes output to `eval_results/` relative to wherever it is run from, so run it from `~/dev/` to keep output in the correct location.

---

## 3. Docker Compose Stack

Seven services total. Six in `docker-compose.yml`, one pending:

| # | Service | Container | Role | Status |
|---|---|---|---|---|
| 1 | Kafka | xai_kafka | KRaft message bus, ports 9092 (internal) / 9094 (external) | Working |
| 2 | Producer | xai_producer | Streams dataset CSV rows to `raw_flows` topic | Working |
| 3 | Inference | xai_inference | Loads joblib models, runs `explain_instance()`, publishes to `alerts` | Working |
| 4 | Translator | xai_translator | XAI→MITRE mapping, severity scoring, writes to PostgreSQL | Working |
| 5 | PostgreSQL | xai_postgres | Persistent store for alerts, explanations, analyst decisions | Working |
| 6 | Dashboard | xai_dashboard | FastAPI analyst UI with htmx live refresh | Working |
| 7 | NFStream | xai_nfstream | Live traffic capture → feature extraction → Kafka | In progress |

**Key networking note:** The NFStream service uses `network_mode: host` (required for live capture). Because of this it cannot use the `xai_net` Docker bridge — it reaches Kafka via `localhost:9094` (the external listener).

**Resource limits** are set on all services. Inference is capped at 2GB RAM / 2 CPU.

---

## 4. ML Models and Serialisation

Models are serialised as a single `mapper.joblib` dict with these keys:

```python
mapper = {
    "rf_best":               # RandomForest trained on BEST_FEATURES (9 features)
    "xgb_rt":                # XGBoost trained on REALTIME_SAFE_FEATURES (65 features)
    "xxgb":                  # XGBoost trained on BEST_FEATURES (9 features)
    "scaler_rt":             # StandardScaler for xgb_rt
    "scaler_best":           # StandardScaler for rf_best / xxgb
    "REALTIME_SAFE_FEATURES": # list of 65 feature names
    "BEST_FEATURES":          # list of 9 feature names
    "target_cols":            # label column name(s)
}
```

**Best Features (9)** — highest importance intersection of RF and XGBoost top-20:
```python
BEST_FEATURES = [
    "The_times_of_change_of_payload_per_session",
    "max_Interval_of_arrival_time_of_backward_traffic",
    "mean_Interval_of_arrival_time_of_backward_traffic",
    "mean_Interval_of_arrival_time_of_forward_traffic",
    "mean_TCP_windows_size_value",
    "median_Time_difference_between_packets_per_session",
    "std_Interval_of_arrival_time_of_backward_traffic",
    "std_Length_of_IP_packets",
    "std_time_to_live",
]
```

**Detection performance (on CICFlowMeter-extracted training data):**
- Random Forest: Accuracy=0.9998, F1=0.9997, ROC-AUC=1.0000
- XGBoost: Accuracy=0.9997, F1=0.9997, ROC-AUC=1.0000
- EBM: Accuracy=0.9989, F1=0.9989, ROC-AUC=0.9998

---

## 5. Training Dataset

**Composed Encrypted Malicious Traffic Dataset** — 117,627 sessions, ~50/50 malicious/benign, composed from 5 public benchmarks:
- Malware Capture Facility Project Dataset
- CICIDS-2012
- CIC-AndMal 2017
- CICIDS-2017
- UNSW-NB19

Features were extracted using **CICFlowMeter** — this is important context for the current problem described in Section 8.

---

## 6. NFStream Feature Extraction Service

### NFPlugin implementation

`ExtendedFlowFeatures` in `nfstream_producer.py` computes features not available from NFStream's built-in `statistical_analysis=True`:

```python
class ExtendedFlowFeatures(NFPlugin):
    # on_init:   initialise piat_list, payload tracking, window tracking, TTL tracking
    # on_update: append IAT, count payload changes, count transport size changes
    # on_expire: compute median IAT, TTL stats from flow-level attrs, window stats
```

### Known NFPacket attribute issue
NFStream's NFPacket does **not** expose `ip_ttl` or `tcp_window` as per-packet attributes. The correct approach is to derive TTL statistics from flow-level attributes (`src2dst_min_ttl`, `src2dst_max_ttl`, `dst2src_min_ttl`, `dst2src_max_ttl`) inside `on_expire`. TCP window statistics are derived from packet size distributions as a proxy.

### NFStream → Model column mapping (NFSTREAM_TO_MODEL dict)
Key mappings:
```python
"bidirectional_stddev_ps"    → "std_Length_of_IP_packets"
"src2dst_mean_piat_ms"       → "mean_Interval_of_arrival_time_of_forward_traffic"
"dst2src_stddev_piat_ms"     → "std_Interval_of_arrival_time_of_backward_traffic"
"dst2src_max_piat_ms"        → "max_Interval_of_arrival_time_of_backward_traffic"
"dst2src_mean_piat_ms"       → "mean_Interval_of_arrival_time_of_backward_traffic"
"udps.std_ttl"               → "std_time_to_live"
"udps.mean_window_size"      → "mean_TCP_windows_size_value"
"udps.payload_changes"       → "The_times_of_change_of_payload_per_session"
"udps.median_piat_ms"        → "median_Time_difference_between_packets_per_session"
```

### Volume mount for CSV output
```yaml
volumes:
  - ./services/nfstream/output:/app/generated_flows
environment:
  CSV_FILE: /app/generated_flows/aggregated_flows.csv
```

---

## 7. Two-Tier XAI Pipeline

Implemented in `explain_instance.py` and called from `inference_service.py`:

**Tier 1 (always-on, every flow):**
- EBM local explanation — 3.5ms p50, 285 exp/s, exact by construction
- XGBoost built-in contributions — 12.7ms p50, 76 exp/s, deterministic (Jaccard=1.0)

**Tier 2 (on-demand, flagged flows only):**
- Triggered when P(malicious) ≥ 0.80 or P ∈ [0.45, 0.55]
- SHAP TreeExplainer — 12.8ms p50, fidelity reference
- LIME — 6.2ms p50, Jaccard=0.899±0.137, forensic use

All explainers return a unified `explain_instance()` record: instance ID, model, tier, predicted label, confidence, top-k feature attributions (name, value, signed contribution, direction), wall-clock time.

---

## 8. Current Problem — Feature Distribution Shift

### The problem
Models were trained on features extracted by **CICFlowMeter**. The NFStream feature extractor produces different feature distributions and is missing 32 of the 65 expected features entirely. Running `nfstream_model_eval.py` showed:

- 29/65 features populated
- 4/65 all-zero (TTL fields — `on_expire` TTL derivation not working)
- 32/65 completely missing (include all header-length features, median variants, session ratio features that CICFlowMeter computes but NFStream does not)

**Model performance on NFStream-extracted features (with 32 features zeroed):**
- Random Forest (best_features): Accuracy=0.12, F1=0.11 — completely broken
- XGBoost crashed before evaluation due to missing features bug (now fixed)

The model is predicting almost everything as malicious (9229 FP out of 10486 benign flows) because the zeroed feature values fall outside all learned decision boundaries.

### Root cause
This is a **feature extraction tool distribution shift** problem. CICFlowMeter and NFStream compute different feature sets with different statistical properties. The existing models cannot bridge this gap.

### Fix: script available
`utils/nfstream_model_eval.py` — evaluates trained models on NFStream-extracted PCAP features. Bug fix needed: add missing columns as zeros to `df` before `df[features].copy()` in `evaluate()`. **Run from `~/dev/` so that relative output path `eval_results/` resolves correctly.**

### Evaluation status — preliminary only
The initial evaluation used only one benign PCAP and one malicious PCAP (67 malicious flows vs 10,486 benign flows). This class imbalance makes the metrics misleading and the results are not a reliable basis for conclusions. A **more extensive evaluation is planned** using multiple PCAP files across multiple attack classes and benign traffic types to get statistically meaningful results before deciding whether to retrain. Until that evaluation is complete, the distribution shift conclusion should be treated as preliminary.

---

## 9. Immediate Next Step — Retrain on NFStream Data

### Plan
1. **Run extensive evaluation of existing mapper** — multiple benign PCAPs (different traffic types: browsing, streaming, corporate) and multiple malicious PCAPs (different attack classes: C2, ransomware, exfiltration). Goal is a balanced, statistically meaningful evaluation before deciding whether retraining is necessary.
2. Analyse results per attack class — some classes may generalise better than others across the CICFlowMeter→NFStream shift.
3. If accuracy is acceptable (F1 ≥ 0.90 on NFStream features): proceed to pipeline integration with existing models.
4. If accuracy is insufficient: collect PCAP files for target attack classes, extract features using NFStream + ExtendedFlowFeatures plugin, build a new training dataset, retrain RF/XGBoost/EBM on NFStream-extracted feature set, update `REALTIME_SAFE_FEATURES` and `BEST_FEATURES`, re-serialise `mapper.joblib`.
5. Validate end-to-end through the full pipeline.

### Target attack classes (for PoC pipeline)
Focus on attacks that map naturally to MITRE ATT&CK TTPs already in `feature_mitre_map.py`:
- **C2 beaconing** — T1071.001 (Web Protocols), T1573 (Encrypted Channel)
- **Encrypted exfiltration** — T1048.002
- **Ransomware C2** — T1071, T1486 (WannaCry PCAP already available)

Joel will provide links to the public datasets that make up the original Composed Encrypted Malicious Traffic Dataset, and details of the composition approach, when ready to proceed with dataset construction.

### NFStream-computable feature set (what to train on)
Features confirmed extractable from NFStream (`statistical_analysis=True` + `ExtendedFlowFeatures`):

```python
# Direct from statistical_analysis=True
"mean_Length_of_IP_packets",       # bidirectional_mean_ps
"std_Length_of_IP_packets",        # bidirectional_stddev_ps
"max_Length_of_IP_packets",        # bidirectional_max_ps
"min_Length_of_IP_packets",        # bidirectional_min_ps
"mean_Length_of_TCP_payload",      # src2dst_mean_ps
"std_Length_of_TCP_payload",       # src2dst_stddev_ps
"max_Length_of_TCP_payload",       # src2dst_max_ps
"min_Length_of_TCP_payload",       # src2dst_min_ps
"Length_of_TCP_payload",           # src2dst_bytes
"mean_Time_difference_between_packets_per_session",    # bidirectional_mean_piat_ms
"std_Time_difference_between_packets_per_session",     # bidirectional_stddev_piat_ms
"max_Time_difference_between_packets_per_session",     # bidirectional_max_piat_ms
"min_Time_difference_between_packets_per_session",     # bidirectional_min_piat_ms
"mean_Interval_of_arrival_time_of_forward_traffic",    # src2dst_mean_piat_ms
"std_Interval_of_arrival_time_of_forward_traffic",     # src2dst_stddev_piat_ms
"max_Interval_of_arrival_time_of_forward_traffic",     # src2dst_max_piat_ms
"min_Interval_of_arrival_time_of_forward_traffic",     # src2dst_min_piat_ms
"mean_Interval_of_arrival_time_of_backward_traffic",   # dst2src_mean_piat_ms
"std_Interval_of_arrival_time_of_backward_traffic",    # dst2src_stddev_piat_ms
"max_Interval_of_arrival_time_of_backward_traffic",    # dst2src_max_piat_ms
"min_Interval_of_arrival_time_of_backward_traffic",    # dst2src_min_piat_ms

# From ExtendedFlowFeatures NFPlugin
"median_Time_difference_between_packets_per_session",  # udps.median_piat_ms
"mean_time_to_live",               # udps.mean_ttl
"std_time_to_live",                # udps.std_ttl
"max_time_to_live",                # udps.max_ttl
"min_time_to_live",                # udps.min_ttl
"mean_TCP_windows_size_value",     # udps.mean_window_size
"std_TCP_windows_size_value",      # udps.std_window_size
"max_TCP_windows_size_value",      # udps.max_window_size
"min_TCP_windows_size_value",      # udps.min_window_size
"median_TCP_windows_size_value",   # udps.median_window_size
"The_times_of_change_of_payload_per_session",          # udps.payload_changes
"Change_values_of_TCP_windows_length_per_session",     # udps.window_changes
```

---

## 10. Future Work (Thesis Remaining)

### Pipeline completion
- [ ] End-to-end pipeline validation — all 6 services running and data flowing through to dashboard
- [ ] Pipeline evaluation metrics: end-to-end latency, TTP assignment accuracy, Tier-2 trigger rate
- [ ] TheHive + Cortex SOAR integration — **being implemented by Isaac Womoakor (co-author) as a separate module**. Integration point with Joel's pipeline: translator service publishes HIGH severity alerts to TheHive via API to create cases; Cortex responders trigger automated response actions. Joel's responsibility is the API interface between the translator and TheHive, not the TheHive/Cortex deployment itself.

### Dataset and model evaluation / retraining
- [ ] **Run extensive model evaluation** — multiple benign + malicious PCAPs, multiple attack classes, balanced evaluation (immediate next step)
- [ ] Decide based on evaluation results: retrain vs proceed with existing models
- [ ] If retraining: obtain PCAPs for target attack classes, build NFStream-extracted training dataset, retrain models, re-serialise mapper
- [ ] Validate model on live captured traffic through the full pipeline

### Thesis writing
- [ ] SOAR chapter: architecture design decisions, XAI-to-MITRE translation layer design, pipeline evaluation results, limitations
- [ ] Related Work chapter: cite NFStream paper (Aouini & Pekar 2022, Computer Networks 204:108719) as primary reference for feature extraction module
- [ ] Conclusion chapter: explicitly acknowledge single-dataset limitation, class imbalance gap, future cross-dataset validation
- [ ] Final review and submission

### Open questions requiring supervisor input
- Is a human evaluation of annotation quality expected for the SOAR module, or is automated TTP accuracy against dataset labels sufficient?
- Does the current timeline align with departmental submission deadlines?

---

## 11. Key Technical Decisions and Rationale

| Decision | Choice | Rationale |
|---|---|---|
| Feature extraction tool | NFStream 6.6.0 | CICFlowMeter has known bugs; NFStream is reproducible and Python-native. Cite: Aouini & Pekar 2022 |
| Packet capture (evaluated and rejected) | Argus | PCAP-mode jitter DSR produces `sintpkt=0.0` for all records — IAT computation broken in file replay mode |
| SOAR platform | TheHive + Cortex | Joel's partner Isaac Womoakor is implementing this module separately. TheHive for case management and alert triage; Cortex for automated response actions. Integration point: translator service publishes HIGH severity alerts → TheHive API creates cases → Cortex responders trigger actions. |
| Model serialisation | joblib | Faster and more reliable than pickle for sklearn/XGBoost objects |
| Kafka compatibility | kafka-python-ng==2.2.3 | kafka-python 2.0.2 broken on Python 3.12 — this fork is the actively maintained replacement |
| Kafka listener | Two listeners: internal kafka:9092, external localhost:9094 | NFStream service uses network_mode:host and cannot reach Docker bridge network |

---

## 12. Known Bugs and Fixes

| Bug | Status | Fix |
|---|---|---|
| `nfstream_model_eval.py` crashes on missing features | Fixed description available | Add `df[f] = 0.0` for missing columns before `df[features].copy()` in `evaluate()` |
| NFPlugin TTL fields all zero | Root cause identified | `ip_ttl` not a valid NFPacket attribute; derive from flow-level `src2dst_min_ttl` etc. in `on_expire` |
| NFPlugin TCP window fields all zero | Root cause identified | `tcp_window` not a valid NFPacket attribute; use `transport_size` changes as proxy |
| Dashboard `TemplateNotFound: index.html` | Fixed | Dockerfile must `COPY templates/ templates/` explicitly |
| Dashboard metrics 500 error | Fixed | PostgreSQL `SUM()`/`AVG()` returns `Decimal` type; cast to `int()`/`float()` before `JSONResponse` |
| Dashboard horizontal scroll | Fixed | Use `table-layout: fixed` + `<colgroup>` percentage widths; set `overflow-x: hidden` |
| Kafka `NodeNotReadyError` from host | Fixed | Add `EXTERNAL` listener on port 9094 advertised as `localhost:9094` |

---

## 13. File Locations on Joel's Machine

```
~/dev/                          # Project root (all work happens here)
├── docker-compose.yml
├── models/mapper               # Trained model mapper (no .joblib extension)
├── pcaps/                      # PCAPs for evaluation
├── eval_results/               # Evaluation output CSVs
├── context/claude_code_context.md
├── services/                   # Docker service code
└── utils/
    ├── nfstream_model_eval.py  # Run from ~/dev/ to write output to eval_results/
    ├── test_kafka.py
    └── *.ipynb                 # Training notebook
```

**Key commands:**
```bash
# Docker stack
cd ~/dev
docker compose up --build              # Full stack
docker compose up --build dashboard    # Rebuild single service

# Model evaluation (run from project root so relative paths resolve correctly)
cd ~/dev
python3 utils/nfstream_model_eval.py     --benign  pcaps/benign.pcap     --malicious pcaps/malicious.pcap     --model   models/mapper     --output  eval_results/

# NFStream live capture (separate venv outside project, requires sudo)
sudo ~/dev/nfstream/.env/bin/python3 ~/dev/nfstream/nfs-main.py

# Kafka test
cd ~/dev
python3 utils/test_kafka.py
```