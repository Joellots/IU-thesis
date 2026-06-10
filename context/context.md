# XAI-SOAR Thesis Project — Context

**Author:** Joel C. Okore, MSc Computer Science, Innopolis University
**Supervisor:** Dr Andrei Petrovski
**Last updated:** 2026-06-10 (reflects state after the extensive NFStream evaluation)

Thesis: **"Explainable Machine Learning for Malicious Encrypted Traffic Detection and Trust-Aware SOAR Integration."**
Two deliverables: (1) a conference paper (USBEREIT 2026, accepted with minor corrections); (2) a proof-of-concept SOAR pipeline — a Docker Compose stack that operationalises the paper's models.

---

## Current Goal

Decide whether the existing classifier (`models/mapper`, trained on dpkt/scapy-extracted features from the Composed Encrypted Malicious Traffic Dataset) can be used in the live NFStream pipeline, or whether it must be **retrained on NFStream-extracted features**. The extensive evaluation is now done and **points to retraining** — see *What's Done* and *Next Steps*.

The downstream aim is an end-to-end demo: live/simulated encrypted traffic → NFStream features → inference → XAI → MITRE mapping → dashboard, with predictions that are actually correct on NFStream-extracted features.

---

## What's Done

- **Full 8-service Docker Compose stack is defined and individually working** (see *Docker Stack*). Pipeline code for all stages exists: producer, NFStream, inference, translator, dashboard.
- **Models present.** `models/mapper` (319 MB joblib dict) is the trained mapper used by inference and the evaluation. (Note the duplicate at repo root — see *Gotchas*.)
- **Training/replay dataset present.** `data/dataset.csv` (1.8 MB) — header columns are the NFStream model-feature names; consumed by the producer service.
- **PCAP corpus fetched.** `utils/fetch_pcaps.py` downloaded 14 PCAPs into `pcaps/benign/` (4× CTU-Normal) and `pcaps/malicious/` (10× CTU-13 + IoT-23). Manifest at `pcaps/download_manifest.json`. Sources overlap the original dataset's source benchmarks (MCFP/CTU-13, IoT-23).
- **Extensive evaluation complete.** Ran `utils/nfstream_model_eval.py` over all 14 PCAPs: **941,672 flows**. Results in `eval_results/extracted_features.csv` and `eval_results/per_flow_predictions.csv`.

### Evaluation result (the headline)

Aggregate (RandomForest `rf_best` on the 9 `BEST_FEATURES`):
- Accuracy **0.9478**, F1 macro **0.5540**, ROC-AUC **0.5676**
- Confusion: TP=888,698 FP=33,575 TN=3,833 FN=15,566

**Real interpretation — high sensitivity, near-zero specificity.** The model detects malicious traffic well (94–100% TP per malicious PCAP) but flags **80–99% of benign flows as malicious**. The aggregate accuracy is an artefact of a 24:1 malicious:benign class imbalance in the evaluation set. Per-PCAP false-positive rates on benign:

| Benign PCAP | flows | predicted malicious |
|---|---|---|
| `ctu_normal7_general_2013` | 2,663 | 98.6% |
| `ctu_normal20_win_2017_https` | 18,700 | 92.2% |
| `ctu_normal21_kali_2017` | 10,486 | 88.0% |
| `ctu_normal14_win_full_2017` | 5,559 | 80.6% |

This is **not** "everything zeroed / everything broken." It is a genuine feature-distribution shift: the benign decision boundary learned on dpkt/scapy features does not hold under NFStream semantics. Conclusion: **retrain on NFStream-extracted data.**

---

## In Progress (exactly where it stands)

- **NFStream live-capture service** (`services/nfstream/nfstream_producer.py`): code complete, builds, runs in PCAP and live (`source="any"`) modes, publishes to Kafka and writes CSV. Two extraction defects remain unfixed (see *Gotchas*) — these must be corrected **before** generating any retraining dataset, because they corrupt `median_Time_difference_between_packets_per_session` and zero out `std_time_to_live`.
- **Retraining decision:** made in principle (retrain). Not started. Attack-class scope drafted (C2 beaconing, HTTPS exfiltration, encrypted scan/recon) but not finalised.
- **TheHive/Cortex SOAR integration:** not in this repo. A separate `origin/soar` branch (commit `53be3d7` "SOAR base") holds the start of it; being implemented by co-author Isaac Womoakor. The translator service has **no** TheHive API code yet — Joel's integration point (publish HIGH-severity alerts → TheHive case) is still to be written.

---

## Next Steps (ordered)

1. **Fix the two NFStream extraction bugs** in `services/nfstream/nfstream_producer.py` (and the mirrored logic in `utils/nfstream_model_eval.py`):
   - `on_init` (line 88): change `flow.udps.piat_list = [packet.time]` → `[]` so the absolute epoch timestamp doesn't contaminate the median IAT.
   - Drop `std_time_to_live` from the feature set — it is structurally 0 under NFStream (min==max for fixed-TTL OSes). Replace with an NFStream-computable signal during retraining.
2. **Finalise attack classes** for the retraining corpus. Each must be: in the original source datasets, mappable to a TTP already in `feature_mitre_map.py`, lab-simulatable for end-to-end testing, and productive of non-zero NFStream features. Working set: **(a) encrypted C2 beaconing** (CTU-13 Neris/Virut PCAPs already downloaded), **(b) HTTPS exfiltration** (need to acquire/self-generate), **(c) encrypted scan/recon** (IoT-23 Mirai PCAPs already downloaded — cap at ≤10% of training flows).
3. **Build the NFStream-extracted training dataset** from PCAPs using the (fixed) `ExtendedFlowFeatures` plugin. Filter to bidirectional, multi-packet, port-443/TLS sessions; aim for 1:1–2:1 class balance at the flow level.
4. **Retrain** RF / XGBoost / EBM using `utils/usbereit-xai-for-encrypted-https-traffic-anomaly-detection-MAIN.ipynb` as the template; update `REALTIME_SAFE_FEATURES` / `BEST_FEATURES`; re-serialise `mapper`.
5. **Re-run** `utils/nfstream_model_eval.py` on a **balanced** hold-out to confirm benign specificity recovers (target benign F1 ≫ 0.13).
6. **Update `feature_mitre_map.py`** once the new `BEST_FEATURES` and SHAP rankings are known — *later-stage, do not start until step 5 confirms the new feature set.*
7. **Wire the TheHive API call** into `translator_service.py` for HIGH-severity alerts.

---

## Key Decisions & Rationale

| Decision | Choice | Rationale |
|---|---|---|
| Feature extraction tool | NFStream 6.6.0 | CICFlowMeter has known bugs; NFStream is reproducible and Python-native. Cite Aouini & Pekar 2022, *Computer Networks* 204:108719. |
| Packet capture — rejected | Argus | PCAP-replay jitter DSR yields `sintpkt=0.0` for all records — IAT computation broken in file-replay mode. |
| Model serialisation | joblib (file named `mapper`, no extension) | Faster/more reliable than pickle for sklearn/XGBoost. Load with `joblib.load("models/mapper")`. |
| Kafka image & mode | `apache/kafka:3.7.0`, KRaft (no Zookeeper) | Single-node broker; controller+broker roles in one container. |
| Kafka client | `kafka-python-ng==2.2.3` | `kafka-python` 2.0.2 broken on Python 3.12; this fork is the maintained replacement. |
| Kafka listeners | internal `kafka:9092` + external `localhost:9094` | NFStream uses `network_mode: host` and cannot reach the Docker bridge; it dials `localhost:9094`. |
| SOAR platform | TheHive + Cortex | Implemented separately by Isaac Womoakor on the `soar` branch. Joel owns only the translator→TheHive API interface. |
| Retraining (new) | Retrain on NFStream features | Extensive eval shows benign specificity collapses under the dpkt/scapy→NFStream distribution shift. |

---

## Gotchas / Things That Didn't Work

- **`piat_list` seeded with an absolute timestamp.** `on_init` does `piat_list = [packet.time]`; later packets append *relative* IATs. For a 2-packet flow the median ≈ epoch/2 → `median_Time_difference_between_packets_per_session` shows ~52-billion-ms values (≈48% of flows affected). **Must fix before retraining.**
- **`std_time_to_live` is structurally 0 (100% of flows).** NFStream exposes only flow-level `src2dst_min/max_ttl`; modern OSes use a fixed initial TTL so min==max → std=0. The earlier "derive TTL from flow-level attrs" fix was applied but cannot rescue *variance*. Drop the feature.
- **Evaluation class imbalance hides the real story.** 66% of eval flows come from one 625K-flow Mirai scan PCAP. Aggregate accuracy (0.95) looks fine; benign F1 (0.13) is the truth. Always evaluate on a balanced, bidirectional, multi-packet subset.
- **Scan/probe PCAPs are nearly all 1–3-packet unidirectional flows** → `backward_IAT`, `payload_changes`, `std_IP_packet_length` all 0. They're correctly classed as malicious but contribute nothing to the benign/malicious boundary and skew distributions. Cap their share of any training set.
- **CIC dataset server (`205.174.165.80`) has TLS cert hostname-mismatch** — WebFetch/automated download fails. Self-generating HTTPS-exfiltration PCAPs in the lab is the more reproducible path anyway.
- **TTL/window per-packet attributes don't exist on NFStream's NFPacket** (`ip_ttl`, `tcp_window`). TTL is derived from flow-level fields; TCP window is proxied from packet-size distribution — note the proxy means `*_TCP_windows_size_value` are on a different scale than the training data's true window values.
- **Two `mapper` files with different md5s:** `models/mapper` (319 MB, used everywhere) and an untracked `./mapper` (17 MB) at repo root. Use `models/mapper`; the root copy is a stray.

---

## Relevant Files (path → purpose)

**Pipeline services**
- `docker-compose.yml` — 8-service stack (kafka, nfstream, producer, inference, translator, postgres, dashboard, kafka-ui).
- `services/producer/producer.py` — streams `data/dataset.csv` rows to Kafka `raw_flows` (env: `DATASET_PATH`, `TOPIC`, `STREAM_DELAY_MS`, `LOOP`, `LABEL_COL`, `MALICIOUS_RATIO`).
- `services/nfstream/nfstream_producer.py` — live/PCAP capture → `ExtendedFlowFeatures` plugin → `NFSTREAM_TO_MODEL` mapping → Kafka `raw_flows` + CSV. Env: `KAFKA_BROKER`, `PCAP_FILE`, `CSV_FILE`, `BPF_FILTER`, `IDLE_TIMEOUT`, `ACTIVE_TIMEOUT`.
- `services/inference/inference_service.py` — loads `mapper`, consumes `raw_flows`, runs `explain_instance()`, publishes to `alerts`. **Uses `xgb_rt`/`rf_best`/`xxgb` on the 65-feature `REALTIME_SAFE_FEATURES`.**
- `services/inference/explain_instance.py` — two-tier XAI (Tier-1 EBM + XGBoost contributions always; Tier-2 SHAP + LIME when P≥0.80 or P∈[0.45,0.55]).
- `services/translator/translator_service.py` — consumes `alerts`, calls `translate()`, writes to PostgreSQL. (No TheHive code yet.)
- `services/translator/feature_mitre_map.py` — `FEATURE_MITRE_MAP` dict + `compute_severity()` + `translate()`. To be revised post-retraining.
- `services/dashboard/main.py` — FastAPI + Jinja2 + htmx analyst UI; `services/dashboard/schema.sql` is the PostgreSQL schema.

**Models & data**
- `models/mapper` — trained joblib dict: `rf_best`, `xgb_rt`, `xxgb`, `scaler_rt`, `scaler_best`, `REALTIME_SAFE_FEATURES` (65), `BEST_FEATURES` (9), `target_cols`.
- `data/dataset.csv` — producer replay source; columns are NFStream model-feature names.
- `pcaps/benign/`, `pcaps/malicious/` — 14 evaluation PCAPs; `pcaps/download_manifest.json` records source/size/TLS-priority.
- `eval_results/extracted_features.csv`, `eval_results/per_flow_predictions.csv` — latest extensive-eval outputs (941,672 flows).

**Utilities**
- `utils/fetch_pcaps.py` — catalogued PCAP downloader (CTU-13 / IoT-23 / CTU-Normal), TLS-priority filtering, resume, bz2 decompress. `--list`, `--dry-run`, `--category`, `--tls`, `--max-size-mb`, `--jobs`.
- `utils/nfstream_model_eval.py` — extract features from PCAPs and evaluate the mapper. `evaluate()` currently runs only `rf_best`/`BEST_FEATURES` (the `xgb_rt` line is commented out) and fills missing columns with 0.
- `utils/test_kafka.py` — Kafka connectivity check.
- `utils/usbereit-xai-for-encrypted-https-traffic-anomaly-detection-MAIN.ipynb` — training/SHAP notebook; template for retraining.

**`BEST_FEATURES` (9, current model)**
```
The_times_of_change_of_payload_per_session
max_Interval_of_arrival_time_of_backward_traffic
mean_Interval_of_arrival_time_of_backward_traffic
mean_Interval_of_arrival_time_of_forward_traffic
mean_TCP_windows_size_value
median_Time_difference_between_packets_per_session
std_Interval_of_arrival_time_of_backward_traffic
std_Length_of_IP_packets
std_time_to_live          # NOTE: structurally 0 under NFStream — drop on retrain
```

---

## How to Run and Test

All commands run from `~/dev/` so relative paths resolve.

```bash
# ── Docker stack ──────────────────────────────────────────────
docker compose up --build                 # full 8-service stack
docker compose up --build dashboard       # rebuild a single service
docker compose up kafka postgres dashboard # DB-only smoke path (no model needed)
# Dashboard UI: http://localhost:8080   |   Kafka UI: http://localhost:8081

# ── Model evaluation (PCAP subdirs, not single files) ─────────
python3 utils/nfstream_model_eval.py \
    --benign    pcaps/benign/*.pcap \
    --malicious pcaps/malicious/*.pcap \
    --model     models/mapper \
    --output    eval_results/
# Interpretation: F1 macro ≥0.99 great; 0.90–0.99 mild shift; <0.90 retrain.
# Watch benign precision/recall specifically — aggregate accuracy is misleading.

# ── Fetch / inspect PCAP corpus ───────────────────────────────
python3 utils/fetch_pcaps.py --list
python3 utils/fetch_pcaps.py --dry-run --tls high,medium
python3 utils/fetch_pcaps.py --category malicious --tls high --jobs 2

# ── NFStream live capture (separate venv, needs sudo) ─────────
sudo ~/dev/.env/bin/python3 services/nfstream/nfstream_producer.py
# or set PCAP_FILE=… to replay a capture instead of live interface

# ── Kafka connectivity check ──────────────────────────────────
python3 utils/test_kafka.py
```

---

## Docker Stack (reference)

8 services in `docker-compose.yml`. Network bridge is named `net`; Kafka in KRaft mode.

| Service | container_name | Role |
|---|---|---|
| kafka | `kafka` | KRaft broker; 9092 internal, 9094 external (host) |
| producer | `producer` | replays `data/dataset.csv` → `raw_flows` |
| nfstream | `xai_nfstream` | live/PCAP capture → features → `raw_flows` (`network_mode: host`) |
| inference | `inference` | mapper inference + XAI → `alerts` (cap 2 GB / 2 CPU) |
| translator | `translator` | XAI→MITRE, severity, → PostgreSQL |
| postgres | `postgres` | alert/explanation/decision store |
| dashboard | `dashboard` | FastAPI + htmx analyst UI (`:8080`) |
| kafka-ui | `kafka_ui` | dev-only Kafka inspector (`:8081`) |

---

## Source Dataset (reference)

**Composed Encrypted Malicious Traffic Dataset** — 117,627 sessions, ~50/50, composed from 5 public benchmarks: Malware Capture Facility Project (MCFP/CTU), CICIDS-2012, CIC-AndMal 2017, CICIDS-2017, UNSW-NS 2019. Original features extracted with dpkt/scapy-based tooling (≤15 packets/session, 113 features) — the source of the distribution shift vs NFStream.

---

## Thesis Writing Remaining

- SOAR chapter: architecture, XAI→MITRE translation design, pipeline eval metrics (latency, TTP accuracy, Tier-2 trigger rate), limitations.
- Related Work: cite Aouini & Pekar 2022 (NFStream).
- Conclusion: acknowledge single-dataset limitation, the feature-extractor distribution-shift finding, and the benign-specificity gap.
- Open questions for supervisor: is human evaluation of annotation quality expected for the SOAR module, or is automated TTP accuracy vs labels sufficient? Submission-deadline alignment?
