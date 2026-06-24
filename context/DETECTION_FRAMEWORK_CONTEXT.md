# Aegis Framework — Elaborate Project Context (Detection side)

**Purpose of this document.** A single, detailed reference describing the **detection half**
(Half A) of the Aegis thesis framework — its architecture, every processing stage, the
feature engineering, the dataset construction, the models, the explainability layer, and the
**headline contribution** (the validated feature → behavioural-class → MITRE ATT&CK mapping),
plus the design rationale and limitations. It is written to be fed to an LLM (Codex) as
grounding context for **writing the thesis report**, and to onboard any engineer/agent to the
detection codebase. It is the detection-side counterpart to
[`context_soar/SOAR_FRAMEWORK_CONTEXT.md`](../context_soar/SOAR_FRAMEWORK_CONTEXT.md); together
with [`SYSTEM_OVERVIEW.md`](SYSTEM_OVERVIEW.md) (the cross-half bridge) and
[`SOAR_WORKFLOW_SPEC.md`](SOAR_WORKFLOW_SPEC.md) (the authoritative response contract), the four
docs describe the whole framework.

> **Currency:** reflects the repository after retraining on NFStream features, the dataset
> rebuild with JA3, and the mapping validation going live (`fmm-2.0.0`). Inspect the cited
> files before quoting line-level detail — the code evolves. Today's anchor date: 2026-06.

> **Secrets:** no credentials live in the detection repo (`.gitignore` excludes `.env*`,
> `data/`, `models/`, `pcaps/*`). Never paste keys or the training CSV into the report.

---

## 0. Thesis framing

- **Title:** *Explainable Machine Learning for Malicious Encrypted Traffic Detection and
  Trust-Aware SOAR Integration.*
- **Author (detection + overall):** Joel C. Okore (MSc Computer Science, Innopolis University;
  supervisor Dr Andrei Petrovski). **SOAR module co-developed with** Isaac Womoakor on a
  separate machine/repo.
- **Two deliverables:** (1) a conference paper (USBEREIT 2026, accepted w/ minor corrections);
  (2) a proof-of-concept SOAR pipeline operationalising the models.
- **The headline scientific contribution** is on this (detection) side: a **validated
  feature → behavioural-class → MITRE ATT&CK technique mapping** (`fmm-2.0.0`), grounded by
  **four independent methods** (statistics + SHAP-binary + SHAP-3class + EBM-exact) with
  **90–100 % bootstrap stability** and **~87.5 % end-to-end TTP-assignment accuracy**. It
  converts opaque flow statistics into analyst-meaningful ATT&CK techniques *with a calibrated
  per-alert confidence*, which the SOAR half then consumes as a first-class trust signal.
- **The three core technical results are DONE:** (i) retrained NFStream-native classifier
  (F1 ≈ 0.97); (ii) the rebuilt, IOC-labelled encrypted-malware dataset; (iii) the validated,
  live mapping. The **operational PoC is also built and verified end-to-end**: the endpoint
  sensor/actuator bundle (Wazuh Active-Response), the React dashboard makeover, and the
  closed SOAR response loop — an analyst approving a gated **block** in the dashboard now drives
  a real nftables DROP on the target host (see §14). Remaining detection-side work is narrow:
  Phase-4 literature grounding of the mapping, and the thesis write-up.

---

## 1. System-level architecture (both halves)

Two halves on **two machines** meeting at **one durable contract** (the PostgreSQL `alerts`
table) plus a **thin Kafka trigger** for low-latency handoff. Half A (this repo) produces the
alert; Half B (the SOAR repo) consumes it.

```
HALF A — Detection pipeline (detection host 172.31.87.134, Joel)
  NFStream sensor/producer → Kafka(raw_flows) → Inference(+XAI) → Kafka(alerts) → Translator
        │ writes full enriched row
        ▼
   PostgreSQL `alerts`  ← SOURCE OF TRUTH (audit / replay / state)
        │ after commit, emits a thin pointer event
        ▼
   Kafka(`soar_alert_events`, event_type=alert.translated)
        │ trigger only (alert_id + routing metadata)
        ▼
HALF B — SOAR module (SOAR host 172.31.80.148, Joel + Isaac)
  soar_orchestrator → severity → Cortex+MISP enrich → §5 matrix → TheHive case
                    → §7.1 handoff → Shuffle (block / isolate / notify + approval gate)
```

The detection host **owns Postgres (:5432) and Kafka (:9094 external)**; the orchestrator reads
them cross-machine. Detection-side coordination duties: publish/firewall Postgres 5432 to the
SOAR host, and advertise Kafka's external listener as the **detection host IP** (not
`localhost`) via `KAFKA_EXTERNAL_ADVERTISED_HOST`, or remote consumers fail on a localhost
redirect. See `SYSTEM_OVERVIEW.md` for the contract field-by-field.

---

## 2. The detection pipeline — service-by-service

Eight services in `docker-compose.yml` (Kafka KRaft, bridge net `net`); a local
`docker-compose.sim.yml` override drives finite replay. The pipeline is operated with
`scripts/detctl.sh` (the detection-side counterpart to the SOAR `soarctl.sh`).

| Service | container | Role |
|---|---|---|
| **kafka** | `kafka` | `apache/kafka:3.7.0` KRaft broker; 9092 internal / 9094 external |
| **producer** | `producer` | replays a labelled CSV → `raw_flows` (dataset-replay path; `LABEL_COL=true_label`, `LOOP=true`) |
| **nfstream** | `xai_nfstream` | live/PCAP capture → features → `raw_flows` (`network_mode: host`) |
| **inference** | `inference` | loads `models/mapper`, two-tier inference + XAI → `alerts` |
| **translator** | `translator` | XAI→MITRE (`fmm-2.0.0`) + observables → PostgreSQL `alerts`, then emits the `alert.translated` Kafka trigger |
| **postgres** | `postgres` | the shared `alerts` store (the SOAR contract; 5432 published cross-machine) |
| **dashboard** | `dashboard` | FastAPI + htmx analyst UI (`:8080`) — slated for a React/TS makeover |
| **kafka-ui** | `kafka_ui` | dev Kafka inspector (`:8081`) |

### 2.1 Two ingress paths to `raw_flows`
- **`producer` (replay):** streams rows of a pre-built labelled CSV (`data/dataset.csv` or
  `data/training_dataset.csv`) as flow records, each `{flow_id (new uuid), true_label,
  features: row[feature_cols]}`. Knobs: `BATCH_SIZE`, `MALICIOUS_RATIO`, `STREAM_DELAY_MS`,
  `LOOP`. This is the deterministic path used for demos/eval (the SOAR side's live runs consume
  these). `docker-compose.sim.yml` overrides it to a **finite** batch (`LOOP=false`,
  `BATCH_SIZE`, `MALICIOUS_RATIO=0.7`) for a bounded, observable run.
- **`nfstream` (live):** captures a real interface (`network_mode: host`), extracts features
  with the same `ExtendedFlowFeatures` plugin, and publishes the same record shape — so
  inference/translator are identical regardless of ingress. This is the path the **endpoint
  sensor** (roadmap §14) generalises to a shippable remote sensor.

### 2.2 Flow record → alert
`inference` consumes `raw_flows`, selects the model features, runs the classifier(s), produces
XAI attributions, and publishes one or more rows to the `alerts` Kafka topic (one per
model/tier; the primary row is `model=XGBoost, tier=fast`). `translator` consumes `alerts`,
calls `feature_mitre_map.translate()`, extracts observables, writes the enriched row to
PostgreSQL, and — **only after the insert commits** — publishes the thin `alert.translated`
pointer event. Postgres-first guarantees the source of truth exists before SOAR is triggered.

---

## 3. NFStream feature extraction (the sensor foundation)

**Why NFStream 6.6.0:** reproducible, Python-native, actively maintained; cite **Aouini & Pekar
2022, *Computer Networks* 204:108719**. Configured `statistical_analysis=True`,
`n_dissections=20` (deep protocol dissection, needed for TLS app-name + JA3). A custom
`NFPlugin`, **`ExtendedFlowFeatures`**, computes the per-session statistical features the model
expects; a `NFSTREAM_TO_MODEL` dict renames NFStream attributes to the model's feature names.
`services/nfstream/nfstream_producer.py`.

### 3.1 The feature set — 29 `REALTIME_SAFE_FEATURES`
Per-flow statistics over packet lengths, TCP payload lengths, TCP window sizes, IP packet
lengths, and inter-arrival/inter-packet timing (mean/std/min/max/median aggregates), plus
per-session change counts. `BEST_FEATURES` (9) is the TCP-payload-length + window/payload-change
centric subset used by the high-precision model:
```
max/std/min/mean_Length_of_TCP_payload, Length_of_TCP_payload,
Change_values_of_TCP_windows_length_per_session,
The_times_of_change_of_payload_per_session,
max_Interval_of_arrival_time_of_forward_traffic,
max_Time_difference_between_packets_per_session
```

### 3.2 TLS fingerprints (JA3/JA3S)
NFStream 6.6.0 exposes `client_fingerprint` (JA3) and `server_fingerprint` (JA3S). The producer
emits them as context fields; they propagate through inference → translator and become a
`{type: "ja3", value, role}` **observable** + a stamped column, so the SOAR side can correlate
in MISP (`ja3-fingerprint-md5`). This was wired end-to-end and the dataset rebuilt to carry JA3.

### 3.3 Bugs found & fixed (honest methodology notes for the thesis)
- **All 4 TTL features are dead.** NFStream 6.6.0 exposes **no** TTL attribute
  (`[a for a in dir(flow) if 'ttl' in a] == []`). The four TTL features were dropped → the
  feature count is **29, not 33**. (A real "extractor capability" finding, not a config error.)
- **`piat_list` epoch bug [FIXED].** `on_init` seeded the list with the packet's **absolute**
  timestamp, so `median_piat_ms` came out ~5 × 10¹⁰ ms (epoch-scale). Fixed by seeding `[]` and
  guarding the median on `len >= 1`; verified the max dropped 7.7 × 10¹¹ → ~4081 ms and 99.5 %
  of values became non-zero. *This bug existed in the original extractor and silently poisoned a
  timing feature — worth a sentence in Methods.*
- **Argus rejected.** Earlier Argus-based extraction produced `sintpkt=0.0` (broken IAT) under
  PCAP **file-replay** mode (replay jitter / DSR), so timing features were unusable; NFStream
  was adopted instead.

---

## 4. The dataset (the sourcing odyssey + labelling methodology)

`data/training_dataset.csv` — **11,822 flows, balanced 1:1**, drawn from **~25 real Windows
malware families (2022–2025)** captured by **malware-traffic-analysis.net (MTA)** over TLS, plus
benign traffic (CTU-Normal + the malware captures' own host background). Built by
`utils/build_training_dataset.py` (+ `utils/fetch_mta_pcaps.py`). The dataset is gitignored;
`pcaps/mta/ioc_manifest.json` is the only tracked artefact and **pins** the dataset (the IOCs
that define the labels).

### 4.1 Why MTA / why not the obvious alternatives
- The original benchmark inspiration is the **Composed Encrypted Malicious Traffic Dataset**;
  the goal was publicly-available encrypted (HTTPS/TLS) malicious captures resembling it.
- **CIC-AndMal rejected:** Android platform → platform mismatch with a Windows-malware target,
  and it would **confound** the model (it would learn "Android-ness", not maliciousness).
- **Real encrypted *malicious* flows are sparse in public data.** Infection captures are
  overwhelmingly the victim host's **benign background** plus a *handful* of C2 flows; HTTPS
  **exfil** is especially rare (~5–10 flows/capture). CICIDS yielded ~36 encrypted-malicious
  flows; CSE-CIC-IDS2018 is 50 GB for little encrypted-malicious yield. **Hence aggregation of
  86 MTA captures** to assemble enough real malicious TLS flows — and hence the *finding* that
  **exfil is a minority class**. This is a defensible thesis observation, not a tooling gap.

### 4.2 Labelling — per-5-tuple IOC matching (and its caveat)
Mixed captures are labelled **per flow**: a flow is malicious **iff** its 5-tuple matches a
capture's **published IOCs** (malicious IP / SNI), via `CAPTURE_MANIFEST` + the auto-loaded
`pcaps/mta/ioc_manifest.json` (strategies: `all_malicious` / `all_benign` / `ioc` /
`cicids_csv`). `utils/fetch_mta_pcaps.py` batch-downloads captures by date and auto-parses the
published IOCs (password `infected_YYYYMMDD`) into the manifest. **Caveat (state it):** labelling
is **IOC-completeness-dependent** — a C2 endpoint missing from the published IOC file is
mislabelled benign. Benign sourced from the captures' own host background avoids a
**capture-origin confound** (the model can't cheat by learning "which pcap this came from").

---

## 5. The models (two-tier, retrained NFStream-native)

`models/mapper` is a **joblib dict** (`joblib.load("models/mapper")`, no file extension, ≈50 MB)
holding: `rf_best` (RandomForest), `xgb_rt` (XGBoost, the realtime/fast tier), `xxgb`
(`ExplainableBoostingClassifier`, EBM), `scaler_rt`, `scaler_best`, `REALTIME_SAFE_FEATURES`
(29), `BEST_FEATURES` (9), `target_cols`. Notebook:
`model_training/retrain_nfstream_model.ipynb` (clean 18-cell retraining template; the original
research notebook `usbereit-xai-MAIN-reference.ipynb` is kept untouched as reference).

### 5.1 The distribution-shift result (a core Methods finding)
The original `models/mapper` was trained on **dpkt/scapy/CICFlowMeter**-style features. Evaluated
against **NFStream**-generated features it collapsed to **~0.52 F1** — an extractor-induced
**distribution shift** (the same conceptual feature is computed differently by a different tool).
**Retraining on NFStream features solved it: in-domain held-out F1 ≈ 0.97.** This is the
justification for the whole "retrain on the deployment extractor" step.

### 5.2 Two-tier inference
A **fast tier** (XGBoost `xgb_rt` on the 9 `BEST_FEATURES`, the primary contract row) for
low-latency screening, and a **fuller tier** (RF / EBM on the 29 features) for higher-fidelity
scoring/explanation. The EBM is also a glass-box model whose exact term contributions serve as
one of the four mapping-validation methods (§7).

### 5.3 Independent cross-era evaluation
`utils/nfstream_model_eval.py --encrypted-only --balance` on **legacy out-of-distribution**
captures: **ROC-AUC 0.977, F1-macro 0.80, malicious precision 0.99, FP rate ~0.5 %.** The
old over-flagging is gone and the retrained model generalises across capture eras. The
`--encrypted-only` filter selects TLS flows by **protocol detection** (NFStream
`application_name ~ TLS/SSL/QUIC/DTLS`) ∪ encrypted ports {443,465,993,995,853} — port-only
missed ~⅔ of malicious TLS on non-standard ports.

---

## 6. The XAI layer

`services/inference/explain_instance.py`. For each flagged flow it produces a ranked
`top_k_json` of feature attributions `[{feature, value, contribution, direction}]`, where
`direction` ∈ {positive, negative} = whether the feature **pushed toward malicious**. Three
explainers triangulate:
- **SHAP** `TreeExplainer` for the tree models (note: shap 0.45 multiclass returns a 3-D array
  `(n, feat, classes)` → index `sv[:,:,k]`).
- **LIME** local surrogate.
- **EBM exact** term contributions (glass-box, no approximation).

`top_k_json` is the **only XAI artefact that crosses the contract** — the translator's mapping
and the SOAR case's "Top Evidence" both read it. The mapping (§7) deliberately consumes **only
positive-direction** (malicious-pushing) entries as evidence.

---

## 7. THE HEADLINE — feature → class → TTP mapping (`fmm-2.0.0`)

`services/translator/feature_mitre_map.py`. This is the thesis's core contribution: a principled,
**empirically validated** map from opaque flow statistics to MITRE ATT&CK techniques, carrying a
**calibrated per-alert confidence**, which the SOAR side uses as a trust gate.

### 7.1 Structure (three stages)
1. **`FEATURE_CLASS_MAP`** — each validated feature votes for **one** behavioural class with a
   value-**direction** (`high`/`low`) and a **confidence** = its bootstrap top-k stability (0–1).
   14 features across two classes:
   - **C2 beaconing** (HIGH): `mean/std/max_Length_of_TCP_payload` (1.00),
     `mean/std/median_TCP_windows_size_value` (1.00), `mean/std_Length_of_IP_packets`
     (1.00/0.98).
   - **Exfiltration** (LOW timing): `mean/std/max_Interval_of_arrival_time_of_backward_traffic`
     (1.00/1.00/0.90), `mean/std_..._forward_traffic` (1.00/0.96),
     `mean_Time_difference_between_packets_per_session` (1.00).
2. **`CLASS_TTP_MAP`** — class → ATT&CK techniques (top-level + sub-technique):
   - `c2_beaconing` → **T1071** (Application Layer Protocol), **T1071.001** (Web Protocols),
     **T1573** (Encrypted Channel); tactic *Command and Control*.
   - `exfil` → **T1041** (Exfiltration Over C2 Channel), **T1048.002** (Exfil Over Asymmetric
     Encrypted Non-C2 Protocol); tactic *Exfiltration*.
   - Each has a human `summary` and a `citation: None` placeholder (Phase 4 literature grounding).
3. **`translate(alert)`** — aggregates the malicious-pushing top-k features into a per-class
   weighted vote (`weight = feature.confidence × |contribution|`), picks the dominant class,
   assigns its TTPs, and computes `mapping_confidence` = contribution-weighted mean stability of
   the matched evidence.

### 7.2 The ambiguity-margin gate (precision protection)
`CLASS_MARGIN` (env `MAPPING_CLASS_MARGIN`, default **0.60**). The winning class's **dominance**
= its vote / total vote. If `dominance ≥ margin` → `mapping_status="mapped"` (full confidence);
else the evidence is split between C2 and exfil, so the TTP is asserted only **tentatively**
(`unmapped_heuristic`, confidence scaled by dominance). `0.5` turns the gate off (pure argmax).
This protects precision on the **overlapping/minority** class (exfil). Malicious flows with no
validated-feature evidence fall to a keyword heuristic (`unmapped_heuristic`, conf 0.30) or a
last-resort fallback `T1071` (`unmapped`, conf 0.0) for observability.

### 7.3 The output contract (what `translate()` returns)
`mitre_ttps`, `mitre_names`, `severity`(1/2/3, advisory), `severity_label`, `annotation`
(SOC-readable), `n_ttps_matched`, **`mapping_status`** (`mapped`/`unmapped_heuristic`/`unmapped`),
**`mapping_confidence`** (0–1), `mapping_version` (`fmm-2.0.0`), `mapping_reason`. Severity here
is **advisory** — the SOAR orchestrator re-derives it from `pred_proba` (it is the single source
of truth).

### 7.4 The validation (why it's "ground truth" grade)
`model_training/feature_mitre_validation.ipynb`. Each signature is confirmed by **four
independent methods that agree**: descriptive **statistics**, **SHAP (binary)**, **SHAP
(3-class)**, and **EBM exact** contributions — with **90–100 % bootstrap top-k stability**
(the stability *is* the per-feature confidence baked into `FEATURE_CLASS_MAP`). The validated
signatures:
- **C2 beaconing = HIGH** TCP-payload length, TCP-window size, IP-packet length (stability
  0.98–1.00) — large, low-variance encrypted payloads + programmatic TCP windows, i.e. automated
  beaconing, not human HTTPS browsing.
- **Exfiltration = LOW** inter-arrival / inter-packet timing (0.90–1.00) — rapid, regular bulk
  upload.

**End-to-end (Phase 6):** replaying labelled flows through the live `translate()` gave
**~87.5 % TTP-assignment accuracy** vs true labels — **C2 F1 0.93** (≈0.99 confidence); **exfil
weaker** (documented limitation: minority class + signature overlap with C2). **Bonus result:**
the validation **caught a wrong link in the prior hand-asserted map** — *low-IAT* had been
attributed to C2 when it is actually **exfil's** signature. That correction is itself evidence
the data-driven method beats hand assertion.

---

## 8. The translator & the contract (what detection writes)

`services/translator/translator_service.py` consumes `alerts`, runs `translate()`, extracts
observables, writes the enriched PostgreSQL `alerts` row (`services/dashboard/schema.sql`), then
emits the `alert.translated` pointer.

### 8.1 Observable extraction
`extract_observables()` pattern-matches the flow's context fields into
`[{type, value, role: src|dst}]`: `ip`, `domain` (SNI), `url`, and **`ja3`** (regex on
`fingerprint` keys; `client`→src, `server`→dst). A null-ish guard skips empty/`nan`/`none`/`0`
strings (a real bug surfaced in simulation: SNI-less flows had been emitting
`{type:domain,value:"nan"}`). These observables are the SOAR side's Cortex/MISP routing keys and
the block targets.

### 8.2 The `alerts` table — the seam
One row per flagged flow; the SOAR orchestrator reads it. Key columns: `flow_id, model, tier,
pred_label, pred_proba, top_k_json, mitre_ttps, mitre_names, severity, annotation, observables
(JSONB), mapping_confidence/_version/_status/_reason, n_ttps_matched, translated_ts`, plus
analyst Step-6 fields (`analyst_decision/_ts/_note`, `explanation_useful`,
`flag_for_retraining`). **`pred_proba` IS the SOAR's `model_confidence`.** The schema is the
**detection-owned** contract; additive/nullable migrations keep replay rows valid. See
`SYSTEM_OVERVIEW.md §1` and `SOAR_FRAMEWORK_CONTEXT.md §2` for the full field semantics.

---

## 9. Detection scope — why only C2 + exfil (a documented finding)

In **TLS** traffic, malicious behaviour with a distinctive flow signature reduces to exactly two
classes: **C2 beaconing** and **exfiltration**. The other ATT&CK families were **deliberately
dropped** and the reasoning is a thesis result, not an omission:
- **Scan / lateral movement** run over **unencrypted** protocols → outside an *encrypted*-traffic
  detector's remit (a probe found **1 / 7209** east-west flows was TLS).
- **Ransomware-impact** is largely **non-network** (local file encryption) — no distinctive flow
  signature.
So the encrypted-traffic detector is scoped to the two behaviours TLS can actually reveal, and
the mapping has exactly those two classes.

---

## 10. Configuration reference (detection side, env-var names only)

| Group | Vars |
|---|---|
| **Producer (replay)** | `DATASET_PATH`, `LABEL_COL` (= `true_label`), `BATCH_SIZE`, `MALICIOUS_RATIO`, `STREAM_DELAY_MS`, `LOOP`, `TOPIC`, `KAFKA_BROKER` |
| **NFStream sensor** | capture interface, `KAFKA_BROKER`, `TOPIC` (`raw_flows`), `n_dissections`, `statistical_analysis` |
| **Inference** | `INPUT_TOPIC` (`raw_flows`), `OUTPUT_TOPIC` (`alerts`), model path (`models/mapper`) |
| **Translator** | `INPUT_TOPIC` (`alerts`), `DATABASE_URL`, `SOAR_ALERT_EVENTS_TOPIC` (`soar_alert_events`), **`MAPPING_CLASS_MARGIN`** (0.60) |
| **Kafka (cross-machine)** | `KAFKA_EXTERNAL_ADVERTISED_HOST` / `KAFKA_ADVERTISED_LISTENERS` (advertise the **detection host IP** on :9094) |

---

## 11. Deployment & operations

- **`scripts/detctl.sh`** is the **single control surface** for the whole detection engine +
  the endpoint agent (the operator reference is [`CHEATSHEET.md`](../CHEATSHEET.md)):
  - **stack** — `up`/`down`/`reset`/`build`/`restart`/`status`/`logs`/`config`;
  - **simulation** — `sim [AGENT_ID]` (finite replay; an `AGENT_ID` stamps this host's identity
    = *replay-as-endpoint*), `replay` (continuous);
  - **inspect** — `alerts` (counts, mapping, JA3, endpoint-identity, avg conf), `approvals`
    (pending `soar_pending_approvals`), `psql`;
  - **data & model** — `dataset` / `eval` / `fetch-pcaps` / `fetch-mta` (host Python wrappers);
  - **endpoint agent** — `agent status|blocks|ar-log|unblock <ip>|unisolate|install|uninstall|package`.
  Default `up` = the always-on consumers (kafka, postgres, inference, translator, dashboard,
  dashboard-web); the producer is the on-demand replay source.
- **Stack:** `docker compose up --build` (dashboard :8080, kafka-ui :8081, Kafka ext :9094).
- **Retrain / evaluate / rebuild dataset / fetch captures** (from `~/dev/`,
  `source .env/bin/activate`):
  ```bash
  python3 utils/nfstream_model_eval.py --benign pcaps/benign/*.pcap \
      --malicious pcaps/malicious/*.pcap --model models/mapper \
      --output /tmp/eval/ --encrypted-only --balance --min-packets 4
  python3 utils/build_training_dataset.py --output data/ --min-packets 4 --encrypted-only --balance
  python3 utils/fetch_mta_pcaps.py --out pcaps/mta/ --jobs 4
  ```
- **Cross-machine:** publish/firewall Postgres 5432 to the SOAR host; advertise Kafka's external
  listener as the detection host IP; the orchestrator's `DATABASE_URL`/`KAFKA_BROKER` point here.

---

## 12. Design decisions & rationale (for the thesis discussion)

| Decision | Choice | Rationale |
|---|---|---|
| Feature extractor | **NFStream 6.6.0** | reproducible, Python-native (Aouini & Pekar 2022); Argus rejected (file-replay broke IAT → `sintpkt=0.0`) |
| Retrain on the deployment extractor | done | the dpkt/scapy-trained mapper collapsed (0.52 F1) under the NFStream distribution shift; retrained = 0.97 |
| Detection scope | **C2 + exfil only** | the only TLS-observable malicious behaviours; scan/lateral are unencrypted, ransomware-impact is non-network (1/7209 east-west flows was TLS) |
| Training data | real Windows malware (MTA) | CIC-AndMal (Android) rejected — platform mismatch + confound; MTA = Windows + real HTTPS-C2 |
| Benign source | captures' own host background + CTU-Normal | avoids a capture-origin confound |
| Encrypted filter | TLS-protocol detection | catches TLS on non-standard ports — port-only missed ~⅔ of malicious |
| Mapping structure | **feature → class → TTP** | aggregates XAI evidence into a behavioural class, then assigns TTPs; carries a per-alert confidence |
| Mapping confidence | **= bootstrap top-k stability** | a principled, calibrated reliability the SOAR trust gate can key on |
| Severity ownership | translator advisory; **SOAR authoritative** | one source of truth (orchestrator re-derives from `pred_proba`) |
| Model serialisation | joblib dict `models/mapper` | single artefact carrying models + scalers + feature lists |

---

## 13. Current state, limitations & known gaps (be honest in the report)

- **Three core results done:** retrained NFStream-native model (F1 0.97), rebuilt IOC-labelled
  encrypted-malware dataset (with JA3), validated + live mapping (`fmm-2.0.0`).
- **Exfiltration mapping is weaker than C2** — minority class + signature overlap; the end-to-end
  ~87.5 % is dominated by strong C2 (F1 0.93) and weaker exfil. State it plainly.
- **Labelling is IOC-completeness-dependent** — a C2 endpoint absent from a capture's published
  IOCs is mislabelled benign. A bounded, defensible caveat.
- **Phase-4 literature grounding is outstanding** — `citation` placeholders in `CLASS_TTP_MAP`;
  the *empirical* validation is complete, this only adds prior-work citations per link.
- **Single-deployment scope** — one lab topology; generalisation across networks is future work.
- **Two analyst UIs run in parallel** — the original FastAPI+htmx dashboard (`:8080`) and the new
  React/TS SPA (`:3000`, `services/dashboard-web`) over the same FastAPI JSON API.

---

## 14. Operational PoC — built & verified (design + status)

> **STATUS (2026-06):** §14.1–14.3 are **BUILT and verified end-to-end**; the sections below are
> the design description, now realised. The closed loop works: an analyst approving a gated
> **block** in the dashboard drives a real **nftables DROP** on the target host (Wazuh agent),
> visible in `active-responses.log`. **14.4 (Phase-4 literature grounding)** is the only roadmap
> item left. Two implementation findings worth a sentence in the report's limitations:
> (a) Wazuh `execd` keeps the AR script's stdin pipe open, so the scripts must read **one line**
> (`read -r`), not `cat` to EOF, or they hang and block all further AR; (b) `isolate` on a host
> that *also* runs the container stack must spare the Docker bridge interfaces, else it severs
> inter-container traffic — both handled in `endpoint_agent/active-response/lib/soar-ar-common.sh`.

### 14.1 Endpoint agent bundle — sensor + actuator (closing the SOAR loop on the endpoint) — DONE
A shippable bundle that turns any experimentation VM/host into both a **SENSOR** (feeds this
pipeline) and an **ACTUATOR** (executes SOAR-ordered response), Wazuh-active-response style. The
*same* endpoint that generates a flow is where a block/isolate is enforced.
- **NFStream sensor** reused from `services/nfstream` against a configurable interface +
A shippable bundle that turns any experimentation VM/host into both a **SENSOR** (feeds this
pipeline) and an **ACTUATOR** (executes SOAR-ordered response), Wazuh-active-response style. The
*same* endpoint that generates a flow is where a block/isolate is enforced.
- **NFStream sensor** reused from `services/nfstream` against a configurable interface +
  `KAFKA_BROKER`, publishing to the same `raw_flows` topic (pipeline unchanged).
- **Endpoint identity in the contract (the key new field):** stamp a stable `agent_id` (the
  Wazuh agent id) + `host_id`/host IP onto every emitted flow, propagate through
  inference/translator, and add **nullable** column(s) to `schema.sql`. This populates the SOAR
  §7.1 payload's `endpoint:{host_id, ip, source}` so the orchestrator can route a block to the
  right Wazuh agent. Backward-compatible: existing replay/producer rows leave it null.
- **Wazuh agent** (4.14.x to match the SOAR-side manager-only deployment) enrolled to the SOAR
  host (enrollment :1515, comms :1516, API :55000), with a predictable agent name = `host_id`.
- **Four vetted Active-Response executables** — `soar-block` / `soar-unblock` / `soar-isolate`
  / `soar-unisolate` — the allowlisted safety centerpiece: strict IP validation, RFC1918/own-
  infra denylist (never block manager/gateway/loopback), reversible with TTL, isolate keeps the
  manager channel alive, every action logged. The orchestrator triggers them on demand via
  `PUT /active-response` (the API call is the trigger; no Wazuh rule involved).
- **Packaging:** one-command installer (shell / Docker / Ansible) parametrized by
  `MANAGER_HOST`, enrollment port/password, agent name, Kafka broker, capture interface; +
  teardown + README. *(Manager-side AR registration and the orchestrator's dispatcher are
  SOAR-side.)*

### 14.2 Dashboard makeover (React/TypeScript)
Replace the FastAPI+htmx UI with a modern interactive SPA: **keep FastAPI as a JSON API**
(`/alerts`, `/approvals`, `/feedback`, `/metrics`, + a WebSocket live feed); **React + TS +
Tailwind/shadcn** frontend. Features: live alert feed, alert-detail **XAI viz** (feature
contributions + the validated `feature→TTP` mapping + JA3/observables + intel verdict), a MITRE
ATT&CK matrix highlight, the **approval queue**, and the **Step-6 feedback** form (writing
`analyst_decision`/`explanation_useful`/`flag_for_retraining`). Pairs with the automated-response
work so the UI is built against real endpoints.

### 14.3 Automated response integration (detection-side seam)
The detection-owned surface for the SOAR action loop: the `soar_status` write-back on alerts
(notified/case_created/blocked/pending_approval) the dashboard renders, the approval-queue
endpoints, and the Step-6 feedback that retires the orchestrator's interim feedback table. SOAR
owns Shuffle + the orchestrator dispatcher; detection owns the dashboard + contract fields.

### 14.4 Phase-4 literature grounding
Add prior-work citations to each `CLASS_TTP_MAP` link (the `citation` placeholders).

---

## 15. File / module map (detection)

| File | Responsibility |
|---|---|
| `services/nfstream/nfstream_producer.py` | live/PCAP capture → `ExtendedFlowFeatures` plugin → `NFSTREAM_TO_MODEL` → `raw_flows` (+CSV); JA3 context fields; TTL/piat fixes |
| `services/inference/inference_service.py` (+ `explain_instance.py`) | load `models/mapper`, two-tier inference, SHAP/LIME/EBM XAI, publish `alerts` with `top_k_json` + context |
| `services/translator/translator_service.py` | `translate()` + `extract_observables()` → PostgreSQL `alerts`, then `alert.translated` Kafka trigger |
| **`services/translator/feature_mitre_map.py`** | **`fmm-2.0.0`** — `FEATURE_CLASS_MAP` + `CLASS_TTP_MAP` + `translate()` (class voting + margin gate) + `compute_severity()` (advisory) |
| `services/dashboard/main.py` + `schema.sql` | analyst UI + the shared `alerts` schema (the contract) |
| `models/mapper` | retrained joblib dict (29 `REALTIME_SAFE_FEATURES`, 9 `BEST_FEATURES`, RF/XGB/EBM + scalers) |
| `data/training_dataset.csv` | labelled training set (gitignored); `data/dataset.csv` = replay source |
| `pcaps/mta/ioc_manifest.json` | pins the dataset (only tracked file under `pcaps/`) |
| `utils/build_training_dataset.py` | builds the labelled NFStream training set (manifest + IOC labelling) |
| `utils/fetch_mta_pcaps.py` | batch-downloads MTA captures by date, auto-parses IOCs → manifest |
| `utils/fetch_pcaps.py` | catalogued PCAP downloader (CTU-13/IoT-23/CTU-Normal/ransomware) |
| `utils/nfstream_model_eval.py` | evaluate the mapper on PCAPs (`--encrypted-only --balance …`) |
| `model_training/retrain_nfstream_model.ipynb` | clean retraining notebook |
| `model_training/feature_mitre_validation.ipynb` | mapping validation (stats + SHAP×2 + EBM + bootstrap + end-to-end) |
| `model_training/usbereit-xai-MAIN-reference.ipynb` | original research notebook (reference, untouched) |
| `scripts/detctl.sh` | detection-stack control tool |
| `docker-compose.yml` / `docker-compose.sim.yml` | 8-service stack / finite-replay override |

---

## 16. Glossary / key identifiers

- **`mapping_status`** ∈ `mapped` / `unmapped_heuristic` / `unmapped`; **`mapping_confidence`**
  ∈ [0,1] = bootstrap top-k stability (`fmm-2.0.0`).
- **`MAPPING_CLASS_MARGIN`** — ambiguity gate, default 0.60 (dominance threshold for `mapped`).
- **`pred_proba` ≡ `model_confidence`** (the SOAR side's name; no rename).
- **Severity** — translator advisory (≥0.85 HIGH); SOAR authoritative (High ≥0.90 / Med 0.70–0.89
  / Low <0.70 from `pred_proba`).
- **Classes → TTPs** — `c2_beaconing` → T1071/T1071.001/T1573; `exfil` → T1041/T1048.002.
- **`REALTIME_SAFE_FEATURES`** (29) / **`BEST_FEATURES`** (9) — the model's feature sets.
- **Hosts** — detection `172.31.87.134` (Postgres :5432, Kafka :9094); SOAR `172.31.80.148`.
- **Trigger** — `alert.translated` event on `soar_alert_events` (Postgres = source of truth).

---

# Appendix A — Methodology & decision narrative (the full path, incl. dead-ends)

*This appendix is the chronological "flow of thought" behind each result — the dead-ends, the
decisions and their rationale, and the exact figures — written so the thesis Methods/Results
chapters have no blind spots. The numbered sections above are the structured reference; this is
the story that produced them.*

## A.1 Point of departure — and the distribution-shift discovery

The project inherited a classifier from the prior conference work (USBEREIT 2026), trained on
features extracted with **dpkt/scapy/CICFlowMeter**-style tooling. The deployment goal was a
*live* pipeline, for which features must be computed from real/replayed traffic by a streaming
extractor. Evaluated against **NFStream**-generated features, the inherited model **collapsed to
≈0.52 macro-F1** (from a held-out ~0.9 in-tool). The first instinct — "the model is broken" — was
wrong. A careful diagnosis (on a balanced 32,654-flow set after the extraction fixes below)
decomposed the failure:

- **ROC-AUC was still 0.806** → the model retained discriminative signal; it was *mis-thresholded*,
  not blind.
- A **decision-threshold sweep** recovered most of the loss: 0.5 → macro-F1 0.52; **0.70 → 0.735
  (optimal)**; ≥0.9 collapsed (no flow scored ≥0.9 under the new extractor). So **recalibration
  alone recovers ~0.74**; the residual gap to ~0.9 is genuine **covariate/distribution shift** —
  the *same* conceptual feature (e.g. mean packet length) is computed differently by a different
  tool, so the learned decision surface no longer fits.

This **calibration-vs-shift decomposition is itself a reportable result**, and it justified the
central methodological decision: **retrain natively on the deployment extractor (NFStream)**
rather than patch thresholds. (Baselines preserved under `eval_results_fixed/`.)

## A.2 Feature extractor — NFStream, and why not Argus

**NFStream 6.6.0** was chosen as the streaming extractor: Python-native, reproducible, actively
maintained, and able to replay PCAPs *and* capture live with identical feature semantics (cite
**Aouini & Pekar, 2022, *Computer Networks* 204:108719**). It runs with `statistical_analysis=True`
and `n_dissections=20` (deep nDPI dissection — needed for the TLS application-name filter and JA3),
plus a custom `ExtendedFlowFeatures` NFPlugin computing the per-session aggregates the model
expects, and a `NFSTREAM_TO_MODEL` rename map.

**Argus was trialled and rejected:** under PCAP **file-replay**, Argus emitted `sintpkt = 0.0`
(broken inter-arrival timing) because replay jitter / DSR corrupts its timing model — fatal for a
feature family the model leans on.

**Two extractor bugs were found and fixed during validation** (honest Methods notes):
1. **`piat_list` epoch-seeding bug.** `on_init` seeded the inter-arrival list with the packet's
   *absolute* epoch timestamp, so `median_Time_difference…` came out ~5×10¹⁰ ms (epoch-scale) and
   silently poisoned a timing feature. Fixed by seeding `[]` and guarding the median on `len≥1`;
   verified the max dropped 7.7×10¹¹ → ~4081 ms and 99.5 % of values became non-zero.
2. **TTL features are structurally dead.** NFStream 6.6.0 exposes **no per-packet TTL**
   (`[a for a in dir(flow) if 'ttl' in a] == []`); only flow-level min/max, which are equal for
   fixed-TTL OSes — so `std_time_to_live` was **100 % zero** across the 941k-flow evaluation. All
   four TTL features were dropped → **the model trains on 29 features, not 33**.

## A.3 The dataset sourcing odyssey (the hardest part)

**Target.** Build an *encrypted* (TLS/HTTPS) malicious-vs-benign flow dataset resembling the
**Composed Encrypted Malicious Traffic Dataset** (Mendeley `ztyk4h3v6s`; method paper arXiv
2203.09332): Zeek/Bro detects TLS/SSL → keep only encrypted sessions → inherit source labels →
first ~15 packets/session → statistical features.

**The core empirical finding: real encrypted-*malicious* flows are sparse in public data.**
A succession of sources was tried and rejected, each a documented dead-end:
- **CICIDS-2017 (Thursday)** — obtained the 7.8 GB capture via the token-gated CIC portal
  (`cicresearch.ca`, browser `Cookie: Token=…` on `download.php`), but the *Infiltration* scenario
  is only **36 malicious flows** among ~288k benign — too few to train (kept as ~456k benign TLS
  flows + 36 infiltration flows for an external test set).
- **CSE-CIC-IDS2018** — has ~62k infiltration flows but only inside ~**50 GB** daily PCAP zips on
  public S3 (no awscli on the box; impractical).
- **malware-traffic-analysis.net stealers** — 3–22 flows/pcap, and StealC/RedLine exfiltrate over
  **HTTP, not HTTPS**; only Lumma used HTTPS (~4–5 C2 flows/pcap).
- **CIC-AndMal-2017** — this is where the *Composed* dataset got its encrypted-malicious volume
  (Android apps default to TLS). It was **rejected on principle**: Android is a **platform
  mismatch** with a Windows/Linux deployment, and pairing Android-malware with Windows-benign
  would **confound** the model into learning *platform*, not *maliciousness*. Sandbox-generation
  and synthetic-C2 were also rejected — the supervisor/author wanted **real** captures.

**Decision: aggregate real Windows-malware captures from malware-traffic-analysis.net (MTA).**
A purpose-built `utils/fetch_mta_pcaps.py` takes a curated list of *dates*, auto-discovers each
day's `pcap.zip` + `IOCs.txt.zip`, extracts them (password `infected_YYYYMMDD`, ZipCrypto so
Python's `zipfile` works), and **auto-parses the published IOCs** (malicious IPs / SNIs) into
`pcaps/mta/ioc_manifest.json` — with denylists for benign infrastructure and analysis-reference
domains and a TLD allowlist to drop filename fragments. The manifest **merges** across runs so
partial re-fetches don't drop other families.

**Labelling — per-5-tuple IOC matching.** Infection captures are *mixed*: mostly the victim host's
benign background plus a handful of malicious flows. A flow is labelled **malicious iff** its
5-tuple matches a capture's *published* IOCs (dst/src IP in `malicious_ips`, **or** the TLS SNI in
`malicious_domains`); everything else in the same capture is benign. **Benign** is drawn from
**CTU-Normal plus the malware captures' own host background**, which is essential to **avoid a
capture-origin confound** (the model must not learn "which pcap this came from"). The honest
caveat — written into the report — is that labelling is **IOC-completeness-dependent**: a C2
endpoint absent from a capture's published IOC file is mislabelled benign.

**The encrypted-only filter** (a real methodological lever). Filtering by **TLS *protocol*
detection** (NFStream `application_name ~ TLS/SSL/QUIC`, the Zeek-equivalent of the source method)
∪ a small encrypted-port set **tripled the malicious yield** (47 → 157 flows from the first 12
captures) versus port-only filtering, because modern loaders (DarkGate/Pikabot/Danabot) run TLS on
non-standard ports that a port filter misses.

**The two-class scope — a *finding*, not a shortcut.** A third TLS-observable class was actively
hunted. The model operates at the **post-exploitation** kill-chain stage, so phishing
(pre-exploitation) is the wrong fit; **lateral movement** (T1021) was the candidate. A probe of the
64 MTA captures found **7,209 east-west (internal→internal) flows but only *one* over TLS** — the
rest is unencrypted Windows domain background (DNS, LDAP, SMB/NetBIOS, RPC, Kerberos). Scan/recon
is likewise unencrypted, and ransomware *impact* is non-network (local file encryption). **Thesis
finding:** *in encrypted/TLS traffic, network-observable malicious behaviour reduces to exactly two
classes — C2 beaconing (T1071) and exfiltration (T1041)*. Two classes is therefore the **honest,
correct scope**, not a gap.

**Final dataset (`data/training_dataset.csv`).** **11,822 flows, balanced 1:1**, from **~25 real
Windows-malware families (2022–2025)** across **86 MTA captures** (42 C2-leaning + 44 exfil-leaning),
later rebuilt to also carry **JA3/JA3S** (~94 % populated). Within the malicious class the C2:exfil
ratio is ~16:1 — **exfil is a genuine minority class**, a reality carried through to the results and
discussed as a limitation, not hidden.

## A.4 Retraining and independent evaluation

`model_training/retrain_nfstream_model.ipynb` (a clean 18-cell notebook; the 7 MB original research
notebook is kept untouched as reference) trains the two-tier `models/mapper` joblib dict — RF
(`rf_best`), XGBoost (`xgb_rt`, the fast tier), and an EBM (`xxgb`, glass-box) — plus scalers and
the `REALTIME_SAFE_FEATURES` (29) / `BEST_FEATURES` (9) lists. **In-domain held-out results:**
XGBoost **F1 0.972 / AUC 0.996**, RF 0.965, EBM 0.958 — comfortably above the 0.90 target, versus
the inherited mapper's 0.52 on NFStream features. (Implementation note: EBM `interactions="3x"` is
invalid in `interpret` 0.6.1 → set to integer `10`.) The retrained `BEST_FEATURES` shifted from the
old IAT/TTL-centric set to a **TCP-payload-length + window/payload-change** set — itself evidence
the extractor change moved the signal. The validation run **overwrote `models/mapper`** (≈50 MB)
on top of the old 319 MB CICFlowMeter baseline (old metrics preserved in `eval_results_fixed/`).

**Independent, out-of-distribution evaluation** (`utils/nfstream_model_eval.py --encrypted-only
--balance`) on **legacy CTU-13/IoT-23 captures not in training** (a different malware era):
**ROC-AUC 0.977, macro-F1 0.80, malicious precision 0.99, recall 0.62, FP rate ~0.5 %**. The
**specificity problem inverted**: the old model was trigger-happy (12,744 false positives); the
retrained model is **conservative/well-calibrated** (44 FPs) and *correctly ignores* old plaintext
malware as out-of-scope, while still catching 62 % of unseen, different-era encrypted malware at
0.99 precision — strong cross-era generalisation.

## A.5 The headline — the mapping validation process

**Goal.** Convert opaque per-flow statistics into MITRE ATT&CK techniques **with a calibrated
per-alert confidence**, reliable enough to serve as *ground truth* for downstream SOAR decisions —
not hand-asserted from a paper's table, but **empirically validated**.

**Methodology — accept a feature→class→TTP link only when independent methods agree.** Four lines
of evidence were computed and intersected (`model_training/feature_mitre_validation.ipynb`):
1. **Descriptive statistics** — Mann–Whitney U + effect size + *direction* (which value-direction
   separates the class).
2. **SHAP on the *deployed* binary model** (`xgb_rt`), **stratified by class** so per-class drivers
   are visible despite a single binary head.
3. **SHAP on an *auxiliary* 3-class model** — an independent vantage on per-class attributions.
4. **EBM *exact* glass-box contributions** — no approximation, a different model family entirely.
Plus **bootstrap top-k stability** (the fraction of bootstraps in which a feature stays in the
class's top-k) — used directly as the per-feature **`confidence`** baked into `FEATURE_CLASS_MAP`
and rolled up into each alert's `mapping_confidence`.

**Validated signatures (all four methods agree; bootstrap stability in parentheses):**
- **C2 beaconing →** *HIGH* TCP-payload length (mean/std/max), TCP-window size (mean/std/median),
  IP-packet length (mean/std) — **98–100 %**. Interpretation: large, low-variance encrypted payloads
  and programmatic TCP-window behaviour = automated beaconing, not human HTTPS browsing.
- **Exfiltration →** *LOW* inter-arrival / inter-packet timing (backward+forward IAT, time-diff) —
  **90–100 %**. Interpretation: rapid, regular bulk upload.

**The result that validated the *method itself*:** the data-driven process **caught a wrong link in
the prior hand-asserted map** — low inter-arrival-time variance had been attributed to **C2**, but
all four methods show it is **exfil's** signature. A hand-built map would have shipped the error;
the triangulated, empirical map corrected it.

**Operationalisation (`fmm-2.0.0`, `services/translator/feature_mitre_map.py`).** `FEATURE_CLASS_MAP`
(14 validated features → class + value-direction + confidence) and `CLASS_TTP_MAP`
(`c2_beaconing` → T1071/T1071.001/T1573; `exfil` → T1041/T1048.002). `translate()` aggregates the
**malicious-pushing** XAI top-k features into a **confidence × |contribution| weighted class vote**,
takes the argmax, and assigns that class's TTPs; `mapping_confidence` is the contribution-weighted
mean stability of the matched evidence. An **ambiguity-margin gate** (`MAPPING_CLASS_MARGIN`,
default 0.60) asserts a class as `mapped` only when its vote share clears the margin; below it the
TTP is tentative (`unmapped_heuristic`, reduced confidence) — protecting precision on the
overlapping/minority exfil class.

**End-to-end validation (Phase 6).** Held-out flows were scored, each flow's XAI top-k generated as
in production, and run through the *live* `translate()`; assigned class compared to the true label.
At the default operating point: **~87.5 % TTP-assignment accuracy**, mean `mapping_confidence`
0.99, coverage ~76 %. Per class: **C2 (T1071) precision 0.97 / recall 0.86 / F1 0.93 —
ground-truth-grade**; **exfil (T1041) weak** (precision ~0.18) because it is a minority class with a
**partial signature overlap** with C2 (some C2 flows carry low-IAT in their top-k and vote exfil) —
a clean, disclosed limitation, not a failure.

**Operating-point analysis (the margin-gate sweep).** Margin 0.50 → 0.80 trades coverage for
precision: mapped-accuracy **0.844 / 0.875 / 0.882 / 0.847**, coverage **0.832 / 0.760 / 0.706 /
0.491**, exfil-F1 **0.265 → 0.346** (the gate ~doubles exfil F1 by filtering C2-leakage). **0.60**
is the chosen default (≈87.5 % mapped-accuracy at ~76 % coverage). The **only remaining piece** is
**Phase 4 — literature grounding** (prior-work `citation` per link); the empirical validation is
complete.

## A.6 Operationalisation & the closed loop (how the result became a system)

The validated mapping became the live **XAI→SOAR translation seam**: the translator writes one
enriched row per flagged flow to the PostgreSQL **`alerts`** contract (prediction + `top_k_json` +
`mitre_ttps` + **`mapping_status`/`mapping_confidence`** + `observables` incl. **JA3**), then emits a
thin `alert.translated` Kafka trigger. The SOAR half consumes it, re-derives severity from
`pred_proba`, enriches observables (Cortex/MISP), applies a **trust-aware** §5 decision matrix that
treats `mapping_confidence`/`mapping_status` as a first-class gate (a *tentative* TTP can never
justify an automated block), and — after an analyst approval for gated actions — drives response.
The loop was **closed on the endpoint**: a shippable agent bundle (NFStream sensor + Wazuh agent +
four vetted Active-Response scripts) lets the *same* host that produced a flow enforce a
block/isolate, routed via a new nullable **`agent_id`/`host_id`** contract field. Bringing this up
end-to-end surfaced two real engineering findings worth a sentence each: Wazuh `execd` holds the
AR script's stdin pipe open (so the scripts must read **one line**, not `cat` to EOF, or they hang
and stall *all* subsequent AR), and `isolate` on a container-host must spare the Docker bridges or
it severs the detection stack itself. The analyst surface evolved from a FastAPI+htmx dashboard to
a React/TS SPA over the same JSON API (alert queue + XAI/attribution viz, an ATT&CK-coverage
heatmap of the mapping, the approvals + Step-6 feedback loop, an endpoint inventory, a
mapping-confidence distribution, and a WebSocket live feed).

## A.7 Consolidated limitations (for the Limitations chapter)
- **Exfil is a minority class with C2 signature overlap** → weaker exfil TTP precision; the
  headline accuracy is C2-dominated.
- **Labelling is IOC-completeness-dependent** (missing published IOCs → mislabelled benign).
- **Single-deployment / single-era scope** — one lab topology; one malware era for in-domain.
- **Phase-4 literature citations** for the mapping links are outstanding (empirical validation done).
- **Severity semantics**: the translator's advisory `severity_label` (≥0.85 HIGH) and the SOAR
  orchestrator's authoritative band (`pred_proba` ≥0.90 High / 0.70–0.89 Medium / <0.70 Low) differ,
  so a ~0.80 flow shows "HIGH" in the dashboard yet is Medium (notify-only, no approval) to SOAR —
  align the translator thresholds to the orchestrator to remove the ambiguity.
