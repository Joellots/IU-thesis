# XAI-SOAR — Full System Overview (cross-machine context)

**Audience:** Claude Code instances on *either* side of the project (the ML-detection
machine and the SOAR machine). Read this first to understand the whole system and the
contract between the two halves.

**Thesis:** "Explainable Machine Learning for Malicious Encrypted Traffic Detection and
Trust-Aware SOAR Integration" — Joel C. Okore (MSc, Innopolis). The SOAR module is
co-developed with **Isaac Womoakor**.

The project has **two halves that meet at one contract (the PostgreSQL `alerts` table):**

```
  ┌─────────────────────── HALF A: Detection pipeline (Joel) ───────────────────────┐
  NFStream producer → Kafka(raw_flows) → Inference(+XAI) → Kafka(alerts) → Translator
                                                                               │
                                                          writes annotated alert ▼
                                                    ┌──────── PostgreSQL `alerts` ────────┐   ← THE CONTRACT
                                                                               │ reads
  ┌─────────────────────── HALF B: SOAR module (Joel + Isaac) ──────────────────────┐
  soar_orchestrator → severity → Cortex+MISP enrich → TheHive case → Shuffle actions
                                                    → Dashboard (notify / approve / feedback)
```

---

## 1. The Contract — PostgreSQL `alerts` table (`services/dashboard/schema.sql`)

Half A **writes** one row per flagged flow; Half B **reads** it. This is the single
integration point. Authoritative fields:

| Field | Written by | Meaning |
|---|---|---|
| `flow_id`, `model`, `tier` | inference | flow identity; `model=XGBoost tier=fast` is the primary row |
| `pred_label`, `pred_proba` | inference | 0/1 and P(malicious) — **this is the SOAR's `model_confidence`** |
| `top_k_json` | inference (XAI) | top-k feature attributions `[{feature, value, contribution, direction}]` |
| `mitre_ttps`, `mitre_names` | translator | mapped ATT&CK technique IDs/names |
| `severity`, `severity_label` | translator | 1/2/3, LOW/MEDIUM/HIGH (advisory — see §5 adjustment) |
| `annotation` | translator | human-readable SOC explanation |
| `observables` | translator | `[{type: ip\|domain\|url, value, role: src\|dst}]` → Cortex/MISP routing |
| `mapping_confidence`/`_version`/`_status`/`_reason` | translator | reliability of the feature→TTP mapping (`mapped`/`unmapped_heuristic`/`unmapped`) |
| `analyst_decision`/`_ts`/`_note` | dashboard | analyst feedback (Step 6) → retraining labels |

**Transport:** currently DB-based (translator writes, orchestrator reads). The SOAR spec
also allows an **ML-API webhook** (translator POSTs the alert to the orchestrator/Shuffle).
Either is valid; the DB path is what's implemented.

---

## 2. Half A — Detection pipeline (this machine, Joel)

Full detail in `context/context.md`. Summary of current state (2026-06):

- **Models retrained on NFStream features** — `models/mapper` (RF `rf_best`, XGBoost
  `xgb_rt`, EBM `xxgb`, scalers, `REALTIME_SAFE_FEATURES` (29), `BEST_FEATURES` (9)).
  In-domain held-out **F1 ≈ 0.97**; the old CICFlowMeter→NFStream distribution-shift
  problem is solved. Retraining notebook: `model_training/retrain_nfstream_model.ipynb`.
- **Two detection classes (the only TLS-observable malicious behaviours):**
  **C2 beaconing → T1071/T1071.001/T1573** and **Exfiltration → T1041/T1048.002**.
  Scan, lateral movement, and ransomware-impact were dropped: they run over
  unencrypted protocols or generate no distinctive flow signature (documented finding).
- **Dataset** — 11.8k balanced flows from ~25 real Windows-malware families (2022–2025,
  malware-traffic-analysis.net) + benign; per-flow IOC-labelled. Built by
  `utils/build_training_dataset.py` (+ `utils/fetch_mta_pcaps.py`).
- **Feature→MITRE mapping validation (IN PROGRESS — the thesis headline):**
  `model_training/feature_mitre_validation.ipynb`. Triangulates SHAP (deployed binary +
  auxiliary 3-class) + statistics + (pending) EBM/LIME + literature. Validated signatures:
  **C2 = HIGH payload/IP-packet length; Exfil = LOW inter-arrival timing.** This rebuild
  targets a `feature → class → TTP` structure with a per-mapping confidence (feeds the
  `mapping_*` columns).

Key files: `services/nfstream/nfstream_producer.py`, `services/inference/inference_service.py`
(+`explain_instance.py`), `services/translator/translator_service.py`
(+`feature_mitre_map.py`).

---

## 3. Half B — SOAR module (`services/soar_orchestrator/`, Joel + Isaac)

Spec: `services/soar_orchestrator/SOAR_WORKFLOW_SPEC.md` (decision matrix is authoritative).
Two layers: the **`soar_orchestrator`** Python service (alert parsing, severity, Cortex
calls, TheHive cases, persistence) + **Shuffle workflows** (block/isolate/notify + the
manual-approval pause gate).

Workflow: parse alert → severity (by `pred_proba`) → **High/Medium:** Cortex+MISP enrich
observables → combine ML+intel+XAI → decision matrix → TheHive case / Shuffle action
(auto-block only on High+confirmed-IOC; **isolate always human-gated**) → async analyst
feedback to PostgreSQL (retraining labels). **Low (<0.70): notify only.**

Components: TheHive (cases), Cortex+MISP (enrichment; tiered analyzers in
`integration_config.py`), Shuffle (response + approval gate), optional Wazuh (endpoint
context / isolate path), Dashboard (notify/approve/feedback). Key files:
`orchestrator.py`, `thehive_client.py`, `cortex_client.py`, `case_automation.py`,
`attack_stix_resolver.py`, `playbook_catalog.py`, `integration_config.py`, `db.py`.

---

## 4. Responsibility split

| Area | Owner |
|---|---|
| NFStream capture, inference, XAI, feature→MITRE mapping, the `alerts`-table producer side | **Joel** |
| soar_orchestrator service, TheHive/Cortex/MISP integration, Shuffle workflows | **Isaac (+ Joel)** |
| The `alerts`-table contract + observables + `mapping_*` fields (the seam) | **Joel**, consumed by Isaac |

---

## 5. Integration adjustments / open sync items (2026-06)

1. **JA3/JA3S `tls_fingerprint` observable — NOW FEASIBLE.** The SOAR spec Step 1 wants
   `tls_fingerprint`, and NFStream 6.6.0 **does** expose `client_fingerprint` (JA3) and
   `server_fingerprint` (JA3S). The producer should emit them and the translator's
   `extract_observables()` should add an observable `{type: "ja3", value, role}` so Cortex/MISP
   can correlate (MISP `ja3-fingerprint-md5`). *Currently only ip/domain/url are extracted.*
2. **`mapping_*` columns ← mapping-validation output.** The in-progress feature→class→TTP
   validation produces a per-mapping confidence + status — wire these into `translate()` so
   `mapping_confidence` / `mapping_status` (`mapped`/`unmapped_heuristic`/`unmapped`) /
   `mapping_version` are populated, not the current placeholders.
3. **Severity ownership.** Translator `compute_severity()` (≥0.85 HIGH) and SOAR spec Step 2
   (`pred_proba` ≥0.90 High / 0.70–0.89 Med / <0.70 review) use different thresholds.
   Decide: orchestrator re-derives from `pred_proba` (spec) and treats `severity_label` as
   advisory, **or** align the translator thresholds to the spec. Recommend the orchestrator
   is authoritative (single source) and the translator aligns its thresholds to match.
4. **Confidence field name.** SOAR calls it `model_confidence`; the column is `pred_proba`.
   The orchestrator should read `pred_proba` (no rename needed — just document it).

---

## 6. Run / infra quick facts

- Stack: `docker-compose.yml` (Kafka KRaft, producer/nfstream, inference, translator,
  postgres, dashboard, kafka-ui). SOAR components (TheHive/Cortex/MISP/Shuffle) run
  separately and reach the shared PostgreSQL + the orchestrator.
- Dashboard `:8080`, Kafka-UI `:8081`, Kafka external `:9094`.
- PostgreSQL db `soar` is shared across both halves — it is the integration substrate.
