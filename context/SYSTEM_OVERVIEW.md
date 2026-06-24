# Aegis — Full System Overview (cross-machine context)

**Audience:** Claude Code instances on *either* side of the project (the ML-detection
machine and the SOAR machine). Read this first to understand the whole system and the
contract between the two halves.

> **Standalone, cross-machine doc.** The two halves live in **separate git repositories** 
> on separate machines; they are NOT synced via git. This file is the shared bridge — keep
> an identical copy in each repo's `context/`, and when the contract (the `alerts` schema,
> the SOAR workflow, or the responsibility split) changes, copy the updated file to the
> other repo. Each repo's own `context.md` is *that machine's* local detail and differs
> between the two; this overview is the only doc that describes both halves.

**Thesis:** "Explainable Machine Learning for Malicious Encrypted Traffic Detection and
Trust-Aware SOAR Integration" — Joel C. Okore (MSc, Innopolis). The SOAR module is
co-developed with **Isaac Womoakor**.

The project has **two halves that meet at one durable contract (the PostgreSQL
`alerts` table) plus a thin Kafka trigger for low-latency SOAR handoff:**

```
  ┌─────────────────────── HALF A: Detection pipeline (Joel) ───────────────────────┐
  NFStream producer → Kafka(raw_flows) → Inference(+XAI) → Kafka(alerts) → Translator
                                                                               │
                                                          writes annotated alert ▼
                                                    ┌──────── PostgreSQL `alerts` ────────┐   ← AUDIT / REPLAY SOURCE OF TRUTH
                                                                               │
                                                          emits pointer event after commit ▼
                                                    Kafka(`soar_alert_events`, alert.translated)
                                                                               │ consume trigger, then fetch row
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
| `observables` | translator | `[{type: ip\|domain\|url\|ja3, value, role: src\|dst}]` → Cortex/MISP routing |
| `mapping_confidence`/`_version`/`_status`/`_reason` | translator | reliability of the feature→TTP mapping (`mapped`/`unmapped_heuristic`/`unmapped`) |
| `agent_id`/`host_id`/`host_ip` (nullable) | sensor→translator | **endpoint identity** → SOAR routes block/isolate to the right Wazuh agent (§7.1 `endpoint`); NULL for replay/in-stack flows |
| `analyst_decision`/`_ts`/`_note`, `explanation_useful`, `flag_for_retraining` | dashboard | analyst verdict + feedback (Step 6) → retraining labels |

**Transport:** translator always writes the full enriched row to PostgreSQL first. After a
successful insert commit, it publishes a small Kafka event (`event_type=alert.translated`)
to `SOAR_ALERT_EVENTS_TOPIC` (default `soar_alert_events`) containing only identifiers and
routing metadata (`alert_id`, `flow_id`, model/tier, timestamps, mapping status, prediction).
The SOAR consumer treats Kafka as a trigger and fetches the full row from PostgreSQL.
Postgres remains the audit/replay source of truth, and Postgres polling can remain as a
fallback or replay path. The SOAR spec also allows an **ML-API webhook**
(translator POSTs the alert to the orchestrator/Shuffle), but the implemented path is now
Postgres + Kafka trigger.

---

## 2. Half A — Detection pipeline (this machine, Joel)

Full detail lives in the **detection repo's** `context/context.md` (not present on the SOAR
machine). Summary of current state (2026-06):

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
- **Feature→MITRE mapping validation (DONE — the thesis headline):**
  `model_training/feature_mitre_validation.ipynb`. Signatures validated by **four methods**
  (statistics + SHAP-binary + SHAP-3class + EBM exact) with **90–100% bootstrap stability**:
  **C2 = HIGH payload/IP-packet length; Exfil = LOW inter-arrival timing.** The map is rebuilt
  as `feature → class → TTP` and **live in `services/translator/feature_mitre_map.py`
  (`fmm-2.0.0`)**, emitting real `mapping_confidence` (calibrated 0–1, = bootstrap stability)
  and `mapping_status` (`mapped`/`unmapped_heuristic`/`unmapped`), with a tunable
  ambiguity-margin gate (`MAPPING_CLASS_MARGIN`, default 0.60). End-to-end validation:
  **87.5% TTP-assignment accuracy** vs true labels (C2 F1 0.93 / ~0.99 confidence; exfil
  lower — a documented limitation: minority class + signature overlap). Phase 4 literature
  grounding for each link is the only remaining piece (`citation` placeholders).

Key files: `services/nfstream/nfstream_producer.py`, `services/inference/inference_service.py`
(+`explain_instance.py`), `services/translator/translator_service.py`
(+`feature_mitre_map.py`).

---

## 3. Half B — SOAR module (SOAR machine / SOAR repo, Joel + Isaac)

The SOAR module (`soar_orchestrator` + the vendored stacks) lives in the **SOAR repo** and
runs on the **SOAR machine** — it is not in the detection repo. Spec: `SOAR_WORKFLOW_SPEC.md`
(decision matrix authoritative) — kept in `context/` on the detection repo and in
`services/soar_orchestrator/` on the SOAR repo.
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

## 5. Integration status — RECONCILED (2026-06)

The integration is **built and verified end-to-end** — an analyst-approved gated block drives a
real nftables DROP on the target host. The former open sync items are now resolved:

1. **JA3/JA3S observable — DONE.** The producer emits `client_fingerprint`/`server_fingerprint`;
   the translator's `extract_observables()` adds `{type: "ja3", value, role}` so Cortex/MISP
   correlate via MISP `ja3-fingerprint-md5`.
2. **`mapping_*` columns — DONE.** `translate()` (`fmm-2.0.0`) emits live `mapping_confidence`
   (calibrated 0–1 = bootstrap stability), `mapping_status`, `mapping_version`, `mapping_reason`;
   the SOAR trust gate keys on them (C2/T1071 ≈ 0.99; exfil/T1041 lower).
3. **Severity — ALIGNED.** The orchestrator is authoritative and derives severity from
   `pred_proba`; the translator's advisory `severity_label` now uses the **same** bands. Live
   deployment bands: **High ≥0.80, Medium 0.70–0.79, Low <0.70** (lowered from ≥0.90 because the
   retrained NFStream model rarely scores ≥0.90 — most true-malicious flows land 0.80–0.89). Both
   sides are env-tunable (`SEVERITY_HIGH_MIN`/`SEVERITY_MED_MIN` on the translator;
   `SEVERITY_*_THRESHOLD` on the orchestrator) — **keep them matched.**
4. **Endpoint identity — NEW contract field.** The endpoint sensor (or `detctl sim <agent_id>`)
   stamps `agent_id`/`host_id`/`host_ip` (nullable) onto each flow → the `alerts` row → the §7.1
   handoff `endpoint:{host_id, ip, source}`, so SOAR routes block/isolate to the right Wazuh agent.
   The actuator is the shippable `endpoint_agent/` bundle (Wazuh agent + the four vetted
   Active-Response scripts `soar-{block,unblock,isolate,unisolate}`).
5. **`model_confidence` ≡ `pred_proba`** — documented equivalence, no rename.

---

## 6. Run / infra quick facts

- Stack: `docker-compose.yml` (Kafka KRaft, producer/nfstream, inference, translator,
  postgres, dashboard, dashboard-web, kafka-ui). SOAR components (TheHive/Cortex/MISP/Shuffle)
  run separately and consume the `soar_alert_events` Kafka trigger while reading full alert state
  from the shared PostgreSQL `alerts` table.
- Dashboard: **React SPA `:3000`** (the makeover) / htmx `:8080`, Kafka-UI `:8081`,
  Kafka external `:9094`, Postgres `:5432`.
- PostgreSQL db `soar` is shared across both halves — it is the integration substrate.
