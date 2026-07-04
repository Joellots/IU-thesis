# XAI-SOAR Framework — Elaborate Project Context (SOAR side)

**Purpose of this document.** A single, detailed reference describing the SOAR half of the
XAI-SOAR thesis framework — its architecture, every processing step, the data contracts, the
component integrations, the deployment model, and the design rationale/limitations. It is
written to be fed to an LLM (Codex) as grounding context for **writing the thesis report**,
and to onboard any engineer/agent to the codebase. It is descriptive, not a spec; the
**authoritative** behavioural contract is `context/SOAR_WORKFLOW_SPEC.md` (the §5 decision
matrix and §7.1 handoff payload), and the cross-half picture is `context/SYSTEM_OVERVIEW.md`.

> **Secrets:** all credentials live in `services/soar_orchestrator/.env`; this document names
> the env vars but never their values. Do not paste real keys into the report.

> **Currency:** reflects the repository after the move to a **Kafka-triggered,
> Postgres-backed** orchestrator with **pre-case enrichment**. Inspect the cited files before
> quoting line-level detail — the code evolves.

---

## 0. Thesis framing

- **Title:** *Explainable Machine Learning for Malicious Encrypted Traffic Detection and
  Trust-Aware SOAR Integration.*
- **Author (detection + overall):** Joel C. Okore (MSc, Innopolis University; supervisor
  Dr Andrei Petrovski). **SOAR module co-developed with** Isaac Womoakor.
- **Two deliverables:** (1) a conference paper (USBEREIT 2026, accepted w/ minor
  corrections); (2) a proof-of-concept SOAR pipeline operationalising the models.
- **The headline scientific contribution** lives on the detection side: a **validated
  feature → behavioural-class → MITRE ATT&CK technique mapping** (`fmm-2.0.0`), validated by
  four independent methods (statistics + SHAP-binary + SHAP-3class + EBM-exact) with 90–100%
  bootstrap stability and ~87.5% end-to-end TTP-assignment accuracy. The SOAR half's
  contribution is a **trust-aware** automated response that consumes that mapping and its
  calibrated confidence as a first-class decision signal.

---

## 1. System-level architecture (both halves)

The framework is two halves on **two machines** that meet at **one durable contract** (the
PostgreSQL `alerts` table) plus a **thin Kafka trigger** for low-latency handoff.

```
HALF A — Detection pipeline (detection machine, Joel)
  NFStream producer → Kafka(raw_flows) → Inference(+XAI) → Kafka(alerts) → Translator
        │ writes full enriched row
        ▼
   PostgreSQL `alerts`  ← SOURCE OF TRUTH (audit / replay / state)
        │ after commit, emits a thin pointer event
        ▼
   Kafka(`soar_alert_events`, event_type=alert.translated)
        │ trigger only (alert_id + routing metadata)
        ▼
HALF B — SOAR module (SOAR machine, Joel + Isaac)
  soar_orchestrator → severity → Cortex+MISP enrich → §5 matrix → TheHive case
                    → §7.1 handoff → Shuffle (block / isolate / notify + approval gate)
                    → callback → Postgres; async analyst feedback (Step 6) → Dashboard
```

**Deployment topology** (the IPs below are this deployment's values; they are **env-driven** —
`.env.example` uses `<DETECTION_HOST>`/`<SOAR_HOST>` placeholders and a deployer edits only `.env`):

| Machine | Role | Key services |
|---|---|---|
| **Detection host** (`172.31.87.134`) | produces alerts; **owns Postgres + Kafka** | nfstream/producer, inference, translator, **postgres :5432**, **kafka :9094 (external)**, dashboard :8080 |
| **SOAR host** (`172.31.80.148`) | consumes alerts; runs orchestrator + SOAR stack | soar_orchestrator (:8200/:9100), TheHive :9000, Cortex :9001, MISP :8088, Shuffle :3001 |

- The orchestrator reads Postgres **cross-machine** (`DATABASE_URL → 172.31.87.134:5432`) and
  consumes the Kafka trigger (`KAFKA_BROKER → 172.31.87.134:9094`).
- It reaches the **local** SOAR stack over the SOAR host's published ports (host LAN IP
  `172.31.80.148`); MISP via `host.docker.internal`. It does **not** join the vendored stacks'
  Docker networks.
- **Coordination dependencies on the detection side:** Postgres must publish `5432` +
  firewall to the SOAR host; Kafka must advertise its **external** listener as the detection
  host IP (not `localhost`) via `KAFKA_EXTERNAL_ADVERTISED_HOST`, or remote consumers connect
  to the bootstrap then fail on a `localhost` redirect (the orchestrator detects and warns on
  this — see §6).

---

## 2. The integration contract

### 2.1 PostgreSQL `alerts` table (the durable seam)
Written by the translator (Half A), read by the orchestrator (Half B). Schema owned by
`services/dashboard/schema.sql` on the detection side. Fields the SOAR side relies on:

| Field | Meaning / SOAR use |
|---|---|
| `id` | primary key; the **Kafka pointer** references this |
| `flow_id`, `model`, `tier` | flow identity; primary row is `model=XGBoost, tier=fast` |
| `pred_label` (0/1), `pred_proba` ∈[0,1] | **`pred_proba` IS the SOAR's `model_confidence`** — drives severity |
| `top_k_json` | XAI top-k feature attributions `[{feature,value,contribution,direction}]` → "Top Evidence" |
| `mitre_ttps`, `mitre_names` | mapped ATT&CK IDs/names → case title, tags, TheHive procedures |
| `severity`, `severity_label` (1/2/3, LOW/MED/HIGH) | translator's **advisory** label — traceability only, NOT branched on |
| `annotation` | SOC explanation → case "Translator Annotation" table |
| `observables` | `[{type: ip\|domain\|url\|ja3, value, role: src\|dst}]` → enrichment routing + block targets |
| `mapping_confidence` / `_status` / `_version` / `_reason` | feature→TTP **trust signal** (`mapped`/`unmapped_heuristic`/`unmapped`) |
| `n_ttps_matched` | count gate for case creation |
| `translated_ts` | ordering for the polling fallback |
| `analyst_decision`/`_ts`/`_note` (planned: Step-6 columns) | analyst feedback → retraining labels |

The translator **does not delete or update** these rows for SOAR's benefit; Postgres is the
audit/replay store. SOAR keeps its own state in separate tables (§4.10).

### 2.2 Kafka pointer event (the low-latency trigger)
Topic `SOAR_ALERT_EVENTS_TOPIC` (default `soar_alert_events`). Emitted by the translator
**only after the Postgres insert commits**; if the insert conflicts on `(flow_id, model)`,
no event is emitted. Shape (validated by `kafka_events.validate_soar_alert_event`):

```json
{ "schema_version": "1.0", "event_type": "alert.translated",
  "alert_id": 123, "flow_id": "...", "model": "XGBoost", "tier": "fast",
  "translated_ts": "2026-06-19T...", "mapping_status": "mapped",
  "pred_label": 1, "pred_proba": 0.97 }
```

**Kafka is a trigger, not the source of truth.** The orchestrator uses only `alert_id` to
fetch the full row from Postgres. Unknown `schema_version`/`event_type` are logged and
**skipped** (non-fatal, so the topic can evolve / be shared). Invalid JSON or non-positive
`alert_id` are skipped with a reason.

---

## 3. SOAR orchestrator — service lifecycle & main loop

Entry point `services/soar_orchestrator/orchestrator.py :: main()`.

1. `_normalize_bom_env_keys()` — strips UTF-8 BOM from env keys saved on Windows.
2. `start_metrics_server()` — Prometheus `/metrics` on `METRICS_PORT` (9100).
3. `start_api_server()` — Flask HTTP listener on `ORCHESTRATOR_HTTP_PORT` (8200), in a daemon
   thread; serves `/soar/shuffle-result` + `/soar/feedback`. **Starts before the DB** and
   stays up regardless of DB state.
4. `connect_with_retry()` — blocks (never raises) with capped exponential backoff
   (`DB_RECONNECT_BACKOFF_START_SEC`→`_MAX_SEC`) until Postgres is reachable, then
   `ensure_tables()` (idempotent `CREATE TABLE IF NOT EXISTS` for the 3 SOAR tables).
   *Rationale:* the DB is cross-machine, so transient outages must not kill the process or the
   callback server.
5. `validate_integration_settings()` — logs Cortex connector id + count of enabled analyzers,
   warns on missing keys / unreachable Cortex.
6. `ensure_attack_bundle()` — prefetches/caches the MITRE ATT&CK STIX bundle to `/app/cache`
   (volume `attack_stix_cache`) for technique resolution.
7. **Main loop** (one combined Kafka + polling pass per iteration):
   - If `ENABLE_KAFKA_TRIGGER` and no consumer, try to (re)create one every
     `KAFKA_RECONNECT_INTERVAL_SEC` (`make_soar_alert_consumer`); failure ⇒ fall back to
     polling, retry later.
   - If a consumer exists: `poll(KAFKA_POLL_TIMEOUT_MS, KAFKA_MAX_RECORDS)`, process each
     event via `process_kafka_event`, then **manual `commit()`** (auto-commit disabled). Any
     consumer error closes/nulls the consumer (→ polling continues, Kafka retried).
   - **Always** also runs `process_polling_batch(limit=POLL_BATCH_LIMIT)` — the replay/fallback
     path that picks unclaimed alerts directly from Postgres.
   - Sleeps `0.2s` when Kafka is live (tight loop) or `POLL_INTERVAL_SEC` when polling-only.
   - Outer `except` reconnects the DB with backoff (handles disconnects without dying).

Both trigger paths converge on the **same** `process_alert()` — Kafka and polling are
interchangeable; only the trigger source label differs (`kafka` vs `postgres_poll`).

---

## 4. `process_alert()` — the per-alert pipeline (the core)

`process_alert(conn, cortex, alert, *, trigger_source, trigger_event=None)` maps 1:1 onto the
spec's Steps 1–6.

### 4.1 Idempotency claim (first operation)
`claim_alert_for_processing()` does `INSERT ... ON CONFLICT (alert_id) DO NOTHING RETURNING
alert_id` into `soar_orchestrator_bookkeeping` with status `running`. **First writer wins** —
a duplicate Kafka event, a replayed offset, or a polling pass racing the Kafka trigger can
only claim once. If the claim returns nothing → `"duplicate"`, logged and returned. This is
the single mechanism guaranteeing **no duplicate TheHive cases/actions**.

### 4.2 Step 1 — parse + observable optimization
- JSON fields (`mitre_ttps`, `mitre_names`, `top_k_json`, `observables`) parsed defensively
  (`_ensure_parsed_json`).
- `_parse_observables()` **normalizes, deduplicates, and filters**:
  - normalize: IPs → compressed form; domain/hash/ja3 → lowercased.
  - dedupe: `(type, value)` set.
  - **private-IP skip:** `_should_skip_observable()` drops non-global IPs **iff**
    `SKIP_PRIVATE_IP_OBSERVABLES=true`. The **code default and `.env.example` template are
    `true`**, but the **live `.env` overrides to `false`**, so private IPs are presently kept
    (relevant when reading live cases that show RFC1918 targets). JA3/domain/url are never skipped.
  - emits a `observables_filtered` structured log with kept/skipped counts.

### 4.3 Step 2 — severity (authoritative)
`severity.compute_severity(pred_proba)`:

| `pred_proba` | severity |
|---|---|
| ≥ `SEVERITY_HIGH_THRESHOLD` (deployment **0.80**, spec default 0.90) | **High** |
| ≥ `SEVERITY_MEDIUM_THRESHOLD` (0.70) and < High | **Medium** |
| < `SEVERITY_MEDIUM_THRESHOLD` | **Low** (analyst-review-only / notify-only) |

Bands are env-configurable. **This deployment lowers High to ≥0.80** (Medium 0.70–0.79) because
the NFStream model rarely scores ≥0.90 — without it, the High cell (the only one that emits a
gated block) would almost never fire and the approval loop couldn't be demonstrated. The
orchestrator is the **single source of truth** for severity; `severity_label` from the
translator is advisory (aligned to the same bands; kept on the case as `soarSeverityAdvisory`).

### 4.4 Case-creation gate — `should_create_thehive_case()`
A case is created **only** for: `pred_label==1` **and** severity≠Low **and** (strict mapping
gate) `mapping_status=="mapped"` **and** `n_ttps_matched≥1` **and** a TheHive key is present
(unless dry-run). Skip reasons recorded in bookkeeping:
- benign (`pred_label!=1`),
- `Low` severity → **notify-only** (still dispatches a notify to Shuffle; no case),
- `MITRE mapping incomplete (status=…)` under the strict gate
  (`REQUIRE_STRICT_MAPPED=true` accepts only `mapped`; set `false` to also accept
  `unmapped_heuristic`/`unmapped`),
- no TTPs matched,
- missing `THEHIVE_API_KEY`.
Gate knobs: `REQUIRE_MAPPED_FOR_THEHIVE`, `REQUIRE_STRICT_MAPPED`.

### 4.5 Step 3 — pre-case enrichment (Cortex + MISP) — *runs BEFORE the case*
`case_automation.run_pre_case_enrichment()` is invoked **before** TheHive case creation so the
case description and the Step-5 decision both see real intel. For each observable (bounded by
`MAX_OBSERVABLES_PER_FLOW`, `MAX_CORTEX_RUNS_PER_FLOW`), it runs the analyzers routed by
observable type (`analyzers_for_observable_type`) **directly** via `CortexClient.
run_analyzer_on_observable()` with a bounded `CORTEX_PRE_CASE_WAIT_SEC` (falls back to
`CORTEX_WAIT_SECONDS`) per `waitreport`. Returns `{cortex_results, verdicts, intel_malicious,
intel_score, enriched_observables}`. Skipped entirely when `ORCHESTRATOR_DRY_RUN=true` or
`AUTO_RUN_CORTEX=false`.

> **`pending` is not "skipped".** If an analyzer doesn't return within the bounded wait, its
> verdict is recorded as `pending` (the full report still lands natively in Cortex/TheHive);
> the initial case may therefore show `pending` rows. This is wait-expiry, not an enrichment
> failure.

**Analyzer routing & tiers** (`integration_config.py`):
- Tier-0 (no external key, always-on baseline) and Tier-1 (need a free key) lists per type
  (ip/domain/url/hash). **`ja3` is MISP-only** (`MISP_2_1`) — no no-key analyzer does
  fingerprint lookups; routed to MISP `ja3-fingerprint-md5`.
- Runtime selection comes from `CORTEX_<TYPE>_ANALYZERS` env (falls back to the Tier-0+Tier-1
  defaults). The **current `.env`** uses a lean set: `ip=Cyberprotect_ThreatScore_3_0`,
  `domain/url/hash/ja3=MISP_2_1`.

### 4.6 Cortex verdict logic (nuanced — see `_summarize_cortex_job`)
Do **not** rely only on `summary.taxonomies`. Some analyzers put the useful signal in `full`:
- **URLhaus**: emits **no taxonomy tags** — `_fallback_cortex_verdict` reads `report["full"]`
  directly. The response structure differs by lookup type:
  - *URL-type lookups*: `threat`, `url_status`, `payloads` are at the top level of `full`.
  - *Domain/host-type lookups*: those fields are **absent** at the top level; instead `threat`
    and `url_status` are nested inside `full["urls"][].threat` / `full["urls"][].url_status`,
    and `full["blacklists"]` carries Spamhaus DBL / SURBL status (e.g. `malware_domain`,
    `listed`). The fallback scans both: a non-empty `blacklists` hit **or** a nested
    `threat`/`url_status` in `urls[]` returns `malicious`.
  - `query_status=ok` with no blacklist hits and no active URLs → `info`; `no_results` → `info`.
  - This path is what makes **auto-block fire on live C2 domains** without MISP seeding:
    kzaa.co.za (Spamhaus DBL `malware_domain`, SURBL `listed`, RemcosRAT) is confirmed
    malicious by URLhaus_2_0 directly via the domain-type fallback, no IOC in MISP required.
- **MISP**: a positive local event match (`_misp_event_count > 0`) is treated as `malicious`
  (the analyzer itself labels it `suspicious`).
- **CIRCL hashlookup**: `full.KnownMalicious == true` ⇒ `malicious`.
These analyzer-specific fallbacks (`_fallback_cortex_verdict`) convert dedicated threat-intel
hits into the confirmed `malicious` verdict that the §5 gate keys off, while leaving generic
enrichment analyzers' taxonomy verdicts untouched. Job states `waiting/inprogress/pending` →
`pending`; `failure/failed/deleted` → that status; missing → `missing`.

### 4.7 Step 4 — combine signals → intel verdict
`derive_intel_verdict(verdicts)`:
- **`intel_malicious`** = `True` **only if** a designated **confirmation analyzer** returned an
  explicit `malicious` verdict. The allowlist is narrow and named
  (`INTEL_CONFIRMATION_ANALYZERS`, default `MISP_2_1, VirusTotal_GetReport_3_1, URLhaus_2_0`)
  — dedicated intel/reputation sources, **not** "any analyzer says malicious". This is the
  conservative bar for "Malicious IOC confirmed".
- **`intel_score`** = fraction of *resolved* verdicts that were malicious (soft context
  signal; does **not** by itself unlock auto-block).
- `annotate_observable_intel()` tags **per-observable** `intel_malicious=True` only for
  `(type,value)` pairs a confirmation analyzer flagged malicious — these become the auto-block
  targets and the `observables[].intel_malicious` field in the §7.1 payload.
- **Mapping trust gate** (`mapping_trust.is_ttp_tentative`, `MAPPING_TRUST_MIN_CONFIDENCE`):
  when `mapping_status != "mapped"` or `mapping_confidence` is low, the TTP is "tentative" —
  surfaced in the case but **never** a basis for an automated block on its own. (It is *not* an
  input to `decide_actions`; the matrix only auto-blocks on a real intel confirmation.)

### 4.8 Step 5 — decision matrix (`decision_matrix.decide_actions`, AUTHORITATIVE)
Pure function: `severity + intel_malicious (+ endpoint_risk/endpoint) → actions[]`.

| Severity | Intel verdict | Actions emitted |
|---|---|---|
| **High** | confirmed malicious IOC | `block` **`requires_approval:false`** (auto), targets = confirmed observables only; + `notify` |
| **High** | no confirmation | `block` **`requires_approval:true`** (gated), targets = all blockable observables; + `notify` |
| **High** | managed endpoint (`agent_id`) | + `isolate` **`requires_approval:true`** (always gated) — now **live** via the approval loop; `endpoint_risk=bool(agent_id)` |
| **Medium** | any | `notify` only |
| **Low** | (enrichment skipped) | `notify` only |

**Invariants** (must not be relaxed without updating the spec): `isolate` is **never**
`requires_approval:false`; `block` is `requires_approval:false` **only** in the single
High+confirmed-IOC cell; `mapping_*` are **not** inputs and can never unlock auto-block.
Blockable types = `ip`, `domain`.

### 4.9 TheHive case creation + automation
- `build_thehive_case_payload()` builds a **rich markdown description** with structured tables:
  **Alert Summary**, **Cortex/MISP Intel** + per-analyzer **verdict table**, **SOAR Actions**,
  **Translator Annotation** (+ parsed Evidence), **Mapping Reason**, **Top Evidence** (XAI
  top-k). Plus a human-scannable title (`[SEV] <lead technique> (Txxxx) p=… flow=…`),
  queryable **custom fields** (`soarModel/Tier/PredProba/Severity/SeverityAdvisory/
  MappingStatus/MappingVersion/MappingConfidence/FlowId/AlertId`), and **tags**
  (TTPs, `MITRE_UNMAPPED*`, `severity:*`, `model:*`). `severity` maps to TheHive 1/2/3;
  `tlp`=`THEHIVE_TLP`. Tasks attached only if `CREATE_THEHIVE_TASKS=true`.
- `create_case(**payload)` (TheHive 5, `X-Organisation` header — **org = `AEGIS`**, the key's
  org; mismatch ⇒ 401). Wrapped in `time_case_creation()` metric.
- `run_case_automation()` then: links MITRE **procedures** (`bulk_create_case_procedures`,
  patternId), attaches **case observables** (`create_case_observable`; ja3 tagged `ja3`,
  dataType "other"), optionally runs **responders** (`should_run_responders`, Tier-0 only),
  and — **only if pre-case enrichment produced no verdicts** — runs Cortex **through TheHive's
  connector** so reports bind to the case observable's Analysis tab. A **Cortex Enrichment
  Summary** task (markdown verdict table) is posted from the already-polled verdicts
  (`POST_CORTEX_SUMMARY_TASK`); tasks auto-completed if `AUTO_COMPLETE_CASE_TASKS=true`.
- **Deferred path:** `TheHiveRecoverableError` ⇒ status `deferred_thehive`, replayable via
  `scripts/retry_deferred_thehive.py`.

### 4.10 §7.1 handoff to Shuffle
`shuffle_client.build_handoff_payload()` produces the exact §7.1 object: `alert{…}`,
`case{thehive_case_id,url}`, `observables[]` (enriched, with `intel_malicious`), `actions[]`
(authoritative), `callback_url`, plus **flat action-hint booleans** (`block_present`,
`block_requires_approval`, `isolate_present`, `isolate_requires_approval`, `notify_present`)
for Shuffle's branch nodes. `post_to_shuffle()` dispatches via Shuffle's **workflow-run API**:
`POST {SHUFFLE_BASE_URL}/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}/run` with
`Authorization: Bearer {SHUFFLE_API_KEY}` and the payload as the JSON-string
`execution_argument` (not a webhook). Dry-run aware.

### 4.11 Persistence of the outcome
`mark_status(status="done", thehive_case_id, playbook_plan={steps, automation, shuffle:
{actions, dispatch}, trigger_source, trigger_event})`. Emits `case_created` and
`shuffle_dispatched` structured logs. Failure paths set `failed`/`deferred_thehive`/`skipped`
and record metrics.

---

## 5. Response enforcement — real, endpoint-routed via Wazuh

Enforcement is **orchestrator-owned and real** (not Shuffle placeholders). Three actuators:

- **Notify → Slack** (`notify_client.py`, `SLACK_WEBHOOK_URL`): real, fail-soft, never gated.
- **Block/Isolate → Wazuh on-demand Active-Response** (`wazuh_response.py`): the orchestrator
  authenticates to the manager API and `PUT /active-response?agents_list=<agent_id>`
  `{"command":"soar-block0","arguments":["<dst_ip>"]}`; the agent runs the vetted local
  script. **Auto-block** (High+confirmed-IOC, managed endpoint) fires immediately; **gated
  block/isolate** fire on analyst approval (§5b). No `agent_id` ⇒ skipped (notify+case only).
- The §7.1 handoff still goes to **Shuffle**, but Shuffle is now a **recorder/visualizer**
  only: its `parse` node always routes to `execute_direct` (records the directive, `urllib`
  POST to the callback). The **User-Input gate is retired** (a gated payload now runs
  `parse → execute_direct → FINISHED`; the gate node is unreachable). The recorded
  `enforced:false, placeholder:true` entries are an audit trail, not the enforcement.

### 5b. The gated-action approval loop (dashboard-mediated)

The Shuffle gate was retired (it was binary — reject aborted the whole run, no in-workflow
log — and left gated runs hung once approval moved to the dashboard). Replacement:

```
gated block/isolate on a managed endpoint
   → orchestrator writes soar_pending_approvals (status=pending, TTL)
      → dashboard lists it (reads the table) → analyst Approve/Reject
         → POST /soar/approve {approval_id, decision, analyst, note}   (token: SOAR_APPROVAL_TOKEN)
            → approve → wazuh_response.block/isolate (REAL) → row executed/failed
              reject  → row rejected (the "reject→log" Shuffle couldn't do)
```

Claim is atomic (`pending → deciding`, no double-execute); rows auto-expire after
`APPROVAL_TTL_SEC`. The dashboard list/buttons are a **detection-side build**; the SOAR side
owns the table + `POST /soar/approve` + `GET /soar/pending-approvals` (token-gated).

---

## 6. Component stack & integrations

| Component | Role | How the orchestrator reaches it | Notes |
|---|---|---|---|
| **TheHive 5** (StrangeBee) | case management | `THEHIVE_BASE_URL` (`:9000/thehive`), `X-Organisation: AEGIS`, Bearer key | org/key must match (else 401); Cortex bundled in the same `deploy/soar/thehive/testing` compose (cassandra, elasticsearch, thehive, cortex, nginx) |
| **Cortex** | analyzer/responder engine | `CORTEX_BASE_URL` (`:9001/cortex`), Bearer key | key org `AEGIS`, roles read/analyze/orgadmin; analyzers activated by `scripts/setup_soar_integrations.py` |
| **MISP** | threat-intel correlation (incl. ja3) | `MISP_URL` via `host.docker.internal:8088` | the only `ja3` analyzer path; `MISP_2_1` activated with `MISP_URL/MISP_API_KEY/MISP_NAME` |
| **Shuffle** (Docker Swarm) | record/visualize the directive (gate retired) | `SHUFFLE_BASE_URL` (`:3001`), `/run` API, Bearer | only Shuffle-Tools `execute_python` worker reliably deployed |
| **Wazuh manager** (manager-only) | endpoint Active-Response channel | `WAZUH_API_URL` (`:55000`), Bearer (JWT) | `deploy/soar/wazuh-manager`; agents enroll at `:1515`, comms `:1516`; AR via `wazuh_response.py` |
| **Endpoint agent** (detection-owned) | NFStream sensor + Wazuh agent + AR scripts | enrolls to the manager | runs `soar-block`/`soar-isolate`; stamps `agent_id`/`host_id`/`host_ip` onto flows |
| **Dashboard** (detection-owned) | notify / approve / Step-6 feedback UI | shared Postgres + orchestrator HTTP | integration is via DB tables + `/soar/*` endpoints; UI is a detection-side task |

**Cortex analyzer tiering** (`integration_config.py`): Tier-0 (no key) vs Tier-1 (free key via
`*_API_KEY` env). The setup script injects keys at activation; `MISP_2_1` is multi-field
(url/key/name/cert_check). Tier-1 keys currently present: VirusTotal, URLhaus, URLscan,
Maltiverse (MaxMind absent). Verdict trust for the §5 gate is restricted to
`INTEL_CONFIRMATION_ANALYZERS`.

---

## 7. Persistence model (SOAR-owned tables, in the shared DB)

All in `db.py`, created idempotently at startup; kept **separate** from the detection-owned
`alerts` table:

1. **`soar_orchestrator_bookkeeping`** — one row per alert (`alert_id` PK). `status` ∈
   `pending/running/done/failed/skipped/deferred_thehive`; `thehive_case_id`; `last_error`;
   `playbook_plan` JSONB (steps, automation summary, shuffle actions+dispatch, trigger source/
   event). This is the **idempotency ledger** and the per-alert audit trail. `pick_next_alert`
   left-joins against it to find unclaimed alerts.
2. **`soar_shuffle_results`** — append-only log of Shuffle's `/soar/shuffle-result` callbacks
   (`flow_id, thehive_case_id, results JSONB, received_ts`). Separate so a retried/duplicate
   callback never clobbers the dispatch record.
3. **`soar_analyst_feedback`** — interim Step-6 store (`true_positive`, `explanation_useful`,
   `flag_for_retraining`, `note`). Columns deliberately named to match the shared `alerts`
   Step-6 columns so a future migration is a straight copy; Step 6's real home is the
   dashboard.
4. **`soar_pending_approvals`** — the gated-action approval queue (`alert_id, flow_id,
   agent_id, action_type, target_value, case_id/url, severity, mitre_ttps, intel_malicious,
   status, requested/expires/decided_ts, analyst, note, ar_result`). Lifecycle
   `pending → deciding → executed|failed|rejected|expired` (atomic claim; TTL).

**`api_server.py`** (Flask, daemon thread, port 8200): `POST /soar/shuffle-result`,
`POST /soar/feedback`, and the approval loop — **`POST /soar/approve`** (token-gated via
`SOAR_APPROVAL_TOKEN`; approve → real `wazuh_response.block/isolate`, reject → logged) and
**`GET /soar/pending-approvals`**. Each request opens its own short-lived DB connection.

---

## 8. Configuration reference (env-var names only — values live in `.env`)

| Group | Vars |
|---|---|
| **DB / trigger** | `DATABASE_URL`, `ENABLE_KAFKA_TRIGGER`, `KAFKA_BROKER`, `SOAR_ALERT_EVENTS_TOPIC`, `SOAR_ALERT_EVENTS_CONSUMER_GROUP`, `SOAR_ALERT_EVENTS_OFFSET_RESET`, `KAFKA_POLL_TIMEOUT_MS`, `KAFKA_MAX_RECORDS`, `KAFKA_RECONNECT_INTERVAL_SEC`, `POLL_INTERVAL_SEC`, `POLL_BATCH_LIMIT`, `DB_RECONNECT_BACKOFF_START_SEC/_MAX_SEC` |
| **TheHive** | `THEHIVE_BASE_URL`, `THEHIVE_ORGANISATION` (= `AEGIS`), `THEHIVE_API_KEY`, `THEHIVE_TLP`, `THEHIVE_PAP`, `THEHIVE_CORTEX_ID`, `CREATE_THEHIVE_TASKS`, `REQUIRE_MAPPED_FOR_THEHIVE`, `REQUIRE_STRICT_MAPPED`, `THEHIVE_PROCEDURE_RETRIES/_BACKOFF_MS` |
| **Cortex/MISP** | `CORTEX_BASE_URL`, `CORTEX_API_KEY`, `CORTEX_<IP\|DOMAIN\|URL\|HASH\|JA3>_ANALYZERS`, `CORTEX_WAIT_SECONDS`, `CORTEX_PRE_CASE_WAIT_SEC`, `CORTEX_SUMMARY_PER_JOB_WAIT_SEC`, `CORTEX_SUMMARY_TOTAL_BUDGET_SEC`, `MAX_CORTEX_RUNS_PER_FLOW`, `MAX_OBSERVABLES_PER_FLOW`, `POST_CORTEX_SUMMARY_TASK`, `INTEL_CONFIRMATION_ANALYZERS`, `MISP_URL/_API_KEY/_NAME/_CERT_CHECK`, Tier-1 keys (`VIRUSTOTAL_API_KEY`, `URLHAUS_API_KEY`, `URLSCAN_API_KEY`, `MALTIVERSE_API_KEY`, `MAXMIND_LICENSE_KEY`) |
| **Decision / enrichment** | `MAPPING_TRUST_MIN_CONFIDENCE`, `SKIP_PRIVATE_IP_OBSERVABLES` (code default true; `.env` sets false), `AUTO_RUN_CORTEX`, `AUTO_LINK_CASE_PROCEDURES`, `AUTO_RUN_RESPONDERS`, `AUTO_COMPLETE_CASE_TASKS`, `CREATE_CASE_OBSERVABLES`, `MAX_CASE_OBSERVABLES`, `MAX_RESPONDERS_PER_FLOW`, `RESPONDER_MATCH_MODE`, `PLAYBOOK_MAX_TECHNIQUES`, `ACTIVE_RESPONSE_MIN_PROBA`, `FORCE_ACTIVE_RESPONSE` |
| **Shuffle handoff** | `SHUFFLE_BASE_URL`, `SHUFFLE_API_KEY`, `SHUFFLE_WORKFLOW_ID`, `SOAR_CALLBACK_BASE_URL`, `ORCHESTRATOR_HTTP_PORT` |
| **Runtime** | `ORCHESTRATOR_DRY_RUN` (false = live), `METRICS_PORT`, `LOG_FORMAT`, `LOG_LEVEL`, `ATTACK_STIX_CACHE_PATH`, `ATTACK_STIX_CACHE_MAX_AGE_SEC` |

---

## 9. Deployment & operations

- **Start the orchestrator (single command):** `scripts/soarctl.sh start orchestrator [--build]`
  (target added to soarctl; not in `core`/`all` — explicit start). Standalone:
  `docker compose -f deploy/soar/orchestrator/docker-compose.yml up -d --build`. Compose:
  build context `services/soar_orchestrator`, `env_file` the `.env`, publishes 8200+9100,
  `attack_stix_cache` volume, `host.docker.internal` extra_host, own bridge net. The
  orchestrator is **decoupled** from the detection compose (removed there).
- **Clone-and-deploy:** `cp services/soar_orchestrator/.env.example .env`, fill keys + the
  detection host IP + the shared `SOAR_APPROVAL_TOKEN`, obtain the vendored stacks, then start
  (full runbook: `deploy/soar/README.md`). Only `.env` is edited; no IPs are hardcoded in code.
- **Start the SOAR stack:** `scripts/soarctl.sh start core` (TheHive + **Cortex** + MISP +
  Shuffle), then **`scripts/soarctl.sh start wazuh-manager`** (the manager-only Wazuh AR
  enforcement channel — its own soarctl target, NOT in `core`/`all`). soarctl manages the
  vendored stacks under `deploy/soar/{thehive,misp,shuffle}` plus our `wazuh-manager`/
  `orchestrator` as separate compose projects.
- **Enable Cortex analyzers:** `scripts/setup_soar_integrations.py --skip-thehive-config`
  (export the orchestrator `.env` first; the script reads repo-root `.env`). Activates Tier-0 +
  any Tier-1 with keys present; idempotent.
- **Ops helpers (both dry-run aware/default):** `scripts/delete_cortex_jobs.sh [--dry-run]
  [--batch-size N]` (batch-deletes Cortex jobs; Cortex may still show stale/soft-deleted
  jobs), `scripts/delete_thehive_cases.sh` (deletes cases safely, **dry-run by default**).
- **Cross-machine Kafka:** detection broker must advertise its **external** listener as the
  detection host IP (`KAFKA_ADVERTISED_LISTENERS=…,EXTERNAL://<DETECTION_HOST_IP>:9094`); SOAR
  `.env` uses `KAFKA_BROKER=<DETECTION_HOST_IP>:9094`. `kafka_events._has_unusable_remote_
  metadata` detects a `localhost`-advertised broker and logs
  `kafka_advertised_listener_unreachable` rather than hanging.
- **Resilience:** the api_server stays up without the DB; the DB reconnects with backoff; Kafka
  is optional (polling fallback always runs); idempotency makes replays safe.

---

## 10. Design decisions & rationale (for the thesis discussion)

| Decision | Rationale |
|---|---|
| **Kafka = trigger, Postgres = source of truth** | low-latency handoff without coupling correctness to a broker; full audit/replay/state stays in Postgres; idempotent so duplicates/replays are safe |
| **Single `process_alert` for both triggers** | one code path → identical behaviour whether Kafka- or poll-driven; polling is a first-class fallback, not a degraded mode |
| **Idempotency via DB claim** (`ON CONFLICT DO NOTHING`) | the simplest correct primitive; survives at-least-once Kafka, offset replays, and poll/Kafka races without distributed locks |
| **Severity re-derived from `pred_proba`** | one authoritative source; decouples SOAR from the translator's advisory thresholds (≥0.85) |
| **Enrichment BEFORE case creation** | Step-5 decisions and the case description both reflect real Cortex/MISP intel; analysts see verdicts inline |
| **Conservative auto-block** (named confirmation allowlist; mapping not an input) | only a dedicated intel source confirming an IOC unlocks the single auto-block cell — avoids automating enforcement off a model/heuristic alone (trust-aware) |
| **Mapping-confidence trust gate** | the thesis's calibrated `mapping_confidence`/`mapping_status` become an operational signal: a tentative TTP is surfaced but can't justify action |
| **Strict mapping gate for cases** | keeps TheHive focused on high-confidence (`mapped`) alerts; relaxable via env |
| **Observable normalization/dedupe + private-IP skip** | fewer wasted analyzer runs, no duplicate enrichment; private IPs are not externally meaningful IOCs (toggle in `.env`) |
| **Analyzer-specific verdict fallbacks** | real intel sources (URLhaus/MISP/CIRCL) don't all populate `summary.taxonomies`; the gate would miss confirmations otherwise |
| **Orchestrator owns enforcement, not Shuffle** | the matrix + real actuators (Slack, Wazuh AR) + the approval loop all live in the orchestrator (it holds the secrets + has reliable egress); Shuffle records/visualizes only |
| **Endpoint-routed response via Wazuh on-demand AR** | enforce on the exact host that produced the flow (precise; the only clean way to isolate); a vetted **pre-registered script allowlist** makes the command channel safe, not an arbitrary-RCE hole |
| **Dashboard-mediated approval (not the Shuffle gate)** | fixes Shuffle's reject-aborts-the-run limitation; gives a real analyst surface + a logged reject + an atomic claim + TTL expiry |

---

## 11. Current state, limitations & known gaps (be honest in the report)

- **Enforcement is REAL now** (notify→Slack, block/isolate→Wazuh AR), but only for **managed
  endpoints** — a flow must carry `agent_id` (an enrolled agent). Replay/in-stack flows have
  no agent ⇒ endpoint enforcement is skipped (notify + case only).
- **AR command name confirmed live:** the API needs the active-response NAME `soar-block0`
  (registered `<command>` + Wazuh's `0` timeout suffix), NOT `soar-block` (1652 "not defined")
  or `!soar-block` (accepted but never relayed). The dispatcher also treats HTTP 200 with
  empty `affected_items` as a failure (the manager returns 200 even when nothing relays).
- **Dashboard approval UI is live** — the SOAR contract (`soar_pending_approvals` +
  `/soar/approve`) is in production; the detection-side dashboard lists and executes approvals.
  Demonstrated in the official simulation: an isolate gated action was approved via the
  dashboard, `ar_executed_ts` was stamped, and Wazuh AR dispatched `soar-isolate0` to agent 005
  within 0s of the decision (decision latency was the 6m 10s human review time, not system
  latency). Remaining gap: **unblock/unisolate** button in the dashboard UI (the orchestrator
  `wazuh_response.unblock/unisolate` functions exist; the UI trigger is pending).
- **Step 6 is interim** on the orchestrator (`/soar/feedback` → `soar_analyst_feedback`);
  destined for the dashboard + shared columns.
- **Auto-block fires reliably on live C2 domains via URLhaus** — no MISP IOC seeding required.
  URLhaus_2_0 is an `INTEL_CONFIRMATION_ANALYZERS` member and confirms domain observables
  directly via the domain-type `_fallback_cortex_verdict` (§4.6). In the official simulation,
  kzaa.co.za was confirmed malicious and auto-block dispatched to agent 005 without any MISP
  event. On **synthetic-dataset** flows the auto-block cell is rarely reached because dataset
  IPs/domains are not in live threat feeds — that is expected, correct behaviour, and a fair
  evaluation point, not a defect.
- **Exfiltration mapping is weaker** than C2 (minority class + signature overlap) — inherited
  from the detection side; relevant when discussing end-to-end TTP fidelity.
- **The detection half lives in a separate repo** — its services (`nfstream`/`inference`/
  `translator`/`producer`/`dashboard`), `utils/`, `model_training/`, and `schema.sql` are **not
  in this repo** (this SOAR repo ships only `soar_orchestrator`). Cross-half changes (e.g. the
  `alerts` Step-6 columns, the `agent_id` field, severity-band alignment) are coordination items.

---

## 12. Roadmap — automated response (status)

1. **Notify real** — ✅ done (Slack via `notify_client.py`).
2. **Block/Isolate real** — ✅ done via **Wazuh on-demand AR** (endpoint-routed; precise +
   reversible + allowlisted), not a central firewall service. Auto-block live; gated via (3).
3. **Dashboard approval loop** — ✅ SOAR side done (`soar_pending_approvals` + token-gated
   `POST /soar/approve` → real Wazuh AR; atomic claim + TTL). **Pending:** the dashboard
   list/Approve-Reject UI (detection-side build; prompt provided).
4. **Lifecycle / next** — dashboard-driven **unblock/unisolate** (the agent scripts +
   `wazuh_response.unblock/unisolate` exist; needs a dashboard action + endpoint); confirm the
   `!` command prefix on first real dispatch; migrate Step 6 to the dashboard + shared columns.
Integration substrate = the shared Postgres (SOAR-owned tables) + the orchestrator HTTP API;
the dashboard UI is a **detection-side coordination** task.

---

## 13. File / module map (SOAR orchestrator)

| File | Responsibility |
|---|---|
| `orchestrator.py` | main loop (Kafka+polling), `process_alert`, case-payload markdown builders, observable parsing, severity gate, DB resilience |
| `kafka_events.py` | event validation/decoding, consumer factory, loopback-advertised-listener guard |
| `case_automation.py` | pre-case enrichment, Cortex verdict logic + analyzer fallbacks, intel verdict aggregation, observable annotation, case procedures/observables/responders/summary task |
| `decision_matrix.py` | §5 matrix — pure `decide_actions` (the auto-block invariants) |
| `severity.py` | `compute_severity(pred_proba)` + thresholds |
| `mapping_trust.py` | `is_ttp_tentative` trust gate |
| `shuffle_client.py` | §7.1 payload builder + action hints + `/run` dispatch (Shuffle now record-only) |
| `notify_client.py` | real Slack notify (Block Kit, fail-soft, severity/dry-run gates) |
| `wazuh_response.py` | Wazuh on-demand AR dispatcher (authenticate + `PUT /active-response`); `block/isolate/unblock/unisolate`; `dispatch_endpoint_actions` (auto-block only) |
| `thehive_client.py` | TheHive 5 REST (cases, procedures, observables, Cortex-via-connector, responders, `X-Organisation`, `thehive_case_url`, `TheHiveRecoverableError`) |
| `cortex_client.py` | Cortex REST (`list_enabled_analyzers`, `resolve_analyzer_id`, `run_analyzer_on_observable` + bounded waitreport) |
| `integration_config.py` | analyzer tier catalogue, Tier-1 credential injection, Cortex-id resolution, startup `validate_integration_settings` |
| `db.py` | the 3 SOAR tables, `claim_alert_for_processing` (idempotency), `pick_next_alert`, `fetch_alert_by_id`, `mark_status`, callback/feedback writers |
| `api_server.py` | Flask: `/soar/shuffle-result`, `/soar/feedback`, and the approval loop — token-gated `/soar/approve` + `/soar/pending-approvals` |
| `playbook_catalog.py` | `build_playbook_plan` (steps/tasks; High-gated active response) |
| `attack_stix_resolver.py` | MITRE ATT&CK STIX bundle cache → technique resolution |
| `metrics.py` / `slog.py` | Prometheus metrics / JSON structured logging (`log_event`) |
| `shuffle/` | importable Shuffle workflow artifact + README |
| `deploy/soar/orchestrator/` | standalone compose + README |
| `deploy/soar/wazuh-manager/` | manager-only Wazuh compose + `config/ossec.conf` (AR command registration) + README |
| `deploy/soar/README.md` | clone-and-deploy runbook; `services/soar_orchestrator/.env.example` is the env template |
| `scripts/{setup_soar_integrations,delete_cortex_jobs,delete_thehive_cases,retry_deferred_thehive}.*` | ops helpers |

---

## 14. Glossary / key identifiers

- **`model_confidence` ≡ `pred_proba`** (no rename; document the equivalence).
- **`intel_malicious`** — conservative confirmation flag (named-analyzer `malicious`).
- **`mapping_status`** ∈ `mapped` / `unmapped_heuristic` / `unmapped`; **`mapping_confidence`**
  ∈ [0,1] (= bootstrap stability from `fmm-2.0.0`).
- **Severity** — env-configurable; deployment **High ≥0.80 / Medium 0.70–0.79 / Low <0.70**
  (spec default High ≥0.90); SOAR-authoritative, `severity_label` advisory.
- **Org** — TheHive & Cortex organisation is **`AEGIS`** (the API keys' org).
- **Shuffle workflow** — "SOAR Response Actions", ID `77913ca2-11ce-4870-9eaf-6ce2ba545374`.
- **Trigger sources** — `kafka` (`alert.translated`) and `postgres_poll` (fallback/replay).
- **Hosts** — detection `172.31.87.134` (Postgres :5432, Kafka :9094); SOAR `172.31.80.148`
  (orchestrator :8200/:9100, TheHive :9000, Cortex :9001, MISP :8088, Shuffle :3001).

---

## 15. Development narrative — how the SOAR half was built (the flow of thought)

Sections §0–14 describe the *current state*; this section reconstructs the *engineering journey*
juncture by juncture so the thesis can describe the process and rationale, not only the result.
Each juncture states the problem it addressed, what was built, and how the design evolved.

**Juncture 1 — Gap analysis against the spec, then build highest-priority-first.** The
orchestrator already created TheHive cases and ran Cortex, so the work began as a **gap analysis**
against `SOAR_WORKFLOW_SPEC.md` + the frozen `alerts` contract, not a rebuild. Implemented in order:
*severity recompute from `pred_proba`* (`severity.py` — the orchestrator becomes the single source
of truth; `severity_label` demoted to advisory); the *mapping-confidence trust gate*
(`mapping_trust.py` — the detection side's calibrated `fmm-2.0.0` confidence becomes an operational
signal: a tentative TTP is surfaced but never alone justifies a block — **the trust-aware thread**);
the *§5 decision matrix* (`decision_matrix.py` — pure function, invariants enforced); the *four
synced adjustments* (severity from `pred_proba`; route observables incl. `ja3`→MISP; the trust gate;
`model_confidence ≡ pred_proba`, no rename); the *conservative intel confirmation* (`intel_malicious`
only on a **named-analyzer** `malicious` verdict); and moving *enrichment BEFORE case creation* so
the case description and the Step-5 decision both see real intel.

**Juncture 2 — The §7.1 handoff and the Shuffle workflow, built live.** Building the
orchestrator→Shuffle handoff and an importable workflow against the running instance surfaced
Shuffle realities that shaped the design: dispatch is the **workflow-run API** (not a webhook);
`$exec` must be `json.loads("""$exec""")`'d (a bare `$exec` injects raw JSON as Python); branches
reference `$node.message.<field>`; the **`http` app worker isn't deployed** (callback done via
`urllib` in `execute_python`); and the **User-Input gate is binary** — *decline aborts the whole run*
(no in-workflow reject log) and an armed gate globally pauses the execution. Block/isolate were
**safe no-op placeholders** at this stage, isolating the "make it real" work to one layer.

**Juncture 3 — Deployment separation and resilience.** The detection side removed the orchestrator
from its compose; the SOAR side made it runnable here (standalone `deploy/soar/orchestrator/` compose
+ a `soarctl` target), reading Postgres **cross-machine** and reaching the local stack by host IP.
Because the DB is cross-machine, **resilience** was added: `api_server`/metrics start *before* the DB;
`connect_with_retry` blocks with backoff rather than crashing; the loop reconnects on loss. (This
proved essential — the cross-machine link flaps when a host idles.)

**Juncture 4 — Bring-up incidents** (TheHive org mismatch, Cortex activation, the Elasticsearch
read-only blank-UI incident) — root-caused and fixed; captured as lessons in §16.

**Juncture 5 — Real automated response.** *Notify→Slack* first (`notify_client.py`),
orchestrator-side (it holds the secret + has reliable egress, unlike the Shuffle worker). Then
*block/isolate→Wazuh on-demand Active-Response*: after weighing a custom agent vs Wazuh vs
Velociraptor (§17), Wazuh was chosen — it provides enrolled agents + mutual auth + a NAT-friendly
command channel + a vetted-script allowlist for free, and its **on-demand AR API** decouples the
trigger from rules (correcting the assumption that Wazuh AR is rule-only). Deployed **manager-only**
(no indexer/dashboard) because the full SIEM would OOM the host. The **endpoint-identity contract**
(`agent_id`/`host_id`/`host_ip` on the flow → the §7.1 `endpoint`) lit up the dormant isolate path
and let SOAR route enforcement to the exact host that produced a flow.

**Juncture 6 — The approval loop (retiring the Shuffle gate).** Because the Shuffle gate aborts on
reject and hangs once approval moves elsewhere, the gated path moved to a **dashboard-mediated loop**:
the orchestrator parks gated actions in `soar_pending_approvals` (atomic claim + TTL); the dashboard
lists them; token-gated `POST /soar/approve` runs the real Wazuh AR on approve or logs the rejection.
Shuffle was simplified to a recorder.

**Juncture 7 — Severity policy tuning.** A ~0.80 flow appeared to produce "no case / no Cortex";
diagnosis showed it was **not a code gap** (Medium *does* create a case + enrich) but the
cross-machine DB being unreachable. Separately, because the model rarely scores ≥0.90, the High band
was lowered (env-configurable) to **≥0.80** so the High cell — the only one emitting a gated block —
fires in the model's real confidence range, making the approval loop demonstrable.

**Juncture 8 — Clone-and-deploy readiness & repo hygiene.** `.env.example` (placeholders + host
vars), a `.gitignore` audit (commit our infra; ignore vendored stacks + secrets + the 335 MB
`soar.zip`), the `deploy/soar/README.md` runbook, and trimming the repo to SOAR-only (removed the
stray detection services and the detection `context.md`).

---

## 16. Operational incidents & lessons learned (hard-won — thesis-relevant)

Strong material for an *Implementation challenges / Discussion* chapter — each is root-caused, fixed,
and generalizable.

**16.1 Elasticsearch flood-stage read-only → "cases created but invisible."** The orchestrator
logged `case_created` with IDs and ran Cortex, yet the TheHive/Cortex UIs showed nothing. Diagnosis:
`GET /case/{id}` (served from **Cassandra**) returned the case, but `listCase`/the UI (served from
**Elasticsearch**) were empty → an ES *indexing* problem, not a creation problem. Root cause: disk at
**97%** (a 12 GB unrotated `producer` log) tripped ES's flood-stage watermark, setting
`thehive_global`/`cortex_6` **read-only**. Fix: truncate logs, clear `read_only_allow_delete`,
`docker system prune`, add global **log rotation** + swap. *Lessons:* TheHive's dual store (Cassandra
of record + ES for search) makes "write succeeds but UI is blank" a real failure mode; watch disk
watermarks; "success but invisible" needs observability beyond HTTP 200.

**16.2 TheHive 401 — organisation mismatch.** Case creation failed `401 AuthenticationError` with a
valid key: the `X-Organisation` header didn't match the key's org (`AEGIS`). *Lesson:* in TheHive 5
the org header must equal the API user's org, and a mismatch is a **401** (not a 403) — easy to
misread as a bad key.

**16.3 Cortex analyzers — permissions + activation.** Cortex listing returned `403 Insufficient
rights` (the key needed org-admin); with a correct key, `setup_soar_integrations.py` activates the
Tier-0 + keyed Tier-1 analyzers. *Lesson:* "0 analyzers enabled" silently makes the auto-block cell
unreachable (no confirmation possible) — activation is a prerequisite, not polish.

**16.4 Shuffle User-Input gate limits → the dashboard loop.** Live testing showed the gate is binary
(decline aborts the entire run, no in-workflow log) and that an armed gate globally pauses execution;
the `http` app worker also wasn't deployed. These concrete limits — not a preference — drove retiring
the Shuffle gate for the orchestrator-owned, dashboard-mediated loop (logged reject, atomic claim, TTL).

**16.5 The Wazuh AR command-name saga (+ a false-success bug).** The dispatcher first sent
`!soar-block` → HTTP 200 but **never relayed**; then `soar-block` → `1652 "command not defined"`;
finally **`soar-block0`** worked — the active-response *name* is the registered command + Wazuh's `0`
timeout suffix (as in the agent's `merged.mg`). This exposed a dispatcher bug: it called any HTTP 200
"dispatched", but the manager returns 200 with empty `affected_items` when nothing relays — fixed to
require the agent in `affected_items`. A later "sent but agent doesn't run" was isolated to the
**agent side** by proving the manager *does* forward (remoted's `sent_breakdown.ar` counter increments
per relayed command) → the agent's own `ossec.conf` must have AR enabled ("execd running" ≠ "AR
enabled"). *Lesson:* Wazuh on-demand AR semantics are subtle; verify **delivery** via daemon stats,
not the API status code.

**16.6 Memory pressure → manager-only Wazuh.** The host already runs TheHive+ES, Cortex, MISP,
Shuffle+OpenSearch; the full Wazuh SIEM (a fourth Elasticsearch-family store) would OOM it. Wazuh was
deployed **manager-only** (~0.7 GB) — used purely as the agent + AR channel, not a SIEM — plus a swap
file. *Lesson:* single-host resource budgeting is a real constraint that shaped the architecture; the
log/event-context (SIEM) role was deliberately deferred.

**16.7 The cross-machine DB flap.** Intermittent "nothing happens" traced to the detection Postgres
being unreachable from the SOAR host. Because processing is idempotent and the orchestrator reconnects
with backoff (and always runs the polling fallback), unprocessed rows are claimed on the next
successful poll — a transient outage pauses but does not drop alerts. *Lesson:* in a two-machine split,
separate **infra outage** from **logic bugs** (the "Medium produces no case" report was the former);
design for at-least-once + idempotency.

---

## 17. Design forks & alternatives considered (the deliberation, for the Discussion chapter)

| Fork | Options weighed | Choice + why |
|---|---|---|
| **Endpoint response mechanism** | custom thin agent · **Wazuh** AR · Velociraptor · central firewall (Cortex responder) | **Wazuh on-demand AR** — reuses agents/mutual-auth/NAT-friendly channel/script-allowlist; a custom agent re-implements security-critical infra; a central firewall can't host-*isolate*; Velociraptor is heavier + a new component |
| **Where enforcement lives** | Shuffle nodes · **orchestrator** | **Orchestrator** — holds the secrets + reliable egress (the Shuffle swarm worker's egress is limited); Shuffle became a recorder/visualizer |
| **Approval gate** | Shuffle User-Input · **dashboard loop** | **Dashboard loop** — the Shuffle gate aborts on reject (no logged decision) and hangs once approval moves to the dashboard; the DB-backed loop gives a real analyst surface + logged reject + atomic claim + TTL |
| **Trigger** | webhook push · **Kafka pointer + Postgres polling** | **Kafka trigger, Postgres source of truth** — low latency without coupling correctness to a broker; polling is a first-class fallback |
| **Wazuh footprint** | full SIEM · **manager-only** | **Manager-only** — memory; only the AR channel is needed; the SIEM/log-context role is deferred |
| **Auto-block trust bar** | any-analyzer-malicious · **named confirmation allowlist** | **Named allowlist** (MISP/VT/URLhaus) + mapping never an input — trust-aware; avoids automating enforcement off a model/heuristic alone |

---

## 18. Evaluation observations & thesis-write-up guidance

**Official simulation results (2026-06-25, two-arm live run):**

Two traffic arms were used:
- **Live adversary arm** (Mythic/Poseidon HTTPS C2 to kzaa.co.za): demonstrated the
  generalization gap — Poseidon HTTPS produced flows at p≈0.50–0.74, below the High threshold.
  One flow crossed High (p=0.996), triggered URLhaus confirmation, and produced an auto-block +
  a gated isolate. This arm's weaker scores are a deliberate thesis finding: the model was
  trained on captured malware PCAPs, and a novel live implant's traffic profile sits closer to
  the decision boundary.
- **PCAP replay arm** (`pcap-replay --class exfil/c2_beaconing`): reliably produced
  p=0.965–1.000 flows from real captured malware, generating the bulk of cases and gated actions.

| Metric | Value |
|---|---|
| Total flows ingested | 735 (1 in-flight at snapshot; effectively 736) |
| Benign / correctly skipped (total) | 67 (50 benign · 9 Low/notify-only · 8 unmapped_heuristic) |
| HIGH-confidence cases (p ≥ 0.80) | 17 |
| TheHive cases created | 17 |
| Pipeline failures | 0 |
| Kafka idempotency skips (redelivery deduped) | 291 |
| Reconnect events (Postgres/Kafka) | 27 |
| Auto-blocks dispatched | 3 (alert\_ids 40, 47, 48) |
| Blocked IPs | `45.56.99.101`, `188.114.97.3` |
| Empty-target blocks | 0 (block-target fix confirmed) |
| Host IP ever blocked | No (safety invariant held) |
| Gated actions queued | 44 pending (28 block + 16 isolate) |
| Human-approved (isolate, dashboard) | 1 (executed immediately, 0.00s enforcement latency) |
| Human decision latency | 369.99s (~6m 10s) |
| **MTTR** (`sent_ts→done_ts`) | **542s** median · 879s p90 · **50s** min · **975s** max · n=17 |
| `process_alert` (claim→done) | 51s median · 71s p90 |
| Throughput | 4.63 alerts/min over 1 088s wall-clock |

**Interpreting the MTTR:** MTTR = `done_ts − sent_ts` (bookkeeping.updated_ts when
`process_alert` completed). For auto-block flows this equals enforcement time; for gated flows
it is time-to-case-and-queue. The 542s median reflects `CORTEX_PRE_CASE_WAIT_SEC` enrichment
hold plus Kafka back-pressure (291 idempotency skips). The 50s minimum is alert_id=40,
an uncontested PCAP-replay flow with no queue wait. Human decision (370s) is a deliberate
trust-gate cost, not a system defect.

**Population note:** All 17 cases in the observation window (≤14:09:33 UTC) came from the
PCAP replay arm. The Poseidon live-C2 arm's one HIGH flow (alert_id=732, kzaa.co.za, p=0.967)
completed at 14:11:46 UTC — just outside the snapshot boundary — and is the primary generalization-gap
demonstration: the model correctly scored most Poseidon flows at p≈0.50–0.74 (below HIGH),
confirming the calibration boundary on novel implant traffic.

**Model confidence distribution (live run):** the live C2 arm (Poseidon HTTPS) produced scores
at the decision boundary (p≈0.50–0.74), demonstrating the generalization gap between training
PCAPs and a novel implant. The PCAP replay arm scored 0.965–1.000. The **High≥0.80** band was
set to match the model's real operating range on training-distribution traffic; this is a correct
operationalisation of the calibrated confidence, not a threshold hack.

**Mapping to thesis chapters (so Codex can place material):**
- *Architecture* → §1–§7 (two-half contract, Kafka+Postgres, the per-alert pipeline, persistence).
- *Implementation* → §3–§5, §15 (lifecycle, the response actuators, the development narrative).
- *Engineering challenges / Discussion* → §16 (incidents) + §17 (design forks).
- *Evaluation* → §18 (the table above; MTTR breakdown; funnel; gated-vs-auto split; generalization gap).
- *Limitations / Future work* → §11–§12 (managed-endpoint-only enforcement, generalization gap
  on novel implants, exfil mapping weakness, unblock/unisolate UI pending, Step-6 migration).

**Claims to make carefully (be honest):** the SOAR half's contribution is the **trust-aware,
human-in-the-loop automated response** that consumes the detection side's calibrated mapping
confidence — *not* a novel detector. Enforcement is real but **managed-endpoint-scoped**
(Wazuh agent 005 only; no network-perimeter control). The auto-block trigger in the live run
used a **real URLhaus-confirmed malicious domain** (kzaa.co.za), not a seeded synthetic IOC —
the intel confirmation path is exercised against genuine threat intelligence. The human-decision
latency (370s) is the deliberate trust-gate cost; enforcement once approved is immediate (0s).
Host-based response carries the inherent limit that a compromised host could kill its own agent
(argue **defense-in-depth**: pair with a network-perimeter control for isolation).
