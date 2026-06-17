# SOAR Workflow Specification
**Module:** `services/soar_orchestrator`
**Purpose:** Orchestration logic that consumes annotated ML alerts and drives the SOAR response stack (TheHive, Cortex+MISP, Shuffle, optionally Wazuh).
**Audience:** Claude Code (implementation), Shuffle (workflow import reference).

---

## 1. Overview

The SOAR module receives annotated detection alerts from the translator service and orchestrates enrichment, case management, and response actions. The orchestration logic is implemented in two layers:

1. **`soar_orchestrator` service** (Python) — middleware between the translator service and the SOAR components. Handles TheHive case creation, Cortex analyzer invocation, severity logic, and persistence.
2. **Shuffle workflows** — visual automation for response actions (block, isolate, notify) and the manual approval gate.

This document specifies the end-to-end logic. The decision matrix in Section 4 is authoritative — implement those rules exactly.

---

## 2. Component Roles

| Component | Role |
|---|---|
| **Translator service** | Produces annotated alert: confidence, XAI top features, MITRE TTPs, observables. Source of the trigger. |
| **soar_orchestrator** | Parses alert, applies severity logic, calls Cortex, creates TheHive cases, persists state. |
| **TheHive** | Case management — one case per qualifying alert, with tasks and observables. |
| **Cortex + MISP** | Observable enrichment — IP/domain reputation, hash lookup, threat intel correlation. |
| **Shuffle** | Response orchestration — block, isolate, notify, and the manual approval pause gate. |
| **Wazuh** (optional) | Endpoint log analysis and additional context for hosts in flagged flow sessions. Alternative trigger source. |
| **Dashboard** | Analyst interface — notifications, manual approval responses, and feedback labelling (Step 6). |
| **PostgreSQL** | Persistent store — alerts, enrichment results, analyst decisions, retraining labels. |

---

## 3. Trigger

The workflow is triggered by a **new ML alert**, arriving via one of:
- **ML API webhook** — the translator service POSTs the annotated alert to the orchestrator / Shuffle webhook.
- **Wazuh alert** — if Wazuh is integrated, a Wazuh rule match forwards context.

The trigger payload is the annotated alert record (see Step 1 fields).

---

## 4. Workflow Steps

### Step 1 — Parse Alert Fields

**Source of truth = the shared PostgreSQL `alerts` table** (written by the translator, one
row per flagged flow where `model='XGBoost' AND tier='fast'`). Field names below are the
actual column names — read them directly; do not rename. Full contract + producer-side
detail in `context/SYSTEM_OVERVIEW.md`.

- `flow_id` — flow identity
- `pred_proba` — **this is `model_confidence`**, P(malicious) ∈ [0,1] (drives Step 2)
- `pred_label` — 0 benign / 1 malicious
- `observables` (JSONB) — `[{type, value, role}]`; `type ∈ {ip, domain, url, ja3}`,
  `role ∈ {src, dst}`. **`ja3`** carries the TLS client fingerprint (NFStream
  `client_fingerprint`); `server_fingerprint` (JA3S) may also appear. Route to Cortex/MISP
  by `type` (see Step 3).
- `top_k_json` (JSONB) — `xai_top_features`: top-k `[{feature, value, contribution, direction}]`
- `mitre_ttps`, `mitre_names` (JSONB) — mapped ATT&CK technique IDs / names
- `mapping_confidence` (float), `mapping_status` (`mapped`/`unmapped_heuristic`/`unmapped`),
  `mapping_version` — **trust signal for the feature→TTP mapping** (used in Step 4)
- `severity`, `severity_label` — translator's *advisory* severity (see Step 2)
- `annotation` — human-readable SOC explanation

### Step 2 — Severity Classification
The **orchestrator is the authoritative source of severity**, derived from `pred_proba`
(`model_confidence`). The translator's `severity_label` column is *advisory only* — do not
branch on it; recompute here so there is a single source of truth:

| `pred_proba` (model_confidence) | Severity |
|---|---|
| `>= 0.90` | **High** |
| `0.70 – 0.89` | **Medium** |
| `< 0.70` | **Analyst review only** |

> Note: the translator currently labels severity with a different threshold (≥0.85 = HIGH).
> That mismatch is intentional/known — the orchestrator's thresholds above win.

### Step 3 — Enrich Observables (Cortex + MISP)
For High and Medium severity only. Iterate `observables` and route each to its analyzers
by `type` (analyzer lists are in `integration_config.py`):
- `ip` → IP reputation (src and dst)
- `domain` → domain reputation
- `url` → URL analyzers
- `ja3` → **TLS-fingerprint correlation** (MISP `ja3-fingerprint-md5`; malware families
  reuse client JA3s, so this catches encrypted C2 even when IP/domain are clean/rotating)
- file hash, if present → hash lookup
- MISP threat-intel correlation across all of the above

Record the enrichment verdict: `intel_malicious` (bool) and `intel_score`.

**Analyst-review-only (Low) alerts skip enrichment** — they go straight to notification.

### Step 4 — Combine Signals
Compute a combined decision input from:
- `model_confidence` (ML signal)
- `intel_malicious` / `intel_score` (threat intel signal)
- `xai_top_features` + `mitre_ttps` (explanation context)
- `mapping_confidence` / `mapping_status` (**mapping trust signal**) — when
  `mapping_status != "mapped"` or `mapping_confidence` is low, treat the assigned
  `mitre_ttps` as tentative: surface them in the case but do not let an unvalidated TTP
  alone justify an automated block.

This combined view drives Step 5.

### Step 5 — Decide Action
Apply the **Decision Matrix** below. This is authoritative.

### Step 6 — Store Analyst Feedback (asynchronous)
**This is NOT part of the Shuffle detection workflow.** It is a separate endpoint on the dashboard/orchestrator, invoked later when an analyst reviews the alert. Persists to PostgreSQL:
- `true_positive` / `false_positive` label
- `explanation_useful` (bool)
- `flag_for_retraining` (bool)

This data feeds the retraining dataset.

---

## 5. Decision Matrix (Step 5 — AUTHORITATIVE)

| Severity | Cortex/MISP verdict | Actions |
|---|---|---|
| **High** | Malicious IOC confirmed | Auto-block IP/domain (Shuffle) + create case (TheHive) + notify (Slack + Dashboard) |
| **High** | No IOC confirmation | Create case (TheHive) + **request manual approval** before block/isolate + notify |
| **High** | Endpoint risk flagged (Wazuh) | Request manual approval for **isolate endpoint** + create case + notify |
| **Medium** | Any | Create case (TheHive) + notify (Slack + Dashboard). No automated block. |
| **Low** | (enrichment skipped) | Notify analyst only (Dashboard + Slack). No case, no response action. |

### Action definitions
- **Create case (TheHive)** — orchestrator calls TheHive API, attaches observables, MITRE TTPs as procedures, and renders the playbook as tasks.
- **Auto-block IP/domain (Shuffle)** — Shuffle firewall/block-rule app. Fires automatically only in the High + confirmed-IOC case.
- **Isolate endpoint (Shuffle)** — Shuffle containment app. **Always gated behind manual approval.**
- **Notify (Shuffle)** — Slack message + dashboard notification.
- **Request manual approval (Dashboard)** — see Section 6.

---

## 6. Manual Approval Gate (CRITICAL implementation note)

Risky actions (**block**, **isolate**) must NOT fire automatically except in the single auto-block case defined in the matrix. All other block/isolate actions route through a **human approval pause**.

In Shuffle this is implemented with a **User Input trigger node** that:
1. Pauses the workflow.
2. Sends an approval request to Slack and/or the dashboard with alert context.
3. Waits for an `approve` / `reject` response.
4. On `approve` → execute the block/isolate action.
5. On `reject` → skip the action, log the decision, proceed to feedback.

Do not generate a fully automated flow with no human gate for isolate actions.

---

## 7. Implementation Boundaries (for Claude Code)

- **Synchronous detection workflow:** Steps 1–5 run in one pass when an alert arrives.
- **Asynchronous feedback:** Step 6 is a separate dashboard endpoint writing to PostgreSQL. It may be invoked hours after detection. Do NOT make the Shuffle workflow wait for it.
- **soar_orchestrator owns:** alert parsing, severity logic, Cortex calls, TheHive case creation, persistence.
- **Shuffle owns:** block, isolate, notify actions, and the approval pause gate.
- **The orchestrator triggers Shuffle** via Shuffle's webhook for response actions, passing the decision and observables (exact payload in §7.1).

---

## 7.1 Orchestrator → Shuffle Handoff Payload (AUTHORITATIVE)

This is the contract for the chosen architecture: the orchestrator runs Steps 1–4 and the
decision matrix (Step 5), creates the TheHive case, then POSTs this payload to the Shuffle
webhook. **Shuffle executes the `actions` directive as given — it does NOT re-derive
severity, re-run the matrix, or re-run Cortex.** The orchestrator is the single source of
truth for the decision; Shuffle is the action layer.

```jsonc
{
  "schema_version": "1.0",
  "alert": {
    "flow_id": "…",
    "severity": "High | Medium | Low",
    "model_confidence": 0.94,          // = pred_proba
    "mitre_ttps": ["T1071", "T1071.001"],
    "mapping_status": "mapped",        // mapped | unmapped_heuristic | unmapped
    "mapping_confidence": 0.87,
    "annotation": "…",                 // SOC explanation for approval/notify context
    "intel": { "intel_malicious": true, "intel_score": 0.0 }  // Cortex/MISP verdict (Step 3)
  },
  "case": {                            // TheHive case already created by the orchestrator
    "thehive_case_id": "~12345",
    "thehive_case_url": "https://thehive/cases/~12345"
  },
  "observables": [                     // enriched; used as block targets + approval/notify context
    { "type": "ip",     "value": "203.0.113.7", "role": "dst", "intel_malicious": true },
    { "type": "domain", "value": "bad.example",  "role": "dst" },
    { "type": "ja3",    "value": "e7d705a3286e19ea42f587b344ee6865" }
  ],
  "endpoint": {                        // present only when Wazuh/endpoint risk drives isolate
    "host_id": "agent-014", "ip": "10.0.0.14", "source": "wazuh"
  },
  "actions": [                         // AUTHORITATIVE — emitted from the §5 decision matrix
    { "type": "block",   "targets": [{ "type": "ip", "value": "203.0.113.7" }], "requires_approval": false },
    { "type": "isolate", "target": { "host_id": "agent-014" },                  "requires_approval": true  },
    { "type": "notify",  "channels": ["slack", "dashboard"],                    "requires_approval": false }
  ],
  "callback_url": "http://orchestrator:8200/soar/shuffle-result"  // Shuffle POSTs action outcomes back
}
```

### Shuffle execution rules (uniform — no matrix logic in Shuffle)
- Iterate `actions` in order. For each action:
  - `requires_approval: true` → **pause at the §6 User Input node**, send context (alert
    summary, TTPs, case URL) to Slack/dashboard, then: **approve →** execute; **reject →**
    log the decision, skip the action.
  - `requires_approval: false` → execute directly.
- Action semantics: `block` → firewall/block app on `targets`; `isolate` → containment app
  on `endpoint`/`target` (**always arrives with `requires_approval: true`**); `notify` →
  Slack + dashboard message.
- This makes the gate a property of each action, so the matrix lives only in the
  orchestrator. The single auto-block cell (High + confirmed IOC) is the only `block` that
  arrives with `requires_approval: false`; `isolate` is never sent without approval.
- POST a result summary (per-action: executed / approved / rejected / failed) to
  `callback_url` so the orchestrator can persist the outcome.

---

## 8. Reference Flowchart

```mermaid
flowchart TD
    Start([New ML Alert]) --> Trigger{Trigger Source}
    Trigger -->|ML API webhook| Parse
    Trigger -->|Wazuh alert| Parse

    Parse[["Step 1: Parse Alert Fields<br/>src IP, dst IP, domain,<br/>TLS fingerprint, confidence,<br/>XAI top features, MITRE TTPs"]]
    Parse --> Conf{"Step 2:<br/>Confidence Score?"}

    Conf -->|">= 0.90"| High[High Severity]
    Conf -->|"0.70 - 0.89"| Med[Medium Severity]
    Conf -->|"< 0.70"| Low[Analyst Review Only]

    High --> Enrich
    Med --> Enrich
    Low --> NotifyOnly[Notify Analyst<br/>Dashboard + Slack]

    Enrich[["Step 3: Enrich Observables<br/>Cortex + MISP<br/>IP reputation, domain reputation,<br/>hash lookup, threat intel"]]
    Enrich --> Combine

    Combine[["Step 4: Combine Signals<br/>ML confidence +<br/>threat intel +<br/>XAI reasoning"]]
    Combine --> Decide{"Step 5:<br/>Decide Action<br/>(severity + intel)"}

    Decide -->|All qualifying| CreateCase[Create Case<br/>TheHive]
    Decide -->|High + bad intel| AutoBlock[Block IP/Domain<br/>Shuffle]
    Decide -->|High + endpoint risk| Isolate[Isolate Endpoint<br/>Shuffle]
    Decide -->|Risky action| Approval[Request Manual Approval<br/>Dashboard / Slack]
    Decide -->|All qualifying| Notify[Notify Analyst<br/>Slack + Dashboard]

    Approval -->|Approved| AutoBlock
    Approval -->|Approved| Isolate
    Approval -->|Rejected| Feedback

    CreateCase --> Feedback
    AutoBlock --> Feedback
    Isolate --> Feedback
    Notify --> Feedback
    NotifyOnly --> Feedback

    Feedback[["Step 6: Store Analyst Feedback<br/>(asynchronous — dashboard endpoint)<br/>TP / FP label,<br/>explanation useful?,<br/>flag for retraining"]]
    Feedback --> DB[(PostgreSQL<br/>retraining dataset)]
    DB --> End([End])
```

---

## 9. Notes on Wazuh (optional component)

Wazuh is an optional enhancement, not a core dependency. If integrated:
- Acts as an alternative trigger source (Wazuh rule match → orchestrator).
- Provides endpoint-level context for hosts appearing in flagged flow sessions.
- Enables the "endpoint risk flagged" path in the decision matrix (isolate endpoint).

If Wazuh is not deployed, the "isolate endpoint" action and the Wazuh trigger path are simply inactive — the rest of the workflow is unaffected.
