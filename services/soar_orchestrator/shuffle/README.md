# SOAR Response-Action Workflow (Shuffle)

`soar_response_actions.workflow.json` is the importable Shuffle workflow that
executes the orchestrator's §5 decision-matrix **actions** directive, handed off
via the §7.1 payload (`SOAR_WORKFLOW_SPEC.md`). It is architecture **option (a)**:
the orchestrator owns all decisioning; Shuffle only *executes* the directive it
is given — it never re-derives severity, re-runs the matrix, or re-runs Cortex.

- **Workflow ID:** `77913ca2-11ce-4870-9eaf-6ce2ba545374`
- **Trigger:** the orchestrator calls
  `POST {SHUFFLE_BASE_URL}/api/v1/workflows/{id}/run` with the §7.1 payload as
  the `execution_argument` (see `shuffle_client.post_to_shuffle`).

## Graph

```
soar_handoff_webhook ─▶ parse
                          │  approval_required == "false"  ─▶ execute_direct ──▶ (callback POST)
                          │  approval_required == "true"   ─▶ approval_gate (User Input)
                                                                   │ approve ─▶ execute_approved ─▶ (callback POST)
                                                                   └ decline ─▶ (run terminates, enforcement skipped)
```

- **parse** — `json.loads($exec)`; computes `approval_required` =
  `(block_present AND block_requires_approval) OR (isolate_present AND isolate_requires_approval)`.
  Notify is never gated.
- **execute_direct / execute_approved** — enact the directive with **safe no-op
  placeholders** (block/isolate are *recorded with `enforced: false`*, never
  enacted — no firewall/EDR call), then `urllib` **POST** the
  `{flow_id, thehive_case_id, approval_outcome, results[]}` body to `callback_url`
  (the orchestrator's `/soar/shuffle-result`).
- **approval_gate** — Shuffle *User Input* node. Approve continues to
  `execute_approved`; **decline aborts the whole execution** (Shuffle's native
  User-Input semantics), which is the safe default: no enforcement runs.

### Implementation notes (verified live against the instance)

- All logic runs in **Shuffle Tools `execute_python`** nodes. The `http` app
  worker is **not deployed** in this swarm (`dial tcp: lookup http_1-4-0 … no
  such host`), so the callback POST is done with `urllib` inside `execute_python`
  rather than an `http` action node — the shuffle-tools worker is always up.
- Branch conditions reference `$parse.message.<field>` (execute_python output is
  wrapped under `message`).
- `$exec` must be parsed with `json.loads("""$exec""")` — a bare `$exec` injects
  raw JSON as Python (`true`/`false`/`null` become NameErrors).
- **Reject → log:** Shuffle terminates the run on User-Input *decline*, so a
  declined gate produces no callback. The rejection is still captured by the
  orchestrator's pre-dispatch record (the gated action is persisted with
  `requires_approval: true` before hand-off) and the absence of an `executed`
  callback. A fuller "rejected" callback would require a User-Input *decline
  subflow* — left as a follow-up.

## Verified scenarios

| Scenario | Path | Outcome |
|---|---|---|
| notify-only (Medium/Low) | `execute_direct` | notify executed, callback POSTed, FINISHED |
| auto-block (High + confirmed IOC) | `execute_direct` | block placeholder (`enforced:false`) + notify, callback, FINISHED |
| gated-block (High, no confirmation) → approve | `approval_gate` → `execute_approved` | block placeholder + notify, callback, FINISHED |
| gated-block → decline | `approval_gate` abort | run terminates, no enforcement |

## Re-import

The orchestrator references the workflow by **ID**, so re-importing on a fresh
Shuffle keeps the same ID. Import via the Shuffle UI (Workflows → Import) or the
API, then set `SHUFFLE_API_KEY` / `SHUFFLE_WORKFLOW_ID` / `SHUFFLE_BASE_URL` in
`services/soar_orchestrator/.env`. The instance-specific `org_id`/`owner` are
blanked in the artifact and are re-assigned on import.
