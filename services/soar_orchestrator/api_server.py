"""Lightweight HTTP API for the orchestrator — runs alongside the poll loop.

Two routes:
  POST /soar/shuffle-result  — the §7.1 `callback_url`. Shuffle posts back
      per-action outcomes (executed/approved/rejected/failed) after running
      the actions directive from the handoff payload.
  POST /soar/feedback        — SOAR_WORKFLOW_SPEC.md Step 6 (analyst
      feedback), async and separate from the synchronous Steps 1-5 path.
      Interim only: Step 6's real home is the dashboard once the detection
      side adds the matching columns to the shared `alerts` schema — this
      endpoint just keeps the SOAR side unblocked until then.

Each request opens its own short-lived DB connection (db.get_db()) rather
than sharing the poll loop's long-lived connection across threads.
"""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request

from db import (
    claim_pending_approval,
    ensure_feedback_table,
    ensure_pending_approvals_table,
    ensure_shuffle_results_table,
    finalize_pending_approval,
    get_db,
    get_pending_approval,
    list_pending_approvals,
    record_feedback,
    record_shuffle_result,
)
import wazuh_response
from slog import get_logger, log_event

log = get_logger(__name__)

app = Flask(__name__)

_server_started = False


def start_api_server(port: Optional[int] = None) -> None:
    """Start the Flask listener in a daemon thread. Safe to call repeatedly
    (mirrors metrics.start_metrics_server's idempotency)."""
    global _server_started
    if _server_started:
        return
    p = int(port or os.getenv("ORCHESTRATOR_HTTP_PORT", "8200"))
    thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=p, debug=False, use_reloader=False),
        daemon=True,
        name="soar-api-server",
    )
    thread.start()
    _server_started = True
    log_event("api_server_started", port=p)


def _bad_request(message: str):
    return jsonify({"error": message}), 400


def _approval_token_ok() -> bool:
    """The /soar/approve* routes can trigger real endpoint enforcement, so they
    are token-gated. If SOAR_APPROVAL_TOKEN is set it MUST match (Bearer or
    X-SOAR-Token header); if unset, allow but warn loudly (dev only)."""
    token = os.getenv("SOAR_APPROVAL_TOKEN", "").strip()
    if not token:
        log.warning("approval_token_unset",
                    extra={"event": "approval_token_unset",
                           "msg": "SOAR_APPROVAL_TOKEN is not set — /soar/approve is UNAUTHENTICATED"})
        return True
    auth = request.headers.get("Authorization", "")
    provided = auth[7:].strip() if auth.lower().startswith("bearer ") else \
        request.headers.get("X-SOAR-Token", "").strip()
    return bool(provided) and provided == token


@app.post("/soar/shuffle-result")
def shuffle_result():
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    flow_id = body.get("flow_id")
    results = body.get("results")
    if not flow_id:
        return _bad_request("flow_id is required")
    if not isinstance(results, list):
        return _bad_request("results must be a list")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            ensure_shuffle_results_table(cur)
        conn.commit()
        record_shuffle_result(
            conn,
            flow_id=str(flow_id),
            thehive_case_id=str(body.get("thehive_case_id") or ""),
            results=results,
        )
    except Exception as exc:
        log.error("shuffle_result_failed", extra={"event": "shuffle_result_failed", "error": str(exc)})
        return jsonify({"error": "failed to record shuffle result"}), 500
    finally:
        conn.close()

    log_event("shuffle_result_received", flow=str(flow_id)[:8], n_results=len(results))
    return jsonify({"status": "recorded"}), 200


@app.post("/soar/feedback")
def feedback():
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    flow_id = body.get("flow_id")
    if not flow_id:
        return _bad_request("flow_id is required")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            ensure_feedback_table(cur)
        conn.commit()
        record_feedback(
            conn,
            flow_id=str(flow_id),
            alert_id=body.get("alert_id"),
            true_positive=body.get("true_positive"),
            explanation_useful=body.get("explanation_useful"),
            flag_for_retraining=body.get("flag_for_retraining"),
            note=body.get("note"),
        )
    except Exception as exc:
        log.error("feedback_failed", extra={"event": "feedback_failed", "error": str(exc)})
        return jsonify({"error": "failed to record feedback"}), 500
    finally:
        conn.close()

    log_event("feedback_received", flow=str(flow_id)[:8])
    return jsonify({"status": "recorded"}), 200


@app.get("/soar/pending-approvals")
def pending_approvals():
    """List gated actions awaiting an analyst decision (for the dashboard).
    The dashboard may also read the soar_pending_approvals table directly."""
    if not _approval_token_ok():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    try:
        with conn.cursor() as cur:
            ensure_pending_approvals_table(cur)
        conn.commit()
        rows = list_pending_approvals(conn, limit=int(request.args.get("limit", 100)))
    except Exception as exc:
        log.error("pending_approvals_failed", extra={"event": "pending_approvals_failed", "error": str(exc)})
        return jsonify({"error": "failed to list pending approvals"}), 500
    finally:
        conn.close()
    return jsonify({"pending": rows, "count": len(rows)}), 200


@app.post("/soar/approve")
def approve():
    """Resolve a gated action. Body: {approval_id, decision: approve|reject,
    analyst, note}. On approve, executes the real Wazuh AR on the agent;
    on reject, logs the decision and skips. Idempotent + token-gated."""
    if not _approval_token_ok():
        return jsonify({"error": "unauthorized"}), 401

    body: Dict[str, Any] = request.get_json(silent=True) or {}
    approval_id = body.get("approval_id")
    decision = str(body.get("decision") or "").strip().lower()
    analyst = body.get("analyst")
    note = body.get("note")
    if approval_id is None:
        return _bad_request("approval_id is required")
    try:
        approval_id = int(approval_id)
    except (TypeError, ValueError):
        return _bad_request("approval_id must be an integer")
    if decision not in ("approve", "reject"):
        return _bad_request("decision must be 'approve' or 'reject'")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            ensure_pending_approvals_table(cur)
        conn.commit()

        if get_pending_approval(conn, approval_id) is None:
            return jsonify({"error": "approval not found"}), 404

        # Atomically claim so two concurrent calls can't double-execute.
        row = claim_pending_approval(conn, approval_id)
        if row is None:
            current = get_pending_approval(conn, approval_id)
            return jsonify({"error": "approval is not pending",
                            "status": (current or {}).get("status")}), 409

        if decision == "reject":
            finalize_pending_approval(conn, approval_id, status="rejected", analyst=analyst, note=note)
            log_event("approval_rejected", approval_id=approval_id,
                      flow=str(row.get("flow_id"))[:8], action=row.get("action_type"), analyst=analyst)
            return jsonify({"status": "rejected", "approval_id": approval_id}), 200

        # approve → execute the real endpoint enforcement
        agent_id = row.get("agent_id")
        action_type = row.get("action_type")
        if action_type == "block":
            ar_result = wazuh_response.block(agent_id, str(row.get("target_value") or ""))
        elif action_type == "isolate":
            ar_result = wazuh_response.isolate(agent_id)
        else:
            ar_result = {"error": f"unknown action_type {action_type}"}

        executed = ar_result.get("status") == "dispatched"
        final_status = "executed" if executed else "failed"
        finalize_pending_approval(conn, approval_id, status=final_status,
                                  analyst=analyst, note=note, ar_result=ar_result,
                                  executed=executed)
        log_event("approval_executed", approval_id=approval_id, flow=str(row.get("flow_id"))[:8],
                  action=action_type, agent_id=agent_id, status=final_status, analyst=analyst)
        return jsonify({"status": final_status, "approval_id": approval_id, "ar_result": ar_result}), 200
    except Exception as exc:
        log.error("approve_failed", extra={"event": "approve_failed", "approval_id": approval_id, "error": str(exc)})
        return jsonify({"error": "failed to process approval"}), 500
    finally:
        conn.close()
