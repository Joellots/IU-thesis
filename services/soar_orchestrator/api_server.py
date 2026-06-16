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
    ensure_feedback_table,
    ensure_shuffle_results_table,
    get_db,
    record_feedback,
    record_shuffle_result,
)
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
