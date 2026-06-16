"""§7.1 Orchestrator -> Shuffle handoff (SOAR_WORKFLOW_SPEC.md, AUTHORITATIVE schema).

The orchestrator runs Steps 1-4 and the §5 decision matrix, creates the
TheHive case, then POSTs this payload to Shuffle's webhook. Shuffle executes
the `actions` directive as given — it does not re-derive severity, re-run
the matrix, or re-run Cortex.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import requests

from thehive_client import _orchestrator_dry_run

SCHEMA_VERSION = "1.0"


def callback_url() -> str:
    base = os.getenv("SOAR_CALLBACK_BASE_URL", "http://soar_orchestrator:8200").rstrip("/")
    return f"{base}/soar/shuffle-result"


def shuffle_base_url() -> str:
    return os.getenv("SHUFFLE_BASE_URL", "http://shuffle-frontend:3001").rstrip("/")


def shuffle_api_key() -> Optional[str]:
    return os.getenv("SHUFFLE_API_KEY", "").strip() or None


def shuffle_workflow_id() -> Optional[str]:
    return os.getenv("SHUFFLE_WORKFLOW_ID", "").strip() or None


def _action_hints(actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Flat, top-level convenience fields derived from `actions` — not part
    of the documented §7.1 shape, purely so Shuffle's if_else_routing nodes
    have simple booleans to branch on instead of inspecting a JSON array.
    `actions` stays the authoritative source; these are always recomputed
    from it, never set independently.
    """
    by_type = {a.get("type"): a for a in (actions or [])}
    block = by_type.get("block")
    isolate = by_type.get("isolate")
    notify = by_type.get("notify")
    return {
        "block_present": block is not None,
        "block_requires_approval": bool(block.get("requires_approval")) if block else False,
        "isolate_present": isolate is not None,
        "isolate_requires_approval": bool(isolate.get("requires_approval")) if isolate else False,
        "notify_present": notify is not None,
    }


def build_handoff_payload(
    *,
    flow_id: str,
    severity: str,
    model_confidence: float,
    mitre_ttps: List[str],
    mapping_status: str,
    mapping_confidence: float,
    annotation: str,
    intel_malicious: bool,
    intel_score: float,
    thehive_case_id: str,
    thehive_case_url: str,
    observables: List[Dict[str, Any]],
    actions: List[Dict[str, Any]],
    endpoint: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the exact §7.1 payload. Pure function — every field comes from
    an explicit argument, nothing is re-derived here, so this stays a
    faithful mirror of the authoritative schema."""
    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "alert": {
            "flow_id": str(flow_id or ""),
            "severity": severity,
            "model_confidence": round(float(model_confidence or 0.0), 4),
            "mitre_ttps": list(mitre_ttps or []),
            "mapping_status": mapping_status or "unknown",
            "mapping_confidence": round(float(mapping_confidence or 0.0), 4),
            "annotation": annotation or "",
            "intel": {
                "intel_malicious": bool(intel_malicious),
                "intel_score": round(float(intel_score or 0.0), 4),
            },
        },
        "case": {
            "thehive_case_id": str(thehive_case_id or ""),
            "thehive_case_url": thehive_case_url or "",
        },
        "observables": list(observables or []),
        "actions": list(actions or []),
        "callback_url": callback_url(),
    }
    payload.update(_action_hints(actions))
    # Present only when Wazuh/endpoint risk drives an isolate action.
    if endpoint:
        payload["endpoint"] = endpoint
    return payload


def post_to_shuffle(payload: Dict[str, Any], *, timeout: int = 15) -> Dict[str, Any]:
    """Run the §7.1 handoff through Shuffle's workflow-run API. Dry-run
    aware, like the orchestrator's other external clients (TheHive/Cortex).

    Uses POST /api/v1/workflows/{id}/run with `execution_argument` rather
    than a webhook URL — verified directly against the live instance to
    actually execute the workflow, where webhook-trigger activation status
    couldn't be confirmed without the Shuffle UI.
    """
    if _orchestrator_dry_run():
        print("[DRY_RUN] Would run Shuffle workflow with payload:", json.dumps(payload)[:500])
        return {"dry_run": True}

    api_key = shuffle_api_key()
    workflow_id = shuffle_workflow_id()
    if not api_key or not workflow_id:
        return {"error": "SHUFFLE_API_KEY/SHUFFLE_WORKFLOW_ID is not set"}

    url = f"{shuffle_base_url()}/api/v1/workflows/{workflow_id}/run"
    try:
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"execution_argument": json.dumps(payload)},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if resp.status_code not in (200, 201, 202):
        return {"error": f"Shuffle run failed {resp.status_code}: {resp.text[:300]}"}
    data = resp.json() if resp.text else {}
    return {
        "status": "dispatched",
        "http_status": resp.status_code,
        "execution_id": data.get("execution_id"),
    }
