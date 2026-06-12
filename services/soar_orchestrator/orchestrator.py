import json
import os
import time
from typing import Any, Dict, List

from attack_stix_resolver import ensure_attack_bundle
from db import get_db, ensure_bookkeeping_table, pick_next_alert, mark_status
from case_automation import run_case_automation
from integration_config import get_configured_analyzers, validate_integration_settings
from playbook_catalog import build_playbook_plan
from thehive_client import (
    create_case,
    _orchestrator_dry_run,
    _normalize_secret,
    TheHiveRecoverableError,
)
from cortex_client import CortexClient
from slog import get_logger, log_event
from metrics import start_metrics_server, record_alert, time_case_creation

log = get_logger(__name__)


MAX_TECHNIQUES = int(os.getenv("PLAYBOOK_MAX_TECHNIQUES", "5"))
ACTIVE_RESPONSE_MIN_PROBA = float(os.getenv("ACTIVE_RESPONSE_MIN_PROBA", "0.80"))
FORCE_ACTIVE_RESPONSE = os.getenv("FORCE_ACTIVE_RESPONSE", "false").lower() == "true"
POLL_INTERVAL_SEC = int(os.getenv("POLL_INTERVAL_SEC", "3"))
CREATE_THEHIVE_TASKS = os.getenv("CREATE_THEHIVE_TASKS", "false").lower() == "true"

_ANALYZERS = get_configured_analyzers()
CORTEX_IP_ANALYZERS = _ANALYZERS["ip"]
CORTEX_DOMAIN_ANALYZERS = _ANALYZERS["domain"]
CORTEX_URL_ANALYZERS = _ANALYZERS["url"]
CORTEX_HASH_ANALYZERS = _ANALYZERS["hash"]

THEHIVE_TLP = int(os.getenv("THEHIVE_TLP", "2"))
THEHIVE_SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
def should_create_thehive_case(alert: Dict[str, Any]) -> tuple[bool, str]:
    """
    TheHive cases are created only for malicious alerts with full MITRE mapping.
    Unmapped or benign flows are recorded in bookkeeping as skipped.
    """
    require_mapped = os.getenv("REQUIRE_MAPPED_FOR_THEHIVE", "true").lower() == "true"
    if not require_mapped:
        pred_label = int(alert.get("pred_label") or 0)
        if pred_label != 1:
            return False, "Benign flow — TheHive case not created"
        if not _orchestrator_dry_run() and not _normalize_secret(os.getenv("THEHIVE_API_KEY")):
            return (
                False,
                "THEHIVE_API_KEY is not set — copy .env.example to .env or set ORCHESTRATOR_DRY_RUN=true for dry-run",
            )
        return True, ""

    pred_label = int(alert.get("pred_label") or 0)
    if pred_label != 1:
        return False, "Benign flow — TheHive case not created"

    # Strict gating (current policy): we only create TheHive cases for alerts
    # whose translator confidently matched at least one explicit MITRE rule
    # (`mapping_status == "mapped"`). The translator still assigns a fallback
    # TTP (`unmapped` -> T1595, `unmapped_heuristic` -> keyword-based TTP) for
    # observability and metrics, but we drop those at the gate to keep TheHive
    # focused on high-confidence alerts.
    #
    # To relax this gate later — e.g. when the analyst team also wants to
    # triage heuristic fallbacks — set REQUIRE_STRICT_MAPPED=false in `.env`
    # / `docker-compose.yml`; the orchestrator will then accept all three
    # statuses (mapped, unmapped_heuristic, unmapped).
    mapping_status = str(alert.get("mapping_status") or "").lower()
    strict = os.getenv("REQUIRE_STRICT_MAPPED", "true").lower() == "true"
    if strict:
        accepted_statuses = {"mapped"}
    else:
        accepted_statuses = {"mapped", "unmapped_heuristic", "unmapped"}
    if mapping_status not in accepted_statuses:
        reason = mapping_status or "unknown"
        suffix = " (strict mode)" if strict else ""
        return False, f"MITRE mapping incomplete (status={reason}) — TheHive case deferred{suffix}"

    if int(alert.get("n_ttps_matched") or 0) < 1:
        return False, "No MITRE techniques matched — TheHive case deferred"

    if not _orchestrator_dry_run() and not _normalize_secret(os.getenv("THEHIVE_API_KEY")):
        return (
            False,
            "THEHIVE_API_KEY is not set — copy .env.example to .env or set ORCHESTRATOR_DRY_RUN=true for dry-run",
        )

    return True, ""


def _ensure_parsed_json(value: Any, default):
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except Exception:
            return default
    return default


def _format_case_title(alert: Dict[str, Any], mitre_ttps: List[str], mitre_names: List[str], pred_proba: float, severity_label: str) -> str:
    """Human-scannable title: severity + lead technique + confidence + short flow id.

    Example: "[HIGH] C2 over Web Protocols (T1071.001) p=0.91 flow=3d7e219e"

    Falls back gracefully when MITRE info or labels are missing so titles
    stay readable across the full alert mix.
    """
    flow = str(alert.get("flow_id") or "unknown")[:8]
    lead_ttp = mitre_ttps[0] if mitre_ttps else None
    lead_name = mitre_names[0] if mitre_names else None
    severity_label = (severity_label or "LOW").upper()
    if lead_ttp and lead_name:
        return f"[{severity_label}] {lead_name} ({lead_ttp}) p={pred_proba:.2f} flow={flow}"
    if lead_ttp:
        return f"[{severity_label}] Threat {lead_ttp} p={pred_proba:.2f} flow={flow}"
    return f"[{severity_label}] Unclassified threat p={pred_proba:.2f} flow={flow}"


def _build_thehive_custom_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Custom fields exposed at the top of the TheHive case, queryable.

    Each value follows TheHive 5's customFields schema: a dict keyed by field
    name with `{type, value}` payload. We use only the standard primitive
    types (`string`, `float`, `integer`, `boolean`) so the case import works
    even if no custom-field definitions were pre-created in the org —
    TheHive will just skip unknown ones rather than reject the case.
    """
    def _f(value, _type: str):
        return {_type: value}

    pred_proba = float(alert.get("pred_proba") or 0.0)
    return {
        "soarModel":            _f(str(alert.get("model") or ""), "string"),
        "soarTier":             _f(str(alert.get("tier") or ""), "string"),
        "soarPredProba":        _f(round(pred_proba, 4), "float"),
        "soarMappingStatus":    _f(str(alert.get("mapping_status") or ""), "string"),
        "soarMappingVersion":   _f(str(alert.get("mapping_version") or ""), "string"),
        "soarMappingConfidence":_f(float(alert.get("mapping_confidence") or 0.0), "float"),
        "soarFlowId":           _f(str(alert.get("flow_id") or ""), "string"),
        "soarAlertId":          _f(int(alert.get("id") or 0), "integer"),
    }


def build_thehive_case_payload(alert: Dict[str, Any], steps: List[Dict[str, Any]]):
    mitre_ttps = _ensure_parsed_json(alert.get("mitre_ttps"), [])
    mitre_names = _ensure_parsed_json(alert.get("mitre_names"), [])
    top_k_json = _ensure_parsed_json(alert.get("top_k_json"), [])

    pred_proba = float(alert.get("pred_proba", 0.0) or 0.0)
    severity_label = alert.get("severity_label") or "LOW"
    severity_int = THEHIVE_SEVERITY_MAP.get(str(severity_label).upper(), 1)
    mapping_confidence = float(alert.get("mapping_confidence", 0.0) or 0.0)
    mapping_version = str(alert.get("mapping_version") or "unknown")
    mapping_status = str(alert.get("mapping_status") or "unknown")
    mapping_reason = str(alert.get("mapping_reason") or "")

    tasks = []
    for s in steps:
        tasks.append(
            {
                "title": s.get("title", "Playbook Step"),
                "description": s.get("description", ""),
                # Group is not guaranteed to exist in every TheHive task schema.
                # It's still useful for readability when supported.
                "group": s.get("group", "Playbook"),
            }
        )

    techniques_line = ", ".join(mitre_ttps[:5]) if mitre_ttps else "Unclassified"
    case_title = _format_case_title(
        alert, mitre_ttps, mitre_names, pred_proba, severity_label
    )

    evidence_lines = []
    for item in top_k_json[:5]:
        feat = item.get("feature")
        contrib = item.get("contribution")
        if feat is None:
            continue
        if isinstance(contrib, (int, float)):
            evidence_lines.append(f"- {feat}: contribution={contrib:.4f}")
        else:
            evidence_lines.append(f"- {feat}")
    evidence_block = "\n".join(evidence_lines) if evidence_lines else "- none"

    description = (
        f"Flow ID: {alert.get('flow_id')}\n"
        f"Prediction: {'MALICIOUS' if alert.get('pred_label') == 1 else 'benign'} "
        f"(proba={pred_proba:.2%})\n"
        f"Severity: {severity_label}\n"
        f"Mapping: status={mapping_status}, confidence={mapping_confidence:.2f}, version={mapping_version}\n"
        f"Matched MITRE Techniques: {techniques_line}\n\n"
        f"Translator Annotation:\n{alert.get('annotation') or ''}\n"
        f"\nMapping Reason:\n{mapping_reason}\n"
        f"\nTop Evidence:\n{evidence_block}\n"
    )

    tags = mitre_ttps[:10] if mitre_ttps else []
    if mapping_status == "unmapped":
        tags.append("MITRE_UNMAPPED")
    elif mapping_status == "unmapped_heuristic":
        tags.append("MITRE_UNMAPPED_HEURISTIC")
    tags.append(f"severity:{str(severity_label).lower()}")
    tags.append(f"model:{str(alert.get('model') or 'unknown')}")

    payload = {
        "title": case_title,
        "description": description,
        "severity": severity_int,
        "tlp": THEHIVE_TLP,
        "tags": tags,
        "custom_fields": _build_thehive_custom_fields(alert),
    }
    if CREATE_THEHIVE_TASKS:
        payload["tasks"] = tasks
    return payload


TECHNIQUE_TO_OBSERVABLE_TYPES: Dict[str, List[str]] = {
    # Your translator maps features to these MITRE techniques.
    # This mapping controls which observable types to enrich via Cortex.
    "T1041": ["ip", "domain", "url"],  # Exfiltration
    "T1071": ["ip", "domain"],  # C2 over application protocols
    "T1071.001": ["ip", "domain", "url"],
    "T1573": ["ip"],  # Encrypted channel often tied to endpoints
    "T1572": ["ip"],
    "T1095": ["ip"],  # Non-application layer protocol
}


def _parse_observables(observables_value: Any) -> List[Dict[str, Any]]:
    if observables_value is None:
        return []
    if isinstance(observables_value, list):
        return [o for o in observables_value if isinstance(o, dict)]
    if isinstance(observables_value, str) and observables_value.strip():
        try:
            parsed = json.loads(observables_value)
            if isinstance(parsed, list):
                return [o for o in parsed if isinstance(o, dict)]
        except Exception:
            return []
    return []


def pick_observable_types(mitre_ttps: List[str]) -> List[str]:
    types = set()
    for t in mitre_ttps or []:
        for ot in TECHNIQUE_TO_OBSERVABLE_TYPES.get(t, []):
            types.add(ot)
    # Default: if nothing matched, still allow basic enrichment.
    if not types:
        types = {"ip"}
    return sorted(types)


def analyzers_for_observable_type(data_type: str) -> List[str]:
    if data_type == "ip":
        return CORTEX_IP_ANALYZERS
    if data_type == "domain":
        return CORTEX_DOMAIN_ANALYZERS
    if data_type == "url":
        return CORTEX_URL_ANALYZERS
    if data_type == "hash":
        return CORTEX_HASH_ANALYZERS
    return []


def _normalize_bom_env_keys() -> None:
    """Fix UTF-8 BOM in env var names from Windows-saved .env (e.g. \\ufeffTHEHIVE_API_KEY)."""
    bom = "\ufeff"
    for key in list(os.environ.keys()):
        if key.startswith(bom):
            clean = key.lstrip(bom)
            if clean:
                os.environ.setdefault(clean, os.environ[key])
            del os.environ[key]


def main():
    _normalize_bom_env_keys()
    start_metrics_server()           # Prometheus /metrics on :METRICS_PORT
    conn = get_db()
    with conn.cursor() as cur:
        ensure_bookkeeping_table(cur)
    conn.commit()

    log_event("orchestrator_started")
    integration = validate_integration_settings()
    log_event(
        "integration_status",
        cortex_id=integration.get("thehive_cortex_id"),
        cortex_analyzers_enabled=integration.get("cortex_analyzers_enabled"),
    )
    for warning in integration.get("warnings") or []:
        log.warning("integration_warning", extra={"event": "integration_warning", "warning": warning})
    try:
        p = ensure_attack_bundle()
        log_event("attack_stix_cached", path=str(p))
    except Exception as e:
        log.warning(
            "attack_stix_prefetch_failed",
            extra={"event": "attack_stix_prefetch_failed", "error": str(e)},
        )
    cortex = CortexClient()
    while True:
        try:
            alerts = pick_next_alert(conn, limit=5)
            if not alerts:
                time.sleep(POLL_INTERVAL_SEC)
                continue

            for alert in alerts:
                alert_id = int(alert["id"])
                flow_id = str(alert["flow_id"])
                model = str(alert.get("model") or "unknown")

                mark_status(conn, alert_id, flow_id, model, status="running")

                try:
                    create_case_ok, skip_reason = should_create_thehive_case(alert)
                    if not create_case_ok:
                        mark_status(
                            conn,
                            alert_id,
                            flow_id,
                            model,
                            status="skipped",
                            last_error=skip_reason,
                            playbook_plan={"skip_reason": skip_reason},
                        )
                        record_alert(status="skipped", model=model)
                        log_event(
                            "alert_skipped",
                            alert_id=alert_id,
                            flow=flow_id[:8],
                            reason=skip_reason,
                        )
                        continue

                    mitre_ttps = _ensure_parsed_json(alert.get("mitre_ttps"), [])
                    mitre_names = _ensure_parsed_json(alert.get("mitre_names"), [])
                    top_k_json = _ensure_parsed_json(alert.get("top_k_json"), [])
                    observables = _parse_observables(alert.get("observables"))

                    playbook_plan = build_playbook_plan(
                        mitre_ttps=mitre_ttps,
                        mitre_names=mitre_names,
                        severity_label=alert.get("severity_label"),
                        pred_proba=float(alert.get("pred_proba") or 0.0),
                        top_k_json=top_k_json,
                        n_ttps_matched=int(alert.get("n_ttps_matched") or 0),
                        max_techniques=MAX_TECHNIQUES,
                        active_response_min_proba=ACTIVE_RESPONSE_MIN_PROBA,
                        force_active_response=FORCE_ACTIVE_RESPONSE,
                        mapping_status=str(alert.get("mapping_status") or ""),
                    )

                    payload = build_thehive_case_payload(alert, playbook_plan)

                    with time_case_creation():
                        case_id = create_case(**payload)

                    automation = run_case_automation(
                        case_id=str(case_id),
                        alert=alert,
                        mitre_ttps=mitre_ttps,
                        observables=observables,
                        cortex=cortex,
                        pick_observable_types=pick_observable_types,
                        analyzers_for_observable_type=analyzers_for_observable_type,
                    )

                    mark_status(
                        conn,
                        alert_id,
                        flow_id,
                        model,
                        status="done",
                        thehive_case_id=case_id,
                        playbook_plan={
                            "steps": playbook_plan,
                            "automation": automation,
                        },
                    )

                    record_alert(status="done", model=model)
                    log_event(
                        "case_created",
                        alert_id=alert_id,
                        case_id=case_id,
                        procedures=len(automation.get("procedures") or []),
                        responders=len(automation.get("responder_runs") or []),
                        cortex=len(automation.get("cortex_results") or []),
                        tasks_completed=len(automation.get("completed_task_ids") or []),
                        cortex_summary_task=automation.get("cortex_summary_task_id"),
                    )
                except TheHiveRecoverableError as e:
                    mark_status(
                        conn,
                        alert_id,
                        flow_id,
                        model,
                        status="deferred_thehive",
                        last_error=str(e),
                    )
                    record_alert(status="deferred_thehive", model=model)
                    log.warning(
                        "alert_deferred",
                        extra={
                            "event": "alert_deferred",
                            "alert_id": alert_id,
                            "flow": flow_id[:8],
                            "reason": str(e),
                            "replay_with": "python scripts/retry_deferred_thehive.py",
                        },
                    )
                except Exception as e:
                    mark_status(
                        conn,
                        alert_id,
                        flow_id,
                        model,
                        status="failed",
                        last_error=str(e),
                    )
                    record_alert(status="failed", model=model)
                    log.error(
                        "alert_failed",
                        extra={"event": "alert_failed", "alert_id": alert_id, "error": str(e)},
                    )
        except Exception as outer_e:
            # If something temporary fails (DB disconnect), wait and retry.
            log.error(
                "outer_failure",
                extra={"event": "outer_failure", "error": str(outer_e)},
            )
            time.sleep(3)
            try:
                conn.close()
            except Exception:
                pass
            conn = get_db()


if __name__ == "__main__":
    main()

