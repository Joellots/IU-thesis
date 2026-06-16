import json
import os
import time
from typing import Any, Dict, List

from api_server import start_api_server
from attack_stix_resolver import ensure_attack_bundle
from db import (
    get_db,
    ensure_bookkeeping_table,
    ensure_feedback_table,
    ensure_shuffle_results_table,
    pick_next_alert,
    mark_status,
)
from case_automation import run_case_automation
from decision_matrix import decide_actions
from integration_config import get_configured_analyzers, validate_integration_settings
from playbook_catalog import build_playbook_plan
from severity import compute_severity, SEVERITY_LOW
from shuffle_client import build_handoff_payload, post_to_shuffle
from thehive_client import (
    create_case,
    thehive_case_url,
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
CORTEX_JA3_ANALYZERS = _ANALYZERS["ja3"]

THEHIVE_TLP = int(os.getenv("THEHIVE_TLP", "2"))
THEHIVE_SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
def should_create_thehive_case(alert: Dict[str, Any]) -> tuple[bool, str]:
    """
    TheHive cases are created only for malicious, non-Low-severity alerts
    with full MITRE mapping. Benign, Low-severity (analyst-review-only per
    Step 2), and unmapped flows are recorded in bookkeeping as skipped.
    """
    pred_label = int(alert.get("pred_label") or 0)
    if pred_label != 1:
        return False, "Benign flow — TheHive case not created"

    pred_proba = float(alert.get("pred_proba") or 0.0)
    severity = compute_severity(pred_proba)
    if severity == SEVERITY_LOW:
        return False, (
            f"Severity={severity} (pred_proba={pred_proba:.2f}) — "
            "analyst-review-only per Step 2 thresholds; notify only, no case"
        )

    require_mapped = os.getenv("REQUIRE_MAPPED_FOR_THEHIVE", "true").lower() == "true"
    if not require_mapped:
        if not _orchestrator_dry_run() and not _normalize_secret(os.getenv("THEHIVE_API_KEY")):
            return (
                False,
                "THEHIVE_API_KEY is not set — copy .env.example to .env or set ORCHESTRATOR_DRY_RUN=true for dry-run",
            )
        return True, ""

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


def _format_case_title(alert: Dict[str, Any], mitre_ttps: List[str], mitre_names: List[str], pred_proba: float, severity: str) -> str:
    """Human-scannable title: severity + lead technique + confidence + short flow id.

    Example: "[HIGH] C2 over Web Protocols (T1071.001) p=0.91 flow=3d7e219e"

    Falls back gracefully when MITRE info or labels are missing so titles
    stay readable across the full alert mix.
    """
    flow = str(alert.get("flow_id") or "unknown")[:8]
    lead_ttp = mitre_ttps[0] if mitre_ttps else None
    lead_name = mitre_names[0] if mitre_names else None
    severity = (severity or "Low").upper()
    if lead_ttp and lead_name:
        return f"[{severity}] {lead_name} ({lead_ttp}) p={pred_proba:.2f} flow={flow}"
    if lead_ttp:
        return f"[{severity}] Threat {lead_ttp} p={pred_proba:.2f} flow={flow}"
    return f"[{severity}] Unclassified threat p={pred_proba:.2f} flow={flow}"


def _build_thehive_custom_fields(alert: Dict[str, Any], severity: str) -> Dict[str, Any]:
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
        "soarSeverity":         _f(severity, "string"),
        "soarSeverityAdvisory": _f(str(alert.get("severity_label") or ""), "string"),
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
    severity = compute_severity(pred_proba)
    severity_int = THEHIVE_SEVERITY_MAP.get(severity.upper(), 1)
    severity_label = alert.get("severity_label") or "LOW"  # translator's advisory label — traceability only
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
        alert, mitre_ttps, mitre_names, pred_proba, severity
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
        f"Severity: {severity} (translator advisory: {severity_label})\n"
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
    tags.append(f"severity:{severity.lower()}")
    tags.append(f"model:{str(alert.get('model') or 'unknown')}")

    payload = {
        "title": case_title,
        "description": description,
        "severity": severity_int,
        "tlp": THEHIVE_TLP,
        "tags": tags,
        "custom_fields": _build_thehive_custom_fields(alert, severity),
    }
    if CREATE_THEHIVE_TASKS:
        payload["tasks"] = tasks
    return payload


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


def analyzers_for_observable_type(data_type: str) -> List[str]:
    if data_type == "ip":
        return CORTEX_IP_ANALYZERS
    if data_type == "domain":
        return CORTEX_DOMAIN_ANALYZERS
    if data_type == "url":
        return CORTEX_URL_ANALYZERS
    if data_type == "hash":
        return CORTEX_HASH_ANALYZERS
    if data_type == "ja3":
        return CORTEX_JA3_ANALYZERS
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
    start_api_server()                # /soar/shuffle-result + /soar/feedback on :ORCHESTRATOR_HTTP_PORT
    conn = get_db()
    with conn.cursor() as cur:
        ensure_bookkeeping_table(cur)
        ensure_shuffle_results_table(cur)
        ensure_feedback_table(cur)
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
                    mitre_ttps = _ensure_parsed_json(alert.get("mitre_ttps"), [])
                    mitre_names = _ensure_parsed_json(alert.get("mitre_names"), [])
                    top_k_json = _ensure_parsed_json(alert.get("top_k_json"), [])
                    observables = _parse_observables(alert.get("observables"))
                    pred_proba = float(alert.get("pred_proba") or 0.0)
                    severity = compute_severity(pred_proba)
                    pred_label = int(alert.get("pred_label") or 0)

                    create_case_ok, skip_reason = should_create_thehive_case(alert)
                    if not create_case_ok:
                        # Step 5 Low row: still notify, even with no case and no
                        # enrichment. Other skip reasons (benign, unmapped under
                        # the strict gate, missing API key) get no dispatch.
                        shuffle_dispatch = None
                        if pred_label == 1 and severity == SEVERITY_LOW:
                            actions = decide_actions(severity=severity, intel_malicious=False)
                            shuffle_payload = build_handoff_payload(
                                flow_id=flow_id,
                                severity=severity,
                                model_confidence=pred_proba,
                                mitre_ttps=mitre_ttps,
                                mapping_status=str(alert.get("mapping_status") or "unknown"),
                                mapping_confidence=float(alert.get("mapping_confidence") or 0.0),
                                annotation=str(alert.get("annotation") or ""),
                                intel_malicious=False,
                                intel_score=0.0,
                                thehive_case_id="",
                                thehive_case_url="",
                                observables=observables,
                                actions=actions,
                            )
                            shuffle_dispatch = post_to_shuffle(shuffle_payload)
                        mark_status(
                            conn,
                            alert_id,
                            flow_id,
                            model,
                            status="skipped",
                            last_error=skip_reason,
                            playbook_plan={"skip_reason": skip_reason, "shuffle_dispatch": shuffle_dispatch},
                        )
                        record_alert(status="skipped", model=model)
                        log_event(
                            "alert_skipped",
                            alert_id=alert_id,
                            flow=flow_id[:8],
                            reason=skip_reason,
                            notified=shuffle_dispatch is not None,
                        )
                        continue

                    playbook_plan = build_playbook_plan(
                        mitre_ttps=mitre_ttps,
                        mitre_names=mitre_names,
                        severity=severity,
                        severity_label=alert.get("severity_label"),
                        pred_proba=pred_proba,
                        top_k_json=top_k_json,
                        n_ttps_matched=int(alert.get("n_ttps_matched") or 0),
                        max_techniques=MAX_TECHNIQUES,
                        active_response_min_proba=ACTIVE_RESPONSE_MIN_PROBA,
                        force_active_response=FORCE_ACTIVE_RESPONSE,
                        mapping_status=str(alert.get("mapping_status") or ""),
                    )

                    case_payload = build_thehive_case_payload(alert, playbook_plan)

                    with time_case_creation():
                        case_id = create_case(**case_payload)

                    automation = run_case_automation(
                        case_id=str(case_id),
                        alert=alert,
                        mitre_ttps=mitre_ttps,
                        observables=observables,
                        cortex=cortex,
                        analyzers_for_observable_type=analyzers_for_observable_type,
                    )

                    intel_malicious = bool(automation.get("intel_malicious"))
                    intel_score = float(automation.get("intel_score") or 0.0)
                    enriched_observables = automation.get("enriched_observables") or observables

                    actions = decide_actions(
                        severity=severity,
                        intel_malicious=intel_malicious,
                        observables=enriched_observables,
                        # Wazuh isn't wired as a trigger source yet (spec §9) —
                        # endpoint risk stays dormant until a real signal exists.
                        endpoint_risk=False,
                        endpoint=None,
                    )
                    shuffle_payload = build_handoff_payload(
                        flow_id=flow_id,
                        severity=severity,
                        model_confidence=pred_proba,
                        mitre_ttps=mitre_ttps,
                        mapping_status=str(alert.get("mapping_status") or "unknown"),
                        mapping_confidence=float(alert.get("mapping_confidence") or 0.0),
                        annotation=str(alert.get("annotation") or ""),
                        intel_malicious=intel_malicious,
                        intel_score=intel_score,
                        thehive_case_id=str(case_id),
                        thehive_case_url=thehive_case_url(str(case_id)),
                        observables=enriched_observables,
                        actions=actions,
                    )
                    shuffle_dispatch = post_to_shuffle(shuffle_payload)

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
                            "shuffle": {"actions": actions, "dispatch": shuffle_dispatch},
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
                    log_event(
                        "shuffle_dispatched",
                        alert_id=alert_id,
                        case_id=case_id,
                        severity=severity,
                        actions=[a["type"] for a in actions],
                        intel_malicious=intel_malicious,
                        dispatch_status=shuffle_dispatch.get("status")
                        or shuffle_dispatch.get("error")
                        or ("dry_run" if shuffle_dispatch.get("dry_run") else "unknown"),
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

