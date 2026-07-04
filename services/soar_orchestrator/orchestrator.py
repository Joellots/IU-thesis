import ipaddress
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)

from api_server import start_api_server
from attack_stix_resolver import ensure_attack_bundle
from db import (
    get_db,
    ensure_bookkeeping_table,
    ensure_feedback_table,
    ensure_pending_approvals_table,
    ensure_shuffle_results_table,
    pick_next_alert,
    fetch_alert_by_id,
    claim_alert_for_processing,
    mark_status,
    stamp_bookkeeping_ts,
    record_pending_approval,
)
from case_automation import run_case_automation, run_pre_case_enrichment
from decision_matrix import decide_actions
from integration_config import get_configured_analyzers, validate_integration_settings
from kafka_events import decode_soar_alert_event, make_soar_alert_consumer
from notify_client import send_slack_notification
from wazuh_response import dispatch_endpoint_actions
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
POLL_BATCH_LIMIT = int(os.getenv("POLL_BATCH_LIMIT", "5"))
# Alerts are claimed on the main loop's connection (cheap, immediate) but
# processed (enrichment/case/dispatch — the slow part) on a worker pool, each
# with its own short-lived DB connection, so one slow alert doesn't delay the
# next claim. See _process_alert_async / _connect_db_with_retry.
ORCHESTRATOR_WORKER_COUNT = int(os.getenv("ORCHESTRATOR_WORKER_COUNT", "4"))
ENABLE_KAFKA_TRIGGER = os.getenv("ENABLE_KAFKA_TRIGGER", "true").lower() == "true"
KAFKA_POLL_TIMEOUT_MS = int(os.getenv("KAFKA_POLL_TIMEOUT_MS", "1000"))
KAFKA_MAX_RECORDS = int(os.getenv("KAFKA_MAX_RECORDS", "10"))
KAFKA_RECONNECT_INTERVAL_SEC = float(os.getenv("KAFKA_RECONNECT_INTERVAL_SEC", "10"))
CREATE_THEHIVE_TASKS = os.getenv("CREATE_THEHIVE_TASKS", "false").lower() == "true"

_ANALYZERS = get_configured_analyzers()
CORTEX_IP_ANALYZERS = _ANALYZERS["ip"]
CORTEX_DOMAIN_ANALYZERS = _ANALYZERS["domain"]
CORTEX_URL_ANALYZERS = _ANALYZERS["url"]
CORTEX_HASH_ANALYZERS = _ANALYZERS["hash"]
CORTEX_JA3_ANALYZERS = _ANALYZERS["ja3"]

THEHIVE_TLP = int(os.getenv("THEHIVE_TLP", "2"))
THEHIVE_SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# The detection Postgres is cross-machine, so transient unavailability is
# expected (restarts, network blips). Never let it take the process down —
# api_server (Shuffle callbacks + Step-6 feedback) must keep serving while we
# wait for the DB to come back.
DB_RECONNECT_BACKOFF_START_SEC = float(os.getenv("DB_RECONNECT_BACKOFF_START_SEC", "2"))
DB_RECONNECT_BACKOFF_MAX_SEC = float(os.getenv("DB_RECONNECT_BACKOFF_MAX_SEC", "30"))

# Gated block/isolate are parked for analyst approval (dashboard loop) for this
# long before they auto-expire and can no longer be executed.
APPROVAL_TTL_SEC = int(os.getenv("APPROVAL_TTL_SEC", "1800"))  # 30 min


def ensure_tables(conn) -> None:
    """(Re)create the orchestrator-owned bookkeeping tables. Idempotent
    (CREATE TABLE IF NOT EXISTS), so it's safe to run on every (re)connect."""
    with conn.cursor() as cur:
        ensure_bookkeeping_table(cur)
        ensure_shuffle_results_table(cur)
        ensure_feedback_table(cur)
        ensure_pending_approvals_table(cur)
    conn.commit()


def _connect_db_with_retry() -> tuple[Any, int]:
    """Block until a fresh DB connection is available, retrying with capped
    exponential backoff. Never raises. Returns (conn, attempts) — callers
    that don't care how many attempts it took (the worker pool) can discard
    the count; connect_with_retry uses it to decide whether to log a
    reconnect event."""
    backoff = DB_RECONNECT_BACKOFF_START_SEC
    attempt = 0
    while True:
        attempt += 1
        try:
            return get_db(), attempt
        except Exception as e:
            log.warning(
                "db_connect_retry",
                extra={"event": "db_connect_retry", "attempt": attempt,
                       "retry_in_sec": backoff, "error": str(e)},
            )
            time.sleep(backoff)
            backoff = min(backoff * 2, DB_RECONNECT_BACKOFF_MAX_SEC)


def connect_with_retry():
    """Block until the DB is reachable, retrying with capped exponential
    backoff. Runs the table setup once connected. Returns a live connection.
    Never raises — the process stays up (and api_server keeps serving) for as
    long as the cross-machine Postgres is unavailable."""
    conn, attempt = _connect_db_with_retry()
    ensure_tables(conn)
    if attempt > 1:
        log_event("db_reconnected", attempts=attempt)
    return conn


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


def _md_cell(value: Any, *, limit: int = 160) -> str:
    text = str(value if value is not None else "").strip()
    if not text:
        return "-"
    text = text.replace("|", "\\|").replace("\r\n", "\n").replace("\n", "<br>")
    if len(text) > limit:
        text = text[: max(0, limit - 3)].rstrip() + "..."
    return text


def _format_cortex_verdict_table(verdicts: List[Dict[str, Any]] | None) -> str:
    rows = [
        "| Observable | Type | Analyzer | Verdict | Taxonomies |",
        "|---|---|---|---|---|",
    ]
    for item in (verdicts or [])[:30]:
        rows.append(
            "| {observable} | {otype} | {analyzer} | {verdict} | {tax} |".format(
                observable=_md_cell(item.get("observable_value"), limit=80),
                otype=_md_cell(item.get("observable_type"), limit=24),
                analyzer=_md_cell(item.get("analyzer_name"), limit=60),
                verdict=_md_cell(item.get("verdict") or "unknown", limit=32),
                tax=_md_cell(item.get("taxonomies"), limit=180),
            )
        )
    if len(rows) == 2:
        rows.append("| - | - | - | not run | No Cortex/MISP verdicts were available before case creation. |")
    return "\n".join(rows)


def _format_actions_table(actions: List[Dict[str, Any]] | None) -> str:
    rows = ["| Action | Approval | Target |", "|---|---|---|"]
    for action in actions or []:
        approval = "required" if action.get("requires_approval") else "not required"
        # block uses "targets" (list of {type, value}); isolate/notify use "target" (scalar/dict).
        targets_list = action.get("targets") or []
        if targets_list:
            target: Any = ", ".join(
                str(t.get("value") or "?") for t in targets_list if isinstance(t, dict)
            ) or "-"
        else:
            target = action.get("target") or action.get("observable") or action.get("endpoint") or "-"
        rows.append(
            f"| {_md_cell(action.get('type', 'unknown'), limit=40)} | "
            f"{_md_cell(approval, limit=24)} | {_md_cell(target, limit=100)} |"
        )
    if len(rows) == 2:
        rows.append("| none | - | - |")
    return "\n".join(rows)


def _split_annotation(annotation: Any) -> tuple[str, List[str]]:
    lines = [line.strip() for line in str(annotation or "").replace("\r\n", "\n").split("\n")]
    summary: List[str] = []
    evidence: List[str] = []
    in_evidence = False
    for line in lines:
        if not line:
            continue
        if line.lower().rstrip(":") == "evidence":
            in_evidence = True
            continue
        if in_evidence:
            evidence.append(line.lstrip("-•* ").strip())
        else:
            summary.append(line)
    return "<br>".join(summary) if summary else "-", evidence


def _format_translator_annotation_table(alert: Dict[str, Any], techniques_line: str, mapping_status: str, mapping_confidence: float) -> str:
    summary, evidence = _split_annotation(alert.get("annotation"))
    rows = [
        "| Field | Value |",
        "|---|---|",
        f"| Detection summary | {_md_cell(summary, limit=600)} |",
        f"| Model | {_md_cell(alert.get('model'), limit=80)} |",
        f"| Tier | {_md_cell(alert.get('tier'), limit=40)} |",
        f"| MITRE ATT&CK | {_md_cell(techniques_line, limit=180)} |",
        f"| Mapping | status={_md_cell(mapping_status, limit=40)}, confidence={mapping_confidence:.2f} |",
    ]
    if evidence:
        rows.extend(["", "| # | Evidence |", "|---|---|"])
        for idx, item in enumerate(evidence[:5], start=1):
            rows.append(f"| {idx} | {_md_cell(item, limit=500)} |")
    return "\n".join(rows)


def _format_mapping_reason_table(mapping_reason: str) -> str:
    text = str(mapping_reason or "").strip()
    rows = ["| Field | Value |", "|---|---|"]
    if not text:
        rows.append("| Mapping reason | - |")
        return "\n".join(rows)
    parts = [part.strip() for part in text.split(";") if part.strip()]
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            rows.append(f"| {_md_cell(key.strip().replace('_', ' ').title(), limit=80)} | {_md_cell(value.strip(), limit=500)} |")
        else:
            rows.append(f"| Detail | {_md_cell(part, limit=500)} |")
    return "\n".join(rows)


def _format_top_evidence_table(top_k_json: List[Dict[str, Any]]) -> str:
    rows = ["| Feature | Contribution |", "|---|---:|"]
    for item in top_k_json[:5]:
        feat = item.get("feature")
        if feat is None:
            continue
        contrib = item.get("contribution")
        contrib_text = f"{contrib:.4f}" if isinstance(contrib, (int, float)) else _md_cell(contrib, limit=80)
        rows.append(f"| {_md_cell(feat, limit=180)} | {contrib_text} |")
    if len(rows) == 2:
        rows.append("| - | - |")
    return "\n".join(rows)


def build_thehive_case_payload(
    alert: Dict[str, Any],
    steps: List[Dict[str, Any]],
    *,
    intel_malicious: bool = False,
    intel_score: float = 0.0,
    actions: List[Dict[str, Any]] | None = None,
    cortex_verdicts: List[Dict[str, Any]] | None = None,
):
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

    top_evidence_table = _format_top_evidence_table(top_k_json)

    intel_status = "confirmed malicious IOC" if intel_malicious else "no confirmed malicious IOC"
    prediction = "MALICIOUS" if int(alert.get("pred_label") or 0) == 1 else "benign"
    summary_table = "\n".join([
        "| Field | Value |",
        "|---|---|",
        f"| Flow ID | `{_md_cell(alert.get('flow_id'), limit=96)}` |",
        f"| Prediction | **{prediction}** ({pred_proba:.2%}) |",
        f"| Severity | **{severity}** (translator advisory: {_md_cell(severity_label, limit=24)}) |",
        f"| MITRE Techniques | {_md_cell(techniques_line, limit=160)} |",
        f"| Mapping | status={_md_cell(mapping_status, limit=40)}, confidence={mapping_confidence:.2f}, version={_md_cell(mapping_version, limit=60)} |",
    ])
    intel_table = "\n".join([
        "| Signal | Value |",
        "|---|---|",
        f"| Intel verdict | **{intel_status}** |",
        f"| Intel score | `{float(intel_score or 0.0):.4f}` |",
    ])

    description = "\n\n".join([
        "## Alert Summary\n" + summary_table,
        "## Cortex/MISP Intel\n" + intel_table + "\n\n" + _format_cortex_verdict_table(cortex_verdicts),
        "## SOAR Actions\n" + _format_actions_table(actions),
        "## Translator Annotation\n" + _format_translator_annotation_table(alert, techniques_line, mapping_status, mapping_confidence),
        "## Mapping Reason\n" + _format_mapping_reason_table(mapping_reason),
        "## Top Evidence\n" + top_evidence_table,
    ])

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


def _normalize_observable_value(obs_type: str, value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if obs_type == "ip":
        try:
            return ipaddress.ip_address(text).compressed
        except ValueError:
            return text
    if obs_type in ("domain", "hash", "ja3"):
        return text.lower()
    return text


def _should_skip_observable(obs_type: str, value: str) -> bool:
    if obs_type != "ip":
        return False
    if os.getenv("SKIP_PRIVATE_IP_OBSERVABLES", "true").lower() != "true":
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not ip.is_global


def _parse_observables(observables_value: Any) -> List[Dict[str, Any]]:
    if observables_value is None:
        raw_observables = []
    elif isinstance(observables_value, list):
        raw_observables = observables_value
    elif isinstance(observables_value, str) and observables_value.strip():
        try:
            parsed = json.loads(observables_value)
            raw_observables = parsed if isinstance(parsed, list) else []
        except Exception:
            raw_observables = []
    else:
        raw_observables = []

    observables: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    skipped_private_ips = 0
    skipped_duplicates = 0

    for raw in raw_observables:
        if not isinstance(raw, dict):
            continue
        obs_type = str(raw.get("type") or "").strip().lower()
        value = _normalize_observable_value(obs_type, raw.get("value"))
        if not obs_type or not value:
            continue
        if _should_skip_observable(obs_type, value):
            skipped_private_ips += 1
            continue
        key = (obs_type, value)
        if key in seen:
            skipped_duplicates += 1
            continue
        seen.add(key)
        obs = dict(raw)
        obs["type"] = obs_type
        obs["value"] = value
        observables.append(obs)

    if skipped_private_ips or skipped_duplicates:
        log_event(
            "observables_filtered",
            kept=len(observables),
            skipped_private_ips=skipped_private_ips,
            skipped_duplicates=skipped_duplicates,
        )
    return observables


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



def _record_gated_approvals(
    conn,
    *,
    alert: Dict[str, Any],
    actions: List[Dict[str, Any]],
    agent_id: str | None,
    case_id: Any,
    case_url: str,
    severity: str,
    mitre_ttps: List[str],
    intel_malicious: bool,
) -> List[Dict[str, Any]]:
    """Park each gated action (requires_approval=True) on a managed endpoint as a
    `pending` approval for the dashboard loop. The Shuffle User-Input gate is
    retired — analysts approve/reject via the dashboard, which calls
    POST /soar/approve to execute the real Wazuh AR. No managed endpoint (no
    agent_id) → nothing to enforce, so nothing is parked."""
    parked: List[Dict[str, Any]] = []
    if not agent_id:
        return parked
    for action in actions or []:
        if not action.get("requires_approval"):
            continue
        atype = action.get("type")
        if atype == "block":
            targets = [t for t in (action.get("targets") or []) if t.get("type") == "ip" and t.get("value")]
        elif atype == "isolate":
            targets = [None]  # one approval; no IP arg
        else:
            continue
        for target in targets:
            approval_id = record_pending_approval(
                conn,
                alert_id=int(alert["id"]),
                flow_id=str(alert["flow_id"]),
                agent_id=agent_id,
                action_type=atype,
                target_value=(target.get("value") if isinstance(target, dict) else None),
                case_id=case_id,
                case_url=case_url,
                severity=severity,
                mitre_ttps=mitre_ttps,
                intel_malicious=intel_malicious,
                ttl_seconds=APPROVAL_TTL_SEC,
            )
            parked.append({
                "approval_id": approval_id,
                "action": atype,
                "target": (target.get("value") if isinstance(target, dict) else None),
            })
    if parked:
        log_event("approvals_parked", alert_id=int(alert["id"]), flow=str(alert["flow_id"])[:8],
                  count=len(parked), agent_id=agent_id)
    return parked


def process_alert(
    conn,
    cortex: CortexClient,
    alert: Dict[str, Any],
    *,
    trigger_source: str,
    trigger_event: Dict[str, Any] | None = None,
    skip_claim: bool = False,
) -> str:
    """Process one durable Postgres alert row.

    Kafka and polling both enter here after fetching the full row from Postgres.
    The first operation is an idempotent bookkeeping insert, so duplicate Kafka
    events or replayed polling passes cannot create duplicate cases/actions.

    skip_claim: set True when the caller (process_polling_batch) already
    claimed the alert on the main-loop connection before submitting to the
    worker pool, so this worker skips the redundant re-claim attempt.
    """
    alert_id = int(alert["id"])
    flow_id = str(alert["flow_id"])
    model = str(alert.get("model") or "unknown")

    if not skip_claim:
        if not claim_alert_for_processing(conn, alert_id, flow_id, model):
            log_event(
                "alert_already_claimed",
                alert_id=alert_id,
                flow=flow_id[:8],
                trigger_source=trigger_source,
            )
            return "duplicate"

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
            # Step 5 Low row: still notify, even with no case and no enrichment.
            # Other skip reasons (benign, unmapped under the strict gate, missing
            # API key) get no dispatch.
            shuffle_dispatch = None
            notify_result = None
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
                notify_result = send_slack_notification(
                    flow_id=flow_id,
                    severity=severity,
                    pred_proba=pred_proba,
                    mitre_ttps=mitre_ttps,
                    intel_malicious=False,
                    intel_score=0.0,
                    actions=actions,
                    annotation=str(alert.get("annotation") or ""),
                )
            mark_status(
                conn,
                alert_id,
                flow_id,
                model,
                status="skipped",
                last_error=skip_reason,
                playbook_plan={
                    "skip_reason": skip_reason,
                    "shuffle_dispatch": shuffle_dispatch,
                    "slack_notify": notify_result,
                    "trigger_source": trigger_source,
                },
            )
            record_alert(status="skipped", model=model)
            log_event(
                "alert_skipped",
                alert_id=alert_id,
                flow=flow_id[:8],
                reason=skip_reason,
                notified=shuffle_dispatch is not None,
                trigger_source=trigger_source,
            )
            return "skipped"

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

        # Step 3/4 happen before TheHive case creation so Step 5 decisions and
        # the case payload include Cortex/MISP intel.
        pre_enrichment = run_pre_case_enrichment(
            alert=alert,
            observables=observables,
            cortex=cortex,
            analyzers_for_observable_type=analyzers_for_observable_type,
        )
        stamp_bookkeeping_ts(conn, alert_id, enriched_ts=_now())
        intel_malicious = bool(pre_enrichment.get("intel_malicious"))
        intel_score = float(pre_enrichment.get("intel_score") or 0.0)
        enriched_observables = pre_enrichment.get("enriched_observables") or observables

        # Endpoint identity (populated only for flows captured by an endpoint
        # sensor; NULL for replay/in-stack flows). When present we have a managed
        # Wazuh agent to route block/isolate to.
        agent_id = str(alert.get("agent_id") or "").strip() or None
        endpoint = None
        if agent_id:
            endpoint = {
                "host_id": alert.get("host_id"),
                "ip": alert.get("host_ip"),  # the sensor's own IP (NOT a block target)
                "source": "wazuh",
                "agent_id": agent_id,
            }

        actions = decide_actions(
            severity=severity,
            intel_malicious=intel_malicious,
            observables=enriched_observables,
            # A managed endpoint makes the (always-gated) isolate cell real;
            # without an agent there is nothing to isolate. Tunable so isolate
            # can be suppressed independent of having an agent.
            endpoint_risk=bool(endpoint) and os.getenv("EMIT_ISOLATE_FOR_MANAGED_ENDPOINT", "true").lower() == "true",
            endpoint=endpoint,
        )

        case_payload = build_thehive_case_payload(
            alert,
            playbook_plan,
            intel_malicious=intel_malicious,
            intel_score=intel_score,
            actions=actions,
            cortex_verdicts=pre_enrichment.get("verdicts") or [],
        )

        with time_case_creation():
            case_id = create_case(**case_payload)
        stamp_bookkeeping_ts(conn, alert_id, case_created_ts=_now())

        automation = run_case_automation(
            case_id=str(case_id),
            alert=alert,
            mitre_ttps=mitre_ttps,
            observables=observables,
            cortex=cortex,
            analyzers_for_observable_type=analyzers_for_observable_type,
            pre_enrichment=pre_enrichment,
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
            endpoint=endpoint,
        )
        shuffle_dispatch = post_to_shuffle(shuffle_payload)
        # Endpoint-routed enforcement: real Wazuh AR for the auto-block cell
        # only (block, requires_approval=False). Gated block + isolate stay in
        # the §7.1 handoff for the approval gate and are NOT enacted here.
        endpoint_response = dispatch_endpoint_actions(agent_id=agent_id, actions=actions)
        # Gated block/isolate go to the dashboard approval loop (the Shuffle
        # User-Input gate is retired); they enforce on approve via /soar/approve.
        pending_approvals = _record_gated_approvals(
            conn,
            alert=alert,
            actions=actions,
            agent_id=agent_id,
            case_id=case_id,
            case_url=thehive_case_url(str(case_id)),
            severity=severity,
            mitre_ttps=mitre_ttps,
            intel_malicious=intel_malicious,
        )
        notify_result = send_slack_notification(
            flow_id=flow_id,
            severity=severity,
            pred_proba=pred_proba,
            mitre_ttps=mitre_ttps,
            intel_malicious=intel_malicious,
            intel_score=intel_score,
            actions=actions,
            thehive_case_url=thehive_case_url(str(case_id)),
            annotation=str(alert.get("annotation") or ""),
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
                "shuffle": {"actions": actions, "dispatch": shuffle_dispatch},
                "slack_notify": notify_result,
                "endpoint": endpoint,
                "endpoint_response": endpoint_response,
                "pending_approvals": pending_approvals,
                "trigger_source": trigger_source,
                "trigger_event": trigger_event,
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
            trigger_source=trigger_source,
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
            trigger_source=trigger_source,
        )
        return "done"
    except TheHiveRecoverableError as e:
        try:
            conn.rollback()
        except Exception:
            pass
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
                "trigger_source": trigger_source,
            },
        )
        return "deferred_thehive"
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
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
            extra={
                "event": "alert_failed",
                "alert_id": alert_id,
                "error": str(e),
                "trigger_source": trigger_source,
            },
        )
        return "failed"


def _decode_and_fetch_kafka_alert(conn, raw_value: Any) -> tuple[Dict[str, Any] | None, Dict[str, Any] | None]:
    """Decode one Kafka pointer event and fetch the full alert row from
    Postgres, using the caller's (main-loop) connection — both are quick
    reads, unlike the process_alert pipeline. Returns (alert, event); alert
    is None if the event was invalid/unknown (event is also None) or its
    alert_id no longer resolves (event is the decoded event)."""
    event, error = decode_soar_alert_event(raw_value)
    if error:
        log.warning("kafka_event_skipped", extra={"event": "kafka_event_skipped", "reason": error})
        return None, None

    alert_id = int(event["alert_id"])
    alert = fetch_alert_by_id(conn, alert_id)
    if not alert:
        log.warning(
            "kafka_alert_missing",
            extra={"event": "kafka_alert_missing", "alert_id": alert_id, "flow_id": event.get("flow_id")},
        )
        return None, event

    return alert, event


def process_kafka_event(conn, cortex: CortexClient, raw_value: Any) -> str:
    """Handle one Kafka pointer event synchronously on the caller's
    connection (decode + fetch + full process_alert pipeline). The main loop
    no longer calls this directly — see _process_alert_async — but it's kept
    as a single-call synchronous entrypoint."""
    alert, event = _decode_and_fetch_kafka_alert(conn, raw_value)
    if alert is None:
        return "missing" if event is not None else "skipped"
    return process_alert(conn, cortex, alert, trigger_source="kafka", trigger_event=event)


def _process_alert_async(
    cortex: CortexClient,
    alert: Dict[str, Any],
    *,
    trigger_source: str,
    trigger_event: Dict[str, Any] | None = None,
    skip_claim: bool = False,
) -> None:
    """Worker-pool entrypoint: runs one alert's full pipeline (claim through
    notify/dispatch) on its own short-lived DB connection, so a slow
    enrichment/case-creation pipeline for one alert never blocks claiming the
    next one. Mirrors api_server's one-connection-per-request pattern rather
    than sharing the poll loop's long-lived connection across threads
    (psycopg2 connections aren't thread-safe)."""
    worker_conn, _ = _connect_db_with_retry()
    try:
        process_alert(
            worker_conn, cortex, alert,
            trigger_source=trigger_source, trigger_event=trigger_event, skip_claim=skip_claim,
        )
    except Exception as exc:
        # process_alert already catches and records its own failures
        # (status="failed"/"deferred_thehive"); this is a safety net for the
        # rare case an exception escapes that handling (e.g. the connection
        # itself broke mid-pipeline).
        log.error(
            "alert_worker_unhandled_error",
            extra={"event": "alert_worker_unhandled_error", "alert_id": alert.get("id"), "error": str(exc)},
        )
    finally:
        try:
            worker_conn.rollback()
        except Exception:
            pass
        try:
            worker_conn.close()
        except Exception:
            pass


def process_polling_batch(conn, cortex: CortexClient, executor: ThreadPoolExecutor, *, limit: int = POLL_BATCH_LIMIT) -> int:
    """Replay/fallback path: pick unprocessed alerts directly from Postgres
    (cheap read on the main-loop connection) and dispatch each to the worker
    pool for processing.

    Claims each alert synchronously on the main-loop connection BEFORE
    submitting to the executor. Without this, the poll loop re-picks the
    same alert on every iteration until the worker thread has had CPU time
    to call claim_alert_for_processing on its own connection — a gap of
    many seconds while Cortex enrichment runs in the worker, causing O(N)
    redundant claim attempts per alert per polling pass.
    """
    alerts = pick_next_alert(conn, limit=limit)
    submitted = 0
    for alert in alerts:
        alert_id = int(alert["id"])
        flow_id = str(alert.get("flow_id") or "")
        model = str(alert.get("model") or "unknown")
        if not claim_alert_for_processing(conn, alert_id, flow_id, model):
            # Already claimed by the Kafka path or a concurrent worker.
            continue
        executor.submit(
            _process_alert_async, cortex, alert,
            trigger_source="postgres_poll", skip_claim=True,
        )
        submitted += 1
    return submitted


def _close_kafka_consumer(consumer) -> None:
    try:
        consumer.close()
    except Exception:
        pass


def main():
    _normalize_bom_env_keys()
    start_metrics_server()           # Prometheus /metrics on :METRICS_PORT
    start_api_server()                # /soar/shuffle-result + /soar/feedback on :ORCHESTRATOR_HTTP_PORT
    # api_server/metrics are up first and stay up regardless of DB state; block
    # here (without dying) until the cross-machine detection Postgres is reachable.
    conn = connect_with_retry()

    log_event("orchestrator_started", kafka_trigger_enabled=ENABLE_KAFKA_TRIGGER)
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
    # CortexClient's only mutable state is its analyzer-id cache (a dict);
    # concurrent first-population races are benign (duplicate fetch, not
    # corruption), so one instance is shared across all worker threads.
    executor = ThreadPoolExecutor(max_workers=ORCHESTRATOR_WORKER_COUNT, thread_name_prefix="alert-worker")
    consumer = None
    last_kafka_retry = 0.0

    while True:
        try:
            processed = 0

            if ENABLE_KAFKA_TRIGGER and consumer is None:
                now = time.monotonic()
                if now - last_kafka_retry >= KAFKA_RECONNECT_INTERVAL_SEC:
                    last_kafka_retry = now
                    try:
                        consumer = make_soar_alert_consumer(retries=1)
                    except Exception as exc:
                        log.warning(
                            "kafka_consumer_unavailable",
                            extra={"event": "kafka_consumer_unavailable", "error": str(exc)},
                        )
                        consumer = None

            if consumer is not None:
                try:
                    records = consumer.poll(
                        timeout_ms=KAFKA_POLL_TIMEOUT_MS,
                        max_records=KAFKA_MAX_RECORDS,
                    )
                    for messages in records.values():
                        for message in messages:
                            alert, event = _decode_and_fetch_kafka_alert(conn, message.value)
                            if alert is not None:
                                executor.submit(
                                    _process_alert_async, cortex, alert, trigger_source="kafka", trigger_event=event
                                )
                            processed += 1
                    if processed:
                        consumer.commit()
                except Exception as exc:
                    log.warning(
                        "kafka_consumer_error",
                        extra={"event": "kafka_consumer_error", "error": str(exc)},
                    )
                    _close_kafka_consumer(consumer)
                    consumer = None

            processed += process_polling_batch(conn, cortex, executor, limit=POLL_BATCH_LIMIT)
            if not processed:
                time.sleep(0.2 if consumer is not None else POLL_INTERVAL_SEC)
        except Exception as outer_e:
            # If something temporary fails (DB disconnect), reconnect with
            # backoff instead of a single get_db() that could re-raise and kill
            # the process — the cross-machine DB may stay down for a while.
            log.error(
                "outer_failure",
                extra={"event": "outer_failure", "error": str(outer_e)},
            )
            try:
                conn.close()
            except Exception:
                pass
            conn = connect_with_retry()


if __name__ == "__main__":
    main()

