"""
Automated TheHive case actions after SOAR creates a mapped malicious alert case.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from cortex_client import CortexClient
from slog import get_logger
from metrics import record_cortex_run, record_responder_run
from thehive_client import (
    bulk_complete_case_tasks,
    bulk_create_case_procedures,
    create_case_observable,
    create_case_task,
    extract_observable_id,
    get_cortex_job_via_thehive,
    list_case_responders,
    list_case_tasks,
    run_analyzer_via_thehive,
    run_responder_action,
    to_thehive_observable_type,
)

log = get_logger(__name__)


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() == "true"


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def normalize_pattern_ids(mitre_ttps: List[str]) -> List[str]:
    """Deduplicated MITRE technique IDs suitable for TheHive patternId."""
    seen: List[str] = []
    for raw in mitre_ttps or []:
        tid = str(raw or "").strip()
        if not tid.upper().startswith("T"):
            continue
        if tid not in seen:
            seen.append(tid)
    return seen


def _taxonomy_verdict(tax: List[Dict[str, Any]]) -> str:
    levels = [str(t.get("level") or "").lower() for t in tax if isinstance(t, dict)]
    if any(lvl == "malicious" for lvl in levels):
        return "malicious"
    if any(lvl == "suspicious" for lvl in levels):
        return "suspicious"
    if any(lvl == "safe" for lvl in levels):
        return "safe"
    return "info"


def _taxonomy_str(tax: List[Dict[str, Any]]) -> str:
    return "; ".join(
        f"{t.get('namespace','?')}/{t.get('predicate','?')}={t.get('value','?')}"
        for t in tax if isinstance(t, dict)
    )[:200]


def _misp_event_count(full: Dict[str, Any]) -> int:
    total = 0
    for server_result in full.get("results") or []:
        if not isinstance(server_result, dict):
            continue
        result = server_result.get("result") or []
        if isinstance(result, list):
            total += len(result)
    return total


def _fallback_cortex_verdict(report: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Analyzer-specific fallbacks for reports whose useful signal is in `full`.

    Some Cortex analyzers, notably URLhaus, return an empty summary taxonomy even
    when `full` clearly identifies an IOC. Others, such as MISP, use
    `suspicious` for a positive intel hit. These fallbacks convert dedicated
    threat-intel hits into the confirmed `malicious` verdict used by the SOAR
    decision gate while leaving generic enrichment/context analyzers unchanged.
    """
    full = report.get("full") or {}
    if not isinstance(full, dict):
        return None

    # URLhaus: query_status=ok means the host/URL was found. The analyzer
    # leaves summary.taxonomies empty, so we derive the verdict from `full`.
    #
    # URL-type responses carry threat/url_status/payloads at the top level.
    # Domain/host-type responses carry them inside a nested `urls[]` array
    # and also expose a `blacklists` dict (spamhaus_dbl, surbl, etc.).
    if str(full.get("query_status") or "").lower() == "ok":
        # URL-type fields (top-level)
        threat = str(full.get("threat") or "").strip()
        url_status = str(full.get("url_status") or "").strip()
        payloads = full.get("payloads") or []

        # Domain/host-type: check blacklists dict
        blacklists = full.get("blacklists") or {}
        bl_hits = [
            f"{k}={v}" for k, v in blacklists.items()
            if str(v).lower() not in ("not listed", "none", "")
        ] if isinstance(blacklists, dict) else []

        # Domain/host-type: scan nested urls[] for any live/known-bad entry
        urls = full.get("urls") or []
        nested_threat = next(
            (str(u.get("threat") or "").strip() for u in urls if u.get("threat")), ""
        )
        nested_url_status = next(
            (str(u.get("url_status") or "") for u in urls
             if str(u.get("url_status") or "") in ("online", "offline")), ""
        )

        if threat or payloads or url_status in ("online", "offline") \
                or bl_hits or nested_threat or nested_url_status:
            detail = (
                threat
                or nested_threat
                or (", ".join(bl_hits) if bl_hits else "")
                or f"url_status={url_status or nested_url_status}"
                or "URLhaus hit"
            )
            return "malicious", f"URLhaus/Search={detail}"[:200]
    if str(full.get("query_status") or "").lower() == "no_results":
        return "info", "URLhaus/Search=No results"

    # MISP: a positive local MISP event match is a trusted intel hit for this
    # workflow, even though the analyzer labels the taxonomy as suspicious.
    misp_hits = _misp_event_count(full)
    if misp_hits > 0:
        return "malicious", f"MISP/Search={misp_hits} event(s)"

    # CIRCL hashlookup uses full.KnownMalicious for some hits.
    known_malicious = full.get("KnownMalicious")
    if known_malicious is True or str(known_malicious).lower() == "true":
        return "malicious", "CIRCLHashlookup/KnownMalicious=true"

    return None


def _summarize_cortex_job(job: Dict[str, Any]) -> Tuple[str, str]:
    """Extract (verdict, taxonomies_str) from a TheHive-wrapped Cortex job."""
    if not job:
        return ("missing", "")
    if job.get("error"):
        return ("error", str(job.get("error"))[:120])
    status = str(job.get("status", "")).lower()
    if status in ("waiting", "inprogress", "in_progress", "pending", ""):
        return ("pending", "")
    if status in ("failure", "failed", "deleted"):
        return (status, "")

    report = job.get("report") or {}
    if isinstance(report.get("report"), dict):
        report = report["report"]
    if not isinstance(report, dict):
        return ("info", "(no report)")

    fallback = _fallback_cortex_verdict(report)

    summary = report.get("summary") or {}
    tax = summary.get("taxonomies") or [] if isinstance(summary, dict) else []
    if isinstance(tax, list) and tax:
        tax_str = _taxonomy_str(tax)
        verdict = _taxonomy_verdict(tax)
        # Positive MISP event hits are confirmation-grade for this SOAR flow.
        if fallback and fallback[0] == "malicious" and fallback[1].startswith("MISP/"):
            return fallback
        return (verdict, tax_str)

    if fallback:
        return fallback
    return ("info", "(no taxonomies)")


def _collect_cortex_verdicts(
    launched_jobs: List[Dict[str, Any]],
    *,
    per_job_wait_seconds: int,
    total_budget_seconds: int,
) -> List[Dict[str, Any]]:
    """Poll each Cortex job once, bounded by `total_budget_seconds`. Any job
    still pending when the budget runs out is recorded as 'pending' — its
    full report remains available natively on the observable's Analysis tab.

    This is the single poll pass shared by the summary task (markdown
    recap) and the intel-verdict aggregation (`derive_intel_verdict`) so a
    job is never polled twice for the same alert.
    """
    start = time.monotonic()
    verdicts: List[Dict[str, Any]] = []
    for lj in launched_jobs:
        remaining = total_budget_seconds - (time.monotonic() - start)
        if remaining <= 0:
            verdict, tax = ("pending", "")
        else:
            wait = max(0, min(per_job_wait_seconds, int(remaining)))
            try:
                job = get_cortex_job_via_thehive(
                    job_id=lj["thehive_job_id"], wait_seconds=wait
                )
            except Exception as exc:
                job = {"error": str(exc)}
            verdict, tax = _summarize_cortex_job(job)
        verdicts.append(
            {
                "analyzer_name": lj.get("analyzer_name", "?"),
                "observable_value": lj.get("observable_value", ""),
                "observable_type": lj.get("observable_type", "?"),
                "verdict": verdict,
                "taxonomies": tax,
            }
        )
    return verdicts


def _intel_confirmation_analyzers() -> set:
    """Analyzers trusted to "confirm" an IOC for the §5 auto-block cell.

    Deliberately a narrow, named allowlist (not "any analyzer says
    malicious") — these are dedicated threat-intel/reputation sources, not
    heuristics, so a single positive from one of them is a defensible bar
    for "Malicious IOC confirmed". Override via env if Cortex is configured
    with different analyzer names.
    """
    raw = os.getenv(
        "INTEL_CONFIRMATION_ANALYZERS",
        "MISP_2_1,VirusTotal_GetReport_3_1,URLhaus_2_0",
    )
    return {s.strip() for s in raw.split(",") if s.strip()}


def derive_intel_verdict(verdicts: List[Dict[str, Any]]) -> Tuple[bool, float]:
    """Combine per-job Cortex verdicts into the Step 4 intel signal.

    intel_malicious: True only when a designated intel-grade analyzer (see
    `_intel_confirmation_analyzers`) reports an explicit 'malicious'
    taxonomy verdict. This is what the §5 decision matrix's single
    High+confirmed-IOC auto-block cell keys off — kept conservative on
    purpose.

    intel_score: the fraction of resolved verdicts (excluding
    pending/missing/error) that came back malicious, from ALL launched
    analyzers — a softer signal for case context; it does not by itself
    drive the auto-block gate.
    """
    confirmation_analyzers = _intel_confirmation_analyzers()
    resolved = [v for v in verdicts if v.get("verdict") not in ("missing", "pending", "error", "")]
    malicious = [v for v in resolved if v.get("verdict") == "malicious"]
    intel_malicious = any(v.get("analyzer_name") in confirmation_analyzers for v in malicious)
    intel_score = (len(malicious) / len(resolved)) if resolved else 0.0
    return intel_malicious, round(intel_score, 4)


def annotate_observable_intel(
    observables: List[Dict[str, Any]], verdicts: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Tag each observable with a per-observable `intel_malicious` flag —
    True only when a designated confirmation analyzer (see
    `_intel_confirmation_analyzers`) returned a `malicious` verdict for that
    exact (type, value) pair. This is what decision_matrix.decide_actions
    uses to pick auto-block targets, and what the §7.1 payload's
    `observables[].intel_malicious` field reports.
    """
    confirmation_analyzers = _intel_confirmation_analyzers()
    malicious_keys = {
        (v.get("observable_type"), v.get("observable_value"))
        for v in verdicts
        if v.get("verdict") == "malicious" and v.get("analyzer_name") in confirmation_analyzers
    }
    annotated = []
    for obs in observables:
        obs = dict(obs)
        if (obs.get("type"), obs.get("value")) in malicious_keys:
            obs["intel_malicious"] = True
        annotated.append(obs)
    return annotated


def _post_cortex_summary_task(*, case_id: str, verdicts: List[Dict[str, Any]]) -> Optional[str]:
    """Build a markdown verdict table from already-polled verdicts and post
    it back to the case as a Completed task so analysts see the recap inline.
    """
    rows = [
        "| Observable | Type | Analyzer | Verdict | Taxonomies |",
        "|---|---|---|---|---|",
    ]
    for v in verdicts:
        obs_value = (v.get("observable_value") or "")[:60]
        rows.append(
            f"| `{obs_value}` | {v.get('observable_type','?')} | "
            f"{v.get('analyzer_name','?')} | {v.get('verdict','?')} | {v.get('taxonomies','')} |"
        )
    description = (
        "Automated Cortex/MISP enrichment results used for the SOAR decision. "
        "When analyzers are run before case creation, the full report remains in "
        "Cortex job history and this task carries the analyst-facing verdict recap.\n\n"
        + "\n".join(rows)
    )
    try:
        return create_case_task(
            case_id=case_id,
            title="Cortex Enrichment Summary",
            description=description,
            group="Enrichment",
            status="Completed",
        )
    except Exception as exc:
        log.warning(
            "cortex_summary_task_failed",
            extra={"event": "cortex_summary_task_failed", "case_id": case_id, "error": str(exc)},
        )
        return None


def _cortex_data_type_for_observable(obs: Dict[str, Any]) -> str:
    """Data type used for direct Cortex jobs before a TheHive case exists."""
    return to_thehive_observable_type(obs)


def _summarize_direct_cortex_result(result: Dict[str, Any]) -> Tuple[str, str]:
    if result.get("error"):
        return _summarize_cortex_job({"error": result.get("error")})
    report = result.get("report") or result.get("run_response") or {}
    status = "Success"
    if isinstance(report, dict):
        status = str(report.get("status") or (report.get("report") or {}).get("status") or status)
    return _summarize_cortex_job({"status": status, "report": report})


def _accumulate_direct_cortex_result(
    summary: Dict[str, Any],
    record: Dict[str, Any],
    *,
    analyzer_name: str,
    obs_value: str,
    obs_type: str,
    result: Dict[str, Any],
) -> None:
    record["result"] = result
    verdict, tax = _summarize_direct_cortex_result(result)
    outcome = "completed" if verdict not in ("error", "failure", "failed") else "run_failed"
    record_cortex_run(analyzer=analyzer_name, outcome=outcome)
    summary["cortex_results"].append(record)
    summary["verdicts"].append(
        {
            "analyzer_name": analyzer_name,
            "observable_value": obs_value,
            "observable_type": obs_type,
            "verdict": verdict,
            "taxonomies": tax,
        }
    )


def run_pre_case_enrichment(
    *,
    alert: Dict[str, Any],
    observables: List[Dict[str, Any]],
    cortex: CortexClient,
    analyzers_for_observable_type,
) -> Dict[str, Any]:
    """Run Step 3 enrichment before TheHive case creation.

    This keeps the workflow order aligned with SOAR_WORKFLOW_SPEC.md: Cortex/MISP
    verdicts are available before Step 5 decides actions and before the case
    payload is built. The later case automation phase attaches procedures,
    observables, and posts the already-computed summary into TheHive.

    Jobs run one at a time via `cortex.run_analyzer_on_observable`, which
    holds the global CORTEX_MAX_CONCURRENT semaphore for each job's whole
    launch→report span. An earlier two-phase variant (launch every job, then
    poll them all in one budgeted pass) was faster for a single alert, but
    it released the concurrency cap the moment a job was queued — with
    multiple orchestrator workers, Cortex's queue saturated and enrichment
    latency grew linearly with alert_id. Per-job serialization is the point:
    a new job is not launched until a running one has returned its report.
    CORTEX_PRE_CASE_TOTAL_BUDGET_SEC still bounds the whole phase — jobs
    that would start after the budget is spent are recorded as pending and
    never launched.
    """
    summary: Dict[str, Any] = {
        "source": "pre_case_direct_cortex",
        "cortex_results": [],
        "verdicts": [],
        "intel_malicious": False,
        "intel_score": 0.0,
        "enriched_observables": list(observables),
    }

    if _env_bool("ORCHESTRATOR_DRY_RUN", "true") or not _env_bool("AUTO_RUN_CORTEX", "true"):
        return summary

    run_count = 0
    max_cortex = _env_int("MAX_CORTEX_RUNS_PER_FLOW", 20)
    max_obs = _env_int("MAX_OBSERVABLES_PER_FLOW", 10)
    # CORTEX_PRE_CASE_WAIT_SEC: max wait per individual analyzer job.
    # CORTEX_PRE_CASE_TOTAL_BUDGET_SEC bounds the whole phase; each job's
    # wait is capped by whatever budget remains (semaphore queueing counts
    # against it), and jobs reached after it is spent are marked pending
    # without being launched.
    per_job_wait_seconds = _env_int("CORTEX_PRE_CASE_WAIT_SEC", _env_int("CORTEX_WAIT_SECONDS", 5))
    total_budget_seconds = _env_int("CORTEX_PRE_CASE_TOTAL_BUDGET_SEC", per_job_wait_seconds)
    start = time.monotonic()

    for obs in observables[:max_obs]:
        if run_count >= max_cortex:
            break
        obs_value = obs.get("value")
        obs_type = str(obs.get("type") or "")
        if not obs_value or not obs_type:
            continue
        analyzers = analyzers_for_observable_type(obs_type)
        if not analyzers:
            continue
        data_type = _cortex_data_type_for_observable(obs)
        for analyzer_name in analyzers:
            if run_count >= max_cortex:
                break
            run_count += 1
            record: Dict[str, Any] = {
                "analyzer_name": analyzer_name,
                "data": str(obs_value),
                "data_type": str(data_type),
                "observable_type": obs_type,
            }
            remaining = total_budget_seconds - (time.monotonic() - start)
            if remaining <= 0:
                summary["cortex_results"].append(record)
                summary["verdicts"].append(
                    {
                        "analyzer_name": analyzer_name,
                        "observable_value": str(obs_value),
                        "observable_type": obs_type,
                        "verdict": "pending",
                        "taxonomies": "",
                    }
                )
                record_cortex_run(analyzer=analyzer_name, outcome="skipped")
                continue
            try:
                # Holds the global CORTEX_MAX_CONCURRENT semaphore from
                # launch until the report is back — do not switch back to
                # the launch/wait halves (that uncaps Cortex concurrency).
                result = cortex.run_analyzer_on_observable(
                    analyzer_name=analyzer_name,
                    data=str(obs_value),
                    data_type=str(data_type),
                    wait_seconds=max(1, min(per_job_wait_seconds, int(remaining))),
                )
            except Exception as exc:
                record["error"] = str(exc)
                summary["cortex_results"].append(record)
                summary["verdicts"].append(
                    {
                        "analyzer_name": analyzer_name,
                        "observable_value": str(obs_value),
                        "observable_type": obs_type,
                        "verdict": "error",
                        "taxonomies": str(exc)[:120],
                    }
                )
                record_cortex_run(analyzer=analyzer_name, outcome="run_failed")
                continue

            _accumulate_direct_cortex_result(
                summary,
                record,
                analyzer_name=analyzer_name,
                obs_value=str(obs_value),
                obs_type=obs_type,
                result=result,
            )

    verdicts = summary["verdicts"]
    summary["intel_malicious"], summary["intel_score"] = derive_intel_verdict(verdicts)
    summary["enriched_observables"] = annotate_observable_intel(observables, verdicts)
    return summary


def should_run_responders(alert: Dict[str, Any]) -> bool:
    if _env_bool("AUTO_RUN_RESPONDERS", "true"):
        return True
    if _env_bool("RUN_RESPONDERS_ON_ALL") or _env_bool("FORCE_ACTIVE_RESPONSE"):
        return True
    pred_label = int(alert.get("pred_label") or 0)
    severity_label = str(alert.get("severity_label") or "LOW").upper()
    return pred_label == 1 and severity_label in ("MEDIUM", "HIGH")


def run_case_automation(
    *,
    case_id: str,
    alert: Dict[str, Any],
    mitre_ttps: List[str],
    observables: List[Dict[str, Any]],
    cortex: CortexClient,
    analyzers_for_observable_type,
    pre_enrichment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Link TTPs, attach observables, run Cortex/responders, and complete waiting tasks.
    """
    pre_enrichment = pre_enrichment or {}
    precomputed_verdicts = list(pre_enrichment.get("verdicts") or [])
    summary: Dict[str, Any] = {
        "procedures": [],
        "case_observable_results": [],
        "responder_runs": [],
        "cortex_results": list(pre_enrichment.get("cortex_results") or []),
        "completed_task_ids": [],
        "intel_malicious": bool(pre_enrichment.get("intel_malicious", False)),
        "intel_score": float(pre_enrichment.get("intel_score") or 0.0),
        "enriched_observables": list(pre_enrichment.get("enriched_observables") or observables),
        "pre_case_enrichment": bool(precomputed_verdicts),
    }

    if _env_bool("ORCHESTRATOR_DRY_RUN", "true"):
        pattern_ids = normalize_pattern_ids(mitre_ttps)
        print(
            "[DRY_RUN] Would automate case",
            case_id,
            f"procedures={pattern_ids}",
            f"observables={len(observables)}",
        )
        return summary

    if _env_bool("AUTO_LINK_CASE_PROCEDURES", "true"):
        pattern_ids = normalize_pattern_ids(mitre_ttps)
        if pattern_ids:
            summary["procedures"] = bulk_create_case_procedures(case_id, pattern_ids)

    # observable_index keeps (original_type, thehive_observable_id) pairs so the
    # Cortex step below can run analyzers ON the TheHive observable (not on a
    # raw string), which is what makes the analyzer report appear inside the
    # case UI instead of being orphaned in Cortex.
    observable_index: List[Dict[str, Any]] = []
    if _env_bool("CREATE_CASE_OBSERVABLES", "true") and observables:
        pred_label = int(alert.get("pred_label") or 0)
        ioc_flag = pred_label == 1
        for obs in observables[:_env_int("MAX_CASE_OBSERVABLES", 10)]:
            obs_value = obs.get("value")
            obs_type = obs.get("type")
            if not obs_value or not obs_type:
                continue
            data_type = to_thehive_observable_type(obs)
            # ja3 has no standard TheHive dataType — to_thehive_observable_type()
            # falls back to "other", so tag it to keep it findable/filterable.
            extra_tags = ["ja3"] if str(obs_type).lower() == "ja3" else None
            try:
                result = create_case_observable(
                    case_id=str(case_id),
                    data_type=str(data_type),
                    data=str(obs_value),
                    tlp=_env_int("THEHIVE_TLP", 2),
                    pap=2,
                    ioc=ioc_flag,
                    sighted=False,
                    tags=extra_tags,
                )
            except Exception as exc:
                summary["case_observable_results"].append(
                    {"error": str(exc), "data": obs_value, "dataType": data_type}
                )
                continue
            summary["case_observable_results"].append(result)
            thehive_obs_id = extract_observable_id(result)
            if thehive_obs_id:
                observable_index.append(
                    {
                        "value": str(obs_value),
                        "type": str(obs_type),
                        "thehive_data_type": str(data_type),
                        "thehive_id": str(thehive_obs_id),
                    }
                )

    if should_run_responders(alert):
        responders = list_case_responders(str(case_id))
        mitre_ttps_upper = [str(t).upper() for t in (mitre_ttps or [])]
        matched: List[Tuple[str, str]] = []
        for r in responders:
            r_id = r.get("id") or r.get("_id") or r.get("responderId")
            r_name = str(r.get("name") or r.get("responderName") or "")
            if not r_id:
                continue
            if os.getenv("RESPONDER_MATCH_MODE", "all").lower() == "mitre":
                if any(t in r_name.upper() for t in mitre_ttps_upper if t):
                    matched.append((str(r_id), r_name))
            else:
                matched.append((str(r_id), r_name))

        for rid, rname in matched[:_env_int("MAX_RESPONDERS_PER_FLOW", 10)]:
            try:
                result = run_responder_action(case_id=str(case_id), responder_id=rid)
                record_responder_run(responder=rname, outcome="launched")
            except Exception as exc:
                result = {"error": str(exc)}
                record_responder_run(responder=rname, outcome="launch_failed")
            summary["responder_runs"].append(
                {"responder_id": rid, "responder_name": rname, "result": result}
            )

    # Cortex runs are routed through TheHive's Cortex connector so the resulting
    # job is bound to the case observable (analysts then see the mini-report and
    # taxonomies in the case's Observables -> Analysis tab, natively).
    launched_jobs: List[Dict[str, Any]] = []
    if _env_bool("AUTO_RUN_CORTEX", "true") and observable_index and not precomputed_verdicts:
        # Route every observable by its own type (spec Step 3) — no MITRE-TTP
        # based filtering. analyzers_for_observable_type() already returns []
        # for any type with no configured analyzer, which is gate enough.
        run_count = 0
        max_cortex = _env_int("MAX_CORTEX_RUNS_PER_FLOW", 20)
        max_obs = _env_int("MAX_OBSERVABLES_PER_FLOW", 10)
        for entry in observable_index[:max_obs]:
            if run_count >= max_cortex:
                break
            analyzers = analyzers_for_observable_type(entry["type"])
            if not analyzers:
                continue
            for analyzer_name in analyzers:
                if run_count >= max_cortex:
                    break
                analyzer_id = cortex.resolve_analyzer_id(analyzer_name)
                if not analyzer_id:
                    summary["cortex_results"].append(
                        {
                            "analyzer_name": analyzer_name,
                            "observable_id": entry["thehive_id"],
                            "data": entry["value"],
                            "error": f"Analyzer not enabled in Cortex: {analyzer_name}",
                        }
                    )
                    continue
                try:
                    action = run_analyzer_via_thehive(
                        observable_id=entry["thehive_id"],
                        analyzer_id=analyzer_id,
                    )
                except Exception as exc:
                    summary["cortex_results"].append(
                        {
                            "analyzer_name": analyzer_name,
                            "observable_id": entry["thehive_id"],
                            "data": entry["value"],
                            "error": str(exc),
                        }
                    )
                    record_cortex_run(analyzer=analyzer_name, outcome="launch_failed")
                    continue
                record_cortex_run(analyzer=analyzer_name, outcome="launched")
                # TheHive 5: the case_artifact_job's `_id` is the canonical
                # poll-key. `cortexJobId` is literal "-" until Cortex picks
                # up the job, so it's useless as an immediate identifier.
                thehive_job_id = action.get("_id") or action.get("id")
                # Cortex-side id only used for logging/forensics; may be "-".
                cortex_job_id_observed = action.get("cortexJobId")
                record = {
                    "analyzer_name": analyzer_name,
                    "observable_id": entry["thehive_id"],
                    "data": entry["value"],
                    "thehive_job_id": thehive_job_id,
                    "cortex_job_id": cortex_job_id_observed,
                }
                summary["cortex_results"].append(record)
                if thehive_job_id:
                    launched_jobs.append(
                        {
                            "analyzer_name": analyzer_name,
                            "observable_value": entry["value"],
                            "observable_type": entry["type"],
                            "thehive_job_id": str(thehive_job_id),
                        }
                    )
                run_count += 1
                if run_count >= max_cortex:
                    break

    verdicts: List[Dict[str, Any]] = precomputed_verdicts
    if launched_jobs:
        verdicts = _collect_cortex_verdicts(
            launched_jobs,
            per_job_wait_seconds=_env_int("CORTEX_SUMMARY_PER_JOB_WAIT_SEC", 2),
            total_budget_seconds=_env_int("CORTEX_SUMMARY_TOTAL_BUDGET_SEC", 20),
        )
        summary["intel_malicious"], summary["intel_score"] = derive_intel_verdict(verdicts)
        summary["enriched_observables"] = annotate_observable_intel(observables, verdicts)

    if verdicts and _env_bool("POST_CORTEX_SUMMARY_TASK", "true"):
        summary["cortex_summary_task_id"] = _post_cortex_summary_task(
            case_id=str(case_id), verdicts=verdicts
        )

    if _env_bool("AUTO_COMPLETE_CASE_TASKS", "true"):
        task_ids = [str(t["id"]) for t in list_case_tasks(case_id) if t.get("id")]
        if task_ids:
            summary["completed_task_ids"] = bulk_complete_case_tasks(task_ids)

    return summary
