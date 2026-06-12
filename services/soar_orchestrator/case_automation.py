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


def _summarize_cortex_job(job: Dict[str, Any]) -> Tuple[str, str]:
    """Extract (verdict, taxonomies_str) from a TheHive-wrapped Cortex job.

    Cortex analyzers emit a `summary.taxonomies` list with namespace/predicate/value/level
    (e.g. `Abuse_Finder/abuse=clean/safe`). We collapse the highest severity
    level seen across taxonomies into a single verdict for the table row.
    """
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
    summary = report.get("summary") or {}
    tax = summary.get("taxonomies") or []
    if not isinstance(tax, list) or not tax:
        return ("info", "(no taxonomies)")
    levels = [str(t.get("level") or "").lower() for t in tax if isinstance(t, dict)]
    if any(lvl == "malicious" for lvl in levels):
        verdict = "malicious"
    elif any(lvl == "suspicious" for lvl in levels):
        verdict = "suspicious"
    elif any(lvl == "safe" for lvl in levels):
        verdict = "safe"
    else:
        verdict = "info"
    tax_str = "; ".join(
        f"{t.get('namespace','?')}/{t.get('predicate','?')}={t.get('value','?')}"
        for t in tax if isinstance(t, dict)
    )
    return (verdict, tax_str[:200])


def _post_cortex_summary_task(
    *,
    case_id: str,
    launched_jobs: List[Dict[str, Any]],
    per_job_wait_seconds: int,
    total_budget_seconds: int,
) -> Optional[str]:
    """Poll each Cortex job briefly, build a markdown verdict table, and post
    it back to the case as a Completed task so analysts see the recap inline.

    Latency is bounded by `total_budget_seconds`; any job that's still pending
    when we run out of budget is shown as 'pending' and the full report stays
    available natively on the observable's Analysis tab.
    """
    start = time.monotonic()
    rows = [
        "| Observable | Type | Analyzer | Verdict | Taxonomies |",
        "|---|---|---|---|---|",
    ]
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
        obs_value = (lj.get("observable_value") or "")[:60]
        rows.append(
            f"| `{obs_value}` | {lj.get('observable_type','?')} | "
            f"{lj.get('analyzer_name','?')} | {verdict} | {tax} |"
        )
    description = (
        "Automated Cortex enrichment results. Full per-job reports are attached "
        "to each observable under its **Analysis** tab.\n\n" + "\n".join(rows)
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
    pick_observable_types,
    analyzers_for_observable_type,
) -> Dict[str, Any]:
    """
    Link TTPs, attach observables, run Cortex/responders, and complete waiting tasks.
    """
    summary: Dict[str, Any] = {
        "procedures": [],
        "case_observable_results": [],
        "responder_runs": [],
        "cortex_results": [],
        "completed_task_ids": [],
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
            try:
                result = create_case_observable(
                    case_id=str(case_id),
                    data_type=str(data_type),
                    data=str(obs_value),
                    tlp=_env_int("THEHIVE_TLP", 2),
                    pap=2,
                    ioc=ioc_flag,
                    sighted=False,
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
    if _env_bool("AUTO_RUN_CORTEX", "true") and observable_index:
        allowed_types = pick_observable_types(mitre_ttps)
        run_count = 0
        max_cortex = _env_int("MAX_CORTEX_RUNS_PER_FLOW", 20)
        max_obs = _env_int("MAX_OBSERVABLES_PER_FLOW", 10)
        for entry in observable_index[:max_obs]:
            if run_count >= max_cortex:
                break
            if entry["type"] not in allowed_types:
                continue
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

    if launched_jobs and _env_bool("POST_CORTEX_SUMMARY_TASK", "true"):
        summary["cortex_summary_task_id"] = _post_cortex_summary_task(
            case_id=str(case_id),
            launched_jobs=launched_jobs,
            per_job_wait_seconds=_env_int("CORTEX_SUMMARY_PER_JOB_WAIT_SEC", 2),
            total_budget_seconds=_env_int("CORTEX_SUMMARY_TOTAL_BUDGET_SEC", 20),
        )

    if _env_bool("AUTO_COMPLETE_CASE_TASKS", "true"):
        task_ids = [str(t["id"]) for t in list_case_tasks(case_id) if t.get("id")]
        if task_ids:
            summary["completed_task_ids"] = bulk_complete_case_tasks(task_ids)

    return summary
