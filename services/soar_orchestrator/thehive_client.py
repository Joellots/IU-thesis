import os
import time
from typing import Any, Dict, List, Optional

import requests


class TheHiveRecoverableError(RuntimeError):
    """TheHive is temporarily unavailable for this alert and the orchestrator
    should defer (not permanently fail) it.

    Raised on:
    - 402 Payment Required (StrangeBee TheHive 5 license expired)
    - 403 AuthorizationError on case creation (user lacks `manageCase/create`
      — typically a role/profile issue that the operator can fix without
      losing data)
    - 5xx server errors (TheHive temporarily down)

    The orchestrator catches this and marks the row `deferred_thehive`. Use
    `scripts/retry_deferred_thehive.py` to replay those alerts once the
    license / permissions are restored.
    """


def _thehive_base_url() -> str:
    return os.getenv("THEHIVE_BASE_URL", "http://thehive:9000").rstrip("/")


def thehive_case_url(case_id: str) -> str:
    """Browsable case URL for approval/notify context (§7.1 `case.thehive_case_url`).

    THEHIVE_BASE_URL is usually the in-network API host (e.g.
    `http://thehive:9000`), not what an analyst's browser can reach — set
    THEHIVE_EXTERNAL_URL to the public UI origin when they differ.
    """
    base = os.getenv("THEHIVE_EXTERNAL_URL", "").rstrip("/") or _thehive_base_url()
    return f"{base}/cases/{case_id}/details"


def _orchestrator_dry_run() -> bool:
    return os.getenv("ORCHESTRATOR_DRY_RUN", "true").lower() == "true"


def _normalize_secret(value: Optional[str]) -> str:
    """Strip BOM/whitespace and optional surrounding quotes from .env values."""
    v = (value or "").lstrip("\ufeff").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v


def thehive_organisation() -> str:
    """Organisation slug for StrangeBee TheHive 5 (sent as X-Organisation)."""
    return _normalize_secret(os.getenv("THEHIVE_ORGANISATION", "") or os.getenv("THEHIVE_ORG", ""))


# Legacy snapshot for callers that import THEHIVE_BASE_URL / THEHIVE_API_KEY
THEHIVE_BASE_URL = os.getenv("THEHIVE_BASE_URL", "http://thehive:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")


def _headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    api_key = _normalize_secret(os.getenv("THEHIVE_API_KEY"))
    header_name = os.getenv("THEHIVE_API_KEY_HEADER", "Authorization")
    auth_prefix = os.getenv("THEHIVE_AUTH_PREFIX", "Bearer ")
    if api_key:
        if header_name.lower() == "authorization":
            headers["Authorization"] = f"{auth_prefix}{api_key}".strip()
        else:
            headers[header_name] = api_key
    org = thehive_organisation()
    if org:
        headers["X-Organisation"] = org
    return headers


def create_case(
    *,
    title: str,
    description: str,
    severity: Optional[int] = None,
    tlp: int = 2,
    pap: Optional[int] = None,
    tags: Optional[List[str]] = None,
    tasks: Optional[List[Dict[str, Any]]] = None,
    custom_fields: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Creates a TheHive case and returns its ID.

    Notes:
    - TheHive 5 (StrangeBee): POST /api/v1/case + X-Organisation (see thehive_external scripts).
    - TheHive 4: POST /api/case — we fall back when /api/v1/case is not found.
    """
    base = _thehive_base_url()
    if pap is None:
        pap = int(os.getenv("THEHIVE_PAP", "2"))

    payload: Dict[str, Any] = {
        "title": title,
        "description": description,
        "tlp": tlp,
        "pap": pap,
    }
    if severity is not None:
        payload["severity"] = severity
    if tags:
        payload["tags"] = tags
    if tasks:
        payload["tasks"] = tasks
    if custom_fields:
        payload["customFields"] = custom_fields

    if _orchestrator_dry_run():
        # Keep the request safe for the first run; user can set ORCHESTRATOR_DRY_RUN=false later.
        print("[DRY_RUN] Would create TheHive case with payload:")
        print(payload)
        return "dry-run-case"

    order = os.getenv("THEHIVE_CASE_API_ORDER", "v1_first").strip().lower()
    if order == "legacy_first":
        urls = (f"{base}/api/case", f"{base}/api/v1/case")
    else:
        urls = (f"{base}/api/v1/case", f"{base}/api/case")

    resp = None
    for url in urls:
        body = dict(payload)
        if url.endswith("/api/case"):
            body.pop("pap", None)
        resp = requests.post(url, json=body, headers=_headers(), timeout=30)
        if resp.status_code in (200, 201):
            break
        if resp.status_code == 404 and url.endswith("/api/v1/case"):
            continue
        if resp.status_code == 401:
            hint = ""
            if not thehive_organisation():
                hint = " Hint: set THEHIVE_ORGANISATION to your org slug (e.g. demo for the testing stack)."
            raise RuntimeError(
                f"TheHive create case failed: {resp.status_code} {resp.text}{hint}"
            )
        # Recoverable: license expired, missing permission, or backend down.
        # The orchestrator will mark these alerts deferred (not failed) so they
        # can be replayed once the operator fixes things.
        body_text = (resp.text or "")[:300]
        body_lower = body_text.lower()
        if resp.status_code == 402 or "license" in body_lower:
            raise TheHiveRecoverableError(
                f"TheHive license unavailable ({resp.status_code}): {body_text}"
            )
        if (
            resp.status_code == 403
            and ("managecase" in body_lower or "not authorized" in body_lower)
        ):
            raise TheHiveRecoverableError(
                f"TheHive permission denied for case creation ({resp.status_code}): {body_text}"
            )
        if 500 <= resp.status_code < 600:
            raise TheHiveRecoverableError(
                f"TheHive backend error ({resp.status_code}): {body_text}"
            )
        raise RuntimeError(f"TheHive create case failed: {resp.status_code} {resp.text}")

    data = resp.json() if resp.text else {}
    case_id = data.get("id") or data.get("_id") or data.get("caseId")
    if not case_id:
        # Some TheHive configs might respond with { "data": { "id": ... } }.
        case_id = (data.get("data") or {}).get("id")
    if not case_id:
        raise RuntimeError(f"Could not extract case id from TheHive response: {data}")
    return str(case_id)


def list_case_responders(case_id: str) -> List[Dict[str, Any]]:
    """
    Lists available Cortex responders for a given TheHive case.

    Endpoint (TheHive 5):
      GET /api/connector/cortex/responder/case/{id}
    """
    if _orchestrator_dry_run():
        return []

    url = f"{_thehive_base_url()}/api/connector/cortex/responder/case/{case_id}"
    resp = requests.get(url, headers=_headers(), timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"TheHive list responders failed: {resp.status_code} {resp.text}")

    data = resp.json() if resp.text else None
    if data is None:
        return []
    if isinstance(data, list):
        return data
    # Common patterns: {"data": [...]}, {"items": [...]}
    if isinstance(data, dict):
        for key in ("data", "items", "responders"):
            if isinstance(data.get(key), list):
                return data.get(key)
    return []


def run_responder_action(
    *,
    case_id: str,
    responder_id: str,
    cortex_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Starts a Cortex responder via TheHive Cortex connector.

    Endpoint (TheHive 5):
      POST /api/connector/cortex/action
    """
    if _orchestrator_dry_run():
        print("[DRY_RUN] Would run responder action:", {"case_id": case_id, "responder_id": responder_id})
        return {"dry_run": True, "case_id": case_id, "responder_id": responder_id}

    url = f"{_thehive_base_url()}/api/connector/cortex/action"
    payload: Dict[str, Any] = {
        "responderId": responder_id,
        "objectType": "case",
        "objectId": case_id,
    }
    cortex_id_final = cortex_id
    if not cortex_id_final:
        try:
            from integration_config import resolve_thehive_cortex_id

            cortex_id_final = resolve_thehive_cortex_id()
        except Exception:
            cortex_id_final = os.getenv("THEHIVE_CORTEX_ID", "").strip() or None
    if cortex_id_final:
        payload["cortexId"] = cortex_id_final

    resp = requests.post(url, json=payload, headers=_headers(), timeout=30)
    if resp.status_code not in (200, 201, 202):
        raise RuntimeError(f"TheHive run responder failed: {resp.status_code} {resp.text}")

    return resp.json() if resp.text else {"status": "started"}


def _extract_id_list(data: Any, nested_keys: tuple = ("data", "items", "tasks")) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in nested_keys:
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
            if isinstance(value, dict):
                for inner in nested_keys:
                    inner_list = value.get(inner)
                    if isinstance(inner_list, list):
                        return [x for x in inner_list if isinstance(x, dict)]
    return []


def _extract_task_id(task: Dict[str, Any]) -> Optional[str]:
    for key in ("_id", "id", "taskId"):
        value = task.get(key)
        if value:
            return str(value)
    return None


def _is_pattern_not_found(resp: requests.Response) -> bool:
    """True when TheHive returned 404 because it could not resolve a patternId.

    This is almost always TheHive 5's JanusGraph index warm-up window right
    after a cold start: the Pattern vertices exist in Cassandra but the
    `patternId` secondary index hasn't fully materialised yet, so a lookup
    transiently returns 'Pattern not found' for a couple of minutes. A short
    retry with backoff clears it.
    """
    if resp.status_code != 404:
        return False
    body = (resp.text or "").lower()
    return "pattern not found" in body or "notfounderror" in body


def _post_case_procedures_bulk(
    *, case_id: str, procedures: List[Dict[str, Any]]
) -> requests.Response:
    url = f"{_thehive_base_url()}/api/v1/case/{case_id}/procedures"
    return requests.post(url, json={"procedures": procedures}, headers=_headers(), timeout=30)


def _post_case_procedure_single(
    *, case_id: str, procedure: Dict[str, Any]
) -> requests.Response:
    url = f"{_thehive_base_url()}/api/v1/case/{case_id}/procedure"
    return requests.post(url, json=procedure, headers=_headers(), timeout=30)


def bulk_create_case_procedures(case_id: str, pattern_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Link MITRE techniques to a case (TheHive TTP / Procedures panel).

    POST /api/v1/case/{caseId}/procedures

    Resilience (added 2026-05):
    - On 404 'Pattern not found' the bulk call is retried with backoff to ride
      out TheHive 5's post-cold-start index warm-up window
      (env: THEHIVE_PROCEDURE_RETRIES, default 3; THEHIVE_PROCEDURE_BACKOFF_MS,
      default 500). The delay grows linearly.
    - If the bulk call is still failing, we degrade to per-pattern singular
      POSTs so a partial success (e.g. parent T1071 links even when sub-tech
      T1071.001 is still missing) is preserved instead of losing the case
      entirely. Partial success is logged but does NOT raise.
    - If EVERY pattern still 404s after retries, we raise
      `TheHiveRecoverableError` so the orchestrator marks the alert
      `deferred_thehive` and `scripts/retry_deferred_thehive.py` can replay
      it later.
    """
    if not pattern_ids:
        return []
    if _orchestrator_dry_run():
        print("[DRY_RUN] Would link case procedures:", {"case_id": case_id, "patterns": pattern_ids})
        return [{"dry_run": True, "patternId": p} for p in pattern_ids]

    max_retries = max(1, int(os.getenv("THEHIVE_PROCEDURE_RETRIES", "3")))
    backoff_ms = max(0, int(os.getenv("THEHIVE_PROCEDURE_BACKOFF_MS", "500")))

    occur_ms = int(time.time() * 1000)
    procedures = [{"patternId": pid, "occurDate": occur_ms} for pid in pattern_ids]

    # ── Phase 1: bulk POST with retry-on-warmup ────────────────────────────
    resp: Optional[requests.Response] = None
    for attempt in range(1, max_retries + 1):
        resp = _post_case_procedures_bulk(case_id=case_id, procedures=procedures)
        if resp.status_code in (200, 201):
            data = resp.json() if resp.text else []
            return _extract_id_list(data) or procedures
        if not _is_pattern_not_found(resp):
            break  # different error class → don't keep retrying
        if attempt < max_retries:
            time.sleep((backoff_ms / 1000.0) * attempt)

    # ── Phase 2: per-pattern fallback (partial success preferred) ──────────
    # Only enter fallback if the failure looked like a pattern-resolution
    # issue. Other errors (auth, malformed body, etc.) should still bubble.
    if resp is None or not _is_pattern_not_found(resp):
        raise RuntimeError(
            f"TheHive link procedures failed: "
            f"{getattr(resp, 'status_code', '?')} {getattr(resp, 'text', '')}"
        )

    linked: List[Dict[str, Any]] = []
    unresolved: List[str] = []
    for proc in procedures:
        last_single: Optional[requests.Response] = None
        for attempt in range(1, max_retries + 1):
            last_single = _post_case_procedure_single(case_id=case_id, procedure=proc)
            if last_single.status_code in (200, 201):
                body = last_single.json() if last_single.text else proc
                linked.append(body if isinstance(body, dict) else proc)
                break
            if not _is_pattern_not_found(last_single):
                break
            if attempt < max_retries:
                time.sleep((backoff_ms / 1000.0) * attempt)
        else:
            unresolved.append(proc["patternId"])
            continue
        if last_single is not None and last_single.status_code not in (200, 201):
            if _is_pattern_not_found(last_single):
                unresolved.append(proc["patternId"])
            else:
                # Non-warmup hard error on this pattern; record and continue.
                print(
                    f"[SOAR ORCHESTRATOR] WARNING: procedure {proc['patternId']} "
                    f"on case {case_id} failed: {last_single.status_code} "
                    f"{(last_single.text or '')[:160]}"
                )

    if not linked:
        # Nothing got attached and the only failure mode was 'Pattern not found'.
        # That's recoverable — defer the alert so we can replay it once TheHive
        # finishes warming its pattern index.
        raise TheHiveRecoverableError(
            f"TheHive could not resolve any MITRE patterns for case {case_id} "
            f"after {max_retries} retries (likely post-restart index warm-up): "
            f"{pattern_ids}"
        )

    if unresolved:
        print(
            f"[SOAR ORCHESTRATOR] WARNING: linked {len(linked)}/{len(procedures)} "
            f"procedures on case {case_id}; unresolved={unresolved}"
        )
    return linked


def list_case_tasks(case_id: str) -> List[Dict[str, Any]]:
    """Return tasks for a case (best-effort across TheHive API variants)."""
    if _orchestrator_dry_run():
        return []

    candidates = (
        f"{_thehive_base_url()}/api/v1/case/{case_id}/task",
        f"{_thehive_base_url()}/api/case/{case_id}/task",
    )
    for url in candidates:
        resp = requests.get(url, headers=_headers(), timeout=30)
        if resp.status_code != 200:
            continue
        tasks = _extract_id_list(resp.json() if resp.text else [], ("data", "tasks", "items"))
        normalized = []
        for task in tasks:
            task_id = _extract_task_id(task)
            if task_id:
                normalized.append({"id": task_id, "title": task.get("title"), "status": task.get("status")})
        if normalized:
            return normalized

    # Fallback: fetch case object and read embedded tasks.
    for url in (
        f"{_thehive_base_url()}/api/v1/case/{case_id}",
        f"{_thehive_base_url()}/api/case/{case_id}",
    ):
        resp = requests.get(url, headers=_headers(), timeout=30)
        if resp.status_code != 200:
            continue
        body = resp.json() if resp.text else {}
        root = body.get("data") if isinstance(body.get("data"), dict) else body
        tasks = _extract_id_list(root, ("tasks", "extraData", "task"))
        normalized = []
        for task in tasks:
            task_id = _extract_task_id(task)
            if task_id:
                normalized.append({"id": task_id, "title": task.get("title"), "status": task.get("status")})
        if normalized:
            return normalized
    return []


def bulk_complete_case_tasks(task_ids: List[str]) -> List[str]:
    """Mark tasks Completed so analysts are not blocked on Waiting checklist items."""
    if not task_ids:
        return []
    if _orchestrator_dry_run():
        print("[DRY_RUN] Would complete tasks:", task_ids)
        return task_ids

    url = f"{_thehive_base_url()}/api/v1/task/_bulk"
    completed: List[str] = []
    for status_value in ("Completed", "Complete"):
        resp = requests.patch(
            url,
            json={"ids": task_ids, "status": status_value},
            headers=_headers(),
            timeout=30,
        )
        if resp.status_code in (200, 204):
            return task_ids
    # Per-task fallback if bulk endpoint differs on this install.
    for task_id in task_ids:
        for status_value in ("Completed", "Complete"):
            patch_url = f"{_thehive_base_url()}/api/v1/task/{task_id}"
            resp = requests.patch(
                patch_url,
                json={"status": status_value},
                headers=_headers(),
                timeout=30,
            )
            if resp.status_code in (200, 204):
                completed.append(task_id)
                break
    return completed


def to_thehive_observable_type(obs: Dict[str, Any]) -> str:
    """Maps internal observable dicts to TheHive observable dataType."""
    t = str(obs.get("type") or "").lower()
    if t == "hash":
        hash_type = str(obs.get("hashType") or "").lower()
        return hash_type or "hash"
    if t == "ja3":
        # No standard TheHive dataType for a JA3 fingerprint; land it as
        # "other" (the caller tags it "ja3" so it stays findable/filterable)
        # unless the org has configured a custom "ja3" observable type.
        return os.getenv("THEHIVE_JA3_DATA_TYPE", "other")
    return t


def create_case_observable(
    *,
    case_id: str,
    data_type: str,
    data: str,
    tlp: int = 2,
    pap: int = 2,
    ioc: bool = True,
    sighted: bool = False,
    tags: Optional[List[str]] = None,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Adds an observable to a TheHive 5 case.

    Endpoint:
      POST /api/v1/case/{caseId}/observable
    """
    if _orchestrator_dry_run():
        print(
            "[DRY_RUN] Would create case observable:",
            {"case_id": case_id, "data_type": data_type, "data": data[:30]},
        )
        return {"dry_run": True, "data_type": data_type, "data": data}

    # StrangeBee/TheHive 5 exposes observable creation on the v1 case endpoint.
    url = f"{_thehive_base_url()}/api/v1/case/{case_id}/observable"
    payload: Dict[str, Any] = {
        "dataType": data_type,
        "data": data,
        "tlp": tlp,
        "pap": pap,
        "ioc": ioc,
        "sighted": sighted,
    }
    if tags:
        payload["tags"] = tags
    if message:
        payload["message"] = message

    resp = requests.post(url, json=payload, headers=_headers(), timeout=30)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"TheHive create observable failed: {resp.status_code} {resp.text}")
    return resp.json() if resp.text else {"status": "created"}


def extract_observable_id(result: Any) -> Optional[str]:
    """Extract the TheHive observable `_id` from a create-observable response.

    TheHive 5 returns either a single dict OR a list of dicts (when `data`
    was passed as an array). We accept both.
    """
    if isinstance(result, list) and result:
        result = result[0]
    if isinstance(result, dict):
        return result.get("_id") or result.get("id")
    return None


def create_case_task(
    *,
    case_id: str,
    title: str,
    description: str,
    group: str = "Playbook",
    status: str = "Waiting",
) -> Optional[str]:
    """Create a single task on a case. Returns the task `_id` (or None in dry-run).

    Endpoint (TheHive 5):
      POST /api/v1/case/{caseId}/task
    """
    if _orchestrator_dry_run():
        print(
            "[DRY_RUN] Would create case task:",
            {"case_id": case_id, "title": title, "status": status},
        )
        return None

    url = f"{_thehive_base_url()}/api/v1/case/{case_id}/task"
    payload: Dict[str, Any] = {
        "title": title,
        "description": description,
        "group": group,
        "status": status,
    }
    resp = requests.post(url, json=payload, headers=_headers(), timeout=30)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"TheHive create task failed: {resp.status_code} {resp.text}")
    data = resp.json() if resp.text else {}
    if isinstance(data, list) and data:
        data = data[0]
    if isinstance(data, dict):
        return data.get("_id") or data.get("id")
    return None


def run_analyzer_via_thehive(
    *,
    observable_id: str,
    analyzer_id: str,
    cortex_id: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Trigger a Cortex analyzer **via TheHive's Cortex connector** so the
    resulting job is linked to the case observable (visible natively in the
    case's Observable -> Analysis tab).

    Endpoint (TheHive 5.x):
      POST /api/connector/cortex/job
      Body: { "analyzerId": "<cortex_analyzer_id>",
              "cortexId":   "<thehive_cortex_server_id>",
              "artifactId": "<thehive_observable_id>",
              "parameters": {...} }

    Returns the TheHive `case_artifact_job` object. Note that on creation
    `cortexJobId` is the literal string "-" (Cortex hasn't picked up the job
    yet); use the response's `_id` as the canonical job identifier and feed
    that to `get_cortex_job_via_thehive()`.

    (Note: the older `/api/connector/cortex/analyzer/{analyzerId}/run` path
    was removed in TheHive 5 — that's what this function originally targeted
    and why every job 404'd until 2026-06-04.)
    """
    if _orchestrator_dry_run():
        print(
            "[DRY_RUN] Would run analyzer via TheHive connector:",
            {"observable_id": observable_id, "analyzer_id": analyzer_id},
        )
        return {"dry_run": True, "analyzer_id": analyzer_id, "observable_id": observable_id}

    cortex_id_final = cortex_id
    if not cortex_id_final:
        try:
            from integration_config import resolve_thehive_cortex_id

            cortex_id_final = resolve_thehive_cortex_id()
        except Exception:
            cortex_id_final = os.getenv("THEHIVE_CORTEX_ID", "").strip() or None

    payload: Dict[str, Any] = {
        "analyzerId": analyzer_id,
        "artifactId": observable_id,
    }
    if cortex_id_final:
        payload["cortexId"] = cortex_id_final
    if parameters:
        payload["parameters"] = parameters

    url = f"{_thehive_base_url()}/api/connector/cortex/job"
    resp = requests.post(url, json=payload, headers=_headers(), timeout=30)
    if resp.status_code not in (200, 201, 202):
        raise RuntimeError(
            f"TheHive run analyzer (via connector) failed: {resp.status_code} {resp.text}"
        )
    return resp.json() if resp.text else {}


def get_cortex_job_via_thehive(
    *, job_id: str, wait_seconds: int = 2
) -> Dict[str, Any]:
    """Fetch a Cortex job's status + report via TheHive's connector.

    Endpoint (TheHive 5.x):
      GET /api/connector/cortex/job/{thehive_job_id}

    IMPORTANT: `job_id` here is TheHive's `case_artifact_job._id` (e.g.
    "~180448"), NOT the Cortex-side job id. The Cortex-side id is reported
    on the response as `cortexJobId` once Cortex has picked the job up
    (initially literal "-").

    We poll-loop locally for up to `wait_seconds` instead of relying on a
    server-side `?atMost=` parameter (which is supported on Cortex's native
    waitreport endpoint but not exposed on TheHive's connector route).
    """
    if _orchestrator_dry_run():
        return {"dry_run": True, "job_id": job_id}

    url = f"{_thehive_base_url()}/api/connector/cortex/job/{job_id}"
    deadline = time.monotonic() + max(int(wait_seconds), 0)
    last_body: Dict[str, Any] = {}
    while True:
        resp = requests.get(url, headers=_headers(), timeout=30)
        if resp.status_code != 200:
            return {
                "job_id": job_id,
                "error": f"{resp.status_code} {(resp.text or '')[:200]}",
            }
        last_body = resp.json() if resp.text else {}
        status = str(last_body.get("status") or "").lower()
        if status in ("success", "failure", "deleted"):
            return last_body
        if time.monotonic() >= deadline:
            return last_body
        time.sleep(0.5)

