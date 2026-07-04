import os
import threading
from typing import Any, Dict, List, Optional

import requests


# Caps how many Cortex jobs are actually RUNNING at once across all
# orchestrator workers: held from job launch until its report is retrieved
# (see run_analyzer_on_observable). Gating only the launch POST proved
# insufficient — the POST returns in <1s with the job merely queued, so
# workers still flooded Cortex's queue and enrichment latency grew linearly
# with alert_id.
_cortex_launch_sem = threading.Semaphore(
    int(os.getenv("CORTEX_MAX_CONCURRENT", "2"))
)

CORTEX_BASE_URL = os.getenv("CORTEX_BASE_URL", "http://host.docker.internal:9001/cortex")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "")
CORTEX_BASIC_USER = os.getenv("CORTEX_BASIC_USER", "").strip()
CORTEX_BASIC_PASSWORD = os.getenv("CORTEX_BASIC_PASSWORD", "").strip()


def _cortex_api_key() -> str:
    v = (os.getenv("CORTEX_API_KEY") or "").lstrip("\ufeff").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v


def _cortex_base_url() -> str:
    return os.getenv("CORTEX_BASE_URL", "http://host.docker.internal:9001/cortex").rstrip("/")


def _orchestrator_dry_run() -> bool:
    return os.getenv("ORCHESTRATOR_DRY_RUN", "true").lower() == "true"


CORTEX_TLP = int(os.getenv("CORTEX_TLP", "0"))


def _headers(with_json_body: bool = False) -> Dict[str, str]:
    h: Dict[str, str] = {"Accept": "application/json"}
    if with_json_body:
        h["Content-Type"] = "application/json"
    return h


def _auth() -> Optional[tuple[str, str]]:
    if _cortex_api_key():
        return None
    if CORTEX_BASIC_USER:
        return (CORTEX_BASIC_USER, CORTEX_BASIC_PASSWORD)
    return None


def _request_kwargs(*, with_json_body: bool = False) -> Dict[str, Any]:
    """Build kwargs for `requests.*`. Only sets Content-Type when a JSON body is sent —
    Cortex (Play framework) returns 400 BadRequest if Content-Type: application/json
    is sent on a GET with no body."""
    kwargs: Dict[str, Any] = {"headers": _headers(with_json_body=with_json_body), "auth": _auth()}
    api_key = _cortex_api_key()
    if api_key:
        kwargs["headers"] = {
            **kwargs["headers"],
            "Authorization": f"Bearer {api_key}",
        }
    return kwargs


class CortexClient:
    def __init__(self):
        self._analyzer_index: Optional[Dict[str, Dict[str, Any]]] = None

    def _url(self, path: str) -> str:
        return f"{_cortex_base_url()}{path}"

    def list_enabled_analyzers(self) -> List[Dict[str, Any]]:
        """List analyzers visible to the current Cortex user / organisation.

        Endpoint preference:
          1. `/api/analyzer` — visible to any analyze-role user (most common
             for the integration `thehive` user).
          2. `/api/organization/analyzer` — org-scoped listing, but requires
             org-admin rights in Cortex 4/5.

        Stops on 401 (bad credentials — no point trying the next path with
        the same auth). On 403/404 keeps trying the next path, since the
        next endpoint may use a different permission scope.
        """
        if _orchestrator_dry_run():
            return []

        order_env = os.getenv("CORTEX_LIST_ANALYZER_PATH_ORDER", "").strip()
        if order_env:
            paths = tuple(p.strip() for p in order_env.split(",") if p.strip())
        else:
            paths = ("/api/analyzer", "/api/organization/analyzer")

        last_err: Optional[str] = None
        for path in paths:
            try:
                resp = requests.get(self._url(path), timeout=30, **_request_kwargs())
            except requests.RequestException as exc:
                last_err = str(exc)
                continue
            if resp.status_code == 200:
                data = resp.json() if resp.text else []
                if isinstance(data, list):
                    return data
                return data.get("data") or data.get("items") or []
            last_err = f"{resp.status_code} {resp.text}"
            if resp.status_code == 401:
                break
        raise RuntimeError(f"Cortex list analyzers failed: {last_err}")

    def _ensure_analyzer_index(self) -> None:
        if self._analyzer_index is not None:
            return
        analyzers = self.list_enabled_analyzers()
        idx: Dict[str, Dict[str, Any]] = {}
        for a in analyzers:
            name = a.get("name")
            if name:
                idx[str(name)] = a
        self._analyzer_index = idx

    def resolve_analyzer_id(self, analyzer_name: str) -> Optional[str]:
        if _orchestrator_dry_run():
            return None
        self._ensure_analyzer_index()
        if not self._analyzer_index:
            return None
        analyzer = self._analyzer_index.get(analyzer_name)
        if not analyzer:
            return None
        return analyzer.get("id")

    def launch_analyzer_on_observable(
        self,
        *,
        analyzer_name: str,
        data: str,
        data_type: str,
        parameters: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """POST-only half of `run_analyzer_on_observable`: launches the
        analyzer job in Cortex and returns immediately, without waiting for
        the report. On success the result carries `job_id` — pass it to
        `wait_for_job_report` to fetch the result once ready.

        Do not call this directly for enrichment: it does not hold
        `_cortex_launch_sem`, so it puts no cap on how many jobs pile up in
        Cortex. Use `run_analyzer_on_observable`, which holds the semaphore
        across the whole launch→report span.
        """
        if _orchestrator_dry_run():
            return {
                "analyzer_name": analyzer_name,
                "data_type": data_type,
                "data": data,
                "dry_run": True,
            }

        analyzer_id = self.resolve_analyzer_id(analyzer_name)
        if not analyzer_id:
            return {
                "analyzer_name": analyzer_name,
                "data_type": data_type,
                "data": data,
                "error": f"Analyzer not found/enabled in Cortex: {analyzer_name}",
            }

        payload = {
            "data": data,
            "dataType": data_type,
            "tlp": CORTEX_TLP,
        }
        if parameters:
            payload["parameters"] = parameters

        force_param = "?force=1" if force else ""
        run_url = self._url(f"/api/analyzer/{analyzer_id}/run{force_param}")
        resp = requests.post(run_url, json=payload, timeout=30, **_request_kwargs(with_json_body=True))
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Cortex run failed: {resp.status_code} {resp.text}")

        run_data = resp.json() if resp.text else {}
        job_id = run_data.get("id") or run_data.get("jobId") or run_data.get("job", {}).get("id")
        if not job_id:
            # Fall back to returning run response only.
            return {
                "analyzer_name": analyzer_name,
                "data_type": data_type,
                "data": data,
                "run_response": run_data,
            }

        return {
            "analyzer_name": analyzer_name,
            "data_type": data_type,
            "data": data,
            "job_id": job_id,
        }

    def wait_for_job_report(
        self,
        *,
        analyzer_name: str,
        data: str,
        data_type: str,
        job_id: str,
        wait_seconds: int = 5,
    ) -> Dict[str, Any]:
        """Poll-only half of `run_analyzer_on_observable`: blocks (bounded by
        `wait_seconds`) for a previously launched job's report.
        Cortex docs: /api/job/JOB_ID/waitreport?atMost=1minute (we use seconds)."""
        at_most = f"{wait_seconds}seconds"
        wait_url = self._url(f"/api/job/{job_id}/waitreport?atMost={at_most}")
        report_resp = requests.get(wait_url, timeout=30 + wait_seconds, **_request_kwargs())  # GET → no Content-Type
        if report_resp.status_code not in (200, 201):
            return {
                "analyzer_name": analyzer_name,
                "data_type": data_type,
                "data": data,
                "job_id": job_id,
                "error": f"Waitreport failed: {report_resp.status_code} {report_resp.text}",
            }
        report = report_resp.json() if report_resp.text else {}

        return {
            "analyzer_name": analyzer_name,
            "data_type": data_type,
            "data": data,
            "job_id": job_id,
            "report": report,
        }

    def run_analyzer_on_observable(
        self,
        *,
        analyzer_name: str,
        data: str,
        data_type: str,
        parameters: Optional[Dict[str, Any]] = None,
        force: bool = False,
        wait_seconds: int = 5,
    ) -> Dict[str, Any]:
        """Runs a Cortex analyzer on a single observable and returns a
        report-like payload — launch + wait in one blocking call, composed
        from `launch_analyzer_on_observable` + `wait_for_job_report`.

        The whole launch→report span holds `_cortex_launch_sem`, so at most
        CORTEX_MAX_CONCURRENT jobs are in flight in Cortex across ALL
        orchestrator workers. This is the enrichment entry point every
        caller should use — calling the launch/wait halves directly bypasses
        the cap and re-creates the queue-saturation problem this guards
        against."""
        with _cortex_launch_sem:
            launch = self.launch_analyzer_on_observable(
                analyzer_name=analyzer_name,
                data=data,
                data_type=data_type,
                parameters=parameters,
                force=force,
            )
            job_id = launch.get("job_id")
            if not job_id:
                return launch
            return self.wait_for_job_report(
                analyzer_name=analyzer_name,
                data=data,
                data_type=data_type,
                job_id=job_id,
                wait_seconds=wait_seconds,
            )

