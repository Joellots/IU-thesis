import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

import requests


def load_env_file(env_path: Path) -> None:
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ[key] = value


def fetch_job_page(session: requests.Session, base_url: str, batch_size: int) -> list[dict]:
    url = f"{base_url}/api/job?range=0-{batch_size - 1}&sort=-createdAt"
    try:
        resp = session.post(
            f"{base_url}/api/job/_search?range=0-{batch_size - 1}&sort=-createdAt",
            json={},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else data.get("data", data.get("items", []))
    except requests.RequestException:
        pass
    # fall back to GET
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else data.get("data", data.get("items", []))
    except requests.RequestException as exc:
        print(f"ERROR: Failed to list Cortex jobs: {exc}")
    return []


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    load_env_file(repo_root / ".env")
    load_env_file(repo_root / "services" / "soar_orchestrator" / ".env")

    base_url = os.getenv("CORTEX_BASE_URL", "http://localhost:9001/cortex").rstrip("/")
    api_key = os.getenv("CORTEX_API_KEY", "").strip()
    workers = int(os.getenv("CLEANUP_WORKERS", "16"))
    batch_size = 500

    if not api_key:
        print("ERROR: CORTEX_API_KEY is missing.")
        return 1

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    session = requests.Session()
    session.headers.update(headers)

    masked_key = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 10 else "***"
    print(f"Cortex URL : {base_url}")
    print(f"API key    : {masked_key}")
    print(f"Workers    : {workers}")

    deleted = 0
    failures = []
    total_seen = 0
    lock = Lock()

    def delete_one(job_id: str, analyzer: str, status: str) -> tuple[str, bool, str]:
        try:
            resp = requests.delete(
                f"{base_url}/api/job/{job_id}",
                headers=headers,
                timeout=15,
            )
            ok = resp.status_code in (200, 202, 204)
            reason = "" if ok else f"{resp.status_code} {resp.text[:200]}"
            return job_id, ok, reason
        except requests.RequestException as exc:
            return job_id, False, f"request-error: {exc}"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            jobs = fetch_job_page(session, base_url, batch_size)
            if not jobs:
                break

            job_ids = [
                (j.get("id") or j.get("_id"), j.get("analyzerName") or j.get("workerName") or "?", j.get("status") or "?")
                for j in jobs
                if isinstance(j, dict) and (j.get("id") or j.get("_id"))
            ]
            if not job_ids:
                break

            total_seen += len(job_ids)
            before_deleted = deleted
            print(f"Fetched {len(job_ids)} job(s); deleting in parallel (workers={workers})…")

            futures = {pool.submit(delete_one, jid, analyzer, status): jid for jid, analyzer, status in job_ids}
            for fut in as_completed(futures):
                job_id, ok, reason = fut.result()
                with lock:
                    if ok:
                        deleted += 1
                    else:
                        failures.append((job_id, reason))
                        if len(failures) == 1:
                            print(f"First delete failure -> job {job_id}: {reason}")

            print(f"  batch done — deleted so far: {deleted}")

            if deleted == before_deleted:
                print("No deletion progress in this batch; stopping to avoid looping.")
                break

    print(f"Seen   : {total_seen}")
    print(f"Deleted: {deleted}")
    print(f"Failed : {len(failures)}")
    for job_id, reason in failures[:20]:
        print(f"  - {job_id}: {reason}")

    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
