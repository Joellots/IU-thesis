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
            # Always prefer .env for this script to avoid stale shell-level vars.
            os.environ[key] = value


def fetch_current_user(session: requests.Session, base_url: str):
    for endpoint in ("/api/v1/user/current", "/api/user/current"):
        try:
            resp = session.get(f"{base_url}{endpoint}", timeout=10)
        except requests.RequestException:
            continue
        if resp.status_code == 200:
            try:
                data = resp.json()
            except json.JSONDecodeError:
                return None
            if isinstance(data, dict):
                return data
    return None


def _as_list(value):
    if isinstance(value, list):
        return value
    return []


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    load_env_file(repo_root / ".env")
    load_env_file(repo_root / "services" / "soar_orchestrator" / ".env")

    base_url = os.getenv("THEHIVE_BASE_URL", "http://localhost:9000/thehive").rstrip("/")
    api_key = os.getenv("THEHIVE_API_KEY", "").strip()
    org = os.getenv("THEHIVE_ORGANISATION", "").strip()

    if not api_key:
        print("ERROR: THEHIVE_API_KEY is missing.")
        return 1

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if org:
        headers["X-Organisation"] = org

    session = requests.Session()
    session.headers.update(headers)
    masked_key = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 10 else "***"
    print(f"Using TheHive URL: {base_url}")
    print(f"Using API key fingerprint: {masked_key}")
    current_user = fetch_current_user(session, base_url)
    if current_user:
        user_name = current_user.get("login") or current_user.get("name") or current_user.get("_id") or "unknown"
        print(f"Resolved TheHive user: {user_name}")
        orgs = _as_list(current_user.get("organisation"))
        profiles = _as_list(current_user.get("profile"))
        perms = _as_list(current_user.get("permissions"))
        if orgs:
            print(f"User organisations: {orgs}")
        if profiles:
            print(f"User profiles: {profiles}")
        if perms:
            has_delete = "manageCase/delete" in perms
            print(f"Permissions count: {len(perms)} | manageCase/delete={has_delete}")
            if not has_delete:
                preview = ", ".join(perms[:20])
                print(f"Permissions preview: {preview}")
    else:
        print("Could not resolve current TheHive user from API.")

    workers = int(os.getenv("CLEANUP_WORKERS", "16"))
    page_size = 500

    deleted = 0
    failures = []
    total_seen = 0
    lock = Lock()

    def delete_one(case_id: str) -> tuple[str, bool, str]:
        try:
            resp = requests.delete(
                f"{base_url}/api/case/{case_id}",
                headers=dict(session.headers),
                timeout=15,
            )
            ok = resp.status_code in (200, 204)
            reason = "" if ok else f"{resp.status_code} {resp.text[:200]}"
            return case_id, ok, reason
        except requests.RequestException as exc:
            return case_id, False, f"request-error: {exc}"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            list_url = f"{base_url}/api/case?range=0-{page_size - 1}"
            try:
                list_resp = session.get(list_url, timeout=15)
            except requests.RequestException as exc:
                print(f"ERROR: Failed to query TheHive cases: {exc}")
                break

            if list_resp.status_code != 200:
                print(f"ERROR: Case listing failed: {list_resp.status_code} {list_resp.text[:300]}")
                break

            try:
                cases = list_resp.json()
            except json.JSONDecodeError:
                print("ERROR: TheHive response was not valid JSON.")
                break

            if not isinstance(cases, list):
                print("ERROR: Unexpected TheHive response shape for case list.")
                break

            case_ids = [c.get("id") for c in cases if isinstance(c, dict) and c.get("id")]
            if not case_ids:
                break

            total_seen += len(case_ids)
            before_deleted = deleted
            print(f"Fetched {len(case_ids)} case(s); deleting in parallel (workers={workers})…")

            futures = {pool.submit(delete_one, cid): cid for cid in case_ids}
            for fut in as_completed(futures):
                case_id, ok, reason = fut.result()
                with lock:
                    if ok:
                        deleted += 1
                    else:
                        failures.append((case_id, reason))
                        if len(failures) == 1:
                            print(f"First delete failure -> case {case_id}: {reason}")

            print(f"  batch done — deleted so far: {deleted}")

            if deleted == before_deleted:
                print("No deletion progress in this batch; stopping to avoid looping.")
                break

    print(f"Seen: {total_seen}")
    print(f"Deleted: {deleted}")
    print(f"Failed: {len(failures)}")
    for case_id, reason in failures[:20]:
        print(f"  - {case_id}: {reason}")

    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
