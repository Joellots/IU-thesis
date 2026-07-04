#!/usr/bin/env python3
"""
Pull recent Cortex jobs and print their FULL error reports so we can diagnose
exactly why analyzers are failing.

Usage:
  python scripts/inspect_cortex_jobs.py [--limit 10] [--only-failed]
                                        [--analyzer Abuse_Finder_3_0]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services" / "soar_orchestrator"))


def _load_dotenv(env_path: Path) -> None:
    if not env_path.exists():
        return
    try:
        text = env_path.read_text(encoding="utf-8-sig")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lstrip("\ufeff")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


_load_dotenv(REPO_ROOT / ".env")

os.environ["CORTEX_BASE_URL"] = "http://127.0.0.1:9001/cortex"
os.environ["ORCHESTRATOR_DRY_RUN"] = "false"

import requests  # noqa: E402

from cortex_client import _cortex_api_key, _cortex_base_url  # noqa: E402


def _headers() -> dict:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {_cortex_api_key()}",
    }


def list_jobs(limit: int) -> list:
    """Cortex /api/job?range=0-N returns most-recent jobs."""
    url = f"{_cortex_base_url()}/api/job?range=0-{max(0, limit - 1)}&sort=-createdAt"
    resp = requests.get(url, headers=_headers(), timeout=20)
    if resp.status_code != 200:
        sys.stderr.write(f"List jobs failed: {resp.status_code} {resp.text[:300]}\n")
        sys.exit(2)
    data = resp.json()
    return data if isinstance(data, list) else data.get("data") or []


def get_job_report(job_id: str) -> dict:
    url = f"{_cortex_base_url()}/api/job/{job_id}/report"
    resp = requests.get(url, headers=_headers(), timeout=20)
    if resp.status_code != 200:
        return {"_fetch_error": f"{resp.status_code} {resp.text[:300]}"}
    return resp.json()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--only-failed", action="store_true")
    p.add_argument("--analyzer", default=None, help="Filter by analyzer name.")
    args = p.parse_args()

    print(f"Cortex: {_cortex_base_url()}\n")
    jobs = list_jobs(args.limit)
    if not jobs:
        print("No jobs found.")
        return 0

    shown = 0
    for j in jobs:
        analyzer_name = j.get("analyzerName") or j.get("workerName") or "?"
        status = j.get("status", "?")
        job_id = j.get("id") or j.get("_id")
        observable = j.get("data", "?")
        dtype = j.get("dataType", "?")
        created = j.get("createdAt")

        if args.only_failed and status != "Failure":
            continue
        if args.analyzer and analyzer_name != args.analyzer:
            continue

        shown += 1
        print("=" * 80)
        print(f"Job {job_id}")
        print(f"  analyzer = {analyzer_name}")
        print(f"  status   = {status}")
        print(f"  data     = {dtype}={observable}")
        print(f"  created  = {created}")

        report = get_job_report(job_id)
        inner = report.get("report") or {}

        if status == "Failure":
            err = (
                report.get("errorMessage")
                or inner.get("errorMessage")
                or "(no errorMessage field)"
            )
            print("\n  --- FULL ERROR ---")
            print("  " + str(err).replace("\n", "\n  "))
            inp = report.get("input") or inner.get("input")
            if inp:
                print("\n  --- INPUT PASSED TO ANALYZER ---")
                print("  " + json.dumps(inp, indent=2).replace("\n", "\n  ")[:800])
        else:
            summary = inner.get("summary") or {}
            print(f"  taxonomies = {summary.get('taxonomies')}")

    if shown == 0:
        print("(no jobs matched the filters)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
