#!/usr/bin/env python3
"""
End-to-end sanity check of the Cortex analyzer integration that the SOAR
orchestrator uses, WITHOUT going through TheHive.

This proves:
  - .env is loaded correctly
  - CORTEX_API_KEY is valid
  - The analyzers we activated are visible to the orchestrator's user
  - Each analyzer can actually run a job and return a report

Usage:
  python scripts/test_cortex_analyzers.py [--observable 8.8.8.8] [--type ip]
                                          [--timeout 60] [--only Abuse_Finder_3_0]

Defaults to running every Tier-0 analyzer compatible with the given data type
against the given observable.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List

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

# This script runs on the host (not inside Docker), so always reach Cortex on
# 127.0.0.1. The orchestrator inside the docker network uses host.docker.internal
# or the `cortex:` service name — neither resolves from the host.
os.environ["CORTEX_BASE_URL"] = os.environ.get(
    "CORTEX_BASE_URL_HOST", "http://127.0.0.1:9001/cortex"
)

# Force real (non-dry-run) calls regardless of what's in .env.
os.environ["ORCHESTRATOR_DRY_RUN"] = "false"

from cortex_client import (  # noqa: E402
    CortexClient,
    _cortex_api_key,
    _cortex_base_url,
)
from integration_config import (  # noqa: E402
    TIER0_DOMAIN_ANALYZERS,
    TIER0_HASH_ANALYZERS,
    TIER0_IP_ANALYZERS,
    TIER0_URL_ANALYZERS,
)

TIER0_BY_TYPE = {
    "ip": TIER0_IP_ANALYZERS,
    "domain": TIER0_DOMAIN_ANALYZERS,
    "url": TIER0_URL_ANALYZERS,
    "hash": TIER0_HASH_ANALYZERS,
}


def _summarize_report(report: dict) -> str:
    """Extract a short, human-friendly line from a Cortex job report."""
    if not isinstance(report, dict):
        return "(no report)"
    if report.get("error"):
        return f"ERROR: {report['error']}"

    inner = report.get("report") or {}
    status = report.get("status") or inner.get("status")

    # Cortex puts errorMessage at the top of the report or inside `errorMessage`
    # on Failure jobs.
    if status == "Failure":
        err = (
            report.get("errorMessage")
            or inner.get("errorMessage")
            or (inner.get("errors") or [{}])[0].get("message")
            or "(no error message)"
        )
        # Show the LAST 600 chars — tracebacks are most informative at the bottom.
        s = str(err).strip()
        if len(s) > 600:
            s = "...\n" + s[-600:]
        return f"FAILURE:\n{s}"

    summary = inner.get("summary") or {}
    tax = summary.get("taxonomies") or []
    parts: List[str] = []
    for t in tax[:4]:
        if not isinstance(t, dict):
            continue
        parts.append(
            f"{t.get('level','info')}:{t.get('namespace','?')}/{t.get('predicate','?')}={t.get('value','?')}"
        )
    if parts:
        return " | ".join(parts)
    if status:
        return f"status={status}"
    return "(no taxonomies returned)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observable", default="8.8.8.8")
    parser.add_argument("--type", dest="dtype", default="ip",
                        choices=["ip", "domain", "url", "hash"])
    parser.add_argument("--timeout", type=int, default=45,
                        help="Per-analyzer wait_seconds passed to waitreport.")
    parser.add_argument("--only", default=None, help="Only run this analyzer name.")
    args = parser.parse_args()

    print(f"Cortex base URL: {_cortex_base_url()}")
    key = _cortex_api_key()
    print(f"API key:         {('set ('+str(len(key))+' chars)') if key else 'MISSING'}")

    client = CortexClient()
    try:
        enabled = client.list_enabled_analyzers()
    except Exception as exc:
        print(f"\nERROR: could not list analyzers — {exc}")
        return 2
    enabled_names = sorted({str(a.get("name")) for a in enabled if a.get("name")})
    print(f"Analyzers visible: {len(enabled_names)}")
    for n in enabled_names:
        print(f"   - {n}")
    print()

    if args.only:
        targets = [args.only]
    else:
        targets = [a for a in TIER0_BY_TYPE.get(args.dtype, []) if a in enabled_names]

    if not targets:
        print("No matching activated analyzers found. Activate them first with:\n"
              "  python scripts/setup_soar_integrations.py")
        return 1

    print(f"Running {len(targets)} analyzer(s) against {args.dtype}={args.observable} "
          f"(per-job wait: {args.timeout}s) ...\n")

    fails = 0
    for name in targets:
        try:
            result = client.run_analyzer_on_observable(
                analyzer_name=name,
                data=args.observable,
                data_type=args.dtype,
                wait_seconds=args.timeout,
            )
        except Exception as exc:
            print(f"  ! {name:35s} -> EXCEPTION: {exc}")
            fails += 1
            continue
        if result.get("error"):
            print(f"  ! {name:35s} -> ERROR: {result['error']}")
            fails += 1
            continue
        report = result.get("report") or {}
        line = _summarize_report(report)
        ok = not (line.startswith("ERROR") or line.startswith("FAILURE"))
        marker = "+" if ok else "!"
        if not ok:
            fails += 1
        print(f"  {marker} {name:35s} -> {line}")

    print(f"\nDone. {len(targets) - fails}/{len(targets)} analyzer(s) returned a usable report.")
    return 0 if fails == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
