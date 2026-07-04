"""Reproducibility helper for the SOAR thesis demo.

Brings the full stack up (if not already running), then polls Postgres until at
least ``--cases`` orchestrator bookkeeping rows have reached ``status='done'``.
Finally prints a compact summary table and the URLs the reviewer should open
(TheHive, Cortex, Grafana, Prometheus, Dashboard).

Usage examples::

    # Default: bring stack up, wait for 5 done cases, give up after 25 min
    python scripts/run_demo.py

    # Custom thresholds
    python scripts/run_demo.py --cases 20 --timeout 1800

    # Skip `docker compose up` (assume the stack is already running)
    python scripts/run_demo.py --no-up

This script intentionally has *zero* third-party dependencies beyond psycopg2
(already required by the orchestrator) so it can be run from a freshly cloned
repo without `pip install`.

It is read-only against the database. The point is to give a thesis reviewer
one command that proves the entire pipeline works.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Tuple

# psycopg2 is part of the orchestrator deps — install it on the host with
# `pip install psycopg2-binary` if you want to run this script outside Docker.
try:
    import psycopg2
    import psycopg2.extras
except ImportError:                              # pragma: no cover
    print(
        "ERROR: psycopg2 is required. Install it with `pip install psycopg2-binary`.",
        file=sys.stderr,
    )
    sys.exit(2)


# ---- defaults -------------------------------------------------------------

DEFAULT_DB_URL = os.getenv(
    "DEMO_DATABASE_URL",
    "postgresql://user:pass@127.0.0.1:5432/soar",
)
DEFAULT_COMPOSE_SERVICES = [
    "postgres", "kafka", "kafka-ui",
    "producer", "inference", "translator", "dashboard",
    "soar_orchestrator", "prometheus", "grafana",
]


# ---- helpers --------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _run(cmd: List[str], *, check: bool = True) -> int:
    print(f"[{_now()}] $ {' '.join(cmd)}")
    return subprocess.call(cmd) if not check else subprocess.check_call(cmd)


def _compose_up(services: List[str]) -> None:
    """`docker compose up -d` for the given services. Errors are bubbled up."""
    # --progress plain keeps compose's output readable when this script's
    # output is piped or captured (the TTY renderer garbles in a pipe).
    _run(["docker", "compose", "--progress", "plain", "up", "-d", *services])


def _query_status(db_url: str) -> Tuple[Counter, List[Dict]]:
    """Return (status_counts, recent_done_rows). 5 most-recent done rows."""
    with psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, COUNT(*) AS n FROM soar_orchestrator_bookkeeping GROUP BY status"
            )
            counts = Counter({row["status"]: int(row["n"]) for row in cur.fetchall()})
            cur.execute(
                """
                SELECT alert_id, flow_id, model, thehive_case_id, updated_ts
                FROM soar_orchestrator_bookkeeping
                WHERE status = 'done'
                ORDER BY updated_ts DESC
                LIMIT 5
                """
            )
            recent = list(cur.fetchall())
        conn.commit()
    return counts, recent


def _wait_for_done(db_url: str, target: int, timeout: int, poll: int = 5) -> Tuple[Counter, List[Dict]]:
    deadline = time.time() + timeout
    counts: Counter = Counter()
    recent: List[Dict] = []
    while time.time() < deadline:
        try:
            counts, recent = _query_status(db_url)
        except psycopg2.OperationalError as exc:
            # DB may still be starting up — retry quietly for the first minute.
            print(f"[{_now()}] postgres not ready yet: {exc}")
            time.sleep(poll)
            continue
        done = counts.get("done", 0)
        line = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"[{_now()}] progress done={done}/{target} {line}")
        if done >= target:
            return counts, recent
        time.sleep(poll)
    return counts, recent


def _print_summary(counts: Counter, recent: List[Dict], target: int) -> int:
    print()
    print("=" * 72)
    print(" SOAR demo summary")
    print("=" * 72)
    if not counts:
        print(" (no orchestrator bookkeeping rows yet)")
        return 1
    width = max(len(k) for k in counts.keys())
    for status, n in sorted(counts.items()):
        print(f"   {status.ljust(width)}  {n}")
    print()
    if recent:
        print(" Last 5 cases created:")
        for row in recent:
            print(
                f"   alert={row['alert_id']:<8} "
                f"flow={row['flow_id'][:8]} "
                f"model={row['model']:<10} "
                f"case={row['thehive_case_id']:<10} "
                f"at={row['updated_ts'].astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}Z"
            )
    print()
    print(" Open these in your browser to verify:")
    print("   TheHive    : http://127.0.0.1:9000")
    print("   Cortex     : http://127.0.0.1:9001")
    print("   Dashboard  : http://127.0.0.1:8501")
    print("   Prometheus : http://127.0.0.1:9090")
    print("   Grafana    : http://127.0.0.1:3001    (admin / admin)")
    print()
    done = counts.get("done", 0)
    if done >= target:
        print(f" SUCCESS — observed {done} completed cases (target {target}).")
        return 0
    print(f" TIMEOUT — only {done}/{target} cases reached 'done'.")
    return 1


# ---- entry point ----------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=5,
                        help="Number of 'done' cases to wait for (default 5).")
    parser.add_argument("--timeout", type=int, default=1500,
                        help="Overall wait in seconds (default 1500 = 25 min).")
    parser.add_argument("--db-url", default=DEFAULT_DB_URL,
                        help="Postgres URL (default uses DEMO_DATABASE_URL or localhost).")
    parser.add_argument("--no-up", action="store_true",
                        help="Skip `docker compose up`; assume the stack is already running.")
    parser.add_argument("--services", nargs="*", default=DEFAULT_COMPOSE_SERVICES,
                        help="Compose services to start (default: full pipeline).")
    args = parser.parse_args()

    if not args.no_up:
        try:
            _compose_up(args.services)
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"docker compose up failed: {exc}", file=sys.stderr)
            print("Tip: run with --no-up if the stack is already managed elsewhere.")
            return 2

    counts, recent = _wait_for_done(args.db_url, args.cases, args.timeout)
    return _print_summary(counts, recent, args.cases)


if __name__ == "__main__":
    raise SystemExit(main())
