#!/usr/bin/env python3
"""
Replay alerts that the SOAR orchestrator deferred because TheHive was
unavailable (expired license, insufficient permissions, or temporary 5xx).

Usage (after restoring the TheHive license / fixing the user profile):

  python scripts/retry_deferred_thehive.py [--dry-run] [--limit N] [--postgres-container postgres]

What it does:
  - Connects to the orchestrator's bookkeeping table via `docker exec postgres psql`
    (Postgres is only reachable on the Docker network, not on the host).
  - Finds every row with status='deferred_thehive'.
  - Either prints them (--dry-run) or DELETES the bookkeeping row so the
    orchestrator's `pick_next_alert` LEFT JOIN gate picks them up again on
    its next poll. The original alert rows in `alerts` are NOT touched.

Why DELETE the row instead of marking it 'pending'? The orchestrator's
queue logic is "row absent from bookkeeping = needs processing". Re-inserting
'pending' would still leave the row present and require special handling.
DELETE keeps the queue model simple.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from typing import List, Tuple


def _psql(container: str, sql: str) -> Tuple[int, str, str]:
    """Run `psql -U user -d soar -c <sql>` inside the postgres container."""
    if shutil.which("docker") is None:
        return 127, "", "docker CLI not found on PATH"
    proc = subprocess.run(
        [
            "docker", "exec", "-i", container,
            "psql", "-U", "user", "-d", "soar",
            "-At", "-F", "|",  # unaligned, tuples-only, pipe separator
            "-c", sql,
        ],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def list_deferred(container: str, limit: int) -> List[dict]:
    sql = (
        "SELECT alert_id, flow_id, model, COALESCE(last_error,''), updated_ts "
        "FROM soar_orchestrator_bookkeeping "
        "WHERE status = 'deferred_thehive' "
        "ORDER BY updated_ts ASC"
    )
    if limit > 0:
        sql += f" LIMIT {int(limit)}"
    sql += ";"
    rc, out, err = _psql(container, sql)
    if rc != 0:
        sys.stderr.write(f"psql failed (rc={rc}): {err}\n")
        sys.exit(2)
    rows: List[dict] = []
    for line in out.strip().splitlines():
        parts = line.split("|", 4)
        if len(parts) != 5:
            continue
        rows.append({
            "alert_id": parts[0],
            "flow_id": parts[1],
            "model": parts[2],
            "last_error": parts[3],
            "updated_ts": parts[4],
        })
    return rows


def delete_deferred(container: str, alert_ids: List[str]) -> int:
    if not alert_ids:
        return 0
    # Build IN-clause safely (alert_id is an INTEGER column, so coerce).
    ids_csv = ",".join(str(int(x)) for x in alert_ids)
    sql = (
        "WITH deleted AS ("
        "  DELETE FROM soar_orchestrator_bookkeeping "
        f"  WHERE alert_id IN ({ids_csv}) AND status = 'deferred_thehive' "
        "  RETURNING 1"
        ") SELECT count(*) FROM deleted;"
    )
    rc, out, err = _psql(container, sql)
    if rc != 0:
        sys.stderr.write(f"psql failed (rc={rc}): {err}\n")
        sys.exit(2)
    try:
        return int(out.strip())
    except ValueError:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print, don't delete.")
    parser.add_argument("--limit", type=int, default=0, help="Cap rows replayed (0 = no cap).")
    parser.add_argument(
        "--postgres-container",
        default="postgres",
        help="Name of the Postgres container (default: postgres).",
    )
    args = parser.parse_args()

    print(f"Querying soar_orchestrator_bookkeeping inside container '{args.postgres_container}' ...")
    rows = list_deferred(args.postgres_container, args.limit)

    if not rows:
        print("No deferred-TheHive alerts to replay.")
        return 0

    print(f"Found {len(rows)} deferred alert(s):")
    for r in rows[:10]:
        flow_short = (r["flow_id"] or "")[:8]
        err_short = (r["last_error"] or "")[:80]
        print(
            f"  alert_id={r['alert_id']} flow={flow_short} "
            f"model={r['model']} at={r['updated_ts']} -- {err_short}"
        )
    if len(rows) > 10:
        print(f"  ... and {len(rows) - 10} more")

    if args.dry_run:
        print("\n--dry-run: not deleting bookkeeping rows. Re-run without --dry-run to replay.")
        return 0

    deleted = delete_deferred(args.postgres_container, [r["alert_id"] for r in rows])
    print(
        f"\nDeleted {deleted} bookkeeping row(s). "
        "The orchestrator will re-pick these alerts on its next poll."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
