import os
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras


DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/soar")


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def ensure_bookkeeping_table(cur) -> None:
    # Keep orchestration idempotency outside of the main `alerts` table.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS soar_orchestrator_bookkeeping (
            alert_id INTEGER PRIMARY KEY,
            flow_id TEXT NOT NULL,
            model TEXT NOT NULL,
            created_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            status TEXT NOT NULL DEFAULT 'pending', -- pending/running/done/failed/skipped
            thehive_case_id TEXT,
            last_error TEXT,
            playbook_plan JSONB,
            enriched_ts TIMESTAMPTZ,
            case_created_ts TIMESTAMPTZ
        );
        ALTER TABLE soar_orchestrator_bookkeeping
            ADD COLUMN IF NOT EXISTS enriched_ts TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS case_created_ts TIMESTAMPTZ;
        """
    )


def ensure_shuffle_results_table(cur) -> None:
    """Append-only log of Shuffle's POSTs to /soar/shuffle-result (the §7.1
    callback_url). Kept separate from soar_orchestrator_bookkeeping so a
    retried/duplicate callback never clobbers the original dispatch record.
    """
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS soar_shuffle_results (
            id SERIAL PRIMARY KEY,
            flow_id TEXT NOT NULL,
            thehive_case_id TEXT,
            results JSONB,
            received_ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )


def ensure_feedback_table(cur) -> None:
    """Interim store for SOAR_WORKFLOW_SPEC.md Step 6 (analyst feedback).

    Column names deliberately match the shared `alerts` columns the
    detection side has agreed to add (explanation_useful, flag_for_retraining,
    a true_positive/false_positive verdict) so this table's rows can move
    onto the shared schema with a straight column copy once that migration
    lands — Step 6 will then be owned by the dashboard, not this endpoint.
    """
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS soar_analyst_feedback (
            id SERIAL PRIMARY KEY,
            alert_id INTEGER,
            flow_id TEXT NOT NULL,
            true_positive BOOLEAN,       -- NULL = undecided, true = TP, false = FP
            explanation_useful BOOLEAN,
            flag_for_retraining BOOLEAN,
            note TEXT,
            decided_ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )


def record_shuffle_result(conn, *, flow_id: str, thehive_case_id: str, results: Any) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO soar_shuffle_results (flow_id, thehive_case_id, results)
            VALUES (%s, %s, %s)
            """,
            (flow_id, thehive_case_id, psycopg2.extras.Json(results)),
        )
    conn.commit()


def record_feedback(
    conn,
    *,
    flow_id: str,
    alert_id: Any,
    true_positive: Any,
    explanation_useful: Any,
    flag_for_retraining: Any,
    note: Any,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO soar_analyst_feedback
              (alert_id, flow_id, true_positive, explanation_useful, flag_for_retraining, note)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (alert_id, flow_id, true_positive, explanation_useful, flag_for_retraining, note),
        )
    conn.commit()


def pick_next_alert(conn, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Returns alert rows that have not been processed by the orchestrator yet.

    Selects a.* on purpose: the translator owns the alerts schema and evolves
    it (startup ALTERs), so an explicit column list here would break on every
    schema change. Downstream code reads fields via .get() with defaults, so
    extra or missing columns degrade gracefully instead of crashing the poll
    loop.
    """
    sql = """
        SELECT a.*
        FROM alerts a
        LEFT JOIN soar_orchestrator_bookkeeping b
          ON b.alert_id = a.id
        WHERE b.alert_id IS NULL
        ORDER BY a.translated_ts DESC NULLS LAST
        LIMIT %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (limit,))
        rows = list(cur.fetchall())
    # Read-only, but psycopg2 leaves the transaction open until commit/rollback.
    # Without this, empty polls stay "idle in transaction" and block DDL on `alerts`
    # (e.g. translator startup ALTERs).
    conn.commit()
    return rows



def fetch_alert_by_id(conn, alert_id: int) -> Dict[str, Any] | None:
    """Fetch the durable alert row pointed to by a Kafka trigger event."""
    with conn.cursor() as cur:
        cur.execute("SELECT a.* FROM alerts a WHERE a.id = %s", (alert_id,))
        row = cur.fetchone()
    conn.commit()
    return row


def claim_alert_for_processing(conn, alert_id: int, flow_id: str, model: str) -> bool:
    """Atomically claim an alert before processing.

    This is the idempotency gate shared by Kafka events and Postgres polling:
    a duplicate Kafka event, a replayed offset, or a polling pass racing the
    Kafka trigger can only insert this bookkeeping row once.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO soar_orchestrator_bookkeeping
              (alert_id, flow_id, model, status, updated_ts)
            VALUES
              (%s, %s, %s, 'running', NOW())
            ON CONFLICT (alert_id) DO NOTHING
            RETURNING alert_id
            """,
            (alert_id, flow_id, model),
        )
        row = cur.fetchone()
    conn.commit()
    return row is not None


def mark_status(conn, alert_id: int, flow_id: str, model: str, status: str, **extra) -> None:
    """
    Creates or updates bookkeeping row for one alert.
    """
    extra.setdefault("thehive_case_id", None)
    extra.setdefault("last_error", None)
    extra.setdefault("playbook_plan", None)

    with conn.cursor() as cur:
        # psycopg2 needs explicit JSON adaptation for JSONB columns.
        if "playbook_plan" in extra and extra["playbook_plan"] is not None:
            extra["playbook_plan"] = psycopg2.extras.Json(extra["playbook_plan"])

        cur.execute(
            """
            INSERT INTO soar_orchestrator_bookkeeping
              (alert_id, flow_id, model, status, thehive_case_id, last_error, playbook_plan, updated_ts)
            VALUES
              (%(alert_id)s, %(flow_id)s, %(model)s, %(status)s, %(thehive_case_id)s, %(last_error)s, %(playbook_plan)s, NOW())
            ON CONFLICT (alert_id) DO UPDATE SET
              status = EXCLUDED.status,
              thehive_case_id = EXCLUDED.thehive_case_id,
              last_error = EXCLUDED.last_error,
              playbook_plan = EXCLUDED.playbook_plan,
              updated_ts = NOW()
            """,
            {
                "alert_id": alert_id,
                "flow_id": flow_id,
                "model": model,
                "status": status,
                **extra,
            },
        )
    conn.commit()


# ── Gated-action approval loop (dashboard-mediated) ──────────────────────────
# A gated block/isolate on a managed endpoint is parked here as `pending`; the
# dashboard surfaces it, the analyst approves/rejects, and POST /soar/approve
# resolves it (executing the real Wazuh AR on approve). Replaces the Shuffle
# User-Input gate, which could not log a rejection.

def ensure_pending_approvals_table(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS soar_pending_approvals (
            id SERIAL PRIMARY KEY,
            alert_id INTEGER,
            flow_id TEXT NOT NULL,
            agent_id TEXT,                 -- Wazuh agent to route the action to
            action_type TEXT NOT NULL,     -- block | isolate
            target_value TEXT,             -- malicious dst IP for block; NULL for isolate
            case_id TEXT,
            case_url TEXT,
            severity TEXT,
            mitre_ttps JSONB,
            intel_malicious BOOLEAN,
            status TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|rejected|executed|failed|expired
            requested_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_ts TIMESTAMPTZ,
            decided_ts TIMESTAMPTZ,
            analyst TEXT,
            note TEXT,
            ar_result JSONB,
            ar_executed_ts TIMESTAMPTZ
        );
        """
    )
    cur.execute(
        "ALTER TABLE soar_pending_approvals "
        "ADD COLUMN IF NOT EXISTS ar_executed_ts TIMESTAMPTZ;"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_soar_pending_approvals_status "
        "ON soar_pending_approvals (status);"
    )


def record_pending_approval(
    conn,
    *,
    alert_id: Any,
    flow_id: str,
    agent_id: Any,
    action_type: str,
    target_value: Any,
    case_id: Any,
    case_url: Any,
    severity: Any,
    mitre_ttps: Any,
    intel_malicious: Any,
    ttl_seconds: int,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO soar_pending_approvals
              (alert_id, flow_id, agent_id, action_type, target_value, case_id,
               case_url, severity, mitre_ttps, intel_malicious, expires_ts)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW() + (%s || ' seconds')::interval)
            RETURNING id
            """,
            (
                alert_id, flow_id, (str(agent_id) if agent_id else None), action_type,
                (str(target_value) if target_value else None), (str(case_id) if case_id else None),
                case_url, severity, psycopg2.extras.Json(mitre_ttps or []),
                bool(intel_malicious), int(ttl_seconds),
            ),
        )
        approval_id = cur.fetchone()["id"]
    conn.commit()
    return int(approval_id)


def get_pending_approval(conn, approval_id: int) -> Dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM soar_pending_approvals WHERE id = %s", (approval_id,))
        row = cur.fetchone()
    conn.commit()
    return row


def list_pending_approvals(conn, *, limit: int = 100) -> List[Dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM soar_pending_approvals WHERE status = 'pending' "
            "ORDER BY requested_ts DESC LIMIT %s",
            (limit,),
        )
        rows = list(cur.fetchall())
    conn.commit()
    return rows


def claim_pending_approval(conn, approval_id: int) -> Dict[str, Any] | None:
    """Atomically move a row out of `pending` so two concurrent /soar/approve
    calls can't both execute it. Also expires stale rows. Returns the claimed
    row (status was 'pending' and not expired) or None."""
    with conn.cursor() as cur:
        # expire if past TTL
        cur.execute(
            "UPDATE soar_pending_approvals SET status = 'expired', decided_ts = NOW() "
            "WHERE id = %s AND status = 'pending' AND expires_ts IS NOT NULL AND expires_ts < NOW() "
            "RETURNING id",
            (approval_id,),
        )
        if cur.fetchone():
            conn.commit()
            return None
        cur.execute(
            "UPDATE soar_pending_approvals SET status = 'deciding' "
            "WHERE id = %s AND status = 'pending' RETURNING *",
            (approval_id,),
        )
        row = cur.fetchone()
    conn.commit()
    return row


def stamp_bookkeeping_ts(conn, alert_id: int, **ts_kwargs) -> None:
    """Set per-stage timestamp columns on an existing bookkeeping row.

    Accepts keyword args: enriched_ts=<datetime>, case_created_ts=<datetime>.
    Targeted UPDATE — leaves status and all other columns untouched.
    """
    allowed = {"enriched_ts", "case_created_ts"}
    cols = {k: v for k, v in ts_kwargs.items() if k in allowed and v is not None}
    if not cols:
        return
    set_clause = ", ".join(f"{col} = %s" for col in cols)
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE soar_orchestrator_bookkeeping SET {set_clause} WHERE alert_id = %s",
            [*cols.values(), alert_id],
        )
    conn.commit()


def finalize_pending_approval(
    conn, approval_id: int, *, status: str, analyst: Any, note: Any,
    ar_result: Any = None, executed: bool = False,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE soar_pending_approvals
               SET status = %s, analyst = %s, note = %s, ar_result = %s,
                   decided_ts = NOW(),
                   ar_executed_ts = CASE WHEN %s THEN NOW() ELSE NULL END
             WHERE id = %s
            """,
            (
                status, analyst, note,
                psycopg2.extras.Json(ar_result) if ar_result is not None else None,
                executed,
                approval_id,
            ),
        )
    conn.commit()

