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
            playbook_plan JSONB
        );
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

