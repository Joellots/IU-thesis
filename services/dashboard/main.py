"""
main.py — XAI-SOAR Alert Dashboard (FastAPI + Jinja2 + htmx)
-------------------------------------------------------------
Routes:
    GET  /              — dashboard home (alert queue)
    GET  /alert/{id}    — alert detail with full XAI annotation
    POST /decision      — analyst confirm / dismiss action
    GET  /metrics       — pipeline statistics as JSON (for thesis evaluation)
    GET  /alerts/live   — htmx polling endpoint (returns table rows fragment)
"""

import os
import json
import logging
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

DATABASE_URL      = os.getenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/soar")
REFRESH_MS        = int(os.getenv("REFRESH_INTERVAL_MS", "3000"))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [DASHBOARD] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app       = FastAPI(title="XAI-SOAR Dashboard")
templates = Jinja2Templates(directory="templates")


# ── DB helpers ────────────────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(DATABASE_URL,
                            cursor_factory=psycopg2.extras.RealDictCursor)


def fetch_alerts(limit: int = 100, only_malicious: bool = False):
    conn = get_db()
    cur  = conn.cursor()
    where = "WHERE pred_label = 1" if only_malicious else ""
    cur.execute(f"""
        SELECT id, flow_id, translated_ts, pred_label, pred_proba,
               severity, severity_label, mitre_ttps, top_k_features,
               analyst_decision, model, tier, true_label
        FROM alerts
        {where}
        ORDER BY translated_ts DESC
        LIMIT %s
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def fetch_alert_detail(alert_id: int):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
    row = cur.fetchone()
    conn.close()
    return row


def fetch_metrics():
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM alerts")
    total = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS mal FROM alerts WHERE pred_label = 1")
    malicious = cur.fetchone()["mal"]

    cur.execute("""
        SELECT COUNT(*) AS tier2
        FROM raw_explanations
        WHERE model IN ('XGBoost_SHAP', 'XGBoost_LIME')
    """)
    tier2_count = cur.fetchone()["tier2"]

    cur.execute("""
        SELECT AVG(explain_time_ms) AS avg_ms
        FROM raw_explanations
        WHERE model = 'XGBoost' AND tier = 'fast'
    """)
    avg_explain = cur.fetchone()["avg_ms"]

    cur.execute("""
        SELECT
            AVG(EXTRACT(EPOCH FROM (inferred_ts::timestamptz - sent_ts::timestamptz)) * 1000)
            AS avg_pipeline_ms
        FROM alerts
        WHERE sent_ts IS NOT NULL AND inferred_ts IS NOT NULL
    """)
    avg_pipeline = cur.fetchone()["avg_pipeline_ms"]

    cur.execute("""
        SELECT analyst_decision, COUNT(*) AS n
        FROM alerts GROUP BY analyst_decision
    """)
    decisions = {r["analyst_decision"]: r["n"] for r in cur.fetchall()}

    # TP/FP/TN/FN (only valid where true_label != -1)
    cur.execute("""
        SELECT
            SUM(CASE WHEN pred_label=1 AND true_label=1 THEN 1 ELSE 0 END) AS tp,
            SUM(CASE WHEN pred_label=1 AND true_label=0 THEN 1 ELSE 0 END) AS fp,
            SUM(CASE WHEN pred_label=0 AND true_label=0 THEN 1 ELSE 0 END) AS tn,
            SUM(CASE WHEN pred_label=0 AND true_label=1 THEN 1 ELSE 0 END) AS fn
        FROM alerts WHERE true_label != -1
    """)
    cm = cur.fetchone()

    conn.close()

    return {
        "total_flows":          total,
        "malicious_detected":   malicious,
        "benign_detected":      total - malicious,
        "tier2_trigger_count":  tier2_count // 2 if tier2_count else 0,
        "tier2_trigger_rate":   round(tier2_count / 2 / total, 4) if total else 0,
        "avg_explain_ms":       round(avg_explain, 2) if avg_explain else None,
        "avg_pipeline_ms":      round(avg_pipeline, 2) if avg_pipeline else None,
        "analyst_decisions":    decisions,
        "confusion_matrix":     dict(cm) if cm else {},
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, malicious_only: bool = False):
    alerts = fetch_alerts(limit=200, only_malicious=malicious_only)
    return templates.TemplateResponse("index.html", {
        "request":        request,
        "alerts":         alerts,
        "refresh_ms":     REFRESH_MS,
        "malicious_only": malicious_only,
    })


@app.get("/alerts/live", response_class=HTMLResponse)
async def alerts_live(request: Request, malicious_only: bool = False):
    """htmx polling endpoint — returns only the table body fragment."""
    alerts = fetch_alerts(limit=200, only_malicious=malicious_only)
    return templates.TemplateResponse("_alert_rows.html", {
        "request": request,
        "alerts":  alerts,
    })


@app.get("/alert/{alert_id}", response_class=HTMLResponse)
async def alert_detail(request: Request, alert_id: int):
    alert = fetch_alert_detail(alert_id)
    if not alert:
        return HTMLResponse("<h2>Alert not found</h2>", status_code=404)

    # Parse JSON fields for template rendering
    alert = dict(alert)
    for field in ("top_k_json", "mitre_ttps", "mitre_names"):
        if isinstance(alert.get(field), str):
            alert[field] = json.loads(alert[field])

    return templates.TemplateResponse("detail.html", {
        "request": request,
        "alert":   alert,
    })


@app.post("/decision")
async def analyst_decision(
    alert_id: int  = Form(...),
    decision: str  = Form(...),
    note:     str  = Form(""),
):
    """Record analyst confirm/dismiss decision."""
    conn = get_db()
    cur  = conn.cursor()
    ts   = datetime.now(timezone.utc).isoformat()

    cur.execute("""
        UPDATE alerts
        SET analyst_decision = %s, analyst_ts = %s, analyst_note = %s
        WHERE id = %s
    """, (decision, ts, note, alert_id))

    cur.execute("""
        INSERT INTO analyst_decisions (alert_id, flow_id, decision, note, decided_at)
        SELECT %s, flow_id, %s, %s, %s FROM alerts WHERE id = %s
    """, (alert_id, decision, note, ts, alert_id))

    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.get("/metrics")
async def metrics():
    """Pipeline statistics — JSON endpoint for thesis evaluation."""
    return JSONResponse(content=fetch_metrics())