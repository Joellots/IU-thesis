"""
main.py — Aegis Alert Dashboard (FastAPI + Jinja2 + htmx)
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
import asyncio
import logging
from datetime import datetime, timezone

import httpx
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Request, Form, Body, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates

DATABASE_URL      = os.getenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/soar")
REFRESH_MS        = int(os.getenv("REFRESH_INTERVAL_MS", "3000"))

# ── SOAR approval endpoint (cross-machine, on the SOAR host) ───────────────────
# The dashboard only READS the SOAR-owned soar_pending_approvals table and POSTs
# the analyst's decision here; all enforcement (the real Wazuh Active-Response)
# happens SOAR-side. The token is a shared secret — supplied via env, NEVER code.
SOAR_APPROVAL_URL   = os.getenv("SOAR_APPROVAL_URL", "https://172.31.80.148:8200").rstrip("/")
SOAR_APPROVAL_TOKEN = os.getenv("SOAR_APPROVAL_TOKEN", "")
SOAR_VERIFY_TLS     = os.getenv("SOAR_APPROVAL_VERIFY_TLS", "false").lower() == "true"
SOAR_TIMEOUT_S      = float(os.getenv("SOAR_APPROVAL_TIMEOUT", "10"))
DASHBOARD_ANALYST   = os.getenv("DASHBOARD_ANALYST", "dashboard-analyst")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [DASHBOARD] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app       = FastAPI(title="Aegis Dashboard")
templates = Jinja2Templates(directory="templates")

# CORS for the React SPA (served from a separate origin in dev; same-origin via
# nginx in prod). The browser only ever talks to THIS API — the SOAR token stays
# server-side — so a permissive default is acceptable for the PoC.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Live updates (WebSocket) ──────────────────────────────────────────────────
# One backend task polls a cheap DB "version"; on change it pushes a tick to all
# connected clients, which then refetch. This replaces N clients each polling.
class WSManager:
    def __init__(self):
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, msg: dict):
        for ws in list(self.active):
            try:
                await ws.send_json(msg)
            except Exception:
                self.disconnect(ws)


ws_manager = WSManager()


def _db_version() -> dict:
    """A cheap snapshot that changes whenever there's something new to show."""
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT count(*) AS c, COALESCE(max(id), 0) AS m FROM alerts")
        a = cur.fetchone()
        pending = 0
        if _table_exists(cur, "public.soar_pending_approvals"):
            cur.execute("SELECT count(*) AS c, COALESCE(max(id), 0) AS m FROM soar_pending_approvals")
            p = cur.fetchone()
            pending = int(p["c"]) * 100000 + int(p["m"])     # changes on new/decided
        return {"alerts": int(a["c"]), "max_id": int(a["m"]), "approvals": pending}
    finally:
        conn.close()


async def _poller():
    last = None
    interval = float(os.getenv("WS_POLL_SEC", "2"))
    while True:
        try:
            v = await asyncio.to_thread(_db_version)
            if v != last:
                last = v
                await ws_manager.broadcast({"type": "tick", **v})
        except Exception as e:
            log.warning("ws poller: %s", e)
        await asyncio.sleep(interval)


@app.on_event("startup")
async def _start_poller():
    asyncio.create_task(_poller())


@app.websocket("/api/ws")
async def ws_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        await ws.send_json({"type": "hello"})
        while True:
            await ws.receive_text()      # held open; client never sends — server pushes
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)


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
               analyst_decision, model, tier, true_label,
               agent_id, host_id
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
    total = cur.fetchone()["total"] or 0

    cur.execute("SELECT COUNT(*) AS mal FROM alerts WHERE pred_label = 1")
    malicious = cur.fetchone()["mal"] or 0

    cur.execute("""
        SELECT COUNT(*) AS tier2
        FROM raw_explanations
        WHERE model IN ('XGBoost_SHAP', 'XGBoost_LIME')
    """)
    tier2_count = cur.fetchone()["tier2"] or 0

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
    decisions = {r["analyst_decision"]: int(r["n"]) for r in cur.fetchall()}

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
        "total_flows":         int(total),
        "malicious_detected":  int(malicious),
        "benign_detected":     int(total - malicious),
        "tier2_trigger_count": int(tier2_count // 2),
        "tier2_trigger_rate":  round(tier2_count / 2 / total, 4) if total else 0,
        "avg_explain_ms":      round(float(avg_explain), 2) if avg_explain else None,
        "avg_pipeline_ms":     round(float(avg_pipeline), 2) if avg_pipeline else None,
        "analyst_decisions":   decisions,
        "confusion_matrix": {
            "tp": int(cm["tp"] or 0),
            "fp": int(cm["fp"] or 0),
            "tn": int(cm["tn"] or 0),
            "fn": int(cm["fn"] or 0),
        } if cm else {},
    }

# ── SOAR Approvals (READ-ONLY of the SOAR-owned table; decisions go via API) ──
def _table_exists(cur, qualified_name: str) -> bool:
    cur.execute("SELECT to_regclass(%s) AS reg", (qualified_name,))
    return cur.fetchone()["reg"] is not None


def _mins_left(expires_ts) -> int | None:
    """Whole minutes until expiry (negative if already expired); None if unknown."""
    if not expires_ts:
        return None
    if isinstance(expires_ts, str):
        try:
            expires_ts = datetime.fromisoformat(expires_ts)
        except ValueError:
            return None
    if expires_ts.tzinfo is None:
        expires_ts = expires_ts.replace(tzinfo=timezone.utc)
    return int((expires_ts - datetime.now(timezone.utc)).total_seconds() // 60)


def fetch_pending_approvals(limit: int = 100, include_decided: bool = False):
    """Read the SOAR-owned soar_pending_approvals table (created at runtime by the
    orchestrator). Returns [] gracefully if the orchestrator hasn't created it yet.
    Joins alerts for endpoint identity + flow context. Never writes."""
    conn = get_db()
    cur  = conn.cursor()
    try:
        if not _table_exists(cur, "public.soar_pending_approvals"):
            return []
        where = "" if include_decided else "WHERE p.status = 'pending'"
        cur.execute(f"""
            SELECT p.id, p.alert_id, p.flow_id, p.agent_id, p.action_type,
                   p.target_value, p.case_id, p.case_url, p.severity, p.mitre_ttps,
                   p.intel_malicious, p.status, p.requested_ts, p.expires_ts,
                   p.decided_ts, p.analyst, p.note, p.ar_result,
                   a.host_id, a.host_ip, a.pred_proba, a.severity_label,
                   a.annotation
            FROM soar_pending_approvals p
            LEFT JOIN alerts a ON a.id = p.alert_id
            {where}
            ORDER BY (p.status = 'pending') DESC, p.requested_ts DESC
            LIMIT %s
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    for r in rows:
        r["mins_left"] = _mins_left(r.get("expires_ts"))
    return rows


def fetch_pending_count() -> int:
    conn = get_db()
    cur  = conn.cursor()
    try:
        if not _table_exists(cur, "public.soar_pending_approvals"):
            return 0
        cur.execute("SELECT COUNT(*) AS n FROM soar_pending_approvals WHERE status = 'pending'")
        return int(cur.fetchone()["n"] or 0)
    finally:
        conn.close()


def record_alert_feedback(alert_id: int, decision: str, note: str,
                          explanation_useful: bool, flag_for_retraining: bool) -> str:
    """Persist the Step-6 verdict + feedback to alerts + analyst_decisions.
    verdict ∈ true_positive / false_positive (legacy confirmed/dismissed accepted)."""
    legacy  = {"confirmed": "true_positive", "dismissed": "false_positive"}
    verdict = legacy.get(decision, decision)
    conn = get_db()
    cur  = conn.cursor()
    ts   = datetime.now(timezone.utc).isoformat()
    try:
        cur.execute("""
            UPDATE alerts
            SET analyst_decision = %s, analyst_ts = %s, analyst_note = %s,
                explanation_useful = %s, flag_for_retraining = %s
            WHERE id = %s
        """, (verdict, ts, note, explanation_useful, flag_for_retraining, alert_id))
        cur.execute("""
            INSERT INTO analyst_decisions
                (alert_id, flow_id, decision, note, explanation_useful, flag_for_retraining, decided_at)
            SELECT %s, flow_id, %s, %s, %s, %s, %s FROM alerts WHERE id = %s
        """, (alert_id, verdict, note, explanation_useful, flag_for_retraining, ts, alert_id))
        conn.commit()
    finally:
        conn.close()
    return verdict


def post_approval_decision(approval_id: int, decision: str, analyst: str, note: str) -> dict:
    """POST the decision to the orchestrator's /soar/approve. Returns a normalized
    {ok, kind, status, ar_result, detail} dict — the dashboard never enforces."""
    if not SOAR_APPROVAL_TOKEN:
        return {"ok": False, "kind": "config", "detail": "SOAR_APPROVAL_TOKEN is not configured."}
    try:
        resp = httpx.post(
            f"{SOAR_APPROVAL_URL}/soar/approve",
            json={"approval_id": approval_id, "decision": decision,
                  "analyst": analyst, "note": note},
            headers={"Authorization": f"Bearer {SOAR_APPROVAL_TOKEN}"},
            timeout=SOAR_TIMEOUT_S,
            verify=SOAR_VERIFY_TLS,
        )
    except Exception as e:                       # network/TLS/timeout
        log.warning("approve POST failed id=%s: %s", approval_id, e)
        return {"ok": False, "kind": "unreachable", "detail": str(e)}

    try:
        body = resp.json()
    except Exception:
        body = {}

    if resp.status_code == 200:
        return {"ok": True, "kind": "ok", "status": body.get("status", "done"),
                "ar_result": body.get("ar_result")}
    if resp.status_code == 409:
        return {"ok": False, "kind": "conflict", "detail": "Already decided or expired — refreshing."}
    if resp.status_code == 401:
        return {"ok": False, "kind": "config", "detail": "Rejected by SOAR (401) — check SOAR_APPROVAL_TOKEN."}
    if resp.status_code == 404:
        return {"ok": False, "kind": "notfound", "detail": "Approval id not found (404)."}
    return {"ok": False, "kind": "error",
            "detail": f"SOAR returned {resp.status_code}: {body.get('detail') or resp.text[:200]}"}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, malicious_only: bool = False):
    alerts = fetch_alerts(limit=200, only_malicious=malicious_only)
    return templates.TemplateResponse("index.html", {
        "request":        request,
        "alerts":         alerts,
        "refresh_ms":     REFRESH_MS,
        "malicious_only": malicious_only,
        "pending_count":  fetch_pending_count(),
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
    alert_id:            int = Form(...),
    decision:            str = Form(...),
    note:                str = Form(""),
    explanation_useful:  str = Form(None),   # checkbox → "true" when ticked, else absent
    flag_for_retraining: str = Form(None),
):
    """Record the Step-6 analyst verdict + feedback on an alert (htmx form post)."""
    record_alert_feedback(alert_id, decision, note,
                          explanation_useful == "true", flag_for_retraining == "true")
    return RedirectResponse(url=f"/alert/{alert_id}", status_code=303)


@app.get("/metrics")
async def metrics():
    """Pipeline statistics — JSON endpoint for thesis evaluation."""
    return JSONResponse(content=fetch_metrics())


# ── Analyst Approvals surface ─────────────────────────────────────────────────
@app.get("/approvals", response_class=HTMLResponse)
async def approvals(request: Request):
    rows = fetch_pending_approvals(limit=200, include_decided=False)
    return templates.TemplateResponse("approvals.html", {
        "request":          request,
        "approvals":        rows,
        "refresh_ms":       REFRESH_MS,
        "pending_count":    len(rows),
        "soar_url":         SOAR_APPROVAL_URL,
        "token_configured": bool(SOAR_APPROVAL_TOKEN),
    })


@app.get("/approvals/live", response_class=HTMLResponse)
async def approvals_live(request: Request):
    """htmx polling endpoint — returns the pending-approvals fragment."""
    rows = fetch_pending_approvals(limit=200, include_decided=False)
    return templates.TemplateResponse("_approval_rows.html", {
        "request":   request,
        "approvals": rows,
    })


@app.post("/approvals/decide", response_class=HTMLResponse)
async def approvals_decide(
    request: Request,
    approval_id: int = Form(...),
    decision:    str = Form(...),
    analyst:     str = Form(None),
):
    """Convey the analyst's decision to the orchestrator's /soar/approve. The
    dashboard performs NO enforcement — it only relays the decision + token."""
    note     = (request.headers.get("HX-Prompt") or "").strip()
    analyst  = (analyst or DASHBOARD_ANALYST).strip() or DASHBOARD_ANALYST
    decision = decision.lower().strip()

    if decision not in ("approve", "reject"):
        result = {"ok": False, "kind": "error", "detail": "Invalid decision."}
    else:
        result = post_approval_decision(approval_id, decision, analyst, note)

    # Re-fetch the (now updated) row so the card reflects the new status/ar_result.
    rows = fetch_pending_approvals(limit=500, include_decided=True)
    row  = next((r for r in rows if r["id"] == approval_id), None)
    return templates.TemplateResponse("_approval_card.html", {
        "request":     request,
        "a":           row,
        "result":      result,
        "approval_id": approval_id,
    })


# ── JSON API (consumed by the React SPA — htmx routes above are unchanged) ────
def _parse_json_fields(row: dict, fields) -> dict:
    row = dict(row)
    for f in fields:
        if isinstance(row.get(f), str):
            try:
                row[f] = json.loads(row[f])
            except (ValueError, TypeError):
                pass
    return row


@app.get("/api/summary")
async def api_summary():
    m = fetch_metrics()
    return {
        "total_flows":        m["total_flows"],
        "malicious_detected": m["malicious_detected"],
        "benign_detected":    m["benign_detected"],
        "pending_approvals":  fetch_pending_count(),
    }


@app.get("/api/alerts")
async def api_alerts(malicious_only: bool = False, limit: int = 200):
    return fetch_alerts(limit=limit, only_malicious=malicious_only)


def fetch_soar_actions(alert_id: int):
    """SOAR response actions parked for this alert (read-only of the SOAR-owned
    table). [] if the orchestrator hasn't created it yet."""
    conn = get_db()
    cur  = conn.cursor()
    try:
        if not _table_exists(cur, "public.soar_pending_approvals"):
            return []
        cur.execute("""
            SELECT id, action_type, target_value, status, case_id, case_url,
                   requested_ts, decided_ts, analyst, note
            FROM soar_pending_approvals WHERE alert_id = %s ORDER BY id
        """, (alert_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@app.get("/api/alerts/{alert_id}")
async def api_alert(alert_id: int):
    row = fetch_alert_detail(alert_id)
    if not row:
        return JSONResponse({"detail": "alert not found"}, status_code=404)
    out = _parse_json_fields(row, ("top_k_json", "mitre_ttps", "mitre_names", "observables"))
    out["soar_actions"] = fetch_soar_actions(alert_id)
    return out


@app.get("/api/endpoints")
async def api_endpoints():
    """Endpoint inventory — alerts aggregated by the stamping host/agent."""
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT host_id, agent_id, max(host_ip) AS host_ip,
                   count(*) AS alerts,
                   count(*) FILTER (WHERE pred_label = 1) AS malicious,
                   max(translated_ts) AS last_seen
            FROM alerts
            WHERE agent_id IS NOT NULL OR host_id IS NOT NULL
            GROUP BY host_id, agent_id
            ORDER BY malicious DESC, alerts DESC
        """)
        rows = [dict(r) for r in cur.fetchall()]
        pend = {}
        if _table_exists(cur, "public.soar_pending_approvals"):
            cur.execute("SELECT agent_id, count(*) AS n FROM soar_pending_approvals WHERE status='pending' GROUP BY agent_id")
            pend = {r["agent_id"]: int(r["n"]) for r in cur.fetchall()}
        for r in rows:
            r["pending"] = pend.get(r["agent_id"], 0)
        return rows
    finally:
        conn.close()


@app.get("/api/mapping")
async def api_mapping():
    """Feature→TTP mapping reliability — the headline calibrated-confidence result."""
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT COALESCE(mapping_status, 'unknown') AS status, count(*) AS n,
                   avg(mapping_confidence) AS avg_conf
            FROM alerts WHERE pred_label = 1 GROUP BY mapping_status
        """)
        by_status = {r["status"]: {"n": int(r["n"]),
                     "avg_conf": round(float(r["avg_conf"]), 3) if r["avg_conf"] is not None else None}
                     for r in cur.fetchall()}
        cur.execute("""
            SELECT width_bucket(mapping_confidence, 0, 1, 10) AS b, count(*) AS n
            FROM alerts WHERE pred_label = 1 AND mapping_confidence IS NOT NULL
            GROUP BY b ORDER BY b
        """)
        hist = [0] * 10
        for r in cur.fetchall():
            b = int(r["b"])
            idx = min(max(b - 1, 0), 9)      # bucket 11 == exactly 1.0 → last bin
            hist[idx] += int(r["n"])
        cur.execute("SELECT avg(mapping_confidence) AS a FROM alerts WHERE pred_label=1 AND mapping_status='mapped'")
        a = cur.fetchone()["a"]
        return {"by_status": by_status, "histogram": hist,
                "avg_mapped": round(float(a), 3) if a is not None else None}
    finally:
        conn.close()


@app.get("/api/metrics")
async def api_metrics():
    return fetch_metrics()


@app.get("/api/attack")
async def api_attack():
    """Per-technique alert counts for the ATT&CK coverage matrix
    (how many malicious flows the framework mapped to each TTP)."""
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT ttp, count(*) AS n
            FROM alerts, jsonb_array_elements_text(mitre_ttps) AS ttp
            WHERE pred_label = 1 AND jsonb_typeof(mitre_ttps) = 'array'
            GROUP BY ttp
        """)
        return {r["ttp"]: int(r["n"]) for r in cur.fetchall()}
    finally:
        conn.close()


@app.get("/api/approvals")
async def api_approvals(include_decided: bool = False):
    return fetch_pending_approvals(limit=200, include_decided=include_decided)


@app.post("/api/approvals/{approval_id}/decide")
async def api_approval_decide(approval_id: int, payload: dict = Body(...)):
    decision = str(payload.get("decision", "")).lower().strip()
    if decision not in ("approve", "reject"):
        return JSONResponse({"ok": False, "detail": "decision must be 'approve' or 'reject'"},
                            status_code=400)
    result = post_approval_decision(
        approval_id, decision,
        str(payload.get("analyst") or DASHBOARD_ANALYST),
        str(payload.get("note") or ""),
    )
    # Always 200 with the normalized result; the client branches on result.ok/kind.
    return JSONResponse(result, status_code=200)


@app.post("/api/alerts/{alert_id}/feedback")
async def api_feedback(alert_id: int, payload: dict = Body(...)):
    decision = str(payload.get("decision", "")).lower().strip()
    if decision not in ("true_positive", "false_positive", "confirmed", "dismissed"):
        return JSONResponse({"ok": False, "detail": "decision must be true_positive|false_positive"},
                            status_code=400)
    verdict = record_alert_feedback(
        alert_id, decision, str(payload.get("note") or ""),
        bool(payload.get("explanation_useful")),
        bool(payload.get("flag_for_retraining")),
    )
    return {"ok": True, "alert_id": alert_id, "verdict": verdict}
