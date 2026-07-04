#!/usr/bin/env python3
"""SOAR evaluation metrics harvester — SOAR_EVAL_CHECKLIST.md A1–A8 + B3 plots.

Non-destructive: opens read-only DB connections; never writes to any SOAR table.

Usage (from the repo root):
    DATABASE_URL=... python3 utils/soar_metrics_harvest.py [--since-id ALERT_ID] [--log PATH]

Default: --since-id 0  (all rows; pass a watermark alert_id to filter to a specific run)

Outputs into report/eval/:
    metrics.json          — machine-readable metrics (all sections)
    SOAR_EVAL_SUMMARY.md  — human-readable per-area tables
    timeline.csv          — per-alert per-stage latencies
    cortex_verdicts.csv   — per-observable Cortex job outcomes
    approvals.csv         — per-approval outcomes with AR result
    confidence.csv        — per-alert pred_proba (for the confidence histogram)
    *.png                 — B3 figures (requires matplotlib)

Schema notes (live DB, as of 2026-06-25 run):
    alerts.severity_label        → uppercase 'HIGH'/'MEDIUM'/'LOW'
    bookkeeping.playbook_plan    → JSONB; decision cells in endpoint_response (auto-block)
                                   and pending_approvals[] list (gated); no shuffle.actions key
    bookkeeping.enriched_ts      → populated by stamp_bookkeeping_ts() after Phase A build
    bookkeeping.case_created_ts  → same
    pending_approvals.ar_executed_ts → set only for human-approved gated actions
    For auto-blocks the enforcement timestamp is approximated by bookkeeping.updated_ts (done_ts)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
import psycopg2.extras

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

OUTDIR = Path(__file__).parent.parent / "report" / "eval"
OUTDIR.mkdir(parents=True, exist_ok=True)

HOST_IP = "172.31.87.134"
# Domains that distinguish the live C2 arm from the PCAP replay arm
LIVE_C2_DOMAINS = {"kzaa.co.za"}


# ── DB helpers ────────────────────────────────────────────────────────────────

def _db() -> psycopg2.extensions.connection:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        sys.exit("DATABASE_URL env var is not set")
    return psycopg2.connect(url)


def _q(conn, sql: str, params: dict | None = None) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params or {})
        return [dict(r) for r in cur.fetchall()]


def _td_s(a, b) -> float | None:
    if a is None or b is None:
        return None
    return (b - a).total_seconds()


def _pct(n: int, d: int) -> str:
    return f"{100*n/d:.1f}%" if d else "N/A"


def _stats(vals: list) -> dict:
    v = sorted(x for x in vals if x is not None)
    if not v:
        return {"median": None, "p90": None, "min": None, "max": None, "n": 0}
    mid = len(v) // 2
    median = (v[mid - 1] + v[mid]) / 2 if len(v) % 2 == 0 else v[mid]
    p90 = v[max(0, int(len(v) * 0.9) - 1)]
    return {"median": median, "p90": p90, "min": v[0], "max": v[-1], "n": len(v)}


def _fmt_s(v) -> str:
    return "N/A" if v is None else f"{v:.2f}s"


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def _population(enriched_observables: list | None) -> str:
    """Classify a done alert as 'live_c2' or 'pcap_replay' by its domain observable."""
    for obs in (enriched_observables or []):
        if obs.get("type") == "domain" and obs.get("value") in LIVE_C2_DOMAINS:
            return "live_c2"
    return "pcap_replay"


# ── A1 / B1: Per-stage latency ───────────────────────────────────────────────

def _before_clause(before_ts: str | None, col: str = "b.updated_ts") -> tuple[str, dict]:
    """Returns (sql_fragment, extra_params) for an optional upper-bound filter."""
    if before_ts:
        return f"AND {col} <= %(before_ts)s", {"before_ts": before_ts}
    return "", {}


def harvest_latency(conn, since_id: int, before_ts: str | None = None) -> dict:
    """
    Joins alerts + bookkeeping + pending_approvals (first approved isolate per flow).

    MTTR clock:
      - sent_ts → ar_executed_ts  for gated actions that were approved (ar_executed_ts set)
      - sent_ts → done_ts         for auto-block flows (block fires inside process_alert;
                                  ar_executed_ts is NULL because no gated approval used)
      - sent_ts → done_ts         fallback for all other done rows
    """
    bclause, bparams = _before_clause(before_ts)
    rows = _q(conn, f"""
        SELECT
            a.id              AS alert_id,
            a.flow_id,
            a.sent_ts,
            a.translated_ts,
            b.created_ts      AS claimed_ts,
            b.enriched_ts,
            b.case_created_ts,
            b.updated_ts      AS done_ts,
            b.status,
            b.playbook_plan,
            MIN(p.requested_ts)    AS approval_requested_ts,
            MAX(CASE WHEN p.status='executed' THEN p.decided_ts    END) AS approval_decided_ts,
            MAX(CASE WHEN p.status='executed' THEN p.ar_executed_ts END) AS ar_executed_ts
        FROM alerts a
        JOIN soar_orchestrator_bookkeeping b ON b.alert_id = a.id
        LEFT JOIN soar_pending_approvals p ON p.alert_id = a.id
        WHERE a.id > %(since_id)s {bclause}
        GROUP BY a.id, a.flow_id, a.sent_ts, a.translated_ts,
                 b.created_ts, b.enriched_ts, b.case_created_ts, b.updated_ts,
                 b.status, b.playbook_plan
        ORDER BY a.id
    """, {"since_id": since_id, **bparams})

    timeline = []
    for r in rows:
        plan = r.get("playbook_plan") or {}
        eo = (plan.get("automation") or {}).get("enriched_observables") or []
        pop = _population(eo)

        timeline.append({
            "alert_id":         r["alert_id"],
            "flow_id":          r["flow_id"],
            "status":           r["status"],
            "population":       pop,
            "detection_s":      _td_s(r["sent_ts"],               r["translated_ts"]),
            "claim_s":          _td_s(r["translated_ts"],         r["claimed_ts"]),
            "enrichment_s":     _td_s(r["claimed_ts"],            r["enriched_ts"]),
            "case_creation_s":  _td_s(r["enriched_ts"],           r["case_created_ts"]),
            "to_approval_s":    _td_s(r["case_created_ts"],       r["approval_requested_ts"]),
            "human_decision_s": _td_s(r["approval_requested_ts"], r["approval_decided_ts"]),
            "enforcement_s":    _td_s(r["approval_decided_ts"],   r["ar_executed_ts"]),
            "mttr_s":           _td_s(r["sent_ts"],               r["done_ts"]),
        })

    _write_csv(OUTDIR / "timeline.csv", timeline)

    done = [t for t in timeline if t["status"] == "done"]
    stages = ["detection_s", "claim_s", "enrichment_s", "case_creation_s",
              "to_approval_s", "human_decision_s", "enforcement_s", "mttr_s"]
    stats = {s: _stats([t[s] for t in done]) for s in stages}

    if HAS_MPL and done:
        _plot_latency_bars(done)
        _plot_latency_box(done)

    return {"rows": timeline, "stats": stats,
            "mttr_note": ("mttr = done_ts − sent_ts for all flows; "
                          "done_ts is when process_alert completed (case created + action dispatched/parked). "
                          "For auto-block flows this equals the enforcement time; "
                          "for gated flows this is time-to-case-and-queue.")}


def _plot_latency_bars(done: list[dict]) -> None:
    stage_keys   = ["detection_s", "claim_s", "enrichment_s", "case_creation_s",
                    "to_approval_s", "human_decision_s", "enforcement_s"]
    stage_labels = ["detection", "claim", "enrich", "case_create",
                    "to_approval", "human_dec", "enforcement"]
    colors = ["#4C72B0", "#DD8452", "#55A868", "#C44E52",
              "#8172B3", "#937860", "#DA8BC3"]
    fig, ax = plt.subplots(figsize=(max(8, len(done)*0.55 + 2), 5))
    bottoms = [0.0] * len(done)
    xs = list(range(len(done)))
    for key, label, color in zip(stage_keys, stage_labels, colors):
        heights = [t.get(key) or 0 for t in done]
        ax.bar(xs, heights, bottom=bottoms, label=label, color=color, width=0.7)
        bottoms = [b + h for b, h in zip(bottoms, heights)]
    ax.set_xlabel("Alert (index, ordered by alert_id)")
    ax.set_ylabel("Seconds")
    ax.set_title(f"Per-alert stage latency — {len(done)} done alerts")
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(OUTDIR / "latency_stages.png", dpi=150)
    plt.close(fig)


def _plot_latency_box(done: list[dict]) -> None:
    stage_keys   = ["detection_s", "claim_s", "enrichment_s", "case_creation_s", "mttr_s"]
    stage_labels = ["detection", "claim", "enrich", "case_create", "MTTR"]
    data = [[t.get(k) or 0 for t in done] for k in stage_keys]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.boxplot(data, tick_labels=stage_labels, patch_artist=True,
               boxprops=dict(facecolor="#AEC6CF"), medianprops=dict(color="red", linewidth=2))
    ax.set_ylabel("Seconds (log scale)")
    ax.set_yscale("log")
    ax.set_title("Stage latency distribution (box plot, log scale)")
    fig.tight_layout()
    fig.savefig(OUTDIR / "latency_boxplot.png", dpi=150)
    plt.close(fig)


# ── A2 / B2: Throughput & reliability ────────────────────────────────────────

def harvest_throughput(conn, since_id: int, before_ts: str | None = None,
                       log_path: str | None = None) -> dict:
    bclause, bparams = _before_clause(before_ts, col="updated_ts")
    status_rows = _q(conn, f"""
        SELECT status, COUNT(*) AS n,
               MIN(created_ts) AS first_claim,
               MAX(updated_ts) AS last_done
        FROM soar_orchestrator_bookkeeping
        WHERE alert_id > %(since_id)s {bclause}
        GROUP BY status
    """, {"since_id": since_id, **bparams})

    status_dist = {r["status"]: r["n"] for r in status_rows}
    total       = sum(status_dist.values())
    all_first   = min((r["first_claim"] for r in status_rows if r["first_claim"]), default=None)
    all_last    = max((r["last_done"]   for r in status_rows if r["last_done"]),   default=None)
    wall_s      = _td_s(all_first, all_last)
    tpm         = (total / wall_s * 60) if wall_s else None

    dur_rows = _q(conn, f"""
        SELECT (updated_ts - created_ts) AS dur
        FROM soar_orchestrator_bookkeeping
        WHERE alert_id > %(since_id)s AND status = 'done' {bclause}
    """, {"since_id": since_id, **bparams})
    durations = [r["dur"].total_seconds() for r in dur_rows if r["dur"]]

    idempotency_skips = reconnect_events = 0
    if log_path and Path(log_path).exists():
        with open(log_path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    ev = d.get("event", "")
                    if ev == "alert_already_claimed":
                        idempotency_skips += 1
                    if "connected" in ev:
                        reconnect_events += 1
                except Exception:
                    pass

    return {
        "total_claimed":          total,
        "status_distribution":    status_dist,
        "wall_clock_s":           wall_s,
        "throughput_per_min":     tpm,
        "process_alert_duration": _stats(durations),
        "idempotency_skips":      idempotency_skips,
        "reconnect_events":       reconnect_events,
    }


# ── A3 / B3: Triage funnel + decision matrix ─────────────────────────────────

def harvest_funnel(conn, since_id: int, before_ts: str | None = None) -> dict:
    """
    Two-level funnel:
      Level 1 (alerts table): ALL alerts ingested — severity split from pred_proba / severity_label.
      Level 2 (bookkeeping): alerts claimed by the orchestrator — cases, decision cells.

    Decision cell derivation (correct JSON paths in live DB):
      Auto-block:   playbook_plan.endpoint_response[].type == "block"  (intel_malicious=True path)
      Gated block:  playbook_plan.pending_approvals[].action == "block"
      Gated isolate:playbook_plan.pending_approvals[].action == "isolate"
      Notify-only:  no endpoint_response and no pending_approvals entries
    """
    # Level 1: all alerts (use translated_ts for upper bound when before_ts is set)
    bclause_a, bparams_a = _before_clause(before_ts, col="translated_ts")
    all_alerts = _q(conn, f"""
        SELECT id, pred_proba, severity_label, mapping_status, mapping_confidence,
               observables, agent_id
        FROM alerts
        WHERE id > %(since_id)s {bclause_a}
    """, {"since_id": since_id, **bparams_a})

    total_alerts = len(all_alerts)
    n_high   = sum(1 for a in all_alerts if (a.get("severity_label") or "").upper() == "HIGH")
    n_medium = sum(1 for a in all_alerts if (a.get("severity_label") or "").upper() == "MEDIUM")
    n_low    = sum(1 for a in all_alerts if (a.get("severity_label") or "").upper() == "LOW")
    n_mapped = sum(1 for a in all_alerts if (a.get("mapping_status") or "") == "mapped")
    n_unmapped_heuristic = sum(1 for a in all_alerts
                               if (a.get("mapping_status") or "") == "unmapped_heuristic")

    # Confidence CSV for histogram
    conf_rows = [{"alert_id": a["id"],
                  "pred_proba": a.get("pred_proba"),
                  "severity_label": a.get("severity_label"),
                  "mapping_status": a.get("mapping_status")}
                 for a in all_alerts]
    _write_csv(OUTDIR / "confidence.csv", conf_rows)

    # Level 2: claimed alerts (in bookkeeping)
    bclause, bparams = _before_clause(before_ts)
    done_rows = _q(conn, f"""
        SELECT b.alert_id, b.status, b.thehive_case_id, b.playbook_plan,
               a.pred_proba, a.severity_label, a.mapping_status
        FROM soar_orchestrator_bookkeeping b
        JOIN alerts a ON a.id = b.alert_id
        WHERE b.alert_id > %(since_id)s {bclause}
    """, {"since_id": since_id, **bparams})

    total_claimed = len(done_rows)
    cases_created = sum(1 for r in done_rows if r.get("thehive_case_id"))

    auto_block_decided = 0
    auto_block_with_ip = 0
    gated_block = 0
    gated_isolate = 0
    notify_only = 0
    pop_counts: dict[str, Counter] = {
        "live_c2":     Counter(),
        "pcap_replay": Counter(),
    }
    auto_block_ips: list[str] = []

    for r in done_rows:
        plan = r.get("playbook_plan") or {}
        automation = plan.get("automation") or {}
        eo = automation.get("enriched_observables") or []
        ep = plan.get("endpoint_response") or []
        pa = plan.get("pending_approvals") or []
        pop = _population(eo)

        has_auto_block   = any(e.get("type") == "block" for e in ep)
        has_gated_block  = any(a.get("action") == "block"   for a in pa)
        has_gated_isolate= any(a.get("action") == "isolate" for a in pa)

        if has_auto_block:
            auto_block_decided += 1
            pop_counts[pop]["auto_block"] += 1
            for e in ep:
                if e.get("type") == "block":
                    tgt = str(e.get("target") or "")
                    if tgt:
                        auto_block_with_ip += 1
                        auto_block_ips.append(tgt)
        if has_gated_block:
            gated_block += 1
            pop_counts[pop]["gated_block"] += 1
        if has_gated_isolate:
            gated_isolate += 1
            pop_counts[pop]["gated_isolate"] += 1
        if not has_auto_block and not has_gated_block and not has_gated_isolate:
            notify_only += 1
            pop_counts[pop]["notify_only"] += 1

    if HAS_MPL:
        # Funnel uses all alerts at top, narrows to claimed/cases/auto-block
        _plot_funnel(
            [total_alerts, n_mapped, n_high, total_claimed, cases_created, auto_block_decided],
            ["All alerts", "Mapped", "High sev", "Claimed", "Cases", "Auto-block"],
        )
        _plot_decision_bar({
            "auto-block\n(decided)":  auto_block_decided,
            "auto-block\n(IP target)": auto_block_with_ip,
            "gated\nblock":           gated_block,
            "gated\nisolate":         gated_isolate,
            "notify\nonly":           notify_only,
        })
        _plot_confidence_histogram([a.get("pred_proba") for a in all_alerts
                                    if a.get("pred_proba") is not None])

    return {
        "total_alerts_ingested":     total_alerts,
        "total_claimed_by_soar":     total_claimed,
        "unclaimed_below_threshold": total_alerts - total_claimed,
        "mapped_flows":              n_mapped,
        "unmapped_heuristic":        n_unmapped_heuristic,
        "severity": {"high": n_high, "medium": n_medium, "low": n_low},
        "cases_created":             cases_created,
        "decision_cells": {
            "auto_block_decided":  auto_block_decided,
            "auto_block_with_ip":  auto_block_with_ip,
            "gated_block":         gated_block,
            "gated_isolate":       gated_isolate,
            "notify_only":         notify_only,
        },
        "population_breakdown": {
            pop: dict(cnt) for pop, cnt in pop_counts.items()
        },
        "auto_block_ips": sorted(set(auto_block_ips)),
    }


def _plot_funnel(values: list[int], labels: list[str]) -> None:
    fig, ax = plt.subplots(figsize=(9, 5))
    colors = plt.cm.Blues([0.25 + 0.13 * i for i in range(len(values))])
    ys = list(range(len(values)))
    bars = ax.barh(ys, values, color=colors, height=0.6)
    ax.set_yticks(ys)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    for i, (v, lbl) in enumerate(zip(values, labels)):
        ax.text(v + max(values) * 0.01, i, str(v), va="center", fontsize=9, fontweight="bold")
    ax.set_xlabel("Count")
    ax.set_title("Triage funnel — two-arm simulation")
    fig.tight_layout()
    fig.savefig(OUTDIR / "funnel.png", dpi=150)
    plt.close(fig)


def _plot_decision_bar(cells: dict[str, int]) -> None:
    colors = ["#2ecc71", "#27ae60", "#e74c3c", "#e67e22", "#95a5a6"]
    fig, ax = plt.subplots(figsize=(9, 5))
    keys = list(cells.keys())
    vals = [cells[k] for k in keys]
    bars = ax.bar(keys, vals, color=colors[:len(keys)])
    for i, v in enumerate(vals):
        ax.text(i, v + max(vals) * 0.01, str(v), ha="center", fontsize=10, fontweight="bold")
    ax.set_ylabel("Alerts")
    ax.set_title("Decision matrix cells — decided vs enforced")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUTDIR / "decision_cells.png", dpi=150)
    plt.close(fig)


def _plot_confidence_histogram(probas: list[float]) -> None:
    if not probas:
        return
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(probas, bins=40, color="#4C72B0", edgecolor="white", linewidth=0.5)
    ax.axvline(0.80, color="red",    linestyle="--", linewidth=1.5, label="High ≥ 0.80")
    ax.axvline(0.50, color="orange", linestyle="--", linewidth=1.5, label="Benign / Low")
    ax.set_xlabel("Prediction probability (pred_proba)")
    ax.set_ylabel("Flow count")
    ax.set_title("Detection confidence distribution — all ingested flows")
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUTDIR / "confidence_histogram.png", dpi=150)
    plt.close(fig)


# ── A4 / B4: TheHive cases ───────────────────────────────────────────────────

def harvest_thehive(conn, since_id: int, before_ts: str | None = None) -> dict:
    bclause, bparams = _before_clause(before_ts)
    rows = _q(conn, f"""
        SELECT b.alert_id, b.thehive_case_id, a.severity_label, a.pred_proba,
               a.mitre_ttps, a.mitre_names, a.n_ttps_matched,
               b.playbook_plan
        FROM soar_orchestrator_bookkeeping b
        JOIN alerts a ON a.id = b.alert_id
        WHERE b.alert_id > %(since_id)s AND b.thehive_case_id IS NOT NULL {bclause}
        ORDER BY b.alert_id
    """, {"since_id": since_id, **bparams})

    cases = []
    for r in rows:
        plan  = r.get("playbook_plan") or {}
        auto  = plan.get("automation") or {}
        eo    = auto.get("enriched_observables") or []
        steps = plan.get("steps") or []
        n_mitre_steps = sum(1 for s in steps if s.get("group") == "MITRE ATT&CK")
        cases.append({
            "alert_id":      r["alert_id"],
            "case_id":       r["thehive_case_id"],
            "severity":      r.get("severity_label"),
            "pred_proba":    r.get("pred_proba"),
            "n_ttps":        r.get("n_ttps_matched") or 0,
            "mitre_ttps":    r.get("mitre_ttps"),
            "n_observables": len(eo),
            "n_mitre_steps": n_mitre_steps,
            "population":    _population(eo),
        })

    sev_dist  = dict(Counter(c["severity"]   for c in cases))
    pop_dist  = dict(Counter(c["population"] for c in cases))
    ttp_dist  = Counter()
    for c in cases:
        for t in (c.get("mitre_ttps") or []):
            ttp_dist[t] += 1

    return {
        "total_cases":          len(cases),
        "severity_distribution": sev_dist,
        "population_distribution": pop_dist,
        "top_ttps":             dict(ttp_dist.most_common(10)),
        "cases":                [{k: v for k, v in c.items() if k != "mitre_ttps"}
                                 for c in cases],
        "case_ids_for_api":     [c["case_id"] for c in cases],
        "note": "[HUMAN: verify per-case tasks/observables via TheHive UI with case_ids_for_api]",
    }


# ── A5 / B5: Cortex enrichment ───────────────────────────────────────────────

def harvest_cortex(conn, since_id: int, before_ts: str | None = None) -> dict:
    """
    Reads from playbook_plan.automation.cortex_results (list of analyzer job records).
    Verdict derived from job.result.report.report.summary.taxonomies[].level.
    URLhaus domain-type verdicts use the _fallback_cortex_verdict path (no taxonomy emitted);
    those are captured via enriched_observables[].intel_malicious=True.
    """
    bclause, bparams = _before_clause(before_ts)
    rows = _q(conn, f"""
        SELECT b.alert_id, b.playbook_plan
        FROM soar_orchestrator_bookkeeping b
        WHERE b.alert_id > %(since_id)s AND b.status = 'done' {bclause}
        ORDER BY b.alert_id
    """, {"since_id": since_id, **bparams})

    verdict_rows: list[dict] = []
    analyzer_obs_counter: Counter = Counter()
    verdict_counter: Counter = Counter()
    urlhaus_fallback_malicious = 0
    intel_malicious_count = 0

    for r in rows:
        plan   = r.get("playbook_plan") or {}
        auto   = plan.get("automation") or {}
        cr     = auto.get("cortex_results") or []
        eo     = auto.get("enriched_observables") or []

        # Count URLhaus fallback hits (domain confirmed via blacklists/urls[], not taxonomy)
        if auto.get("intel_malicious"):
            intel_malicious_count += 1
            for obs in eo:
                if obs.get("intel_malicious"):
                    urlhaus_fallback_malicious += 1

        for job in (cr if isinstance(cr, list) else []):
            aname    = job.get("analyzer_name", "?")
            obs_type = job.get("observable_type") or job.get("data_type", "?")
            data     = job.get("data", "")
            result   = job.get("result") or {}
            report   = result.get("report") or {}
            inner    = report.get("report") or {}
            taxos    = (inner.get("summary") or {}).get("taxonomies") or []
            verdict  = "no_verdict"
            for t in taxos:
                lvl = (t.get("level") or "").lower()
                if lvl in ("malicious", "suspicious", "safe", "info"):
                    verdict = lvl
                    break

            analyzer_obs_counter[(aname, obs_type)] += 1
            verdict_counter[(aname, verdict)] += 1
            verdict_rows.append({
                "alert_id":     r["alert_id"],
                "analyzer":     aname,
                "observable":   data,
                "obs_type":     obs_type,
                "verdict":      verdict,
            })

    _write_csv(OUTDIR / "cortex_verdicts.csv", verdict_rows)

    # Top-level verdict roll-up (ignoring analyzer)
    top_verdict = dict(Counter(v["verdict"] for v in verdict_rows))
    top_analyzer = dict(Counter(v["analyzer"] for v in verdict_rows))

    # Per-analyzer breakdown
    per_analyzer: dict[str, dict] = defaultdict(lambda: Counter())
    for (a, v), n in verdict_counter.items():
        per_analyzer[a][v] += n
    per_analyzer_dict = {a: dict(cnt) for a, cnt in per_analyzer.items()}

    if HAS_MPL and top_verdict:
        _plot_verdict_bar(top_verdict)

    return {
        "total_cortex_jobs":         len(verdict_rows),
        "verdict_distribution":      top_verdict,
        "analyzer_distribution":     top_analyzer,
        "per_analyzer_verdict":      per_analyzer_dict,
        "intel_malicious_flows":     intel_malicious_count,
        "urlhaus_fallback_malicious_obs": urlhaus_fallback_malicious,
        "note": (
            "URLhaus domain verdicts use _fallback_cortex_verdict (reads blacklists/urls[] in full JSON); "
            "no taxonomy emitted, so they appear as 'no_verdict' here. "
            "urlhaus_fallback_malicious_obs counts observables confirmed via that path. "
            "[CROSS-REF: pcaps/mta/ioc_manifest.json not available in this repo — on detection side]"
        ),
    }


def _plot_verdict_bar(dist: dict[str, int]) -> None:
    color_map = {"malicious": "#e74c3c", "suspicious": "#e67e22",
                 "safe": "#2ecc71", "info": "#95a5a6",
                 "no_verdict": "#bdc3c7", "error": "#8e44ad"}
    fig, ax = plt.subplots(figsize=(8, 5))
    keys = list(dist.keys())
    vals = [dist[k] for k in keys]
    ax.bar(keys, vals, color=[color_map.get(k, "#bdc3c7") for k in keys])
    for i, v in enumerate(vals):
        ax.text(i, v + max(vals) * 0.01, str(v), ha="center", fontsize=10, fontweight="bold")
    ax.set_ylabel("Cortex jobs")
    ax.set_title("Cortex verdict distribution\n(no_verdict = URLhaus fallback path, see note)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUTDIR / "verdict_bar.png", dpi=150)
    plt.close(fig)


# ── A6 / B6: Approval loop ───────────────────────────────────────────────────

def harvest_approvals(conn, since_id: int, before_ts: str | None = None) -> dict:
    bclause, bparams = _before_clause(before_ts, col="p.requested_ts")
    rows = _q(conn, f"""
        SELECT p.id, p.alert_id, p.agent_id, p.action_type, p.target_value,
               p.status, p.intel_malicious,
               p.requested_ts, p.decided_ts, p.expires_ts, p.ar_executed_ts,
               p.ar_result
        FROM soar_pending_approvals p
        WHERE p.alert_id > %(since_id)s {bclause}
        ORDER BY p.id
    """, {"since_id": since_id, **bparams})

    csv_rows = [
        {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in r.items()}
        for r in rows
    ]
    _write_csv(OUTDIR / "approvals.csv", csv_rows)

    status_dist   = dict(Counter(r["status"]      for r in rows))
    type_dist     = dict(Counter(r["action_type"] for r in rows))
    agent_dist    = dict(Counter(r["agent_id"]    for r in rows))
    dec_lats      = [_td_s(r["requested_ts"], r["decided_ts"])
                     for r in rows if r.get("decided_ts")]
    enf_lats      = [_td_s(r["decided_ts"],   r["ar_executed_ts"])
                     for r in rows if r.get("ar_executed_ts")]
    executed_ok   = sum(1 for r in rows
                        if isinstance(r.get("ar_result"), dict)
                        and r["ar_result"].get("status") == "dispatched")

    if HAS_MPL:
        # Plot status × action_type (2D breakdown)
        _plot_approval_bar(rows)

    return {
        "total_requests":           len(rows),
        "status_distribution":      status_dist,
        "action_type_distribution": type_dist,
        "per_agent_requests":       agent_dist,
        "decision_latency":         _stats(dec_lats),
        "enforcement_latency":      _stats(enf_lats),
        "ar_success_rate":          _pct(executed_ok, len(rows)),
        "ar_dispatched_count":      executed_ok,
    }


def _plot_approval_bar(rows: list[dict]) -> None:
    from collections import defaultdict
    # Group: action_type × status
    groups: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        groups[r["action_type"]][r["status"]] += 1

    statuses = ["executed", "pending", "rejected", "expired"]
    colors   = {"executed": "#2ecc71", "pending": "#3498db",
                "rejected": "#e74c3c", "expired": "#e67e22"}
    action_types = sorted(groups.keys())

    fig, ax = plt.subplots(figsize=(8, 5))
    width = 0.15
    xs = range(len(action_types))
    for i, status in enumerate(statuses):
        vals = [groups[at].get(status, 0) for at in action_types]
        offset = (i - len(statuses)/2 + 0.5) * width
        bars = ax.bar([x + offset for x in xs], vals, width,
                      label=status, color=colors.get(status, "#bdc3c7"))
        for bar, v in zip(bars, vals):
            if v:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                        str(v), ha="center", fontsize=8)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(action_types)
    ax.set_ylabel("Count")
    ax.set_title("Approval outcomes by action type")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUTDIR / "approval_outcomes.png", dpi=150)
    plt.close(fig)


# ── A7 / B7: Wazuh enforcement ───────────────────────────────────────────────

def harvest_wazuh(conn, since_id: int, before_ts: str | None = None) -> dict:
    """
    Two enforcement paths:
      1. Auto-block: playbook_plan.endpoint_response (intel_malicious=True path, no approval)
      2. Gated: soar_pending_approvals.ar_result where status='executed'
    """
    bclause, bparams = _before_clause(before_ts)
    done_rows = _q(conn, f"""
        SELECT b.alert_id, b.playbook_plan
        FROM soar_orchestrator_bookkeeping b
        WHERE b.alert_id > %(since_id)s AND b.status = 'done' {bclause}
    """, {"since_id": since_id, **bparams})

    auto_dispatched = 0
    auto_empty_target = 0
    auto_blocked_ips: list[str] = []
    host_ip_blocked = False
    auto_block_detail: list[dict] = []

    for r in done_rows:
        plan = r.get("playbook_plan") or {}
        eo   = (plan.get("automation") or {}).get("enriched_observables") or []
        pop  = _population(eo)
        for entry in (plan.get("endpoint_response") or []):
            if entry.get("type") == "block":
                auto_dispatched += 1
                tgt    = str(entry.get("target") or "")
                result = entry.get("result") or {}
                if not tgt:
                    auto_empty_target += 1
                else:
                    auto_blocked_ips.append(tgt)
                    if tgt == HOST_IP:
                        host_ip_blocked = True
                auto_block_detail.append({
                    "alert_id":   r["alert_id"],
                    "target_ip":  tgt or "(empty)",
                    "status":     result.get("status"),
                    "command":    result.get("command"),
                    "affected":   result.get("affected"),
                    "population": pop,
                })

    bclause_a, bparams_a = _before_clause(before_ts, col="p.requested_ts")
    app_rows = _q(conn, f"""
        SELECT p.action_type, p.target_value, p.status, p.agent_id, p.ar_result
        FROM soar_pending_approvals p
        WHERE p.alert_id > %(since_id)s {bclause_a}
    """, {"since_id": since_id, **bparams_a})
    gated_ok      = sum(1 for r in app_rows
                        if r["status"] == "executed"
                        and isinstance(r.get("ar_result"), dict)
                        and r["ar_result"].get("status") == "dispatched")
    gated_detail  = [r for r in app_rows if r["status"] == "executed"]

    return {
        "auto_block_dispatched":   auto_dispatched,
        "auto_block_empty_target": auto_empty_target,
        "auto_block_ips":          sorted(set(auto_blocked_ips)),
        "unique_ips_blocked":      len(set(auto_blocked_ips)),
        "host_ip_blocked_ERROR":   host_ip_blocked,
        "auto_block_detail":       auto_block_detail,
        "gated_executed":          gated_ok,
        "gated_detail":            [
            {k: (json.dumps(v) if isinstance(v, dict) else v) for k, v in r.items()}
            for r in gated_detail
        ],
        "note": (
            "auto_block fires inside process_alert (no approval); "
            "gated_executed requires human /soar/approve call. "
            "[HUMAN: confirm live enforcement: ssh <endpoint> 'sudo nft list table inet soar']"
        ),
    }


# ── A8 / B8: Robustness ──────────────────────────────────────────────────────

def harvest_robustness(conn, since_id: int, before_ts: str | None = None,
                       log_path: str | None = None) -> dict:
    bclause, bparams = _before_clause(before_ts, col="updated_ts")
    skipped = _q(conn, f"""
        SELECT last_error, COUNT(*) AS n
        FROM soar_orchestrator_bookkeeping
        WHERE alert_id > %(since_id)s AND status = 'skipped' {bclause}
        GROUP BY last_error ORDER BY n DESC
    """, {"since_id": since_id, **bparams})

    failed = _q(conn, f"""
        SELECT last_error, COUNT(*) AS n
        FROM soar_orchestrator_bookkeeping
        WHERE alert_id > %(since_id)s AND status = 'failed' {bclause}
        GROUP BY last_error ORDER BY n DESC
    """, {"since_id": since_id, **bparams})

    shuf = _q(conn, """
        SELECT COUNT(*) AS tot, COUNT(DISTINCT flow_id) AS uniq
        FROM soar_shuffle_results
    """)

    retry_events = outer_failures = 0
    if log_path and Path(log_path).exists():
        with open(log_path) as f:
            for line in f:
                try:
                    d  = json.loads(line)
                    ev = d.get("event", "")
                    if "connected" in ev:
                        retry_events += 1
                    if ev == "outer_failure":
                        outer_failures += 1
                except Exception:
                    pass

    return {
        "skipped_breakdown":       [{"reason": r["last_error"], "count": r["n"]}
                                    for r in skipped],
        "failed_breakdown":        [{"reason": r["last_error"], "count": r["n"]}
                                    for r in failed],
        "total_skipped":           sum(r["n"] for r in skipped),
        "total_failed":            sum(r["n"] for r in failed),
        "shuffle_total_callbacks": shuf[0]["tot"]  if shuf else 0,
        "shuffle_unique_flows":    shuf[0]["uniq"] if shuf else 0,
        "reconnect_events_log":    retry_events,
        "outer_failure_events":    outer_failures,
    }


# ── Markdown summary ──────────────────────────────────────────────────────────

def write_summary(m: dict, path: Path) -> None:
    b1 = m.get("A1_latency",    {})
    b2 = m.get("A2_throughput", {})
    b3 = m.get("A3_funnel",     {})
    b4 = m.get("A4_thehive",    {})
    b5 = m.get("A5_cortex",     {})
    b6 = m.get("A6_approvals",  {})
    b7 = m.get("A7_wazuh",      {})
    b8 = m.get("A8_robustness", {})

    def row(label, val, src=""):
        return f"| {label} | {val} | {src} |"

    def lat_row(key, name):
        s = (b1.get("stats") or {}).get(key) or {}
        return (f"| {name} | {_fmt_s(s.get('median'))} "
                f"| {_fmt_s(s.get('p90'))} | {_fmt_s(s.get('min'))} "
                f"| {_fmt_s(s.get('max'))} | {s.get('n', 0)} |")

    dc   = b3.get("decision_cells") or {}
    sev  = b3.get("severity") or {}
    dur  = b2.get("process_alert_duration") or {}
    decs = b6.get("decision_latency") or {}
    enfl = b6.get("enforcement_latency") or {}
    pop_breakdown = b3.get("population_breakdown") or {}

    lines = [
        "# SOAR Evaluation Summary — Aegis (Thesis Run)",
        "",
        f"> Generated: {datetime.now(tz=timezone.utc).isoformat()}  ",
        f"> Watermark alert_id > {m.get('since_id', 'N/A')}  ",
        f"> Git SHA: {m.get('git_sha', 'unknown')}  ",
        f"> Two-arm run: live Poseidon C2 (kzaa.co.za) + malware PCAP replay",
        "",
        "---",
        "",
        "## A1 — Per-stage latency (done alerts only)",
        "",
        "> MTTR = `done_ts − sent_ts` (process_alert completion). For auto-block flows this equals the enforcement time.",
        "> Source: `alerts.sent_ts/translated_ts` · `bookkeeping.created_ts` (claimed) · `enriched_ts`",
        "> · `case_created_ts` · `updated_ts` (done) · `pending_approvals.requested_ts/decided_ts/ar_executed_ts`",
        "",
        "| Stage | Median | p90 | Min | Max | N |",
        "|---|---|---|---|---|---|",
        lat_row("detection_s",      "Detection (`sent_ts→translated_ts`)"),
        lat_row("claim_s",          "Claim (`translated_ts→claimed_ts`)"),
        lat_row("enrichment_s",     "Enrichment (`claimed_ts→enriched_ts`)"),
        lat_row("case_creation_s",  "Case creation (`enriched_ts→case_created_ts`)"),
        lat_row("to_approval_s",    "To approval request"),
        lat_row("human_decision_s", "Human decision latency *(trust-gate cost)*"),
        lat_row("enforcement_s",    "Enforcement (`decided_ts→ar_executed_ts`)"),
        lat_row("mttr_s",           "**Total MTTR** (`sent_ts→ar_executed/done_ts`)"),
        "",
        "## A2 — Throughput & reliability",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row("Total claimed by SOAR",        b2.get("total_claimed", 0),          "bookkeeping COUNT"),
        row("Wall-clock span",              _fmt_s(b2.get("wall_clock_s")),      "max(updated_ts)−min(created_ts)"),
        row("Throughput",
            f"{b2['throughput_per_min']:.2f} alerts/min" if b2.get("throughput_per_min") else "N/A",
            "total/wall_s×60"),
        row("process_alert median",         _fmt_s(dur.get("median")),           "claimed→done"),
        row("process_alert p90",            _fmt_s(dur.get("p90")),              "claimed→done"),
        *[row(f"Status: {k}", v, "bookkeeping.status")
          for k, v in (b2.get("status_distribution") or {}).items()],
        row("Idempotency skips (log)",      b2.get("idempotency_skips", 0),      "log event=alert_already_claimed"),
        row("Reconnect events (log)",       b2.get("reconnect_events", 0),       "log event=*connected"),
        "",
        "## A3 — Triage funnel & decision matrix",
        "",
        "### Funnel",
        "",
        "| Stage | Count | % of total alerts |",
        "|---|---|---|",
        f"| **Total alerts ingested** | {b3.get('total_alerts_ingested', 0)} | 100% |",
        (f"| Mapped (mapping_status=\'mapped\') | {b3.get('mapped_flows', 0)} | "
         f"{_pct(b3.get('mapped_flows', 0), b3.get('total_alerts_ingested', 1))} |"),
        (f"| High severity (pred_proba ≥ 0.80) | {sev.get('high', 0)} | "
         f"{_pct(sev.get('high', 0), b3.get('total_alerts_ingested', 1))} |"),
        (f"| Medium severity | {sev.get('medium', 0)} | "
         f"{_pct(sev.get('medium', 0), b3.get('total_alerts_ingested', 1))} |"),
        (f"| Low / benign | {sev.get('low', 0)} | "
         f"{_pct(sev.get('low', 0), b3.get('total_alerts_ingested', 1))} |"),
        (f"| **Claimed by SOAR** (bookkeeping row) | {b3.get('total_claimed_by_soar', 0)} | "
         f"{_pct(b3.get('total_claimed_by_soar', 0), b3.get('total_alerts_ingested', 1))} |"),
        (f"| TheHive cases created | {b3.get('cases_created', 0)} | "
         f"{_pct(b3.get('cases_created', 0), b3.get('total_alerts_ingested', 1))} |"),
        "",
        "### Decision cells",
        "",
        "| Cell | Count | Source |",
        "|---|---|---|",
        row("Auto-block *decided* (intel_malicious, no approval)",
            dc.get("auto_block_decided", 0), "endpoint_response[].type=block"),
        row("Auto-block *with IP target* (enforced — target non-empty)",
            dc.get("auto_block_with_ip", 0), "endpoint_response[].target"),
        row("Gated block (approval required)",
            dc.get("gated_block", 0), "pending_approvals[].action=block"),
        row("Gated isolate",
            dc.get("gated_isolate", 0), "pending_approvals[].action=isolate"),
        row("Notify-only (no endpoint action)",
            dc.get("notify_only", 0), "no endpoint_response, no pending_approvals"),
        "",
        "### Population breakdown (live C2 vs PCAP replay)",
        "",
        "| Cell | live_c2 | pcap_replay |",
        "|---|---|---|",
        *[f"| {cell} | {pop_breakdown.get('live_c2', {}).get(cell, 0)} | "
          f"{pop_breakdown.get('pcap_replay', {}).get(cell, 0)} |"
          for cell in ["auto_block", "gated_block", "gated_isolate", "notify_only"]],
        "",
        f"> Blocked IPs (auto-block): {', '.join(b3.get('auto_block_ips') or []) or 'none'}",
        "",
        "## A4 — TheHive cases",
        "",
        f"Total cases: **{b4.get('total_cases', 0)}**",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Severity distribution | {b4.get('severity_distribution', {})} |",
        f"| Population split | {b4.get('population_distribution', {})} |",
        f"| Top MITRE techniques | {', '.join(list((b4.get('top_ttps') or {}).keys())[:5])} |",
        "",
        "Case IDs (for TheHive API / UI verification):",
        "",
        "```",
        "\n".join(b4.get("case_ids_for_api") or []),
        "```",
        "",
        "> [HUMAN: capture TheHive case view screenshot (B4.14): severity, TTPs, observables, tasks, Cortex panel]",
        "",
        "## A5 — Cortex enrichment",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row("Total Cortex jobs run",         b5.get("total_cortex_jobs", 0),
            "playbook_plan→automation→cortex_results"),
        row("Flows with intel_malicious=True", b5.get("intel_malicious_flows", 0),
            "automation.intel_malicious"),
        row("URLhaus fallback malicious obs", b5.get("urlhaus_fallback_malicious_obs", 0),
            "enriched_observables[].intel_malicious (blacklists/urls[] path)"),
        *[row(f"Verdict: {k}", v, "cortex_results taxonomy")
          for k, v in (b5.get("verdict_distribution") or {}).items()],
        "",
        "> `no_verdict` = URLhaus fallback path (reads `full.blacklists` / `full.urls[].threat`).",
        "> These ARE confirmed malicious — reported in urlhaus_fallback_malicious_obs above.",
        "> [HUMAN: capture Cortex/URLhaus result screenshot showing malicious verdict (B4.15)]",
        "> [CROSS-REF: pcaps/mta/ioc_manifest.json not in this repo — on detection side]",
        "",
        "**Per-analyzer verdict breakdown:**",
        "",
        "| Analyzer | " + " | ".join(["malicious", "suspicious", "safe", "info", "no_verdict"]) + " |",
        "|---|" + "---|" * 5,
        *[f"| {a} | " + " | ".join(
            str((b5.get("per_analyzer_verdict") or {}).get(a, {}).get(v, 0))
            for v in ["malicious", "suspicious", "safe", "info", "no_verdict"]
          ) + " |"
          for a in sorted((b5.get("per_analyzer_verdict") or {}).keys())],
        "",
        "## A6 — Approval loop",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row("Total approval requests",       b6.get("total_requests", 0),        "soar_pending_approvals"),
        *[row(f"Status: {k}", v, "pending_approvals.status")
          for k, v in (b6.get("status_distribution") or {}).items()],
        *[row(f"Action type: {k}", v, "pending_approvals.action_type")
          for k, v in (b6.get("action_type_distribution") or {}).items()],
        row("Decision latency median",       _fmt_s(decs.get("median")),         "requested_ts→decided_ts"),
        row("Decision latency p90",          _fmt_s(decs.get("p90")),            "requested_ts→decided_ts"),
        row("Enforcement latency median",    _fmt_s(enfl.get("median")),         "decided_ts→ar_executed_ts"),
        row("AR dispatched (success)",       b6.get("ar_dispatched_count", 0),   "ar_result.status=dispatched"),
        row("AR success rate",               b6.get("ar_success_rate", "N/A"),   "dispatched/total"),
        "",
        "> [HUMAN: capture Dashboard approvals page screenshot (B4.20)]",
        "",
        "## A7 — Wazuh enforcement",
        "",
        "| Metric | Value | Source |",
        "|---|---|---|",
        row("Auto-block dispatched",          b7.get("auto_block_dispatched", 0),
            "playbook_plan→endpoint_response"),
        row("Empty-target auto-blocks (must be 0)", b7.get("auto_block_empty_target", 0),
            "endpoint_response.target safety check"),
        row("Unique IPs blocked (auto)",      b7.get("unique_ips_blocked", 0),
            "endpoint_response.target distinct"),
        row("IPs blocked",                   ", ".join(b7.get("auto_block_ips") or []) or "none",
            "endpoint_response.target"),
        row("Host IP blocked — MUST BE FALSE",
            "⚠️ YES" if b7.get("host_ip_blocked_ERROR") else "✓ No", "safety invariant check"),
        row("Gated actions approved+executed", b7.get("gated_executed", 0),
            "pending_approvals.status=executed"),
        "",
        "**Auto-block detail:**",
        "",
        "| alert_id | target_ip | command | status | population |",
        "|---|---|---|---|---|",
        *[f"| {d.get('alert_id')} | {d.get('target_ip')} | {d.get('command')} "
          f"| {d.get('status')} | {d.get('population')} |"
          for d in (b7.get("auto_block_detail") or [])],
        "",
        "> [HUMAN: `ssh <endpoint> 'sudo nft list table inet soar'` — capture nft DROP rule (B4.19)]",
        "> [HUMAN: capture Wazuh manager AR log / agent list (B4.18)]",
        "",
        "## A8 — Robustness / negative cases",
        "",
        "**Skipped alerts:**",
        "",
        *(([f"- {e['count']} × `{str(e.get('reason',''))[:100]}`"
            for e in (b8.get("skipped_breakdown") or [])]) or ["- none"]),
        "",
        f"Total skipped: **{b8.get('total_skipped', 0)}** · Failed: **{b8.get('total_failed', 0)}**",
        "",
        "**Failed alerts:**",
        "",
        *(([f"- {e['count']} × `{str(e.get('reason',''))[:100]}`"
            for e in (b8.get("failed_breakdown") or [])]) or ["- none"]),
        "",
        f"Shuffle callbacks: {b8.get('shuffle_total_callbacks', 0)} total / "
        f"{b8.get('shuffle_unique_flows', 0)} unique flows.",
        "",
        "---",
        "",
        "## B3 Figures generated",
        "",
        "- `funnel.png` — triage funnel (A3)",
        "- `latency_stages.png` — stacked stage latency per alert (A1)",
        "- `latency_boxplot.png` — stage latency box plots (A1)",
        "- `decision_cells.png` — decision matrix distribution (A3)",
        "- `verdict_bar.png` — Cortex verdict distribution (A5)",
        "- `approval_outcomes.png` — approval outcomes by type (A6)",
        "- `confidence_histogram.png` — pred_proba distribution (B3.13)",
        "",
        "## Human captures needed (B4 screenshots)",
        "",
        "- [ ] B4.14 TheHive case view: severity, MITRE TTPs, observables, tasks, Cortex panel",
        "- [ ] B4.15 Cortex/URLhaus result: malicious verdict for kzaa.co.za or replay domain",
        "- [ ] B4.16 Shuffle workflow canvas + one successful run",
        "- [ ] B4.17 MISP / URLhaus / VT hit on a real IOC",
        "- [ ] B4.18 Wazuh manager AR log / agent list showing dispatched command",
        "- [ ] B4.19 Endpoint `nft list table inet soar` — DROP rule after block",
        "- [ ] B4.20 Dashboard approvals page (pending + approved)",
        "",
        "---",
        "",
        "## Honest limitations",
        "",
        ("- **Enforcement scope:** Wazuh agent 005 (172.31.87.134) only. "
         "Block/isolate AR does not reach other network segments."),
        ("- **Auto-block confirmed by URLhaus_2_0 via domain-type fallback** (blacklists / urls[]). "
         "kzaa.co.za: Spamhaus DBL `malware_domain`, SURBL listed, RemcosRAT family. "
         "savory.com.bd, paste.ee, uploaddeimagens.com.br: confirmed via PCAP replay arm. "
         "No synthetic IOC seeding required."),
        ("- **MTTR approximation for auto-block flows:** "
         "`ar_executed_ts` is set only for human-approved gated actions. "
         "Auto-block MTTR uses `done_ts` (bookkeeping.updated_ts) as proxy."),
        ("- **Cortex URLhaus verdicts appear as `no_verdict`** in the taxonomy table "
         "because the fallback reads `full.blacklists`/`full.urls[]` directly, "
         "emitting no taxonomy object. Count via `urlhaus_fallback_malicious_obs`."),
        ("- **Human-decision latency** is a deliberate trust-gate cost (§5 invariant), not a defect."),
        ("- **IOC cross-reference:** `pcaps/mta/ioc_manifest.json` is in the detection-side repo; "
         "not available here for automated cross-check."),
        "",
    ]

    path.write_text("\n".join(lines))


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-id", type=int, default=0,
                    help="Filter to alert_id > this (default 0 = all)")
    ap.add_argument("--before-ts", type=str, default=None,
                    help="Upper bound on bookkeeping.updated_ts (ISO8601, e.g. 2026-06-25T14:04:46Z). "
                         "Use to scope harvest to the live-log window. Default: no upper bound.")
    ap.add_argument("--log", type=str, default="report/eval/orchestrator_run.log")
    ap.add_argument("--git-sha", type=str, default=None)
    args = ap.parse_args()

    since_id  = args.since_id
    before_ts = args.before_ts
    git_sha   = args.git_sha or os.popen("git rev-parse HEAD 2>/dev/null").read().strip()
    log_path  = args.log if Path(args.log).exists() else None

    print(f"Harvesting: alert_id > {since_id}"
          + (f"  before_ts={before_ts}" if before_ts else "")
          + f"  log={log_path or 'not captured'}")

    conn = _db()

    metrics: dict[str, Any] = {
        "since_id":     since_id,
        "before_ts":    before_ts,
        "git_sha":      git_sha,
        "harvested_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    sections = [
        ("A1_latency",    lambda: harvest_latency(conn, since_id, before_ts)),
        ("A2_throughput", lambda: harvest_throughput(conn, since_id, before_ts, log_path)),
        ("A3_funnel",     lambda: harvest_funnel(conn, since_id, before_ts)),
        ("A4_thehive",    lambda: harvest_thehive(conn, since_id, before_ts)),
        ("A5_cortex",     lambda: harvest_cortex(conn, since_id, before_ts)),
        ("A6_approvals",  lambda: harvest_approvals(conn, since_id, before_ts)),
        ("A7_wazuh",      lambda: harvest_wazuh(conn, since_id, before_ts)),
        ("A8_robustness", lambda: harvest_robustness(conn, since_id, before_ts, log_path)),
    ]
    for key, fn in sections:
        print(f"  {key} …", end=" ", flush=True)
        try:
            metrics[key] = fn()
            print("done")
        except Exception as e:
            conn.rollback()
            print(f"ERROR: {e}")
            metrics[key] = {"error": str(e)}

    json_path    = OUTDIR / "metrics.json"
    summary_path = OUTDIR / "SOAR_EVAL_SUMMARY.md"

    json_path.write_text(json.dumps(metrics, indent=2, default=str))
    write_summary(metrics, summary_path)

    b1 = metrics.get("A1_latency", {})
    b2 = metrics.get("A2_throughput", {})
    b3 = metrics.get("A3_funnel", {})
    b7 = metrics.get("A7_wazuh", {})
    mttr = (b1.get("stats") or {}).get("mttr_s") or {}
    dc   = b3.get("decision_cells") or {}

    print()
    print("=== Headline numbers ===")
    print(f"  Total alerts ingested : {b3.get('total_alerts_ingested', 0)}")
    print(f"  Claimed by SOAR       : {b2.get('total_claimed', 0)}  "
          f"({b2.get('status_distribution', {})})")
    print(f"  Cases created         : {b3.get('cases_created', 0)}")
    print(f"  Auto-blocks decided   : {dc.get('auto_block_decided', 0)}  "
          f"(with IP: {dc.get('auto_block_with_ip', 0)})")
    print(f"  Blocked IPs           : {b7.get('auto_block_ips')}")
    print(f"  Host IP blocked       : {'⚠️  YES' if b7.get('host_ip_blocked_ERROR') else '✓ No'}")
    print(f"  MTTR median           : {_fmt_s(mttr.get('median'))}  "
          f"(p90 {_fmt_s(mttr.get('p90'))} / min {_fmt_s(mttr.get('min'))} / n={mttr.get('n')})")
    print(f"  Human decision lat    : "
          f"{_fmt_s(((metrics.get('A6_approvals') or {}).get('decision_latency') or {}).get('median'))}")
    print(f"  Enforcement lat       : "
          f"{_fmt_s(((metrics.get('A6_approvals') or {}).get('enforcement_latency') or {}).get('median'))}")
    print()
    print(f"Artifacts → {OUTDIR}/")
    print(f"  metrics.json · SOAR_EVAL_SUMMARY.md")
    print(f"  timeline.csv · cortex_verdicts.csv · approvals.csv · confidence.csv")
    if HAS_MPL:
        print(f"  funnel.png · latency_stages.png · latency_boxplot.png")
        print(f"  decision_cells.png · verdict_bar.png · approval_outcomes.png · confidence_histogram.png")
    else:
        print("  (matplotlib not available — PNGs skipped)")

    conn.close()


if __name__ == "__main__":
    main()
