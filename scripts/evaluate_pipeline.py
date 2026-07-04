"""Thesis evaluation harness for the XAI -> Translator -> SOAR pipeline.

Produces the *quantitative* artefacts a thesis defence usually asks for:

1. Per-stage latency percentiles (producer -> inference -> translator -> case
   created in TheHive) at p50 / p90 / p95 / p99.
2. Verdict mix from Cortex analyzer runs (safe / suspicious / malicious /
   error / unknown), grouped by analyzer.
3. MITRE ATT&CK technique distribution across created cases.
4. Pipeline outcome breakdown (done / skipped / failed / deferred_thehive)
   from the orchestrator's bookkeeping table.

All numeric outputs are written as JSON to ``--out-dir`` so they can be embedded
in the thesis. If ``matplotlib`` is available, four PNG charts are also emitted.

Examples::

    # Default: query localhost postgres, write to ./reports/<timestamp>/
    python scripts/evaluate_pipeline.py

    # Limit to the last 1000 alerts and skip plots
    python scripts/evaluate_pipeline.py --limit 1000 --no-plots

    # Use a custom DB URL
    python scripts/evaluate_pipeline.py --db-url postgresql://u:p@host:5432/soar

Design note: the script never mutates state. Run it as many times as you like.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import psycopg2
    import psycopg2.extras
except ImportError:                              # pragma: no cover
    print("ERROR: psycopg2 is required. `pip install psycopg2-binary`.", file=sys.stderr)
    sys.exit(2)


# ---- helpers --------------------------------------------------------------

def _percentile(sorted_values: List[float], q: float) -> Optional[float]:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    k = (len(sorted_values) - 1) * q
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return float(sorted_values[f])
    return float(sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f))


def _latency_summary(values_ms: Iterable[float]) -> Dict[str, Any]:
    arr = sorted(float(v) for v in values_ms if v is not None and v >= 0)
    if not arr:
        return {"n": 0}
    return {
        "n": len(arr),
        "min_ms": round(arr[0], 1),
        "p50_ms": round(_percentile(arr, 0.50) or 0, 1),
        "p90_ms": round(_percentile(arr, 0.90) or 0, 1),
        "p95_ms": round(_percentile(arr, 0.95) or 0, 1),
        "p99_ms": round(_percentile(arr, 0.99) or 0, 1),
        "max_ms": round(arr[-1], 1),
        "mean_ms": round(sum(arr) / len(arr), 1),
        "median_ms": round(median(arr), 1),
    }


# ---- collectors -----------------------------------------------------------

def collect_alert_latencies(conn, limit: int) -> Dict[str, Dict[str, Any]]:
    """End-to-end latency per stage based on the `alerts` table timestamps."""
    sql = """
        SELECT id, sent_ts, inferred_ts, translated_ts, pred_label, model
        FROM alerts
        ORDER BY id DESC
        LIMIT %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (limit,))
        rows = list(cur.fetchall())

    ingest_to_inference: List[float] = []
    inference_to_translate: List[float] = []
    ingest_to_translate: List[float] = []
    malicious_only_e2e: List[float] = []

    for row in rows:
        sent, inf, tr = row.get("sent_ts"), row.get("inferred_ts"), row.get("translated_ts")
        if sent and inf:
            ingest_to_inference.append((inf - sent).total_seconds() * 1000)
        if inf and tr:
            inference_to_translate.append((tr - inf).total_seconds() * 1000)
        if sent and tr:
            ms = (tr - sent).total_seconds() * 1000
            ingest_to_translate.append(ms)
            if row.get("pred_label") == 1:
                malicious_only_e2e.append(ms)
    return {
        "ingest_to_inference_ms": _latency_summary(ingest_to_inference),
        "inference_to_translate_ms": _latency_summary(inference_to_translate),
        "ingest_to_translate_ms": _latency_summary(ingest_to_translate),
        "ingest_to_translate_malicious_only_ms": _latency_summary(malicious_only_e2e),
    }


def collect_case_latencies(conn) -> Dict[str, Any]:
    """How long after translation until the orchestrator wrote a 'done' row."""
    sql = """
        SELECT
            a.translated_ts,
            b.updated_ts,
            b.status
        FROM soar_orchestrator_bookkeeping b
        JOIN alerts a ON a.id = b.alert_id
        WHERE b.status = 'done' AND a.translated_ts IS NOT NULL
        ORDER BY b.updated_ts DESC
        LIMIT 5000
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = list(cur.fetchall())
    diffs = [(r["updated_ts"] - r["translated_ts"]).total_seconds() * 1000
             for r in rows if r["updated_ts"] and r["translated_ts"]]
    return {"translate_to_case_done_ms": _latency_summary(diffs)}


def collect_orchestrator_outcomes(conn) -> Dict[str, Any]:
    """status histogram + per-model breakdown from bookkeeping table."""
    with conn.cursor() as cur:
        cur.execute("SELECT status, COUNT(*) AS n FROM soar_orchestrator_bookkeeping GROUP BY status")
        statuses = {r["status"]: int(r["n"]) for r in cur.fetchall()}
        cur.execute("SELECT model, status, COUNT(*) AS n FROM soar_orchestrator_bookkeeping GROUP BY model, status")
        per_model: Dict[str, Dict[str, int]] = defaultdict(dict)
        for r in cur.fetchall():
            per_model[r["model"]][r["status"]] = int(r["n"])
    return {"status_counts": statuses, "per_model": dict(per_model)}


def collect_mitre_distribution(conn) -> Dict[str, Any]:
    """Top MITRE techniques across alerts that reached a TheHive case."""
    sql = """
        SELECT a.mitre_ttps, a.mitre_names
        FROM soar_orchestrator_bookkeeping b
        JOIN alerts a ON a.id = b.alert_id
        WHERE b.status = 'done'
    """
    counter: Counter = Counter()
    id_to_name: Dict[str, str] = {}
    with conn.cursor() as cur:
        cur.execute(sql)
        for r in cur.fetchall():
            ttps = r.get("mitre_ttps") or []
            names = r.get("mitre_names") or []
            if isinstance(ttps, str):
                try:
                    ttps = json.loads(ttps)
                except Exception:
                    ttps = []
            if isinstance(names, str):
                try:
                    names = json.loads(names)
                except Exception:
                    names = []
            for i, tid in enumerate(ttps):
                if not tid:
                    continue
                counter[tid] += 1
                if i < len(names) and names[i]:
                    id_to_name.setdefault(tid, names[i])
    top = counter.most_common(20)
    return {
        "total_cases_with_mitre": sum(counter.values()),
        "unique_techniques": len(counter),
        "top": [
            {"id": tid, "name": id_to_name.get(tid, ""), "count": n}
            for tid, n in top
        ],
    }


def collect_cortex_verdicts(conn) -> Dict[str, Any]:
    """Pulls Cortex job summaries stashed by case_automation.py into playbook_plan.automation.cortex_results."""
    sql = """
        SELECT playbook_plan
        FROM soar_orchestrator_bookkeeping
        WHERE status = 'done' AND playbook_plan IS NOT NULL
    """
    per_analyzer_levels: Dict[str, Counter] = defaultdict(Counter)
    total_jobs = 0
    with conn.cursor() as cur:
        cur.execute(sql)
        for r in cur.fetchall():
            plan = r["playbook_plan"] or {}
            results = (((plan or {}).get("automation") or {}).get("cortex_results")) or []
            for job in results:
                if not isinstance(job, dict):
                    continue
                analyzer = job.get("analyzer_name") or job.get("analyzer_id") or "unknown"
                level: Optional[str] = None
                summary = job.get("report") or job.get("summary") or {}
                if isinstance(summary, dict):
                    tax = summary.get("taxonomies") or []
                    if tax and isinstance(tax, list):
                        level = (tax[0] or {}).get("level")
                if not level:
                    level = "error" if job.get("error") else "unknown"
                per_analyzer_levels[analyzer][str(level)] += 1
                total_jobs += 1
    return {
        "total_cortex_jobs": total_jobs,
        "per_analyzer": {a: dict(c) for a, c in per_analyzer_levels.items()},
    }


# ---- plotting (optional) --------------------------------------------------

def _plot_all(report: Dict[str, Any], out_dir: Path) -> List[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:
        print(f"[evaluate] matplotlib unavailable, skipping plots: {exc}")
        return []

    files: List[str] = []

    # 1. Latency bar chart (per stage, p95)
    lat = report.get("latency", {})
    stages, p95s = [], []
    for name, s in lat.items():
        if isinstance(s, dict) and s.get("p95_ms") is not None:
            stages.append(name.replace("_ms", ""))
            p95s.append(s["p95_ms"])
    if stages:
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.barh(stages, p95s, color="steelblue")
        ax.set_xlabel("p95 latency (ms)")
        ax.set_title("Pipeline stage latency (p95)")
        fig.tight_layout()
        path = out_dir / "latency_p95.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        files.append(str(path))

    # 2. Orchestrator outcomes (pie)
    outcomes = report.get("orchestrator_outcomes", {}).get("status_counts") or {}
    if outcomes:
        fig, ax = plt.subplots(figsize=(6, 6))
        ax.pie(list(outcomes.values()), labels=list(outcomes.keys()), autopct="%1.1f%%")
        ax.set_title("SOAR orchestrator outcomes")
        fig.tight_layout()
        path = out_dir / "orchestrator_outcomes.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        files.append(str(path))

    # 3. MITRE top techniques (horizontal bar)
    top = (report.get("mitre_distribution") or {}).get("top") or []
    if top:
        labels = [f"{t['id']} {t['name'][:30]}" for t in top]
        counts = [t["count"] for t in top]
        fig, ax = plt.subplots(figsize=(10, max(4, 0.35 * len(top))))
        ax.barh(labels[::-1], counts[::-1], color="darkorange")
        ax.set_xlabel("Cases")
        ax.set_title("MITRE ATT&CK techniques across created cases (top 20)")
        fig.tight_layout()
        path = out_dir / "mitre_distribution.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        files.append(str(path))

    # 4. Cortex verdicts (stacked bar per analyzer)
    cortex = (report.get("cortex_verdicts") or {}).get("per_analyzer") or {}
    if cortex:
        analyzers = list(cortex.keys())
        levels = sorted({lvl for v in cortex.values() for lvl in v.keys()})
        bottoms = [0] * len(analyzers)
        colour_map = {
            "safe": "seagreen", "info": "lightgreen", "suspicious": "orange",
            "malicious": "crimson", "error": "dimgray", "unknown": "lightgray",
        }
        fig, ax = plt.subplots(figsize=(max(6, len(analyzers) * 0.7), 5))
        for lvl in levels:
            vals = [cortex[a].get(lvl, 0) for a in analyzers]
            ax.bar(analyzers, vals, bottom=bottoms, label=lvl,
                   color=colour_map.get(lvl, None))
            bottoms = [b + v for b, v in zip(bottoms, vals)]
        ax.set_ylabel("Jobs")
        ax.set_title("Cortex verdicts per analyzer")
        ax.legend()
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
        fig.tight_layout()
        path = out_dir / "cortex_verdicts.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        files.append(str(path))

    return files


# ---- main -----------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db-url",
                   default=os.getenv("DEMO_DATABASE_URL",
                                     "postgresql://user:pass@127.0.0.1:5432/soar"))
    p.add_argument("--limit", type=int, default=10000,
                   help="Max alerts to sample for latency (default 10000).")
    p.add_argument("--out-dir", default=None,
                   help="Where to write report.json (default ./reports/<timestamp>/).")
    p.add_argument("--no-plots", action="store_true",
                   help="Skip matplotlib PNGs (text/JSON only).")
    args = p.parse_args()

    out_dir = Path(args.out_dir or f"reports/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    out_dir.mkdir(parents=True, exist_ok=True)

    with psycopg2.connect(args.db_url, cursor_factory=psycopg2.extras.RealDictCursor) as conn:
        report: Dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "db_url": args.db_url.split("@")[-1],
            "alert_sample_limit": args.limit,
            "latency": collect_alert_latencies(conn, args.limit),
            "case_latency": collect_case_latencies(conn),
            "orchestrator_outcomes": collect_orchestrator_outcomes(conn),
            "mitre_distribution": collect_mitre_distribution(conn),
            "cortex_verdicts": collect_cortex_verdicts(conn),
        }
        conn.commit()

    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    plots: List[str] = []
    if not args.no_plots:
        plots = _plot_all(report, out_dir)

    print(f"\nReport written to: {json_path}")
    for f in plots:
        print(f"  plot: {f}")

    print("\n--- summary ---")
    oc = report["orchestrator_outcomes"]["status_counts"]
    print(f"  outcomes: {oc}")
    e2e = report["latency"].get("ingest_to_translate_ms") or {}
    print(f"  ingest->translate p95: {e2e.get('p95_ms')} ms (n={e2e.get('n')})")
    ctd = report["case_latency"].get("translate_to_case_done_ms") or {}
    print(f"  translate->case_done p95: {ctd.get('p95_ms')} ms (n={ctd.get('n')})")
    md = report["mitre_distribution"]
    print(f"  unique MITRE techniques in cases: {md.get('unique_techniques')}")
    cv = report["cortex_verdicts"]
    print(f"  total cortex jobs analysed: {cv.get('total_cortex_jobs')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
