"""
sim_harvest.py — detection-side simulation metric capture (non-destructive).
────────────────────────────────────────────────────────────────────────────────
Companion to the SOAR-side harvest. Captures the DETECTION half's numbers for a
replay/simulation straight from the live `alerts` table — operational confidence,
severity funnel, mapping quality, the intra-detection pipeline latencies
(`sent_ts→inferred_ts→translated_ts`, `explain_time_ms`) and endpoint identity.

Three subcommands, deliberately split by dependency so each runs in an image we
already have (no image has BOTH psycopg2 and matplotlib):

  begin    record a pre-run watermark + run metadata        (psycopg2 + stdlib)
  end      query the run window, write JSON/MD/CSV artifacts (psycopg2 + stdlib)
  render   draw PNG figures from the CSVs                    (pandas + matplotlib)

Workflow (compose network = dev_net; DB = soar):
  # before the replay
  docker run --rm -i --network dev_net -e DATABASE_URL=postgresql://user:pass@postgres:5432/soar \
      -v /home/ubuntu/dev:/work -w /work dev-dashboard:latest python utils/sim_harvest.py begin
  # ... run the simulation ...
  docker run --rm -i --network dev_net -e DATABASE_URL=postgresql://user:pass@postgres:5432/soar \
      -v /home/ubuntu/dev:/work -w /work dev-dashboard:latest python utils/sim_harvest.py end
  # figures (different image)
  docker run --rm -i -v /home/ubuntu/dev:/work -w /work dev-inference:latest \
      python utils/sim_harvest.py render

`begin` is non-destructive by default (records max(id) as a watermark so `end`
filters to this run only). Pass --reset to TRUNCATE alerts for a clean slate.
"""
import os, sys, json, csv, argparse, subprocess, statistics
from datetime import datetime, timezone

OUT = "thesis/eval"
META = os.path.join(OUT, "sim_run_meta.json")
DB = os.getenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/soar")


def connect():
    import psycopg2
    return psycopg2.connect(DB)


def q(cur, sql, args=None):
    cur.execute(sql, args or ())
    return cur.fetchall()


def git_sha():
    try:
        return subprocess.check_output(["git", "-C", "/work", "rev-parse", "--short", "HEAD"],
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        pass
    # no git binary (e.g. dashboard image): resolve .git/HEAD manually, following a symref
    try:
        head = open("/work/.git/HEAD").read().strip()
        if head.startswith("ref:"):
            ref = head.split(" ", 1)[1].strip()
            return open(f"/work/.git/{ref}").read().strip()[:12]
        return head[:12]
    except Exception:
        return "unknown"


def severity_env():
    """Best-effort: read the live severity band from the repo .env (translator owns it)."""
    out = {}
    for path in (".env", "/work/.env"):
        if os.path.exists(path):
            for line in open(path):
                line = line.strip()
                if line.startswith(("SEVERITY_HIGH_MIN", "SEVERITY_MED_MIN")) and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    return out or {"SEVERITY_HIGH_MIN": "0.80 (default)", "SEVERITY_MED_MIN": "0.70 (default)"}


# ── begin ────────────────────────────────────────────────────────────────────
def cmd_begin(args):
    os.makedirs(OUT, exist_ok=True)
    conn = connect(); cur = conn.cursor()
    counts = dict(q(cur, "SELECT 'alerts', count(*) FROM alerts "
                        "UNION ALL SELECT 'analyst_decisions', count(*) FROM analyst_decisions"))
    wm = q(cur, "SELECT coalesce(max(id),0) FROM alerts")[0][0]
    if args.reset:
        cur.execute("TRUNCATE alerts RESTART IDENTITY CASCADE")
        conn.commit()
        wm = 0
        print("RESET: alerts truncated (clean slate).")
    meta = {
        "started_ts": datetime.now(timezone.utc).isoformat(),
        "watermark_alert_id": int(wm),
        "git_sha": git_sha(),
        "severity_env": severity_env(),
        "table_counts_before": counts,
        "dataset": args.dataset, "expected_flows": args.flows,
        "note": "fill dataset/flows if not passed; end filters id > watermark_alert_id",
    }
    json.dump(meta, open(META, "w"), indent=2)
    conn.close()
    print(f"WROTE {META}\n  watermark alert id = {wm}  | counts_before={counts}")


# ── end ──────────────────────────────────────────────────────────────────────
def pctl(cur, expr, where):
    r = q(cur, f"""SELECT count(*), avg({expr}),
                   percentile_cont(0.5) WITHIN GROUP (ORDER BY {expr}),
                   percentile_cont(0.9) WITHIN GROUP (ORDER BY {expr}),
                   min({expr}), max({expr}) FROM alerts WHERE {where}""")[0]
    keys = ["n", "mean", "median", "p90", "min", "max"]
    return {k: (float(v) if v is not None else None) for k, v in zip(keys, r)}


def cmd_end(args):
    os.makedirs(OUT, exist_ok=True)
    meta = json.load(open(META)) if os.path.exists(META) else {"watermark_alert_id": 0}
    wm = meta.get("watermark_alert_id", 0)
    W = f"id > {int(wm)}"
    conn = connect(); cur = conn.cursor()

    total = q(cur, f"SELECT count(*) FROM alerts WHERE {W}")[0][0]
    if not total:
        print(f"No alerts with id > {wm}. Did the simulation run? Aborting.")
        sys.exit(1)

    by_label = dict(q(cur, f"SELECT pred_label, count(*) FROM alerts WHERE {W} GROUP BY 1"))
    by_sev = dict(q(cur, f"SELECT coalesce(severity_label,'(null)'), count(*) FROM alerts WHERE {W} GROUP BY 1"))
    by_mapstatus = dict(q(cur, f"SELECT coalesce(mapping_status,'(null)'), count(*) FROM alerts WHERE {W} GROUP BY 1"))

    # operational confidence
    flagged = pctl(cur, "pred_proba", f"{W} AND pred_label=1")
    thr = q(cur, f"""SELECT sum((pred_proba>=0.90)::int), sum((pred_proba>=0.80)::int),
                     sum((pred_proba>=0.70)::int), count(*) FROM alerts WHERE {W}""")[0]
    hist = q(cur, f"SELECT (width_bucket(pred_proba,0,1,10)-1)*0.1, count(*) "
                  f"FROM alerts WHERE {W} GROUP BY 1 ORDER BY 1")

    # mapping confidence (mapped flows only)
    mapconf = pctl(cur, "mapping_confidence",
                   f"{W} AND mapping_confidence IS NOT NULL")

    # detection-stage latency (ms) — guard against NULL timestamps
    def lat(expr, extra=""):
        return pctl(cur, f"extract(epoch from ({expr}))*1000",
                    f"{W} AND {expr.split(' - ')[0]} IS NOT NULL AND {expr.split(' - ')[1]} IS NOT NULL {extra}")
    lat_si = lat("inferred_ts - sent_ts")
    lat_it = lat("translated_ts - inferred_ts")
    lat_st = lat("translated_ts - sent_ts")
    explain = pctl(cur, "explain_time_ms", f"{W} AND explain_time_ms IS NOT NULL")

    # endpoint identity
    endpoints = q(cur, f"""SELECT coalesce(agent_id,'(none)'), coalesce(host_ip,'(none)'), count(*)
                           FROM alerts WHERE {W} GROUP BY 1,2 ORDER BY 3 DESC LIMIT 20""")
    n_agents = q(cur, f"SELECT count(DISTINCT agent_id) FROM alerts WHERE {W} AND agent_id IS NOT NULL")[0][0]

    # ── CSVs (feed render) ────────────────────────────────────────────────
    with open(os.path.join(OUT, "sim_proba.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["id", "pred_label", "pred_proba", "severity_label"])
        for row in q(cur, f"SELECT id, pred_label, pred_proba, severity_label FROM alerts WHERE {W} ORDER BY id"):
            w.writerow(row)
    with open(os.path.join(OUT, "sim_latency.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "sent_inferred_ms", "inferred_translated_ms", "sent_translated_ms", "explain_time_ms"])
        for row in q(cur, f"""SELECT id,
              extract(epoch from (inferred_ts - sent_ts))*1000,
              extract(epoch from (translated_ts - inferred_ts))*1000,
              extract(epoch from (translated_ts - sent_ts))*1000,
              explain_time_ms FROM alerts WHERE {W} ORDER BY id"""):
            w.writerow(row)

    metrics = {
        "run_meta": meta, "window": W, "n_total": int(total),
        "by_pred_label": {str(k): int(v) for k, v in by_label.items()},
        "by_severity_label": by_sev, "by_mapping_status": by_mapstatus,
        "operational_confidence_flagged": flagged,
        "threshold_counts": {"ge_0.90": int(thr[0] or 0), "ge_0.80": int(thr[1] or 0),
                             "ge_0.70": int(thr[2] or 0), "n": int(thr[3] or 0)},
        "confidence_histogram": [[float(b), int(c)] for b, c in hist],
        "mapping_confidence": mapconf,
        "latency_ms": {"sent_to_inferred": lat_si, "inferred_to_translated": lat_it,
                       "sent_to_translated": lat_st, "explain_time_ms": explain},
        "endpoints_top": [[a, h, int(c)] for a, h, c in endpoints],
        "distinct_agents": int(n_agents),
    }
    json.dump(metrics, open(os.path.join(OUT, "sim_detection_metrics.json"), "w"), indent=2)
    conn.close()

    # ── markdown ──────────────────────────────────────────────────────────
    def L(d): return (f"n={d['n']:.0f} median={d['median']:.1f} p90={d['p90']:.1f} "
                      f"max={d['max']:.1f}") if d and d['n'] else "no data"
    md = []
    md.append("# Detection-side simulation harvest (live `alerts`, this run)\n")
    md.append(f"- **Window:** `{W}` (watermark id={wm}) · **git** `{meta.get('git_sha','?')}` · "
              f"**severity** {meta.get('severity_env','?')}")
    md.append(f"- **Flows scored:** {total:,} · flagged (pred_label=1): {by_label.get(1,0):,} · "
              f"benign-pred: {by_label.get(0,0):,} · distinct endpoints: {n_agents}\n")
    md.append("## Severity funnel\n")
    md.append("| severity_label | flows |\n|---|---|")
    for k in ["HIGH", "MEDIUM", "LOW", "(null)"]:
        if k in by_sev: md.append(f"| {k} | {by_sev[k]} |")
    md.append("\n## Operational confidence (the severity-band evidence)\n")
    md.append(f"- Flagged-flow P(malicious): mean={flagged['mean']:.3f} median={flagged['median']:.3f} "
              f"max={flagged['max']:.3f} (n={flagged['n']:.0f})" if flagged['n'] else "- no flagged flows")
    md.append(f"- whole-run thresholds: ≥0.90 → **{metrics['threshold_counts']['ge_0.90']}**, "
              f"≥0.80 → **{metrics['threshold_counts']['ge_0.80']}**, "
              f"≥0.70 → **{metrics['threshold_counts']['ge_0.70']}**")
    md.append("\n> This is the OPERATIONAL distribution (live NFStream extraction). Contrast with the "
              "in-distribution held-out test in `EVAL_SUMMARY.md` (malicious median ≈1.0); do not "
              "conflate them. See `operational_confidence.md` for the standing write-up.\n")
    md.append("## Mapping quality\n")
    md.append(f"- mapping_status: {by_mapstatus}")
    md.append(f"- mapping_confidence (mapped flows): {L(mapconf)}\n")
    md.append("## Intra-detection latency (ms)\n")
    md.append("| stage | stats |\n|---|---|")
    md.append(f"| sent → inferred (inference) | {L(lat_si)} |")
    md.append(f"| inferred → translated (translate+map) | {L(lat_it)} |")
    md.append(f"| **sent → translated (detection total)** | {L(lat_st)} |")
    md.append(f"| explain_time_ms (XAI cost) | {L(explain)} |")
    md.append("\n> `translated_ts` is the hand-off to the SOAR chain; join the SOAR harvest on "
              "`alerts.id`/`flow_id` for end-to-end MTTR.\n")
    md.append("## Endpoints (top by alert volume)\n")
    md.append("| agent_id | host_ip | flows |\n|---|---|---|")
    for a, h, c in endpoints[:10]:
        md.append(f"| {a} | {h} | {c} |")
    md.append("\n## Figures (run `render` in the inference image)\n")
    md.append("- `sim_confidence_hist.png` · `sim_severity_bar.png` · `sim_latency_box.png`")
    open(os.path.join(OUT, "SIM_DETECTION_SUMMARY.md"), "w").write("\n".join(md) + "\n")

    print(f"WROTE {OUT}/SIM_DETECTION_SUMMARY.md + sim_detection_metrics.json + CSVs")
    print(json.dumps({"n_total": int(total), "flagged": by_label.get(1, 0),
                      "ge_0.80": metrics['threshold_counts']['ge_0.80'],
                      "detection_total_ms_median": lat_st.get("median")}, indent=2))


# ── render (inference image: pandas + matplotlib) ─────────────────────────────
def cmd_render(args):
    import pandas as pd, matplotlib
    matplotlib.use("Agg"); import matplotlib.pyplot as plt
    p = pd.read_csv(os.path.join(OUT, "sim_proba.csv"))
    lat = pd.read_csv(os.path.join(OUT, "sim_latency.csv"))

    # confidence histogram (log y, band lines)
    fig, ax = plt.subplots(figsize=(6.2, 3.8))
    bins = [i / 20 for i in range(21)]
    ax.hist(p[p.pred_label == 0].pred_proba, bins=bins, alpha=0.55, label="benign-pred", color="C0")
    ax.hist(p[p.pred_label == 1].pred_proba, bins=bins, alpha=0.7, label="flagged", color="C3")
    for t, c in [(0.80, "green"), (0.90, "purple")]:
        ax.axvline(t, ls="--", color=c, lw=1.3, label=f"band {t:.2f}")
    ax.set_yscale("log"); ax.set_xlabel("P(malicious) — operational"); ax.set_ylabel("flows (log)")
    ax.set_title("Operational confidence (simulation)"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "sim_confidence_hist.png"), dpi=160); plt.close(fig)

    # severity bar
    order = ["HIGH", "MEDIUM", "LOW"]
    counts = p.severity_label.value_counts().reindex(order).fillna(0)
    fig, ax = plt.subplots(figsize=(4.6, 3.6))
    ax.bar(order, counts.values, color=["C3", "C1", "C0"])
    for i, v in enumerate(counts.values): ax.text(i, v, f"{int(v)}", ha="center", va="bottom")
    ax.set_title("Severity distribution (simulation)"); ax.set_ylabel("flows")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "sim_severity_bar.png"), dpi=160); plt.close(fig)

    # latency box
    cols = ["sent_inferred_ms", "inferred_translated_ms", "sent_translated_ms", "explain_time_ms"]
    data = [lat[c].dropna().values for c in cols]
    fig, ax = plt.subplots(figsize=(6.6, 3.8))
    ax.boxplot(data, showfliers=False)  # mpl renamed labels->tick_labels; set ticks manually
    ax.set_xticks(range(1, len(cols) + 1))
    ax.set_xticklabels(["sent→inf", "inf→transl", "sent→transl", "explain"])
    ax.set_ylabel("ms"); ax.set_title("Intra-detection latency (simulation)")
    ax.tick_params(axis="x", labelsize=8); fig.tight_layout()
    fig.savefig(os.path.join(OUT, "sim_latency_box.png"), dpi=160); plt.close(fig)
    print(f"WROTE figures -> {OUT}/sim_confidence_hist.png, sim_severity_bar.png, sim_latency_box.png")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("begin"); b.add_argument("--reset", action="store_true")
    b.add_argument("--dataset", default=None); b.add_argument("--flows", type=int, default=None)
    sub.add_parser("end")
    sub.add_parser("render")
    args = ap.parse_args()
    {"begin": cmd_begin, "end": cmd_end, "render": cmd_render}[args.cmd](args)


if __name__ == "__main__":
    main()
