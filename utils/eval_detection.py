"""
eval_detection.py — honest held-out evaluation of the DEPLOYED detection models.
────────────────────────────────────────────────────────────────────────────────
Reproduces the canonical 80/20 stratified split (seed=42) from
`model_training/retrain_nfstream_model.ipynb`, reconstructs the *exact* training-time
scaling, then evaluates the **already-shipped** models in `models/mapper`
(`xgb_rt`, `xxgb` EBM, `rf_best`) on the held-out test set. It does NOT retrain or
overwrite the mapper — it only reads it.

Outputs (to --out, default thesis/eval/):
  metrics.json              all numbers, machine-readable
  EVAL_SUMMARY.md           Codex-ready human-readable summary
  classification_*.txt      per-model sklearn classification reports
  test_proba.csv            per-test-flow true label, attack_type, predicted proba
  threshold_sweep.csv       precision/recall/F1/#flagged at thresholds 0.50..0.95
  per_attack_type.csv       recall + mean proba per malicious subtype (c2 vs exfil)
  *.png                     confusion matrix, ROC+PR, confidence histogram, threshold sweep

Run inside the version-matched inference image:
  docker run --rm -i -v /home/ubuntu/dev:/work -w /work dev-inference:latest \
      python utils/eval_detection.py
"""
import os, json, argparse, warnings
warnings.simplefilter("ignore")
import numpy as np, pandas as pd, joblib
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, f1_score,
                             precision_recall_fscore_support, roc_auc_score,
                             average_precision_score, matthews_corrcoef,
                             classification_report, confusion_matrix,
                             roc_curve, precision_recall_curve)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ── exact replica of retrain notebook cell 4 + cell 6 ────────────────────────
META = ["true_label", "class", "attack_type", "source", "flow_id", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "bidirectional_packets", "requested_server_name"]
DEAD_TTL = ["mean_time_to_live", "std_time_to_live", "max_time_to_live", "min_time_to_live"]
SEED, TEST_SIZE = 42, 0.2


def load_split(data_path, mapper):
    df = pd.read_csv(data_path)
    feats = list(mapper["REALTIME_SAFE_FEATURES"])
    # sanity: the mapper's feature list must be derivable from the dataset
    derived = [c for c in df.columns if c not in META + DEAD_TTL]
    missing = [f for f in feats if f not in df.columns]
    assert not missing, f"mapper features absent from dataset: {missing}"

    X_raw = (df[feats].apply(pd.to_numeric, errors="coerce")
                      .replace([np.inf, -np.inf], np.nan))
    X_raw = X_raw.fillna(X_raw.median())
    # cell-6 training scaler: fit on the full median-imputed matrix, pre-split
    scaler = MinMaxScaler().fit(X_raw)
    X = pd.DataFrame(scaler.transform(X_raw), columns=feats, index=X_raw.index)
    y = df["true_label"].astype(int)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=SEED, stratify=y)
    # carry the fine-grained subtype label for the test rows
    attack_te = df.loc[X_te.index, "attack_type"].fillna("benign")
    return df, feats, X_te, y_te, attack_te, len(df), derived


def eval_model(name, model, X_te, y_te, feats_used=None):
    Xe = X_te[feats_used] if feats_used else X_te
    y_pred = model.predict(Xe)
    y_proba = model.predict_proba(Xe)[:, 1]
    p, r, f, _ = precision_recall_fscore_support(y_te, y_pred, average=None,
                                                 labels=[0, 1], zero_division=0)
    cm = confusion_matrix(y_te, y_pred, labels=[0, 1])
    out = {
        "accuracy": float(accuracy_score(y_te, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_te, y_pred)),
        "f1_macro": float(f1_score(y_te, y_pred, average="macro", zero_division=0)),
        "mcc": float(matthews_corrcoef(y_te, y_pred)),
        "roc_auc": float(roc_auc_score(y_te, y_proba)),
        "pr_auc": float(average_precision_score(y_te, y_proba)),
        "precision": {"benign": float(p[0]), "malicious": float(p[1])},
        "recall":    {"benign": float(r[0]), "malicious": float(r[1])},
        "f1":        {"benign": float(f[0]), "malicious": float(f[1])},
        "confusion_matrix": {"tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                             "fn": int(cm[1, 0]), "tp": int(cm[1, 1])},
        "n_test": int(len(y_te)),
    }
    report = classification_report(y_te, y_pred, target_names=["benign", "malicious"],
                                   zero_division=0, digits=4)
    return out, y_proba, report


def threshold_sweep(y_te, proba):
    rows = []
    for t in np.round(np.arange(0.50, 0.96, 0.05), 2):
        pred = (proba >= t).astype(int)
        p, r, f, _ = precision_recall_fscore_support(y_te, pred, average="binary",
                                                     pos_label=1, zero_division=0)
        rows.append({"threshold": float(t), "precision": float(p), "recall": float(r),
                     "f1": float(f), "flagged": int(pred.sum()),
                     "flagged_pct": float(pred.mean() * 100)})
    return pd.DataFrame(rows)


def confidence_story(y_te, proba):
    mal = proba[y_te.values == 1]
    return {
        "n_true_malicious": int(len(mal)),
        "proba_mean": float(mal.mean()), "proba_median": float(np.median(mal)),
        "proba_p10": float(np.percentile(mal, 10)), "proba_max": float(mal.max()),
        "frac_ge_0.90": float((mal >= 0.90).mean()),
        "frac_ge_0.80": float((mal >= 0.80).mean()),
        "frac_ge_0.70": float((mal >= 0.70).mean()),
    }


def per_attack_type(attack_te, y_te, proba):
    d = pd.DataFrame({"attack_type": attack_te.values, "y": y_te.values, "proba": proba})
    mal = d[d.y == 1]
    rows = []
    for at, g in mal.groupby("attack_type"):
        rows.append({"attack_type": at, "n": int(len(g)),
                     "recall_at_0.5": float((g.proba >= 0.5).mean()),
                     "recall_at_0.8": float((g.proba >= 0.8).mean()),
                     "mean_proba": float(g.proba.mean()),
                     "median_proba": float(g.proba.median())})
    return pd.DataFrame(rows)


# ── figures ──────────────────────────────────────────────────────────────────
def fig_confusion(cm, out):
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    M = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    ax.imshow(M, cmap="Blues")
    for (i, j), v in np.ndenumerate(M):
        ax.text(j, i, f"{v}", ha="center", va="center",
                color="white" if v > M.max() / 2 else "black", fontsize=13, fontweight="bold")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["benign", "malicious"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["benign", "malicious"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title("Confusion matrix — xgb_rt (held-out test)")
    fig.tight_layout(); fig.savefig(out, dpi=160); plt.close(fig)


def fig_roc_pr(y_te, proba, roc_auc, pr_auc, out):
    fpr, tpr, _ = roc_curve(y_te, proba)
    prec, rec, _ = precision_recall_curve(y_te, proba)
    fig, ax = plt.subplots(1, 2, figsize=(8.4, 3.8))
    ax[0].plot(fpr, tpr, lw=2); ax[0].plot([0, 1], [0, 1], "--", color="grey")
    ax[0].set_title(f"ROC (AUC={roc_auc:.3f})"); ax[0].set_xlabel("FPR"); ax[0].set_ylabel("TPR")
    ax[1].plot(rec, prec, lw=2, color="C1")
    ax[1].set_title(f"Precision–Recall (AP={pr_auc:.3f})")
    ax[1].set_xlabel("Recall"); ax[1].set_ylabel("Precision")
    fig.tight_layout(); fig.savefig(out, dpi=160); plt.close(fig)


def fig_conf_hist(y_te, proba, out):
    mal = proba[y_te.values == 1]; ben = proba[y_te.values == 0]
    fig, ax = plt.subplots(figsize=(6.2, 3.8))
    bins = np.linspace(0, 1, 41)
    ax.hist(ben, bins=bins, alpha=0.55, label="benign", color="C0")
    ax.hist(mal, bins=bins, alpha=0.7, label="malicious", color="C3")
    for t, c in [(0.80, "green"), (0.90, "purple")]:
        ax.axvline(t, ls="--", color=c, lw=1.4, label=f"threshold {t:.2f}")
    ax.set_yscale("log"); ax.set_xlabel("Predicted P(malicious) — xgb_rt")
    ax.set_ylabel("flows (log)"); ax.set_title("Confidence distribution on held-out test")
    ax.legend(fontsize=8); fig.tight_layout(); fig.savefig(out, dpi=160); plt.close(fig)


def fig_threshold(df_sweep, out):
    fig, ax = plt.subplots(figsize=(6.2, 3.8))
    ax.plot(df_sweep.threshold, df_sweep.precision, "-o", label="precision", ms=4)
    ax.plot(df_sweep.threshold, df_sweep.recall, "-o", label="recall", ms=4)
    ax.plot(df_sweep.threshold, df_sweep.f1, "-o", label="F1", ms=4)
    ax.axvline(0.80, ls="--", color="green", lw=1.2, label="High band (0.80)")
    ax.set_xlabel("decision threshold"); ax.set_ylabel("score")
    ax.set_title("Operating-point sweep — xgb_rt (malicious class)")
    ax.legend(fontsize=8); ax.grid(alpha=0.3); fig.tight_layout()
    fig.savefig(out, dpi=160); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/training_dataset.csv")
    ap.add_argument("--mapper", default="models/mapper")
    ap.add_argument("--out", default="thesis/eval")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    mapper = joblib.load(args.mapper)
    df, feats, X_te, y_te, attack_te, n_total, derived = load_split(args.data, mapper)

    models = {
        "xgb_rt": (mapper["xgb_rt"], None),          # deployed real-time model
        "xxgb_ebm": (mapper["xxgb"], None),          # glass-box EBM (Tier-1)
        "rf_best": (mapper["rf_best"], mapper["BEST_FEATURES"]),
    }
    metrics, reports, probas = {}, {}, {}
    for name, (mdl, fu) in models.items():
        m, proba, rep = eval_model(name, mdl, X_te, y_te, fu)
        metrics[name] = m; reports[name] = rep; probas[name] = proba
        with open(os.path.join(args.out, f"classification_{name}.txt"), "w") as fh:
            fh.write(rep)

    primary = probas["xgb_rt"]
    sweep = threshold_sweep(y_te, primary)
    conf = confidence_story(y_te, primary)
    pat = per_attack_type(attack_te, y_te, primary)

    sweep.to_csv(os.path.join(args.out, "threshold_sweep.csv"), index=False)
    pat.to_csv(os.path.join(args.out, "per_attack_type.csv"), index=False)
    pd.DataFrame({"attack_type": attack_te.values, "true_label": y_te.values,
                  "proba_xgb_rt": primary}).to_csv(
        os.path.join(args.out, "test_proba.csv"), index=False)

    summary = {
        "dataset": args.data, "n_total_flows": int(n_total),
        "n_features": len(feats), "n_test": int(len(y_te)),
        "split": {"test_size": TEST_SIZE, "seed": SEED, "stratified": True},
        "class_balance_total": df["true_label"].astype(int).value_counts().to_dict(),
        "models": metrics, "confidence_story_xgb_rt": conf,
        "threshold_sweep_xgb_rt": sweep.to_dict(orient="records"),
        "per_attack_type_xgb_rt": pat.to_dict(orient="records"),
    }
    with open(os.path.join(args.out, "metrics.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    # figures (xgb_rt = the deployed model)
    fig_confusion(metrics["xgb_rt"]["confusion_matrix"], os.path.join(args.out, "confusion_matrix_xgb_rt.png"))
    fig_roc_pr(y_te, primary, metrics["xgb_rt"]["roc_auc"], metrics["xgb_rt"]["pr_auc"],
               os.path.join(args.out, "roc_pr_xgb_rt.png"))
    fig_conf_hist(y_te, primary, os.path.join(args.out, "confidence_hist_xgb_rt.png"))
    fig_threshold(sweep, os.path.join(args.out, "threshold_sweep_xgb_rt.png"))

    # markdown summary
    md = []
    md.append("# Detection-side evaluation — deployed models on held-out test set\n")
    md.append(f"- **Dataset:** `{args.data}` — {n_total:,} flows, {len(feats)} real-time features.")
    md.append(f"- **Protocol:** stratified 80/20 split, seed={SEED}; **{len(y_te):,} held-out test flows** "
              "(reproduces `retrain_nfstream_model.ipynb`). Models are the *shipped* `models/mapper`, not retrained.")
    bal = df['true_label'].astype(int).value_counts().to_dict()
    md.append(f"- **Class balance (full set):** benign={bal.get(0,0):,}, malicious={bal.get(1,0):,}.\n")
    md.append("## Headline metrics (held-out test)\n")
    md.append("| Model | Acc | Bal-Acc | F1(macro) | ROC-AUC | PR-AUC | MCC | Recall(mal) | Precision(mal) |")
    md.append("|---|---|---|---|---|---|---|---|---|")
    for n, m in metrics.items():
        md.append(f"| `{n}` | {m['accuracy']:.4f} | {m['balanced_accuracy']:.4f} | {m['f1_macro']:.4f} | "
                  f"{m['roc_auc']:.4f} | {m['pr_auc']:.4f} | {m['mcc']:.4f} | "
                  f"{m['recall']['malicious']:.4f} | {m['precision']['malicious']:.4f} |")
    cmx = metrics["xgb_rt"]["confusion_matrix"]
    md.append(f"\n**xgb_rt confusion matrix:** TN={cmx['tn']}  FP={cmx['fp']}  FN={cmx['fn']}  TP={cmx['tp']}\n")
    md.append("## Confidence distribution — IN-DISTRIBUTION separation (xgb_rt, held-out test)\n")
    md.append(f"On the {conf['n_true_malicious']} true-malicious test flows: mean P={conf['proba_mean']:.3f}, "
              f"median={conf['proba_median']:.3f}, p10={conf['proba_p10']:.3f}, max={conf['proba_max']:.3f}.")
    md.append(f"- fraction scoring ≥0.90: **{conf['frac_ge_0.90']*100:.1f}%**")
    md.append(f"- fraction scoring ≥0.80: **{conf['frac_ge_0.80']*100:.1f}%**")
    md.append(f"- fraction scoring ≥0.70: **{conf['frac_ge_0.70']*100:.1f}%**")
    md.append("\n> **Read this correctly.** On clean, in-distribution test data the model is highly "
              "confident and strongly separated (median P≈1.0). This is a *model-quality* result; it does "
              "**NOT** by itself justify the operational severity band. The **High≥0.80** band is motivated "
              "by the **operational** distribution — live NFStream feature extraction compresses confidence "
              "markedly (see `operational_confidence.md`, generated from the live `alerts` table). Do not "
              "conflate the two distributions in the report.\n")
    md.append("## Operating-point sweep (xgb_rt, malicious class)\n")
    md.append("| thr | precision | recall | F1 | flagged% |")
    md.append("|---|---|---|---|---|")
    for _, r in sweep.iterrows():
        md.append(f"| {r.threshold:.2f} | {r.precision:.4f} | {r.recall:.4f} | {r.f1:.4f} | {r.flagged_pct:.1f}% |")
    md.append("\n## Per-attack-type detection (xgb_rt, true-malicious only)\n")
    md.append("| attack_type | n | recall@0.5 | recall@0.8 | mean P | median P |")
    md.append("|---|---|---|---|---|---|")
    for _, r in pat.iterrows():
        md.append(f"| {r.attack_type} | {int(r.n)} | {r['recall_at_0.5']:.3f} | {r['recall_at_0.8']:.3f} | "
                  f"{r.mean_proba:.3f} | {r.median_proba:.3f} |")
    md.append("\n## Figures\n")
    for f in ["confusion_matrix_xgb_rt.png", "roc_pr_xgb_rt.png",
              "confidence_hist_xgb_rt.png", "threshold_sweep_xgb_rt.png"]:
        md.append(f"- `{f}`")
    md.append("\n> Caveat: per-flow labels inherit the IOC-completeness limitation of the dataset build "
              "(benign flows in a malicious capture window may be unlabelled-malicious). Report as a "
              "construct-validity threat, not a measurement error.")
    with open(os.path.join(args.out, "EVAL_SUMMARY.md"), "w") as fh:
        fh.write("\n".join(md) + "\n")

    print("WROTE ->", args.out)
    print(json.dumps({k: {"f1_macro": v["f1_macro"], "roc_auc": v["roc_auc"],
                          "recall_mal": v["recall"]["malicious"]} for k, v in metrics.items()}, indent=2))
    print("confidence:", json.dumps(conf, indent=2))


if __name__ == "__main__":
    main()
