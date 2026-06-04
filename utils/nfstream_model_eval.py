"""
nfstream_model_eval.py
──────────────────────
Extracts flow features from PCAP files using NFStream + ExtendedFlowFeatures
plugin (identical logic to nfstream_producer.py), then evaluates the trained
XGBoost / RF models on the resulting instances.

This tests whether models trained on CICFlowMeter-extracted features remain
accurate when predicting on NFStream-extracted features of the same traffic —
a feature extraction tool distribution shift experiment.

Usage:
    python3 nfstream_model_eval.py \
        --benign  path/to/benign.pcap \
        --malicious path/to/malicious.pcap \
        --model   path/to/mapper.joblib \
        --output  results/

    # Multiple PCAPs per class:
    python3 nfstream_model_eval.py \
        --benign  pcaps/benign1.pcap pcaps/benign2.pcap \
        --malicious pcaps/wannacry.pcap pcaps/mirai.pcap \
        --model   mapper.joblib

    # PCAP only, no labels (exploration mode):
    python3 nfstream_model_eval.py \
        --pcap    pcaps/capture.pcap \
        --model   mapper.joblib
"""

import argparse
import os
import sys
import statistics
import logging
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import joblib
from pathlib import Path

from nfstream import NFStreamer, NFPlugin

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [eval] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# NFPlugin — identical to nfstream_producer.py
# ─────────────────────────────────────────────────────────────────────────────

class ExtendedFlowFeatures(NFPlugin):

    def on_init(self, packet, flow):
        flow.udps.piat_list           = [packet.time]
        flow.udps.last_seen_ms        = packet.time
        flow.udps.payload_changes     = 0
        flow.udps.last_payload_size   = packet.payload_size
        flow.udps.transport_changes   = 0
        flow.udps.last_transport_size = packet.transport_size

        # Initialise output fields
        flow.udps.median_piat_ms     = 0.0
        flow.udps.mean_ttl           = 0.0
        flow.udps.std_ttl            = 0.0
        flow.udps.max_ttl            = 0.0
        flow.udps.min_ttl            = 0.0
        flow.udps.mean_window_size   = 0.0
        flow.udps.std_window_size    = 0.0
        flow.udps.max_window_size    = 0.0
        flow.udps.min_window_size    = 0.0
        flow.udps.median_window_size = 0.0
        flow.udps.window_changes     = 0

    def on_update(self, packet, flow):
        iat = packet.time - flow.udps.last_seen_ms
        if iat > 0:
            flow.udps.piat_list.append(iat)
        flow.udps.last_seen_ms = packet.time

        if packet.payload_size != flow.udps.last_payload_size:
            flow.udps.payload_changes += 1
        flow.udps.last_payload_size = packet.payload_size

        if packet.transport_size != flow.udps.last_transport_size:
            flow.udps.transport_changes += 1
        flow.udps.last_transport_size = packet.transport_size

    def on_expire(self, flow):
        piats = flow.udps.piat_list
        flow.udps.median_piat_ms = (
            statistics.median(piats) if len(piats) >= 2 else 0.0
        )

        # ── TTL statistics — derived from flow-level fields ───────────────
        # NFStream tracks TTL (IPv4) or hop_limit (IPv6) at flow level.
        # Collect all available min/max values from both directions.
        ttl_vals = []

        # IPv4 TTL fields
        for attr in ['src2dst_min_ttl', 'src2dst_max_ttl', 'dst2src_min_ttl', 'dst2src_max_ttl']:
            v = getattr(flow, attr, None)
            # Include TTL values >= 0 (0 is technically invalid but collect it)
            if v is not None and isinstance(v, (int, float)) and v >= 0:
                ttl_vals.append(float(v))

        # IPv6 hop limit fields (if present)
        for attr in ['src2dst_min_hop_limit', 'src2dst_max_hop_limit',
                     'dst2src_min_hop_limit', 'dst2src_max_hop_limit']:
            v = getattr(flow, attr, None)
            if v is not None and isinstance(v, (int, float)) and v >= 0:
                ttl_vals.append(float(v))

        if ttl_vals:
            flow.udps.mean_ttl = statistics.mean(ttl_vals)
            flow.udps.std_ttl  = statistics.pstdev(ttl_vals) if len(ttl_vals) >= 2 else 0.0
            flow.udps.max_ttl  = float(max(ttl_vals))
            flow.udps.min_ttl  = float(min(ttl_vals))

        # ── TCP window statistics — derived from transport_size distribution ────
        # NFStream does not expose per-packet TCP window values.
        # Collect bidirectional transport size range as window proxy.
        win_vals = []
        for attr in ['bidirectional_min_ps', 'bidirectional_max_ps', 'bidirectional_mean_ps',
                     'src2dst_min_ps', 'src2dst_max_ps', 'src2dst_mean_ps',
                     'dst2src_min_ps', 'dst2src_max_ps', 'dst2src_mean_ps']:
            v = getattr(flow, attr, None)
            if v is not None and isinstance(v, (int, float)) and v > 0:
                win_vals.append(float(v))

        if win_vals:
            flow.udps.mean_window_size   = statistics.mean(win_vals)
            flow.udps.std_window_size    = statistics.pstdev(win_vals) if len(win_vals) >= 2 else 0.0
            flow.udps.max_window_size    = float(max(win_vals))
            flow.udps.min_window_size    = float(min(win_vals))
            flow.udps.median_window_size = statistics.median(win_vals)

        flow.udps.window_changes = flow.udps.transport_changes
        flow.udps.piat_list = []


# ─────────────────────────────────────────────────────────────────────────────
# NFStream → model feature name mapping (same as producer)
# ─────────────────────────────────────────────────────────────────────────────

NFSTREAM_TO_MODEL = {
    "bidirectional_mean_ps":        "mean_Length_of_IP_packets",
    "bidirectional_stddev_ps":      "std_Length_of_IP_packets",
    "bidirectional_max_ps":         "max_Length_of_IP_packets",
    "bidirectional_min_ps":         "min_Length_of_IP_packets",
    "src2dst_mean_ps":              "mean_Length_of_TCP_payload",
    "src2dst_stddev_ps":            "std_Length_of_TCP_payload",
    "src2dst_max_ps":               "max_Length_of_TCP_payload",
    "src2dst_min_ps":               "min_Length_of_TCP_payload",
    "src2dst_bytes":                "Length_of_TCP_payload",
    "bidirectional_mean_piat_ms":   "mean_Time_difference_between_packets_per_session",
    "bidirectional_stddev_piat_ms": "std_Time_difference_between_packets_per_session",
    "bidirectional_max_piat_ms":    "max_Time_difference_between_packets_per_session",
    "bidirectional_min_piat_ms":    "min_Time_difference_between_packets_per_session",
    "src2dst_mean_piat_ms":         "mean_Interval_of_arrival_time_of_forward_traffic",
    "src2dst_stddev_piat_ms":       "std_Interval_of_arrival_time_of_forward_traffic",
    "src2dst_max_piat_ms":          "max_Interval_of_arrival_time_of_forward_traffic",
    "src2dst_min_piat_ms":          "min_Interval_of_arrival_time_of_forward_traffic",
    "dst2src_mean_piat_ms":         "mean_Interval_of_arrival_time_of_backward_traffic",
    "dst2src_stddev_piat_ms":       "std_Interval_of_arrival_time_of_backward_traffic",
    "dst2src_max_piat_ms":          "max_Interval_of_arrival_time_of_backward_traffic",
    "dst2src_min_piat_ms":          "min_Interval_of_arrival_time_of_backward_traffic",
    "udps.median_piat_ms":          "median_Time_difference_between_packets_per_session",
    "udps.mean_ttl":                "mean_time_to_live",
    "udps.std_ttl":                 "std_time_to_live",
    "udps.max_ttl":                 "max_time_to_live",
    "udps.min_ttl":                 "min_time_to_live",
    "udps.mean_window_size":        "mean_TCP_windows_size_value",
    "udps.std_window_size":         "std_TCP_windows_size_value",
    "udps.max_window_size":         "max_TCP_windows_size_value",
    "udps.min_window_size":         "min_TCP_windows_size_value",
    "udps.median_window_size":      "median_TCP_windows_size_value",
    "udps.payload_changes":         "The_times_of_change_of_payload_per_session",
    "udps.window_changes":          "Change_values_of_TCP_windows_length_per_session",
}

# Context fields kept for reporting (not fed to model)
CONTEXT_FIELDS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_duration_ms", "bidirectional_packets",
    "application_name", "application_category_name",
    "requested_server_name",
]


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_flows(pcap_path: str, label: int = None) -> pd.DataFrame:
    """
    Extract flows from a PCAP file using NFStream + ExtendedFlowFeatures.

    Args:
        pcap_path: path to the PCAP file
        label:     0 = benign, 1 = malicious, None = unknown

    Returns:
        DataFrame with model feature columns + context + label
    """
    log.info(f"Extracting flows from: {pcap_path}  (label={'unknown' if label is None else label})")

    streamer = NFStreamer(
        source=pcap_path,
        statistical_analysis=True,
        n_dissections=20,
        udps=ExtendedFlowFeatures(),
        # No BPF filter here — capture everything for evaluation
    )

    rows = []
    for flow in streamer:
        record = {}

        # Model features
        for nf_col, model_col in NFSTREAM_TO_MODEL.items():
            if "." in nf_col:
                attr = nf_col.split(".")[1]
                record[model_col] = getattr(flow.udps, attr, 0.0)
            else:
                record[model_col] = getattr(flow, nf_col, 0.0)

        # Context
        for field in CONTEXT_FIELDS:
            record[field] = getattr(flow, field, None)

        # Flow identifier
        record["flow_id"] = (
            f"{flow.src_ip}:{flow.src_port}-{flow.dst_ip}:{flow.dst_port}"
            f"-{flow.protocol}-{flow.bidirectional_first_seen_ms}"
        )
        record["pcap_source"] = os.path.basename(pcap_path)

        if label is not None:
            record["true_label"] = label

        rows.append(record)

    df = pd.DataFrame(rows)
    log.info(f"  Extracted {len(df)} flows from {os.path.basename(pcap_path)}")
    return df


def extract_all_pcaps(
    benign_pcaps: list,
    malicious_pcaps: list,
    unlabelled_pcaps: list
) -> pd.DataFrame:
    """Combine flows from all provided PCAPs into one DataFrame."""
    frames = []

    for p in benign_pcaps:
        frames.append(extract_flows(p, label=0))

    for p in malicious_pcaps:
        frames.append(extract_flows(p, label=1))

    for p in unlabelled_pcaps:
        frames.append(extract_flows(p, label=None))

    if not frames:
        raise ValueError("No PCAP files provided.")

    df = pd.concat(frames, ignore_index=True)
    log.info(f"Total flows extracted: {len(df)}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Feature distribution analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyse_feature_coverage(df: pd.DataFrame, feature_cols: list):
    """
    Report which features are all-zero (likely extraction failures)
    vs populated, and show basic distribution stats.
    """
    log.info("\n" + "═" * 60)
    log.info(" Feature Coverage Analysis")
    log.info("═" * 60)

    all_zero, populated = [], []
    for col in feature_cols:
        if col not in df.columns:
            log.warning(f"  MISSING from DataFrame: {col}")
            continue
        if df[col].fillna(0).eq(0).all():
            all_zero.append(col)
        else:
            populated.append(col)

    log.info(f"\n  Populated features : {len(populated)}/{len(feature_cols)}")
    log.info(f"  All-zero features  : {len(all_zero)}/{len(feature_cols)}")

    if all_zero:
        log.warning("\n  All-zero (likely NFStream extraction gaps):")
        for col in all_zero:
            log.warning(f"    {col}")

    log.info("\n  Populated feature statistics (mean ± std):")
    for col in populated[:15]:  # show first 15
        m = df[col].mean()
        s = df[col].std()
        log.info(f"    {col[:55]:55s}  {m:10.3f} ± {s:.3f}")
    if len(populated) > 15:
        log.info(f"    ... and {len(populated) - 15} more")

    return populated, all_zero


# ─────────────────────────────────────────────────────────────────────────────
# Model evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(df: pd.DataFrame, mapper: dict, output_dir: str):
    """
    Run prediction using all available models in the mapper.
    Compute metrics if true_label column is present.
    """
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        accuracy_score, f1_score, roc_auc_score
    )

    has_labels = "true_label" in df.columns and df["true_label"].notna().any()

    results = {}

    for model_key, feature_key, scaler_key, label in [
        ("rf_best",  "BEST_FEATURES",          "scaler_best", "Random Forest (best_features)"),
        # ("xgb_rt",   "REALTIME_SAFE_FEATURES",  "scaler_rt",   "XGBoost (realtime-safe)"),
    ]:
        if model_key not in mapper:
            log.warning(f"Model '{model_key}' not found in mapper — skipping")
            continue
        if feature_key not in mapper:
            log.warning(f"Feature list '{feature_key}' not found in mapper — skipping")
            continue

        model   = mapper[model_key]
        scaler  = mapper.get(scaler_key)
        features = mapper[feature_key]

        # Filter to features that exist and are populated in this df
        available = [f for f in features if f in df.columns]
        missing   = [f for f in features if f not in df.columns]

        log.info(f"\n{'─'*60}")
        log.info(f" {label}")
        log.info(f"{'─'*60}")
        log.info(f"  Expected features : {len(features)}")
        log.info(f"  Available in df   : {len(available)}")
        if missing:
            log.warning(f"  Missing features  : {len(missing)}")
            for m in missing:
                log.warning(f"    {m}")

        # Fill missing features with 0 — documents the distribution shift
        X = df[features].copy()
        for f in missing:
            X[f] = 0.0
        X = X.fillna(0.0)

        # Scale if scaler present
        if scaler is not None:
            try:
                X_scaled = scaler.transform(X)
            except Exception as e:
                log.warning(f"  Scaler failed ({e}) — using unscaled features")
                X_scaled = X.values
        else:
            X_scaled = X.values

        # Predict
        y_pred  = model.predict(X_scaled)
        y_proba = model.predict_proba(X_scaled)[:, 1]

        # Store predictions in df
        col_pred  = f"pred_{model_key}"
        col_proba = f"proba_{model_key}"
        df[col_pred]  = y_pred
        df[col_proba] = y_proba

        log.info(f"\n  Prediction distribution:")
        log.info(f"    Malicious : {y_pred.sum()} ({y_pred.mean()*100:.1f}%)")
        log.info(f"    Benign    : {(y_pred == 0).sum()} ({(y_pred == 0).mean()*100:.1f}%)")

        if has_labels:
            y_true = df["true_label"].fillna(-1).astype(int)
            labelled_mask = y_true != -1
            y_true_l = y_true[labelled_mask].values
            y_pred_l = y_pred[labelled_mask]
            y_prob_l = y_proba[labelled_mask]

            acc  = accuracy_score(y_true_l, y_pred_l)
            f1   = f1_score(y_true_l, y_pred_l, average="macro", zero_division=0)
            try:
                auc = roc_auc_score(y_true_l, y_prob_l)
            except Exception:
                auc = float("nan")

            log.info(f"\n  Evaluation metrics (on {labelled_mask.sum()} labelled flows):")
            log.info(f"    Accuracy : {acc:.4f}")
            log.info(f"    F1 Macro : {f1:.4f}")
            log.info(f"    ROC-AUC  : {auc:.4f}")
            log.info(f"\n  Classification report:")
            print(classification_report(
                y_true_l, y_pred_l,
                target_names=["Benign", "Malicious"],
                zero_division=0
            ))
            log.info(f"\n  Confusion matrix:")
            cm = confusion_matrix(y_true_l, y_pred_l)
            log.info(f"    TN={cm[0,0]}  FP={cm[0,1]}")
            log.info(f"    FN={cm[1,0]}  TP={cm[1,1]}")

            results[label] = {
                "accuracy": acc, "f1": f1, "auc": auc,
                "tp": int(cm[1,1]), "fp": int(cm[0,1]),
                "tn": int(cm[0,0]), "fn": int(cm[1,0]),
            }

    return df, results


# ─────────────────────────────────────────────────────────────────────────────
# Per-flow report
# ─────────────────────────────────────────────────────────────────────────────

def flow_report(df: pd.DataFrame, output_dir: str):
    """Save per-flow predictions with context fields to CSV."""
    os.makedirs(output_dir, exist_ok=True)

    context = CONTEXT_FIELDS + ["flow_id", "pcap_source"]
    pred_cols = [c for c in df.columns if c.startswith("pred_") or c.startswith("proba_")]
    label_col = ["true_label"] if "true_label" in df.columns else []

    report_df = df[context + label_col + pred_cols].copy()

    out_path = os.path.join(output_dir, "per_flow_predictions.csv")
    report_df.to_csv(out_path, index=False)
    log.info(f"\nPer-flow predictions saved to: {out_path}")

    # Also save full feature df for distribution analysis
    full_path = os.path.join(output_dir, "extracted_features.csv")
    df.to_csv(full_path, index=False)
    log.info(f"Full feature DataFrame saved to: {full_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate trained model on NFStream-extracted PCAP features"
    )
    parser.add_argument("--benign",    nargs="+", default=[],
                        help="PCAP files labelled benign (label=0)")
    parser.add_argument("--malicious", nargs="+", default=[],
                        help="PCAP files labelled malicious (label=1)")
    parser.add_argument("--pcap",      nargs="+", default=[],
                        help="Unlabelled PCAP files (exploration mode)")
    parser.add_argument("--model",     required=True,
                        help="Path to mapper.joblib")
    parser.add_argument("--output",    default="eval_results",
                        help="Output directory for reports (default: eval_results)")
    args = parser.parse_args()

    if not args.benign and not args.malicious and not args.pcap:
        parser.error("Provide at least one PCAP via --benign, --malicious, or --pcap")

    # Load model mapper
    log.info(f"Loading model mapper from: {args.model}")
    mapper = joblib.load(args.model)
    log.info(f"  Keys in mapper: {list(mapper.keys())}")

    # Extract flows
    df = extract_all_pcaps(args.benign, args.malicious, args.pcap)

    if df.empty:
        log.error("No flows extracted — check PCAP files and NFStream installation")
        sys.exit(1)

    log.info(f"\nDataFrame shape: {df.shape}")

    # Analyse feature coverage
    model_features = (
        list(mapper.get("REALTIME_SAFE_FEATURES", []))
        or list(mapper.get("BEST_FEATURES", []))
    )
    if model_features:
        populated, all_zero = analyse_feature_coverage(df, model_features)
    else:
        log.warning("No feature list found in mapper — skipping coverage analysis")

    # Evaluate
    df, results = evaluate(df, mapper, args.output)

    # Save reports
    flow_report(df, args.output)

    # Summary
    if results:
        log.info("\n" + "═" * 60)
        log.info(" Summary")
        log.info("═" * 60)
        for model_name, metrics in results.items():
            log.info(f"\n  {model_name}")
            log.info(f"    Accuracy : {metrics['accuracy']:.4f}")
            log.info(f"    F1 Macro : {metrics['f1']:.4f}")
            log.info(f"    ROC-AUC  : {metrics['auc']:.4f}")
            log.info(f"    TP={metrics['tp']}  FP={metrics['fp']}  "
                     f"TN={metrics['tn']}  FN={metrics['fn']}")

        log.info("\n  Interpretation guide:")
        log.info("    F1 >= 0.99  → Model generalises well to NFStream features")
        log.info("    F1  0.90-0.99 → Moderate distribution shift — consider retraining")
        log.info("    F1 <  0.90  → Significant shift — retrain on NFStream-extracted data")


if __name__ == "__main__":
    main()