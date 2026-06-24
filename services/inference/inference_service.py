"""
inference_service.py
--------------------
Consumes flow feature messages from `raw_flows`, runs ML prediction and
XAI explanation, then publishes enriched records to `alerts`.

Published alert schema:
{
    "flow_id":         str,
    "sent_ts":         str,    # original producer timestamp
    "inferred_ts":     str,    # when inference completed
    "true_label":      int,
    "model":           str,
    "tier":            str,    # "fast" | "deep"
    "pred_label":      int,
    "pred_proba":      float,
    "explain_time_ms": float,
    "top_k_features":  str,    # comma-separated
    "top_k_json":      list,
}

Environment variables:
    KAFKA_BROKER, INPUT_TOPIC, OUTPUT_TOPIC, MODEL_DIR,
    CONSUMER_GROUP, EXPLAIN_K,
    LIME_PROBA_THRESHOLD, LIME_UNCERTAIN_LO, LIME_UNCERTAIN_HI
"""

import os
import re
import json
import time
import joblib
import logging
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable

from explain_instance import (
    explain_instance,
    is_flagged,
    make_xgb_contrib_fn,
    make_ebm_contrib_fn,
    make_lime_contrib_fn,
    make_shap_contrib_fn,
)

# ── Config ────────────────────────────────────────────────────────────────────
BROKER          = os.getenv("KAFKA_BROKER",         "kafka:9092")
INPUT_TOPIC     = os.getenv("INPUT_TOPIC",          "raw_flows")
OUTPUT_TOPIC    = os.getenv("OUTPUT_TOPIC",         "alerts")
MODEL_DIR       = Path(os.getenv("MODEL_DIR",       "/models"))
CONSUMER_GROUP  = os.getenv("CONSUMER_GROUP",       "inference_group")
EXPLAIN_K       = int(os.getenv("EXPLAIN_K",        "5"))
LIME_THRESH     = float(os.getenv("LIME_PROBA_THRESHOLD", "0.80"))
LIME_UNC_LO     = float(os.getenv("LIME_UNCERTAIN_LO",    "0.45"))
LIME_UNC_HI     = float(os.getenv("LIME_UNCERTAIN_HI",    "0.55"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [INFERENCE] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)


# ── Model loading ─────────────────────────────────────────────────────────────
# def load_pickle(name: str):
#     path = MODEL_DIR / name
#     if not path.exists():
#         raise FileNotFoundError(f"Model file not found: {path}")
#     with open(path, "rb") as f:
#         obj = pickle.load(f)
#     log.info("Loaded %s", path)
#     return obj


def load_models():
    """Load all serialised artefacts from the /models volume."""

    mapper = joblib.load(MODEL_DIR / "mapper")
    log.info("Loaded mapper. Keys: %s", list(mapper.keys()))

    # log.info("All models loaded. Feature count: %d", len(models["feature_cols"]))

    return {
        "xgb_rt":       mapper["xgb_rt"],
        "rf_best":      mapper["rf_best"],
        "xxgb":         mapper["xxgb"],
        "scaler":       mapper["scaler_rt"],
        "feature_cols": mapper["REALTIME_SAFE_FEATURES"],
    }


# ── Kafka helpers ─────────────────────────────────────────────────────────────
def make_consumer(retries: int = 20, delay: int = 3) -> KafkaConsumer:
    for attempt in range(1, retries + 1):
        try:
            c = KafkaConsumer(
                INPUT_TOPIC,
                bootstrap_servers=BROKER,
                group_id=CONSUMER_GROUP,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            )
            log.info("Consumer connected to %s, topic=%s", BROKER, INPUT_TOPIC)
            return c
        except NoBrokersAvailable:
            log.warning("Broker not ready (%d/%d) — retrying in %ds",
                        attempt, retries, delay)
            time.sleep(delay)
    raise RuntimeError("Could not connect consumer to Kafka")


def make_producer(retries: int = 20, delay: int = 3) -> KafkaProducer:
    for attempt in range(1, retries + 1):
        try:
            p = KafkaProducer(
                bootstrap_servers=BROKER,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks="all",
            )
            log.info("Producer connected to %s", BROKER)
            return p
        except NoBrokersAvailable:
            log.warning("Broker not ready (%d/%d) — retrying in %ds",
                        attempt, retries, delay)
            time.sleep(delay)
    raise RuntimeError("Could not connect producer to Kafka")


# ── SOAR context passthrough ──────────────────────────────────────────────────
# Identifier-ish fields (IPs, ports, domains) are not model features, but the
# translator needs them to build observables for the SOAR orchestrator.
# Matching by name pattern instead of a fixed column list keeps this working
# when the dataset schema changes (source_IP_address vs src_ip etc.).
CONTEXT_KEY_RE = re.compile(
    r"(ip_address|(^|_)(src|source|dst|destination)_?ip$|(^|_)port$"
    r"|server_name|domain|hostname|(^|_)url$|^protocol$|fingerprint)",
    re.IGNORECASE,
)


def extract_context(payload: dict) -> dict:
    """Collect identifier fields from the producer message (top level and the
    features dict) to forward alongside model output."""
    context = {}
    for source in (payload.get("features") or {}, payload):
        for key, value in source.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            if CONTEXT_KEY_RE.search(str(key)):
                context[key] = value
    return context


# ── Feature preparation ───────────────────────────────────────────────────────
def prepare_features(raw_features: dict,
                     feature_cols: list,
                     scaler) -> pd.Series:
    """
    Convert the raw feature dict from the producer message into a
    scaled pd.Series aligned to the model's expected feature columns.
    """
    df = pd.DataFrame([raw_features])

    # Keep only columns the model knows about; fill missing with 0
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0.0

    df = df[feature_cols].astype(float)
    df[feature_cols] = scaler.transform(df[feature_cols])

    return df.iloc[0]    # return as Series


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    artefacts  = load_models()
    xgb_model  = artefacts["xgb_rt"]
    rf_model   = artefacts["rf_best"]
    ebm_model  = artefacts["xxgb"]
    scaler     = artefacts["scaler"]
    feat_cols  = artefacts["feature_cols"]

    # Build contribution functions
    xgb_contrib_fn = make_xgb_contrib_fn(xgb_model)
    ebm_contrib_fn = make_ebm_contrib_fn(ebm_model)

    # LIME — built lazily on first use (needs training data for background)
    lime_contrib_fn = None

    # SHAP
    import shap
    shap_explainer  = shap.TreeExplainer(xgb_model)
    shap_contrib_fn = make_shap_contrib_fn(shap_explainer)

    consumer = make_consumer()
    producer = make_producer()

    log.info("Inference service running — consuming from '%s'", INPUT_TOPIC)
    processed = 0

    for message in consumer:
        payload = message.value

        flow_id    = payload.get("flow_id",    "unknown")
        sent_ts    = payload.get("sent_ts",    "")
        true_label = int(payload.get("true_label", -1) if payload.get("true_label") is not None else -1)

        # The dataset-replay producer nests model features under "features"; the
        # live NFStream sensor publishes a flat record (features at top level).
        # Accept both so the same inference path serves replay and live endpoints.
        raw_feats  = payload.get("features") or payload

        # Endpoint identity (stamped by the live sensor; absent for replay flows).
        # Forwarded onto every output record so the translator can persist it and
        # the SOAR orchestrator can route a response to the right Wazuh agent.
        endpoint_identity = {
            "agent_id": payload.get("agent_id"),
            "host_id":  payload.get("host_id"),
            "host_ip":  payload.get("host_ip"),
        }

        try:
            x_row = prepare_features(raw_feats, feat_cols, scaler)
        except Exception as e:
            log.error("Feature preparation failed for flow %s: %s", flow_id, e)
            continue

        # ── Tier-1: XGBoost contributions (always) ────────────────────────
        xgb_record = explain_instance(
            x_row       = x_row,
            model       = xgb_model,
            model_name  = "XGBoost",
            contrib_fn  = xgb_contrib_fn,
            tier        = "fast",
            k           = EXPLAIN_K,
            instance_id = flow_id,
            true_label  = true_label,
        )

        # ── Tier-1: EBM (always) ──────────────────────────────────────────
        ebm_record = explain_instance(
            x_row       = x_row,
            model       = ebm_model,
            model_name  = "EBM",
            contrib_fn  = ebm_contrib_fn,
            tier        = "fast",
            k           = EXPLAIN_K,
            instance_id = flow_id,
            true_label  = true_label,
        )

        # Use XGBoost proba for tier-2 trigger decision
        p_malicious = xgb_record["pred_proba"]
        records     = [xgb_record, ebm_record]

        # ── Tier-2: SHAP + LIME (flagged flows only) ──────────────────────
        if is_flagged(p_malicious, LIME_THRESH, LIME_UNC_LO, LIME_UNC_HI):

            shap_record = explain_instance(
                x_row       = x_row,
                model       = xgb_model,
                model_name  = "XGBoost_SHAP",
                contrib_fn  = shap_contrib_fn,
                tier        = "deep",
                k           = EXPLAIN_K,
                instance_id = flow_id,
                true_label  = true_label,
            )
            records.append(shap_record)

            # LIME contrib fn built on first flagged flow
            if lime_contrib_fn is None:
                from lime.lime_tabular import LimeTabularExplainer
                # Use a small background array of zeros as stand-in
                # (replace with saved training data array for production)
                background = np.zeros((1, len(feat_cols)))
                lime_explainer  = LimeTabularExplainer(
                    training_data  = background,
                    feature_names  = feat_cols,
                    mode           = "classification",
                )
                lime_contrib_fn = make_lime_contrib_fn(
                    lime_explainer,
                    xgb_model.predict_proba,
                    feat_cols,
                )

            lime_record = explain_instance(
                x_row       = x_row,
                model       = xgb_model,
                model_name  = "XGBoost_LIME",
                contrib_fn  = lime_contrib_fn,
                tier        = "deep",
                k           = EXPLAIN_K,
                instance_id = flow_id,
                true_label  = true_label,
            )
            records.append(lime_record)

        # ── Publish all records for this flow to alerts topic ─────────────
        inferred_ts = datetime.now(timezone.utc).isoformat()
        context     = extract_context(payload)
        for rec in records:
            rec["sent_ts"]     = sent_ts
            rec["inferred_ts"] = inferred_ts
            rec["context"]     = context
            rec.update(endpoint_identity)
            producer.send(OUTPUT_TOPIC, value=rec)

        processed += 1
        tier2 = "⚑ TIER-2" if is_flagged(p_malicious) else ""
        log.info(
            "[%d] flow=%s  pred=%s  proba=%.4f  xgb_explain=%.1fms  %s",
            processed, flow_id[:8],
            "MALICIOUS" if xgb_record["pred_label"] == 1 else "benign",
            p_malicious,
            xgb_record["explain_time_ms"],
            tier2,
        )


if __name__ == "__main__":
    main()