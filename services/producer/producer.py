"""
producer.py
-----------
Reads the flow feature dataset and publishes each row to the Kafka topic
`raw_flows` at a configurable rate, simulating live network traffic capture.

Each message payload:
{
    "flow_id":    str,   # uuid4 assigned at send time
    "sent_ts":    str,   # ISO8601 timestamp
    "true_label": int,   # 0=benign, 1=malicious (kept for dashboard evaluation)
    "features":   dict   # all flow feature columns
}

Environment variables (set in docker-compose.yml):
    KAFKA_BROKER      — broker address (default: kafka:9092)
    TOPIC             — target topic   (default: raw_flows)
    STREAM_DELAY_MS   — ms between messages (default: 500)
    DATASET_PATH      — path to CSV   (default: /data/dataset.csv)
    LOOP              — replay dataset when exhausted (default: true)
    LABEL_COL         — name of the label column (default: label)
"""

import os
import json
import time
import uuid
import logging
from datetime import datetime, timezone

import pandas as pd
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

# ── Config ────────────────────────────────────────────────────────────────────
BROKER          = os.getenv("KAFKA_BROKER",     "kafka:9092")
TOPIC           = os.getenv("TOPIC",            "raw_flows")
DELAY_MS        = int(os.getenv("STREAM_DELAY_MS",  "500"))
DATASET_PATH    = os.getenv("DATASET_PATH",     "/data/dataset.csv")
LOOP            = os.getenv("LOOP",             "true").lower() == "true"
LABEL_COL       = os.getenv("LABEL_COL",        "label")
BATCH_SIZE      = int(os.getenv("BATCH_SIZE",   "0"))     # 0 = no limit
MALICIOUS_RATIO = float(os.getenv("MALICIOUS_RATIO", "-1"))  # -1 = use dataset as-is
SHUFFLE         = os.getenv("SHUFFLE",          "true").lower() == "true"

# ── Simulated endpoint identity (replay-as-endpoint) ──────────────────────────
# When SIM_AGENT_ID is set, every replayed flow is stamped with this endpoint's
# identity — making the dataset replay behave "as though THIS machine produced the
# flow". It propagates through inference → translator → the alerts row, so the SOAR
# orchestrator routes any block/isolate back to THIS host's Wazuh agent (and the
# action is verifiable here). Set these to the detection host's real Wazuh
# agent id / name / LAN IP (after installing the endpoint_agent bundle + enrolling).
import socket
SIM_AGENT_ID = os.getenv("SIM_AGENT_ID") or None
SIM_HOST_ID  = os.getenv("SIM_HOST_ID")  or socket.gethostname()
SIM_HOST_IP  = os.getenv("SIM_HOST_IP")  or None
STAMP_IDENTITY = SIM_AGENT_ID is not None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PRODUCER] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)


def make_producer(retries=20, delay=3):
    for attempt in range(1, retries + 1):
        try:
            p = KafkaProducer(
                bootstrap_servers=BROKER,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks="all",
                retries=5,
                linger_ms=10,
            )
            log.info("Connected to Kafka at %s", BROKER)
            return p
        except NoBrokersAvailable:
            log.warning("Broker not ready (%d/%d) — retrying in %ds",
                        attempt, retries, delay)
            time.sleep(delay)
    raise RuntimeError("Could not connect to Kafka")


def load_dataset(path: str) -> pd.DataFrame:
    log.info("Loading dataset from %s", path)
    df = pd.read_csv(path, low_memory=False)
    log.info("Loaded %d rows, %d columns", len(df), len(df.columns))

    if LABEL_COL not in df.columns:
        raise ValueError(
            f"Label column '{LABEL_COL}' not found. "
            f"Available: {df.columns.tolist()}"
        )
    return df


def prepare_batch(df: pd.DataFrame, iteration: int) -> pd.DataFrame:
    """
    Apply MALICIOUS_RATIO, BATCH_SIZE, and SHUFFLE controls
    to produce the batch for one loop iteration.
    """
    # ── Class ratio control ───────────────────────────────────────────────────
    if MALICIOUS_RATIO >= 0:
        malicious = df[df[LABEL_COL] == 1]
        benign    = df[df[LABEL_COL] == 0]

        if MALICIOUS_RATIO == 1.0:
            batch = malicious
        elif MALICIOUS_RATIO == 0.0:
            batch = benign
        else:
            # Balance to requested ratio using the smaller class as the limit
            n_mal = int(len(malicious) * MALICIOUS_RATIO)
            n_ben = int(n_mal / MALICIOUS_RATIO * (1 - MALICIOUS_RATIO))
            n_mal = min(n_mal, len(malicious))
            n_ben = min(n_ben, len(benign))
            batch = pd.concat([
                malicious.sample(n=n_mal, random_state=iteration),
                benign.sample(n=n_ben,    random_state=iteration),
            ])
    else:
        batch = df.copy()

    # ── Shuffle ───────────────────────────────────────────────────────────────
    if SHUFFLE:
        batch = batch.sample(frac=1, random_state=iteration).reset_index(drop=True)

    # ── Batch size limit ──────────────────────────────────────────────────────
    if BATCH_SIZE > 0:
        batch = batch.head(BATCH_SIZE)

    log.info(
        "Batch ready: %d rows | malicious=%d benign=%d",
        len(batch),
        int((batch[LABEL_COL] == 1).sum()),
        int((batch[LABEL_COL] == 0).sum()),
    )
    return batch


def stream(producer: KafkaProducer, batch: pd.DataFrame):
    delay_s      = DELAY_MS / 1000.0
    feature_cols = [c for c in batch.columns if c != LABEL_COL]

    for _, row in batch.iterrows():
        payload = {
            "flow_id":    str(uuid.uuid4()),
            "sent_ts":    datetime.now(timezone.utc).isoformat(),
            "true_label": int(row[LABEL_COL]),
            "features":   row[feature_cols].to_dict(),
        }
        if STAMP_IDENTITY:                       # replay-as-endpoint (this machine)
            payload["agent_id"] = SIM_AGENT_ID
            payload["host_id"]  = SIM_HOST_ID
            payload["host_ip"]  = SIM_HOST_IP
        producer.send(TOPIC, value=payload)

        label_str = "MALICIOUS" if payload["true_label"] == 1 else "benign"
        log.info("Sent flow_id=%s  label=%s", payload["flow_id"][:8], label_str)

        time.sleep(delay_s)

    producer.flush()


def main():
    producer = make_producer()
    df       = load_dataset(DATASET_PATH)

    if STAMP_IDENTITY:
        log.info("Replay-as-endpoint: stamping agent_id=%s host_id=%s host_ip=%s onto every flow",
                 SIM_AGENT_ID, SIM_HOST_ID, SIM_HOST_IP)

    iteration = 0
    while True:
        iteration += 1
        log.info("─── Stream iteration %d ───", iteration)

        batch = prepare_batch(df, iteration)
        stream(producer, batch)

        log.info("Iteration %d complete — %d messages sent", iteration, len(batch))

        if not LOOP:
            log.info("LOOP=false — producer exiting")
            break

        log.info("Replaying (LOOP=true)...")


if __name__ == "__main__":
    main()