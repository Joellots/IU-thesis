"""
translator_service.py
---------------------
Consumes enriched alerts from Kafka, applies the XAI→MITRE translation,
and persists enriched records to PostgreSQL.

Only processes XGBoost Tier-1 records (one record per flow) to avoid
duplicate DB entries — SHAP/LIME records for the same flow are stored
in the raw_explanations table for audit/research purposes.
"""

import os
import re
import json
import time
import logging
import ipaddress
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

from feature_mitre_map import translate

# ── Config ────────────────────────────────────────────────────────────────────
BROKER         = os.getenv("KAFKA_BROKER",    "kafka:9092")
INPUT_TOPIC    = os.getenv("INPUT_TOPIC",     "alerts")
CONSUMER_GROUP = os.getenv("CONSUMER_GROUP",  "translator_group")
DATABASE_URL   = os.getenv("DATABASE_URL",    "postgresql://user:pass@postgres:5432/soar")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [TRANSLATOR] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)


# ── Database ──────────────────────────────────────────────────────────────────
def get_db(retries: int = 20, delay: int = 3):
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
            log.info("Connected to PostgreSQL")
            return conn
        except psycopg2.OperationalError as e:
            log.warning("DB not ready (%d/%d): %s — retrying in %ds",
                        attempt, retries, e, delay)
            time.sleep(delay)
    raise RuntimeError("Could not connect to PostgreSQL")


# Columns the translator owns beyond the base schema.sql definition. Applied
# idempotently at startup so older databases (created before these fields
# existed) are migrated in place — the SOAR orchestrator reads them.
ALERT_COLUMN_MIGRATIONS = {
    "observables":        "JSONB",
    "mapping_confidence": "DOUBLE PRECISION",
    "mapping_version":    "TEXT",
    "mapping_status":     "TEXT",
    "mapping_reason":     "TEXT",
}


def ensure_alerts_schema(cur, retries: int = 20, delay: int = 3):
    """Waits for the alerts table (created by the postgres init script),
    then adds any translator-owned columns that are missing."""
    for attempt in range(1, retries + 1):
        cur.execute("SELECT to_regclass('public.alerts')")
        if cur.fetchone()[0] is not None:
            break
        log.warning("alerts table not ready (%d/%d) — retrying in %ds",
                    attempt, retries, delay)
        time.sleep(delay)
    else:
        raise RuntimeError("alerts table never appeared — check postgres init")

    for column, col_type in ALERT_COLUMN_MIGRATIONS.items():
        cur.execute(
            f"ALTER TABLE alerts ADD COLUMN IF NOT EXISTS {column} {col_type}"
        )
    log.info("alerts schema ensured (%d translator-owned columns)",
             len(ALERT_COLUMN_MIGRATIONS))


# ── Observable extraction ─────────────────────────────────────────────────────
# Identifier fields are matched by *name pattern*, not a fixed column list, so
# the pipeline keeps working when the dataset schema changes (e.g.
# source_IP_address vs src_ip). Values are validated before being typed.
_IP_KEY_RE     = re.compile(r"(ip_address|(^|_)(src|source|dst|destination)_?ip$)", re.I)
_DOMAIN_KEY_RE = re.compile(r"(server_name|domain|hostname)", re.I)
_URL_KEY_RE    = re.compile(r"(^|_)url$", re.I)
_JA3_KEY_RE    = re.compile(r"fingerprint", re.I)               # client/server_fingerprint → ja3
_SRC_KEY_RE    = re.compile(r"(^|_)(src|source|client)", re.I)  # client_fingerprint → src
_DST_KEY_RE    = re.compile(r"(^|_)(dst|destination|server)", re.I)  # server_fingerprint → dst


def extract_observables(alert: dict) -> list:
    """Builds the alerts.observables list ([{type, value, role?}, ...]) from
    the alert's context fields. Types align with the orchestrator's Cortex
    analyzer routing: ip / domain / url / ja3 (TLS fingerprint → MISP)."""
    observables, seen = [], set()
    sources = [alert.get("context") or {}, alert]

    for source in sources:
        for key, value in source.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            text = str(value).strip()
            if not text or text.lower() in ("nan", "none", "null", "0.0", "0"):
                continue

            if _IP_KEY_RE.search(key):
                try:
                    ip = ipaddress.ip_address(text)
                except ValueError:
                    continue
                if ip.is_unspecified or ip.is_loopback:
                    continue
                obs_type = "ip"
            elif _URL_KEY_RE.search(key):
                obs_type = "url"
            elif _DOMAIN_KEY_RE.search(key):
                obs_type = "domain"
            elif _JA3_KEY_RE.search(key):
                obs_type = "ja3"
            else:
                continue

            if (obs_type, text) in seen:
                continue
            seen.add((obs_type, text))

            obs = {"type": obs_type, "value": text}
            if _SRC_KEY_RE.search(key):
                obs["role"] = "src"
            elif _DST_KEY_RE.search(key):
                obs["role"] = "dst"
            observables.append(obs)

    return observables


def insert_alert(cur, record: dict):
    """Insert enriched alert into the alerts table."""
    cur.execute("""
        INSERT INTO alerts (
            flow_id, sent_ts, inferred_ts, translated_ts,
            model, tier, pred_label, pred_proba, true_label,
            explain_time_ms, top_k_features, top_k_json,
            mitre_ttps, mitre_names, severity, severity_label,
            annotation, n_ttps_matched,
            observables, mapping_confidence, mapping_version,
            mapping_status, mapping_reason
        ) VALUES (
            %(flow_id)s, %(sent_ts)s, %(inferred_ts)s, %(translated_ts)s,
            %(model)s, %(tier)s, %(pred_label)s, %(pred_proba)s, %(true_label)s,
            %(explain_time_ms)s, %(top_k_features)s, %(top_k_json)s,
            %(mitre_ttps)s, %(mitre_names)s, %(severity)s, %(severity_label)s,
            %(annotation)s, %(n_ttps_matched)s,
            %(observables)s, %(mapping_confidence)s, %(mapping_version)s,
            %(mapping_status)s, %(mapping_reason)s
        )
        ON CONFLICT (flow_id, model) DO NOTHING;
    """, {
        **record,
        "translated_ts": datetime.now(timezone.utc).isoformat(),
        "top_k_json":    json.dumps(record.get("top_k_json", [])),
        "mitre_ttps":    json.dumps(record.get("mitre_ttps", [])),
        "mitre_names":   json.dumps(record.get("mitre_names", [])),
        "observables":   json.dumps(record.get("observables", [])),
        "mapping_confidence": record.get("mapping_confidence", 0.0),
        "mapping_version":    record.get("mapping_version", "unknown"),
        "mapping_status":     record.get("mapping_status", "unknown"),
        "mapping_reason":     record.get("mapping_reason", ""),
    })


def insert_raw_explanation(cur, record: dict):
    """Store all explanation records (including SHAP/LIME) for audit."""
    cur.execute("""
        INSERT INTO raw_explanations (
            flow_id, model, tier, pred_label, pred_proba,
            explain_time_ms, top_k_json, sent_ts, inferred_ts
        ) VALUES (
            %(flow_id)s, %(model)s, %(tier)s, %(pred_label)s, %(pred_proba)s,
            %(explain_time_ms)s, %(top_k_json)s, %(sent_ts)s, %(inferred_ts)s
        )
        ON CONFLICT DO NOTHING;
    """, {
        **record,
        "top_k_json": json.dumps(record.get("top_k_json", [])),
    })


# ── Kafka ─────────────────────────────────────────────────────────────────────
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
            log.info("Translator consumer connected — topic=%s", INPUT_TOPIC)
            return c
        except NoBrokersAvailable:
            log.warning("Broker not ready (%d/%d) — retrying in %ds",
                        attempt, retries, delay)
            time.sleep(delay)
    raise RuntimeError("Could not connect translator consumer to Kafka")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    conn     = get_db()
    cur      = conn.cursor()
    ensure_alerts_schema(cur)
    consumer = make_consumer()

    log.info("Translator running — consuming from '%s'", INPUT_TOPIC)
    processed = 0

    for message in consumer:
        alert = message.value

        # Always store raw explanation for every model/tier
        try:
            insert_raw_explanation(cur, alert)
        except Exception as e:
            log.warning("raw_explanations insert failed for %s: %s",
                        alert.get("flow_id", "?"), e)

        # Only translate and persist the primary XGBoost Tier-1 record
        if alert.get("model") != "XGBoost" or alert.get("tier") != "fast":
            continue

        try:
            enriched = translate(alert)
            enriched["observables"] = extract_observables(alert)
            insert_alert(cur, enriched)
            processed += 1

            label = "MALICIOUS" if enriched["pred_label"] == 1 else "benign"
            log.info(
                "[%d] flow=%s  %s  severity=%s  ttps=%s",
                processed,
                enriched.get("flow_id", "?")[:8],
                label,
                enriched.get("severity_label"),
                enriched.get("mitre_ttps"),
            )
        except Exception as e:
            log.error("Translation/insert failed for flow %s: %s",
                      alert.get("flow_id", "?"), e)


if __name__ == "__main__":
    main()