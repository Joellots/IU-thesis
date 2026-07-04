"""Kafka trigger helpers for SOAR alert events.

Kafka carries only a low-latency pointer. Postgres remains the source of
truth, so validated events are used only to fetch alerts by id.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from slog import get_logger

log = get_logger(__name__)

SUPPORTED_SCHEMA_VERSION = "1.0"
EXPECTED_EVENT_TYPE = "alert.translated"


def _host_part(address: str) -> str:
    return str(address or "").rsplit(":", 1)[0].strip("[]").lower()


def _is_loopback_host(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"}


def _has_unusable_remote_metadata(consumer, bootstrap_broker: str) -> tuple[bool, list[str]]:
    bootstrap_host = _host_part(bootstrap_broker.split(",", 1)[0])
    if _is_loopback_host(bootstrap_host):
        return False, []
    try:
        advertised_hosts = sorted({str(b.host) for b in consumer._client.cluster.brokers()})
    except Exception:
        return False, []
    if any(_is_loopback_host(_host_part(host)) for host in advertised_hosts):
        return True, advertised_hosts
    return False, advertised_hosts


def validate_soar_alert_event(payload: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Validate and normalize the thin detection-side Kafka event.

    Returns ``(event, None)`` on success or ``(None, reason)`` when the event
    should be skipped. Unknown schema versions and event types are deliberately
    non-fatal so the consumer can share a topic safely during evolution.
    """
    if not isinstance(payload, dict):
        return None, "payload is not a JSON object"

    schema_version = str(payload.get("schema_version") or "")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        return None, f"unsupported schema_version={schema_version or 'missing'}"

    event_type = str(payload.get("event_type") or "")
    if event_type != EXPECTED_EVENT_TYPE:
        return None, f"unsupported event_type={event_type or 'missing'}"

    try:
        alert_id = int(payload.get("alert_id"))
    except (TypeError, ValueError):
        return None, "alert_id missing or invalid"
    if alert_id <= 0:
        return None, "alert_id must be positive"

    event = dict(payload)
    event["alert_id"] = alert_id
    return event, None


def decode_soar_alert_event(raw_value: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Decode a Kafka message value and validate the SOAR event contract."""
    if isinstance(raw_value, (bytes, bytearray)):
        try:
            payload = json.loads(raw_value.decode("utf-8"))
        except Exception as exc:
            return None, f"invalid JSON: {exc}"
    elif isinstance(raw_value, str):
        try:
            payload = json.loads(raw_value)
        except Exception as exc:
            return None, f"invalid JSON: {exc}"
    else:
        payload = raw_value
    return validate_soar_alert_event(payload)


def make_soar_alert_consumer(*, retries: int = 1, delay: float = 2.0):
    """Create a KafkaConsumer for SOAR alert pointer events.

    Importing kafka-python happens here so parsing tests do not require the
    runtime dependency. The orchestrator treats failure to connect as a fallback
    condition and continues with Postgres polling.
    """
    from kafka import KafkaConsumer
    from kafka.errors import NoBrokersAvailable

    broker = os.getenv("KAFKA_BROKER", "localhost:9094")
    topic = os.getenv("SOAR_ALERT_EVENTS_TOPIC", "soar_alert_events")
    group_id = os.getenv("SOAR_ALERT_EVENTS_CONSUMER_GROUP", "soar_orchestrator")
    auto_offset_reset = os.getenv("SOAR_ALERT_EVENTS_OFFSET_RESET", "latest")

    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=broker,
                group_id=group_id,
                auto_offset_reset=auto_offset_reset,
                enable_auto_commit=False,
            )
            unusable_metadata, advertised_hosts = _has_unusable_remote_metadata(consumer, broker)
            if unusable_metadata:
                log.warning(
                    "kafka_advertised_listener_unreachable",
                    extra={
                        "event": "kafka_advertised_listener_unreachable",
                        "broker": broker,
                        "advertised_hosts": advertised_hosts,
                        "hint": "set KAFKA_EXTERNAL_ADVERTISED_HOST on the detection Kafka broker",
                    },
                )
                try:
                    consumer.close()
                except Exception:
                    pass
                return None
            log.info(
                "kafka_consumer_connected",
                extra={
                    "event": "kafka_consumer_connected",
                    "broker": broker,
                    "topic": topic,
                    "group_id": group_id,
                    "auto_offset_reset": auto_offset_reset,
                    "advertised_hosts": advertised_hosts,
                },
            )
            return consumer
        except NoBrokersAvailable as exc:
            log.warning(
                "kafka_connect_retry",
                extra={
                    "event": "kafka_connect_retry",
                    "attempt": attempt,
                    "retries": retries,
                    "retry_in_sec": delay,
                    "error": str(exc),
                },
            )
            if attempt < retries:
                time.sleep(delay)
    return None
