"""Tests for the thin Kafka alert pointer contract."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kafka_events import decode_soar_alert_event, validate_soar_alert_event  # noqa: E402


def _event(**overrides):
    payload = {
        "schema_version": "1.0",
        "event_type": "alert.translated",
        "alert_id": 123,
        "flow_id": "flow-1",
        "model": "XGBoost",
        "tier": "fast",
        "translated_ts": "2026-06-19T10:00:00Z",
        "mapping_status": "mapped",
        "pred_label": 1,
        "pred_proba": 0.97,
    }
    payload.update(overrides)
    return payload


def test_validate_accepts_translated_alert_event():
    event, error = validate_soar_alert_event(_event(alert_id="123"))

    assert error is None
    assert event["alert_id"] == 123
    assert event["event_type"] == "alert.translated"


def test_decode_accepts_json_bytes():
    raw = json.dumps(_event(alert_id=456)).encode("utf-8")

    event, error = decode_soar_alert_event(raw)

    assert error is None
    assert event["alert_id"] == 456


def test_validate_rejects_unknown_schema_version():
    event, error = validate_soar_alert_event(_event(schema_version="2.0"))

    assert event is None
    assert "schema_version" in error


def test_validate_rejects_unknown_event_type():
    event, error = validate_soar_alert_event(_event(event_type="other.event"))

    assert event is None
    assert "event_type" in error


def test_validate_rejects_missing_alert_id():
    payload = _event()
    payload.pop("alert_id")

    event, error = validate_soar_alert_event(payload)

    assert event is None
    assert "alert_id" in error
