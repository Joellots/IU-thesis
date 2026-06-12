"""Tests for TheHive case creation gating."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import should_create_thehive_case  # noqa: E402


def _alert(**kwargs):
    base = {
        "pred_label": 1,
        "mapping_status": "mapped",
        "n_ttps_matched": 2,
    }
    base.update(kwargs)
    return base


def test_mapped_malicious_creates_case(monkeypatch):
    monkeypatch.setenv("REQUIRE_MAPPED_FOR_THEHIVE", "true")
    monkeypatch.setenv("THEHIVE_API_KEY", "test-key")
    ok, reason = should_create_thehive_case(_alert())
    assert ok is True
    assert reason == ""


def test_mapped_malicious_skipped_without_api_key(monkeypatch):
    monkeypatch.setenv("REQUIRE_MAPPED_FOR_THEHIVE", "true")
    monkeypatch.delenv("THEHIVE_API_KEY", raising=False)
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    ok, reason = should_create_thehive_case(_alert())
    assert ok is False
    assert "THEHIVE_API_KEY" in reason


def test_mapped_malicious_allowed_dry_run_without_api_key(monkeypatch):
    monkeypatch.setenv("REQUIRE_MAPPED_FOR_THEHIVE", "true")
    monkeypatch.delenv("THEHIVE_API_KEY", raising=False)
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "true")
    ok, reason = should_create_thehive_case(_alert())
    assert ok is True
    assert reason == ""

    # Default policy (REQUIRE_STRICT_MAPPED=true): both `unmapped` and
    # `unmapped_heuristic` are dropped at the gate; only `mapped` survives.
    monkeypatch.delenv("REQUIRE_STRICT_MAPPED", raising=False)
    for status in ("unmapped", "unmapped_heuristic"):
        ok, reason = should_create_thehive_case(
            _alert(mapping_status=status, n_ttps_matched=1)
        )
        assert ok is False, f"expected strict gate to drop status={status}"
        assert status in reason

    # When REQUIRE_STRICT_MAPPED=false is set explicitly, the same fallback
    # statuses are accepted so analysts can triage them via the
    # MITRE_UNMAPPED / MITRE_UNMAPPED_HEURISTIC tag.
    monkeypatch.setenv("REQUIRE_STRICT_MAPPED", "false")
    for status in ("unmapped", "unmapped_heuristic"):
        ok, reason = should_create_thehive_case(
            _alert(mapping_status=status, n_ttps_matched=1)
        )
        assert ok is True, f"expected relaxed gate to accept status={status}"
        assert reason == ""


def test_benign_skipped(monkeypatch):
    monkeypatch.setenv("REQUIRE_MAPPED_FOR_THEHIVE", "true")
    ok, reason = should_create_thehive_case(
        _alert(pred_label=0, mapping_status="mapped")
    )
    assert ok is False
    assert "Benign" in reason


def test_mapped_without_ttps_skipped(monkeypatch):
    monkeypatch.setenv("REQUIRE_MAPPED_FOR_THEHIVE", "true")
    ok, reason = should_create_thehive_case(_alert(n_ttps_matched=0))
    assert ok is False
    assert "No MITRE" in reason
