"""Tests for automated TheHive case actions."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from case_automation import (  # noqa: E402
    normalize_pattern_ids,
    should_run_responders,
)


def test_normalize_pattern_ids_dedupes():
    assert normalize_pattern_ids(["T1071", "T1071.001", "T1071"]) == [
        "T1071",
        "T1071.001",
    ]


def test_should_run_responders_when_auto_enabled(monkeypatch):
    monkeypatch.setenv("AUTO_RUN_RESPONDERS", "true")
    assert should_run_responders({"pred_label": 1, "severity_label": "LOW"}) is True


def test_should_run_responders_legacy_severity_gate(monkeypatch):
    monkeypatch.setenv("AUTO_RUN_RESPONDERS", "false")
    monkeypatch.setenv("RUN_RESPONDERS_ON_ALL", "false")
    monkeypatch.setenv("FORCE_ACTIVE_RESPONSE", "false")
    assert should_run_responders({"pred_label": 1, "severity_label": "LOW"}) is False
    assert should_run_responders({"pred_label": 1, "severity_label": "HIGH"}) is True
