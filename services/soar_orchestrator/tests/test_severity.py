"""Tests for severity recompute (SOAR_WORKFLOW_SPEC.md Step 2)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from severity import compute_severity, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW  # noqa: E402


def test_high_at_and_above_threshold():
    assert compute_severity(0.90) == SEVERITY_HIGH
    assert compute_severity(0.94) == SEVERITY_HIGH
    assert compute_severity(1.0) == SEVERITY_HIGH


def test_medium_band():
    assert compute_severity(0.70) == SEVERITY_MEDIUM
    assert compute_severity(0.89) == SEVERITY_MEDIUM


def test_just_below_high_is_medium_not_high():
    assert compute_severity(0.8999) == SEVERITY_MEDIUM


def test_low_below_medium_threshold():
    assert compute_severity(0.6999) == SEVERITY_LOW
    assert compute_severity(0.0) == SEVERITY_LOW


def test_none_or_missing_defaults_to_low():
    assert compute_severity(None) == SEVERITY_LOW
