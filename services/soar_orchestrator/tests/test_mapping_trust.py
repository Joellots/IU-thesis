"""Tests for the mapping-confidence trust gate (adjustment #3)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mapping_trust import is_ttp_tentative  # noqa: E402


def test_mapped_high_confidence_not_tentative():
    assert is_ttp_tentative("mapped", 0.99) is False


def test_mapped_low_confidence_is_tentative():
    assert is_ttp_tentative("mapped", 0.40) is True


def test_unmapped_heuristic_always_tentative_regardless_of_confidence():
    assert is_ttp_tentative("unmapped_heuristic", 0.99) is True


def test_unmapped_always_tentative():
    assert is_ttp_tentative("unmapped", 0.0) is True


def test_threshold_is_configurable(monkeypatch):
    monkeypatch.setenv("MAPPING_TRUST_MIN_CONFIDENCE", "0.95")
    assert is_ttp_tentative("mapped", 0.90) is True
    monkeypatch.setenv("MAPPING_TRUST_MIN_CONFIDENCE", "0.50")
    assert is_ttp_tentative("mapped", 0.60) is False
