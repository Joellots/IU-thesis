"""Tests for automated TheHive case actions."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from case_automation import (  # noqa: E402
    annotate_observable_intel,
    derive_intel_verdict,
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


def _verdict(analyzer, verdict):
    return {"analyzer_name": analyzer, "observable_value": "x", "observable_type": "ip", "verdict": verdict, "taxonomies": ""}


def test_intel_malicious_requires_a_confirmation_analyzer(monkeypatch):
    monkeypatch.delenv("INTEL_CONFIRMATION_ANALYZERS", raising=False)
    # A non-trusted analyzer flagging "malicious" is not enough on its own.
    malicious, score = derive_intel_verdict([_verdict("Some_Heuristic_1_0", "malicious")])
    assert malicious is False
    assert score == 1.0  # still counts toward the softer intel_score signal


def test_intel_malicious_true_on_single_trusted_positive(monkeypatch):
    monkeypatch.delenv("INTEL_CONFIRMATION_ANALYZERS", raising=False)
    malicious, score = derive_intel_verdict(
        [_verdict("VirusTotal_GetReport_3_1", "malicious"), _verdict("Abuse_Finder_3_0", "safe")]
    )
    assert malicious is True
    assert score == 0.5


def test_intel_score_excludes_pending_and_error(monkeypatch):
    verdicts = [
        _verdict("MISP_2_1", "malicious"),
        _verdict("Abuse_Finder_3_0", "pending"),
        _verdict("DShield_lookup_1_0", "error"),
    ]
    malicious, score = derive_intel_verdict(verdicts)
    assert malicious is True
    assert score == 1.0  # 1 malicious / 1 resolved (pending+error excluded)


def test_intel_confirmation_analyzers_configurable(monkeypatch):
    monkeypatch.setenv("INTEL_CONFIRMATION_ANALYZERS", "Custom_Analyzer_1_0")
    malicious, _ = derive_intel_verdict([_verdict("VirusTotal_GetReport_3_1", "malicious")])
    assert malicious is False  # not in the overridden allowlist
    malicious, _ = derive_intel_verdict([_verdict("Custom_Analyzer_1_0", "malicious")])
    assert malicious is True


def test_no_verdicts_yields_no_intel():
    assert derive_intel_verdict([]) == (False, 0.0)


def test_annotate_observable_intel_flags_only_confirmed_matches(monkeypatch):
    monkeypatch.delenv("INTEL_CONFIRMATION_ANALYZERS", raising=False)
    observables = [
        {"type": "ip", "value": "203.0.113.7", "role": "dst"},
        {"type": "domain", "value": "bad.example", "role": "dst"},
    ]
    verdicts = [
        {"analyzer_name": "VirusTotal_GetReport_3_1", "observable_type": "ip", "observable_value": "203.0.113.7", "verdict": "malicious"},
        {"analyzer_name": "Some_Heuristic_1_0", "observable_type": "domain", "observable_value": "bad.example", "verdict": "malicious"},
    ]
    annotated = annotate_observable_intel(observables, verdicts)
    by_value = {o["value"]: o for o in annotated}
    assert by_value["203.0.113.7"]["intel_malicious"] is True
    assert "intel_malicious" not in by_value["bad.example"]  # non-trusted analyzer doesn't confirm
    # original list is untouched
    assert "intel_malicious" not in observables[0]
