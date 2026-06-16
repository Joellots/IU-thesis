"""Tests for the §5 Decision Matrix — every cell, plus the two hard invariants:
isolate is never auto, and block is never auto outside the single
High+confirmed-IOC cell."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from decision_matrix import decide_actions  # noqa: E402

IP_OBS = {"type": "ip", "value": "203.0.113.7", "role": "dst"}
IP_OBS_CONFIRMED = {**IP_OBS, "intel_malicious": True}
DOMAIN_OBS = {"type": "domain", "value": "bad.example", "role": "dst"}
JA3_OBS = {"type": "ja3", "value": "e7d705a3286e19ea42f587b344ee6865"}
ENDPOINT = {"host_id": "agent-014", "ip": "10.0.0.14", "source": "wazuh"}


def _types(actions):
    return [a["type"] for a in actions]


# ── High + Malicious IOC confirmed → auto-block + notify ──────────────────

def test_high_confirmed_ioc_auto_blocks_and_notifies():
    actions = decide_actions(severity="High", intel_malicious=True, observables=[IP_OBS_CONFIRMED])
    assert _types(actions) == ["block", "notify"]
    block = actions[0]
    assert block["requires_approval"] is False
    assert block["targets"] == [{"type": "ip", "value": "203.0.113.7"}]
    assert actions[1]["requires_approval"] is False


def test_high_confirmed_ioc_only_blocks_confirmed_observables():
    """An unconfirmed observable riding along with a confirmed one must not
    be swept into the ungated auto-block."""
    actions = decide_actions(
        severity="High", intel_malicious=True, observables=[IP_OBS_CONFIRMED, DOMAIN_OBS]
    )
    block = next(a for a in actions if a["type"] == "block")
    assert block["targets"] == [{"type": "ip", "value": "203.0.113.7"}]


def test_high_confirmed_ioc_with_no_blockable_observables_only_notifies():
    actions = decide_actions(severity="High", intel_malicious=True, observables=[JA3_OBS])
    assert _types(actions) == ["notify"]


# ── High + No IOC confirmation → gated block proposal + notify ────────────

def test_high_no_confirmation_proposes_gated_block():
    actions = decide_actions(severity="High", intel_malicious=False, observables=[IP_OBS, DOMAIN_OBS])
    assert _types(actions) == ["block", "notify"]
    block = actions[0]
    assert block["requires_approval"] is True
    assert {"type": "ip", "value": "203.0.113.7"} in block["targets"]
    assert {"type": "domain", "value": "bad.example"} in block["targets"]


def test_high_no_confirmation_no_observables_only_notifies():
    actions = decide_actions(severity="High", intel_malicious=False, observables=[])
    assert _types(actions) == ["notify"]


# ── High + Endpoint risk flagged (Wazuh) → gated isolate + notify ─────────

def test_high_endpoint_risk_proposes_gated_isolate():
    actions = decide_actions(
        severity="High", intel_malicious=False, endpoint_risk=True, endpoint=ENDPOINT
    )
    assert _types(actions) == ["isolate", "notify"]
    isolate = actions[0]
    assert isolate["requires_approval"] is True
    assert isolate["target"] == ENDPOINT


def test_high_endpoint_risk_without_endpoint_payload_is_ignored():
    """endpoint_risk=True with no endpoint details can't be actioned — falls
    back to whatever the IOC branch decides, never a bare isolate with no target."""
    actions = decide_actions(severity="High", intel_malicious=False, endpoint_risk=True, endpoint=None)
    assert "isolate" not in _types(actions)


def test_high_confirmed_ioc_and_endpoint_risk_both_present():
    """Confirmed IOC and endpoint risk aren't mutually exclusive — both a
    block and a gated isolate can be proposed together; isolate stays gated."""
    actions = decide_actions(
        severity="High",
        intel_malicious=True,
        observables=[IP_OBS_CONFIRMED],
        endpoint_risk=True,
        endpoint=ENDPOINT,
    )
    assert _types(actions) == ["block", "isolate", "notify"]
    assert actions[0]["requires_approval"] is False
    assert actions[1]["requires_approval"] is True


# ── Medium → notify only, no automated block ───────────────────────────────

def test_medium_any_verdict_notifies_only():
    for intel_malicious in (True, False):
        actions = decide_actions(
            severity="Medium",
            intel_malicious=intel_malicious,
            observables=[IP_OBS_CONFIRMED],
            endpoint_risk=True,
            endpoint=ENDPOINT,
        )
        assert _types(actions) == ["notify"]
        assert actions[0]["requires_approval"] is False


# ── Low → notify only, no case (handled upstream), no response action ─────

def test_low_notifies_only():
    actions = decide_actions(severity="Low", intel_malicious=True, observables=[IP_OBS_CONFIRMED])
    assert _types(actions) == ["notify"]


# ── Hard invariants, exhaustively ──────────────────────────────────────────

def test_isolate_is_never_unapproved_across_all_combinations():
    for severity in ("High", "Medium", "Low"):
        for intel_malicious in (True, False):
            for endpoint_risk in (True, False):
                actions = decide_actions(
                    severity=severity,
                    intel_malicious=intel_malicious,
                    observables=[IP_OBS_CONFIRMED, DOMAIN_OBS],
                    endpoint_risk=endpoint_risk,
                    endpoint=ENDPOINT,
                )
                for a in actions:
                    if a["type"] == "isolate":
                        assert a["requires_approval"] is True, (severity, intel_malicious, endpoint_risk)


def test_block_is_only_ever_unapproved_in_the_high_confirmed_ioc_cell():
    for severity in ("High", "Medium", "Low"):
        for intel_malicious in (True, False):
            actions = decide_actions(
                severity=severity,
                intel_malicious=intel_malicious,
                observables=[IP_OBS_CONFIRMED, DOMAIN_OBS],
            )
            for a in actions:
                if a["type"] == "block" and a["requires_approval"] is False:
                    assert severity == "High" and intel_malicious is True, (severity, intel_malicious)


def test_notify_is_always_ungated():
    for severity in ("High", "Medium", "Low"):
        for intel_malicious in (True, False):
            actions = decide_actions(severity=severity, intel_malicious=intel_malicious)
            notify = next(a for a in actions if a["type"] == "notify")
            assert notify["requires_approval"] is False
