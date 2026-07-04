"""Tests for the §7.1 orchestrator -> Shuffle handoff payload — the schema
is authoritative, so these assert the exact shape, not just "truthy"."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shuffle_client import build_handoff_payload, callback_url, post_to_shuffle  # noqa: E402


def _payload(**overrides):
    base = dict(
        flow_id="3d7e219e-aaaa",
        severity="High",
        model_confidence=0.94,
        mitre_ttps=["T1071", "T1071.001"],
        mapping_status="mapped",
        mapping_confidence=0.87,
        annotation="C2 beaconing over TLS",
        intel_malicious=True,
        intel_score=0.0,
        thehive_case_id="~12345",
        thehive_case_url="https://thehive/cases/~12345",
        observables=[
            {"type": "ip", "value": "203.0.113.7", "role": "dst", "intel_malicious": True},
            {"type": "domain", "value": "bad.example", "role": "dst"},
            {"type": "ja3", "value": "e7d705a3286e19ea42f587b344ee6865"},
        ],
        actions=[
            {"type": "block", "targets": [{"type": "ip", "value": "203.0.113.7"}], "requires_approval": False},
            {"type": "notify", "channels": ["slack", "dashboard"], "requires_approval": False},
        ],
    )
    base.update(overrides)
    return build_handoff_payload(**base)


def test_top_level_shape_matches_spec():
    payload = _payload()
    assert set(payload.keys()) == {
        "schema_version", "alert", "case", "observables", "actions", "callback_url",
        "block_present", "block_requires_approval", "isolate_present",
        "isolate_requires_approval", "notify_present",
    }
    assert payload["schema_version"] == "1.0"


def test_alert_block_shape_and_values():
    payload = _payload()
    alert = payload["alert"]
    assert alert["flow_id"] == "3d7e219e-aaaa"
    assert alert["severity"] == "High"
    assert alert["model_confidence"] == 0.94
    assert alert["mitre_ttps"] == ["T1071", "T1071.001"]
    assert alert["mapping_status"] == "mapped"
    assert alert["mapping_confidence"] == 0.87
    assert alert["annotation"] == "C2 beaconing over TLS"
    assert alert["intel"] == {"intel_malicious": True, "intel_score": 0.0}


def test_case_block_shape():
    payload = _payload()
    assert payload["case"] == {
        "thehive_case_id": "~12345",
        "thehive_case_url": "https://thehive/cases/~12345",
    }


def test_endpoint_omitted_when_not_provided():
    payload = _payload()
    assert "endpoint" not in payload


def test_endpoint_present_only_when_given():
    endpoint = {"host_id": "agent-014", "ip": "10.0.0.14", "source": "wazuh"}
    payload = _payload(endpoint=endpoint)
    assert payload["endpoint"] == endpoint


def test_callback_url_present_and_configurable(monkeypatch):
    monkeypatch.delenv("SOAR_CALLBACK_BASE_URL", raising=False)
    assert _payload()["callback_url"] == "http://soar_orchestrator:8200/soar/shuffle-result"
    monkeypatch.setenv("SOAR_CALLBACK_BASE_URL", "http://orchestrator:8200")
    assert callback_url() == "http://orchestrator:8200/soar/shuffle-result"


def test_actions_passed_through_verbatim():
    actions = [{"type": "isolate", "target": {"host_id": "agent-014"}, "requires_approval": True}]
    payload = _payload(actions=actions)
    assert payload["actions"] == actions


def test_block_hints_reflect_actions():
    payload = _payload(
        actions=[
            {"type": "block", "targets": [{"type": "ip", "value": "1.2.3.4"}], "requires_approval": False},
            {"type": "notify", "channels": ["slack", "dashboard"], "requires_approval": False},
        ]
    )
    assert payload["block_present"] is True
    assert payload["block_requires_approval"] is False
    assert payload["isolate_present"] is False
    assert payload["isolate_requires_approval"] is False
    assert payload["notify_present"] is True


def test_isolate_hint_reflects_gated_action():
    payload = _payload(
        actions=[
            {"type": "isolate", "target": {"host_id": "agent-014"}, "requires_approval": True},
            {"type": "notify", "channels": ["slack", "dashboard"], "requires_approval": False},
        ]
    )
    assert payload["isolate_present"] is True
    assert payload["isolate_requires_approval"] is True
    assert payload["block_present"] is False


def test_hints_all_false_when_no_actions():
    payload = _payload(actions=[])
    assert payload["block_present"] is False
    assert payload["isolate_present"] is False
    assert payload["notify_present"] is False


def test_post_to_shuffle_dry_run_default(monkeypatch):
    monkeypatch.delenv("ORCHESTRATOR_DRY_RUN", raising=False)
    result = post_to_shuffle(_payload())
    assert result == {"dry_run": True}


def test_post_to_shuffle_missing_config_when_live(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.delenv("SHUFFLE_API_KEY", raising=False)
    monkeypatch.delenv("SHUFFLE_WORKFLOW_ID", raising=False)
    result = post_to_shuffle(_payload())
    assert "error" in result
    assert "SHUFFLE_API_KEY" in result["error"]
