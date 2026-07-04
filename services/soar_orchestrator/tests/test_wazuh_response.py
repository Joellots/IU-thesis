"""Tests for the Wazuh on-demand Active-Response dispatcher. No real network —
requests is stubbed; auth/PUT are asserted by shape."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wazuh_response  # noqa: E402


def _reset_token():
    wazuh_response._token_cache["token"] = None
    wazuh_response._token_cache["exp"] = 0.0


def test_skip_when_no_agent(monkeypatch):
    monkeypatch.setenv("WAZUH_AR_ENABLED", "true")
    assert "skipped" in wazuh_response.block(None, "1.2.3.4")
    assert "skipped" in wazuh_response.run_active_response(agent_id="", command="soar-block", arguments=["1.2.3.4"])


def test_disabled(monkeypatch):
    monkeypatch.setenv("WAZUH_AR_ENABLED", "false")
    assert wazuh_response.block("014", "1.2.3.4") == {"skipped": "WAZUH_AR_ENABLED=false"}


def test_dry_run(monkeypatch):
    monkeypatch.setenv("WAZUH_AR_ENABLED", "true")
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "true")
    assert wazuh_response.block("014", "1.2.3.4") == {"dry_run": True}


def test_missing_password(monkeypatch):
    monkeypatch.setenv("WAZUH_AR_ENABLED", "true")
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.delenv("WAZUH_API_PASSWORD", raising=False)
    res = wazuh_response.block("014", "1.2.3.4")
    assert "skipped" in res and "WAZUH_API_PASSWORD" in res["skipped"]


def _live_env(monkeypatch):
    monkeypatch.setenv("WAZUH_AR_ENABLED", "true")
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "pw")
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh:55000")
    monkeypatch.delenv("WAZUH_AR_COMMAND_PREFIX", raising=False)
    _reset_token()


class _Resp:
    def __init__(self, status, text="", js=None):
        self.status_code = status
        self.text = text
        self._js = js if js is not None else {}

    def json(self):
        return self._js


def test_block_builds_correct_request(monkeypatch):
    _live_env(monkeypatch)
    calls = {}

    def _post(url, auth=None, verify=None, timeout=None):
        calls["auth_url"] = url
        calls["auth"] = auth
        return _Resp(200, text="JWTTOKEN123456")

    def _put(url, headers=None, json=None, verify=None, timeout=None):
        calls["put_url"] = url
        calls["headers"] = headers
        calls["body"] = json
        return _Resp(200, text="{}", js={"data": {"affected_items": ["014"], "failed_items": []}})

    monkeypatch.setattr(wazuh_response.requests, "post", _post)
    monkeypatch.setattr(wazuh_response.requests, "put", _put)

    res = wazuh_response.block("014", "203.0.113.7")
    assert res["status"] == "dispatched"
    assert calls["auth"] == ("wazuh-wui", "pw")
    assert calls["put_url"].endswith("/active-response?agents_list=014")
    # Registered command name, NO "!" prefix (verified live: "!" doesn't relay).
    assert calls["body"] == {"command": "soar-block0", "arguments": ["203.0.113.7"]}
    assert calls["headers"]["Authorization"] == "Bearer JWTTOKEN123456"


def test_isolate_has_no_arguments(monkeypatch):
    _live_env(monkeypatch)
    captured = {}
    monkeypatch.setattr(wazuh_response.requests, "post", lambda *a, **k: _Resp(200, text="TOK"))
    monkeypatch.setattr(wazuh_response.requests, "put",
                        lambda url, **k: captured.update(body=k.get("json")) or _Resp(200, text="{}", js={}))
    wazuh_response.isolate("014")
    assert captured["body"] == {"command": "soar-isolate0"}


def test_api_failed_items_marks_failed(monkeypatch):
    _live_env(monkeypatch)
    monkeypatch.setattr(wazuh_response.requests, "post", lambda *a, **k: _Resp(200, text="TOK"))
    monkeypatch.setattr(wazuh_response.requests, "put",
                        lambda url, **k: _Resp(200, text="{}", js={"data": {"failed_items": [{"error": "x"}]}}))
    res = wazuh_response.block("014", "1.2.3.4")
    assert res["status"] == "failed"


def test_dispatch_endpoint_actions_only_auto_block(monkeypatch):
    _live_env(monkeypatch)
    sent = []
    monkeypatch.setattr(wazuh_response.requests, "post", lambda *a, **k: _Resp(200, text="TOK"))
    monkeypatch.setattr(wazuh_response.requests, "put",
                        lambda url, **k: sent.append(k.get("json")) or _Resp(200, text="{}", js={}))
    actions = [
        {"type": "block", "requires_approval": False, "targets": [{"type": "ip", "value": "203.0.113.7"}]},
        {"type": "isolate", "requires_approval": True, "target": {"host_id": "h"}},
        {"type": "notify", "requires_approval": False},
    ]
    results = wazuh_response.dispatch_endpoint_actions(agent_id="014", actions=actions)
    # only the non-gated block fired; isolate/notify did not
    assert len(results) == 1 and results[0]["target"] == "203.0.113.7"
    assert sent == [{"command": "soar-block0", "arguments": ["203.0.113.7"]}]


def test_dispatch_skips_without_agent(monkeypatch):
    _live_env(monkeypatch)
    actions = [{"type": "block", "requires_approval": False, "targets": [{"type": "ip", "value": "1.2.3.4"}]}]
    assert wazuh_response.dispatch_endpoint_actions(agent_id=None, actions=actions) == []
