"""Tests for the Slack notify client. No real network — urlopen is stubbed."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import notify_client  # noqa: E402


def _kwargs(**overrides):
    base = dict(
        flow_id="3d7e219e-aaaa",
        severity="High",
        pred_proba=0.94,
        mitre_ttps=["T1071", "T1071.001"],
        intel_malicious=True,
        intel_score=0.5,
        actions=[
            {"type": "block", "requires_approval": True},
            {"type": "notify", "requires_approval": False},
        ],
        thehive_case_url="http://thehive/cases/~1/details",
        annotation="C2 beaconing over TLS",
    )
    base.update(overrides)
    return base


def test_build_message_shape():
    msg = notify_client.build_slack_message(**_kwargs())
    assert "text" in msg and msg["blocks"]
    assert msg["blocks"][0]["type"] == "header"
    # case link block present when url given
    assert any("open case" in str(b) for b in msg["blocks"])
    assert "block (approval required)" in str(msg["blocks"])


def test_dry_run_skips(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "true")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    assert notify_client.send_slack_notification(**_kwargs()) == {"dry_run": True}


def test_missing_webhook_skips(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    result = notify_client.send_slack_notification(**_kwargs())
    assert "skipped" in result and "SLACK_WEBHOOK_URL" in result["skipped"]


def test_disabled_skips(monkeypatch):
    monkeypatch.setenv("SLACK_NOTIFY_ENABLED", "false")
    assert notify_client.send_slack_notification(**_kwargs()) == {"skipped": "SLACK_NOTIFY_ENABLED=false"}


def test_min_severity_filter(monkeypatch):
    monkeypatch.delenv("SLACK_NOTIFY_ENABLED", raising=False)
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    monkeypatch.setenv("SLACK_NOTIFY_MIN_SEVERITY", "high")
    res = notify_client.send_slack_notification(**_kwargs(severity="Medium"))
    assert "skipped" in res and "below" in res["skipped"]


def test_send_success(monkeypatch):
    monkeypatch.delenv("SLACK_NOTIFY_ENABLED", raising=False)
    monkeypatch.delenv("SLACK_NOTIFY_MIN_SEVERITY", raising=False)
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")

    posted = {}

    class _Resp:
        status = 200

        def read(self):
            return b"ok"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=10):
        posted["url"] = req.full_url
        posted["body"] = req.data.decode()
        return _Resp()

    monkeypatch.setattr(notify_client.urllib.request, "urlopen", _fake_urlopen)
    res = notify_client.send_slack_notification(**_kwargs())
    assert res == {"status": "sent", "http_status": 200, "ok": True}
    assert "hooks.slack.com" in posted["url"]
    assert "blocks" in posted["body"]


def test_send_failure_is_soft(monkeypatch):
    monkeypatch.delenv("SLACK_NOTIFY_ENABLED", raising=False)
    monkeypatch.delenv("SLACK_NOTIFY_MIN_SEVERITY", raising=False)
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")

    def _boom(req, timeout=10):
        raise OSError("connection refused")

    monkeypatch.setattr(notify_client.urllib.request, "urlopen", _boom)
    res = notify_client.send_slack_notification(**_kwargs())
    assert "error" in res
