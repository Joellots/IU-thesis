"""Tests for the /soar/shuffle-result and /soar/feedback HTTP routes.

The DB layer is stubbed out (no real Postgres) — these only verify request
validation, response shape, and that the right db.* function gets called
with the right arguments.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import api_server  # noqa: E402


class _FakeConn:
    def __init__(self):
        self.committed = False
        self.closed = False

    def cursor(self):
        return _FakeCursor()

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


class _FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _client(monkeypatch):
    monkeypatch.setattr(api_server, "get_db", lambda: _FakeConn())
    monkeypatch.setattr(api_server, "ensure_shuffle_results_table", lambda cur: None)
    monkeypatch.setattr(api_server, "ensure_feedback_table", lambda cur: None)
    return api_server.app.test_client()


# ── /soar/shuffle-result ───────────────────────────────────────────────────

def test_shuffle_result_records_on_valid_payload(monkeypatch):
    client = _client(monkeypatch)
    calls = {}
    monkeypatch.setattr(
        api_server,
        "record_shuffle_result",
        lambda conn, *, flow_id, thehive_case_id, results: calls.update(
            flow_id=flow_id, thehive_case_id=thehive_case_id, results=results
        ),
    )
    resp = client.post(
        "/soar/shuffle-result",
        json={
            "flow_id": "flow-1",
            "thehive_case_id": "~123",
            "results": [{"type": "block", "outcome": "executed"}],
        },
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "recorded"}
    assert calls["flow_id"] == "flow-1"
    assert calls["thehive_case_id"] == "~123"
    assert calls["results"] == [{"type": "block", "outcome": "executed"}]


def test_shuffle_result_requires_flow_id(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/soar/shuffle-result", json={"results": []})
    assert resp.status_code == 400
    assert "flow_id" in resp.get_json()["error"]


def test_shuffle_result_requires_results_list(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/soar/shuffle-result", json={"flow_id": "flow-1", "results": "not-a-list"})
    assert resp.status_code == 400
    assert "results" in resp.get_json()["error"]


def test_shuffle_result_db_failure_returns_500(monkeypatch):
    client = _client(monkeypatch)

    def _boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(api_server, "record_shuffle_result", _boom)
    resp = client.post("/soar/shuffle-result", json={"flow_id": "flow-1", "results": []})
    assert resp.status_code == 500


# ── /soar/feedback ──────────────────────────────────────────────────────────

def test_feedback_records_on_valid_payload(monkeypatch):
    client = _client(monkeypatch)
    calls = {}
    monkeypatch.setattr(
        api_server,
        "record_feedback",
        lambda conn, **kwargs: calls.update(kwargs),
    )
    resp = client.post(
        "/soar/feedback",
        json={
            "flow_id": "flow-1",
            "alert_id": 42,
            "true_positive": True,
            "explanation_useful": True,
            "flag_for_retraining": False,
            "note": "confirmed C2",
        },
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "recorded"}
    assert calls == {
        "flow_id": "flow-1",
        "alert_id": 42,
        "true_positive": True,
        "explanation_useful": True,
        "flag_for_retraining": False,
        "note": "confirmed C2",
    }


def test_feedback_requires_flow_id(monkeypatch):
    client = _client(monkeypatch)
    resp = client.post("/soar/feedback", json={"true_positive": True})
    assert resp.status_code == 400
    assert "flow_id" in resp.get_json()["error"]


def test_feedback_minimal_payload_defaults_optional_fields_to_none(monkeypatch):
    client = _client(monkeypatch)
    calls = {}
    monkeypatch.setattr(
        api_server,
        "record_feedback",
        lambda conn, **kwargs: calls.update(kwargs),
    )
    resp = client.post("/soar/feedback", json={"flow_id": "flow-2"})
    assert resp.status_code == 200
    assert calls["flow_id"] == "flow-2"
    assert calls["alert_id"] is None
    assert calls["true_positive"] is None
