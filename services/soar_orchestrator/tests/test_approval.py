"""Tests for the dashboard approval loop: POST /soar/approve + GET
/soar/pending-approvals. DB + Wazuh are stubbed — we assert auth, validation,
idempotent claim handling, and that approve executes the real AR call."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import api_server  # noqa: E402

TOKEN = "test-token-123"


class _FakeConn:
    def cursor(self):
        return _FakeCursor()

    def commit(self):
        pass

    def close(self):
        pass


class _FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _client(monkeypatch, *, pending_row=None, claim_row=None):
    monkeypatch.setenv("SOAR_APPROVAL_TOKEN", TOKEN)
    monkeypatch.setattr(api_server, "get_db", lambda: _FakeConn())
    monkeypatch.setattr(api_server, "ensure_pending_approvals_table", lambda cur: None)
    monkeypatch.setattr(api_server, "get_pending_approval", lambda conn, aid: pending_row)
    monkeypatch.setattr(api_server, "claim_pending_approval", lambda conn, aid: claim_row)
    finalized = {}
    monkeypatch.setattr(api_server, "finalize_pending_approval",
                        lambda conn, aid, **kw: finalized.update(id=aid, **kw))
    monkeypatch.setattr(api_server, "list_pending_approvals", lambda conn, **kw: [pending_row] if pending_row else [])
    api_server._finalized = finalized  # type: ignore[attr-defined]
    return api_server.app.test_client()


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def test_approve_requires_token(monkeypatch):
    client = _client(monkeypatch, pending_row={"id": 1})
    resp = client.post("/soar/approve", json={"approval_id": 1, "decision": "approve"})  # no token
    assert resp.status_code == 401


def test_approve_validates_body(monkeypatch):
    client = _client(monkeypatch)
    assert client.post("/soar/approve", headers=_auth(), json={"decision": "approve"}).status_code == 400
    assert client.post("/soar/approve", headers=_auth(), json={"approval_id": 1, "decision": "maybe"}).status_code == 400


def test_approve_not_found(monkeypatch):
    client = _client(monkeypatch, pending_row=None)
    resp = client.post("/soar/approve", headers=_auth(), json={"approval_id": 9, "decision": "approve"})
    assert resp.status_code == 404


def test_approve_not_pending_conflict(monkeypatch):
    # exists, but claim fails (already decided/expired)
    client = _client(monkeypatch, pending_row={"id": 1, "status": "executed"}, claim_row=None)
    resp = client.post("/soar/approve", headers=_auth(), json={"approval_id": 1, "decision": "approve"})
    assert resp.status_code == 409


def test_approve_block_executes_wazuh(monkeypatch):
    row = {"id": 5, "flow_id": "f", "agent_id": "014", "action_type": "block", "target_value": "203.0.113.7"}
    client = _client(monkeypatch, pending_row=row, claim_row=row)
    calls = {}
    monkeypatch.setattr(api_server.wazuh_response, "block",
                        lambda agent_id, ip: calls.update(agent_id=agent_id, ip=ip) or {"status": "dispatched"})
    resp = client.post("/soar/approve", headers=_auth(), json={"approval_id": 5, "decision": "approve", "analyst": "joel"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "executed"
    assert calls == {"agent_id": "014", "ip": "203.0.113.7"}
    assert api_server._finalized["status"] == "executed"
    assert api_server._finalized["analyst"] == "joel"


def test_approve_isolate_executes_wazuh(monkeypatch):
    row = {"id": 6, "flow_id": "f", "agent_id": "014", "action_type": "isolate", "target_value": None}
    client = _client(monkeypatch, pending_row=row, claim_row=row)
    calls = {}
    monkeypatch.setattr(api_server.wazuh_response, "isolate",
                        lambda agent_id: calls.update(agent_id=agent_id) or {"status": "dispatched"})
    resp = client.post("/soar/approve", headers=_auth(), json={"approval_id": 6, "decision": "approve"})
    assert resp.status_code == 200 and resp.get_json()["status"] == "executed"
    assert calls == {"agent_id": "014"}


def test_approve_failed_ar_marks_failed(monkeypatch):
    row = {"id": 7, "flow_id": "f", "agent_id": "014", "action_type": "block", "target_value": "1.2.3.4"}
    client = _client(monkeypatch, pending_row=row, claim_row=row)
    monkeypatch.setattr(api_server.wazuh_response, "block", lambda agent_id, ip: {"error": "boom"})
    resp = client.post("/soar/approve", headers=_auth(), json={"approval_id": 7, "decision": "approve"})
    assert resp.get_json()["status"] == "failed"


def test_reject_logs_no_enforcement(monkeypatch):
    row = {"id": 8, "flow_id": "f", "agent_id": "014", "action_type": "block", "target_value": "1.2.3.4"}
    client = _client(monkeypatch, pending_row=row, claim_row=row)
    fired = {"block": False}
    monkeypatch.setattr(api_server.wazuh_response, "block", lambda *a, **k: fired.update(block=True))
    resp = client.post("/soar/approve", headers=_auth(), json={"approval_id": 8, "decision": "reject", "note": "FP"})
    assert resp.status_code == 200 and resp.get_json()["status"] == "rejected"
    assert fired["block"] is False
    assert api_server._finalized["status"] == "rejected"


def test_pending_approvals_listing(monkeypatch):
    client = _client(monkeypatch, pending_row={"id": 1, "action_type": "block", "flow_id": "f"})
    resp = client.get("/soar/pending-approvals", headers=_auth())
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 1 and body["pending"][0]["id"] == 1
