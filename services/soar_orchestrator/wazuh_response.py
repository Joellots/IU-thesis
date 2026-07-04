"""On-demand Wazuh Active-Response dispatcher — endpoint-routed enforcement.

The SOAR engine commands a vetted AR script on a specific Wazuh agent via the
manager's REST API, on demand — no Wazuh rule or triggering log is involved:

    POST {WAZUH_API_URL}/security/user/authenticate   (basic auth -> JWT)
    PUT  {WAZUH_API_URL}/active-response?agents_list=<agent_id>
         {"command": "soar-block0", "arguments": ["<malicious_ip>"]}   # AR name (see wrappers)

The manager relays it to the agent, which runs the pre-registered local script
(soar-block / soar-unblock / soar-isolate / soar-unisolate). The agent-side
scripts validate the target, refuse RFC1918/own-infra, log, and auto-expire.

Contract / guards honoured:
  - `agent_id` may be absent (replay/in-stack flows, or before enrollment) — the
    dispatcher SKIPS endpoint AR with no agent to route to; the caller falls back
    to notify/case only.
  - The block argument is the malicious DST IP (from observables), NOT host_ip
    (the sensor's own address).
  - Fail-soft: never raises into alert processing. Dry-run aware.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import requests

try:  # self-signed manager cert in the lab; silence the verify-off warning
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
except Exception:
    pass

from slog import get_logger, log_event

log = get_logger(__name__)

# JWT is valid ~15 min; cache and refresh with a safety margin.
_TOKEN_TTL_SEC = 900
_token_cache: Dict[str, Any] = {"token": None, "exp": 0.0}


def wazuh_api_url() -> str:
    return os.getenv("WAZUH_API_URL", "https://host.docker.internal:55000").rstrip("/")


def _api_user() -> str:
    return os.getenv("WAZUH_API_USER", "wazuh-wui")


def _api_password() -> str:
    return (os.getenv("WAZUH_API_PASSWORD") or "").strip()


def _verify_tls() -> bool:
    return os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true"


def _ar_enabled() -> bool:
    return os.getenv("WAZUH_AR_ENABLED", "true").lower() == "true"


def _command_prefix() -> str:
    # Use the REGISTERED command name as-is (e.g. "soar-block") — verified live
    # against an enrolled agent. A leading "!" means "run a script by name,
    # bypassing the registered command", which the manager accepts (HTTP 200) but
    # never relays to the agent. So the default prefix is empty. Override only if
    # a deployment deliberately registers commands under a different convention.
    return os.getenv("WAZUH_AR_COMMAND_PREFIX", "")


def _dry_run() -> bool:
    return os.getenv("ORCHESTRATOR_DRY_RUN", "true").lower() == "true"


def _authenticate(timeout: int = 10) -> str:
    now = time.time()
    cached = _token_cache.get("token")
    if cached and _token_cache.get("exp", 0.0) > now + 30:
        return cached
    url = f"{wazuh_api_url()}/security/user/authenticate?raw=true"
    resp = requests.post(url, auth=(_api_user(), _api_password()), verify=_verify_tls(), timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(f"Wazuh auth failed {resp.status_code}: {resp.text[:200]}")
    token = resp.text.strip()
    if not token:
        raise RuntimeError("Wazuh auth returned an empty token")
    _token_cache["token"] = token
    _token_cache["exp"] = now + _TOKEN_TTL_SEC
    return token


def run_active_response(
    *,
    agent_id: Optional[str],
    command: str,
    arguments: Optional[List[str]] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Dispatch one AR command to one agent. Never raises. Returns a status dict:
    {"skipped": ...} | {"dry_run": True} | {"status": "dispatched"/"failed", ...} | {"error": ...}."""
    if not _ar_enabled():
        return {"skipped": "WAZUH_AR_ENABLED=false"}
    agent_id = str(agent_id or "").strip() or None
    if not agent_id:
        return {"skipped": "no agent_id — no managed endpoint to route to"}

    cmd = command if command.startswith(_command_prefix()) else f"{_command_prefix()}{command}"

    if _dry_run() or not _api_password():
        reason = "dry_run" if _dry_run() else "WAZUH_API_PASSWORD not set"
        log_event("wazuh_ar_skipped", agent_id=agent_id, command=cmd, reason=reason,
                  arguments=list(arguments or []))
        return {"dry_run": True} if _dry_run() else {"skipped": reason}

    try:
        token = _authenticate()
        url = f"{wazuh_api_url()}/active-response?agents_list={agent_id}"
        body: Dict[str, Any] = {"command": cmd}
        if arguments:
            body["arguments"] = list(arguments)
        resp = requests.put(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
            verify=_verify_tls(),
            timeout=timeout,
        )
        ok = resp.status_code in (200, 201)
        data = resp.json() if resp.text else {}
        block = (data.get("data") or {}) if isinstance(data, dict) else {}
        affected = block.get("affected_items") or []
        api_error = block.get("failed_items") or None
        # HTTP 200 alone is NOT success: the manager returns 200 with
        # affected_items=[] ("AR command was not sent to any agent") when the
        # command name doesn't match a registered active-response. Only count it
        # dispatched when the agent is in affected_items.
        sent = ok and bool(affected) and not api_error
        log_event("wazuh_ar_dispatched", agent_id=agent_id, command=cmd,
                  arguments=list(arguments or []), http_status=resp.status_code,
                  affected=affected, ok=sent)
        return {
            "status": "dispatched" if sent else "failed",
            "http_status": resp.status_code,
            "command": cmd,
            "agent_id": agent_id,
            "affected": affected,
            "message": data.get("message") if isinstance(data, dict) else None,
            "api_error": api_error,
        }
    except Exception as exc:  # network/manager failure must not break processing
        log.warning(
            "wazuh_ar_failed",
            extra={"event": "wazuh_ar_failed", "agent_id": agent_id, "command": cmd, "error": str(exc)},
        )
        return {"error": str(exc)}


# Convenience wrappers. The command we send is the Wazuh ACTIVE-RESPONSE NAME,
# which is the registered <command> name + the timeout suffix Wazuh appends
# ("0" for a no-timeout AR) — i.e. `soar-block0`, as it appears in the agent's
# merged.mg. Verified live against an enrolled agent: `soar-block` → 1652
# "command not defined"; `!soar-block` → accepted but never relayed;
# `soar-block0` → "sent to agent". The "0" suffix follows from registering the
# commands with <timeout_allowed>no</timeout_allowed> in the manager ossec.conf.
def block(agent_id: Optional[str], ip: str) -> Dict[str, Any]:
    return run_active_response(agent_id=agent_id, command="soar-block0", arguments=[ip])


def unblock(agent_id: Optional[str], ip: str) -> Dict[str, Any]:
    return run_active_response(agent_id=agent_id, command="soar-unblock0", arguments=[ip])


def isolate(agent_id: Optional[str]) -> Dict[str, Any]:
    return run_active_response(agent_id=agent_id, command="soar-isolate0")


def unisolate(agent_id: Optional[str]) -> Dict[str, Any]:
    return run_active_response(agent_id=agent_id, command="soar-unisolate0")


def dispatch_endpoint_actions(
    *, agent_id: Optional[str], actions: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Execute the endpoint-routable part of the decision NOW: only the
    auto-block cell (block with requires_approval=False). Gated block and
    isolate are left for the post-approval path — they are NOT dispatched here.

    Returns a per-target result list for the bookkeeping record. Empty when
    there is no managed endpoint (agent_id absent).
    """
    results: List[Dict[str, Any]] = []
    agent_id = str(agent_id or "").strip() or None
    if not agent_id:
        return results
    for action in actions or []:
        if action.get("type") != "block" or action.get("requires_approval"):
            continue  # gated block / isolate await the approval loop
        for target in action.get("targets") or []:
            if str(target.get("type")) == "ip" and target.get("value"):
                res = block(agent_id, str(target["value"]))
                results.append({"type": "block", "target": target["value"], "result": res})
    return results
