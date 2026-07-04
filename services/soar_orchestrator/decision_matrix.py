"""§5 Decision Matrix (SOAR_WORKFLOW_SPEC.md) — AUTHORITATIVE.

Pure function: severity + Cortex/MISP verdict + endpoint risk -> the
`actions` list for the §7.1 orchestrator -> Shuffle handoff payload.
TheHive case creation is handled elsewhere (orchestrator.py); this module
only decides block/isolate/notify and each action's `requires_approval`
gate — Shuffle re-runs no matrix logic of its own.

Invariants (do not relax without updating SOAR_WORKFLOW_SPEC.md first):
  - `isolate` is NEVER emitted with requires_approval=False.
  - `block` is only emitted with requires_approval=False in the single
    High + confirmed-IOC cell. `mapping_status`/`mapping_confidence` (the
    Step 4 trust gate) are NOT inputs here and can never unlock auto-block
    on their own — only a real Cortex/MISP `intel_malicious` confirmation
    can. A tentative TTP is surfaced in the case, never a basis for action.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from severity import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW  # noqa: F401
from slog import get_logger, log_event

log = get_logger(__name__)

BLOCKABLE_TYPES = ("ip", "domain")


def _is_routable_peer_ip(value: str, host_ip: Optional[str]) -> bool:
    """True when `value` is a globally routable IP that is not the monitored host.

    Excludes: the sensor's own address, loopback (127/8), RFC1918, link-local.
    Works for both outbound flows (host=src, C2=dst) and inbound (C2=src, host=dst).
    """
    if host_ip and value == host_ip:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global


def _block_targets(
    observables: List[Dict[str, Any]],
    *,
    only_confirmed: bool,
    host_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Derive the block target list from the flow's observables.

    When `only_confirmed=True` (auto-block cell, intel_malicious=True):
      The confirming IOC can be any type — domain, URL, JA3, or IP. We enforce
      via the flow's external peer IP because Wazuh AR can only act on IPs.
      Returns all IP observables that are globally routable and not the monitored
      host. Caller MUST handle the empty-list case (downgrade to notify; never
      emit a target-less block).

    When `only_confirmed=False` (gated block, analyst review):
      All BLOCKABLE_TYPES observables (IP + domain) for case context; only IP-
      typed entries will be enforced on approval.
    """
    if only_confirmed:
        # Proceed only when at least one observable carries a confirmed verdict,
        # regardless of which type that observable is (domain, JA3, IP, …).
        if not any(obs.get("intel_malicious") for obs in observables):
            return []
        targets = []
        for obs in observables:
            if obs.get("type") != "ip":
                continue
            value = str(obs.get("value") or "")
            if _is_routable_peer_ip(value, host_ip):
                targets.append({"type": "ip", "value": value})
        return targets

    # Gated path — all blockable observables (IP + domain) for analyst review.
    targets = []
    for obs in observables or []:
        if obs.get("type") not in BLOCKABLE_TYPES:
            continue
        targets.append({"type": obs["type"], "value": obs.get("value")})
    return targets


def decide_actions(
    *,
    severity: str,
    intel_malicious: bool,
    observables: Optional[List[Dict[str, Any]]] = None,
    endpoint_risk: bool = False,
    endpoint: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build the `actions` list for the §7.1 payload.

    `observables` should already carry per-observable `intel_malicious`
    flags (see case_automation.annotate_observable_intel) when available.

    For the auto-block cell (High + intel_malicious=True), the block target is
    the flow's external peer IP, not the IOC that confirmed the verdict —
    because Wazuh AR enforces on IPs only, and the confirming IOC may be a
    domain or JA3.  If no eligible peer IP exists, the block is suppressed and
    the alert degrades to notify-only (no target-less block is ever emitted).
    """
    observables = observables or []
    # Extract the monitored host's own IP so the peer-IP selector can exclude it.
    host_ip: Optional[str] = (endpoint or {}).get("ip") or None

    notify: Dict[str, Any] = {
        "type": "notify",
        "channels": ["slack", "dashboard"],
        "requires_approval": False,
    }

    if severity != SEVERITY_HIGH:
        # Medium ("Any" verdict) and Low (analyst-review-only) both reduce
        # to notify-only — no automated block, no isolate.
        return [notify]

    actions: List[Dict[str, Any]] = []

    if intel_malicious:
        targets = _block_targets(observables, only_confirmed=True, host_ip=host_ip)
        if targets:
            actions.append({"type": "block", "targets": targets, "requires_approval": False})
        else:
            # Flow is confirmed malicious but no routable external peer IP found.
            # Suppress block rather than emitting a useless target-less action.
            log_event(
                "auto_block_no_peer_ip",
                host_ip=host_ip,
                obs_types=[o.get("type") for o in observables],
            )
    else:
        targets = _block_targets(observables, only_confirmed=False, host_ip=host_ip)
        if targets:
            actions.append({"type": "block", "targets": targets, "requires_approval": True})

    if endpoint_risk and endpoint:
        actions.append({"type": "isolate", "target": endpoint, "requires_approval": True})

    actions.append(notify)
    return actions
