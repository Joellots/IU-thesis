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

from typing import Any, Dict, List, Optional

from severity import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW  # noqa: F401

BLOCKABLE_TYPES = ("ip", "domain")


def _block_targets(observables: List[Dict[str, Any]], *, only_confirmed: bool) -> List[Dict[str, Any]]:
    targets = []
    for obs in observables or []:
        if obs.get("type") not in BLOCKABLE_TYPES:
            continue
        if only_confirmed and not obs.get("intel_malicious"):
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
    flags (see case_automation.annotate_observable_intel) when available —
    they become the auto-block targets in the confirmed-IOC cell.
    """
    observables = observables or []
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
        targets = _block_targets(observables, only_confirmed=True)
        if targets:
            actions.append({"type": "block", "targets": targets, "requires_approval": False})
    else:
        targets = _block_targets(observables, only_confirmed=False)
        if targets:
            actions.append({"type": "block", "targets": targets, "requires_approval": True})

    if endpoint_risk and endpoint:
        actions.append({"type": "isolate", "target": endpoint, "requires_approval": True})

    actions.append(notify)
    return actions
