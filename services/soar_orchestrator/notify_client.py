"""Slack delivery for the §5 `notify` SOAR action.

The orchestrator owns Slack notification rather than Shuffle: it holds the
`SLACK_WEBHOOK_URL` secret, has all the alert context (case URL, severity,
TTPs, intel verdict, decided actions), and has reliable network egress (the
Shuffle swarm worker does not). The `notify` action's `slack` channel is
therefore fulfilled here.

Fail-soft by contract: every failure is caught and returned as a status dict —
a Slack outage, a bad webhook, or a network blip must never affect alert
processing or case creation.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

from slog import get_logger, log_event

log = get_logger(__name__)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
_SEVERITY_EMOJI = {"low": "\U0001F535", "medium": "\U0001F7E0", "high": "\U0001F534"}  # 🔵 🟠 🔴


def slack_webhook_url() -> Optional[str]:
    return os.getenv("SLACK_WEBHOOK_URL", "").strip() or None


def _dry_run() -> bool:
    return os.getenv("ORCHESTRATOR_DRY_RUN", "true").lower() == "true"


def _slack_enabled() -> bool:
    return os.getenv("SLACK_NOTIFY_ENABLED", "true").lower() == "true"


def _min_severity_rank() -> int:
    """Throttle knob: only notify at/above this severity. Default 'low' = all."""
    return _SEVERITY_RANK.get(os.getenv("SLACK_NOTIFY_MIN_SEVERITY", "low").strip().lower(), 0)


def _actions_summary(actions: Optional[List[Dict[str, Any]]]) -> str:
    parts: List[str] = []
    for a in actions or []:
        atype = str(a.get("type") or "?")
        parts.append(f"{atype} (approval required)" if a.get("requires_approval") else atype)
    return ", ".join(parts) if parts else "notify only"


def _short(text: Any, limit: int = 300) -> str:
    s = str(text if text is not None else "").strip().replace("\r\n", "\n")
    return (s[: limit - 1].rstrip() + "…") if len(s) > limit else s


def build_slack_message(
    *,
    flow_id: str,
    severity: str,
    pred_proba: float,
    mitre_ttps: Optional[List[str]] = None,
    intel_malicious: bool = False,
    intel_score: float = 0.0,
    actions: Optional[List[Dict[str, Any]]] = None,
    thehive_case_url: str = "",
    annotation: str = "",
) -> Dict[str, Any]:
    """Build the Slack incoming-webhook payload (Block Kit + a plain-text
    fallback so notifications render in clients that ignore blocks)."""
    sev = (severity or "Low")
    emoji = _SEVERITY_EMOJI.get(sev.lower(), "⚪")  # ⚪ fallback
    flow_short = str(flow_id or "unknown")[:8]
    ttps = ", ".join((mitre_ttps or [])[:5]) or "Unclassified"
    intel = "confirmed malicious IOC" if intel_malicious else "no confirmed IOC"
    actions_str = _actions_summary(actions)

    text = (
        f"{emoji} SOAR {sev} alert — flow {flow_short} "
        f"(p={pred_proba:.2f}, {ttps}; intel: {intel}; actions: {actions_str})"
    )

    fields = [
        {"type": "mrkdwn", "text": f"*Severity:*\n{emoji} {sev}"},
        {"type": "mrkdwn", "text": f"*Confidence:*\n{pred_proba:.2%}"},
        {"type": "mrkdwn", "text": f"*MITRE ATT&CK:*\n{ttps}"},
        {"type": "mrkdwn", "text": f"*Intel:*\n{intel} (score {intel_score:.2f})"},
        {"type": "mrkdwn", "text": f"*Actions:*\n{actions_str}"},
        {"type": "mrkdwn", "text": f"*Flow:*\n`{flow_short}`"},
    ]
    blocks: List[Dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} SOAR Alert — {sev}"}},
        {"type": "section", "fields": fields},
    ]
    if thehive_case_url:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*TheHive case:* <{thehive_case_url}|open case>"},
        })
    annotation_short = _short(annotation, 280)
    if annotation_short:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": annotation_short}],
        })
    return {"text": text, "blocks": blocks}


def send_slack_notification(
    *,
    flow_id: str,
    severity: str,
    pred_proba: float,
    mitre_ttps: Optional[List[str]] = None,
    intel_malicious: bool = False,
    intel_score: float = 0.0,
    actions: Optional[List[Dict[str, Any]]] = None,
    thehive_case_url: str = "",
    annotation: str = "",
    timeout: int = 10,
) -> Dict[str, Any]:
    """Post the notify message to Slack. Never raises. Returns a status dict:
    {"skipped": reason} | {"dry_run": True} | {"status": "sent"} | {"error": ...}."""
    if not _slack_enabled():
        return {"skipped": "SLACK_NOTIFY_ENABLED=false"}
    if _SEVERITY_RANK.get((severity or "low").lower(), 0) < _min_severity_rank():
        return {"skipped": f"below SLACK_NOTIFY_MIN_SEVERITY ({severity})"}

    url = slack_webhook_url()
    message = build_slack_message(
        flow_id=flow_id, severity=severity, pred_proba=pred_proba,
        mitre_ttps=mitre_ttps, intel_malicious=intel_malicious, intel_score=intel_score,
        actions=actions, thehive_case_url=thehive_case_url, annotation=annotation,
    )

    if _dry_run() or not url:
        reason = "dry_run" if _dry_run() else "SLACK_WEBHOOK_URL not set"
        log_event("slack_notify_skipped", flow=str(flow_id)[:8], severity=severity, reason=reason)
        return {"dry_run": True} if _dry_run() else {"skipped": reason}

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(message).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            ok = resp.status == 200 and body.strip().lower() == "ok"
            log_event("slack_notify_sent", flow=str(flow_id)[:8], severity=severity,
                      http_status=resp.status, ok=ok)
            return {"status": "sent", "http_status": resp.status, "ok": ok}
    except Exception as exc:  # network/Slack failure must not break processing
        log.warning(
            "slack_notify_failed",
            extra={"event": "slack_notify_failed", "flow": str(flow_id)[:8],
                   "severity": severity, "error": str(exc)},
        )
        return {"error": str(exc)}
