"""Severity classification (SOAR_WORKFLOW_SPEC.md Step 2).

The orchestrator is the single, authoritative source of severity, derived
from `pred_proba` (model_confidence). The translator's `severity_label`
column is advisory only — kept on the case/payload for traceability, never
branched on.
"""
from __future__ import annotations

HIGH_THRESHOLD = 0.90
MEDIUM_THRESHOLD = 0.70

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"


def compute_severity(pred_proba: float) -> str:
    """>=0.90 High, 0.70-0.89 Medium, <0.70 Low (analyst-review-only)."""
    p = float(pred_proba or 0.0)
    if p >= HIGH_THRESHOLD:
        return SEVERITY_HIGH
    if p >= MEDIUM_THRESHOLD:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW
