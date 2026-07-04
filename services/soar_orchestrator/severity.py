"""Severity classification (SOAR_WORKFLOW_SPEC.md Step 2).

The orchestrator is the single, authoritative source of severity, derived
from `pred_proba` (model_confidence). The translator's `severity_label`
column is advisory only — kept on the case/payload for traceability, never
branched on.
"""
from __future__ import annotations

import os

# Severity bands are env-configurable. The spec default is High>=0.90, but the
# retrained NFStream model rarely scores >=0.90 — most true-malicious flows land
# in 0.80-0.89 — so this deployment lowers the High band (SEVERITY_HIGH_THRESHOLD)
# to bring confident sub-0.90 flows into the High cell, where the §5 matrix emits
# a (gated) block and the approval loop can actually be demonstrated. Keep the
# translator's advisory `severity_label` aligned to these same bands.
HIGH_THRESHOLD = float(os.getenv("SEVERITY_HIGH_THRESHOLD", "0.90"))
MEDIUM_THRESHOLD = float(os.getenv("SEVERITY_MEDIUM_THRESHOLD", "0.70"))

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"


def compute_severity(pred_proba: float) -> str:
    """>= HIGH_THRESHOLD -> High; >= MEDIUM_THRESHOLD -> Medium; else Low
    (analyst-review-only). Thresholds from SEVERITY_HIGH/MEDIUM_THRESHOLD env."""
    p = float(pred_proba or 0.0)
    if p >= HIGH_THRESHOLD:
        return SEVERITY_HIGH
    if p >= MEDIUM_THRESHOLD:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW
