"""Mapping-confidence trust gate (SOAR_WORKFLOW_SPEC.md Step 4, adjustment #3).

`mapping_status != "mapped"` (or low `mapping_confidence`) means the
translator's feature->TTP assignment is tentative: surface it in the case,
but never let it alone justify an automated block. C2/T1071 mappings come
back near 0.99 when `mapped`; exfil/T1041 mappings are lower by design (the
ambiguity-margin gate in `feature_mitre_map.py` trips more often on exfil's
overlapping signatures), so this gate naturally treats exfil more
cautiously without singling it out by name.
"""
from __future__ import annotations

import os

MAPPED = "mapped"


def mapping_confidence_threshold() -> float:
    return float(os.getenv("MAPPING_TRUST_MIN_CONFIDENCE", "0.75"))


def is_ttp_tentative(mapping_status: str, mapping_confidence: float) -> bool:
    """True when the assigned MITRE TTP(s) should be treated as tentative —
    surfaced in the case, but not by itself sufficient to justify an
    automated block."""
    status = str(mapping_status or "").strip().lower()
    if status != MAPPED:
        return True
    return float(mapping_confidence or 0.0) < mapping_confidence_threshold()
