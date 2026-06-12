from __future__ import annotations

from typing import Any, Dict, List, Optional

from attack_stix_resolver import get_resolver

# Playbook technique steps come from the cached MITRE Enterprise STIX bundle
# (`attack_stix_resolver.py`). Legacy static per-technique text was removed to
# avoid duplicating official ATT&CK content.


def _step(title: str, description: str, group: str = "Playbook") -> Dict[str, Any]:
    return {
        "title": title,
        "description": description,
        "group": group,
    }


def build_playbook_plan(
    *,
    mitre_ttps: List[str],
    mitre_names: Optional[List[str]],
    severity_label: Optional[str],
    pred_proba: float,
    top_k_json: List[Dict[str, Any]],
    n_ttps_matched: int,
    max_techniques: int = 5,
    active_response_min_proba: float = 0.8,
    force_active_response: bool = False,
    mapping_status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Returns an ordered list of steps (the "dynamic playbook").
    Technique-specific steps are built from the cached MITRE ATT&CK Enterprise
    STIX bundle (official names, descriptions, mitigations).
    """
    unique_techniques: List[str] = []
    for t in mitre_ttps or []:
        if t and t not in unique_techniques:
            unique_techniques.append(t)

    chosen = unique_techniques[:max_techniques]

    steps: List[Dict[str, Any]] = []

    evidence_summary: Dict[str, Any] = {
        "severity_label": severity_label,
        "pred_proba": round(pred_proba, 6),
        "n_ttps_matched": n_ttps_matched,
        "top_k_sample": top_k_json[: min(5, len(top_k_json))],
    }
    if mitre_names:
        evidence_summary["mitre_names"] = mitre_names[:10]

    steps.append(
        _step(
            "Attach XAI Evidence",
            "Attach the translator output evidence to the case. "
            f"Evidence summary: {evidence_summary}",
            group="Evidence",
        )
    )

    resolver = get_resolver()
    for technique in chosen:
        for s in resolver.steps_for_technique(technique):
            steps.append(s)

    if (mapping_status or "").lower() == "unmapped":
        feat_hint = ", ".join(
            str(e.get("feature") or "")
            for e in (top_k_json or [])[:5]
            if e.get("feature")
        ) or "(no feature names in top-k)"
        steps.append(
            _step(
                "Analyst: propose mapping for unclassified pattern",
                "Translator marked this alert as **unmapped** relative to the feature→MITRE rule set. "
                "Review top contributing features, validate against ATT&CK technique pages above, and "
                "update `services/translator/feature_mitre_map.json` (or DB rules) if a stable mapping applies.\n\n"
                f"Top-k feature names for review: {feat_hint}",
                group="Triage",
            )
        )

    if force_active_response or (severity_label == "HIGH" and pred_proba >= active_response_min_proba):
        steps.append(
            _step(
                "Execute Response Actions (High Confidence)",
                "Execute active response actions appropriate for the selected techniques. "
                "Examples: block/contain suspected destinations, start network hunts, and escalate to incident management. "
                f"(Gated: force_active_response={force_active_response} OR severity=HIGH and pred_proba>={active_response_min_proba:.2f})",
                group="Response",
            )
        )
    else:
        steps.append(
            _step(
                "Execute Investigation-Only Actions",
                "Run containment-adjacent investigations (enrichment + pivoting) without aggressive blocking. "
                f"(Gated: severity={severity_label or 'UNKNOWN'} and pred_proba={pred_proba:.2f})",
                group="Response",
            )
        )

    return steps
