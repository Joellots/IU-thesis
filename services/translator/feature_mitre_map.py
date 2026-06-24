"""
feature_mitre_map.py  —  feature → class → MITRE ATT&CK mapping (validated)
---------------------------------------------------------------------------
The XAI→SOAR translation layer and the thesis's core contribution: it maps the
model's per-flow XAI feature attributions to a behavioural *class*, and the
class to MITRE ATT&CK techniques, emitting a per-alert reliability score
(`mapping_confidence`) the SOAR orchestrator uses as a trust gate.

Design (v2 — feature → class → TTP):
  1. FEATURE_CLASS_MAP — each validated feature votes for ONE behavioural class
     with a value-direction and a confidence equal to its empirical reliability
     (bootstrap top-k stability, 0–1, from model_training/feature_mitre_validation.ipynb).
  2. translate() aggregates the malicious-pushing top-k features into a class
     vote (weighted by confidence × |contribution|), picks the dominant class,
     and assigns that class's TTPs (CLASS_TTP_MAP).
  3. mapping_confidence = contribution-weighted mean stability of the matched
     evidence; mapping_status = mapped / unmapped_heuristic / unmapped.

Empirical basis (4 methods agree — statistics + SHAP(binary) + SHAP(3-class) +
EBM exact; bootstrap stability in parentheses):
  • C2 beaconing  → HIGH TCP-payload length, TCP-window size, IP-packet length (0.98–1.00)
  • Exfiltration  → LOW  inter-arrival / inter-packet timing                    (0.90–1.00)
Literature citations for each link are added in Phase 4 (see `citation` field).
"""

import os

MAPPING_VERSION = "fmm-2.0.0"   # validated feature→class→TTP map

# Ambiguity-margin gate: a class is asserted as "mapped" only when its weighted
# vote share (dominance = winner / total class vote) clears this margin. Below it
# the evidence is split between classes, so the TTP is asserted only tentatively
# (mapping_status="unmapped_heuristic", reduced confidence) — this protects
# precision on the minority/overlapping class (exfil). 0.5 = gate off (pure argmax).
CLASS_MARGIN = float(os.getenv("MAPPING_CLASS_MARGIN", "0.60"))


# ── 1. Feature → behavioural class ───────────────────────────────────────────
# direction = the feature VALUE direction that indicates the class ("high"/"low").
# confidence = bootstrap top-k stability (per-feature reliability), used as the
#              evidence weight and rolled up into the alert's mapping_confidence.
# Malicious-indicating evidence always has a POSITIVE (malicious-pushing) XAI
# contribution, so translate() only counts top-k entries with direction "positive".
FEATURE_CLASS_MAP = {
    # ── C2 beaconing: large, variable encrypted payloads + programmatic windows ──
    "mean_Length_of_TCP_payload":   {"class": "c2_beaconing", "direction": "high", "confidence": 1.00},
    "std_Length_of_TCP_payload":    {"class": "c2_beaconing", "direction": "high", "confidence": 1.00},
    "max_Length_of_TCP_payload":    {"class": "c2_beaconing", "direction": "high", "confidence": 1.00},
    "mean_TCP_windows_size_value":  {"class": "c2_beaconing", "direction": "high", "confidence": 1.00},
    "std_TCP_windows_size_value":   {"class": "c2_beaconing", "direction": "high", "confidence": 1.00},
    "median_TCP_windows_size_value":{"class": "c2_beaconing", "direction": "high", "confidence": 1.00},
    "mean_Length_of_IP_packets":    {"class": "c2_beaconing", "direction": "high", "confidence": 1.00},
    "std_Length_of_IP_packets":     {"class": "c2_beaconing", "direction": "high", "confidence": 0.98},

    # ── Exfiltration: rapid, regular packet timing of bulk upload (low IAT) ──────
    "mean_Interval_of_arrival_time_of_backward_traffic": {"class": "exfil", "direction": "low", "confidence": 1.00},
    "std_Interval_of_arrival_time_of_backward_traffic":  {"class": "exfil", "direction": "low", "confidence": 1.00},
    "max_Interval_of_arrival_time_of_backward_traffic":  {"class": "exfil", "direction": "low", "confidence": 0.90},
    "mean_Interval_of_arrival_time_of_forward_traffic":  {"class": "exfil", "direction": "low", "confidence": 1.00},
    "std_Interval_of_arrival_time_of_forward_traffic":   {"class": "exfil", "direction": "low", "confidence": 0.96},
    "mean_Time_difference_between_packets_per_session":  {"class": "exfil", "direction": "low", "confidence": 1.00},
}


# ── 2. Class → MITRE ATT&CK techniques (top-level + sub-techniques) ───────────
CLASS_TTP_MAP = {
    "c2_beaconing": {
        "tactic": "Command and Control",
        "ttps": [
            {"mitre_id": "T1071",     "mitre_name": "Application Layer Protocol"},
            {"mitre_id": "T1071.001", "mitre_name": "Web Protocols"},
            {"mitre_id": "T1573",     "mitre_name": "Encrypted Channel"},
        ],
        "summary": (
            "Large, low-variance encrypted payloads and programmatic TCP-window "
            "behaviour, consistent with automated C2 beaconing over an encrypted "
            "channel rather than human-driven HTTPS browsing."
        ),
        "citation": None,  # Phase 4
    },
    "exfil": {
        "tactic": "Exfiltration",
        "ttps": [
            {"mitre_id": "T1041",     "mitre_name": "Exfiltration Over C2 Channel"},
            {"mitre_id": "T1048.002", "mitre_name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"},
        ],
        "summary": (
            "Rapid, regular inter-arrival timing (low IAT) characteristic of "
            "sustained bulk data upload to an external endpoint over an encrypted "
            "channel."
        ),
        "citation": None,  # Phase 4
    },
}

_DIR_WORD = {"high": "elevated", "low": "low"}


# ── Fallbacks for malicious flows with no validated-feature evidence ──────────
# Keyword heuristic → mapping_status "unmapped_heuristic"; the orchestrator drops
# these at the TheHive gate in strict mode but can triage them otherwise.
KEYWORD_TTP_RULES = [
    ("interval_of_arrival", "exfil",        "T1041", "Exfiltration Over C2 Channel"),
    ("time_difference",     "exfil",        "T1041", "Exfiltration Over C2 Channel"),
    ("payload",             "c2_beaconing", "T1573", "Encrypted Channel"),
    ("windows_size",        "c2_beaconing", "T1071", "Application Layer Protocol"),
    ("length_of_ip",        "c2_beaconing", "T1071", "Application Layer Protocol"),
]
FALLBACK_TTP = ("T1071", "Application Layer Protocol")   # last-resort C2 for unmapped malicious


# ── Severity (advisory, ALIGNED to the SOAR orchestrator's bands) ─────────────
# The SOAR orchestrator is the authoritative source of severity — it recomputes
# from pred_proba alone (SOAR_WORKFLOW_SPEC §Step 2). This advisory label MUST use
# the SAME bands so the dashboard reflects what SOAR will actually do. Bands are
# env-tunable (defaults match the live orchestrator: High ≥0.80 / Medium ≥0.70 /
# Low <0.70) — if the SOAR side retunes its thresholds, override these and restart
# the translator, no code change needed.
SEVERITY_HIGH_MIN = float(os.getenv("SEVERITY_HIGH_MIN", "0.80"))
SEVERITY_MED_MIN  = float(os.getenv("SEVERITY_MED_MIN",  "0.70"))


def compute_severity(pred_proba: float, n_matched_features: int = 0) -> int:
    """Returns severity 1 (low) / 2 (medium) / 3 (high), from pred_proba only —
    matching the orchestrator. `n_matched_features` is retained for call-site
    compatibility but no longer shifts the band."""
    if pred_proba >= SEVERITY_HIGH_MIN:
        return 3
    elif pred_proba >= SEVERITY_MED_MIN:
        return 2
    return 1


SEVERITY_LABEL = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}


# ── Translation ───────────────────────────────────────────────────────────────
def translate(alert: dict) -> dict:
    """
    Enrich one inference alert: infer the behavioural class from XAI top-k
    features, assign its MITRE TTPs, and attach mapping provenance/confidence.
    Output keys are the contract consumed by translator_service.py + the SOAR
    orchestrator (mitre_ttps, severity, mapping_status/confidence/version/reason).
    """
    top_k      = alert.get("top_k_json", [])
    pred_proba = float(alert.get("pred_proba", 0.0))
    pred_label = int(alert.get("pred_label", 0) or 0)

    # ── Aggregate malicious-pushing top-k features into per-class votes ──────
    votes = {}                       # class -> weighted vote
    evidence = {}                    # class -> [(feature, confidence, |contrib|)]
    for entry in top_k:
        feature   = entry.get("feature", "")
        direction = entry.get("direction", "positive")
        contrib   = abs(float(entry.get("contribution", 0.0) or 0.0))

        rule = FEATURE_CLASS_MAP.get(feature)
        if rule is None or direction != "positive":   # only validated, malicious-pushing evidence
            continue
        cls    = rule["class"]
        weight = rule["confidence"] * (contrib if contrib > 0 else 1.0)
        votes[cls] = votes.get(cls, 0.0) + weight
        evidence.setdefault(cls, []).append((feature, rule["confidence"], contrib, rule["direction"]))

    matched_ttps, matched_names, annotations = [], [], []

    if votes:
        # ── Dominant validated class, gated by the ambiguity margin ─────────
        inferred_class = max(votes, key=votes.get)
        total_vote = sum(votes.values())
        dominance  = (votes[inferred_class] / total_vote) if total_vote else 1.0

        info = CLASS_TTP_MAP[inferred_class]
        matched_ttps  = [t["mitre_id"]   for t in info["ttps"]]
        matched_names = [t["mitre_name"] for t in info["ttps"]]

        ev = evidence[inferred_class]
        den = sum(w for _, _, w, _ in ev)
        base_conf = (sum(conf * w for _, conf, w, _ in ev) / den) if den > 0 \
            else (sum(conf for _, conf, _, _ in ev) / len(ev))
        feats = ", ".join(f for f, _, _, _ in ev)
        annotations = [info["summary"]] + [
            f"[{f}] {_DIR_WORD.get(d, d)} value (reliability {conf:.2f})"
            for f, conf, _, d in ev
        ]

        if dominance >= CLASS_MARGIN:
            mapping_status     = "mapped"
            mapping_confidence = round(base_conf, 3)
            mapping_reason = (
                f"class={inferred_class} (dominance {dominance:.2f}) from "
                f"{len(ev)} validated feature(s) [{feats}]; conf={mapping_confidence}"
            )
        else:
            # Evidence split between classes — assert the winner only tentatively.
            runner = sorted(votes.items(), key=lambda kv: -kv[1])[1][0]
            mapping_status     = "unmapped_heuristic"
            mapping_confidence = round(base_conf * dominance, 3)
            mapping_reason = (
                f"ambiguous: {inferred_class} vs {runner} (dominance {dominance:.2f} "
                f"< margin {CLASS_MARGIN}); tentative {inferred_class}"
            )

    elif pred_label == 1:
        # ── Heuristic / fallback for malicious flows with no validated evidence ──
        hits = []
        for entry in top_k:
            fl = str(entry.get("feature", "")).lower()
            for kw, cls, ttp, name in KEYWORD_TTP_RULES:
                if kw in fl:
                    hits.append(f"{entry.get('feature')}~{kw}→{ttp}")
                    if ttp not in matched_ttps:
                        matched_ttps.append(ttp); matched_names.append(name)
                    break
        if hits:
            mapping_status, mapping_confidence = "unmapped_heuristic", 0.30
            mapping_reason = "No validated feature matched; keyword heuristic: " + "; ".join(hits)
            annotations = [f"Heuristic classification — {h}" for h in hits]
        else:
            mapping_status, mapping_confidence = "unmapped", 0.0
            matched_ttps  = [FALLBACK_TTP[0]]
            matched_names = [FALLBACK_TTP[1]]
            mapping_reason = f"No validated/heuristic match; fallback {FALLBACK_TTP[0]} for observability"
            annotations = ["No validated feature evidence; fallback TTP assigned."]
    else:
        mapping_status, mapping_confidence = "unmapped", 0.0
        mapping_reason = "Benign flow — no TTP assignment"

    severity_int   = compute_severity(pred_proba, len(matched_ttps) if mapping_status == "mapped" else 0)
    severity_label = SEVERITY_LABEL[severity_int]

    # ── Annotation block (dashboard) ────────────────────────────────────────
    if pred_label == 1:
        annotation = (
            f"MALICIOUS ENCRYPTED TRAFFIC DETECTED — "
            f"Confidence: {pred_proba:.1%} | Severity: {severity_label}\n\n"
            f"Model: {alert.get('model')} | Tier: {alert.get('tier')}\n"
            f"MITRE ATT&CK: {', '.join(matched_ttps) if matched_ttps else 'Unclassified'} "
            f"(mapping: {mapping_status}, conf {mapping_confidence})\n\n"
            f"Evidence:\n" + "\n".join(f"• {a}" for a in annotations)
        )
    else:
        annotation = (
            f"Benign flow — Confidence: {1 - pred_proba:.1%} | Model: {alert.get('model')}"
        )

    return {
        **alert,
        "mitre_ttps":         matched_ttps,
        "mitre_names":        matched_names,
        "severity":           severity_int,
        "severity_label":     severity_label,
        "annotation":         annotation,
        "n_ttps_matched":     len(matched_ttps),
        "mapping_status":     mapping_status,
        "mapping_confidence": mapping_confidence,
        "mapping_version":    MAPPING_VERSION,
        "mapping_reason":     mapping_reason,
    }
