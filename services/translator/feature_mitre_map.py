"""
feature_mitre_map.py
--------------------
Maps XAI top-k feature attributions to MITRE ATT&CK technique IDs,
generates human-readable SOC alert annotations, and computes severity.

This is the XAI→SOAR translation layer — the thesis contribution that
bridges the ML explanation output to operational security context.

Structure of each mapping entry:
    feature_name → {
        "direction":   "positive" | "negative" | "any"
                       (contribution direction that is security-relevant)
        "mitre_id":    ATT&CK technique ID
        "mitre_name":  technique name
        "tactic":      ATT&CK tactic
        "annotation":  human-readable explanation for SOC analyst
    }
"""

# ── Feature → MITRE ATT&CK Mapping ───────────────────────────────────────────
# Based on security semantics analysis from the research paper (Section IV-G)
FEATURE_MITRE_MAP = {

    # ── TTL features ──────────────────────────────────────────────────────────
    "std_time_to_live": {
        "direction":  "negative",   # low variance → suspicious uniformity
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Low TTL variance indicates traffic originates from a fixed OS "
            "environment with rigid TTL initialisation, consistent with "
            "malware using a single C2 host rather than heterogeneous "
            "legitimate endpoints."
        ),
    },
    "mean_time_to_live": {
        "direction":  "any",
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Anomalous mean TTL value suggests traffic does not conform to "
            "expected OS-specific initial TTL values (64/128/255), "
            "potentially indicating tunnelling or spoofed headers."
        ),
    },
    "min_time_to_live": {
        "direction":  "any",
        "mitre_id":   "T1572",
        "mitre_name": "Protocol Tunneling",
        "tactic":     "Command and Control",
        "annotation": (
            "Unusually low minimum TTL across session packets may indicate "
            "protocol tunnelling or traffic relayed through multiple hops "
            "to obscure origin."
        ),
    },

    # ── Backward IAT features (C2 beaconing signatures) ───────────────────────
    "std_Interval_of_arrival_time_of_backward_traffic": {
        "direction":  "negative",   # low std → periodic/regular timing
        "mitre_id":   "T1071.001",
        "mitre_name": "Web Protocols",
        "tactic":     "Command and Control",
        "annotation": (
            "Low backward IAT variance indicates highly regular server-to-client "
            "response timing, consistent with automated C2 beaconing or polling "
            "rather than human-driven HTTPS browsing with variable response times."
        ),
    },
    "mean_Interval_of_arrival_time_of_backward_traffic": {
        "direction":  "any",
        "mitre_id":   "T1071.001",
        "mitre_name": "Web Protocols",
        "tactic":     "Command and Control",
        "annotation": (
            "Anomalous mean backward inter-arrival time deviates from typical "
            "server response patterns, suggesting automated protocol exchanges "
            "characteristic of C2 communication channels."
        ),
    },
    "max_Interval_of_arrival_time_of_backward_traffic": {
        "direction":  "positive",   # high max → burst/polling pattern
        "mitre_id":   "T1071.001",
        "mitre_name": "Web Protocols",
        "tactic":     "Command and Control",
        "annotation": (
            "Elevated maximum backward IAT captures burst characteristics "
            "of C2 polling cycles and keepalive patterns absent in "
            "continuous human-driven sessions."
        ),
    },
    "median_Interval_of_arrival_time_of_backward_traffic": {
        "direction":  "any",
        "mitre_id":   "T1071.001",
        "mitre_name": "Web Protocols",
        "tactic":     "Command and Control",
        "annotation": (
            "Atypical median backward IAT suggests non-human timing regularity "
            "in server responses, consistent with automated malware communication."
        ),
    },

    # ── Forward IAT features ──────────────────────────────────────────────────
    "mean_Interval_of_arrival_time_of_forward_traffic": {
        "direction":  "any",
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Anomalous mean forward IAT indicates non-human request pacing, "
            "consistent with programmatic C2 client behaviour rather than "
            "interactive browsing."
        ),
    },
    "std_Interval_of_arrival_time_of_forward_traffic": {
        "direction":  "negative",
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Low forward IAT variance reflects regular, automated request "
            "timing characteristic of malware polling a C2 endpoint on a "
            "fixed schedule."
        ),
    },
    "median_Interval_of_arrival_time_of_forward_traffic": {
        "direction":  "any",
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Atypical median forward IAT consistent with automated protocol "
            "exchanges rather than human-initiated requests."
        ),
    },

    # ── Payload change features ───────────────────────────────────────────────
    "The_times_of_change_of_payload_per_session": {
        "direction":  "negative",   # few changes → uniform encrypted payloads
        "mitre_id":   "T1573",
        "mitre_name": "Encrypted Channel",
        "tactic":     "Command and Control",
        "annotation": (
            "Low payload size transition count indicates structurally uniform "
            "session content. Automated malware C2 sessions exchange fixed-format "
            "encrypted messages, producing fewer distinct payload sizes than "
            "organic HTTPS sessions loading mixed content types."
        ),
    },

    # ── TCP window features ───────────────────────────────────────────────────
    "mean_TCP_windows_size_value": {
        "direction":  "any",
        "mitre_id":   "T1095",
        "mitre_name": "Non-Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Atypical mean TCP window size suggests programmatic connection "
            "management. Malware connections maintain fixed or OS-default window "
            "sizes; organic browser traffic dynamically adjusts based on "
            "application-layer backpressure."
        ),
    },
    "std_TCP_windows_size_value": {
        "direction":  "negative",
        "mitre_id":   "T1095",
        "mitre_name": "Non-Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Low TCP window size variance is consistent with malware using "
            "fixed programmatic window settings rather than dynamic adjustment "
            "typical of interactive applications."
        ),
    },
    "median_TCP_windows_size_value": {
        "direction":  "any",
        "mitre_id":   "T1095",
        "mitre_name": "Non-Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Atypical median window size deviates from expected OS-negotiated "
            "values, suggesting non-standard protocol implementation."
        ),
    },

    # ── Packet length / IP features ───────────────────────────────────────────
    "std_Length_of_IP_packets": {
        "direction":  "negative",
        "mitre_id":   "T1573",
        "mitre_name": "Encrypted Channel",
        "tactic":     "Command and Control",
        "annotation": (
            "Low IP packet length variance indicates encryption block-size "
            "uniformity. Malware payloads exhibit lower variance than "
            "legitimate traffic carrying variable-length application data."
        ),
    },
    "max_Length_of_IP_packets": {
        "direction":  "positive",
        "mitre_id":   "T1041",
        "mitre_name": "Exfiltration Over C2 Channel",
        "tactic":     "Exfiltration",
        "annotation": (
            "Elevated maximum IP packet size may indicate data exfiltration "
            "bursts within the encrypted session, consistent with bulk data "
            "transfer to a C2 endpoint."
        ),
    },

    # ── TCP header features ───────────────────────────────────────────────────
    "std_Length_of_TCP_packet_header": {
        "direction":  "negative",
        "mitre_id":   "T1095",
        "mitre_name": "Non-Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Low TCP header length variance indicates minimal TCP option "
            "negotiation, consistent with malware connections that do not "
            "negotiate optional TCP features beyond the minimum required."
        ),
    },

    # ── Time difference features ──────────────────────────────────────────────
    "median_Time_difference_between_packets_per_session": {
        "direction":  "any",
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Atypical median inter-packet timing across the session is "
            "inconsistent with human-driven browsing and suggests "
            "automated protocol behaviour."
        ),
    },
    "mean_Time_difference_between_packets_per_session": {
        "direction":  "any",
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Anomalous mean inter-packet time deviates from expected "
            "human interaction patterns."
        ),
    },
    "std_Time_difference_between_packets_per_session": {
        "direction":  "negative",
        "mitre_id":   "T1071",
        "mitre_name": "Application Layer Protocol",
        "tactic":     "Command and Control",
        "annotation": (
            "Low inter-packet time variance suggests rigid, automated timing "
            "rather than the variable pacing of interactive sessions."
        ),
    },
    "max_Time_difference_between_packets_per_session": {
        "direction":  "positive",
        "mitre_id":   "T1071.001",
        "mitre_name": "Web Protocols",
        "tactic":     "Command and Control",
        "annotation": (
            "High maximum inter-packet gap may reflect a C2 polling interval "
            "or keepalive timeout characteristic of persistent encrypted tunnels."
        ),
    },
}

# ── Mapping metadata ──────────────────────────────────────────────────────────
# Version stamp persisted with every alert (alerts.mapping_version) so results
# can be attributed to the mapping table that produced them after rule changes.
MAPPING_VERSION = "fmm-1.1.0"

# Keyword fallback for top-k features that have no explicit rule (or whose
# contribution direction did not match). Produces mapping_status =
# "unmapped_heuristic": the orchestrator drops these at the TheHive gate in
# strict mode but can triage them when REQUIRE_STRICT_MAPPED=false.
KEYWORD_TTP_RULES = [
    ("interval_of_arrival", "T1071", "Application Layer Protocol"),
    ("time_difference",     "T1071", "Application Layer Protocol"),
    ("time_to_live",        "T1071", "Application Layer Protocol"),
    ("windows_size",        "T1095", "Non-Application Layer Protocol"),
    ("payload",             "T1573", "Encrypted Channel"),
    ("length_of_ip",        "T1041", "Exfiltration Over C2 Channel"),
]

# Last-resort TTP for malicious flows where neither explicit rules nor the
# keyword heuristic matched (mapping_status = "unmapped").
FALLBACK_TTP = ("T1595", "Active Scanning")


# ── Severity scoring ──────────────────────────────────────────────────────────
def compute_severity(pred_proba: float, n_matched_features: int) -> int:
    """
    Returns severity 1 (low) / 2 (medium) / 3 (high).
    Combines model confidence with number of security-relevant features.
    """
    base = pred_proba  # 0.0–1.0

    # Boost if multiple security-relevant features agree
    feature_boost = min(n_matched_features * 0.03, 0.15)

    score = base + feature_boost
    if score >= 0.85:
        return 3    # HIGH
    elif score >= 0.65:
        return 2    # MEDIUM
    else:
        return 1    # LOW


SEVERITY_LABEL = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}


# ── Translation function ──────────────────────────────────────────────────────
def translate(alert: dict) -> dict:
    """
    Takes one alert record from the inference service and returns an
    enriched alert ready for persistence and dashboard display.

    Parameters
    ----------
    alert : dict
        Output of explain_instance() with sent_ts and inferred_ts added.

    Returns
    -------
    dict : enriched alert with MITRE mappings, severity, and annotation.
    """
    top_k     = alert.get("top_k_json", [])
    pred_proba = float(alert.get("pred_proba", 0.0))
    pred_label = int(alert.get("pred_label", 0) or 0)

    matched_ttps  = []
    matched_names = []
    annotations   = []
    matched_features = []

    for entry in top_k:
        feature   = entry.get("feature", "")
        direction = entry.get("direction", "positive")

        if feature not in FEATURE_MITRE_MAP:
            continue

        mapping = FEATURE_MITRE_MAP[feature]

        # Check direction relevance
        map_dir = mapping["direction"]
        if map_dir != "any" and map_dir != direction:
            continue

        mitre_id = mapping["mitre_id"]
        if mitre_id not in matched_ttps:
            matched_ttps.append(mitre_id)
            matched_names.append(mapping["mitre_name"])

        matched_features.append(f"{feature}→{mitre_id}")
        annotations.append(
            f"[{feature}] {mapping['annotation']}"
        )

    # Severity reflects explicit rule matches only — heuristic/fallback TTPs
    # added below are provenance-tagged context, not corroborating evidence.
    n_explicit     = len(matched_ttps)
    severity_int   = compute_severity(pred_proba, n_explicit)
    severity_label = SEVERITY_LABEL[severity_int]

    # ── Mapping provenance metadata (consumed by the SOAR orchestrator) ──────
    if n_explicit >= 1:
        mapping_status = "mapped"
        # Fraction of top-k evidence covered by explicit rules.
        mapping_confidence = round(len(annotations) / max(len(top_k), 1), 2)
        mapping_reason = (
            f"{len(annotations)}/{len(top_k)} top-k features matched explicit "
            f"rules: {'; '.join(matched_features)}"
        )
    elif pred_label == 1:
        heuristic_hits = []
        for entry in top_k:
            feature_lc = str(entry.get("feature", "")).lower()
            for keyword, ttp, name in KEYWORD_TTP_RULES:
                if keyword in feature_lc:
                    heuristic_hits.append(f"{entry.get('feature')}~{keyword}→{ttp}")
                    if ttp not in matched_ttps:
                        matched_ttps.append(ttp)
                        matched_names.append(name)
                    break
        if heuristic_hits:
            mapping_status = "unmapped_heuristic"
            mapping_confidence = 0.30
            mapping_reason = (
                "No explicit rule matched; keyword heuristic assigned: "
                + "; ".join(heuristic_hits)
            )
        else:
            mapping_status = "unmapped"
            mapping_confidence = 0.0
            matched_ttps.append(FALLBACK_TTP[0])
            matched_names.append(FALLBACK_TTP[1])
            mapping_reason = (
                "No explicit or heuristic rule matched top-k features; "
                f"fallback {FALLBACK_TTP[0]} assigned for observability"
            )
    else:
        mapping_status = "unmapped"
        mapping_confidence = 0.0
        mapping_reason = "Benign flow — no explicit rules matched; no fallback assigned"

    # Build human-readable annotation block
    if alert.get("pred_label") == 1:
        annotation_header = (
            f"MALICIOUS ENCRYPTED TRAFFIC DETECTED — "
            f"Confidence: {pred_proba:.1%} | Severity: {severity_label}\n\n"
            f"Model: {alert.get('model')} | Tier: {alert.get('tier')}\n"
            f"MITRE ATT&CK: {', '.join(matched_ttps) if matched_ttps else 'Unclassified'}\n\n"
            f"Evidence:\n" + "\n\n".join(f"• {a}" for a in annotations)
        )
    else:
        annotation_header = (
            f"Benign flow — Confidence: {1 - pred_proba:.1%} | "
            f"Model: {alert.get('model')}"
        )

    return {
        **alert,
        "mitre_ttps":      matched_ttps,
        "mitre_names":     matched_names,
        "severity":        severity_int,
        "severity_label":  severity_label,
        "annotation":      annotation_header,
        # Counts the final TTP list (incl. heuristic/fallback) — the
        # orchestrator's n_ttps_matched >= 1 gate must pass for heuristic
        # alerts when strict mapping is relaxed; provenance lives in
        # mapping_status, not in this count.
        "n_ttps_matched":  len(matched_ttps),
        "mapping_status":     mapping_status,
        "mapping_confidence": mapping_confidence,
        "mapping_version":    MAPPING_VERSION,
        "mapping_reason":     mapping_reason,
    }