"""
compare_features.py
───────────────────
Loads an argus-extracted CSV and compares its columns against the
model's expected realtime-safe feature set.

Helps answer: "Which model features does argus cover directly, which
need renaming, and which need computing from available fields?"

Usage (inside container):
    python3 /app/compare_features.py /output/traffic.csv

Usage with custom feature list:
    python3 /app/compare_features.py /output/traffic.csv --features /app/features.txt
"""

import sys
import argparse
import pandas as pd

# ── Your model's realtime-safe feature set ────────────────────────────────────
# Paste in the output of: list(X_train_rt.columns) from your notebook
MODEL_FEATURES = [
    "Payload_ratio",
    "Length_of_IP_packets",
    "Length_of_TCP_payload",
    "Length_of_TCP_packet_header",
    "Length_of_IP_packet_header",
    "TCP_windows_size_value",
    "Length_of_TCP_segment(packet)",
    "Time_difference_between_packets_per_session",
    "Interval_of_arrival_time_of_forward_traffic",
    "Interval_of_arrival_time_of_backward_traffic",
    "Time_to_live",
    "Ratio_to_previous_packets_in_each_session",
    "Change_values_of_TCP_windows_length_per_session",
    "The_times_of_change_of_TCP_windows_length",
    "The_times_of_change_of_payload_per_session",
    "mean_Length_of_IP_packets",
    "median_Length_of_IP_packets",
    "max_Length_of_IP_packets",
    "min_Length_of_IP_packets",
    "std_Length_of_IP_packets",
    "mean_Length_of_TCP_payload",
    "median_Length_of_TCP_payload",
    "max_Length_of_TCP_payload",
    "min_Length_of_TCP_payload",
    "std_Length_of_TCP_payload",
    "mean_Length_of_TCP_packet_header",
    "median_Length_of_TCP_packet_header",
    "max_Length_of_TCP_packet_header",
    "min_Length_of_TCP_packet_header",
    "std_Length_of_TCP_packet_header",
    "mean_Length_of_IP_packet_header",
    "median_Length_of_IP_packet_header",
    "max_Length_of_IP_packet_header",
    "min_Length_of_IP_packet_header",
    "std_Length_of_IP_packet_header",
    "mean_TCP_windows_size_value",
    "median_TCP_windows_size_value",
    "max_TCP_windows_size_value",
    "min_TCP_windows_size_value",
    "std_TCP_windows_size_value",
    "mean_Length_of_TCP_segment(packet)",
    "median_Length_of_TCP_segment(packet)",
    "max_Length_of_TCP_segment(packet)",
    "min_Length_of_TCP_segment(packet)",
    "std_Length_of_TCP_segment(packet)",
    "mean_Time_difference_between_packets_per_session",
    "median_Time_difference_between_packets_per_session",
    "max_Time_difference_between_packets_per_session",
    "min_Time_difference_between_packets_per_session",
    "std_Time_difference_between_packets_per_session",
    "mean_Interval_of_arrival_time_of_forward_traffic",
    "median_Interval_of_arrival_time_of_forward_traffic",
    "max_Interval_of_arrival_time_of_forward_traffic",
    "min_Interval_of_arrival_time_of_forward_traffic",
    "std_Interval_of_arrival_time_of_forward_traffic",
    "mean_Interval_of_arrival_time_of_backward_traffic",
    "median_Interval_of_arrival_time_of_backward_traffic",
    "max_Interval_of_arrival_time_of_backward_traffic",
    "min_Interval_of_arrival_time_of_backward_traffic",
    "std_Interval_of_arrival_time_of_backward_traffic",
    "mean_time_to_live",
    "median_time_to_live",
    "max_time_to_live",
    "min_time_to_live",
    "std_time_to_live",
]

# ── Known argus → model feature mappings ──────────────────────────────────────
# Direct or near-direct equivalents
ARGUS_TO_MODEL = {
    "sintpkt":  "mean_Interval_of_arrival_time_of_forward_traffic",
    "dintpkt":  "mean_Interval_of_arrival_time_of_backward_traffic",
    "sjit":     "std_Interval_of_arrival_time_of_forward_traffic",
    "djit":     "std_Interval_of_arrival_time_of_backward_traffic",
    "swin":     "mean_TCP_windows_size_value",    # src window ~ mean
    "dwin":     "TCP_windows_size_value",
    "sttl":     "mean_time_to_live",
    "dttl":     "std_time_to_live",               # dst TTL used as proxy
    "smean":    "mean_Length_of_IP_packets",
    "dmean":    "mean_Length_of_IP_packets",
    "sbytes":   "Length_of_TCP_payload",
    "dbytes":   "Length_of_TCP_payload",
    "dur":      "mean_Time_difference_between_packets_per_session",
    "load":     "Payload_ratio",
}

# Features that require per-packet data to compute (min/max/median/std)
# — argus only outputs mean/jitter directly; others need packet-level access
REQUIRES_PACKET_DATA = [
    f for f in MODEL_FEATURES
    if any(stat in f for stat in ["median_", "max_", "min_"])
]

# Features argus cannot provide at all
NOT_IN_ARGUS = [
    "Ratio_to_previous_packets_in_each_session",
    "Change_values_of_TCP_windows_length_per_session",
    "The_times_of_change_of_TCP_windows_length",
    "The_times_of_change_of_payload_per_session",
]


def analyse(csv_path: str):
    print("\n" + "═" * 60)
    print(" Argus ↔ Model Feature Alignment Analysis")
    print("═" * 60)

    df = pd.read_csv(csv_path, nrows=5)
    argus_cols = list(df.columns)

    print(f"\nArgus output columns ({len(argus_cols)}):")
    for c in argus_cols:
        mapped = ARGUS_TO_MODEL.get(c, "")
        tag = f"  →  model: {mapped}" if mapped else ""
        print(f"  {c}{tag}")

    print(f"\nModel features: {len(MODEL_FEATURES)} total")

    # Direct or mapped coverage
    covered = [f for f in MODEL_FEATURES
               if f in ARGUS_TO_MODEL.values() or f in argus_cols]
    print(f"\n✓  Directly covered by argus ({len(covered)}):")
    for f in covered:
        print(f"  {f}")

    print(f"\n~  Require per-packet computation (min/max/median/std) ({len(REQUIRES_PACKET_DATA)}):")
    print("   These need either racluster post-processing or a custom")
    print("   Python script that reads the argus binary record stream.")
    for f in REQUIRES_PACKET_DATA[:8]:
        print(f"  {f}")
    if len(REQUIRES_PACKET_DATA) > 8:
        print(f"  ... and {len(REQUIRES_PACKET_DATA) - 8} more")

    print(f"\n✗  Not available from argus standard output ({len(NOT_IN_ARGUS)}):")
    for f in NOT_IN_ARGUS:
        print(f"  {f}")
    print("   These are session-level change counts that require")
    print("   per-packet payload inspection — need custom computation.")

    # Coverage summary
    direct = len(covered)
    total  = len(MODEL_FEATURES)
    pct    = direct / total * 100
    print(f"\n{'─' * 60}")
    print(f" Coverage summary")
    print(f"{'─' * 60}")
    print(f" Direct/mapped features : {direct}/{total}  ({pct:.0f}%)")
    print(f" Need packet-level work : {len(REQUIRES_PACKET_DATA)}")
    print(f" Not available          : {len(NOT_IN_ARGUS)}")
    print(f"\n Recommendation: argus covers the most predictive features")
    print(f" (IAT stats, TTL, window sizes) directly. The missing min/max/")
    print(f" median stats can be derived post-extraction. The 4 change-count")
    print(f" features need a custom Python pass over the PCAP.")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="Path to argus-extracted CSV")
    args = parser.parse_args()
    analyse(args.csv)