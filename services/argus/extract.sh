#!/bin/bash
# extract.sh
# ─────────────────────────────────────────────────────────────────────────────
# Extracts flow features from PCAP files using argus + ra/racluster.
# Produces CSV and JSON output aligned to the model's realtime-safe feature set.
#
# Usage:
#   ./extract.sh <pcap_file> [mode]
#
# Modes:
#   csv      — output CSV (default)
#   json     — output JSON Lines (one record per flow)
#   inspect  — print first 10 flows with all available fields for exploration
#   fields   — list all available ra field names
#
# Output goes to /output/<pcap_basename>.<mode>
# ─────────────────────────────────────────────────────────────────────────────

set -e

PCAP="${1:-}"
MODE="${2:-csv}"

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <pcap_file> [csv|json|inspect|fields]"
    echo ""
    echo "Examples:"
    echo "  $0 /pcaps/traffic.pcap csv"
    echo "  $0 /pcaps/traffic.pcap json"
    echo "  $0 /pcaps/traffic.pcap inspect"
    exit 1
fi

if [ ! -f "$PCAP" ]; then
    echo "Error: PCAP file not found: $PCAP"
    exit 1
fi

BASENAME=$(basename "$PCAP" .pcap)
ARGUS_FILE="/tmp/${BASENAME}.argus"

echo "──────────────────────────────────────────────────────"
echo " Argus Feature Extractor"
echo " Input : $PCAP"
echo " Mode  : $MODE"
echo "──────────────────────────────────────────────────────"

# ── Step 1: Run argus sensor on PCAP ─────────────────────────────────────────
echo "[1/3] Running argus sensor..."
argus -F /etc/argus.conf -r "$PCAP" -w "$ARGUS_FILE"
echo "      Argus binary records written to $ARGUS_FILE"

# ── Step 2: Cluster intermediate records (merges partial flows) ───────────────
CLUSTERED_FILE="/tmp/${BASENAME}_clustered.argus"
echo "[2/3] Clustering flow records (merges partial TCP flows)..."
racluster \
    -r "$ARGUS_FILE" \
    -M nocorrect \
    -m proto saddr sport daddr dport \
    -w "$CLUSTERED_FILE"
echo "      Clustered records written to $CLUSTERED_FILE"

# ── Field set aligned to your model's realtime-safe features ──────────────────
# Mapping to your model features:
#   stime       → timestamp
#   dur         → flow duration
#   proto       → protocol
#   saddr/daddr → addresses (excluded from ML, kept for context)
#   spkts/dpkts → packet counts per direction
#   sbytes/dbytes → byte counts per direction
#   sttl/dttl   → TTL (Time_to_live features)
#   sintpkt     → mean forward IAT  (mean_Interval_of_arrival_time_of_forward_traffic)
#   dintpkt     → mean backward IAT (mean_Interval_of_arrival_time_of_backward_traffic)
#   sjit        → fwd IAT std dev   (std_Interval_of_arrival_time_of_forward_traffic)
#   djit        → bwd IAT std dev   (std_Interval_of_arrival_time_of_backward_traffic)
#   swin/dwin   → TCP window sizes  (TCP_windows_size_value features)
#   smean/dmean → mean pkt length   (mean_Length_of_IP_packets)
#   smeansz/dmeansz → mean segment  (mean_Length_of_TCP_segment)
#   load        → bits/sec (Payload_ratio proxy)
#   loss        → packet loss count

FIELDS="stime dur proto saddr sport daddr dport \
        spkts dpkts sbytes dbytes \
        sttl dttl \
        sintpkt dintpkt sjit djit \
        swin dwin \
        smean dmean \
        load loss"

# ── Step 3: Export in requested format ───────────────────────────────────────
echo "[3/3] Exporting flows as $MODE..."

case "$MODE" in

  csv)
    OUTPUT="/output/${BASENAME}.csv"
    ra -r "$CLUSTERED_FILE" \
       -L 0 \
       -c , \
       -s $FIELDS \
       > "$OUTPUT"
    echo "      CSV written to $OUTPUT"
    echo ""
    echo "Row count: $(wc -l < "$OUTPUT")"
    echo "Columns  : $(head -1 "$OUTPUT")"
    ;;

  json)
    OUTPUT="/output/${BASENAME}.jsonl"
    ra -r "$CLUSTERED_FILE" \
       -M json \
       -s $FIELDS \
       > "$OUTPUT"
    echo "      JSON Lines written to $OUTPUT"
    echo ""
    echo "Flow count: $(wc -l < "$OUTPUT")"
    echo "Sample record:"
    head -1 "$OUTPUT" | python3 -m json.tool 2>/dev/null | head -30
    ;;

  inspect)
    # Print first 10 flows with all fields — useful for exploring what argus produces
    echo ""
    echo "First 10 flows (selected fields):"
    ra -r "$CLUSTERED_FILE" \
       -L 0 \
       -c , \
       -s $FIELDS \
       | head -11
    echo ""
    echo "Full field list from first flow:"
    ra -r "$CLUSTERED_FILE" \
       -M json \
       -s $FIELDS \
       | head -1 | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'  {k}: {v}') for k,v in d.items()]" 2>/dev/null
    ;;

  fields)
    # Show every field argus knows about
    echo ""
    echo "All available ra field names:"
    ra -r "$CLUSTERED_FILE" -h 2>&1 | grep -A 200 "available" | head -100
    ;;

  *)
    echo "Unknown mode: $MODE"
    echo "Valid modes: csv json inspect fields"
    exit 1
    ;;

esac

echo ""
echo "Done."