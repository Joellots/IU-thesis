"""
nfstream_producer.py
────────────────────
NFStream feature extraction service for the Aegis pipeline.

Captures live traffic from a network interface (or replays a PCAP),
computes per-flow features using statistical_analysis + ExtendedFlowFeatures
NFPlugin, maps columns to the model's expected feature names, and
publishes completed flows to Kafka as JSON.

Environment variables:
    INTERFACE       Network interface name (default: auto-detected)
    PCAP_FILE       Path to PCAP file — overrides INTERFACE if set
    KAFKA_BROKER    Kafka broker address (default: localhost:9094)
    TOPIC           Kafka topic (default: raw_flows)
    BPF_FILTER      BPF filter string (default: encrypted traffic ports)
    IDLE_TIMEOUT    Flow idle timeout seconds (default: 15)
    ACTIVE_TIMEOUT  Flow active timeout seconds (default: 120)
"""

import os
import json
import time
import uuid
import logging
import statistics
import pandas as pd
import psutil
from datetime import datetime, timezone

from nfstream import NFStreamer, NFPlugin
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [nfstream] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Interface discovery ───────────────────────────────────────────────────────
interfaces = list(psutil.net_if_stats().keys())

INTERFACE = os.getenv("INTERFACE")
if not INTERFACE:
    non_loopback = [i for i in interfaces if i != "lo"]
    INTERFACE = non_loopback[0] if non_loopback else (interfaces[0] if interfaces else None)

# ── Configuration from environment ───────────────────────────────────────────
PCAP_FILE      = os.getenv("PCAP_FILE", "")          # if set, overrides INTERFACE
KAFKA_BROKER   = os.getenv("KAFKA_BROKER", "localhost:9094")
TOPIC          = os.getenv("TOPIC", "raw_flows")
IDLE_TIMEOUT   = int(os.getenv("IDLE_TIMEOUT", "15"))
ACTIVE_TIMEOUT = int(os.getenv("ACTIVE_TIMEOUT", "120"))

# ── Endpoint identity (the SOAR response-routing contract) ────────────────────
# When this sensor runs as a shippable endpoint agent, it stamps a stable
# identity onto every flow it emits so the SOAR orchestrator can route a
# block/isolate back to THIS host's Wazuh agent (§7.1 endpoint object).
#   AGENT_ID  — the Wazuh agent id (read from /var/ossec/etc/client.keys by the
#               installer); None for the in-stack sensor / before enrollment.
#   HOST_ID   — the Wazuh agent name (= a predictable host id); defaults to the
#               container/host hostname.
#   HOST_IP   — this host's own IP; auto-detected from the default route if unset.
def _default_host_ip():
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))   # no packet sent; just picks the egress IP
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return None

AGENT_ID = os.getenv("AGENT_ID") or None
HOST_ID  = os.getenv("HOST_ID")  or os.getenv("HOSTNAME") or os.uname().nodename or None
HOST_IP  = os.getenv("HOST_IP")  or _default_host_ip()

# BPF filter — captured at the kernel. Default = all TCP (any port), so we never miss
# encrypted C2 on an unforeseen port (a fixed port allowlist structurally can't). The
# producer then keeps only TLS/QUIC-classified flows (ENCRYPTED_ONLY) so the model isn't
# flooded with plaintext (SSH, HTTP, the pipeline's own traffic). Override either as needed.
BPF_FILTER = os.getenv("BPF_FILTER", "tcp")

# Forward only flows nDPI classifies as encrypted (TLS/SSL/QUIC/DTLS) or that carry a TLS SNI.
ENCRYPTED_ONLY = os.getenv("ENCRYPTED_ONLY", "true").lower() in ("1", "true", "yes")


def _is_encrypted(flow):
    """True if the flow is TLS/SSL/QUIC/DTLS (nDPI) or presents a TLS SNI."""
    app = (getattr(flow, "application_name", "") or "").upper()
    if any(k in app for k in ("TLS", "SSL", "QUIC", "DTLS")):
        return True
    return bool(getattr(flow, "requested_server_name", None))


# Optional IOC allowlist (replay flow-purity): when set, forward ONLY flows whose src/dst IP
# or TLS SNI matches one of these indicators (e.g. a pcap's manifest IOCs), dropping the
# benign background traffic in the capture. Empty = forward all (subject to ENCRYPTED_ONLY).
IOC_ALLOWLIST = [x.strip().lower() for x in os.getenv("IOC_ALLOWLIST", "").split(",") if x.strip()]


def _matches_ioc(flow):
    if not IOC_ALLOWLIST:
        return True
    ips = {str(getattr(flow, "src_ip", "")).lower(), str(getattr(flow, "dst_ip", "")).lower()}
    sni = (getattr(flow, "requested_server_name", "") or "").lower()
    for ioc in IOC_ALLOWLIST:
        if ioc in ips:
            return True
        if sni and (sni == ioc or sni.endswith("." + ioc)):
            return True
    return False

if not PCAP_FILE and not INTERFACE:
    raise RuntimeError("No network interface found and no PCAP_FILE provided.")

# Capture source: a PCAP file if given, else an explicitly configured interface
# (INTERFACE env — used by the endpoint sensor), else "any" (default in-stack).
SOURCE = PCAP_FILE if PCAP_FILE else (os.getenv("INTERFACE") or "any")



# ─────────────────────────────────────────────────────────────────────────────
# NFPlugin — computes features not available from statistical_analysis=True
# ─────────────────────────────────────────────────────────────────────────────

class ExtendedFlowFeatures(NFPlugin):
    """
    Computes per-flow statistics using correct NFPacket attributes.

    NFPacket exposes: time, raw_size, ip_size, transport_size,
                      payload_size, direction, syn, ack, fin, rst, psh
    TTL and TCP window are NOT available per-packet — derived from
    flow-level attributes instead.
    """

    def on_init(self, packet, flow):
        # IAT tracking — packet.time is milliseconds since epoch.
        # piat_list holds *relative* inter-arrival times only; it MUST start
        # empty. Seeding it with the absolute epoch timestamp corrupts
        # median_piat_ms (a 2-packet flow would otherwise median over
        # [epoch_ts, iat] ≈ 5e10 ms). The first real IAT is appended in
        # on_update against last_seen_ms (set below).
        flow.udps.piat_list         = []
        flow.udps.last_seen_ms      = packet.time

        # Payload size tracking for change count
        flow.udps.payload_changes   = 0
        flow.udps.last_payload_size = packet.payload_size

        # Transport size tracking (proxy for TCP segment size changes)
        flow.udps.transport_changes  = 0
        flow.udps.last_transport_size = packet.transport_size

        # Initialise all output fields — always exist on expiry
        flow.udps.median_piat_ms     = 0.0
        flow.udps.mean_ttl           = 0.0
        flow.udps.std_ttl            = 0.0
        flow.udps.max_ttl            = 0.0
        flow.udps.min_ttl            = 0.0
        flow.udps.mean_window_size   = 0.0
        flow.udps.std_window_size    = 0.0
        flow.udps.max_window_size    = 0.0
        flow.udps.min_window_size    = 0.0
        flow.udps.median_window_size = 0.0
        flow.udps.window_changes     = 0

    def on_update(self, packet, flow):
        # IAT — difference between current and previous packet time
        iat = packet.time - flow.udps.last_seen_ms
        if iat > 0:
            flow.udps.piat_list.append(iat)
        flow.udps.last_seen_ms = packet.time

        # Payload change count — detects transitions in payload size
        if packet.payload_size != flow.udps.last_payload_size:
            flow.udps.payload_changes += 1
        flow.udps.last_payload_size = packet.payload_size

        # Transport size change count — proxy for TCP window/segment changes
        if packet.transport_size != flow.udps.last_transport_size:
            flow.udps.transport_changes += 1
        flow.udps.last_transport_size = packet.transport_size

    def on_expire(self, flow):
        # ── Median IAT ────────────────────────────────────────────────────
        # >= 1: a single inter-arrival time has a well-defined median; only
        # 1-packet flows (no IAT at all) fall back to 0.0.
        piats = flow.udps.piat_list
        flow.udps.median_piat_ms = (
            statistics.median(piats) if len(piats) >= 1 else 0.0
        )

        # ── TTL statistics — derived from flow-level fields ───────────────
        # NFStream tracks TTL (IPv4) or hop_limit (IPv6) at flow level.
        # Collect all available min/max values from both directions.
        ttl_vals = []

        # IPv4 TTL fields
        for attr in ['src2dst_min_ttl', 'src2dst_max_ttl', 'dst2src_min_ttl', 'dst2src_max_ttl']:
            if hasattr(flow, attr):
                val = getattr(flow, attr, None)
                # Include TTL values >= 0 (0 is technically invalid but collect it)
                if val is not None and isinstance(val, (int, float)) and val >= 0:
                    ttl_vals.append(float(val))

        # IPv6 hop limit fields (if present)
        for attr in ['src2dst_min_hop_limit', 'src2dst_max_hop_limit',
                     'dst2src_min_hop_limit', 'dst2src_max_hop_limit']:
            if hasattr(flow, attr):
                val = getattr(flow, attr, None)
                if val is not None and isinstance(val, (int, float)) and val >= 0:
                    ttl_vals.append(float(val))

        if ttl_vals:
            flow.udps.mean_ttl = statistics.mean(ttl_vals)
            # NOTE: std_ttl is structurally ~0 under NFStream — only flow-level
            # min/max TTL are exposed and fixed-TTL OSes give min==max, so this
            # was 100% zero across the 941k-flow eval. Kept for current-mapper
            # compatibility; DROP from REALTIME_SAFE_FEATURES/BEST_FEATURES on retrain.
            flow.udps.std_ttl  = statistics.pstdev(ttl_vals) if len(ttl_vals) >= 2 else 0.0
            flow.udps.max_ttl  = float(max(ttl_vals))
            flow.udps.min_ttl  = float(min(ttl_vals))

        # ── TCP window statistics — derived from transport_size distribution ────
        # NFStream does not expose per-packet TCP window values.
        # We track transport_size changes in on_update; use transport_size
        # min/max/mean (bidirectional) as the window proxy.
        win_vals = []

        # Collect bidirectional transport size range
        for attr in ['bidirectional_min_ps', 'bidirectional_max_ps', 'bidirectional_mean_ps',
                     'src2dst_min_ps', 'src2dst_max_ps', 'src2dst_mean_ps',
                     'dst2src_min_ps', 'dst2src_max_ps', 'dst2src_mean_ps']:
            if hasattr(flow, attr):
                val = getattr(flow, attr, None)
                if val is not None and isinstance(val, (int, float)) and val > 0:
                    win_vals.append(float(val))

        if win_vals:
            flow.udps.mean_window_size   = statistics.mean(win_vals)
            flow.udps.std_window_size    = statistics.pstdev(win_vals) if len(win_vals) >= 2 else 0.0
            flow.udps.max_window_size    = float(max(win_vals))
            flow.udps.min_window_size    = float(min(win_vals))
            flow.udps.median_window_size = statistics.median(win_vals)

        # window_changes uses transport_size transitions computed in on_update
        flow.udps.window_changes = flow.udps.transport_changes

        # Free per-packet lists to keep memory bounded
        flow.udps.piat_list = []

# ─────────────────────────────────────────────────────────────────────────────
# NFStream column → model feature name mapping
# ─────────────────────────────────────────────────────────────────────────────

NFSTREAM_TO_MODEL = {
    # Packet size statistics (bidirectional)
    "bidirectional_mean_ps":      "mean_Length_of_IP_packets",
    "bidirectional_stddev_ps":    "std_Length_of_IP_packets",
    "bidirectional_max_ps":       "max_Length_of_IP_packets",
    "bidirectional_min_ps":       "min_Length_of_IP_packets",
    # Packet size (src→dst direction)
    "src2dst_mean_ps":            "mean_Length_of_TCP_payload",
    "src2dst_stddev_ps":          "std_Length_of_TCP_payload",
    "src2dst_max_ps":             "max_Length_of_TCP_payload",
    "src2dst_min_ps":             "min_Length_of_TCP_payload",
    "src2dst_bytes":              "Length_of_TCP_payload",
    # Bidirectional IAT statistics
    "bidirectional_mean_piat_ms":   "mean_Time_difference_between_packets_per_session",
    "bidirectional_stddev_piat_ms": "std_Time_difference_between_packets_per_session",
    "bidirectional_max_piat_ms":    "max_Time_difference_between_packets_per_session",
    "bidirectional_min_piat_ms":    "min_Time_difference_between_packets_per_session",
    # Forward IAT statistics (src→dst)
    "src2dst_mean_piat_ms":       "mean_Interval_of_arrival_time_of_forward_traffic",
    "src2dst_stddev_piat_ms":     "std_Interval_of_arrival_time_of_forward_traffic",
    "src2dst_max_piat_ms":        "max_Interval_of_arrival_time_of_forward_traffic",
    "src2dst_min_piat_ms":        "min_Interval_of_arrival_time_of_forward_traffic",
    # Backward IAT statistics (dst→src)
    "dst2src_mean_piat_ms":       "mean_Interval_of_arrival_time_of_backward_traffic",
    "dst2src_stddev_piat_ms":     "std_Interval_of_arrival_time_of_backward_traffic",
    "dst2src_max_piat_ms":        "max_Interval_of_arrival_time_of_backward_traffic",
    "dst2src_min_piat_ms":        "min_Interval_of_arrival_time_of_backward_traffic",
    # NFPlugin — median IAT
    "udps.median_piat_ms":        "median_Time_difference_between_packets_per_session",
    # NFPlugin — TTL statistics
    "udps.mean_ttl":              "mean_time_to_live",
    "udps.std_ttl":               "std_time_to_live",
    "udps.max_ttl":               "max_time_to_live",
    "udps.min_ttl":               "min_time_to_live",
    # NFPlugin — TCP window statistics
    "udps.mean_window_size":      "mean_TCP_windows_size_value",
    "udps.std_window_size":       "std_TCP_windows_size_value",
    "udps.max_window_size":       "max_TCP_windows_size_value",
    "udps.min_window_size":       "min_TCP_windows_size_value",
    "udps.median_window_size":    "median_TCP_windows_size_value",
    # NFPlugin — change count features
    "udps.payload_changes":       "The_times_of_change_of_payload_per_session",
    "udps.window_changes":        "Change_values_of_TCP_windows_length_per_session",
}

# Context fields kept alongside model features for SOAR enrichment
CONTEXT_FIELDS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_duration_ms", "bidirectional_packets",
    "application_name", "application_category_name",
    "requested_server_name",
    # TLS fingerprints (NFStream nDPI) → JA3/JA3S observables for Cortex/MISP
    "client_fingerprint", "server_fingerprint",
]


# ─────────────────────────────────────────────────────────────────────────────
# Kafka producer with retry
# ─────────────────────────────────────────────────────────────────────────────

def make_producer(broker: str, retries: int = 10, delay: int = 5) -> KafkaProducer:
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=broker,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks="all",
                retries=3,
            )
            log.info(f"Connected to Kafka at {broker}")
            return producer
        except NoBrokersAvailable:
            log.warning(f"Kafka not ready (attempt {attempt}/{retries}), retrying in {delay}s...")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to Kafka at {broker} after {retries} attempts")


# ─────────────────────────────────────────────────────────────────────────────
# Flow → dict conversion
# ─────────────────────────────────────────────────────────────────────────────

def flow_to_features(flow) -> dict:
    record = {}

    # Model features
    for nf_col, model_col in NFSTREAM_TO_MODEL.items():
        if "." in nf_col:
            attr = nf_col.split(".")[1]
            record[model_col] = getattr(flow.udps, attr, 0.0)
        else:
            record[model_col] = getattr(flow, nf_col, 0.0)

    # Context fields for SOAR enrichment (not used by ML model)
    for field in CONTEXT_FIELDS:
        record[field] = getattr(flow, field, None)

    # Preserve the deterministic NFStream key inside the feature/context payload;
    # the Kafka envelope uses a uuid4 flow_id to match services/producer.
    record["nfstream_flow_id"] = (
        f"{flow.src_ip}:{flow.src_port}-{flow.dst_ip}:{flow.dst_port}"
        f"-{flow.protocol}-{flow.bidirectional_first_seen_ms}"
    )

    return record


def build_payload(features: dict) -> dict:
    payload = {
        "flow_id":    str(uuid.uuid4()),
        "sent_ts":    datetime.now(timezone.utc).isoformat(),
        "true_label": -1,              # live endpoint flows are unlabelled
        "features":   features,
    }
    # Endpoint identity → propagates through inference/translator to the
    # alerts row (NULL-safe; in-stack/replay flows never set these).
    payload["agent_id"] = AGENT_ID
    payload["host_id"]  = HOST_ID
    payload["host_ip"]  = HOST_IP

    return payload


def main():
    log.info(f"Available interfaces: {interfaces}")
    log.info(f"Source      : {SOURCE}")
    log.info(f"BPF filter  : {BPF_FILTER}")
    log.info(f"Kafka broker: {KAFKA_BROKER}  topic: {TOPIC}")
    log.info(f"Timeouts    : idle={IDLE_TIMEOUT}s  active={ACTIVE_TIMEOUT}s")
    log.info(f"Endpoint    : agent_id={AGENT_ID}  host_id={HOST_ID}  host_ip={HOST_IP}")

    producer = make_producer(KAFKA_BROKER)

    streamer = NFStreamer(
        source=SOURCE,
        statistical_analysis=True,
        bpf_filter=BPF_FILTER,
        idle_timeout=IDLE_TIMEOUT,
        active_timeout=ACTIVE_TIMEOUT,
        n_dissections=20,           # nDPI dissection depth — identifies TLS, QUIC etc
        n_meters=0,                 # 0 = auto-scale to available CPU cores
        promiscuous_mode=True,
        udps=ExtendedFlowFeatures(),
        system_visibility_mode=0,   # no kernel socket probing needed in container
        performance_report=60,      # log performance stats every 60s
    )

    flow_count = 0
    error_count = 0

    CSV_FILE = os.getenv("CSV_FILE", "/app/generated_flows/aggregated_flows.csv")
    df = pd.DataFrame()
    header_written = os.path.exists(CSV_FILE) and os.path.getsize(CSV_FILE) > 0

    log.info("Streaming started — waiting for flows...")

    skipped_plaintext = 0
    for flow in streamer:
        try:
            if ENCRYPTED_ONLY and not _is_encrypted(flow):
                skipped_plaintext += 1
                continue
            if not _matches_ioc(flow):
                continue
            features = flow_to_features(flow)
            payload = build_payload(features)
            producer.send(TOPIC, value=payload)

            csv_record = {
                "flow_id": payload["flow_id"],
                "sent_ts": payload["sent_ts"],
                "true_label": payload["true_label"],
                "agent_id": payload["agent_id"],
                "host_id": payload["host_id"],
                "host_ip": payload["host_ip"],
                **features,
            }

            # Update DataFrame in real time
            if df.empty:
                df = pd.DataFrame([csv_record])
            else:
                df.loc[len(df)] = csv_record

            # Append current flow to CSV immediately
            pd.DataFrame([csv_record]).to_csv(
                CSV_FILE,
                mode="a",
                header=not header_written,
                index=False
            )
            header_written = True

            flow_count += 1

            if flow_count % 100 == 0:
                log.info(
                    f"Flows published: {flow_count}  "
                    f"errors: {error_count}  "
                    f"skipped(plaintext): {skipped_plaintext}  "
                    f"last app: {flow.application_name}"
                )

        except Exception as e:
            error_count += 1
            log.warning(f"Failed to publish flow: {e}")

    producer.flush()
    log.info(f"Streaming complete. Total flows: {flow_count}  errors: {error_count}")


if __name__ == "__main__":
    main()