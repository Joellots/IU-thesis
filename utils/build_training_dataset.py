#!/usr/bin/env python3
"""
build_training_dataset.py
─────────────────────────
Builds an NFStream-extracted, labelled training dataset from the PCAP corpus
for retraining the encrypted-malicious-traffic classifier.

It reuses the (bug-fixed) ExtendedFlowFeatures plugin and feature mapping from
utils/nfstream_model_eval.py, so the training features match exactly what the
live nfstream_producer.py service emits.

Labelling strategies (per capture, declared in CAPTURE_MANIFEST):

  all_malicious : every flow → 1  (infected-host captures: CTU-13 botnets,
                  IoT-23 Mirai, ransomware — essentially all traffic is C2/attack)
  all_benign    : every flow → 0  (CTU-Normal browsing captures)
  ioc           : per-flow label by Indicator-of-Compromise match — a flow is
                  malicious iff its dst_ip/src_ip is in `malicious_ips` OR its
                  TLS SNI (requested_server_name) matches `malicious_domains`.
                  Used for MIXED captures (malware-traffic-analysis stealer
                  pcaps) where benign delivery infra (GitHub/Microsoft) and the
                  malware's own C2/exfil share the same capture.
  cicids_csv    : per-5-tuple join to CICIDS-2017 GeneratedLabelledFlows CSV.
                  Stubbed — requires the token-gated GeneratedLabelledFlows.zip
                  (the MachineLearningCVE CSVs lack source/dest IPs). Used for
                  the held-out CICIDS test set, not training.

Output:
    <output>/training_dataset.csv   — model feature columns + true_label +
                                       class + attack_type + source + context
    <output>/dataset_summary.json   — per-class / per-attack_type counts,
                                       feature coverage, balancing record

Usage:
    cd ~/dev && source .env/bin/activate

    # Dry run — show the manifest and what would be extracted
    python3 utils/build_training_dataset.py --dry-run

    # Full training build (balanced, bidirectional flows, encrypted-only)
    python3 utils/build_training_dataset.py \
        --output data/ --min-packets 4 --encrypted-only --balance

    # Quick test on one or two captures
    python3 utils/build_training_dataset.py --only ransomware --max-per-capture 500

Run from ~/dev/ so the pcaps/ paths resolve.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import pandas as pd

# Reuse the exact extraction logic the eval + live service use.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfstream_model_eval import extract_flows, NFSTREAM_TO_MODEL  # noqa: E402

log = logging.getLogger("build")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [build] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

# Encrypted-traffic ports (same set as the producer's BPF filter)
ENCRYPTED_PORTS = {443, 465, 993, 995, 853}

# Model feature columns (the values of the NFSTREAM_TO_MODEL mapping)
MODEL_FEATURES = list(NFSTREAM_TO_MODEL.values())

# Lumma Stealer HTTPS C2 domains (from the 2024-10-03 MTA IOC file) — the only
# genuinely HTTPS-encrypted exfil/C2 in the staged MTA stealer captures.
LUMMA_C2_DOMAINS = {
    "drawzhotdog.shop", "fragnantbui.shop", "ghostreedmnu.shop",
    "gravvitywio.store", "gutterydhowi.shop", "highawaretemptersudwu.xyz",
    "offensivedzvju.shop", "reinforcenh.shop", "stogeneratmns.shop",
    "vozmeatillu.shop",
}


# ─────────────────────────────────────────────────────────────────────────────
# Capture manifest — single source of truth for the corpus + labelling
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: path, class, attack_type, strategy, [role], [enabled], + strategy
# args. class/attack_type drive stratified balancing; role ('train'|'test')
# selects which build a capture belongs to.

CAPTURE_MANIFEST = [

    # ── Class 1: Encrypted C2 beaconing (T1071.001, T1573) ───────────────────
    {"path": "pcaps/malicious/ctu13_botnet42_neris_spam.pcap",
     "class": "c2_beaconing", "attack_type": "botnet_c2", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/ctu13_botnet43_neris2_spam.pcap",
     "class": "c2_beaconing", "attack_type": "botnet_c2", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/ctu13_botnet53_bingowens_https.pcap",
     "class": "c2_beaconing", "attack_type": "botnet_c2_exfil", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/ctu13_botnet54_virut_https_c2.pcap",
     "class": "c2_beaconing", "attack_type": "botnet_c2", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/ctu13_botnet52_encrypted_mixed.pcap",
     "class": "c2_beaconing", "attack_type": "botnet_c2", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/iot23_mirai_cap3_encrypted_c2.pcap",
     "class": "c2_beaconing", "attack_type": "iot_c2", "strategy": "all_malicious"},

    # ── Class 3: Encrypted scan / recon (T1046, T1071) ───────────────────────
    # Short, unidirectional flows — min-packets filter is skipped for this class.
    {"path": "pcaps/malicious/iot23_mirai_cap1_https_scan.pcap",
     "class": "scan", "attack_type": "scan", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/iot23_capture8_small.pcap",
     "class": "scan", "attack_type": "iot_scan", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/iot23_capture20_small.pcap",
     "class": "scan", "attack_type": "iot_scan", "strategy": "all_malicious"},

    # ── Class 4: Ransomware C2 (T1486, T1071.001, T1573) ─────────────────────
    {"path": "pcaps/malicious/ctu_cerber_190_ransomware_c2.pcap",
     "class": "ransomware_c2", "attack_type": "ransomware_c2", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/ctu_locky_214_ransomware_c2.pcap",
     "class": "ransomware_c2", "attack_type": "ransomware_c2", "strategy": "all_malicious"},
    {"path": "pcaps/malicious/ctu_wannacry_252_ransomware.pcap",
     "class": "ransomware_c2", "attack_type": "ransomware_propagation", "strategy": "all_malicious"},

    # ── Class 2: HTTPS exfiltration (minority, hybrid) — MIXED captures ───────
    # Labelled per-IOC. Only Lumma carries HTTPS exfil; StealC/RedLine exfil
    # over HTTP and survive only if --encrypted-only is OFF.
    {"path": "pcaps/mta_stealers/2024-10-03-SmartLoader-to-Lumma-Stealer.pcap",
     "class": "exfil", "attack_type": "exfil_https", "strategy": "ioc",
     "malicious_ips": {"212.193.4.66"}, "malicious_domains": LUMMA_C2_DOMAINS},
    {"path": "pcaps/mta_stealers/2024-10-23-Redline-Stealer-infection-traffic.pcap",
     "class": "exfil", "attack_type": "exfil_http", "strategy": "ioc",
     "malicious_ips": {"188.190.10.10"}, "malicious_domains": set()},
    {"path": "pcaps/mta_stealers/2024-01-12-StealC-infection-traffic.pcap",
     "class": "exfil", "attack_type": "exfil_http", "strategy": "ioc",
     "malicious_ips": {"109.107.181.33"}, "malicious_domains": set()},

    # ── Benign — CTU-Normal browsing captures ────────────────────────────────
    {"path": "pcaps/benign/ctu_normal14_win_full_2017.pcap",
     "class": "benign", "attack_type": "benign", "strategy": "all_benign"},
    {"path": "pcaps/benign/ctu_normal20_win_2017_https.pcap",
     "class": "benign", "attack_type": "benign", "strategy": "all_benign"},
    {"path": "pcaps/benign/ctu_normal21_kali_2017.pcap",
     "class": "benign", "attack_type": "benign", "strategy": "all_benign"},
    {"path": "pcaps/benign/ctu_normal7_general_2013.pcap",
     "class": "benign", "attack_type": "benign", "strategy": "all_benign"},

    # ── CICIDS-2017 — held-out TEST set (per-5-tuple). Disabled here. ─────────
    # Needs the token-gated GeneratedLabelledFlows.zip (MachineLearningCVE CSVs
    # lack IPs). 36 infiltration flows + premium benign. Build separately with
    # --role test once labels are downloaded.
    {"path": "pcaps/cicids2017/cicids2017_thursday_full.pcap",
     "class": "exfil", "attack_type": "infiltration", "strategy": "cicids_csv",
     "role": "test", "enabled": False,
     "label_csvs": ["data/cicids2017_labels/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"]},
]


# ─────────────────────────────────────────────────────────────────────────────
# Labelling strategies
# ─────────────────────────────────────────────────────────────────────────────

def label_all(df: pd.DataFrame, value: int) -> pd.DataFrame:
    df["true_label"] = value
    return df


def label_ioc(df: pd.DataFrame, malicious_ips: set, malicious_domains: set) -> pd.DataFrame:
    """Malicious iff dst_ip/src_ip in malicious_ips OR SNI matches a C2 domain."""
    ips = malicious_ips or set()
    doms = malicious_domains or set()

    ip_mask = df.get("dst_ip", pd.Series(index=df.index, dtype=object)).isin(ips)
    if "src_ip" in df.columns:
        ip_mask = ip_mask | df["src_ip"].isin(ips)

    sni = df.get("requested_server_name", pd.Series(index=df.index, dtype=object)).fillna("")
    dom_mask = sni.apply(lambda s: bool(s) and any(d in s for d in doms))

    df["true_label"] = (ip_mask | dom_mask).astype(int)
    return df


def label_cicids_csv(df: pd.DataFrame, label_csvs: list) -> pd.DataFrame:
    """
    Per-5-tuple join to CICIDS GeneratedLabelledFlows CSVs.

    Requires the GeneratedLabelledFlows variant (has Source IP / Destination IP /
    ports / Protocol / Label). Builds a direction-insensitive 5-tuple → label
    map and applies it. Raises if a CSV is missing so the gap is explicit.
    """
    import csv as _csv

    def canon(sip, sp, dip, dp, proto):
        a, b = (sip, sp), (dip, dp)
        lo, hi = (a, b) if a <= b else (b, a)
        return (lo[0], lo[1], hi[0], hi[1], str(proto))

    label_map = {}
    for path in label_csvs:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"CICIDS label CSV not found: {path}. Download the token-gated "
                f"GeneratedLabelledFlows.zip (MachineLearningCVE lacks IPs)."
            )
        with open(path, encoding="latin-1") as fh:
            r = _csv.DictReader(fh)
            cols = {c.strip(): c for c in r.fieldnames}
            need = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Label"]
            if not all(n in cols for n in need):
                raise ValueError(f"{path} missing 5-tuple columns; got {list(cols)[:8]}…")
            for row in r:
                key = canon(row[cols["Source IP"]].strip(), row[cols["Source Port"]].strip(),
                            row[cols["Destination IP"]].strip(), row[cols["Destination Port"]].strip(),
                            row[cols["Protocol"]].strip())
                label_map[key] = 0 if row[cols["Label"]].strip().upper() == "BENIGN" else 1

    def lookup(row):
        key = canon(str(row.get("src_ip")), str(row.get("src_port")),
                    str(row.get("dst_ip")), str(row.get("dst_port")), row.get("protocol"))
        return label_map.get(key, 0)  # unmatched → benign background

    df["true_label"] = df.apply(lookup, axis=1)
    return df


def apply_labelling(df: pd.DataFrame, entry: dict) -> pd.DataFrame:
    strat = entry["strategy"]
    if strat == "all_malicious":
        return label_all(df, 1)
    if strat == "all_benign":
        return label_all(df, 0)
    if strat == "ioc":
        return label_ioc(df, entry.get("malicious_ips"), entry.get("malicious_domains"))
    if strat == "cicids_csv":
        return label_cicids_csv(df, entry.get("label_csvs", []))
    raise ValueError(f"Unknown strategy: {strat}")


# ─────────────────────────────────────────────────────────────────────────────
# Filtering & balancing
# ─────────────────────────────────────────────────────────────────────────────

def filter_flows(df: pd.DataFrame, min_packets: int, encrypted_only: bool) -> pd.DataFrame:
    n0 = len(df)

    if min_packets > 0 and "bidirectional_packets" in df.columns:
        # Keep short flows for the scan class (scan IS short/unidirectional).
        keep = (df["bidirectional_packets"].fillna(0) >= min_packets) | (df["class"] == "scan")
        df = df[keep]
        log.info(f"  min_packets>={min_packets} (scan exempt): {n0} → {len(df)}")

    if encrypted_only:
        n1 = len(df)
        # Protocol-based TLS detection (matches the source paper's Zeek approach):
        # NFStream's nDPI tags encrypted flows as TLS/SSL/QUIC/DTLS in
        # application_name, catching TLS on non-standard ports that a port filter
        # would miss. Union with the canonical encrypted ports as a fallback.
        app = df.get("application_name", pd.Series(index=df.index, dtype=object)).fillna("").str.upper()
        tls_proto = app.str.contains("TLS|SSL|QUIC|DTLS", regex=True)
        sp = df.get("src_port"); dp = df.get("dst_port")
        port_enc = dp.isin(ENCRYPTED_PORTS) | sp.isin(ENCRYPTED_PORTS)
        df = df[tls_proto | port_enc]
        log.info(f"  encrypted-only (TLS protocol ∪ ports {sorted(ENCRYPTED_PORTS)}): {n1} → {len(df)}")

    return df.reset_index(drop=True)


def balance_dataset(df: pd.DataFrame, per_class_cap: int, balance: bool, seed: int) -> pd.DataFrame:
    n0 = len(df)

    # 1) cap any single class (esp. scan, which can dominate)
    if per_class_cap:
        df = (df.groupby("class", group_keys=False)
                .apply(lambda g: g.sample(n=min(len(g), per_class_cap), random_state=seed)))
        log.info(f"  per_class_cap={per_class_cap}: {n0} → {len(df)}")

    # 2) balance malicious vs benign (downsample the larger side)
    if balance and "true_label" in df.columns:
        mal = df[df["true_label"] == 1]
        ben = df[df["true_label"] == 0]
        target = min(len(mal), len(ben))
        if target > 0:
            # within malicious, sample proportionally across attack_type
            mal_bal = (mal.groupby("attack_type", group_keys=False)
                          .apply(lambda g: g.sample(
                              n=max(1, round(target * len(g) / len(mal))), random_state=seed)))
            if len(mal_bal) > target:
                mal_bal = mal_bal.sample(n=target, random_state=seed)
            ben_bal = ben.sample(n=target, random_state=seed)
            df = pd.concat([mal_bal, ben_bal], ignore_index=True)
            log.info(f"  balance → {target}/class : malicious={len(mal_bal)} benign={len(ben_bal)}")
        else:
            log.warning(f"  balance skipped — one side empty (mal={len(mal)} ben={len(ben)})")

    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

MTA_MANIFEST_PATH = "pcaps/mta/ioc_manifest.json"


def load_mta_captures(manifest_path: str = MTA_MANIFEST_PATH) -> list:
    """
    Convert the fetch_mta_pcaps.py IOC manifest into capture-manifest entries
    (strategy='ioc'). Each MTA capture is a mixed Windows-malware infection pcap
    labelled per published IOC indicators.
    """
    if not os.path.exists(manifest_path):
        return []
    base = os.path.dirname(manifest_path)
    with open(manifest_path) as f:
        manifest = json.load(f)
    out = []
    for fname, meta in manifest.items():
        out.append({
            "path": os.path.join(base, fname),
            "class": meta["class"],                       # c2_beaconing | exfil
            "attack_type": f"mta_{meta['family'].lower()}",
            "strategy": "ioc",
            "malicious_ips": set(meta.get("malicious_ips", [])),
            "malicious_domains": set(meta.get("malicious_domains", [])),
        })
    return out


def select_manifest(role: str, only: str, include_legacy: bool = False) -> list:
    """
    Default training corpus = MTA modern Windows malware (C2 + exfil) + CTU-Normal
    benign. The legacy pure-malicious captures (CTU-13 / IoT-23 / old ransomware,
    strategy='all_malicious') are mostly plaintext / wrong-era and OPT-IN via
    --include-legacy. Benign captures and the CICIDS test set always come from
    CAPTURE_MANIFEST; MTA captures from the IOC manifest.
    """
    full = CAPTURE_MANIFEST + load_mta_captures()
    out = []
    for e in full:
        if not e.get("enabled", True):
            continue
        if e.get("role", "train") != role:
            continue
        # legacy = the old all-malicious pure captures baked into CAPTURE_MANIFEST
        is_legacy = e.get("strategy") == "all_malicious"
        if is_legacy and not include_legacy:
            continue
        if only and only.lower() not in (e["class"] + " " + e["path"]).lower():
            continue
        out.append(e)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", default="data/", help="Output directory (default: data/)")
    ap.add_argument("--role", default="train", choices=["train", "test"],
                    help="Which capture role to build (default: train)")
    ap.add_argument("--only", default="", help="Only captures whose class/path contains this substring")
    ap.add_argument("--min-packets", type=int, default=4,
                    help="Drop flows below N bidirectional packets (scan class exempt). Default: 4")
    ap.add_argument("--encrypted-only", action="store_true",
                    help="Keep only flows on encrypted ports (443/465/993/995/853)")
    ap.add_argument("--per-class-cap", type=int, default=0,
                    help="Max flows per class before balancing (0 = no cap)")
    ap.add_argument("--balance", action="store_true",
                    help="Downsample to 1:1 malicious:benign (attack_type-stratified)")
    ap.add_argument("--max-per-capture", type=int, default=0,
                    help="Cap flows extracted per capture (0 = all). Useful for quick tests.")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--include-legacy", action="store_true",
                    help="Include legacy plaintext CTU-13/IoT-23 pure-malicious captures")
    ap.add_argument("--dry-run", action="store_true", help="Print the manifest and exit")
    args = ap.parse_args()

    manifest = select_manifest(args.role, args.only, args.include_legacy)
    if not manifest:
        log.error("No captures selected — check --role / --only")
        sys.exit(1)

    log.info(f"Selected {len(manifest)} captures (role={args.role})")
    for e in manifest:
        present = "✓" if os.path.exists(e["path"]) else "✗ MISSING"
        log.info(f"  [{present}] {e['class']:14s} {e['strategy']:13s} {e['path']}")

    if args.dry_run:
        return

    frames = []
    for e in manifest:
        if not os.path.exists(e["path"]):
            log.warning(f"Skipping missing capture: {e['path']}")
            continue
        df = extract_flows(e["path"], label=None)
        if args.max_per_capture and len(df) > args.max_per_capture:
            df = df.sample(n=args.max_per_capture, random_state=args.seed).reset_index(drop=True)
        df = apply_labelling(df, e)
        df["class"] = e["class"]
        df["attack_type"] = e["attack_type"]
        df["source"] = os.path.basename(e["path"])
        n_mal = int((df["true_label"] == 1).sum())
        log.info(f"  {os.path.basename(e['path'])[:45]:45s} flows={len(df):>7} malicious={n_mal}")
        frames.append(df)

    df = pd.concat(frames, ignore_index=True)
    log.info(f"\nTotal extracted: {len(df)} flows")

    df = filter_flows(df, args.min_packets, args.encrypted_only)
    df = balance_dataset(df, args.per_class_cap, args.balance, args.seed)

    # ── Output ───────────────────────────────────────────────────────────────
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    keep_cols = (["true_label", "class", "attack_type", "source", "flow_id"]
                 + [c for c in MODEL_FEATURES if c in df.columns]
                 + [c for c in ["src_ip", "dst_ip", "src_port", "dst_port",
                                "protocol", "bidirectional_packets",
                                "requested_server_name"] if c in df.columns])
    out_df = df[keep_cols]
    csv_path = out_dir / "training_dataset.csv"
    out_df.to_csv(csv_path, index=False)

    # ── Summary ──────────────────────────────────────────────────────────────
    summary = {
        "n_flows": len(out_df),
        "n_malicious": int((out_df["true_label"] == 1).sum()),
        "n_benign": int((out_df["true_label"] == 0).sum()),
        "by_class": out_df.groupby("class").size().to_dict(),
        "by_attack_type": out_df.groupby("attack_type").size().to_dict(),
        "by_class_label": {f"{c}/{l}": int(n) for (c, l), n in
                           out_df.groupby(["class", "true_label"]).size().items()},
        "feature_coverage": {f: float((out_df[f] != 0).mean())
                             for f in MODEL_FEATURES if f in out_df.columns},
        "params": {"min_packets": args.min_packets, "encrypted_only": args.encrypted_only,
                   "per_class_cap": args.per_class_cap, "balance": args.balance,
                   "seed": args.seed, "role": args.role},
    }
    with open(out_dir / "dataset_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    log.info("\n" + "═" * 60)
    log.info(f" Training dataset written: {csv_path}")
    log.info("═" * 60)
    log.info(f"  flows={summary['n_flows']}  malicious={summary['n_malicious']}  benign={summary['n_benign']}")
    log.info(f"  by class : {summary['by_class']}")
    log.info(f"  by attack: {summary['by_attack_type']}")


if __name__ == "__main__":
    main()
