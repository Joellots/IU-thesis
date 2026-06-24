#!/usr/bin/env python3
"""
fetch_pcaps.py
──────────────
Download publicly available PCAP files for Aegis model evaluation.

Sources: CTU-13 Botnets, IoT-23, CTU-Normal — all from the Stratosphere Research
Group / Malware Capture Facility Project (MCFP) at Czech Technical University.
These overlap significantly with the Composed Encrypted Malicious Traffic Dataset
(Sarhan et al. 2021, doi:10.17632/ztyk4h3v6s.2) used in the conference paper.

Traffic is sorted by encrypted content priority:
  high   — confirmed HTTPS/TLS-encrypted C2, exfiltration, or HTTPS-heavy normal
  medium — mixed encrypted + unencrypted traffic
  low    — mostly unencrypted IRC/HTTP C2 (still useful for class balance)

Usage:
    # Dry run — show what would be downloaded and total size
    python3 utils/fetch_pcaps.py --dry-run

    # Download everything (default: tls high+medium, max 500 MB per file)
    python3 utils/fetch_pcaps.py --output-dir pcaps/

    # Malicious only, high TLS priority, cap at 200 MB per file
    python3 utils/fetch_pcaps.py --category malicious --tls high --max-size-mb 200

    # All priorities, parallel downloads
    python3 utils/fetch_pcaps.py --tls high,medium,low --jobs 4

    # Show the full catalog with sizes and metadata
    python3 utils/fetch_pcaps.py --list

Run from ~/dev/ so that the default output path (pcaps/) resolves correctly.
"""

import argparse
import bz2
import hashlib
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [fetch] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# PCAP Catalog
# ─────────────────────────────────────────────────────────────────────────────
#
# tls_priority:
#   "high"   → confirmed HTTPS/TLS-encrypted C2 or HTTPS-heavy benign traffic
#   "medium" → mix of encrypted and unencrypted (HTTP + HTTPS)
#   "low"    → mostly IRC/plaintext HTTP C2 (useful for class balance)
#
# compressed: True → file is .bz2 and will be decompressed after download
# size_mb: approximate — used for --max-size-mb filtering before download starts
# mitre_ttps: relevant ATT&CK technique IDs (empty for benign)
#
# Source: Stratosphere IPS / MCFP (Czech Technical University)
# https://www.stratosphereips.org  |  https://mcfp.felk.cvut.cz/publicDatasets/

_MCFP = "https://mcfp.felk.cvut.cz/publicDatasets"

PCAP_CATALOG = [

    # ── MALICIOUS — HIGH TLS PRIORITY ────────────────────────────────────────
    # Confirmed HTTPS/TLS-encrypted C2 channels

    {
        "name":         "ctu13_botnet54_virut_https",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "botnet_https_c2",
        "tls_priority": "high",
        "description":  "CTU-13 Scenario 12: Virut botnet with HTTPS/TLS encrypted C2 via "
                        "fast-flux DNS. TLS traffic on port 443 to rotating IPs.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-54/"
                        "botnet-capture-20110815-fast-flux-2.pcap",
        "filename":     "ctu13_botnet54_virut_https_c2.pcap",
        "size_mb":      109,
        "compressed":   False,
        "mitre_ttps":   ["T1573", "T1071.001", "T1568.001"],
    },
    {
        "name":         "ctu13_botnet42_neris_spam",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "botnet_spam_https_beaconing",
        "tls_priority": "high",
        "description":  "CTU-13 Scenario 1: Neris spambot — HTTPS beaconing to C2, "
                        "spam relay over port 25/587. Substantial TLS traffic.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-42/"
                        "botnet-capture-20110810-neris.pcap",
        "filename":     "ctu13_botnet42_neris_spam.pcap",
        "size_mb":      56,
        "compressed":   False,
        "mitre_ttps":   ["T1071.001", "T1573", "T1566"],
    },
    {
        "name":         "iot23_mirai_3_encrypted_c2",
        "label":        "malicious",
        "source":       "IoT-23",
        "attack_type":  "iot_botnet_encrypted_c2",
        "tls_priority": "high",
        "description":  "IoT-23 Capture-3: Mirai variant — encrypted C2 communication "
                        "with TLS handshakes. 2018 capture from infected IoT device.",
        "url":          f"{_MCFP}/IoT-23-Dataset/IndividualScenarios/"
                        "CTU-IoT-Malware-Capture-3-1/2018-05-21_capture.pcap",
        "filename":     "iot23_mirai_cap3_encrypted_c2.pcap",
        "size_mb":      55,
        "compressed":   False,
        "mitre_ttps":   ["T1573", "T1071", "T1498"],
    },
    {
        "name":         "ctu13_botnet53_bingowens",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "botnet_https_c2",
        "tls_priority": "high",
        "description":  "CTU-13 Botnet-53: Bingowens — HTTPS-based C2 with encrypted "
                        "exfiltration channels. Confirmed TLS on port 443.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-53/"
                        "botnet-capture-20110819-bot.pcap",
        "filename":     "ctu13_botnet53_bingowens_https.pcap",
        "size_mb":      281,
        "compressed":   False,
        "mitre_ttps":   ["T1573", "T1041", "T1071.001"],
    },

    # ── MALICIOUS — MEDIUM TLS PRIORITY ──────────────────────────────────────
    # Mix of encrypted and unencrypted traffic; HTTPS present but not dominant

    {
        "name":         "ctu13_botnet43_neris2",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "botnet_spam_https_beaconing",
        "tls_priority": "medium",
        "description":  "CTU-13 Scenario 2: Neris botnet second capture — same family "
                        "as Botnet-42 with HTTP/HTTPS spam and C2 beaconing.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-43/"
                        "botnet-capture-20110811-neris.pcap",
        "filename":     "ctu13_botnet43_neris2_spam.pcap",
        "size_mb":      35,
        "compressed":   False,
        "mitre_ttps":   ["T1071.001", "T1566"],
    },
    {
        "name":         "ctu13_botnet52_truncated",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "botnet_encrypted_mixed",
        "tls_priority": "medium",
        "description":  "CTU-13 Botnet-52 (truncated, bz2): encrypted botnet traffic "
                        "with mixed HTTP/HTTPS C2. Decompressed after download.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-52/"
                        "capture20110818-2.truncated.pcap.bz2",
        "filename":     "ctu13_botnet52_encrypted_mixed.pcap",
        "size_mb":      80,
        "compressed":   True,
        "mitre_ttps":   ["T1573", "T1071"],
    },
    {
        "name":         "iot23_mirai_1_https_scan",
        "label":        "malicious",
        "source":       "IoT-23",
        "attack_type":  "iot_botnet_scanning_https",
        "tls_priority": "medium",
        "description":  "IoT-23 Capture-1: Mirai botnet — port 443 scanning, "
                        "HTTPS-based C2 check-in, DDoS. 2018 IoT device capture.",
        "url":          f"{_MCFP}/IoT-23-Dataset/IndividualScenarios/"
                        "CTU-IoT-Malware-Capture-1-1/2018-05-09-192.168.100.103.pcap",
        "filename":     "iot23_mirai_cap1_https_scan.pcap",
        "size_mb":      139,
        "compressed":   False,
        "mitre_ttps":   ["T1046", "T1499", "T1071"],
    },
    {
        "name":         "iot23_capture9_large",
        "label":        "malicious",
        "source":       "IoT-23",
        "attack_type":  "iot_botnet_telnet_mixed",
        "tls_priority": "medium",
        "description":  "IoT-23 Capture-9: IoT botnet — telnet brute-force with mixed "
                        "unencrypted/TLS traffic (5000-packet version for quick eval).",
        "url":          f"{_MCFP}/IoT-23-Dataset/IndividualScenarios/"
                        "CTU-IoT-Malware-Capture-9-1/"
                        "2018-07-25-10-53-16-192.168.100.111-only5000.pcap",
        "filename":     "iot23_capture9_5k_packets.pcap",
        "size_mb":      1,
        "compressed":   False,
        "mitre_ttps":   ["T1110.001", "T1021"],
    },

    # ── MALICIOUS — LOW TLS PRIORITY ─────────────────────────────────────────
    # Mostly plaintext IRC / HTTP C2 — important for class balance in evaluation

    {
        "name":         "ctu13_botnet46_fastflux_http",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "botnet_fastflux_http",
        "tls_priority": "low",
        "description":  "CTU-13 Scenario 5: NSIS.ay fast-flux botnet — HTTP C2 and "
                        "DNS fast-flux. Plaintext HTTP traffic.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-46/"
                        "botnet-capture-20110815-fast-flux.pcap",
        "filename":     "ctu13_botnet46_fastflux_http.pcap",
        "size_mb":      30,
        "compressed":   False,
        "mitre_ttps":   ["T1568.001", "T1071.001"],
    },
    {
        "name":         "ctu13_botnet48_sogou_http",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "spyware_http_exfil",
        "tls_priority": "low",
        "description":  "CTU-13 Scenario 7: Sogou spyware — HTTP-based data exfiltration "
                        "and C2. Maps to T1041 (exfiltration over C2 channel).",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-48/"
                        "botnet-capture-20110816-sogou.pcap",
        "filename":     "ctu13_botnet48_sogou_http_exfil.pcap",
        "size_mb":      18,
        "compressed":   False,
        "mitre_ttps":   ["T1041", "T1071.001"],
    },
    {
        "name":         "ctu13_botnet49_qvod_http",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "adware_http",
        "tls_priority": "low",
        "description":  "CTU-13 Botnet-49: Qvod adware — HTTP-based ad traffic and C2. "
                        "Demonstrates HTTP-over-port-80 exfiltration pattern.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-49/"
                        "botnet-capture-20110816-qvod.pcap",
        "filename":     "ctu13_botnet49_qvod_http.pcap",
        "size_mb":      20,
        "compressed":   False,
        "mitre_ttps":   ["T1071.001"],
    },
    {
        "name":         "ctu13_botnet45_rbot_dos",
        "label":        "malicious",
        "source":       "CTU-13",
        "attack_type":  "botnet_irc_ddos",
        "tls_priority": "low",
        "description":  "CTU-13 Scenario 4: Rbot DDoS — IRC C2 with ICMP flood. "
                        "Small ICMP-only variant (29MB). Unencrypted.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-45/"
                        "botnet-capture-20110815-rbot-dos-icmp.pcap",
        "filename":     "ctu13_botnet45_rbot_dos_icmp.pcap",
        "size_mb":      29,
        "compressed":   False,
        "mitre_ttps":   ["T1498", "T1071.003"],
    },
    {
        "name":         "iot23_capture8_small",
        "label":        "malicious",
        "source":       "IoT-23",
        "attack_type":  "iot_botnet",
        "tls_priority": "low",
        "description":  "IoT-23 Capture-8: Small IoT botnet capture (2MB). "
                        "Useful as a lightweight test file for NFStream evaluation.",
        "url":          f"{_MCFP}/IoT-23-Dataset/IndividualScenarios/"
                        "CTU-IoT-Malware-Capture-8-1/"
                        "2018-07-31-15-15-09-192.168.100.113.pcap",
        "filename":     "iot23_capture8_small.pcap",
        "size_mb":      2,
        "compressed":   False,
        "mitre_ttps":   ["T1071"],
    },
    {
        "name":         "iot23_capture20_small",
        "label":        "malicious",
        "source":       "IoT-23",
        "attack_type":  "iot_malware",
        "tls_priority": "low",
        "description":  "IoT-23 Capture-20: Small IoT malware capture (3.9MB). "
                        "Quick sanity-check file for the eval pipeline.",
        "url":          f"{_MCFP}/IoT-23-Dataset/IndividualScenarios/"
                        "CTU-IoT-Malware-Capture-20-1/"
                        "2018-10-02-13-12-30-192.168.100.103.pcap",
        "filename":     "iot23_capture20_small.pcap",
        "size_mb":      4,
        "compressed":   False,
        "mitre_ttps":   ["T1071"],
    },

    # ── MALICIOUS — RANSOMWARE C2 (attack class 4) ───────────────────────────
    # Encrypted/HTTP(S) C2 from real ransomware infections. T1486 (Data
    # Encrypted for Impact) + T1071 C2. Sourced from Stratosphere/MCFP.

    {
        "name":         "ctu_cerber_190_ransomware_c2",
        "label":        "malicious",
        "source":       "CTU-Ransomware",
        "attack_type":  "ransomware_c2",
        "tls_priority": "high",
        "description":  "CTU Botnet-190-1: Cerber ransomware (via trojanised Ammyy "
                        "Remote Admin). HTTP/HTTPS C2 with mitm-intercepted web traffic. "
                        "Small, clean — primary ransomware-C2 sample.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-190-1/"
                        "2016-09-28_capture_win17.pcap",
        "filename":     "ctu_cerber_190_ransomware_c2.pcap",
        "size_mb":      14,
        "compressed":   False,
        "mitre_ttps":   ["T1486", "T1071.001", "T1573"],
    },
    {
        "name":         "ctu_locky_214_ransomware_c2",
        "label":        "malicious",
        "source":       "CTU-Ransomware",
        "attack_type":  "ransomware_c2",
        "tls_priority": "high",
        "description":  "CTU Botnet-214-1: Trojan.Locky ransomware. HTTP/HTTPS C2 with "
                        "mitm.weblog documenting encrypted web traffic. Larger capture "
                        "with sustained C2 sessions.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-214-1/"
                        "2016-12-30_win12.pcap",
        "filename":     "ctu_locky_214_ransomware_c2.pcap",
        "size_mb":      259,
        "compressed":   False,
        "mitre_ttps":   ["T1486", "T1071.001", "T1573"],
    },
    {
        "name":         "ctu_wannacry_252_ransomware",
        "label":        "malicious",
        "source":       "CTU-Ransomware",
        "attack_type":  "ransomware_propagation",
        "tls_priority": "low",
        "description":  "CTU Botnet-252-1: WannaCry — reached killswitch (no file "
                        "encryption) but still attempted network propagation. Small "
                        "named-family sample; traffic is SMB/scan-heavy, not HTTPS.",
        "url":          f"{_MCFP}/CTU-Malware-Capture-Botnet-252-1/"
                        "2017-05-14_win10.pcap",
        "filename":     "ctu_wannacry_252_ransomware.pcap",
        "size_mb":      1,
        "compressed":   False,
        "mitre_ttps":   ["T1486", "T1210", "T1071"],
    },

    # ── BENIGN — HIGH TLS PRIORITY ────────────────────────────────────────────
    # Windows machines with real-world HTTPS/TLS browsing traffic

    {
        "name":         "ctu_normal20_win_2017_https",
        "label":        "benign",
        "source":       "CTU-Normal",
        "attack_type":  None,
        "tls_priority": "high",
        "description":  "CTU Normal-20: Windows machine normal traffic (April 2017). "
                        "Contains HTTPS browsing, TLS handshakes, and typical user activity.",
        "url":          f"{_MCFP}/CTU-Normal-20/2017-04-30_win-normal.pcap",
        "filename":     "ctu_normal20_win_2017_https.pcap",
        "size_mb":      269,
        "compressed":   False,
        "mitre_ttps":   [],
    },
    {
        "name":         "ctu_normal14_win_full_2017",
        "label":        "benign",
        "source":       "CTU-Normal",
        "attack_type":  None,
        "tls_priority": "high",
        "description":  "CTU Normal-14: Windows full capture (July 2017). "
                        "Rich HTTPS/TLS traffic from a corporate Windows workstation.",
        "url":          f"{_MCFP}/CTU-Normal-14/2017-07-23_capture-winFull.pcap",
        "filename":     "ctu_normal14_win_full_2017.pcap",
        "size_mb":      403,
        "compressed":   False,
        "mitre_ttps":   [],
    },
    {
        "name":         "ctu_normal21_kali_2017",
        "label":        "benign",
        "source":       "CTU-Normal",
        "attack_type":  None,
        "tls_priority": "high",
        "description":  "CTU Normal-21: Kali Linux normal traffic (May 2017). "
                        "HTTPS-heavy developer/security-research normal activity.",
        "url":          f"{_MCFP}/CTU-Normal-21/2017-05-02_kali-normal.pcap",
        "filename":     "ctu_normal21_kali_2017.pcap",
        "size_mb":      297,
        "compressed":   False,
        "mitre_ttps":   [],
    },

    # ── BENIGN — MEDIUM TLS PRIORITY ─────────────────────────────────────────

    {
        "name":         "ctu_normal7_general_2013",
        "label":        "benign",
        "source":       "CTU-Normal",
        "attack_type":  None,
        "tls_priority": "medium",
        "description":  "CTU Normal-7: General network capture (2013). Older traffic "
                        "with mixed HTTP/HTTPS. Useful for temporal diversity.",
        "url":          f"{_MCFP}/CTU-Normal-7/2013-12-17_capture1.pcap",
        "filename":     "ctu_normal7_general_2013.pcap",
        "size_mb":      398,
        "compressed":   False,
        "mitre_ttps":   [],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Priority mapping
# ─────────────────────────────────────────────────────────────────────────────

TLS_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# PCAP magic bytes (little-endian and big-endian pcap, pcapng)
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_mb(mb: float) -> str:
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb:.0f} MB"


def _is_valid_pcap(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic in PCAP_MAGIC
    except OSError:
        return False


def _progress_bar(done: int, total: int, width: int = 40) -> str:
    if total <= 0:
        return f"{done // (1024 * 1024)} MB downloaded"
    pct = done / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"|{bar}| {pct * 100:5.1f}%  {done // (1024 * 1024)}/{total // (1024 * 1024)} MB"


def download_file(
    url: str,
    dest: Path,
    expected_size_mb: Optional[int] = None,
    max_size_mb: Optional[int] = None,
) -> bool:
    """
    Download url to dest with progress reporting.
    Supports HTTP range resume if dest already exists (partial download).
    Returns True on success.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")

    resume_pos = 0
    if tmp.exists():
        resume_pos = tmp.stat().st_size
        log.info(f"Resuming from byte {resume_pos:,}: {dest.name}")

    headers = {}
    if resume_pos > 0:
        headers["Range"] = f"bytes={resume_pos}-"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            total = int(resp.getheader("Content-Length", 0))
            if resume_pos > 0 and resp.status == 206:
                total += resume_pos  # Content-Length is the remaining bytes
            elif resp.status == 200:
                resume_pos = 0       # Server ignored Range — start fresh

            if max_size_mb and total > 0 and total > max_size_mb * 1024 * 1024:
                log.warning(
                    f"Skipping {dest.name}: server reports {total // (1024*1024)} MB "
                    f"which exceeds --max-size-mb {max_size_mb}"
                )
                return False

            mode = "ab" if resume_pos > 0 else "wb"
            downloaded = resume_pos
            last_report = time.time()

            with open(tmp, mode) as f:
                while True:
                    chunk = resp.read(1024 * 256)  # 256 KB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    now = time.time()
                    if now - last_report >= 2.0:
                        bar = _progress_bar(downloaded, total)
                        print(f"\r  {bar}", end="", flush=True)
                        last_report = now

            print()  # newline after progress bar

    except urllib.error.HTTPError as exc:
        log.error(f"HTTP {exc.code} fetching {url}: {exc.reason}")
        return False
    except (urllib.error.URLError, OSError) as exc:
        log.error(f"Download failed for {url}: {exc}")
        return False

    tmp.rename(dest)
    return True


def decompress_bz2(src: Path, dest: Path) -> bool:
    """Decompress a .bz2 PCAP file to dest, removing src on success."""
    log.info(f"Decompressing {src.name} → {dest.name}")
    try:
        with bz2.open(src, "rb") as fin, open(dest, "wb") as fout:
            written = 0
            while True:
                chunk = fin.read(1024 * 1024)  # 1 MB
                if not chunk:
                    break
                fout.write(chunk)
                written += len(chunk)
                print(f"\r  Decompressed: {written // (1024*1024)} MB", end="", flush=True)
        print()
        src.unlink()
        return True
    except (OSError, EOFError) as exc:
        log.error(f"Decompression failed for {src}: {exc}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Core fetch logic
# ─────────────────────────────────────────────────────────────────────────────

def _filter_catalog(
    catalog: list,
    categories: set,
    tls_priorities: set,
    max_size_mb: Optional[int],
) -> list:
    filtered = [
        e for e in catalog
        if e["label"] in categories
        and e["tls_priority"] in tls_priorities
        and (max_size_mb is None or e["size_mb"] <= max_size_mb)
    ]
    # Sort: benign first within each priority, then by tls_priority, then size ascending
    filtered.sort(key=lambda e: (
        TLS_PRIORITY_ORDER[e["tls_priority"]],
        0 if e["label"] == "benign" else 1,
        e["size_mb"],
    ))
    return filtered


def fetch_one(entry: dict, output_dir: Path, max_size_mb: Optional[int], force: bool) -> dict:
    """Download and optionally decompress a single catalog entry. Returns a result dict."""
    label_dir = output_dir / entry["label"]
    label_dir.mkdir(parents=True, exist_ok=True)

    final_path = label_dir / entry["filename"]
    url = entry["url"]
    compressed = entry["compressed"]

    # If compressed, download to a .bz2 temp name first
    download_dest = final_path.with_name(final_path.name + ".bz2") if compressed else final_path

    result = {
        "name":      entry["name"],
        "label":     entry["label"],
        "tls":       entry["tls_priority"],
        "attack":    entry.get("attack_type"),
        "source":    entry["source"],
        "path":      str(final_path),
        "url":       url,
        "status":    "pending",
        "size_bytes": None,
    }

    # Skip if already present and valid
    if final_path.exists() and not force:
        if _is_valid_pcap(final_path):
            log.info(f"[skip] {entry['filename']} already downloaded and valid")
            result["status"] = "skipped"
            result["size_bytes"] = final_path.stat().st_size
            return result
        else:
            log.warning(f"[invalid] {entry['filename']} exists but failed PCAP magic check — re-downloading")
            final_path.unlink(missing_ok=True)

    log.info(f"[download] {entry['filename']}  ({_fmt_mb(entry['size_mb'])})  [{entry['tls_priority']} TLS]")
    log.info(f"  URL: {url}")

    ok = download_file(url, download_dest, expected_size_mb=entry["size_mb"], max_size_mb=max_size_mb)
    if not ok:
        result["status"] = "failed"
        return result

    if compressed:
        ok = decompress_bz2(download_dest, final_path)
        if not ok:
            result["status"] = "decompress_failed"
            return result

    if not _is_valid_pcap(final_path):
        log.warning(f"[warn] {entry['filename']}: PCAP magic bytes check failed — file may be corrupt")
        result["status"] = "invalid_pcap"
    else:
        result["status"] = "ok"

    result["size_bytes"] = final_path.stat().st_size if final_path.exists() else None
    return result


def fetch_all(
    catalog: list,
    output_dir: Path,
    categories: set,
    tls_priorities: set,
    max_size_mb: Optional[int],
    jobs: int,
    force: bool,
    dry_run: bool,
) -> list:
    selected = _filter_catalog(catalog, categories, tls_priorities, max_size_mb)

    total_mb = sum(e["size_mb"] for e in selected)
    log.info(
        f"Selected {len(selected)} files  |  estimated {_fmt_mb(total_mb)}  |  "
        f"categories={categories}  tls={tls_priorities}  max={max_size_mb}MB"
    )

    if dry_run:
        _print_table(selected, header="DRY RUN — files that would be downloaded")
        return []

    if jobs > 1:
        results = []
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = {
                pool.submit(fetch_one, entry, output_dir, max_size_mb, force): entry
                for entry in selected
            }
            for fut in as_completed(futures):
                results.append(fut.result())
    else:
        results = [fetch_one(e, output_dir, max_size_mb, force) for e in selected]

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_table(entries: list, header: str = "PCAP Catalog") -> None:
    TLS_COLOUR = {"high": "\033[92m", "medium": "\033[93m", "low": "\033[90m"}
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    print(f"\n{BOLD}{header}{RESET}")
    print(f"{'#':<4} {'Label':<10} {'TLS':<8} {'~Size':<10} {'Source':<12} {'Name'}")
    print("─" * 90)
    total_mb = 0
    for i, e in enumerate(entries, 1):
        colour = TLS_COLOUR.get(e["tls_priority"], "")
        print(
            f"{i:<4} {e['label']:<10} "
            f"{colour}{e['tls_priority']:<8}{RESET} "
            f"{_fmt_mb(e['size_mb']):<10} "
            f"{e['source']:<12} "
            f"{e['name']}"
        )
        total_mb += e["size_mb"]
    print("─" * 90)
    print(f"{'Total':<34} {_fmt_mb(total_mb)}")
    print()


def _print_results(results: list) -> None:
    STATUS_COLOUR = {
        "ok":               "\033[92m",
        "skipped":          "\033[94m",
        "failed":           "\033[91m",
        "decompress_failed":"\033[91m",
        "invalid_pcap":     "\033[93m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    ok      = [r for r in results if r["status"] in ("ok", "skipped")]
    failed  = [r for r in results if r["status"] not in ("ok", "skipped")]

    print(f"\n{BOLD}Download Summary{RESET}")
    print(f"{'Status':<20} {'TLS':<8} {'Label':<10} {'Name'}")
    print("─" * 70)
    for r in sorted(results, key=lambda x: (x["status"] != "ok", x["label"])):
        colour = STATUS_COLOUR.get(r["status"], "")
        print(f"{colour}{r['status']:<20}{RESET} {r['tls']:<8} {r['label']:<10} {r['name']}")
    print("─" * 70)
    print(f"  Succeeded: {len(ok)}   Failed: {len(failed)}")

    total_bytes = sum(r["size_bytes"] or 0 for r in ok)
    if total_bytes:
        print(f"  Total on disk: {_fmt_mb(total_bytes / (1024 * 1024))}")
    print()


def _save_manifest(results: list, output_dir: Path) -> None:
    manifest_path = output_dir / "download_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(
            {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "files": results,
            },
            f,
            indent=2,
        )
    log.info(f"Manifest written to {manifest_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--output-dir", "-o", default="pcaps/",
        help="Root output directory. Subdirs malicious/ and benign/ are created automatically. "
             "Default: pcaps/ (relative to current working directory — run from ~/dev/).",
    )
    p.add_argument(
        "--category", "-c", default="all",
        choices=["all", "malicious", "benign"],
        help="Which traffic class to download. Default: all.",
    )
    p.add_argument(
        "--tls", "-t", default="high,medium",
        help="Comma-separated TLS priority levels to include: high, medium, low. "
             "Default: 'high,medium' (skips low-priority unencrypted captures).",
    )
    p.add_argument(
        "--max-size-mb", "-m", type=int, default=500,
        help="Skip files whose estimated size exceeds this threshold (MB). "
             "Default: 500. Set to 0 to disable the limit.",
    )
    p.add_argument(
        "--jobs", "-j", type=int, default=1,
        help="Number of parallel download threads. Default: 1 (sequential).",
    )
    p.add_argument(
        "--force", "-f", action="store_true",
        help="Re-download files that already exist on disk.",
    )
    p.add_argument(
        "--dry-run", "-n", action="store_true",
        help="Print what would be downloaded without downloading anything.",
    )
    p.add_argument(
        "--list", "-l", action="store_true",
        help="Print the full catalog (all entries, no filters) and exit.",
    )
    return p.parse_args()


def main():
    args = parse_args()

    if args.list:
        _print_table(PCAP_CATALOG, header=f"Full PCAP Catalog ({len(PCAP_CATALOG)} entries)")
        return

    output_dir = Path(args.output_dir)
    categories = {"malicious", "benign"} if args.category == "all" else {args.category}
    tls_priorities = set(t.strip() for t in args.tls.split(",") if t.strip())
    max_size_mb = args.max_size_mb if args.max_size_mb > 0 else None

    invalid_tls = tls_priorities - {"high", "medium", "low"}
    if invalid_tls:
        log.error(f"Unknown TLS priority value(s): {invalid_tls}. Use high, medium, or low.")
        sys.exit(1)

    results = fetch_all(
        catalog=PCAP_CATALOG,
        output_dir=output_dir,
        categories=categories,
        tls_priorities=tls_priorities,
        max_size_mb=max_size_mb,
        jobs=args.jobs,
        force=args.force,
        dry_run=args.dry_run,
    )

    if results:
        _print_results(results)
        _save_manifest(results, output_dir)


if __name__ == "__main__":
    main()
