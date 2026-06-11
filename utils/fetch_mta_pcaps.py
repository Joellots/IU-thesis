#!/usr/bin/env python3
"""
fetch_mta_pcaps.py
──────────────────
Batch-download real Windows-malware traffic captures from
malware-traffic-analysis.net (MTA) and auto-generate a per-flow labelling
manifest from each capture's PUBLISHED IOC file.

Why: MTA captures are real, modern, Windows, HTTPS-C2 malware traffic — the
right platform/encryption match for this project — but each capture is a MIXED
infection pcap (victim-host benign background + a few malicious C2/exfil flows),
so it needs per-flow labelling. MTA publishes an IOC text file per capture; we
download it, extract the malicious IPs/domains, and write them to a manifest
that build_training_dataset.py consumes (strategy="ioc").

For each dated entry the fetcher:
  1. fetches the day's index page and auto-discovers the *.pcap.zip and
     *IOCs*.txt.zip links (filenames vary, so we don't hard-code them);
  2. downloads both and extracts them (password = infected_YYYYMMDD);
  3. parses the IOC text into malicious_ips / malicious_domains, skipping
     analyst-annotated-benign lines and known benign infrastructure;
  4. copies the pcap to <out>/ and records an entry in ioc_manifest.json.

Usage:
    cd ~/dev && source .env/bin/activate
    python3 utils/fetch_mta_pcaps.py --out pcaps/mta/ --jobs 3
    python3 utils/fetch_mta_pcaps.py --list          # show curated entries
    python3 utils/fetch_mta_pcaps.py --only c2        # only one class

Output:
    <out>/<family>_<date>.pcap          # the capture
    <out>/ioc_manifest.json             # {pcap: {malicious_ips, malicious_domains, class, family, date}}
"""

import argparse
import json
import logging
import os
import re
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [mta] %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

BASE = "https://www.malware-traffic-analysis.net"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/133.0.0.0 Safari/537.36")

# ── Curated entries (DATE only — filenames auto-discovered) ──────────────────
# class ∈ {c2_beaconing, exfil, ransomware}. Families chosen for HTTPS C2/exfil
# on Windows hosts. Expand freely — only the date + class/family tags are needed.
MTA_ENTRIES = [
    # ── Info-stealer / exfil (HTTPS POST/PUT of stolen data) — T1041 ─────────
    {"date": "2024/10/03", "family": "Lumma",      "klass": "exfil"},
    {"date": "2024/09/19", "family": "Lumma",      "klass": "exfil"},
    {"date": "2024/06/24", "family": "Lumma",      "klass": "exfil"},
    {"date": "2024/03/07", "family": "Lumma",      "klass": "exfil"},
    {"date": "2023/10/11", "family": "Lumma",      "klass": "exfil"},
    {"date": "2024/01/12", "family": "StealC",     "klass": "exfil"},
    {"date": "2024/03/06", "family": "Meduza",     "klass": "exfil"},
    {"date": "2024/10/23", "family": "RedLine",    "klass": "exfil"},
    {"date": "2024/10/07", "family": "RedLine",    "klass": "exfil"},
    {"date": "2023/03/02", "family": "RedLine",    "klass": "exfil"},
    {"date": "2023/02/03", "family": "RedLine",    "klass": "exfil"},
    {"date": "2024/12/04", "family": "AgentTesla", "klass": "exfil"},
    {"date": "2024/06/10", "family": "AgentTesla", "klass": "exfil"},
    {"date": "2023/12/13", "family": "AgentTesla", "klass": "exfil"},
    {"date": "2023/11/22", "family": "AgentTesla", "klass": "exfil"},
    {"date": "2023/07/07", "family": "AgentTesla", "klass": "exfil"},
    {"date": "2024/09/17", "family": "SnakeKeylogger", "klass": "exfil"},
    {"date": "2024/09/16", "family": "SnakeKeylogger", "klass": "exfil"},
    {"date": "2024/08/12", "family": "XLoader",    "klass": "exfil"},
    {"date": "2023/11/29", "family": "XLoader",    "klass": "exfil"},
    {"date": "2023/06/13", "family": "XLoader",    "klass": "exfil"},
    {"date": "2023/06/21", "family": "XLoader",    "klass": "exfil"},
    {"date": "2024/10/07", "family": "Formbook",   "klass": "exfil"},
    {"date": "2023/12/11", "family": "Astaroth",   "klass": "exfil"},
    {"date": "2023/01/04", "family": "Astaroth",   "klass": "exfil"},
    {"date": "2023/01/03", "family": "Rhadamanthys", "klass": "exfil"},
    {"date": "2023/09/25", "family": "AgentTesla", "klass": "exfil"},
    {"date": "2023/01/05", "family": "AgentTesla", "klass": "exfil"},
    {"date": "2023/04/13", "family": "Metastealer", "klass": "exfil"},
    {"date": "2023/07/11", "family": "XLoader",    "klass": "exfil"},
    {"date": "2024/06/12", "family": "KoiStealer", "klass": "exfil"},
    {"date": "2024/09/11", "family": "XLoader",    "klass": "exfil"},
    # 2025 — Lumma/StealC dominate, HTTPS exfil
    {"date": "2025/12/30", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/09/24", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/09/03", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/08/15", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/08/13", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/07/15", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/07/02", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/06/26", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/02/13", "family": "Lumma",  "klass": "exfil"},
    {"date": "2025/12/22", "family": "StealC", "klass": "exfil"},
    {"date": "2025/08/20", "family": "StealC", "klass": "exfil"},
    {"date": "2025/06/18", "family": "StealC", "klass": "exfil"},
    {"date": "2025/05/22", "family": "StealC", "klass": "exfil"},
    {"date": "2025/09/05", "family": "XLoader", "klass": "exfil"},
    {"date": "2025/08/11", "family": "XLoader", "klass": "exfil"},
    {"date": "2025/01/30", "family": "XLoader", "klass": "exfil"},
    {"date": "2025/07/08", "family": "KoiStealer", "klass": "exfil"},
    {"date": "2025/06/21", "family": "KoiStealer", "klass": "exfil"},
    {"date": "2025/01/23", "family": "KoiStealer", "klass": "exfil"},
    {"date": "2025/10/01", "family": "Rhadamanthys", "klass": "exfil"},
    {"date": "2025/02/10", "family": "Strela", "klass": "exfil"},
    {"date": "2025/01/31", "family": "AgentTesla", "klass": "exfil"},

    # ── C2 beaconing (loaders / RATs / Cobalt Strike over TLS) — T1071 ───────
    {"date": "2024/04/18", "family": "CobaltStrike", "klass": "c2_beaconing"},
    {"date": "2024/04/09", "family": "Latrodectus",  "klass": "c2_beaconing"},
    {"date": "2024/02/23", "family": "Latrodectus",  "klass": "c2_beaconing"},
    {"date": "2024/02/08", "family": "Pikabot",      "klass": "c2_beaconing"},
    {"date": "2024/05/14", "family": "DarkGate",     "klass": "c2_beaconing"},
    {"date": "2024/01/30", "family": "DarkGate",     "klass": "c2_beaconing"},
    {"date": "2024/08/26", "family": "Remcos",       "klass": "c2_beaconing"},
    {"date": "2024/03/14", "family": "AsyncRAT",     "klass": "c2_beaconing"},
    {"date": "2024/02/14", "family": "Danabot",      "klass": "c2_beaconing"},
    {"date": "2023/08/03", "family": "Danabot",      "klass": "c2_beaconing"},
    # IcedID (Bokbot)
    {"date": "2023/11/27", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2023/10/31", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2023/09/28", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2023/08/31", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2023/07/25", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2023/05/10", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2023/03/24", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2023/01/12", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2022/12/20", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2022/10/31", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2022/08/18", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2022/07/06", "family": "IcedID", "klass": "c2_beaconing"},
    {"date": "2022/01/12", "family": "IcedID", "klass": "c2_beaconing"},
    # Qakbot (Qbot)
    {"date": "2023/05/24", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2023/05/10", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2023/04/12", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2023/03/31", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2023/02/27", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2022/12/09", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2022/11/14", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2022/09/29", "family": "Qakbot", "klass": "c2_beaconing"},
    {"date": "2022/06/27", "family": "Qakbot", "klass": "c2_beaconing"},
    # Pikabot
    {"date": "2023/12/15", "family": "Pikabot", "klass": "c2_beaconing"},
    {"date": "2023/11/02", "family": "Pikabot", "klass": "c2_beaconing"},
    {"date": "2023/10/03", "family": "Pikabot", "klass": "c2_beaconing"},
    {"date": "2023/05/23", "family": "Pikabot", "klass": "c2_beaconing"},
    # DarkGate
    {"date": "2023/12/07", "family": "DarkGate", "klass": "c2_beaconing"},
    {"date": "2023/11/20", "family": "DarkGate", "klass": "c2_beaconing"},
    {"date": "2023/10/25", "family": "DarkGate", "klass": "c2_beaconing"},
    {"date": "2023/10/04", "family": "DarkGate", "klass": "c2_beaconing"},
    # Emotet
    {"date": "2023/03/22", "family": "Emotet", "klass": "c2_beaconing"},
    {"date": "2023/03/17", "family": "Emotet", "klass": "c2_beaconing"},
    {"date": "2022/11/07", "family": "Emotet", "klass": "c2_beaconing"},
    {"date": "2022/07/07", "family": "Emotet", "klass": "c2_beaconing"},
    {"date": "2022/04/25", "family": "Emotet", "klass": "c2_beaconing"},
    # BumbleBee
    {"date": "2022/12/07", "family": "BumbleBee", "klass": "c2_beaconing"},
    {"date": "2022/06/14", "family": "BumbleBee", "klass": "c2_beaconing"},
    {"date": "2022/05/18", "family": "BumbleBee", "klass": "c2_beaconing"},
    # Gozi/ISFB, Remcos, GootLoader
    {"date": "2023/07/12", "family": "Gozi",       "klass": "c2_beaconing"},
    {"date": "2023/06/26", "family": "Remcos",     "klass": "c2_beaconing"},
    {"date": "2023/05/29", "family": "Remcos",     "klass": "c2_beaconing"},
    {"date": "2023/12/29", "family": "GootLoader",  "klass": "c2_beaconing"},
]

# Benign infrastructure + analysis/reference sites — substrings that, if matched,
# exclude an IOC indicator (these appear in IOC files as context, not as C2).
BENIGN_INFRA = {
    # OS / CDN / cert / connectivity infra
    "microsoft", "windows", "msn.com", "msftncsi", "msedge", "bing.com", "live.com",
    "office", "github", "githubusercontent", "google", "gstatic", "googleapis",
    "gvt1", "gvt2", "mozilla", "firefox", "cloudflare-dns", "akamai", "digicert",
    "ip-api.com", "api.ip.sb", "ipify", "wtfismyip", "icanhazip", "checkip",
    "apple.com", "gandi", "verisign", "sectigo", "letsencrypt", "ocsp", "ntp.org",
    "amazontrust", "windowsupdate", "office365", "skype", "t.me", "telegram",
    # threat-intel / sandbox / analysis references (NOT C2 — cited in IOC files)
    "abuse.ch", "malpedia", "fraunhofer", "fkie", "virustotal", "tria.ge",
    "any.run", "joesandbox", "hybrid-analysis", "urlhaus", "threatfox", "bazaar",
    "twitter.com", "x.com", "linkedin", "researchgate", "unit42",
    "paloaltonetworks", "github.io", "shodan", "censys", "alienvault", "otx",
}

# Plausible public TLDs — domains ending in anything else (e.g. filename
# fragments win.stealc / att.file / sample.iso) are rejected as non-domains.
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "tv", "cc", "ws", "pw",
    "xyz", "top", "shop", "store", "online", "site", "website", "space", "fun",
    "club", "vip", "icu", "cfd", "sbs", "bond", "monster", "live", "tech", "app",
    "dev", "pro", "men", "gdn", "link", "click", "stream", "download", "host",
    "ru", "su", "cn", "br", "in", "us", "uk", "de", "fr", "nl", "eu", "pl", "it",
    "es", "ua", "cz", "ro", "tr", "ir", "kz", "ng", "za", "jp", "kr", "hk", "tw",
    "asia", "world", "life", "today", "art", "cloud", "digital", "network", "one",
}

# Lines whose presence flags an indicator as analyst-marked benign.
BENIGN_ANNOTATIONS = ("not inherently", "not malicious", "legitimate", "benign",
                      "not bad", "ip address check", "ip check", "not c2",
                      "connectivity check", "ip lookup")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
NON_DOMAIN_TLDS = {"exe", "dll", "zip", "php", "json", "txt", "bat", "js", "html",
                   "htm", "png", "gif", "jpg", "bin", "dat", "ps1", "vbs", "lnk", "rrd"}


def _get(url: str, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read() if binary else r.read().decode("utf-8", "replace")


def discover_links(date: str):
    """Return (pcap_zip_urls, ioc_zip_url|None) from the day's index page."""
    idx = f"{BASE}/{date}/index.html"
    html = _get(idx)
    hrefs = re.findall(r'href="([^"]+)"', html, re.I)
    pcaps, ioc = [], None
    for h in hrefs:
        hl = h.lower()
        full = h if h.startswith("http") else f"{BASE}/{date}/{h.lstrip('/')}"
        if hl.endswith(".pcap.zip"):
            pcaps.append(full)
        elif "ioc" in hl and hl.endswith(".txt.zip"):
            ioc = full
    return pcaps, ioc


def download_extract_zip(url: str, pw: bytes, dest_dir: Path):
    """Download a password zip, extract members, return list of extracted paths."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_dir / os.path.basename(url)
    tmp.write_bytes(_get(url, binary=True))
    out = []
    with zipfile.ZipFile(tmp) as z:
        for name in z.namelist():
            if name.endswith("/"):
                continue
            z.extract(name, path=dest_dir, pwd=pw)
            out.append(dest_dir / name)
    tmp.unlink(missing_ok=True)
    return out


def parse_iocs(text: str):
    """Extract malicious IPs and domains from an MTA IOC text file."""
    mal_ips, mal_domains = set(), set()
    for line in text.splitlines():
        low = line.lower()
        if any(a in low for a in BENIGN_ANNOTATIONS):
            continue
        for ip in IP_RE.findall(line):
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets) and not ip.startswith(("10.", "192.168.", "127.")):
                if not any(b in low for b in BENIGN_INFRA):
                    mal_ips.add(ip)
        for dom in DOMAIN_RE.findall(line):
            dl = dom.lower()
            tld = dl.rsplit(".", 1)[-1]
            if tld in NON_DOMAIN_TLDS or tld not in COMMON_TLDS:
                continue  # filename fragment or implausible TLD
            if any(b in dl for b in BENIGN_INFRA):
                continue
            mal_domains.add(dl)
    return sorted(mal_ips), sorted(mal_domains)


def fetch_entry(entry: dict, out_dir: Path):
    date = entry["date"]
    pw = f"infected_{date.replace('/', '')}".encode()
    tag = f"{entry['family']}_{date.replace('/', '-')}"
    result = {"tag": tag, "class": entry["klass"], "family": entry["family"],
              "date": date, "status": "pending", "pcaps": []}
    try:
        pcap_urls, ioc_url = discover_links(date)
        if not pcap_urls:
            result["status"] = "no_pcap"
            return result
        if not ioc_url:
            result["status"] = "no_ioc"
            log.warning(f"{tag}: no IOC file — skipping (can't label)")
            return result

        staging = out_dir / ".staging" / tag
        ioc_files = download_extract_zip(ioc_url, pw, staging)
        ioc_text = "\n".join(p.read_text("latin-1", "replace") for p in ioc_files
                             if p.suffix == ".txt")
        mal_ips, mal_domains = parse_iocs(ioc_text)

        for i, purl in enumerate(pcap_urls):
            pfiles = download_extract_zip(purl, pw, staging)
            for pf in pfiles:
                if pf.suffix != ".pcap":
                    continue
                final = out_dir / (f"{tag}.pcap" if len(pcap_urls) == 1 and i == 0
                                   else f"{tag}_{i}.pcap")
                final.write_bytes(pf.read_bytes())
                result["pcaps"].append({
                    "filename": final.name,
                    "malicious_ips": mal_ips,
                    "malicious_domains": mal_domains,
                })
        # cleanup staging
        for p in staging.glob("*"):
            p.unlink(missing_ok=True) if p.is_file() else None
        result["status"] = "ok" if result["pcaps"] else "no_pcap_member"
        log.info(f"{tag}: ok — {len(result['pcaps'])} pcap(s), "
                 f"{len(mal_ips)} IPs, {len(mal_domains)} domains")
    except Exception as e:  # noqa: BLE001 — never let one capture sink the batch
        result["status"] = f"error: {type(e).__name__}"
        log.error(f"{tag}: {type(e).__name__}: {e}")
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="pcaps/mta/", help="Output directory")
    ap.add_argument("--only", default="", help="Only entries whose class/family contains this")
    ap.add_argument("--jobs", type=int, default=3, help="Parallel downloads")
    ap.add_argument("--list", action="store_true", help="List curated entries and exit")
    args = ap.parse_args()

    entries = [e for e in MTA_ENTRIES
               if not args.only or args.only.lower() in (e["klass"] + " " + e["family"]).lower()]

    if args.list:
        for e in entries:
            print(f"  {e['date']}  {e['klass']:13s} {e['family']}")
        print(f"\n{len(entries)} entries")
        return

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    log.info(f"Fetching {len(entries)} MTA captures → {out_dir}")

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(fetch_entry, e, out_dir): e for e in entries}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:  # noqa: BLE001
                ent = futs[f]
                log.error(f"{ent['family']}_{ent['date']}: unhandled {type(e).__name__}: {e}")

    # Build IOC manifest consumed by build_training_dataset.py.
    # MERGE into any existing manifest so partial re-runs (e.g. --only exfil)
    # don't drop entries fetched in previous runs (e.g. c2_beaconing).
    manifest_path = out_dir / "ioc_manifest.json"
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError:
            manifest = {}
    for r in results:
        if r["status"] != "ok":
            continue
        for p in r["pcaps"]:
            manifest[p["filename"]] = {
                "class": r["class"], "family": r["family"], "date": r["date"],
                "malicious_ips": p["malicious_ips"],
                "malicious_domains": p["malicious_domains"],
            }
    manifest_path.write_text(json.dumps(manifest, indent=2))

    # cleanup staging dir
    staging = out_dir / ".staging"
    if staging.exists():
        import shutil
        shutil.rmtree(staging, ignore_errors=True)

    ok = [r for r in results if r["status"] == "ok"]
    log.info("\n" + "═" * 60)
    log.info(f" Fetched {len(ok)}/{len(results)} captures → {out_dir}/ioc_manifest.json")
    for r in sorted(results, key=lambda x: x["status"] != "ok"):
        log.info(f"  {r['status']:18s} {r['class']:13s} {r['tag']}")


if __name__ == "__main__":
    main()
