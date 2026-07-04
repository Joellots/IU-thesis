#!/usr/bin/env python3
"""
One-off bootstrap: import the MITRE ATT&CK Enterprise STIX bundle into
TheHive's Pattern KB so the SOAR orchestrator can link case procedures
without `404 Pattern not found` errors.

Usage (from thesis repo root, with TheHive running):
  python scripts/seed_thehive_attack_patterns.py

The orchestrator also performs this sync on startup (gated by
SYNC_ATTACK_PATTERNS_TO_THEHIVE=true). Run this script when you want to
bootstrap manually with a different (e.g. admin) API key, or after a
TheHive data wipe, without restarting the orchestrator container.

Reads from .env (UTF-8 BOM-tolerant) so no shell exports are required:
  THEHIVE_BASE_URL      (default: http://127.0.0.1:9000/thehive)
  THEHIVE_API_KEY       (required — needs `managePattern` permission)
  THEHIVE_ORGANISATION  (required for TheHive 5)
  THEHIVE_ATTACK_CATALOG_NAME  (default: "Enterprise ATT&CK")
  ATTACK_STIX_URL       (default: official mitre-attack/attack-stix-data master)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services" / "soar_orchestrator"))


def _load_dotenv_into_os_environ(env_path: Path) -> None:
    if not env_path.exists():
        return
    try:
        text = env_path.read_text(encoding="utf-8-sig")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lstrip("\ufeff")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not key:
            continue
        os.environ.setdefault(key, value)


_load_dotenv_into_os_environ(REPO_ROOT / ".env")

# Host-side default: the orchestrator's compose value points at the in-network
# alias `thehive`, which isn't resolvable from the host. Force the host URL
# unless the user has explicitly overridden it.
os.environ["THEHIVE_BASE_URL"] = os.environ.get(
    "THEHIVE_BASE_URL_HOST",
    "http://127.0.0.1:9000/thehive",
)
# Bundle goes next to this script (orchestrator uses /app/cache inside container).
os.environ.setdefault(
    "ATTACK_STIX_CACHE_PATH",
    str(REPO_ROOT / "cache" / "enterprise-attack.json"),
)
os.environ["ORCHESTRATOR_DRY_RUN"] = "false"

from attack_stix_resolver import ensure_attack_bundle  # noqa: E402
from thehive_client import (  # noqa: E402
    _normalize_secret,
    _thehive_base_url,
    import_attack_patterns,
    thehive_organisation,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        type=Path,
        default=None,
        help="Path to a local STIX 2.1 JSON bundle. Default: download "
             "enterprise-attack.json from mitre-attack/attack-stix-data.",
    )
    parser.add_argument(
        "--catalog",
        default=os.environ.get("THEHIVE_ATTACK_CATALOG_NAME", "Enterprise ATT&CK"),
        help="Catalogue name in TheHive (created if missing).",
    )
    parser.add_argument(
        "--variant",
        default="enterprise",
        help="Catalogue variant tag (default: enterprise).",
    )
    args = parser.parse_args()

    print(f"TheHive: {_thehive_base_url()}")
    print(f"Org:     {thehive_organisation() or '(none — set THEHIVE_ORGANISATION)'}")
    print(f"Catalog: {args.catalog!r} (variant={args.variant!r})")

    if not _normalize_secret(os.environ.get("THEHIVE_API_KEY")):
        print(
            "ERROR: THEHIVE_API_KEY is not set. Put it in .env or export it.",
            file=sys.stderr,
        )
        return 2

    if args.bundle is not None:
        bundle_path = args.bundle
        if not bundle_path.is_file():
            print(f"ERROR: bundle not found at {bundle_path}", file=sys.stderr)
            return 2
        print(f"Bundle:  {bundle_path} (local)")
    else:
        print("Bundle:  downloading enterprise-attack.json (cached)...")
        bundle_path = ensure_attack_bundle()
        print(f"Bundle:  {bundle_path}")

    try:
        result = import_attack_patterns(
            bundle_path,
            catalog=args.catalog,
            variant=args.variant,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("OK ->", result)
    print(
        "\nNext step: restart the orchestrator (or just leave it running) — "
        "future cases will link MITRE procedures successfully."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
