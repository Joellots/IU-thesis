"""
Resolve TheHive ↔ Cortex integration settings (server id, API health, defaults).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

from thehive_client import (
    _headers,
    _normalize_secret,
    _orchestrator_dry_run,
    _thehive_base_url,
)

# ── Cortex analyzer catalogue ────────────────────────────────────────────────
#
# Analyzers are grouped in two tiers to make the thesis setup reproducible:
#   Tier-0: runs with no external API key (good baseline; always-on).
#   Tier-1: needs a free API key (signup links in
#           docs/CORTEX_ANALYZERS_AND_RESPONDERS.md). Activated only if the
#           corresponding *_API_KEY env var is set when running
#           scripts/setup_soar_integrations.py.
#
# The DEFAULT_*_ANALYZERS lists below are the runtime fall-back used by the
# orchestrator when the CORTEX_*_ANALYZERS env vars are unset. They include
# both tiers; the SOAR is happy to attempt analyzers Cortex hasn't enabled
# (they short-circuit as "Analyzer not found" without raising).

TIER0_IP_ANALYZERS = [
    "Abuse_Finder_3_0",
    "DShield_lookup_1_0",
    "Cyberprotect_ThreatScore_3_0",
]
TIER0_DOMAIN_ANALYZERS = [
    "Abuse_Finder_3_0",
    "GoogleDNS_resolve_1_0_0",
    "Cyberprotect_ThreatScore_3_0",
]
TIER0_URL_ANALYZERS = [
    "Abuse_Finder_3_0",
    "UnshortenLink_1_2",
    "Cyberprotect_ThreatScore_3_0",
]
TIER0_HASH_ANALYZERS = [
    "CIRCLHashlookup_1_1",
    "Cyberprotect_ThreatScore_3_0",
]

TIER1_IP_ANALYZERS = [
    "MaxMind_GeoIP_4_0",
    "Maltiverse_Report_1_0",
    "Urlscan_io_Search_0_1_1",
    "VirusTotal_GetReport_3_1",
    "URLhaus_2_0",
    "MISP_2_1",
]
TIER1_DOMAIN_ANALYZERS = [
    "Maltiverse_Report_1_0",
    "Urlscan_io_Search_0_1_1",
    "VirusTotal_GetReport_3_1",
    "URLhaus_2_0",
    "MISP_2_1",
]
TIER1_URL_ANALYZERS = [
    "Urlscan_io_Search_0_1_1",
    "VirusTotal_GetReport_3_1",
    "URLhaus_2_0",
    "MISP_2_1",
]
TIER1_HASH_ANALYZERS = [
    "VirusTotal_GetReport_3_1",
    "URLhaus_2_0",
    "MISP_2_1",
]

# JA3/JA3S TLS-fingerprint correlation (SYSTEM_OVERVIEW.md §5.1) is MISP-only —
# no Tier-0 (no-key) analyzer does fingerprint lookups, so there is no
# TIER0_JA3_ANALYZERS list.
TIER1_JA3_ANALYZERS = [
    "MISP_2_1",
]

# Tier-1 analyzers and the env var / Cortex configuration key they need.
# Used by scripts/setup_soar_integrations.py to inject the key during activation.
# URLhaus moved to Tier-1 in 2023 when abuse.ch added free API authentication
# (sign up at https://auth.abuse.ch/).
#
# Most entries use {"env": "...", "field": "..."} for a single credential.
# MISP_2_1 uses {"multi": True, "fields": {...}, "defaults": {...}} because
# Cortex expects url + key (+ cert_check) in the activation payload.
TIER1_ANALYZER_CREDENTIALS: Dict[str, Dict[str, Any]] = {
    "MaxMind_GeoIP_4_0":       {"env": "MAXMIND_LICENSE_KEY",  "field": "license_key"},
    "Maltiverse_Report_1_0":   {"env": "MALTIVERSE_API_KEY",   "field": "service_key"},
    "Urlscan_io_Search_0_1_1": {"env": "URLSCAN_API_KEY",      "field": "key"},
    "VirusTotal_GetReport_3_1": {"env": "VIRUSTOTAL_API_KEY",  "field": "key"},
    "URLhaus_2_0":             {"env": "URLHAUS_API_KEY",      "field": "API_Key"},
    "MISP_2_1": {
        "multi": True,
        "fields": {
            "url": "MISP_URL",
            "key": "MISP_API_KEY",
        },
        "optional_fields": {
            "name": "MISP_NAME",
        },
        "defaults": {
            "cert_check": False,
        },
    },
}

DEFAULT_IP_ANALYZERS = TIER0_IP_ANALYZERS + TIER1_IP_ANALYZERS
DEFAULT_DOMAIN_ANALYZERS = TIER0_DOMAIN_ANALYZERS + TIER1_DOMAIN_ANALYZERS
DEFAULT_URL_ANALYZERS = TIER0_URL_ANALYZERS + TIER1_URL_ANALYZERS
DEFAULT_HASH_ANALYZERS = TIER0_HASH_ANALYZERS + TIER1_HASH_ANALYZERS
DEFAULT_JA3_ANALYZERS = list(TIER1_JA3_ANALYZERS)

# Responders commonly used for case automation (enable in Cortex org via setup script).
# Kept intentionally small + non-destructive for the thesis demo.
# Responders ────────────────────────────────────────────────────────────────
#
# Cortex's responder catalog (3.1.x, ~140 entries) is dominated by third-party
# integrations (Palo Alto, MS Defender, CrowdStrike, etc.); there is no
# built-in `AddTagToCase`-style responder — case tagging happens inside
# TheHive itself via task automation, not via Cortex.
#
# For thesis reproducibility we keep ONLY the no-credential responders in
# code. Anything that needs secrets (SMTP, bot tokens, API keys) is enabled
# directly in the Cortex UI under Organization → Responders, so secrets do
# not have to live in .env files or container environments.
TIER0_RESPONDERS = [
    "DevTools_Echo_Responder_1_0",  # echoes case payload back as a job report
    "Test_1_0",                     # always-succeeds smoke test
]

DEFAULT_RESPONDERS = list(TIER0_RESPONDERS)

_resolved_cortex_id: Optional[str] = None


def tier1_activation_config(analyzer_name: str) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Build the Cortex activation `configuration` extras for a Tier-1 analyzer.

    Returns ``(extra_config, None)`` when all required env vars are set,
    or ``(None, skip_reason)`` when activation should be skipped.
    """
    spec = TIER1_ANALYZER_CREDENTIALS.get(analyzer_name)
    if not spec:
        return {}, None

    if spec.get("multi"):
        extra: Dict[str, Any] = dict(spec.get("defaults") or {})
        missing: List[str] = []
        for field, env_var in spec.get("fields", {}).items():
            value = os.getenv(env_var, "").strip()
            if not value:
                missing.append(env_var)
            else:
                extra[field] = value
        for field, env_var in spec.get("optional_fields", {}).items():
            value = os.getenv(env_var, "").strip()
            if value:
                extra[field] = value
        cert_check_env = os.getenv("MISP_CERT_CHECK", "").strip().lower()
        if analyzer_name == "MISP_2_1" and cert_check_env in ("true", "1", "yes"):
            extra["cert_check"] = True
        elif analyzer_name == "MISP_2_1" and cert_check_env in ("false", "0", "no"):
            extra["cert_check"] = False
        if missing:
            return None, f"env {', '.join(missing)} not set"
        if analyzer_name == "MISP_2_1":
            for field in ("url", "key", "name"):
                if field in extra and not isinstance(extra[field], list):
                    extra[field] = [extra[field]]
        return extra, None

    env_var = spec.get("env", "")
    field = spec.get("field", "")
    key_value = os.getenv(env_var, "").strip()
    if not key_value:
        return None, f"env {env_var} not set"
    return {field: key_value}, None


def analyzers_from_env(var_name: str, defaults: List[str]) -> List[str]:
    raw = os.getenv(var_name, "").strip()
    if not raw:
        return list(defaults)
    return [s.strip() for s in raw.split(",") if s.strip()]


def get_configured_analyzers() -> Dict[str, List[str]]:
    return {
        "ip": analyzers_from_env("CORTEX_IP_ANALYZERS", DEFAULT_IP_ANALYZERS),
        "domain": analyzers_from_env("CORTEX_DOMAIN_ANALYZERS", DEFAULT_DOMAIN_ANALYZERS),
        "url": analyzers_from_env("CORTEX_URL_ANALYZERS", DEFAULT_URL_ANALYZERS),
        "hash": analyzers_from_env("CORTEX_HASH_ANALYZERS", DEFAULT_HASH_ANALYZERS),
        "ja3": analyzers_from_env("CORTEX_JA3_ANALYZERS", DEFAULT_JA3_ANALYZERS),
    }


def _extract_servers(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        servers = payload.get("servers")
        if isinstance(servers, list):
            return [s for s in servers if isinstance(s, dict)]
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get("servers"), list):
            return [s for s in data["servers"] if isinstance(s, dict)]
    return []


def fetch_thehive_cortex_server_id() -> Optional[str]:
    """Read Cortex connector id/name from TheHive admin config."""
    api_key = _normalize_secret(os.getenv("THEHIVE_API_KEY"))
    if _orchestrator_dry_run() or not api_key:
        return None

    endpoints = (
        "/api/v1/admin/config/cortex",
        "/api/config/cortex",
    )
    for endpoint in endpoints:
        url = f"{_thehive_base_url()}{endpoint}"
        try:
            resp = requests.get(url, headers=_headers(), timeout=20)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        for server in _extract_servers(resp.json()):
            for key in ("id", "_id", "name"):
                value = server.get(key)
                if value:
                    return str(value)
    return None


def fetch_cortex_id_from_connector_listing() -> Optional[str]:
    """Fallback: parse cortexId from connector analyzer listing."""
    api_key = _normalize_secret(os.getenv("THEHIVE_API_KEY"))
    if _orchestrator_dry_run() or not api_key:
        return None
    url = f"{_thehive_base_url()}/api/connector/cortex/analyzer"
    try:
        resp = requests.get(url, headers=_headers(), timeout=20)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    data = resp.json()
    items: List[Any] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("data", "items", "analyzers"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
    for item in items:
        if isinstance(item, dict):
            for key in ("cortexId", "cortexServerId", "serverId"):
                if item.get(key):
                    return str(item[key])
    return None


def resolve_thehive_cortex_id(force_refresh: bool = False) -> Optional[str]:
    global _resolved_cortex_id
    if not force_refresh and _resolved_cortex_id:
        return _resolved_cortex_id

    explicit = os.getenv("THEHIVE_CORTEX_ID", "").strip()
    if explicit:
        _resolved_cortex_id = explicit
        return _resolved_cortex_id

    discovered = fetch_thehive_cortex_server_id() or fetch_cortex_id_from_connector_listing()
    _resolved_cortex_id = discovered
    return discovered


def validate_integration_settings() -> Dict[str, Any]:
    """Return a status dict used at orchestrator startup."""
    from cortex_client import CortexClient

    thehive_key = _normalize_secret(os.getenv("THEHIVE_API_KEY"))
    cortex_key = _normalize_secret(os.getenv("CORTEX_API_KEY"))
    cortex_base = os.getenv("CORTEX_BASE_URL", "http://host.docker.internal:9001/cortex")

    cortex_id = resolve_thehive_cortex_id()
    status: Dict[str, Any] = {
        "thehive_base_url": _thehive_base_url(),
        "thehive_api_key_set": bool(thehive_key),
        "cortex_base_url": cortex_base,
        "cortex_api_key_set": bool(cortex_key),
        "thehive_cortex_id": cortex_id,
        "analyzers": get_configured_analyzers(),
        "cortex_analyzers_enabled": 0,
        "warnings": [],
    }

    if not thehive_key:
        status["warnings"].append("THEHIVE_API_KEY is not set")
    if not cortex_key:
        status["warnings"].append("CORTEX_API_KEY is not set — direct Cortex analyzer runs will fail")
    if not cortex_id:
        status["warnings"].append(
            "THEHIVE_CORTEX_ID not set and could not be discovered — responder actions may fail"
        )

    if not _orchestrator_dry_run() and cortex_key:
        try:
            client = CortexClient()
            enabled = client.list_enabled_analyzers()
            status["cortex_analyzers_enabled"] = len(enabled)
            if not enabled:
                status["warnings"].append(
                    "No analyzers enabled in Cortex — run scripts/setup_soar_integrations.py"
                )
        except Exception as exc:
            status["warnings"].append(f"Cortex unreachable: {exc}")

    return status
