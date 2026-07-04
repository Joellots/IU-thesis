#!/usr/bin/env python3
"""
Bootstrap Cortex analyzers/responders and print SOAR integration env values.

Usage (from thesis repo root, with TheHive+Cortex stack running):
  python scripts/setup_soar_integrations.py

Requires Cortex admin credentials (defaults match thehive_external testing stack).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services" / "soar_orchestrator"))


def _load_dotenv_into_os_environ(env_path: Path) -> None:
    """Lightweight `.env` loader so this script works the same way as docker-compose.

    Skips lines that are blank or comments. Strips UTF-8 BOM, surrounding
    quotes, and the optional `export ` prefix. Does NOT overwrite variables
    that are already in the process environment.
    """
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
_load_dotenv_into_os_environ(REPO_ROOT / "services" / "soar_orchestrator" / ".env")

from integration_config import (  # noqa: E402
    DEFAULT_DOMAIN_ANALYZERS,
    DEFAULT_HASH_ANALYZERS,
    DEFAULT_IP_ANALYZERS,
    DEFAULT_URL_ANALYZERS,
    TIER0_DOMAIN_ANALYZERS,
    TIER0_HASH_ANALYZERS,
    TIER0_IP_ANALYZERS,
    TIER0_RESPONDERS,
    TIER0_URL_ANALYZERS,
    TIER1_ANALYZER_CREDENTIALS,
    TIER1_DOMAIN_ANALYZERS,
    TIER1_HASH_ANALYZERS,
    TIER1_IP_ANALYZERS,
    TIER1_URL_ANALYZERS,
    fetch_thehive_cortex_server_id,
    tier1_activation_config,
)

DEFAULT_CORTEX_URL = "http://127.0.0.1:9001/cortex"
DEFAULT_THEHIVE_URL = "http://127.0.0.1:9000/thehive"


def _cortex_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}{path}"


def cortex_request(
    base: str,
    method: str,
    path: str,
    *,
    auth: tuple[str, str] | None = None,
    bearer: str | None = None,
    json_body: Any = None,
) -> requests.Response:
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return requests.request(
        method,
        _cortex_url(base, path),
        auth=auth,
        headers=headers,
        json=json_body,
        timeout=60,
    )


def resolve_cortex_api_key(cortex_base: str, admin_user: str, admin_pass: str) -> str:
    """
    Cortex 4 often disables renew/set key APIs. Prefer CORTEX_API_KEY from env, then renew.
    """
    env_key = os.getenv("CORTEX_API_KEY", "").strip()
    if env_key:
        print("Using CORTEX_API_KEY from environment.")
        return env_key

    resp = cortex_request(
        cortex_base,
        "POST",
        "/api/user/thehive/key/renew",
        auth=(admin_user, admin_pass),
        json_body={},
    )
    if resp.status_code in (200, 201):
        key = resp.text.strip().strip('"')
        if not key and resp.text:
            try:
                data = resp.json()
                key = str(data.get("key") or data.get("apiKey") or "")
            except Exception:
                key = ""
        if key:
            return key

    raise RuntimeError(
        "Could not obtain a Cortex API key automatically (renew/set disabled on Cortex 4). "
        "Create one in the Cortex UI: log in as thehive → profile → API keys → Create, "
        "then set CORTEX_API_KEY in .env and re-run this script."
    )


def _find_org_analyzer_id(
    cortex_base: str,
    bearer: Optional[str],
    name: str,
    admin_basic_auth: Optional[tuple[str, str]],
) -> Optional[str]:
    """Return the instance ID of an already-enabled org analyzer, or None."""
    for auth_kwargs in (
        {"bearer": bearer} if bearer else {},
        {"auth": admin_basic_auth} if admin_basic_auth else {},
    ):
        if not auth_kwargs:
            continue
        resp = cortex_request(cortex_base, "GET", "/api/organization/analyzer", **auth_kwargs)
        if resp.status_code == 200:
            try:
                items = resp.json()
                if not isinstance(items, list):
                    items = items.get("data", [])
                for item in items:
                    if item.get("name") == name or item.get("workerDefinitionId") == name:
                        return item.get("id") or item.get("_id")
            except Exception:
                pass
    return None


def activate_analyzer(
    cortex_base: str,
    bearer: str,
    name: str,
    *,
    extra_config: Optional[Dict[str, Any]] = None,
    admin_basic_auth: Optional[tuple[str, str]] = None,
) -> tuple[bool, str]:
    """Activate one analyzer in the current Cortex organisation.

    Uses the supplied API key (Bearer) which is how Cortex 4/5 expects modern
    integrations to authenticate. Falls back to admin basic-auth on 401 only
    when the caller provides it (kept for backwards compatibility with the
    testing stack defaults).

    Returns (ok, message). `extra_config` is merged into the analyzer
    configuration block — used for Tier-1 analyzers that require an API key.
    """
    config: Dict[str, Any] = {
        "auto_extract_artifacts": False,
        "check_tlp": True,
        "max_tlp": 2,
        "check_pap": True,
        "max_pap": 2,
    }
    if extra_config:
        config.update(extra_config)

    payload = {
        "name": name,
        "configuration": config,
        "jobCache": 10,
        "jobTimeout": 30,
    }
    resp = cortex_request(
        cortex_base,
        "POST",
        f"/api/organization/analyzer/{name}",
        bearer=bearer,
        json_body=payload,
    )
    if resp.status_code in (200, 201, 204):
        return True, "activated"
    body = resp.text or ""
    # Cortex returns 400 ConflictError when the analyzer is already enabled.
    # Delete the existing instance and re-POST so the latest config is always applied.
    if resp.status_code == 400 and ("ConflictError" in body or "already exists" in body):
        instance_id = _find_org_analyzer_id(cortex_base, bearer, name, admin_basic_auth)
        if instance_id:
            del_resp = cortex_request(
                cortex_base, "DELETE", f"/api/organization/analyzer/{instance_id}",
                bearer=bearer,
            )
            if del_resp.status_code not in (200, 204) and admin_basic_auth:
                del_resp = cortex_request(
                    cortex_base, "DELETE", f"/api/organization/analyzer/{instance_id}",
                    auth=admin_basic_auth,
                )
            if del_resp.status_code in (200, 204):
                re_resp = cortex_request(
                    cortex_base, "POST", f"/api/organization/analyzer/{name}",
                    bearer=bearer, json_body=payload,
                )
                if re_resp.status_code in (200, 201, 204):
                    return True, "updated (delete+recreate)"
        return True, "already enabled (config not updated — delete failed)"
    if resp.status_code == 401 and admin_basic_auth:
        resp = cortex_request(
            cortex_base,
            "POST",
            f"/api/organization/analyzer/{name}",
            auth=admin_basic_auth,
            json_body=payload,
        )
        if resp.status_code in (200, 201, 204):
            return True, "activated (via admin basic-auth)"
        body = resp.text or ""
        if resp.status_code == 400 and ("ConflictError" in body or "already exists" in body):
            instance_id = _find_org_analyzer_id(cortex_base, None, name, admin_basic_auth)
            if instance_id:
                del_resp = cortex_request(
                    cortex_base, "DELETE", f"/api/organization/analyzer/{instance_id}",
                    auth=admin_basic_auth,
                )
                if del_resp.status_code in (200, 204):
                    re_resp = cortex_request(
                        cortex_base, "POST", f"/api/organization/analyzer/{name}",
                        auth=admin_basic_auth, json_body=payload,
                    )
                    if re_resp.status_code in (200, 201, 204):
                        return True, "updated (delete+recreate via admin auth)"
            return True, "already enabled (config not updated — delete failed)"
    return False, f"{resp.status_code} {body[:200]}"


def activate_responder(
    cortex_base: str,
    bearer: str,
    name: str,
    *,
    extra_config: Optional[Dict[str, Any]] = None,
    admin_basic_auth: Optional[tuple[str, str]] = None,
) -> tuple[bool, str]:
    """Activate one responder in the current Cortex organisation.

    Mirrors `activate_analyzer`: tries Bearer first, falls back to admin basic
    auth on 401, treats ConflictError as success. `extra_config` is merged
    into the responder configuration block — used for Tier-1 responders that
    require credentials (SMTP, bot tokens, etc.).
    """
    config: Dict[str, Any] = {
        "check_tlp": True,
        "max_tlp": 2,
        "check_pap": True,
        "max_pap": 2,
    }
    if extra_config:
        config.update(extra_config)

    payload = {"name": name, "configuration": config}

    resp = cortex_request(
        cortex_base,
        "POST",
        f"/api/organization/responder/{name}",
        bearer=bearer,
        json_body=payload,
    )
    if resp.status_code in (200, 201, 204):
        return True, "activated"
    body = resp.text or ""
    if resp.status_code == 400 and ("ConflictError" in body or "already exists" in body):
        return True, "already enabled"
    if resp.status_code == 401 and admin_basic_auth:
        resp = cortex_request(
            cortex_base,
            "POST",
            f"/api/organization/responder/{name}",
            auth=admin_basic_auth,
            json_body=payload,
        )
        if resp.status_code in (200, 201, 204):
            return True, "activated (via admin basic-auth)"
        body = resp.text or ""
        if resp.status_code == 400 and ("ConflictError" in body or "already exists" in body):
            return True, "already enabled"
    return False, f"{resp.status_code} {body[:200]}"


def list_cortex_catalog(
    cortex_base: str,
    bearer: str,
    kind: str,
    *,
    admin_basic_auth: Optional[tuple[str, str]] = None,
) -> List[str]:
    resp = cortex_request(cortex_base, "GET", f"/api/{kind}", bearer=bearer)
    if resp.status_code != 200 and admin_basic_auth:
        resp = cortex_request(cortex_base, "GET", f"/api/{kind}", auth=admin_basic_auth)
    if resp.status_code != 200:
        return []
    data = resp.json()
    items = data if isinstance(data, list) else data.get("data") or []
    names = []
    for item in items:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names


def _fetch_responder_catalog_names(
    cortex_base: str,
    bearer: str,
    *,
    admin_basic: Optional[tuple[str, str]] = None,
) -> List[Dict[str, str]]:
    """Pull the FULL responder definition catalog (every responder Cortex knows
    about, whether activated or not). Returns a list of dicts with `name` and
    `version`.

    Cortex 3.1.x splits these: `/api/responderdefinition` is the catalog,
    `/api/organization/responder` (or `/api/responder`) is what's been
    activated in the current org. We need the former so we can resolve names
    like `Mailer_1_0` -> ('Mailer', '1.0') before activation.
    """
    resp = cortex_request(cortex_base, "GET", "/api/responderdefinition", bearer=bearer)
    if resp.status_code != 200 and admin_basic:
        resp = cortex_request(cortex_base, "GET", "/api/responderdefinition", auth=admin_basic)
    if resp.status_code != 200:
        return []
    data = resp.json()
    items = data if isinstance(data, list) else data.get("data") or []
    out: List[Dict[str, str]] = []
    for it in items:
        if isinstance(it, dict) and it.get("name"):
            out.append({"name": str(it["name"]), "version": str(it.get("version") or "")})
    return out


def _responder_in_catalog(activation_id: str, catalog: List[Dict[str, str]]) -> bool:
    """Returns True if `activation_id` (e.g. `Mailer_1_0`) matches some entry
    in the catalog. The catalog stores name+version separately; we accept a
    match either on full id (`{name}_{version_with_underscores}`) or on just
    the bare name (some Cortex builds expose the id directly).
    """
    for entry in catalog:
        if entry["name"] == activation_id:
            return True
        ver = entry["version"].replace(".", "_")
        if f"{entry['name']}_{ver}" == activation_id:
            return True
    return False


def configure_thehive_cortex_connector(
    thehive_base: str,
    thehive_user: str,
    thehive_pass: str,
    cortex_url_for_thehive: str,
    cortex_api_key: str,
    server_name: str = "Cortex",
) -> str:
    """
    Register Cortex in TheHive admin config.
    Use the Docker-internal URL (http://cortex:9001/cortex) when TheHive runs in the
    thehive_external compose network, not host.docker.internal.
    Returns the configured server name (used as cortexId in responder actions).

    Returns the server name even when the configuration call is rejected by a
    license/quota error (TheHive 5 free tier caps Cortex servers at 0). In that
    case the caller is expected to have configured the connector manually in
    the UI; the SOAR will still discover it at runtime via
    `integration_config.resolve_thehive_cortex_id()`.
    """
    url = f"{thehive_base.rstrip('/')}/api/v1/admin/config/cortex"
    payload = {
        "statusCheckInterval": "1 minute",
        "refreshDelay": "5 seconds",
        "maxRetryOnError": 3,
        "jobTimeout": "3 hours",
        "servers": [
            {
                "name": server_name,
                "url": cortex_url_for_thehive.rstrip("/"),
                "includedTheHiveOrganisations": ["*"],
                "excludedTheHiveOrganisations": [],
                "auth": {"type": "bearer", "key": cortex_api_key},
            }
        ],
    }
    resp = requests.put(
        url,
        json=payload,
        auth=(thehive_user, thehive_pass),
        headers={"Content-Type": "application/json"},
        timeout=60,
    )
    if resp.status_code in (200, 204):
        return server_name

    body = (resp.text or "")[:300]
    # TheHive 5 free tier: BadConfigurationError "quota for cortex: the limit is 0"
    if resp.status_code == 400 and ("quota" in body.lower() or "BadConfigurationError" in body):
        print(
            "  ! TheHive Cortex connector NOT updated: license quota = 0 for Cortex servers.\n"
            "    The script will assume the connector was configured manually in the UI\n"
            f"    under name '{server_name}'. Set THEHIVE_CORTEX_ID in .env if it differs."
        )
        return server_name
    if resp.status_code in (401, 403):
        print(
            f"  ! TheHive Cortex connector NOT updated: {resp.status_code} {body}\n"
            "    Check THEHIVE_ADMIN_USER/THEHIVE_ADMIN_PASSWORD or run with --skip-thehive-config."
        )
        return server_name
    raise RuntimeError(f"TheHive Cortex config failed: {resp.status_code} {resp.text}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap SOAR Cortex/TheHive integration")
    parser.add_argument("--cortex-url", default=os.getenv("CORTEX_BASE_URL", DEFAULT_CORTEX_URL))
    parser.add_argument("--thehive-url", default=os.getenv("THEHIVE_BASE_URL", DEFAULT_THEHIVE_URL))
    parser.add_argument("--cortex-admin-user", default=os.getenv("CORTEX_ADMIN_USER", "admin"))
    parser.add_argument("--cortex-admin-password", default=os.getenv("CORTEX_ADMIN_PASSWORD", "thehive1234"))
    parser.add_argument("--thehive-admin-user", default=os.getenv("THEHIVE_ADMIN_USER", "admin@thehive.local"))
    parser.add_argument("--thehive-admin-password", default=os.getenv("THEHIVE_ADMIN_PASSWORD", "secret"))
    parser.add_argument(
        "--thehive-cortex-url",
        default=os.getenv("THEHIVE_CORTEX_URL", "http://cortex:9001/cortex"),
        help="URL TheHive containers use to reach Cortex (Docker service name)",
    )
    parser.add_argument("--skip-thehive-config", action="store_true")
    parser.add_argument("--skip-activate", action="store_true")
    args = parser.parse_args()

    print(f"Cortex: {args.cortex_url}")
    print(f"TheHive: {args.thehive_url}")

    cortex_key = resolve_cortex_api_key(
        args.cortex_url, args.cortex_admin_user, args.cortex_admin_password
    )

    cortex_id = "Cortex"
    if not args.skip_thehive_config:
        cortex_id = configure_thehive_cortex_connector(
            args.thehive_url,
            args.thehive_admin_user,
            args.thehive_admin_password,
            args.thehive_cortex_url,
            cortex_key,
        )
        print(f"Updated TheHive Cortex connector ({args.thehive_cortex_url}).")

    activated_analyzers: List[str] = []
    skipped_tier1: List[Dict[str, str]] = []
    failed_analyzers: List[Dict[str, str]] = []
    activated_responders: List[str] = []
    catalog_responders: List[Dict[str, str]] = []

    if not args.skip_activate:
        # Primary auth: the Cortex API key from .env (the user's "thehive"/integration
        # user). It must belong to an org-admin in the analyze org (e.g. XAI) for
        # analyzer/responder activation to succeed.
        bearer = cortex_key
        admin_basic = (args.cortex_admin_user, args.cortex_admin_password)

        tier0 = (
            TIER0_IP_ANALYZERS
            + TIER0_DOMAIN_ANALYZERS
            + TIER0_URL_ANALYZERS
            + TIER0_HASH_ANALYZERS
        )
        tier1 = (
            TIER1_IP_ANALYZERS
            + TIER1_DOMAIN_ANALYZERS
            + TIER1_URL_ANALYZERS
            + TIER1_HASH_ANALYZERS
        )

        permission_hint_printed = False

        def _maybe_print_permission_hint(err: str) -> None:
            nonlocal permission_hint_printed
            if permission_hint_printed:
                return
            if any(code in err for code in ("401", "403")):
                print(
                    "\n  (Activation auth failure. The user that owns CORTEX_API_KEY must have\n"
                    "   the `manageAnalyzer` permission, i.e. the **org-admin** role in the\n"
                    "   Cortex analyze organisation (e.g. XAI). Either give the integration\n"
                    "   user that role in the Cortex UI, or activate analyzers manually under\n"
                    "   Organization → Analyzers → Enable.)\n"
                )
                permission_hint_printed = True

        print("\n[Tier-0 analyzers — no external API key required]")
        seen: set[str] = set()
        for name in tier0:
            if name in seen:
                continue
            seen.add(name)
            ok, msg = activate_analyzer(
                args.cortex_url, bearer, name, admin_basic_auth=admin_basic
            )
            if ok:
                activated_analyzers.append(name)
                print(f"  + {name}")
            else:
                failed_analyzers.append({"name": name, "error": msg})
                print(f"  ! {name} — {msg}")
                _maybe_print_permission_hint(msg)

        print("\n[Tier-1 analyzers — free API key required, skipped when env var unset]")
        for name in tier1:
            if name in seen:
                continue
            seen.add(name)
            spec = TIER1_ANALYZER_CREDENTIALS.get(name)
            extra_config, skip_reason = tier1_activation_config(name)
            if skip_reason:
                env_hint = spec.get("env") if spec and not spec.get("multi") else ",".join(
                    spec.get("fields", {}).values()
                ) if spec else "?"
                skipped_tier1.append({"name": name, "env": env_hint})
                print(f"  - {name} (skipped: {skip_reason})")
                continue
            ok, msg = activate_analyzer(
                args.cortex_url, bearer, name,
                extra_config=extra_config or None,
                admin_basic_auth=admin_basic,
            )
            if ok:
                activated_analyzers.append(name)
                env_note = ""
                if spec and spec.get("multi"):
                    env_note = f" (url={os.getenv('MISP_URL', '').rstrip('/')[:40]}...)" if name == "MISP_2_1" else " (multi-field config)"
                elif spec:
                    env_note = f" (configured via {spec['env']})"
                print(f"  + {name}{env_note}")
            else:
                failed_analyzers.append({"name": name, "error": msg})
                print(f"  ! {name} — {msg}")
                _maybe_print_permission_hint(msg)

        # ── Responders ──────────────────────────────────────────────────
        # Only Tier-0 responders (no credentials) are activated by this
        # script. Anything that needs SMTP credentials, bot tokens, or API
        # keys (e.g. Mailer_1_0, Telegram_1_0, Slack_*) should be enabled
        # interactively from the Cortex UI under Organization → Responders,
        # so secrets stay inside Cortex's database rather than .env files.
        print("\n[Tier-0 responders — no external credentials]")
        catalog_responders = _fetch_responder_catalog_names(
            args.cortex_url, bearer, admin_basic=admin_basic
        )
        for name in TIER0_RESPONDERS:
            if catalog_responders and not _responder_in_catalog(name, catalog_responders):
                print(f"  - {name} (not in Cortex catalog — skipped)")
                continue
            ok, msg = activate_responder(
                args.cortex_url, bearer, name, admin_basic_auth=admin_basic
            )
            if ok:
                activated_responders.append(name)
                print(f"  + {name}")
            else:
                print(f"  ! {name} — {msg}")
                _maybe_print_permission_hint(msg)
        print(
            "  (To enable Mailer / Telegram / Slack / VirusTotal Submit etc.,\n"
            "   use the Cortex UI: Organization -> Responders -> Enable, then\n"
            "   fill in the SMTP / token / API-key fields. The orchestrator\n"
            "   discovers them automatically -- no code changes needed.)"
        )

    os.environ["THEHIVE_BASE_URL"] = args.thehive_url
    os.environ["THEHIVE_API_KEY"] = os.getenv("THEHIVE_API_KEY", "")
    discovered = fetch_thehive_cortex_server_id()
    if discovered:
        cortex_id = discovered

    env_lines = {
        "THEHIVE_BASE_URL": args.thehive_url.replace("127.0.0.1", "host.docker.internal"),
        "CORTEX_BASE_URL": args.cortex_url.replace("127.0.0.1", "host.docker.internal"),
        "CORTEX_API_KEY": cortex_key,
        "THEHIVE_CORTEX_ID": cortex_id,
        "CORTEX_IP_ANALYZERS": ",".join(DEFAULT_IP_ANALYZERS),
        "CORTEX_DOMAIN_ANALYZERS": ",".join(DEFAULT_DOMAIN_ANALYZERS),
        "CORTEX_URL_ANALYZERS": ",".join(DEFAULT_URL_ANALYZERS),
        "CORTEX_HASH_ANALYZERS": ",".join(DEFAULT_HASH_ANALYZERS),
    }

    print("\nAdd or update these in your .env file:\n")
    for key, value in env_lines.items():
        print(f"{key}={value}")

    print("\nSummary:")
    print(json.dumps(
        {
            "activated_analyzers": activated_analyzers,
            "skipped_tier1_analyzers": skipped_tier1,
            "failed_analyzers": failed_analyzers,
            "activated_responders": activated_responders,
            "catalog_responders_count": len(catalog_responders),
        },
        indent=2,
    ))

    if skipped_tier1:
        print(
            "\nTo enable the skipped Tier-1 analyzers, set the relevant env vars in "
            ".env and re-run this script. See docs/CORTEX_ANALYZERS_AND_RESPONDERS.md "
            "for the catalog and credential details."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
