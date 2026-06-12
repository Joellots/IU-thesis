"""
Load MITRE ATT&CK Enterprise STIX bundle (cached), resolve technique IDs to
official names/descriptions/mitigations, and emit playbook-ready step dicts.

Data source: https://github.com/mitre-attack/attack-stix-data (STIX 2.1 bundles).
Override download URL with ATTACK_STIX_URL; cache path with ATTACK_STIX_CACHE_PATH.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

def _stix_url() -> str:
    return os.getenv(
        "ATTACK_STIX_URL",
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    )
CACHE_PATH = Path(os.getenv("ATTACK_STIX_CACHE_PATH", "/app/cache/enterprise-attack.json"))
CACHE_MAX_AGE_SEC = int(os.getenv("ATTACK_STIX_CACHE_MAX_AGE_SEC", str(7 * 24 * 3600)))
HTTP_TIMEOUT_SEC = int(os.getenv("ATTACK_STIX_DOWNLOAD_TIMEOUT_SEC", "600"))
MAX_DESC_CHARS = int(os.getenv("ATTACK_PLAYBOOK_MAX_DESC_CHARS", "3500"))
MAX_MITIGATIONS = int(os.getenv("ATTACK_PLAYBOOK_MAX_MITIGATIONS", "5"))


def _truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n\n[…truncated]"


def _is_deprecated(obj: Dict[str, Any]) -> bool:
    if obj.get("revoked") is True:
        return True
    ext = obj.get("x_mitre_deprecated")
    return ext is True


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
def _download_bundle(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with requests.get(url, stream=True, timeout=HTTP_TIMEOUT_SEC) as resp:
        resp.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
    tmp.replace(dest)


def _bundle_fresh(path: Path) -> bool:
    if not path.exists() or path.stat().st_size < 1000:
        return False
    age = time.time() - path.stat().st_mtime
    return age < CACHE_MAX_AGE_SEC


def ensure_attack_bundle() -> Path:
    """
    Ensure enterprise-attack STIX JSON exists on disk (download if missing or stale).
    """
    if _bundle_fresh(CACHE_PATH):
        return CACHE_PATH
    _download_bundle(_stix_url(), CACHE_PATH)
    return CACHE_PATH


def _external_technique_id(obj: Dict[str, Any]) -> Optional[str]:
    preferred: List[str] = []
    fallback: List[str] = []
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        ext_id = ref.get("external_id")
        if not ext_id or not _TID_RE.match(str(ext_id)):
            continue
        tid = str(ext_id)
        src = str(ref.get("source_name") or "")
        if src == "mitre-attack" or "mitre-attack" in src.lower():
            preferred.append(tid)
        else:
            fallback.append(tid)
    if preferred:
        return preferred[0]
    if fallback:
        return fallback[0]
    return None


def _build_indexes(objects: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Dict[str, str]]]]:
    """
    Returns:
      techniques_by_tid: T1071 -> {stix_id, name, description}
      mitigations_by_tid: T1071 -> [{name, description}, ...]
    """
    by_id: Dict[str, Dict[str, Any]] = {}
    for obj in objects:
        oid = obj.get("id")
        if isinstance(oid, str):
            by_id[oid] = obj

    stix_to_tid: Dict[str, str] = {}
    techniques_by_tid: Dict[str, Dict[str, Any]] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if _is_deprecated(obj):
            continue
        tid = _external_technique_id(obj)
        if not tid:
            continue
        oid = obj.get("id")
        if not isinstance(oid, str):
            continue
        stix_to_tid[oid] = tid
        techniques_by_tid[tid] = {
            "stix_id": oid,
            "name": obj.get("name") or tid,
            "description": obj.get("description") or "",
        }

    mitigations_by_tid: Dict[str, List[Dict[str, str]]] = {t: [] for t in techniques_by_tid}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "mitigates":
            continue
        if _is_deprecated(obj):
            continue
        src_ref = obj.get("source_ref")
        tgt_ref = obj.get("target_ref")
        if not isinstance(src_ref, str) or not isinstance(tgt_ref, str):
            continue
        src_o = by_id.get(src_ref)
        tgt_o = by_id.get(tgt_ref)
        if not src_o or not tgt_o:
            continue
        # MITRE bundle: course-of-action mitigates attack-pattern
        coa, ap = None, None
        if src_o.get("type") == "course-of-action" and tgt_o.get("type") == "attack-pattern":
            coa, ap = src_o, tgt_o
        elif src_o.get("type") == "attack-pattern" and tgt_o.get("type") == "course-of-action":
            ap, coa = src_o, tgt_o
        else:
            continue
        tid = stix_to_tid.get(ap.get("id", ""))
        if not tid:
            continue
        mitigations_by_tid.setdefault(tid, []).append(
            {
                "name": str(coa.get("name") or "Mitigation"),
                "description": str(coa.get("description") or ""),
            }
        )

    return techniques_by_tid, mitigations_by_tid


class AttackStixResolver:
    """Lazy-loads STIX bundle once and serves technique → playbook steps."""

    def __init__(self) -> None:
        self._techniques: Optional[Dict[str, Dict[str, Any]]] = None
        self._mitigations: Optional[Dict[str, List[Dict[str, str]]]] = None

    def _load(self) -> None:
        if self._techniques is not None:
            return
        path = ensure_attack_bundle()
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        objects = bundle.get("objects")
        if not isinstance(objects, list):
            self._techniques = {}
            self._mitigations = {}
            return
        self._techniques, self._mitigations = _build_indexes(objects)

    def technique_exists(self, tid: str) -> bool:
        self._load()
        assert self._techniques is not None
        return tid in self._techniques

    def steps_for_technique(self, tid: str) -> List[Dict[str, Any]]:
        """
        Build 1–2 playbook steps from official ATT&CK text (+ mitigations list).
        """
        self._load()
        assert self._techniques is not None and self._mitigations is not None

        meta = self._techniques.get(tid)
        if not meta:
            return [
                {
                    "title": f"MITRE ATT&CK: {tid}",
                    "description": _truncate(
                        f"No STIX entry found for `{tid}` in the cached Enterprise bundle. "
                        f"See https://attack.mitre.org/techniques/{tid.replace('.', '/')}/ "
                        "for the current MITRE page (ID may be new, revoked, or non-Enterprise).",
                        MAX_DESC_CHARS,
                    ),
                    "group": "MITRE ATT&CK",
                    "technique": tid,
                }
            ]

        name = meta["name"]
        desc = _truncate(str(meta.get("description") or ""), MAX_DESC_CHARS)
        mit_list = self._mitigations.get(tid, [])[:MAX_MITIGATIONS]

        steps: List[Dict[str, Any]] = [
            {
                "title": f"ATT&CK — {name} ({tid})",
                "description": desc,
                "group": "MITRE ATT&CK",
                "technique": tid,
            }
        ]

        if mit_list:
            lines = []
            for m in mit_list:
                md = _truncate(m.get("description", ""), 800)
                lines.append(f"- **{m.get('name', 'Mitigation')}**: {md}")
            steps.append(
                {
                    "title": f"Mitigations — {tid}",
                    "description": "Official ATT&CK mitigations linked to this technique:\n\n" + "\n\n".join(lines),
                    "group": "MITRE ATT&CK",
                    "technique": tid,
                }
            )

        return steps


_resolver: Optional[AttackStixResolver] = None


def get_resolver() -> AttackStixResolver:
    global _resolver
    if _resolver is None:
        _resolver = AttackStixResolver()
    return _resolver
