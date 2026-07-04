"""Tests for integration defaults."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from integration_config import (  # noqa: E402
    get_configured_analyzers,
    tier1_activation_config,
)


def test_default_analyzers_populated_when_env_empty(monkeypatch):
    monkeypatch.delenv("CORTEX_IP_ANALYZERS", raising=False)
    monkeypatch.delenv("CORTEX_DOMAIN_ANALYZERS", raising=False)
    cfg = get_configured_analyzers()
    assert "Abuse_Finder_3_0" in cfg["ip"]
    assert "URLhaus_2_0" in cfg["url"]
    assert "MISP_2_1" in cfg["hash"]
    assert len(cfg["ip"]) >= 3


def test_tier1_activation_config_misp_skips_when_incomplete(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_API_KEY", raising=False)
    extra, reason = tier1_activation_config("MISP_2_1")
    assert extra is None
    assert "MISP_URL" in reason
    assert "MISP_API_KEY" in reason


def test_tier1_activation_config_misp_builds_payload(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.org")
    monkeypatch.setenv("MISP_API_KEY", "secret-key")
    monkeypatch.setenv("MISP_NAME", "lab")
    monkeypatch.setenv("MISP_CERT_CHECK", "true")
    extra, reason = tier1_activation_config("MISP_2_1")
    assert reason is None
    assert extra == {
        "url": ["https://misp.example.org"],
        "key": ["secret-key"],
        "name": ["lab"],
        "cert_check": True,
    }
