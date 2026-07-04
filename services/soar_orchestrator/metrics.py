"""Prometheus metrics for the SOAR orchestrator.

Exposes a small set of counters + histograms at `http://0.0.0.0:METRICS_PORT/metrics`
(default 9100) so Prometheus/Grafana can chart real-time SOAR throughput,
latency, and per-component success rates.

Why these metrics?
    - `alerts_processed_total{status,model}`         — pipeline throughput by
      outcome (done / skipped / failed / deferred_thehive).
    - `case_creation_seconds`                        — latency from build_case
      payload to TheHive returning a case id.
    - `cortex_runs_total{analyzer,outcome}`          — per-analyzer launch /
      failure counts.
    - `responder_runs_total{responder,outcome}`      — per-responder dispatch
      counts (lets the dashboard show Wazuh failing 100% while Telegram
      succeeds).

All metrics are guarded so importing this module before the server starts is
safe (used by tests / one-shot scripts).
"""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from typing import Optional

try:
    from prometheus_client import Counter, Histogram, start_http_server
    _PROM_AVAILABLE = True
except Exception:                            # pragma: no cover - module not installed
    _PROM_AVAILABLE = False


if _PROM_AVAILABLE:
    ALERTS_PROCESSED = Counter(
        "soar_alerts_processed_total",
        "Total alerts processed by the SOAR orchestrator, labeled by outcome.",
        ["status", "model"],
    )
    CASE_CREATE_LATENCY = Histogram(
        "soar_case_creation_seconds",
        "Latency between building the TheHive case payload and receiving a case id.",
        buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
    )
    CORTEX_RUNS = Counter(
        "soar_cortex_runs_total",
        "Cortex analyzer launches initiated via TheHive's connector.",
        ["analyzer", "outcome"],     # outcome: launched / launch_failed
    )
    RESPONDER_RUNS = Counter(
        "soar_responder_runs_total",
        "Cortex responder launches initiated via TheHive's connector.",
        ["responder", "outcome"],
    )
else:
    ALERTS_PROCESSED = CASE_CREATE_LATENCY = CORTEX_RUNS = RESPONDER_RUNS = None  # type: ignore


_server_started = False


def start_metrics_server(port: Optional[int] = None) -> None:
    """Start the Prometheus HTTP exporter once per process. Safe to call repeatedly."""
    global _server_started
    if not _PROM_AVAILABLE or _server_started:
        return
    p = int(port or os.getenv("METRICS_PORT", "9100"))
    try:
        start_http_server(p)
        _server_started = True
    except OSError:
        # Port already in use (e.g. running tests). Silently skip rather than crash.
        pass


def record_alert(*, status: str, model: str) -> None:
    if ALERTS_PROCESSED is not None:
        ALERTS_PROCESSED.labels(status=status, model=str(model or "unknown")).inc()


def record_cortex_run(*, analyzer: str, outcome: str) -> None:
    if CORTEX_RUNS is not None:
        CORTEX_RUNS.labels(analyzer=analyzer, outcome=outcome).inc()


def record_responder_run(*, responder: str, outcome: str) -> None:
    if RESPONDER_RUNS is not None:
        RESPONDER_RUNS.labels(responder=responder, outcome=outcome).inc()


@contextmanager
def time_case_creation():
    """Context manager that records case-creation latency."""
    start = time.monotonic()
    try:
        yield
    finally:
        if CASE_CREATE_LATENCY is not None:
            CASE_CREATE_LATENCY.observe(time.monotonic() - start)
