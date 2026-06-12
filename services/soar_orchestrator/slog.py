"""Structured JSON logging for the SOAR orchestrator.

Centralises log formatting so every line emitted from the orchestrator,
case automation, TheHive client, and Cortex client follows the same shape.

Why custom JSON instead of pulling `python-json-logger`?
    The orchestrator's `requirements.txt` stays minimal (no new dep) and the
    fields we want are simple enough that a 60-line formatter does the job.
    Add `LOG_FORMAT=text` to keep the legacy print-style output for
    grep-friendliness during local dev.

Usage:
    from slog import get_logger, log_event

    log = get_logger(__name__)              # standard logging.Logger
    log_event("case_created",               # event= field
              alert_id=42, case_id="~99",   # any kwargs become top-level keys
              procedures=3, cortex=10)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any, Dict


SERVICE_NAME = os.getenv("SERVICE_NAME", "soar_orchestrator")
_LOG_FORMAT = os.getenv("LOG_FORMAT", "json").lower()
_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


class _JsonFormatter(logging.Formatter):
    """Emits one JSON object per log record on a single line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                  + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "service": SERVICE_NAME,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Pull any extra=... kwargs the caller attached.
        for key, value in record.__dict__.items():
            if key in (
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "levelname", "levelno", "lineno", "message", "module",
                "msecs", "msg", "name", "pathname", "process", "processName",
                "relativeCreated", "stack_info", "thread", "threadName",
                "taskName",
            ):
                continue
            try:
                json.dumps(value)            # ensure it's serialisable
                payload[key] = value
            except Exception:
                payload[key] = repr(value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _TextFormatter(logging.Formatter):
    """Legacy `[SOAR ORCHESTRATOR] message` shape so existing greps still work."""

    def format(self, record: logging.LogRecord) -> str:
        extra_keys = {
            k: v for k, v in record.__dict__.items()
            if k not in {"args", "asctime", "created", "exc_info", "exc_text",
                         "filename", "funcName", "levelname", "levelno", "lineno",
                         "message", "module", "msecs", "msg", "name", "pathname",
                         "process", "processName", "relativeCreated", "stack_info",
                         "thread", "threadName", "taskName"}
        }
        suffix = ""
        if extra_keys:
            suffix = " " + " ".join(f"{k}={v!s}" for k, v in extra_keys.items())
        return f"[{SERVICE_NAME.upper()}] {record.getMessage()}{suffix}"


def _ensure_root_configured() -> None:
    root = logging.getLogger()
    if getattr(root, "_soar_configured", False):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter() if _LOG_FORMAT == "json" else _TextFormatter())
    root.handlers[:] = [handler]
    root.setLevel(_LOG_LEVEL)
    setattr(root, "_soar_configured", True)


def get_logger(name: str = "soar_orchestrator") -> logging.Logger:
    """Return a logging.Logger configured per LOG_FORMAT/LOG_LEVEL env vars."""
    _ensure_root_configured()
    return logging.getLogger(name)


def log_event(event: str, **fields: Any) -> None:
    """Emit a single structured event. Pulls a module-level logger.

    Calling style mirrors the previous `print("[SOAR ORCHESTRATOR] ...")`
    pattern but produces a machine-parseable record. Example:

        log_event("alert_skipped",
                  alert_id=alert_id, flow=flow_id[:8], reason=reason)
    """
    log = get_logger("soar_orchestrator")
    log.info(event, extra={"event": event, **fields})
