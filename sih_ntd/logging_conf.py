"""Structured logging. JSON by default so pipeline logs are machine-readable.

Log records never carry secrets, and captured strings (domains, SNI) are only
logged at DEBUG so a normal INFO log cannot be poisoned into something that
looks like a log line of its own.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from .config import get_settings

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value if isinstance(value, (str, int, float, bool, type(None))) else repr(value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str | None = None) -> None:
    settings = get_settings().logging
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter()
        if settings.json_output
        else logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel((level or settings.level).upper())
    # uvicorn duplicates access logs through its own handlers; keep one path.
    logging.getLogger("uvicorn.access").propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
