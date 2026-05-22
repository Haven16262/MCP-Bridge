"""Audit logging (SECURITY.md §8).

JSON Lines output to ``logs/bridge.log`` with daily rotation, 30-day retention.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Dict

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

_audit = logging.getLogger("bridge.audit")
_audit.setLevel(logging.INFO)
_audit_handler = TimedRotatingFileHandler(
    LOG_DIR / "bridge.log",
    when="midnight",
    backupCount=30,
    encoding="utf-8",
)
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit.addHandler(_audit_handler)
_audit.propagate = False


def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _audit_log(
    tool: str,
    args_summary: Dict[str, Any],
    result: str,
    details: Dict[str, Any],
) -> None:
    _audit.info(
        json.dumps(
            {
                "ts": _utc_ts(),
                "tool": tool,
                "args_summary": args_summary,
                "result": result,
                "details": details,
                "client": None,
            }
        )
    )
