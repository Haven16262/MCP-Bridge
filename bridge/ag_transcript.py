"""Transcript extraction for ``ag ask`` (SECURITY.md §6.5).

Reads ag's internal transcript.jsonl to extract the answer from a
completed ``ask`` invocation.  All file reads are constrained to ag's
own directories under ``~/.gemini/antigravity-cli/``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# ── Constants (resolved at import time) ────────

_AG_LOG_DIR = Path.home() / ".gemini" / "antigravity-cli" / "log"
_AG_BRAIN_DIR = Path.home() / ".gemini" / "antigravity-cli" / "brain"

_LOG_GLOB = "cli-*.log"
_TRANSCRIPT_DIR = Path(".system_generated") / "logs"
_TRANSCRIPT_FILENAME = "transcript.jsonl"

_LOG_MAX_BYTES = 5 * 1024 * 1024       # 5 MB
_TRANSCRIPT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CONVERSATION_RE = re.compile(r"conversation=([0-9a-f-]+)")


class TranscriptError(Exception):
    """Raised when transcript extraction fails for a known reason."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ── Public API ────────────────────────────────


def snapshot_log_dir() -> set[str]:
    """Return the set of ``cli-*.log`` filenames currently in ``_AG_LOG_DIR``."""
    try:
        return {p.name for p in _AG_LOG_DIR.glob(_LOG_GLOB) if p.is_file()}
    except OSError:
        return set()


def extract_answer(before: set[str], after: set[str]) -> tuple[str, str]:
    """Extract *(answer, conversation_id)* from the transcript created between
    two log-directory snapshots.

    Raises :exc:`TranscriptError` with a normalized *reason* on any failure.
    """
    log_path = _find_new_log(before, after)
    uuid_str = _extract_uuid(log_path)
    transcript_path = _resolve_transcript_path(uuid_str)
    answer = _parse_transcript(transcript_path)
    return answer, uuid_str


# ── Internal steps ────────────────────────────


def _find_new_log(before: set[str], after: set[str]) -> Path:
    new = after - before
    if len(new) != 1:
        raise TranscriptError("log_not_found")
    filename = new.pop()
    if "/" in filename or "\\" in filename:
        raise TranscriptError("log_not_found")
    return _AG_LOG_DIR / filename


def _extract_uuid(log_path: Path) -> str:
    try:
        if log_path.stat().st_size > _LOG_MAX_BYTES:
            raise TranscriptError("uuid_not_found")
        text = log_path.read_text(encoding="utf-8")
    except OSError:
        raise TranscriptError("uuid_not_found")
    match = _CONVERSATION_RE.search(text)
    if not match:
        raise TranscriptError("uuid_not_found")
    uuid_str = match.group(1)
    if not _UUID_RE.match(uuid_str):
        raise TranscriptError("uuid_not_found")
    return uuid_str


def _resolve_transcript_path(uuid_str: str) -> Path:
    raw = _AG_BRAIN_DIR / uuid_str / _TRANSCRIPT_DIR / _TRANSCRIPT_FILENAME
    try:
        resolved = raw.resolve()
    except OSError:
        raise TranscriptError("transcript_not_found")
    try:
        resolved.relative_to(_AG_BRAIN_DIR.resolve())
    except ValueError:
        raise TranscriptError("transcript_not_found")
    if not resolved.is_file():
        raise TranscriptError("transcript_not_found")
    if resolved.stat().st_size > _TRANSCRIPT_MAX_BYTES:
        raise TranscriptError("transcript_not_found")
    return resolved


def _parse_transcript(transcript_path: Path) -> str:
    try:
        lines = transcript_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        raise TranscriptError("transcript_parse_error")

    last_content: str | None = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            raise TranscriptError("transcript_parse_error")
        if record.get("source") == "MODEL" and record.get("type") == "PLANNER_RESPONSE":
            content = record.get("content", "")
            if content:
                last_content = content

    if last_content is None:
        raise TranscriptError("no_planner_response")
    return last_content
