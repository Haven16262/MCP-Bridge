"""Cross-AI file bus tools (SECURITY.md §6.6).

Structured inbox/archive message passing under ``MCP-shared/_bus/``.
Zero external dependencies — only file-system operations, reusing the
existing ``_validate_path`` security model.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from bridge.audit import _audit_log, _utc_ts
from bridge.server import mcp
from bridge.validators import (
    BridgeError,
    _error,
    _validate_path,
)

# ── Constants ─────────────────────────────────

IDENTITIES = {"vps-claude", "windows-claude", "antigravity"}
BUS_ROOT = r"C:\Users\YourUsername\MCP-shared\_bus"
SUBJECT_MAX_CHARS = 200
BODY_MAX_BYTES = 64 * 1024
MESSAGE_ID_PATTERN = re.compile(r"^msg-[0-9a-f]{12}$")


# ── Helpers ───────────────────────────────────


def _check_identity(value: str, field: str) -> str | None:
    """Return error code string if *value* is not a known identity."""
    if value not in IDENTITIES:
        return f"invalid_{field}"
    return None


# ── Tools ─────────────────────────────────────


@mcp.tool
def send_message(
    to: str,
    body: str,
    from_: str,
    subject: str = "",
    reply_to: str = "",
) -> dict:
    """Send a message to *to*'s inbox under ``MCP-shared/_bus/``.

    The message is written atomically (``.tmp`` → ``os.replace``).
    *body* must be ≤ 64 KB UTF-8.
    """
    # ── validation ──
    err = _check_identity(from_, "sender")
    if err:
        _audit_log("send_message", {"from": from_, "to": to}, "error", {"error": err, "reason": from_})
        return {"error": err, "reason": from_}

    err = _check_identity(to, "recipient")
    if err:
        _audit_log("send_message", {"from": from_, "to": to}, "error", {"error": err, "reason": to})
        return {"error": err, "reason": to}

    body_bytes = body.encode("utf-8")
    if len(body_bytes) > BODY_MAX_BYTES:
        _audit_log("send_message", {"from": from_, "to": to}, "error",
                   {"error": "body_too_large", "reason": f"body exceeds {BODY_MAX_BYTES} bytes"})
        return {"error": "body_too_large", "reason": f"body exceeds {BODY_MAX_BYTES} bytes"}

    if len(subject) > SUBJECT_MAX_CHARS:
        _audit_log("send_message", {"from": from_, "to": to}, "error",
                   {"error": "subject_too_long", "reason": f"subject exceeds {SUBJECT_MAX_CHARS} chars"})
        return {"error": "subject_too_long", "reason": f"subject exceeds {SUBJECT_MAX_CHARS} chars"}

    if reply_to and not MESSAGE_ID_PATTERN.match(reply_to):
        _audit_log("send_message", {"from": from_, "to": to}, "error",
                   {"error": "invalid_reply_to", "reason": reply_to})
        return {"error": "invalid_reply_to", "reason": reply_to}

    # ── build message ──
    msg_id = "msg-" + uuid4().hex[:12]
    ts = _utc_ts()
    message: Dict[str, Any] = {
        "id": msg_id,
        "from": from_,
        "to": to,
        "ts": ts,
        "subject": subject,
        "body": body,
    }
    if reply_to:
        message["reply_to"] = reply_to

    # ── resolve target path ──
    target_dir = Path(BUS_ROOT) / "inbox" / to
    try:
        resolved_dir = _validate_path(str(target_dir), "send_message")
    except BridgeError as e:
        return _error(e)

    # ── atomic write ──
    resolved_dir.mkdir(parents=True, exist_ok=True)
    final_path = resolved_dir / f"{msg_id}.json"
    tmp_path = resolved_dir / f"{msg_id}.json.tmp"
    try:
        tmp_path.write_text(json.dumps(message, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp_path, final_path)
    except OSError:
        # Best-effort cleanup of .tmp
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        _audit_log("send_message", {"from": from_, "to": to, "id": msg_id}, "error",
                   {"error": "io_error", "reason": "write or rename failed"})
        return {"error": "io_error", "reason": "write or rename failed"}

    _audit_log(
        "send_message",
        {"from": from_, "to": to, "subject_len": len(subject), "body_bytes": len(body_bytes), "id": msg_id},
        "ok",
        {},
    )
    return {"id": msg_id, "ts": ts, "path": str(final_path)}


@mcp.tool
def list_inbox(box: str, limit: int = 50, unread_only: bool = True) -> dict:
    """List messages in *box*'s inbox (preview only, no body content).

    Set *unread_only* to False to also include archived messages.
    """
    err = _check_identity(box, "box")
    if err:
        _audit_log("list_inbox", {"box": box}, "error", {"error": err, "reason": box})
        return {"error": err, "reason": box}

    # Clamp limit
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500

    messages: List[Dict[str, Any]] = []

    for location in (["inbox"] if unread_only else ["inbox", "archive"]):
        target_dir = Path(BUS_ROOT) / location / box
        try:
            resolved_dir = _validate_path(str(target_dir), "list_inbox")
        except BridgeError:
            continue  # directory doesn't exist yet → silently skip

        if not resolved_dir.is_dir():
            continue

        for entry in resolved_dir.iterdir():
            if not entry.name.endswith(".json"):
                continue
            # 读整个文件解析 JSON;body 也被读入但不返回。MVP 可接受(limit≤500 兜底),未来如需优化可拆 .meta.json 索引
            try:
                data = json.loads(entry.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            messages.append({
                "id": data.get("id", ""),
                "from": data.get("from", ""),
                "to": data.get("to", ""),
                "ts": data.get("ts", ""),
                "subject": data.get("subject", ""),
                "location": location,
            })

    # Sort by ts descending (newest first)
    messages.sort(key=lambda m: m.get("ts", ""), reverse=True)

    total = len(messages)
    truncated = False
    if total > limit:
        messages = messages[:limit]
        truncated = True

    _audit_log(
        "list_inbox",
        {"box": box, "unread_only": unread_only},
        "ok",
        {"total": total, "truncated": truncated},
    )
    return {"messages": messages, "total": total, "truncated": truncated}


@mcp.tool
def read_message(message_id: str, box: str) -> dict:
    """Read a single message's full content (including body).

    Looks in *inbox* first, then *archive*.
    """
    err = _check_identity(box, "box")
    if err:
        _audit_log("read_message", {"id": message_id, "box": box}, "error", {"error": err, "reason": box})
        return {"error": err, "reason": box}

    if not MESSAGE_ID_PATTERN.match(message_id):
        _audit_log("read_message", {"id": message_id, "box": box}, "error",
                   {"error": "invalid_message_id", "reason": message_id})
        return {"error": "invalid_message_id", "reason": message_id}

    for location in ("inbox", "archive"):
        target = Path(BUS_ROOT) / location / box / f"{message_id}.json"
        try:
            resolved = _validate_path(str(target), "read_message")
        except BridgeError:
            continue
        if not resolved.is_file():
            continue
        try:
            data = json.loads(resolved.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        _audit_log("read_message", {"id": message_id, "box": box, "location": location}, "ok", {})
        return {"message": data, "location": location}

    _audit_log("read_message", {"id": message_id, "box": box}, "error",
               {"error": "message_not_found", "reason": f"message {message_id} not found"})
    return {"error": "message_not_found", "reason": f"message {message_id} not found"}


@mcp.tool
def mark_read(message_id: str, box: str) -> dict:
    """Move a message from inbox to archive (mark as read)."""
    err = _check_identity(box, "box")
    if err:
        _audit_log("mark_read", {"id": message_id, "box": box}, "error", {"error": err, "reason": box})
        return {"error": err, "reason": box}

    if not MESSAGE_ID_PATTERN.match(message_id):
        _audit_log("mark_read", {"id": message_id, "box": box}, "error",
                   {"error": "invalid_message_id", "reason": message_id})
        return {"error": "invalid_message_id", "reason": message_id}

    inbox_path = Path(BUS_ROOT) / "inbox" / box / f"{message_id}.json"
    archive_dir = Path(BUS_ROOT) / "archive" / box
    archive_path = archive_dir / f"{message_id}.json"

    try:
        resolved_inbox = _validate_path(str(inbox_path), "mark_read")
    except BridgeError as e:
        return _error(e)

    # Check archive first (message already moved)
    if archive_path.is_file():
        _audit_log("mark_read", {"id": message_id, "box": box}, "error",
                   {"error": "already_archived", "reason": f"message {message_id} already archived"})
        return {"error": "already_archived", "reason": f"message {message_id} already archived"}

    if not resolved_inbox.is_file():
        _audit_log("mark_read", {"id": message_id, "box": box}, "error",
                   {"error": "message_not_found", "reason": f"message {message_id} not found in inbox"})
        return {"error": "message_not_found", "reason": f"message {message_id} not found in inbox"}

    # Resolve archive dir (still under _bus, so validation passes)
    try:
        resolved_archive_dir = _validate_path(str(archive_dir), "mark_read")
    except BridgeError as e:
        return _error(e)

    resolved_archive_dir.mkdir(parents=True, exist_ok=True)

    try:
        os.replace(resolved_inbox, archive_path)
    except OSError:
        _audit_log("mark_read", {"id": message_id, "box": box}, "error",
                   {"error": "io_error", "reason": "rename failed"})
        return {"error": "io_error", "reason": "rename failed"}

    _audit_log("mark_read", {"id": message_id, "box": box}, "ok", {"archived_to": str(archive_path)})
    return {"archived_to": str(archive_path)}
