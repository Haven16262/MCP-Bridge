"""Cross-AI file bus tests (SECURITY.md §6.6).  All use monkeypatched BUS_ROOT."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from bridge import validators
from bridge.tools.bus import (
    BODY_MAX_BYTES,
    MESSAGE_ID_PATTERN,
    SUBJECT_MAX_CHARS,
    list_inbox,
    mark_read,
    read_message,
    send_message,
)


# ── helpers ───────────────────────────────────


def _setup(monkeypatch, tmp_path) -> Path:
    """Set up BUS_ROOT to a tmp_path subdir + whitelist it."""
    bus_root = tmp_path / "MCP-shared" / "_bus"
    monkeypatch.setattr(
        "bridge.tools.bus.BUS_ROOT",
        str(bus_root),
        raising=True,
    )
    # Also whitelist the parent so _validate_path passes
    monkeypatch.setattr(
        validators,
        "WHITELIST_ROOTS",
        [str(tmp_path / "MCP-shared")],
        raising=True,
    )
    # Create minimal inbox dirs
    for box in ("vps-claude", "windows-claude", "antigravity"):
        (bus_root / "inbox" / box).mkdir(parents=True, exist_ok=True)
        (bus_root / "archive" / box).mkdir(parents=True, exist_ok=True)
    return bus_root


def _read_audit(path: Path) -> list:
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    return [json.loads(line) for line in lines if line]


# ── send_message ─────────────────────────────


class TestSendMessage:
    def test_happy_path(self, tmp_path, monkeypatch):
        bus = _setup(monkeypatch, tmp_path)
        result = send_message(to="windows-claude", body="hello", from_="vps-claude", subject="Test")
        assert "id" in result
        assert result["id"].startswith("msg-")
        assert MESSAGE_ID_PATTERN.match(result["id"])
        assert "ts" in result
        # Verify file on disk
        msg_file = bus / "inbox" / "windows-claude" / f"{result['id']}.json"
        assert msg_file.is_file()
        data = json.loads(msg_file.read_text())
        assert data["body"] == "hello"
        assert data["from"] == "vps-claude"
        assert data["subject"] == "Test"

    def test_invalid_sender(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = send_message(to="vps-claude", body="x", from_="hacker")
        assert result["error"] == "invalid_sender"

    def test_invalid_recipient(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = send_message(to="hacker", body="x", from_="vps-claude")
        assert result["error"] == "invalid_recipient"

    def test_body_too_large(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = send_message(to="vps-claude", body="x" * (BODY_MAX_BYTES + 1), from_="antigravity")
        assert result["error"] == "body_too_large"

    def test_subject_too_long(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = send_message(to="vps-claude", body="hi", from_="antigravity",
                              subject="x" * (SUBJECT_MAX_CHARS + 1))
        assert result["error"] == "subject_too_long"

    def test_invalid_reply_to(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = send_message(to="vps-claude", body="hi", from_="antigravity", reply_to="bad-format")
        assert result["error"] == "invalid_reply_to"

    def test_reply_to_ok(self, tmp_path, monkeypatch):
        bus = _setup(monkeypatch, tmp_path)
        result = send_message(to="vps-claude", body="hi", from_="antigravity", reply_to="msg-abc123def456")
        assert "id" in result
        # Check on-disk that reply_to is present
        msg_file = bus / "inbox" / "vps-claude" / f"{result['id']}.json"
        data = json.loads(msg_file.read_text())
        assert data["reply_to"] == "msg-abc123def456"

    def test_audit_does_not_contain_body(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        audit_file = tmp_path / "audit.log"
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)

        send_message(to="vps-claude", body="SECRET_MESSAGE", from_="antigravity")
        records = _read_audit(audit_file)
        send_recs = [r for r in records if r["tool"] == "send_message"]
        assert len(send_recs) >= 1
        # Body text must NOT appear anywhere in audit
        assert "SECRET_MESSAGE" not in json.dumps(send_recs[-1])
        logger.handlers.clear()

    def test_atomic_write_no_tmp_residue(self, tmp_path, monkeypatch):
        bus = _setup(monkeypatch, tmp_path)
        result = send_message(to="vps-claude", body="atomic", from_="antigravity")
        # No .tmp files should remain
        tmp_files = list((bus / "inbox" / "vps-claude").glob("*.tmp"))
        assert len(tmp_files) == 0
        # But the .json should exist
        assert (bus / "inbox" / "vps-claude" / f"{result['id']}.json").is_file()


# ── list_inbox ───────────────────────────────


class TestListInbox:
    def test_happy_path(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        send_message(to="vps-claude", body="msg1", from_="antigravity")
        send_message(to="vps-claude", body="msg2", from_="windows-claude")
        result = list_inbox(box="vps-claude")
        assert len(result["messages"]) == 2
        assert result["truncated"] is False

    def test_invalid_box(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = list_inbox(box="hacker")
        assert result["error"] == "invalid_box"

    def test_archive_included_when_unread_only_false(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        r = send_message(to="vps-claude", body="archive-me", from_="antigravity")
        mark_read(message_id=r["id"], box="vps-claude")
        # unread_only=True → only inbox (should be empty)
        r1 = list_inbox(box="vps-claude", unread_only=True)
        assert len(r1["messages"]) == 0
        # unread_only=False → includes archive
        r2 = list_inbox(box="vps-claude", unread_only=False)
        assert len(r2["messages"]) == 1
        assert r2["messages"][0]["location"] == "archive"

    def test_audit_does_not_contain_body(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        audit_file = tmp_path / "audit.log"
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)

        send_message(to="vps-claude", body="SENSITIVE", from_="antigravity")
        list_inbox(box="vps-claude")
        records = _read_audit(audit_file)
        list_recs = [r for r in records if r["tool"] == "list_inbox"]
        assert len(list_recs) >= 1
        assert "SENSITIVE" not in json.dumps(list_recs[-1])
        logger.handlers.clear()


# ── read_message ─────────────────────────────


class TestReadMessage:
    def test_read_from_inbox(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        r = send_message(to="vps-claude", body="hello inbox", from_="antigravity")
        result = read_message(message_id=r["id"], box="vps-claude")
        assert result["location"] == "inbox"
        assert result["message"]["body"] == "hello inbox"

    def test_read_from_archive(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        r = send_message(to="vps-claude", body="archived body", from_="antigravity")
        mark_read(message_id=r["id"], box="vps-claude")
        result = read_message(message_id=r["id"], box="vps-claude")
        assert result["location"] == "archive"
        assert result["message"]["body"] == "archived body"

    def test_invalid_box(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = read_message(message_id="msg-000000000000", box="hacker")
        assert result["error"] == "invalid_box"

    def test_invalid_message_id(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = read_message(message_id="bad-id", box="vps-claude")
        assert result["error"] == "invalid_message_id"

    def test_message_not_found(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = read_message(message_id="msg-000000000000", box="vps-claude")
        assert result["error"] == "message_not_found"

    def test_audit_does_not_contain_body(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        audit_file = tmp_path / "audit.log"
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)

        r = send_message(to="vps-claude", body="READ_ME_SECRET", from_="antigravity")
        read_message(message_id=r["id"], box="vps-claude")
        records = _read_audit(audit_file)
        read_recs = [r for r in records if r["tool"] == "read_message"]
        assert len(read_recs) >= 1
        assert "READ_ME_SECRET" not in json.dumps(read_recs[-1])
        logger.handlers.clear()


# ── mark_read ────────────────────────────────


class TestMarkRead:
    def test_happy_path(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        r = send_message(to="vps-claude", body="mark me", from_="antigravity")
        result = mark_read(message_id=r["id"], box="vps-claude")
        assert "archived_to" in result

    def test_invalid_box(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = mark_read(message_id="msg-000000000000", box="hacker")
        assert result["error"] == "invalid_box"

    def test_invalid_message_id(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = mark_read(message_id="bad", box="vps-claude")
        assert result["error"] == "invalid_message_id"

    def test_message_not_found(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        result = mark_read(message_id="msg-000000000000", box="vps-claude")
        assert result["error"] == "message_not_found"

    def test_already_archived(self, tmp_path, monkeypatch):
        _setup(monkeypatch, tmp_path)
        r = send_message(to="vps-claude", body="already", from_="antigravity")
        mark_read(message_id=r["id"], box="vps-claude")
        # Mark again → already_archived
        result = mark_read(message_id=r["id"], box="vps-claude")
        assert result["error"] == "already_archived"


# ── cross-role round-trip ────────────────────


class TestBusRoundTrip:
    def test_full_cycle(self, tmp_path, monkeypatch):
        """vps-claude → windows-claude: send → list → read → mark_read."""
        _setup(monkeypatch, tmp_path)
        # Send
        r = send_message(to="windows-claude", body="Hello from VPS!", from_="vps-claude",
                         subject="Greeting")
        assert "id" in r

        # List (as windows-claude)
        inbox = list_inbox(box="windows-claude")
        assert len(inbox["messages"]) == 1
        preview = inbox["messages"][0]
        assert preview["from"] == "vps-claude"
        assert preview["subject"] == "Greeting"

        # Read (as windows-claude)
        full = read_message(message_id=r["id"], box="windows-claude")
        assert full["message"]["body"] == "Hello from VPS!"

        # Archive (as windows-claude)
        mark_read(message_id=r["id"], box="windows-claude")

        # Verify archived
        inbox2 = list_inbox(box="windows-claude", unread_only=True)
        assert len(inbox2["messages"]) == 0
        archive = list_inbox(box="windows-claude", unread_only=False)
        assert len(archive["messages"]) == 1
        assert archive["messages"][0]["location"] == "archive"
