"""Real file bus integration tests — skipped unless running on Windows."""

from __future__ import annotations

import platform

import pytest

from bridge.tools.bus import list_inbox, mark_read, read_message, send_message

_IS_WINDOWS = platform.system() == "Windows"

pytestmark = pytest.mark.skipif(not _IS_WINDOWS, reason="requires Windows")


class TestRealBus:
    def test_send_list_read_mark_cycle(self):
        r = send_message(to="windows-claude", body="integration test body",
                         from_="vps-claude", subject="Integration")
        assert "id" in r

        inbox = list_inbox(box="windows-claude")
        msgs = [m for m in inbox["messages"] if m["id"] == r["id"]]
        assert len(msgs) == 1

        full = read_message(message_id=r["id"], box="windows-claude")
        assert full["message"]["body"] == "integration test body"

        mark_read(message_id=r["id"], box="windows-claude")

        archived = list_inbox(box="windows-claude", unread_only=False)
        arch = [m for m in archived["messages"] if m["id"] == r["id"]]
        assert len(arch) == 1
        assert arch[0]["location"] == "archive"
