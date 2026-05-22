"""Real ag CLI integration tests — skipped unless running on Windows with ``ag`` in PATH."""

from __future__ import annotations

import platform
import shutil

import pytest

from bridge.tools.ag_cli import invoke_ag_cli

_IS_WINDOWS = platform.system() == "Windows"
_AG_FOUND = shutil.which("ag") is not None

pytestmark = pytest.mark.skipif(
    not (_IS_WINDOWS and _AG_FOUND),
    reason="requires ag on Windows",
)


class TestRealAgCli:
    def test_real_version_returns_string(self):
        result = invoke_ag_cli("--version")
        assert result["exit_code"] == 0
        assert len(result["stdout"]) > 0

    def test_real_ask_returns_answer(self):
        """ask spawns ag, then extracts answer from transcript."""
        result = invoke_ag_cli("ask", ["What is 2+2?"])
        assert result["exit_code"] == 0
        assert len(result["answer"]) > 0
        assert len(result["conversation_id"]) > 0
        assert result["command"] == "ag ask"
