"""invoke_ag_cli tests (SECURITY.md §6.5).  All subprocess calls mocked."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict
from unittest import mock

import pytest

from bridge.tools.ag_cli import ALLOWED_SUBCOMMANDS, PROMPT_SENTINEL, invoke_ag_cli


# ── Fake Popen ────────────────────────────────


class FakePopen:
    """Minimal ``subprocess.Popen`` stand-in for tests."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.pid = 99999

    def communicate(self, input=None, timeout=None):
        return self._stdout, self._stderr


# ── helpers ───────────────────────────────────


def _mock_popen_ok(stdout="antigravity 1.2.3\n"):
    return FakePopen(0, stdout, "")


def _mock_popen_err():
    return FakePopen(1, "", "error")


def _bin(monkeypatch):
    import bridge.tools.ag_cli as ag_mod

    monkeypatch.setattr(ag_mod, "_AG_BINARY", "/bin/ag", raising=True)


def _mock_ask_transcript(monkeypatch, answer="回答内容\n",
                         conversation_id="568b060d-a3c5-4b2a-8af1-fb75ed53c342"):
    """Mock transcript extraction so ``ask`` tests don't touch the filesystem."""
    import bridge.ag_transcript as at_mod

    monkeypatch.setattr(at_mod, "snapshot_log_dir", lambda: {"cli-old.log"})
    monkeypatch.setattr(at_mod, "extract_answer",
                        lambda before, after: (answer, conversation_id))
    monkeypatch.setattr(at_mod, "TranscriptError", type("TranscriptError", (Exception,), {"reason": "test"}))


# ── Audit redirect fixture ────────────────────


class TestAgCliAudit:
    """Audit log verification for invoke_ag_cli."""

    @pytest.fixture(autouse=True)
    def _redirect_audit(self, tmp_path):
        audit_file = tmp_path / "_audit" / "test.log"
        audit_file.parent.mkdir()
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)
        self.__class__._audit_log_path = audit_file
        yield
        logger.handlers.clear()

    def _read_audit(self) -> list:
        lines = self._audit_log_path.read_text(encoding="utf-8").strip().split("\n")
        return [json.loads(line) for line in lines if line]

    def test_audit_does_not_contain_stdout(self, monkeypatch):
        _bin(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok("hello world"))
        result = invoke_ag_cli("--version")
        assert result["exit_code"] == 0
        records = self._read_audit()
        inv = [r for r in records if r["tool"] == "invoke_ag_cli"]
        assert len(inv) >= 1
        assert "hello world" not in json.dumps(inv[-1])
        assert result["stdout"] == "hello world"

    def test_audit_does_not_contain_stderr(self, monkeypatch):
        _bin(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_err())
        result = invoke_ag_cli("--version")
        assert result["exit_code"] == 1
        records = self._read_audit()
        inv = [r for r in records if r["tool"] == "invoke_ag_cli"]
        assert "sensitive error" not in json.dumps(inv[-1])

    def test_audit_args_summary_no_args_leak(self, monkeypatch):
        _bin(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        invoke_ag_cli("--version", args=[])
        records = self._read_audit()
        inv = [r for r in records if r["tool"] == "invoke_ag_cli"]
        rec = inv[-1]
        assert rec["args_summary"] == {"subcommand": "--version", "args_count": 0}

    def test_audit_reason_no_args_leak(self, monkeypatch):
        _bin(monkeypatch)
        result = invoke_ag_cli("--version", args=["--help"])
        assert result["error"] == "args_not_allowed"
        records = self._read_audit()
        inv = [r for r in records if r["tool"] == "invoke_ag_cli"]
        rec = inv[-1]
        assert "--help" not in json.dumps(rec["details"])

    def test_audit_success_details_correct(self, monkeypatch):
        _bin(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok("OK\n"))
        invoke_ag_cli("--version")
        records = self._read_audit()
        inv = [r for r in records if r["tool"] == "invoke_ag_cli"]
        rec = inv[-1]
        assert rec["result"] == "ok"
        assert set(rec["details"].keys()) == {"exit_code", "stdout_size", "stderr_size", "duration_ms"}


# ── error code tests ──────────────────────────


class TestAgCliErrors:
    def test_ag_cli_unavailable(self, monkeypatch):
        import bridge.tools.ag_cli as ag_mod

        monkeypatch.setattr(ag_mod, "_AG_BINARY", None, raising=True)
        result = invoke_ag_cli("--version")
        assert result["error"] == "ag_cli_unavailable"

    def test_command_not_allowed(self, monkeypatch):
        import bridge.tools.ag_cli as ag_mod

        monkeypatch.setattr(ag_mod, "_AG_BINARY", "/bin/ag", raising=True)
        result = invoke_ag_cli("nonexistent")
        assert result["error"] == "command_not_allowed"

    def test_args_not_allowed(self, monkeypatch):
        import bridge.tools.ag_cli as ag_mod

        monkeypatch.setattr(ag_mod, "_AG_BINARY", "/bin/ag", raising=True)
        result = invoke_ag_cli("--version", args=["--help"])
        assert result["error"] == "args_not_allowed"

    def test_invalid_subcommand_empty(self, monkeypatch):
        result = invoke_ag_cli("")
        assert result["error"] == "invalid_subcommand"

    def test_invalid_subcommand_none(self, monkeypatch):
        result = invoke_ag_cli(None)
        assert result["error"] == "invalid_subcommand"

    def test_invalid_args_not_list(self, monkeypatch):
        result = invoke_ag_cli("--version", "not-a-list")
        assert result["error"] == "invalid_args"

    def test_invalid_args_contains_non_str(self, monkeypatch):
        result = invoke_ag_cli("--version", [1, 2, 3])
        assert result["error"] == "invalid_args"

    def test_timeout(self, monkeypatch):
        import bridge.tools.ag_cli as ag_mod

        monkeypatch.setattr(ag_mod, "_AG_BINARY", "/bin/ag", raising=True)
        monkeypatch.setattr(ag_mod, "_kill_process_tree", lambda pid: None)

        class _TimeoutPopen(FakePopen):
            def communicate(self, input=None, timeout=None):
                raise subprocess.TimeoutExpired(cmd="ag", timeout=timeout or 1)

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _TimeoutPopen())
        result = invoke_ag_cli("--version")
        assert result["error"] == "timeout"

    def test_execution_error(self, monkeypatch):
        import bridge.tools.ag_cli as ag_mod

        monkeypatch.setattr(ag_mod, "_AG_BINARY", "/bin/ag", raising=True)

        class _OSErrorPopen:
            def __init__(self, *a, **kw):
                raise OSError("no such file")

        monkeypatch.setattr(subprocess, "Popen", _OSErrorPopen)
        result = invoke_ag_cli("--version")
        assert result["error"] == "execution_error"


# ── happy path (--version) ────────────────────


class TestAgCliHappyPath:
    def test_version_succeeds(self, monkeypatch):
        _bin(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok("antigravity 1.2.3\n"))
        result = invoke_ag_cli("--version")
        assert result["exit_code"] == 0
        assert "antigravity" in result["stdout"]
        assert result["command"] == "ag --version"
        assert "duration_ms" in result

    def test_version_stdout_truncation_at_10kb(self, monkeypatch):
        _bin(monkeypatch)
        big = "X" * (10 * 1024 + 100)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok(big))
        result = invoke_ag_cli("--version")
        limit = 10 * 1024
        assert len(result["stdout"]) == limit + len(f"\n[truncated at {limit} bytes]")
        assert f"[truncated at {limit} bytes]" in result["stdout"]

    def test_command_field_does_not_contain_args(self, monkeypatch):
        _bin(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        r1 = invoke_ag_cli("--version")
        assert r1["command"] == "ag --version"
        # ask command field only shows subcommand
        _mock_ask_transcript(monkeypatch)
        r2 = invoke_ag_cli("ask", ["hello"])
        assert r2["command"] == "ag ask"
        assert "hello" not in r2["command"]

    def test_popen_uses_process_group(self, monkeypatch):
        """Verify Popen receives creationflags (Windows) or preexec_fn (POSIX)."""
        _bin(monkeypatch)
        captured: Dict[str, Any] = {}

        class _CapturePopen(FakePopen):
            def __init__(self, *a, **kw):
                nonlocal captured
                captured = kw
                super().__init__()

        monkeypatch.setattr(subprocess, "Popen", _CapturePopen)
        invoke_ag_cli("--version")
        has_pg = captured.get("creationflags") is not None or captured.get("preexec_fn") is not None
        assert has_pg, f"No process-group mechanism in Popen kwargs"


# ── argv construction ─────────────────────────


class TestArgvConstruction:
    """B4: PROMPT_SENTINEL replacement and argv safety."""

    def test_prompt_sentinel_replaced_in_ask(self, monkeypatch):
        _bin(monkeypatch)
        _mock_ask_transcript(monkeypatch)
        captured_argv: list = []

        class _CP(FakePopen):
            def __init__(self, *a, **kw):
                nonlocal captured_argv
                captured_argv = list(a[0]) if a else []
                super().__init__()

        monkeypatch.setattr(subprocess, "Popen", _CP)
        invoke_ag_cli("ask", ["What is 2+2?"])
        assert "What is 2+2?" in captured_argv
        assert PROMPT_SENTINEL not in captured_argv

    def test_prompt_sentinel_not_in_version(self, monkeypatch):
        _bin(monkeypatch)
        captured_argv: list = []

        class _CP(FakePopen):
            def __init__(self, *a, **kw):
                nonlocal captured_argv
                captured_argv = list(a[0]) if a else []
                super().__init__()

        monkeypatch.setattr(subprocess, "Popen", _CP)
        invoke_ag_cli("--version")
        assert PROMPT_SENTINEL not in captured_argv
        assert captured_argv == ["/bin/ag", "--version"]

    def test_prompt_literal_protected(self, monkeypatch):
        """PROMPT_SENTINEL matched against template tokens only, not user prompt content."""
        _bin(monkeypatch)
        _mock_ask_transcript(monkeypatch)
        captured_argv: list = []

        class _CP(FakePopen):
            def __init__(self, *a, **kw):
                nonlocal captured_argv
                captured_argv = list(a[0]) if a else []
                super().__init__()

        monkeypatch.setattr(subprocess, "Popen", _CP)
        # prompt is literally "<PROMPT>" — should not be confused with sentinel
        invoke_ag_cli("ask", ["<PROMPT>"])
        # The prompt "<PROMPT>" appears once (as the user prompt)
        assert captured_argv.count("<PROMPT>") == 1

    def test_command_field_never_contains_prompt(self, monkeypatch):
        """prompt is in argv (via PROMPT_SENTINEL), but 'command' return field only shows subcommand."""
        _bin(monkeypatch)
        _mock_ask_transcript(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["sensitive prompt"])
        assert result["command"] == "ag ask"
        assert "sensitive prompt" not in result["command"]


# ── ask subcommand ────────────────────────────


class TestAgCliAsk:
    def test_ask_happy_path(self, monkeypatch):
        _bin(monkeypatch)
        _mock_ask_transcript(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["你好"])
        assert result["exit_code"] == 0
        assert result["answer"] == "回答内容\n"
        assert result["conversation_id"] == "568b060d-a3c5-4b2a-8af1-fb75ed53c342"
        assert result["command"] == "ag ask"
        assert "duration_ms" in result
        assert "stdout" not in result
        assert "stderr" not in result

    def test_ask_empty_prompt_rejected(self, monkeypatch):
        _bin(monkeypatch)
        result = invoke_ag_cli("ask", [""])
        assert result["error"] == "args_not_allowed"

    def test_ask_oversize_prompt_rejected(self, monkeypatch):
        _bin(monkeypatch)
        result = invoke_ag_cli("ask", ["x" * 20000])
        assert result["error"] == "args_not_allowed"

    def test_ask_non_str_prompt_rejected(self, monkeypatch):
        _bin(monkeypatch)
        result = invoke_ag_cli("ask", [123])
        assert result["error"] == "invalid_args"

    def test_ask_prompt_max_16kb(self, monkeypatch):
        _bin(monkeypatch)
        _mock_ask_transcript(monkeypatch)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok("ok"))
        # 16384 bytes — ok
        r = invoke_ag_cli("ask", ["x" * 16384])
        assert r["exit_code"] == 0
        # 16385 bytes — rejected
        r2 = invoke_ag_cli("ask", ["x" * 16385])
        assert r2["error"] == "args_not_allowed"

    def test_ask_audit_records_prompt_bytes_no_content(self, tmp_path, monkeypatch):
        _bin(monkeypatch)
        _mock_ask_transcript(monkeypatch)
        audit_file = tmp_path / "audit.log"
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok("reply"))
        prompt = "什么是Rust?"
        result = invoke_ag_cli("ask", [prompt])
        assert result["exit_code"] == 0

        records = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").strip().split("\n") if line]
        inv = [r for r in records if r["tool"] == "invoke_ag_cli" and r.get("result") == "ok"]
        rec = inv[-1]
        assert rec["args_summary"]["subcommand"] == "ask"
        assert rec["args_summary"]["prompt_bytes"] == len(prompt.encode("utf-8"))
        # audit must NOT contain answer content
        assert "什么是Rust" not in json.dumps(rec)
        assert "回答内容" not in json.dumps(rec)
        # success details: answer_bytes not answer content
        assert "answer_bytes" in rec["details"]
        assert "conversation_id" in rec["details"]
        logger.handlers.clear()

    def test_ask_audit_prompt_bytes_on_timeout(self, tmp_path, monkeypatch):
        _bin(monkeypatch)
        import bridge.tools.ag_cli as ag_mod

        monkeypatch.setattr(ag_mod, "_kill_process_tree", lambda pid: None)

        audit_file = tmp_path / "audit.log"
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)

        class _TO(FakePopen):
            def communicate(self, input=None, timeout=None):
                raise subprocess.TimeoutExpired(cmd="ag", timeout=1)

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _TO())
        invoke_ag_cli("ask", ["hello"])
        records = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").strip().split("\n") if line]
        to = [r for r in records if r.get("result") == "error" and r.get("details", {}).get("error") == "timeout"]
        assert len(to) == 1
        assert to[0]["args_summary"]["prompt_bytes"] == 5
        logger.handlers.clear()

    def test_ask_audit_prompt_bytes_on_execution_error(self, tmp_path, monkeypatch):
        _bin(monkeypatch)
        audit_file = tmp_path / "audit.log"
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)

        class _OE:
            def __init__(self, *a, **kw):
                raise OSError("fail")

        monkeypatch.setattr(subprocess, "Popen", _OE)
        invoke_ag_cli("ask", ["hello"])
        records = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").strip().split("\n") if line]
        ee = [r for r in records if r.get("result") == "error" and r.get("details", {}).get("error") == "execution_error"]
        assert len(ee) == 1
        assert ee[0]["args_summary"]["prompt_bytes"] == 5
        logger.handlers.clear()

    def test_ask_answer_truncation_at_1mb(self, monkeypatch):
        _bin(monkeypatch)
        big = "A" * (1024 * 1024 + 500)
        _mock_ask_transcript(monkeypatch, answer=big)
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["hello"])
        limit = 1024 * 1024
        assert len(result["answer"]) == limit + len(f"\n[truncated at {limit} bytes]")
        assert f"[truncated at {limit} bytes]" in result["answer"]

    def test_ask_timeout_uses_660s(self, monkeypatch):
        _bin(monkeypatch)
        captured_kw: Dict[str, Any] = {}

        class _CP(FakePopen):
            def communicate(self, input=None, timeout=None):
                nonlocal captured_kw
                captured_kw["timeout"] = timeout
                return "", ""

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _CP())
        _mock_ask_transcript(monkeypatch)
        invoke_ag_cli("ask", ["hello"])
        assert captured_kw["timeout"] == 660

    def test_timeout_triggers_tree_kill(self, monkeypatch):
        _bin(monkeypatch)
        kill_calls: list = []

        import bridge.tools.ag_cli as ag_mod

        monkeypatch.setattr(ag_mod, "_kill_process_tree", lambda pid: kill_calls.append(pid))

        class _TO(FakePopen):
            def communicate(self, input=None, timeout=None):
                raise subprocess.TimeoutExpired(cmd="ag", timeout=timeout or 1)

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _TO())
        result = invoke_ag_cli("--version")
        assert result["error"] == "timeout"
        assert len(kill_calls) == 1

    def test_ask_ag_output_unavailable(self, monkeypatch):
        """ag_output_unavailable returned when transcript extraction fails."""
        _bin(monkeypatch)
        import bridge.ag_transcript as at_mod

        monkeypatch.setattr(at_mod, "snapshot_log_dir", lambda: {"old.log"})

        class _TranscriptError(Exception):
            def __init__(self, reason):
                self.reason = reason
                super().__init__(reason)

        monkeypatch.setattr(at_mod, "TranscriptError", _TranscriptError)
        monkeypatch.setattr(at_mod, "extract_answer",
                            lambda before, after: (_ for _ in () ).throw(_TranscriptError("transcript_not_found")))
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["hello"])
        assert result["error"] == "ag_output_unavailable"
        assert result["reason"] == "transcript_not_found"


# ── transcript extraction unit tests ──────────


class TestTranscriptExtraction:
    """B1: Unit tests for transcript parsing logic."""

    def test_simple_answer(self, tmp_path):
        """Single PLANNER_RESPONSE with content."""
        from bridge.ag_transcript import _parse_transcript

        tf = tmp_path / "transcript.jsonl"
        tf.write_text(json.dumps({
            "source": "MODEL", "type": "PLANNER_RESPONSE",
            "content": "2 + 2 = 4"
        }) + "\n", encoding="utf-8")
        assert _parse_transcript(tf) == "2 + 2 = 4"

    def test_tool_call_then_answer(self, tmp_path):
        """Tool-call chain: empty planner → tool result → final planner."""
        from bridge.ag_transcript import _parse_transcript

        lines = [
            {"source": "MODEL", "type": "PLANNER_RESPONSE", "content": ""},
            {"source": "TOOL", "type": "LIST_DIRECTORY", "content": "..."},
            {"source": "MODEL", "type": "PLANNER_RESPONSE", "content": "final answer"},
        ]
        tf = tmp_path / "transcript.jsonl"
        tf.write_text("\n".join(json.dumps(r) for r in lines) + "\n", encoding="utf-8")
        assert _parse_transcript(tf) == "final answer"

    def test_all_empty_planner(self, tmp_path):
        """All PLANNER_RESPONSE lines have empty content → no_planner_response."""
        from bridge.ag_transcript import TranscriptError, _parse_transcript

        tf = tmp_path / "transcript.jsonl"
        tf.write_text(json.dumps({
            "source": "MODEL", "type": "PLANNER_RESPONSE", "content": ""
        }) + "\n", encoding="utf-8")
        with pytest.raises(TranscriptError, match="no_planner_response"):
            _parse_transcript(tf)

    def test_no_planner_lines(self, tmp_path):
        """No PLANNER_RESPONSE lines at all."""
        from bridge.ag_transcript import TranscriptError, _parse_transcript

        tf = tmp_path / "transcript.jsonl"
        tf.write_text(json.dumps({
            "source": "TOOL", "type": "LIST_DIRECTORY", "content": "..."
        }) + "\n", encoding="utf-8")
        with pytest.raises(TranscriptError, match="no_planner_response"):
            _parse_transcript(tf)

    def test_json_parse_error(self, tmp_path):
        """Malformed JSON → transcript_parse_error."""
        from bridge.ag_transcript import TranscriptError, _parse_transcript

        tf = tmp_path / "transcript.jsonl"
        tf.write_text("not valid json\n", encoding="utf-8")
        with pytest.raises(TranscriptError, match="transcript_parse_error"):
            _parse_transcript(tf)

    def test_skips_empty_lines(self, tmp_path):
        """Blank lines between valid records are ignored."""
        from bridge.ag_transcript import _parse_transcript

        tf = tmp_path / "transcript.jsonl"
        tf.write_text(
            "\n"
            + json.dumps({"source": "MODEL", "type": "PLANNER_RESPONSE", "content": "ok"})
            + "\n\n", encoding="utf-8")
        assert _parse_transcript(tf) == "ok"

    def test_extract_answer_end_to_end(self, tmp_path, monkeypatch):
        """Full extract_answer flow with real files."""
        from bridge.ag_transcript import _AG_BRAIN_DIR, _AG_LOG_DIR, _TRANSCRIPT_DIR, _TRANSCRIPT_FILENAME, extract_answer

        # Create log dir with a cli log containing a UUID
        log_dir = tmp_path / "log"
        log_dir.mkdir()
        log_file = log_dir / "cli-2026-05-22T12-00-00.log"
        uuid = "568b060d-a3c5-4b2a-8af1-fb75ed53c342"
        log_file.write_text(f"[2026] conversation={uuid}\n", encoding="utf-8")

        # Create transcript at the expected path
        brain_dir = tmp_path / "brain"
        brain_dir.mkdir()
        transcript_dir = brain_dir / uuid / _TRANSCRIPT_DIR
        transcript_dir.mkdir(parents=True)
        transcript = transcript_dir / _TRANSCRIPT_FILENAME
        transcript.write_text(
            json.dumps({"source": "MODEL", "type": "PLANNER_RESPONSE", "content": "answer text"}) + "\n",
            encoding="utf-8")

        # Override the module constants
        monkeypatch.setattr("bridge.ag_transcript._AG_LOG_DIR", log_dir)
        monkeypatch.setattr("bridge.ag_transcript._AG_BRAIN_DIR", brain_dir)

        before = {"cli-old.log"}
        after = {"cli-old.log", "cli-2026-05-22T12-00-00.log"}
        answer, cid = extract_answer(before, after)
        assert answer == "answer text"
        assert cid == uuid


# ── log snapshot diff ─────────────────────────


class TestLogSnapshotDiff:
    """B3: _find_new_log edge cases."""

    def test_exactly_one_new_file(self, tmp_path, monkeypatch):
        from bridge.ag_transcript import _find_new_log, _AG_LOG_DIR

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        (log_dir / "cli-new.log").write_text("")
        monkeypatch.setattr("bridge.ag_transcript._AG_LOG_DIR", log_dir)

        result = _find_new_log({"old.log"}, {"old.log", "cli-new.log"})
        assert result.name == "cli-new.log"

    def test_zero_new_files(self, tmp_path, monkeypatch):
        from bridge.ag_transcript import TranscriptError, _find_new_log, _AG_LOG_DIR

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        monkeypatch.setattr("bridge.ag_transcript._AG_LOG_DIR", log_dir)

        with pytest.raises(TranscriptError, match="log_not_found"):
            _find_new_log({"a.log"}, {"a.log"})

    def test_multiple_new_files(self, tmp_path, monkeypatch):
        from bridge.ag_transcript import TranscriptError, _find_new_log, _AG_LOG_DIR

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        monkeypatch.setattr("bridge.ag_transcript._AG_LOG_DIR", log_dir)

        with pytest.raises(TranscriptError, match="log_not_found"):
            _find_new_log({"old.log"}, {"old.log", "a.log", "b.log"})

    def test_path_separator_in_filename_rejected(self, tmp_path, monkeypatch):
        from bridge.ag_transcript import TranscriptError, _find_new_log, _AG_LOG_DIR

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        monkeypatch.setattr("bridge.ag_transcript._AG_LOG_DIR", log_dir)

        with pytest.raises(TranscriptError, match="log_not_found"):
            _find_new_log(set(), {"../escape.log"})


# ── path security ─────────────────────────────


class TestTranscriptPathSecurity:
    """B2: UUID validation, path traversal, resolve containment."""

    def test_valid_uuid_accepted(self):
        from bridge.ag_transcript import _UUID_RE

        assert _UUID_RE.match("568b060d-a3c5-4b2a-8af1-fb75ed53c342")

    def test_uppercase_uuid_rejected(self):
        from bridge.ag_transcript import _UUID_RE

        assert not _UUID_RE.match("568B060D-A3C5-4B2A-8AF1-FB75ED53C342")

    def test_path_traversal_uuid_rejected(self):
        from bridge.ag_transcript import _UUID_RE

        assert not _UUID_RE.match("../../etc/passwd")
        assert not _UUID_RE.match("../secret-dir")
        assert not _UUID_RE.match("a/b/c/d/e/f/g/h")

    def test_short_uuid_rejected(self):
        from bridge.ag_transcript import _UUID_RE

        assert not _UUID_RE.match("568b060d-a3c5-4b2a-8af1")

    def test_resolve_containment_escape_rejected(self, tmp_path, monkeypatch):
        """Resolved path outside _AG_BRAIN_DIR raises transcript_not_found."""
        from bridge.ag_transcript import TranscriptError, _resolve_transcript_path, _AG_BRAIN_DIR

        brain_dir = tmp_path / "brain"
        brain_dir.mkdir()
        monkeypatch.setattr("bridge.ag_transcript._AG_BRAIN_DIR", brain_dir)

        # Create a symlink that escapes
        uuid_dir = brain_dir / "00000000-0000-0000-0000-000000000001"
        uuid_dir.mkdir(parents=True)
        inner = uuid_dir / ".system_generated" / "logs"
        inner.mkdir(parents=True)
        escape = tmp_path / "outside.txt"
        escape.write_text("escaped")
        try:
            (inner / "transcript.jsonl").symlink_to(escape)
        except OSError as exc:
            pytest.skip(f"symlink unsupported on this platform: {exc}")

        with pytest.raises(TranscriptError, match="transcript_not_found"):
            _resolve_transcript_path("00000000-0000-0000-0000-000000000001")

    def test_file_over_5mb_rejected(self, tmp_path, monkeypatch):
        """Transcript > 5 MB raises transcript_not_found."""
        import os as _os
        from bridge.ag_transcript import TranscriptError, _resolve_transcript_path, _AG_BRAIN_DIR

        brain_dir = tmp_path / "brain"
        brain_dir.mkdir()
        monkeypatch.setattr("bridge.ag_transcript._AG_BRAIN_DIR", brain_dir)

        uuid_dir = brain_dir / "00000000-0000-0000-0000-000000000001"
        uuid_dir.mkdir(parents=True)
        inner = uuid_dir / ".system_generated" / "logs"
        inner.mkdir(parents=True)
        tf = inner / "transcript.jsonl"
        tf.write_text(json.dumps({"source": "MODEL", "type": "PLANNER_RESPONSE", "content": "ok"}))

        st = tf.stat()
        fake_st = _os.stat_result((
            st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
            st.st_uid, st.st_gid, 6 * 1024 * 1024,
            st.st_atime, st.st_mtime, st.st_ctime,
        ))
        with mock.patch.object(tf.__class__, "stat", return_value=fake_st):
            with pytest.raises(TranscriptError, match="transcript_not_found"):
                _resolve_transcript_path("00000000-0000-0000-0000-000000000001")
    def test_log_over_5mb_rejected(self, tmp_path):
        """cli-*.log > 5 MB raises uuid_not_found (size checked before read)."""
        import os as _os
        from bridge.ag_transcript import TranscriptError, _extract_uuid

        log = tmp_path / "cli-20260522_000000.log"
        log.write_text("Print mode: conversation=00000000-0000-0000-0000-000000000001")

        st = log.stat()
        fake_st = _os.stat_result((
            st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
            st.st_uid, st.st_gid, 6 * 1024 * 1024,
            st.st_atime, st.st_mtime, st.st_ctime,
        ))
        with mock.patch.object(log.__class__, "stat", return_value=fake_st):
            with pytest.raises(TranscriptError, match="uuid_not_found"):
                _extract_uuid(log)



# ── ag_output_unavailable error reasons ───────


class TestAgOutputUnavailable:
    """B5: All 5 ag_output_unavailable reason templates."""

    def _setup(self, monkeypatch):
        _bin(monkeypatch)
        import bridge.ag_transcript as at_mod

        monkeypatch.setattr(at_mod, "snapshot_log_dir", lambda: {"old.log"})

        class _TranscriptError(Exception):
            def __init__(self, reason):
                self.reason = reason
                super().__init__(reason)

        monkeypatch.setattr(at_mod, "TranscriptError", _TranscriptError)
        return at_mod

    def test_reason_log_not_found(self, monkeypatch):
        at_mod = self._setup(monkeypatch)
        monkeypatch.setattr(at_mod, "extract_answer",
                            lambda before, after: (_ for _ in ()).throw(at_mod.TranscriptError("log_not_found")))
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["hello"])
        assert result["error"] == "ag_output_unavailable"
        assert result["reason"] == "log_not_found"

    def test_reason_uuid_not_found(self, monkeypatch):
        at_mod = self._setup(monkeypatch)
        monkeypatch.setattr(at_mod, "extract_answer",
                            lambda before, after: (_ for _ in ()).throw(at_mod.TranscriptError("uuid_not_found")))
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["hello"])
        assert result["error"] == "ag_output_unavailable"
        assert result["reason"] == "uuid_not_found"

    def test_reason_transcript_not_found(self, monkeypatch):
        at_mod = self._setup(monkeypatch)
        monkeypatch.setattr(at_mod, "extract_answer",
                            lambda before, after: (_ for _ in ()).throw(at_mod.TranscriptError("transcript_not_found")))
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["hello"])
        assert result["error"] == "ag_output_unavailable"
        assert result["reason"] == "transcript_not_found"

    def test_reason_transcript_parse_error(self, monkeypatch):
        at_mod = self._setup(monkeypatch)
        monkeypatch.setattr(at_mod, "extract_answer",
                            lambda before, after: (_ for _ in ()).throw(at_mod.TranscriptError("transcript_parse_error")))
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["hello"])
        assert result["error"] == "ag_output_unavailable"
        assert result["reason"] == "transcript_parse_error"

    def test_reason_no_planner_response(self, monkeypatch):
        at_mod = self._setup(monkeypatch)
        monkeypatch.setattr(at_mod, "extract_answer",
                            lambda before, after: (_ for _ in ()).throw(at_mod.TranscriptError("no_planner_response")))
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _mock_popen_ok())
        result = invoke_ag_cli("ask", ["hello"])
        assert result["error"] == "ag_output_unavailable"
        assert result["reason"] == "no_planner_response"
