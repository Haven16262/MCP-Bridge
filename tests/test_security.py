"""Security-model tests for mcp-bridge (SECURITY.md §11 implementation checklist).

Covers: path validation, symlink handling, size limits, binary detection,
blacklist matching, and audit logging.  All tests use pytest tmp_path to
avoid touching real filesystems.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Inject bridge module — it may be in parent dir relative to tests/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bridge import validators
from bridge.audit import _audit_log
from bridge.tools.files import list_dir, read_file, write_file
from bridge.tools.system import echo, system_status
from bridge.validators import (
    BridgeError,
    LIST_DIR_ENTRY_LIMIT,
    READ_SIZE_LIMIT,
    WHITELIST_ROOTS,
    WRITE_SIZE_LIMIT,
    _error,
    _is_within,
    _match_parts,
    _matches_blacklist,
    _validate_path,
)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


def _set_whitelist(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(validators, "WHITELIST_ROOTS", [str(root.resolve())], raising=True)


def _make_file(p: Path, content: str = "hello") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _make_link(p: Path, target: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink unsupported on this platform: {exc}")
    return p


# ──────────────────────────────────────────────
# §5  path validation
# ──────────────────────────────────────────────


class TestValidatePath:
    """Coverage: §5 seven-step flow, no bypass branch (§11 line 1)."""

    def test_normal_path_within_whitelist(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / "notes.md")
        result = _validate_path(str(f), "read_file")
        assert result == f.resolve()

    def test_path_outside_whitelist(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path / "subdir")
        f = _make_file(tmp_path / "outside.txt")
        with pytest.raises(BridgeError) as exc:
            _validate_path(str(f), "read_file")
        assert exc.value.error_code == "path_denied"
        assert exc.value.reason == "outside_whitelist"

    def test_dotdot_traversal_escape(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path / "allowed")
        (tmp_path / "allowed").mkdir()
        traversal = str(tmp_path / "allowed" / ".." / "outside.txt")
        with pytest.raises(BridgeError) as exc:
            _validate_path(traversal, "read_file")
        assert exc.value.reason == "outside_whitelist"

    def test_symlink_escape(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        _set_whitelist(monkeypatch, allowed)

        # Create a file outside whitelist
        outside = _make_file(tmp_path / "secret.txt", "secret")
        # Symlink inside whitelist pointing outside
        link = allowed / "link"
        _make_link(link, outside)

        with pytest.raises(BridgeError) as exc:
            _validate_path(str(link), "read_file")
        assert exc.value.reason == "outside_whitelist"

    def test_symlink_partial_traversal(self, tmp_path, monkeypatch):
        """Symlink dir → outside, then access symlink/subpath."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        _set_whitelist(monkeypatch, allowed)

        outside_dir = tmp_path / "secret_dir"
        outside_dir.mkdir()
        _make_file(outside_dir / "passwd", "root:x:0:0:...")
        link = allowed / "linkdir"
        _make_link(link, outside_dir)

        # Access through symlink with additional path component
        with pytest.raises(BridgeError) as exc:
            _validate_path(str(link / "passwd"), "read_file")
        assert exc.value.reason == "outside_whitelist"

    def test_blacklist_rejection(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / ".env", "SECRET=...")
        with pytest.raises(BridgeError) as exc:
            _validate_path(str(f), "read_file")
        assert exc.value.reason == "matches_blacklist"

    def test_blacklist_ssh_directory(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        f = _make_file(ssh_dir / "config", "Host *")
        with pytest.raises(BridgeError) as exc:
            _validate_path(str(f), "read_file")
        assert exc.value.reason == "matches_blacklist"

    def test_empty_string_rejected(self, monkeypatch):
        with pytest.raises(BridgeError) as exc:
            _validate_path("", "read_file")
        assert exc.value.reason == "empty_or_non_string"

    def test_none_rejected(self, monkeypatch):
        with pytest.raises(BridgeError) as exc:
            _validate_path(None, "read_file")  # type: ignore
        assert exc.value.reason == "empty_or_non_string"

    def test_whitespace_only_rejected(self, monkeypatch):
        with pytest.raises(BridgeError) as exc:
            _validate_path("   ", "read_file")
        assert exc.value.reason == "empty_or_non_string"

    def test_relative_path_rejected(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        with pytest.raises(BridgeError) as exc:
            _validate_path("relative/path.txt", "read_file")
        assert exc.value.reason == "relative_path_forbidden"

    def test_neighbor_prefix_not_confused(self, tmp_path, monkeypatch):
        """§5 step 5: /root/workspace/MCP-evil must NOT match /root/workspace/MCP."""
        _set_whitelist(monkeypatch, tmp_path / "MCP")
        (tmp_path / "MCP").mkdir()
        evil = _make_file(tmp_path / "MCP-evil" / "file.txt")
        with pytest.raises(BridgeError) as exc:
            _validate_path(str(evil), "read_file")
        # MCP-evil is NOT within MCP (trailing-separator guard)
        assert exc.value.reason == "outside_whitelist"


# ──────────────────────────────────────────────
# §6.1  read_file
# ──────────────────────────────────────────────


class TestReadFile:
    """Coverage: size limit (§11 line 3), binary detection (§11 line 4)."""

    def test_read_normal_file(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / "hello.txt", "Hello World")
        result = read_file(str(f))
        assert result["content"] == "Hello World"
        assert result["size"] == 11
        assert result["encoding"] == "utf-8"

    def test_file_not_found(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        result = read_file(str(tmp_path / "nonexistent.txt"))
        assert result["error"] == "not_found"

    def test_directory_rejected(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        d = tmp_path / "subdir"
        d.mkdir()
        result = read_file(str(d))
        assert result["error"] == "is_directory"

    def test_binary_file_rejected(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00\x01\xff\xfe\x89PNG\r\n")
        result = read_file(str(f))
        assert result["error"] == "binary_file"

    def test_oversized_file_rejected(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = tmp_path / "large.txt"
        f.write_bytes(b"A" * (READ_SIZE_LIMIT + 1))
        result = read_file(str(f))
        assert result["error"] == "file_too_large"

    def test_empty_file(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / "empty.txt", "")
        result = read_file(str(f))
        assert result["content"] == ""
        assert result["size"] == 0


# ──────────────────────────────────────────────
# §6.2  write_file
# ──────────────────────────────────────────────


class TestWriteFile:
    """Coverage: size limit, modes, parent creation, path security."""

    def test_overwrite_mode(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / "out.txt", "old")
        result = write_file(str(f), "new", "overwrite")
        assert result["bytes_written"] == 3
        assert Path(f).read_text() == "new"

    def test_create_only_success(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = tmp_path / "new.txt"
        result = write_file(str(f), "fresh", "create_only")
        assert result["bytes_written"] == 5

    def test_create_only_refuses_existing(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / "exists.txt", "content")
        result = write_file(str(f), "fresh", "create_only")
        assert result["error"] == "file_exists"

    def test_append_mode(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / "log.txt", "line1\n")
        result = write_file(str(f), "line2\n", "append")
        assert result["bytes_written"] == 6
        assert Path(f).read_text() == "line1\nline2\n"

    def test_content_too_large(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        content = "A" * (WRITE_SIZE_LIMIT + 1)
        result = write_file(str(tmp_path / "big.txt"), content)
        assert result["error"] == "content_too_large"

    def test_auto_create_parent(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = tmp_path / "deeply" / "nested" / "file.txt"
        result = write_file(str(f), "ok")
        assert result["bytes_written"] == 2
        assert Path(f).read_text() == "ok"

    def test_parent_outside_whitelist_rejected(self, tmp_path, monkeypatch):
        # File path resolves into whitelist but an ancestor needs creation
        # outside — this is caught because the resolved path would be outside
        _set_whitelist(monkeypatch, tmp_path / "allowed")
        (tmp_path / "allowed").mkdir()
        f = tmp_path / "not_allowed" / "file.txt"
        result = write_file(str(f), "test")
        assert result["error"] == "path_denied"
        assert result["reason"] == "outside_whitelist"

    def test_invalid_mode(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        result = write_file(str(tmp_path / "f.txt"), "x", "bad_mode")
        assert result["error"] == "invalid_mode"

    def test_outside_whitelist_write(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path / "allowed")
        (tmp_path / "allowed").mkdir()
        result = write_file(str(tmp_path / "outside.txt"), "secret")
        assert result["error"] == "path_denied"


# ──────────────────────────────────────────────
# §6.3  list_dir
# ──────────────────────────────────────────────


class TestListDir:
    """Coverage: path validation, symlink listing, entry limit."""

    def test_list_normal_directory(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        _make_file(tmp_path / "a.txt", "a")
        _make_file(tmp_path / "b.txt", "bb")
        (tmp_path / "sub").mkdir()
        result = list_dir(str(tmp_path))
        assert "error" not in result
        names = [e["name"] for e in result["entries"]]
        assert "a.txt" in names
        assert "b.txt" in names
        assert "sub" in names
        # Verify dir type
        dir_entry = [e for e in result["entries"] if e["name"] == "sub"][0]
        assert dir_entry["type"] == "dir"

    def test_symlink_listed_but_not_followed(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        target = _make_file(tmp_path / "real.txt", "real")
        link = tmp_path / "link.txt"
        _make_link(link, target)
        result = list_dir(str(tmp_path))
        link_entry = [e for e in result["entries"] if e["name"] == "link.txt"][0]
        assert link_entry["type"] == "symlink"

    def test_empty_directory(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        result = list_dir(str(tmp_path))
        assert result["entries"] == []

    def test_truncation_when_over_limit(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        # Create more entries than the limit
        for i in range(LIST_DIR_ENTRY_LIMIT + 10):
            _make_file(tmp_path / f"file_{i:05d}.txt", "x")
        result = list_dir(str(tmp_path))
        assert result["truncated"] is True
        assert len(result["entries"]) == LIST_DIR_ENTRY_LIMIT

    def test_not_a_directory(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        f = _make_file(tmp_path / "file.txt", "text")
        result = list_dir(str(f))
        assert result["error"] == "not_directory"


# ──────────────────────────────────────────────
# §6.4  system_status
# ──────────────────────────────────────────────


class TestSystemStatus:
    def test_returns_all_fields(self):
        result = system_status()
        required = {
            "hostname", "platform", "uptime_seconds", "cpu_count",
            "cpu_percent", "memory", "disk", "process_count", "bridge_time_utc",
        }
        assert required.issubset(result.keys())
        assert "total_mb" in result["memory"]
        assert "used_mb" in result["memory"]
        assert "available_mb" in result["memory"]
        assert isinstance(result["disk"], list)

    def test_no_process_list_leaked(self):
        result = system_status()
        assert "processes" not in result
        assert "process_list" not in result

    def test_no_network_info_leaked(self):
        result = system_status()
        assert "network" not in result
        assert "interfaces" not in result
        assert "ip" not in result


# ──────────────────────────────────────────────
# §8  audit log
# ──────────────────────────────────────────────


class TestAuditLog:
    """Coverage: audit log format (§11 line 6), real on-disk verification."""

    @pytest.fixture(autouse=True)
    def _redirect_audit(self, tmp_path, monkeypatch):
        """Redirect bridge.audit logger to a tmp_path subdir for real verification.

        Log file is created in a subdirectory so it doesn't pollute list_dir tests.
        """
        audit_dir = tmp_path / "_audit"
        audit_dir.mkdir()
        log_file = audit_dir / "test_audit.log"
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)
        self.__class__._audit_log_path = log_file
        yield
        logger.handlers.clear()

    def _read_audit(self) -> list:
        lines = self._audit_log_path.read_text(encoding="utf-8").strip().split("\n")
        return [json.loads(line) for line in lines if line]

    def test_audit_log_format(self):
        system_status()
        records = self._read_audit()
        assert len(records) >= 1
        ss = [r for r in records if r["tool"] == "system_status"]
        assert len(ss) == 1
        rec = ss[0]
        assert "ts" in rec
        assert rec["tool"] == "system_status"
        assert rec["result"] == "ok"
        assert rec["client"] is None

    def test_echo_writes_audit(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        echo("test-audit")
        records = self._read_audit()
        echo_records = [r for r in records if r["tool"] == "echo"]
        assert len(echo_records) == 1
        rec = echo_records[0]
        assert rec["result"] == "ok"
        assert rec["args_summary"] == {"message": "test-audit"}

    def test_read_file_audit_on_rejection(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        read_file(str(tmp_path / "nonexistent.txt"))
        records = self._read_audit()
        read_recs = [r for r in records if r["tool"] == "read_file"]
        assert len(read_recs) >= 1
        rec = read_recs[-1]
        assert rec["result"] == "error"
        assert rec["details"]["error"] == "not_found"

    def test_write_file_audit_logged(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        result = write_file(str(tmp_path / "audit_test.txt"), "log-me")
        assert result["bytes_written"] == 6
        records = self._read_audit()
        write_recs = [r for r in records if r["tool"] == "write_file"]
        assert len(write_recs) >= 1
        rec = write_recs[-1]
        assert rec["result"] == "ok"
        assert rec["details"]["bytes_written"] == 6
        # Content must NOT appear in audit log
        assert "log-me" not in json.dumps(rec)

    def test_list_dir_audit_logged(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        _make_file(tmp_path / "x.txt", "x")
        list_dir(str(tmp_path))
        records = self._read_audit()
        list_recs = [r for r in records if r["tool"] == "list_dir"]
        assert len(list_recs) >= 1
        rec = list_recs[-1]
        assert rec["result"] == "ok"
        assert rec["details"]["entry_count"] >= 1
        # Entry names must NOT appear in audit log
        assert "x.txt" not in json.dumps(rec)

    def test_path_denied_audit_logged(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path / "allowed")
        read_file(str(tmp_path / "outside.txt"))
        records = self._read_audit()
        denied = [r for r in records if r["result"] == "error"]
        assert len(denied) >= 1
        rec = denied[-1]
        assert rec["details"]["error"] == "path_denied"
        assert rec["details"]["reason"] == "outside_whitelist"
        # args_summary records the path (by design, for audit)
        assert "path" in rec["args_summary"]
        # But details/reason must NOT leak the real path
        details_blob = json.dumps(rec["details"])
        assert str(tmp_path) not in details_blob
        # Whitelist assertion: only "error" and "reason" allowed; new
        # fields beyond these two need explicit security sign-off.
        assert set(rec["details"].keys()) <= {"error", "reason"}


# ──────────────────────────────────────────────
# §11  error messages never leak real paths
# ──────────────────────────────────────────────


class TestErrorMessagesNoPathLeak:
    """Coverage: §11 line 2 — path denial never exposes real cwd / absolute path."""

    def test_outside_whitelist_no_abs_path(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path / "allowed")
        (tmp_path / "allowed").mkdir()
        result = read_file(str(tmp_path / "secret.txt"))
        assert "error" in result
        assert str(tmp_path) not in str(result)
        # Only "path_denied" code + reason, no path
        assert result["error"] == "path_denied"
        assert "reason" in result

    def test_blacklist_no_path_in_response(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        _make_file(tmp_path / ".env", "SECRET=x")
        result = read_file(str(tmp_path / ".env"))
        assert result["error"] == "path_denied"
        # Response must NOT contain the actual filename
        assert ".env" not in str(result)

    def test_relative_path_no_cwd_leak(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        result = read_file("relative.txt")
        assert result["error"] == "path_denied"
        assert result["reason"] == "relative_path_forbidden"
        # Must not leak cwd
        cwd = os.getcwd()
        assert cwd not in str(result)

    def test_none_path_no_traceback(self, tmp_path, monkeypatch):
        _set_whitelist(monkeypatch, tmp_path)
        result = read_file(None)  # type: ignore
        assert result["error"] == "path_denied"
        assert "None" not in str(result.get("reason", ""))


# ──────────────────────────────────────────────
# _is_within  edge cases
# ──────────────────────────────────────────────


class TestIsWithin:
    """_is_within expects an already-resolved path (as _validate_path passes it).
    Tests resolve the path arg so they hold on Windows too, where resolve()
    adds a drive-letter prefix that an un-resolved path would lack."""

    def test_exact_match(self):
        root = "/root/workspace/MCP"
        assert _is_within(Path(root).resolve(strict=False), root) is True

    def test_child_inside(self):
        root = "/root/workspace/MCP"
        assert _is_within(Path(root + "/proj/file.txt").resolve(strict=False), root) is True

    def test_neighbor_prefix_rejected(self):
        root = "/root/workspace/MCP"
        assert _is_within(Path(root + "-evil/file.txt").resolve(strict=False), root) is False

    def test_case_insensitive(self):
        root = "/root/workspace/MCP"
        assert _is_within(Path("/ROOT/WORKSPACE/MCP/file.txt").resolve(strict=False), root) is True


# ──────────────────────────────────────────────
# _matches_blacklist
# ──────────────────────────────────────────────


class TestMatchesBlacklist:
    def test_env_file(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.env")) is True

    def test_env_prod(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.env.prod")) is True

    def test_ssh_config(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.ssh/config")) is True

    def test_credentials(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/credentials.json")) is True

    def test_secret_in_name(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/my-secret-key.txt")) is True

    def test_pem_file(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/cert.pem")) is True

    def test_normal_file_passes(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/notes.md")) is False

    def test_normal_dir_passes(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/project/src/main.py")) is False

    def test_case_insensitive(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.ENV")) is True

    # ── deep path recursion (CRITICAL fix verification) ──

    def test_ssh_deep_subdirectory(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.ssh/sub/key")) is True

    def test_aws_deep_cache(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.aws/sso/cache/x.json")) is True

    def test_gnupg_deep_private_keys(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.gnupg/private-keys/y.key")) is True

    # ── Windows case variants (HIGH: 6 additional variants) ──

    def test_dot_SSH_config(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.SSH/config")) is True

    def test_dot_AWS_credentials(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.AWS/credentials")) is True

    def test_dot_GnuPG_secring(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.GnuPG/secring.gpg")) is True

    def test_dot_ENV_local(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.ENV.local")) is True

    def test_Id_Rsa_pub(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/Id_Rsa.pub")) is True

    def test_My_Secret_Key(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/My-Secret-Key.txt")) is True

    # ── critic round 2: additional Windows case variants ──

    def test_dot_GIT_config(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/.GIT/config")) is True

    def test_COOKIES_TXT(self):
        assert _matches_blacklist(Path("/root/workspace/MCP/COOKIES.TXT")) is True


# ──────────────────────────────────────────────
# Shared root (Phase 2.1.x)
# ──────────────────────────────────────────────


class TestSharedRoot:
    """Coverage: shared root whitelist entry (MCP-shared) works for all ops."""

    def _setup_whitelist(self, monkeypatch, primary, shared):
        monkeypatch.setattr(
            validators,
            "WHITELIST_ROOTS",
            [str(primary.resolve()), str(shared.resolve())],
            raising=True,
        )

    def test_shared_write_file(self, tmp_path, monkeypatch):
        shared = tmp_path / "MCP-shared"
        shared.mkdir()
        self._setup_whitelist(monkeypatch, tmp_path, shared)
        result = write_file(str(shared / "test.txt"), "shared content")
        assert result["bytes_written"] == 14

    def test_shared_read_file(self, tmp_path, monkeypatch):
        shared = tmp_path / "MCP-shared"
        shared.mkdir()
        self._setup_whitelist(monkeypatch, tmp_path, shared)
        _make_file(shared / "readme.md", "hello shared")
        result = read_file(str(shared / "readme.md"))
        assert result["content"] == "hello shared"

    def test_shared_list_dir(self, tmp_path, monkeypatch):
        shared = tmp_path / "MCP-shared"
        shared.mkdir()
        self._setup_whitelist(monkeypatch, tmp_path, shared)
        _make_file(shared / "a.txt", "a")
        _make_file(shared / "b.txt", "b")
        result = list_dir(str(shared))
        assert len(result["entries"]) == 2

    def test_shared_blacklist_still_applies(self, tmp_path, monkeypatch):
        shared = tmp_path / "MCP-shared"
        shared.mkdir()
        self._setup_whitelist(monkeypatch, tmp_path, shared)
        _make_file(shared / ".env", "SECRET=x")
        result = read_file(str(shared / ".env"))
        assert result["error"] == "path_denied"

    def test_shared_outside_whitelist_path_rejected(self, tmp_path, monkeypatch):
        """File outside any whitelist root is rejected even when shared root exists."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        shared = tmp_path / "MCP-shared"
        shared.mkdir()
        self._setup_whitelist(monkeypatch, allowed, shared)
        # outside is in tmp_path but NOT in allowed or shared
        outside = tmp_path / "outside.txt"
        _make_file(outside, "outside")
        result = read_file(str(outside))
        assert result["error"] == "path_denied"


# ──────────────────────────────────────────────
# BridgeError / _error
# ──────────────────────────────────────────────


class TestSharedRootDisable:
    """C2: _ensure_shared_root() → WHITELIST_ROOTS pop + audit."""

    def _setup_audit(self, tmp_path):
        audit_file = tmp_path / "_audit" / "test.log"
        audit_file.parent.mkdir()
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)
        return audit_file

    def test_happy_path_returns_false_and_logs_ensured(self, tmp_path, monkeypatch):
        """Successful mkdir → (False, ""), audit has shared_root_ensured."""
        from bridge.server import _ensure_shared_root
        from bridge.validators import WHITELIST_ROOTS as wl

        audit_file = self._setup_audit(tmp_path)
        dummy = str(tmp_path / "MCP-shared-ok")
        wl.append(dummy)
        original_count = len(wl)

        disabled, reason = _ensure_shared_root(dummy)

        assert disabled is False
        assert reason == ""
        assert len(wl) == original_count  # not popped
        records = [json.loads(line) for line in audit_file.read_text().strip().split("\n") if line]
        ensured = [r for r in records if r.get("details", {}).get("created") is not None]
        assert len(ensured) == 1

    def test_mkdir_failure_pops_whitelist_and_logs(self, tmp_path, monkeypatch):
        """mkdir OSError → (True, "mkdir_failed") + pop + shared_root_disabled."""
        from bridge.server import _ensure_shared_root
        from bridge.validators import WHITELIST_ROOTS as wl

        audit_file = self._setup_audit(tmp_path)
        dummy = str(tmp_path / "MCP-shared-fail")
        wl.append(dummy)
        original_count = len(wl)

        _real_mkdir = Path.mkdir
        def _fail_mkdir(self_path, *a, **kw):
            if str(self_path) == dummy:
                raise OSError("permission denied")
            return _real_mkdir(self_path, *a, **kw)
        monkeypatch.setattr(Path, "mkdir", _fail_mkdir)

        disabled, reason = _ensure_shared_root(dummy)

        assert disabled is True
        assert reason == "mkdir_failed"
        assert len(wl) == original_count - 1
        assert dummy not in wl
        records = [json.loads(line) for line in audit_file.read_text().strip().split("\n") if line]
        norm = str(Path(dummy)).replace("\\", "/").lower()
        dr = [r for r in records if r.get("details", {}).get("path") == norm]
        assert len(dr) == 1
        assert dr[0]["details"]["reason"] == "mkdir_failed"

    def test_path_exists_not_a_directory_disables(self, tmp_path, monkeypatch):
        """mkdir succeeds but !is_dir → (True, "path_exists_but_not_a_directory")."""
        from bridge.server import _ensure_shared_root
        from bridge.validators import WHITELIST_ROOTS as wl

        audit_file = self._setup_audit(tmp_path)
        dummy = str(tmp_path / "MCP-shared-file")
        wl.append(dummy)
        original_count = len(wl)

        def _noop_mkdir(self_path, *a, **kw):
            return
        monkeypatch.setattr(Path, "mkdir", _noop_mkdir)

        _real_isdir = Path.is_dir
        def _fake_isdir(self_path):
            if str(self_path) == dummy:
                return False
            return _real_isdir(self_path)
        monkeypatch.setattr(Path, "is_dir", _fake_isdir)

        disabled, reason = _ensure_shared_root(dummy)

        assert disabled is True
        assert reason == "path_exists_but_not_a_directory"
        assert len(wl) == original_count - 1
        assert dummy not in wl
        records = [json.loads(line) for line in audit_file.read_text().strip().split("\n") if line]
        norm = str(Path(dummy)).replace("\\", "/").lower()
        dr = [r for r in records if r.get("details", {}).get("path") == norm]
        assert len(dr) == 1
        assert dr[0]["details"]["reason"] == "path_exists_but_not_a_directory"


# ──────────────────────────────────────────────
# TOCTOU (C3)
# ──────────────────────────────────────────────


class TestTOCTOU:
    """Coverage: TOCTOU post-write realpath recheck (C3)."""

    def _setup_audit(self, tmp_path):
        audit_file = tmp_path / "_audit" / "t.log"
        audit_file.parent.mkdir()
        handler = logging.FileHandler(audit_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("bridge.audit")
        logger.handlers.clear()
        logger.addHandler(handler)
        return audit_file

    def test_normal_write_does_not_trigger_toctou(self, tmp_path, monkeypatch):
        """Happy path: write succeeds without TOCTOU false positive."""
        _set_whitelist(monkeypatch, tmp_path)
        audit_file = self._setup_audit(tmp_path)
        f = tmp_path / "normal.txt"
        result = write_file(str(f), "hello toctou")
        assert result["bytes_written"] == 12
        assert f.read_text() == "hello toctou"
        # Verify no toctou_detected in audit
        records = [json.loads(line) for line in audit_file.read_text().strip().split("\n") if line]
        toctou = [r for r in records if r.get("details", {}).get("reason") == "toctou_detected"]
        assert len(toctou) == 0

    def test_resolve_divergence_triggers_toctou(self, tmp_path, monkeypatch):
        """Attack: post-write Path.resolve returns outside-whitelist → TOCTOU fires."""
        _set_whitelist(monkeypatch, tmp_path)
        audit_file = self._setup_audit(tmp_path)
        f = tmp_path / "trapped.txt"

        # Use a counter: 1st resolve (validation) → in-whitelist; 2nd → outside
        call_count = [0]
        original_resolve = Path.resolve
        def _attack_resolve(self_path, strict=False):
            call_count[0] += 1
            if self_path.name == "trapped.txt" and call_count[0] > 1:
                return Path("/etc/shadow")
            return original_resolve(self_path, strict)
        monkeypatch.setattr(Path, "resolve", _attack_resolve)

        result = write_file(str(f), "should trigger toctou")
        assert result["error"] == "path_denied"
        assert result["reason"] == "toctou_detected"
        # File must have been deleted
        assert not f.exists()
        # Audit must contain toctou_detected
        records = [json.loads(line) for line in audit_file.read_text().strip().split("\n") if line]
        toctou = [r for r in records if r.get("details", {}).get("reason") == "toctou_detected"]
        assert len(toctou) == 1
        assert toctou[0]["details"]["error"] == "path_denied"

    def test_toctou_uses_test_whitelist_not_original(self, tmp_path, monkeypatch):
        """TOCTOU check must use monkeypatched WHITELIST_ROOTS, not module load value.

        Arrange: whitelist = tmp_path only; attack path = /root/workspace/MCP/
        (which IS in the original whitelist but NOT in the test whitelist).
        """
        _set_whitelist(monkeypatch, tmp_path)
        audit_file = self._setup_audit(tmp_path)
        f = tmp_path / "cross_check.txt"

        call_count = [0]
        original_resolve = Path.resolve
        def _attack_resolve(self_path, strict=False):
            call_count[0] += 1
            if self_path.name == "cross_check.txt" and call_count[0] > 1:
                # Return a path that IS in the ORIGINAL whitelist (/root/workspace/MCP/)
                # but NOT in the test whitelist (tmp_path).
                return Path("/root/workspace/MCP/shadow.txt")
            return original_resolve(self_path, strict)
        monkeypatch.setattr(Path, "resolve", _attack_resolve)

        result = write_file(str(f), "should trigger")
        assert result["error"] == "path_denied"
        assert result["reason"] == "toctou_detected"


class TestBridgeError:
    def test_error_code_and_reason(self):
        e = BridgeError("test_code", "test reason")
        assert e.error_code == "test_code"
        assert e.reason == "test reason"
        assert str(e) == "test_code: test reason"

    def test_error_helper(self):
        e = BridgeError("path_denied", "outside_whitelist")
        d = _error(e)
        assert d == {"error": "path_denied", "reason": "outside_whitelist"}
