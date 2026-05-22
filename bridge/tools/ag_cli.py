"""invoke_ag_cli tool (SECURITY.md §6.5).

Command whitelist schema with per-subcommand argv_template, timeout /
limit, and args validation.  Uses Popen + communicate with
platform-aware process group isolation.

For ``ask``: spawns ag, then extracts the answer from ag's transcript
file after the subprocess exits (ag v1.0.0 does not write to pipes).
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import threading
import time
from typing import Any, Dict

from bridge.audit import _audit_log
from bridge.process_tree import _kill_process_tree
from bridge.server import mcp

# ── Constants ─────────────────────────────────

_IS_WINDOWS = platform.system() == "Windows"
_AG_BINARY: str | None = None
"""Cached absolute path to ``ag``, set once at import time."""

PROMPT_SENTINEL = "<PROMPT>"
"""Placeholder in *argv_template* replaced with the user prompt at call time."""

ALLOWED_SUBCOMMANDS: Dict[str, dict] = {
    "--version": {
        "argv_template": ["--version"],
        "args_schema": {"type": "exact", "args": []},
        "timeout_s": 10,
        "stdout_limit_bytes": 10 * 1024,
    },
    "ask": {
        "argv_template": ["--print", PROMPT_SENTINEL, "--print-timeout", "10m",
                          "--dangerously-skip-permissions", "--sandbox"],
        "args_schema": {"type": "single_prompt", "min_bytes": 1, "max_bytes": 16384},
        "timeout_s": 660,
        "answer_limit_bytes": 1024 * 1024,
    },
}

_ask_lock = threading.Lock()


# ── Args validation ───────────────────────────


def _validate_args(subcommand: str, args: list) -> str | None:
    """Validate *args* against the subcommand's *args_schema*."""
    schema = ALLOWED_SUBCOMMANDS[subcommand]["args_schema"]
    stype = schema["type"]

    if stype == "exact":
        if args != schema["args"]:
            return "args not in allowed list"
    elif stype == "single_prompt":
        if len(args) != 1 or not isinstance(args[0], str):
            return "args not in allowed list"
        prompt_bytes = len(args[0].encode("utf-8"))
        if not (schema["min_bytes"] <= prompt_bytes <= schema["max_bytes"]):
            return "prompt size out of range"

    return None


# ── Tool ──────────────────────────────────────


@mcp.tool
def invoke_ag_cli(subcommand: str, args: list | None = None) -> dict:
    """Invoke the antigravity CLI (``ag``) with the given subcommand and args.

    Only commands in the allowlist are permitted.  The subprocess runs under
    strict constraints: list args, no shell, no stdin, per-subcommand timeout.
    """
    if args is None:
        args = []

    # ── input validation ──
    if not isinstance(subcommand, str) or not subcommand.strip():
        _audit_log(
            "invoke_ag_cli", {"subcommand": str(subcommand), "args_count": 0}, "error",
            {"error": "invalid_subcommand", "reason": str(subcommand)},
        )
        return {"error": "invalid_subcommand", "reason": str(subcommand)}

    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        _audit_log(
            "invoke_ag_cli", {"subcommand": subcommand, "args_count": 0}, "error",
            {"error": "invalid_args", "reason": "args must be list[str]"},
        )
        return {"error": "invalid_args", "reason": "args must be list[str]"}

    # ── binary check ──
    if _AG_BINARY is None:
        _audit_log(
            "invoke_ag_cli", {"subcommand": subcommand, "args_count": len(args)}, "error",
            {"error": "ag_cli_unavailable", "reason": "ag binary not found on PATH"},
        )
        return {"error": "ag_cli_unavailable", "reason": "ag binary not found on PATH"}

    # ── command whitelist ──
    spec = ALLOWED_SUBCOMMANDS.get(subcommand)
    if spec is None:
        _audit_log(
            "invoke_ag_cli", {"subcommand": subcommand, "args_count": len(args)}, "error",
            {"error": "command_not_allowed", "reason": f"ag {subcommand}"},
        )
        return {"error": "command_not_allowed", "reason": f"ag {subcommand}"}

    # ── args validation ──
    arg_error = _validate_args(subcommand, args)
    if arg_error is not None:
        _audit_log(
            "invoke_ag_cli", {"subcommand": subcommand, "args_count": len(args)}, "error",
            {"error": "args_not_allowed", "reason": arg_error},
        )
        return {"error": "args_not_allowed", "reason": arg_error}

    # ── args_summary (shared across success / timeout / error paths) ──
    args_summary: dict = {"subcommand": subcommand, "args_count": len(args)}
    if subcommand == "ask" and len(args) == 1:
        args_summary["prompt_bytes"] = len(args[0].encode("utf-8"))

    # ── build argv (PROMPT_SENTINEL → args[0], never include user prompt literally in template) ──
    argv = [_AG_BINARY]
    for tok in spec["argv_template"]:
        argv.append(args[0] if tok == PROMPT_SENTINEL else tok)

    # ── platform-aware process group ──
    if _IS_WINDOWS:
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP
        preexec_fn = None
    else:
        creation_flags = 0
        preexec_fn = os.setsid

    timeout_s = spec["timeout_s"]
    start_ns = time.perf_counter_ns()

    # ── ask: serial lock + transcript extraction ──
    if subcommand == "ask":
        import bridge.ag_transcript as _at

        with _ask_lock:
            log_before = _at.snapshot_log_dir()

            try:
                proc = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                    creationflags=creation_flags,
                    preexec_fn=preexec_fn,
                )
                proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                _kill_process_tree(proc.pid)
                _audit_log(
                    "invoke_ag_cli", args_summary, "warning",
                    {"event": "tree_killed", "pid": proc.pid, "killed": True},
                )
                try:
                    proc.communicate()
                except Exception:
                    pass
                _audit_log(
                    "invoke_ag_cli", args_summary, "error",
                    {"error": "timeout", "reason": f"timed out after {timeout_s}s"},
                )
                return {"error": "timeout", "reason": f"timed out after {timeout_s}s"}
            except OSError:
                _audit_log(
                    "invoke_ag_cli", args_summary, "error",
                    {"error": "execution_error", "reason": "failed to execute binary"},
                )
                return {"error": "execution_error", "reason": "failed to execute binary"}

            log_after = _at.snapshot_log_dir()

            try:
                answer, conversation_id = _at.extract_answer(log_before, log_after)
            except _at.TranscriptError as e:
                _audit_log(
                    "invoke_ag_cli", args_summary, "error",
                    {"error": "ag_output_unavailable", "reason": e.reason},
                )
                return {"error": "ag_output_unavailable", "reason": e.reason}

            answer_limit = spec["answer_limit_bytes"]
            answer_bytes = len(answer.encode("utf-8"))
            if answer_bytes > answer_limit:
                encoded = answer.encode("utf-8")
                answer = encoded[:answer_limit].decode("utf-8", errors="replace")
                answer += f"\n[truncated at {answer_limit} bytes]"

            duration_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000)

            _audit_log(
                "invoke_ag_cli", args_summary, "ok",
                {
                    "exit_code": proc.returncode,
                    "answer_bytes": min(answer_bytes, answer_limit),
                    "conversation_id": conversation_id,
                    "duration_ms": duration_ms,
                },
            )
            return {
                "exit_code": proc.returncode,
                "answer": answer,
                "conversation_id": conversation_id,
                "duration_ms": duration_ms,
                "command": f"ag {subcommand}",
            }

    # ── --version (and future non-ask subcommands): direct stdout ──
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            creationflags=creation_flags,
            preexec_fn=preexec_fn,
        )
        stdout_out, stderr_out = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc.pid)
        _audit_log(
            "invoke_ag_cli", args_summary, "warning",
            {"event": "tree_killed", "pid": proc.pid, "killed": True},
        )
        try:
            stdout_out, stderr_out = proc.communicate()
        except Exception:
            stdout_out, stderr_out = "", ""
        _audit_log(
            "invoke_ag_cli", args_summary, "error",
            {"error": "timeout", "reason": f"timed out after {timeout_s}s"},
        )
        return {"error": "timeout", "reason": f"timed out after {timeout_s}s"}
    except OSError:
        _audit_log(
            "invoke_ag_cli", args_summary, "error",
            {"error": "execution_error", "reason": "failed to execute binary"},
        )
        return {"error": "execution_error", "reason": "failed to execute binary"}

    duration_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000)

    stdout_limit = spec["stdout_limit_bytes"]
    stdout = stdout_out[:stdout_limit]
    if len(stdout_out) > stdout_limit:
        stdout += f"\n[truncated at {stdout_limit} bytes]"
    stderr = stderr_out[:stdout_limit]
    if len(stderr_out) > stdout_limit:
        stderr += f"\n[truncated at {stdout_limit} bytes]"

    _audit_log(
        "invoke_ag_cli", args_summary, "ok",
        {
            "exit_code": proc.returncode,
            "stdout_size": len(stdout_out),
            "stderr_size": len(stderr_out),
            "duration_ms": duration_ms,
        },
    )
    return {
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
        "command": f"ag {subcommand}",
    }


# ── Startup: detect ag binary ─────────────────

_AG_BINARY = shutil.which("ag")
if _AG_BINARY is not None:
    _audit_log("bridge", {}, "ag_cli_ensured", {"path": _AG_BINARY})
else:
    _audit_log("bridge", {}, "ag_cli_not_found", {"reason": "ag not on PATH"})
