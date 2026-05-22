"""File-operation tools: list_dir, read_file, write_file.

All path-accepting tools route through :func:`bridge.validators._validate_path`
(SECURITY.md §5 seven-step flow).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from bridge.audit import _audit_log
from bridge.server import mcp
import bridge.validators as _v
from bridge.validators import (
    BridgeError,
    LIST_DIR_ENTRY_LIMIT,
    READ_SIZE_LIMIT,
    WRITE_SIZE_LIMIT,
    _error,
    _is_within,
    _validate_path,
)


@mcp.tool
def list_dir(path: str) -> dict:
    """List directory entries (non-recursive).

    Symlinks are listed as type=symlink but never followed.
    Maximum 5000 entries; set truncated=true if exceeded.
    """
    try:
        resolved = _validate_path(path, "list_dir")
    except BridgeError as e:
        return _error(e)

    if not resolved.is_dir():
        _audit_log("list_dir", {"path": path}, "error", {"error": "not_directory", "reason": "path is not a directory"})
        return {"error": "not_directory", "reason": "path is not a directory"}

    entries: List[Dict[str, Any]] = []
    truncated = False

    try:
        for entry in sorted(resolved.iterdir()):
            if len(entries) >= LIST_DIR_ENTRY_LIMIT:
                truncated = True
                break
            st = entry.stat()
            etype = "symlink" if entry.is_symlink() else ("dir" if entry.is_dir() else "file")
            entries.append(
                {
                    "name": entry.name,
                    "type": etype,
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                }
            )
    except PermissionError:
        _audit_log("list_dir", {"path": path}, "error", {"error": "permission_denied", "reason": "cannot read directory"})
        return {"error": "permission_denied", "reason": "cannot read directory"}

    entry_count = len(entries)
    _audit_log(
        "list_dir", {"path": path}, "ok",
        {"entry_count": entry_count, "truncated": truncated},
    )
    result: Dict[str, Any] = {"entries": entries}
    if truncated:
        result["truncated"] = True
    return result


@mcp.tool
def read_file(path: str) -> dict:
    """Read file contents as UTF-8 text.

    Rejects files larger than 1 MB and binary (non-UTF-8) files.
    """
    try:
        resolved = _validate_path(path, "read_file")
    except BridgeError as e:
        return _error(e)

    if not resolved.exists():
        _audit_log("read_file", {"path": path}, "error", {"error": "not_found", "reason": "file not found"})
        return {"error": "not_found", "reason": "file not found"}

    if resolved.is_dir():
        _audit_log("read_file", {"path": path}, "error", {"error": "is_directory", "reason": "path is a directory"})
        return {"error": "is_directory", "reason": "path is a directory"}

    if resolved.stat().st_size > READ_SIZE_LIMIT:
        _audit_log(
            "read_file", {"path": path}, "error",
            {"error": "file_too_large", "reason": f"file exceeds {READ_SIZE_LIMIT} bytes"},
        )
        return {"error": "file_too_large", "reason": f"file exceeds {READ_SIZE_LIMIT} bytes"}

    try:
        content = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        _audit_log("read_file", {"path": path}, "error", {"error": "binary_file", "reason": "file is not valid UTF-8 text"})
        return {"error": "binary_file", "reason": "file is not valid UTF-8 text"}

    size = resolved.stat().st_size
    _audit_log("read_file", {"path": path}, "ok", {"size": size})
    return {"content": content, "size": size, "encoding": "utf-8"}


@mcp.tool
def write_file(path: str, content: str, mode: str = "overwrite") -> dict:
    """Write UTF-8 text to a file.

    Modes:
      - overwrite (default): create or overwrite
      - append: append to existing file or create new
      - create_only: fail if file already exists

    Content size limit: 5 MB.  Parent directories are created automatically.
    """
    if mode not in ("overwrite", "append", "create_only"):
        _audit_log(
            "write_file", {"path": path, "mode": mode}, "error",
            {"error": "invalid_mode", "reason": f"unknown mode: {mode}"},
        )
        return {"error": "invalid_mode", "reason": f"unknown mode: {mode}"}

    content_bytes = content.encode("utf-8")
    if len(content_bytes) > WRITE_SIZE_LIMIT:
        _audit_log(
            "write_file", {"path": path, "mode": mode}, "error",
            {"error": "content_too_large", "reason": f"content exceeds {WRITE_SIZE_LIMIT} bytes"},
        )
        return {"error": "content_too_large", "reason": f"content exceeds {WRITE_SIZE_LIMIT} bytes"}

    try:
        resolved = _validate_path(path, "write_file")
    except BridgeError as e:
        return _error(e)

    if mode == "create_only" and resolved.exists():
        _audit_log(
            "write_file", {"path": path, "mode": mode}, "error",
            {"error": "file_exists", "reason": "file already exists"},
        )
        return {"error": "file_exists", "reason": "file already exists"}

    # _validate_path already confirmed the resolved path is within a whitelist
    # root.  Since the whitelist root itself is an ancestor, every intermediate
    # directory created by parents=True is guaranteed to be within the whitelist.
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        _audit_log(
            "write_file", {"path": path, "mode": mode}, "error",
            {"error": "io_error", "reason": "cannot create parent directory"},
        )
        return {"error": "io_error", "reason": "cannot create parent directory"}

    # ── write ──
    try:
        if mode == "append":
            with resolved.open("a", encoding="utf-8") as fh:
                fh.write(content)
        else:
            resolved.write_text(content, encoding="utf-8")
    except OSError:
        _audit_log(
            "write_file", {"path": path, "mode": mode}, "error",
            {"error": "io_error", "reason": "write failed"},
        )
        return {"error": "io_error", "reason": "write failed"}

    # ── TOCTOU post-write check (SECURITY.md §3 startup failure handling, C3) ──
    post_resolved = Path(str(resolved)).resolve()
    if str(post_resolved) != str(resolved) and not any(
        _is_within(post_resolved, r) for r in _v.WHITELIST_ROOTS
    ):
        # symlink was inserted between mkdir and write — file landed outside whitelist
        try:
            os.remove(resolved)
        except OSError:
            pass
        _audit_log(
            "write_file", {"path": path, "mode": mode}, "error",
            {"error": "path_denied", "reason": "toctou_detected"},
        )
        return {"error": "path_denied", "reason": "toctou_detected"}

    bytes_written = len(content_bytes)
    _audit_log(
        "write_file", {"path": path, "mode": mode}, "ok",
        {"bytes_written": bytes_written},
    )
    return {"bytes_written": bytes_written, "path": path}
