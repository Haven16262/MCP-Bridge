"""Path validation and security constants (SECURITY.md §3-§5)."""

from __future__ import annotations

import platform
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List

from bridge.audit import _audit_log

# ── Constants ─────────────────────────────────

_IS_WINDOWS = platform.system() == "Windows"

WHITELIST_ROOTS: List[str] = (
    [
        r"C:\Users\YourUsername\Antigravity\workspace\MCP",
        r"C:\Users\YourUsername\Claude code\workspace\MCP",
        r"C:\Users\YourUsername\MCP-shared",
    ]
    if _IS_WINDOWS
    else [
        "/root/workspace/MCP",
    ]
)

BLACKLIST_PATTERNS: List[str] = [
    "**/.ssh/**",
    "**/.env",
    "**/.env.*",
    "**/.git/config",
    "**/credentials*",
    "**/*secret*",
    "**/.aws/**",
    "**/.gnupg/**",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "**/.npmrc",
    "**/.pypirc",
    "**/cookies.txt",
    "**/*token*",
    "**/*.key",
    "**/*.pem",
]

READ_SIZE_LIMIT = 1 * 1024 * 1024  # 1 MB
WRITE_SIZE_LIMIT = 5 * 1024 * 1024  # 5 MB
LIST_DIR_ENTRY_LIMIT = 5000


# ── BridgeError ───────────────────────────────


class BridgeError(Exception):
    def __init__(self, error_code: str, reason: str) -> None:
        self.error_code = error_code
        self.reason = reason
        super().__init__(f"{error_code}: {reason}")


def _error(ec: BridgeError) -> Dict[str, str]:
    return {"error": ec.error_code, "reason": ec.reason}


# ── Path helpers ──────────────────────────────


def _is_within(path: Path, root_str: str) -> bool:
    root = Path(root_str).resolve(strict=False)
    path_s = str(path).lower().replace("\\", "/")
    root_s = str(root).lower().replace("\\", "/").rstrip("/")
    if path_s == root_s:
        return True
    return path_s.startswith(root_s + "/")


def _match_parts(path_parts: List[str], pat_parts: List[str]) -> bool:
    """Match path parts against pattern parts.  ``**`` matches >=0 components."""
    pi = ppi = 0
    star = -1
    star_match = -1

    while ppi < len(path_parts):
        if pi < len(pat_parts) and pat_parts[pi] == "**":
            star = pi
            star_match = ppi
            pi += 1
        elif pi < len(pat_parts) and fnmatch(path_parts[ppi], pat_parts[pi]):
            ppi += 1
            pi += 1
        elif star != -1:
            pi = star + 1
            star_match += 1
            ppi = star_match
        else:
            return False

    while pi < len(pat_parts) and pat_parts[pi] == "**":
        pi += 1

    return pi == len(pat_parts)


def _matches_blacklist(path: Path) -> bool:
    path_str = str(path).replace("\\", "/").lower()
    path_parts = [p for p in path_str.split("/") if p]
    for pat in BLACKLIST_PATTERNS:
        pat_parts = [p for p in pat.lower().split("/") if p]
        if _match_parts(path_parts, pat_parts):
            return True
    return False


def _validate_path(p: str, op: str) -> Path:
    """Validate ``p`` for operation ``op`` per SECURITY.md §5 seven-step flow."""

    # 1. Type check
    if not isinstance(p, str) or not p.strip():
        _audit_log(
            op, {"path": str(p)}, "error",
            {"error": "path_denied", "reason": "empty_or_non_string"},
        )
        raise BridgeError("path_denied", "empty_or_non_string")

    # 2. Absolute only
    if not Path(p).is_absolute():
        _audit_log(
            op, {"path": p}, "error",
            {"error": "path_denied", "reason": "relative_path_forbidden"},
        )
        raise BridgeError("path_denied", "relative_path_forbidden")

    # 3-4. Normalise + resolve (follows symlinks)
    resolved = Path(p).resolve(strict=False)

    # 5. Whitelist prefix check
    if not any(_is_within(resolved, root) for root in WHITELIST_ROOTS):
        _audit_log(
            op, {"path": p}, "error",
            {"error": "path_denied", "reason": "outside_whitelist"},
        )
        raise BridgeError("path_denied", "outside_whitelist")

    # 6. Blacklist pattern check
    if _matches_blacklist(resolved):
        _audit_log(
            op, {"path": p}, "error",
            {"error": "path_denied", "reason": "matches_blacklist"},
        )
        raise BridgeError("path_denied", "matches_blacklist")

    return resolved
