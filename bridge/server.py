"""FastMCP server instance, auth, and startup logic."""

from __future__ import annotations

import os
import platform
import socket
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from bridge.audit import _audit_log
from bridge.validators import WHITELIST_ROOTS

# ── Environment & auth ────────────────────────

load_dotenv()

BRIDGE_API_KEY = os.environ.get("BRIDGE_API_KEY")
BRIDGE_HOST = os.environ.get("BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "18800"))

if not BRIDGE_API_KEY:
    sys.exit(
        "ERROR: BRIDGE_API_KEY not set. Copy .env.example to .env and fill in a "
        "strong random key (e.g. `openssl rand -hex 32`)."
    )

REQUIRED_SCOPE = "bridge:use"

auth = StaticTokenVerifier(
    tokens={
        BRIDGE_API_KEY: {
            "client_id": "trusted-client",
            "scopes": [REQUIRED_SCOPE],
        }
    },
    required_scopes=[REQUIRED_SCOPE],
)

# ── FastMCP instance ──────────────────────────

mcp = FastMCP(
    name="ag-bridge",
    instructions=(
        "Local bridge running on the user's Windows machine. Use tools here to "
        "operate on the local filesystem, query local services, or invoke "
        "ag-cli. All calls require Bearer token authentication."
    ),
    auth=auth,
)

# ── Startup (before tool imports so events are in order) ──

_IS_WINDOWS = platform.system() == "Windows"
_audit_log("bridge", {}, "started", {"host": socket.gethostname()})

# ── Import tool modules (registers @mcp.tool) ─

import bridge.tools.ag_cli  # noqa: E402, F401
import bridge.tools.bus  # noqa: E402, F401
import bridge.tools.files  # noqa: E402, F401
import bridge.tools.system  # noqa: E402, F401

# ── Startup: shared root (SECURITY.md §3) ────


def _ensure_shared_root(shared_root: str) -> tuple[bool, str]:
    """Ensure the shared whitelist root directory exists.

    Returns ``(disabled, reason)`` where *reason* is one of ``""``,
    ``"mkdir_failed"``, or ``"path_exists_but_not_a_directory"``.

    Side effects when *disabled* is True:
      - Removes *shared_root* from :data:`WHITELIST_ROOTS`.
      - Emits a ``shared_root_disabled`` audit event.
    When *disabled* is False, emits ``shared_root_ensured``.
    """
    shared_norm = str(Path(shared_root)).replace("\\", "/").lower()
    sp = Path(shared_root)
    disabled = False
    reason: str = ""

    try:
        existed = sp.exists()
        sp.mkdir(parents=False, exist_ok=True)
        if sp.is_dir():
            _audit_log(
                "bridge", {}, "shared_root_ensured",
                {"path": shared_norm, "created": not existed},
            )
        else:
            disabled = True
            reason = "path_exists_but_not_a_directory"
    except OSError:
        disabled = True
        reason = "mkdir_failed"

    if disabled:
        WHITELIST_ROOTS[:] = [
            r for r in WHITELIST_ROOTS
            if str(Path(r)).replace("\\", "/").lower() != shared_norm
        ]
        _audit_log(
            "bridge", {}, "shared_root_disabled",
            {"path": shared_norm, "reason": reason},
        )

    return disabled, reason


def _ensure_bus_dirs() -> None:
    """Create ``MCP-shared/_bus/`` inbox/archive subdirectories for all identities.

    Best-effort — failures are audited but never crash the bridge.
    Unlike shared root failures, the whitelist is NOT modified because
    all bus paths are inside ``MCP-shared/``.
    """
    bus_root = Path(r"C:\Users\YourUsername\MCP-shared\_bus")
    subdirs = [
        "inbox/vps-claude", "inbox/windows-claude", "inbox/antigravity",
        "archive/vps-claude", "archive/windows-claude", "archive/antigravity",
    ]
    failed: list[str] = []
    for sd in subdirs:
        try:
            (bus_root / sd).mkdir(parents=True, exist_ok=True)
        except OSError:
            failed.append(sd)
            _audit_log("bridge", {}, "bus_dir_failed",
                       {"path": str(bus_root / sd).replace("\\", "/")})
    if failed:
        _audit_log("bridge", {}, "bus_dirs_partial",
                   {"failed_count": len(failed)})
    else:
        _audit_log("bridge", {}, "bus_dirs_ensured", {})


if _IS_WINDOWS:
    _ensure_shared_root(r"C:\Users\YourUsername\MCP-shared")
    _ensure_bus_dirs()
