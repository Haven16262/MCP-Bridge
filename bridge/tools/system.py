"""Echo and system_status tools."""

from __future__ import annotations

import platform
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import psutil

from bridge.audit import _audit_log
from bridge.server import mcp


@mcp.tool
def echo(message: str) -> dict:
    """Echo a message back, tagged with the bridge host info.

    Use this to verify connectivity from any MCP client. The returned host
    info confirms which physical machine the bridge is running on.
    """
    result_data = {
        "message": message,
        "bridge_host": socket.gethostname(),
        "bridge_platform": platform.platform(),
        "bridge_time_utc": datetime.now(timezone.utc).isoformat(),
    }
    _audit_log("echo", {"message": message}, "ok", {})
    return result_data


@mcp.tool
def system_status() -> dict:
    """Read-only snapshot of the bridge machine's system state.

    No path parameter — skips path validation.  Deliberately excludes
    process listing and network interface IP/MAC addresses.
    """
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)

    mem = psutil.virtual_memory()

    disks: List[Dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append(
            {
                "mount": part.mountpoint,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
            }
        )

    result = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "uptime_seconds": uptime_seconds,
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": round(psutil.cpu_percent(interval=0.1), 1),
        "memory": {
            "total_mb": mem.total // (1024 * 1024),
            "used_mb": mem.used // (1024 * 1024),
            "available_mb": mem.available // (1024 * 1024),
        },
        "disk": disks,
        "process_count": len(psutil.pids()),
        "bridge_time_utc": datetime.now(timezone.utc).isoformat(),
    }
    _audit_log("system_status", {}, "ok", {})
    return result
