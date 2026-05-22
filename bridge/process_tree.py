"""Cross-platform process tree cleanup (SECURITY.md §6.5).

Kills a process and all descendants so orphaned grandchild processes
don't hold pipe handles and corrupt the bridge state.
"""

from __future__ import annotations

import os
import platform
import signal
import subprocess
import time

_IS_WINDOWS = platform.system() == "Windows"


def _kill_process_tree(pid: int) -> None:
    """Kill *pid* and all descendants. Best-effort — never raises."""
    if _IS_WINDOWS:
        try:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(pid)],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            time.sleep(0.5)
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
