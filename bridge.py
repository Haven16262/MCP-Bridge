"""Thin shell entry point — delegates to bridge.server."""

import sys

from bridge import BRIDGE_HOST, BRIDGE_PORT, mcp

if __name__ == "__main__":
    print(
        f"Starting ag-bridge on http://{BRIDGE_HOST}:{BRIDGE_PORT}/mcp",
        file=sys.stderr,
    )
    mcp.run(transport="http", host=BRIDGE_HOST, port=BRIDGE_PORT)
