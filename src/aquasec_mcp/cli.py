"""CLI entrypoint for running the Aqua Security MCP Server."""

from __future__ import annotations

import sys

from aquasec_mcp.config import AquaConfig
from aquasec_mcp.server import create_mcp_server


def main() -> None:
    """Run the Aqua Security MCP server over stdio transport."""
    config = AquaConfig.from_env()
    server = create_mcp_server(config=config)
    try:
        server.run(transport="stdio")
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)


if __name__ == "__main__":
    main()
