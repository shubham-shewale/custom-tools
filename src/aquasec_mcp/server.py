"""FastMCP / MCPServer definition and tool registration for Aqua Security EU Cloud."""

from __future__ import annotations

import datetime

from mcp.server import MCPServer

from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig

# Type alias for compatibility with FastMCP nomenclature
FastMCP = MCPServer


def create_mcp_server(
    config: AquaConfig | None = None,
    client: AquaClient | None = None,
) -> MCPServer:
    """Create and configure the Aqua Security MCP server with registered tools."""
    cfg = config or AquaConfig.from_env()
    aqua_client = client or AquaClient(config=cfg)

    server = MCPServer(
        name="Aqua Security EU",
        instructions=(
            "Aqua Security MCP Server for European Cloud (eu-central-1). "
            "Provides tools to inspect and manage supply chain suppression rules, "
            "users, and roles with strict two-phase confirmation guardrails."
        ),
    )

    @server.tool(
        name="check_aqua_connection",
        description="Verify connection and authentication status with Aqua Security EU Cloud.",
    )
    async def check_aqua_connection() -> str:
        """Verify connection and authentication against the Aqua EU authentication and API endpoints."""
        try:
            conn = await aqua_client.check_connection()
            exp_ts = conn.get("token_expires_at")
            exp_str = (
                datetime.datetime.fromtimestamp(exp_ts, tz=datetime.timezone.utc).isoformat()
                if exp_ts
                else "N/A"
            )
            read_only_str = (
                "Active 🔒 (All mutation requests will be blocked)"
                if cfg.read_only
                else "Inactive 🔓 (Write & staged operations allowed)"
            )

            return (
                f"# 🟢 Aqua Security EU Connection: Successful\n\n"
                f"- **Status**: Connected & Authenticated\n"
                f"- **Region**: {conn.get('region', 'EU')}\n"
                f"- **Base Endpoint**: `{conn.get('base_url')}`\n"
                f"- **Token Endpoint**: `{conn.get('token_url')}`\n"
                f"- **Token Validity Window**: {conn.get('token_validity_minutes', 720)} minutes (12 hours)\n"
                f"- **Token Expiration (UTC)**: `{exp_str}`\n"
                f"- **Read-Only Mode**: {read_only_str}\n"
            )
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Aqua Security EU Connection: Failed\n\n"
                f"- **Status**: Authentication / Connection Error\n"
                f"- **Error**: {exc}\n"
                f"- **Region**: EU (eu-central-1)\n"
                f"- **Configured Base Endpoint**: `{cfg.base_url}`\n"
                f"- **Configured Token Endpoint**: `{cfg.token_url}`\n\n"
                f"### Troubleshooting\n"
                f"1. Verify that `AQUA_API_KEY` and `AQUA_API_SECRET` are properly set.\n"
                f"2. Confirm your API credentials have active permissions for the EU region.\n"
                f"3. Ensure the Aqua EU Cloud endpoints are reachable over your network."
            )

    return server
