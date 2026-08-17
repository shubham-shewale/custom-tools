"""MCP tool modules for Aqua Security EU Cloud."""

from aquasec_mcp.tools.roles_scopes import register_role_and_scope_tools
from aquasec_mcp.tools.suppressions import register_suppression_tools
from aquasec_mcp.tools.users import register_user_tools

__all__ = [
    "register_role_and_scope_tools",
    "register_suppression_tools",
    "register_user_tools",
]
