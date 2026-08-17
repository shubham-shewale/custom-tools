"""Aqua Security Account Management: Users tools (Read & Staged Mutations)."""

from __future__ import annotations

import json
from typing import Any

from mcp.server import MCPServer

from aquasec_mcp.client import AquaClient
from aquasec_mcp.guardrail import GuardrailEngine, ReadOnlyError


def _normalize_expand(expand: str | list[str] | None) -> str | None:
    """Normalize expansion parameter into a comma-separated string."""
    if expand is None:
        return None
    if isinstance(expand, list):
        items = [str(item).strip() for item in expand if str(item).strip()]
        return ",".join(items) if items else None
    cleaned = str(expand).strip()
    return cleaned if cleaned else None


def register_user_tools(
    server: MCPServer,
    client: AquaClient,
    guardrail: GuardrailEngine,
) -> None:
    """Register account management user tools (read & staged mutations) to the MCP server."""

    @server.tool(
        name="list_users",
        description=(
            "List and query Aqua Security user accounts with support for pagination "
            "(limit, offset) and resource expansion (roles, group, account)."
        ),
    )
    async def list_users(
        limit: int | None = None,
        offset: int = 0,
        expand: str | list[str] | None = None,
    ) -> str:
        """Query user accounts from Aqua Security EU Cloud."""
        params: dict[str, Any] = {
            "offset": offset,
        }
        if limit is not None:
            params["limit"] = limit

        normalized_expand = _normalize_expand(expand)
        if normalized_expand:
            params["expand"] = normalized_expand

        try:
            response = await client.get("/cspm/v2/users", params=params)
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to List Users (Client / Network Error)\n\n"
                f"- **Error**: {exc}\n"
                f"- **Endpoint**: `GET /cspm/v2/users`\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 Failed to List Users (HTTP {response.status_code})\n\n"
                f"```json\n{err_str}\n```"
            )

        data = response.json()
        users_list = (
            data.get("data", [])
            if isinstance(data, dict)
            else (data if isinstance(data, list) else [])
        )
        total_count = data.get("total_count") if isinstance(data, dict) else None

        lines = [
            "# 👥 Aqua Security Users\n",
            f"- **Users on Page**: {len(users_list)}",
            f"- **Offset**: {offset}",
        ]
        if limit is not None:
            lines.append(f"- **Limit**: {limit}")
        if total_count is not None:
            lines.append(f"- **Total Users**: {total_count}")

        lines.append("")

        if users_list:
            lines.append("### Users Overview\n")
            for idx, u in enumerate(users_list, 1):
                user_id = u.get("id", "N/A")
                email = u.get("email", "N/A")
                is_admin = u.get("account_admin", False)
                admin_str = "👑 Admin" if is_admin else "👤 Standard User"
                roles = u.get("csp_roles", [])
                roles_str = ", ".join(roles) if roles else "None"
                confirmed_str = "✅ Confirmed" if u.get("confirmed", True) else "⏳ Unconfirmed"

                lines.append(
                    f"{idx}. **{email}** (`ID: {user_id}`) — {admin_str} | {confirmed_str}\n"
                    f"   - **CSP Roles**: {roles_str}"
                )
            lines.append("")
        else:
            lines.append("No users found matching the query criteria.\n")

        lines.append(f"```json\n{json.dumps(data, indent=2)}\n```")
        return "\n".join(lines)

    @server.tool(
        name="get_user",
        description=(
            "Retrieve detailed user profile by ID from Aqua Security EU Cloud with optional "
            "resource expansion (roles, group, account)."
        ),
    )
    async def get_user(
        user_id: int | str,
        expand: str | list[str] | None = None,
    ) -> str:
        """Retrieve full details of a specific user account by ID."""
        clean_id = str(user_id).strip()
        params: dict[str, Any] = {}
        normalized_expand = _normalize_expand(expand)
        if normalized_expand:
            params["expand"] = normalized_expand

        try:
            response = await client.get(f"/cspm/v2/users/{clean_id}", params=params)
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to Get User (Client / Network Error)\n\n"
                f"- **User ID**: `{clean_id}`\n"
                f"- **Error**: {exc}\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 User Not Found or Error (HTTP {response.status_code})\n\n"
                f"- **User ID**: `{clean_id}`\n\n"
                f"```json\n{err_str}\n```"
            )

        data = response.json()
        user_obj = data.get("data", data) if isinstance(data, dict) else {}
        if not isinstance(user_obj, dict):
            user_obj = {}

        uid = user_obj.get("id", clean_id)
        email = user_obj.get("email", "Unknown Email")
        is_admin = user_obj.get("account_admin", False)
        admin_str = "👑 Admin" if is_admin else "👤 Standard User"
        confirmed_str = "✅ Confirmed" if user_obj.get("confirmed", True) else "⏳ Unconfirmed"
        created_at = user_obj.get("created", "N/A")
        last_signin = user_obj.get("last_signin_attempt", "Never")
        failed_signin = user_obj.get("count_failed_signin", 0)

        roles = user_obj.get("csp_roles", [])
        roles_str = ", ".join(roles) if roles else "None"

        groups = user_obj.get("groups", [])
        groups_str = (
            ", ".join(g.get("name", str(g.get("id", "Group"))) for g in groups if isinstance(g, dict))
            if groups
            else "None"
        )

        accounts = user_obj.get("accounts", [])
        accounts_str = (
            ", ".join(
                a.get("name", str(a.get("id", "Account"))) for a in accounts if isinstance(a, dict)
            )
            if accounts
            else "None"
        )

        return (
            f"# 👤 User Profile: {email}\n\n"
            f"- **User ID**: `{uid}`\n"
            f"- **Account Role**: {admin_str}\n"
            f"- **Status**: {confirmed_str}\n"
            f"- **Assigned CSP Roles**: {roles_str}\n"
            f"- **Groups**: {groups_str}\n"
            f"- **Accounts**: {accounts_str}\n"
            f"- **Created At**: `{created_at}`\n"
            f"- **Last Sign-in Attempt**: `{last_signin}` (Failed attempts: {failed_signin})\n\n"
            f"### Full User Profile\n"
            f"```json\n{json.dumps(data, indent=2)}\n```"
        )

    @server.tool(
        name="create_user",
        description=(
            "Stage the creation of an Aqua Security user account with email, CSP roles, "
            "admin status, and MFA settings. "
            "Returns an impact diff preview and a 5-minute confirmation token. "
            "Requires explicit confirmation via `execute_confirmed_action` to apply."
        ),
    )
    async def create_user(
        email: str,
        account_admin: bool = False,
        csp_roles: list[str] | None = None,
        mfa_enabled: bool | None = None,
    ) -> str:
        """Stage addition of a new user account with impact preview."""
        clean_email = email.strip()

        payload: dict[str, Any] = {
            "email": clean_email,
            "account_admin": account_admin,
        }
        field_changes: dict[str, Any] = {
            "email": clean_email,
            "account_admin": account_admin,
        }

        if csp_roles is not None:
            payload["csp_roles"] = csp_roles
            field_changes["csp_roles"] = csp_roles
        if mfa_enabled is not None:
            payload["mfa_enabled"] = mfa_enabled
            field_changes["mfa_enabled"] = mfa_enabled

        try:
            res_create: str = guardrail.stage_mutation(
                action_type="create_user",
                target_resource=f"user:{clean_email}",
                description=f"Create user '{clean_email}'",
                http_method="POST",
                path="/cspm/v2/users",
                field_changes=field_changes,
                payload=payload,
            )
            return res_create
        except ReadOnlyError as err:
            return (
                f"# ⛔ READ-ONLY MODE: Action Staging Blocked\n\n"
                f"{err}"
            )

    @server.tool(
        name="update_user",
        description=(
            "Stage updates to an existing Aqua Security user account "
            "(modify CSP roles, admin status, MFA enabled/reset, or plugin alerts). "
            "Returns an impact diff preview and a 5-minute confirmation token. "
            "Requires explicit confirmation via `execute_confirmed_action` to apply."
        ),
    )
    async def update_user(
        user_id: int | str,
        csp_roles: list[str] | None = None,
        account_admin: bool | None = None,
        mfa_enabled: bool | None = None,
        mfa_reset: bool | None = None,
        send_new_plugins: bool | None = None,
    ) -> str:
        """Stage modification of an existing user account with impact preview."""
        clean_id = str(user_id).strip()

        payload: dict[str, Any] = {}
        field_changes: dict[str, Any] = {"user_id": clean_id}

        if csp_roles is not None:
            payload["csp_roles"] = csp_roles
            field_changes["csp_roles"] = csp_roles
        if account_admin is not None:
            payload["account_admin"] = account_admin
            field_changes["account_admin"] = account_admin
        if mfa_enabled is not None:
            payload["mfa_enabled"] = mfa_enabled
            field_changes["mfa_enabled"] = mfa_enabled
        if mfa_reset is not None:
            payload["mfa_reset"] = mfa_reset
            field_changes["mfa_reset"] = mfa_reset
        if send_new_plugins is not None:
            payload["send_new_plugins"] = send_new_plugins
            field_changes["send_new_plugins"] = send_new_plugins

        if not payload:
            return (
                "# ⚠️ No Updates Specified\n\n"
                f"No modifiable user fields were provided for user `{clean_id}`. "
                "Please specify at least one attribute to update (e.g. `csp_roles`, `account_admin`, `mfa_enabled`, `mfa_reset`)."
            )

        try:
            res_update: str = guardrail.stage_mutation(
                action_type="update_user",
                target_resource=f"user:{clean_id}",
                description=f"Update user '{clean_id}'",
                http_method="PUT",
                path=f"/cspm/v2/users/{clean_id}",
                field_changes=field_changes,
                payload=payload,
            )
            return res_update
        except ReadOnlyError as err:
            return (
                f"# ⛔ READ-ONLY MODE: Action Staging Blocked\n\n"
                f"{err}"
            )

    @server.tool(
        name="delete_user",
        description=(
            "Stage the deletion of an Aqua Security user account by ID. "
            "Returns an impact diff preview and a 5-minute confirmation token. "
            "Requires explicit confirmation via `execute_confirmed_action` to apply."
        ),
    )
    async def delete_user(
        user_id: int | str,
    ) -> str:
        """Stage deletion of a user account with impact preview."""
        clean_id = str(user_id).strip()
        field_changes: dict[str, Any] = {"user_id": clean_id}

        try:
            res_del: str = guardrail.stage_mutation(
                action_type="delete_user",
                target_resource=f"user:{clean_id}",
                description=f"Delete user '{clean_id}'",
                http_method="DELETE",
                path=f"/cspm/v2/users/{clean_id}",
                field_changes=field_changes,
            )
            return res_del
        except ReadOnlyError as err:
            return (
                f"# ⛔ READ-ONLY MODE: Action Staging Blocked\n\n"
                f"{err}"
            )




