"""Aqua Security Account Management: Roles, Permissions & Application Scopes inspection tools."""

from __future__ import annotations

import json
from typing import Any

from mcp.server import MCPServer

from aquasec_mcp.client import AquaClient


def _format_permissions_matrix(permissions: list[Any]) -> str:
    """Format granular permissions into a structured Markdown matrix or categorized table."""
    if not permissions:
        return "No granular permissions assigned."

    # Case 1: Structured permission objects/dictionaries
    if isinstance(permissions[0], dict):
        table_lines = [
            "| Module / Domain | Resource | Action | Description / Details |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for p in permissions:
            if not isinstance(p, dict):
                continue
            module = p.get("module") or p.get("domain") or "General"
            resource = p.get("resource") or p.get("target") or "All"
            action = p.get("action") or p.get("permission") or "Access"
            desc = p.get("description") or p.get("details") or "-"
            table_lines.append(f"| `{module}` | `{resource}` | `{action}` | {desc} |")
        return "\n".join(table_lines)

    # Case 2: String permission keys (e.g. "account_mgmt.users.read", "ssc.suppression_rules.write")
    categorized: dict[str, list[str]] = {}
    for p in permissions:
        perm_str = str(p).strip()
        if not perm_str:
            continue
        parts = perm_str.split(".", 1)
        domain = parts[0] if len(parts) > 1 else "general"
        categorized.setdefault(domain, []).append(perm_str)

    matrix_lines: list[str] = [
        "| Domain / Service | Permission Key | Access Type |",
        "| :--- | :--- | :--- |",
    ]
    for domain, perm_list in sorted(categorized.items()):
        for perm in perm_list:
            access_type = "Write / Mutation" if "write" in perm or "delete" in perm or "create" in perm else "Read / Inspect"
            matrix_lines.append(f"| `{domain}` | `{perm}` | {access_type} |")

    return "\n".join(matrix_lines)


def _format_resource_filters(
    variables: list[dict[str, Any]] | None,
    expression: str | None = None,
) -> str:
    """Format application scope resource filters and boolean expressions into Markdown."""
    lines: list[str] = []

    if expression:
        lines.append(f"- **Boolean Filter Expression**: `{expression}`\n")

    if not variables:
        lines.append("No explicit resource filter variables defined.")
        return "\n".join(lines)

    lines.append("| Variable ID | Target Resource / Attribute | Operator | Filter Pattern / Value |")
    lines.append("| :--- | :--- | :--- | :--- |")

    for v in variables:
        if not isinstance(v, dict):
            continue
        var_id = v.get("id") or v.get("var_id") or "v"
        attr = v.get("attribute") or v.get("field") or v.get("resource_type") or "resource"
        op = v.get("operator") or v.get("op") or "equals"
        val = v.get("value") or v.get("values") or "*"
        if isinstance(val, list):
            val_str = ", ".join(str(item) for item in val)
        else:
            val_str = str(val)
        lines.append(f"| `{var_id}` | `{attr}` | `{op}` | `{val_str}` |")

    return "\n".join(lines)


def register_role_and_scope_tools(
    server: MCPServer,
    client: AquaClient,
) -> None:
    """Register CSP roles, permission definitions, and application scope tools to the MCP server."""

    @server.tool(
        name="list_roles",
        description=(
            "List and query available Aqua Security CSP roles, permission summaries, "
            "and role categories with pagination and search support."
        ),
    )
    async def list_roles(
        limit: int | None = None,
        offset: int = 0,
        search: str | None = None,
    ) -> str:
        """Query CSP roles from Aqua Security EU Cloud."""
        params: dict[str, Any] = {
            "offset": offset,
        }
        if limit is not None:
            params["limit"] = limit
        if search:
            params["search"] = search.strip()

        try:
            response = await client.get("/cspm/v2/roles", params=params)
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to List Roles (Client / Network Error)\n\n"
                f"- **Error**: {exc}\n"
                f"- **Endpoint**: `GET /cspm/v2/roles`\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 Failed to List Roles (HTTP {response.status_code})\n\n"
                f"```json\n{err_str}\n```"
            )

        data = response.json()
        roles_list = (
            data.get("data", [])
            if isinstance(data, dict)
            else (data if isinstance(data, list) else [])
        )
        total_count = data.get("total_count") if isinstance(data, dict) else None

        lines = [
            "# 🛡️ Aqua Security CSP Roles\n",
            f"- **Roles on Page**: {len(roles_list)}",
            f"- **Offset**: {offset}",
        ]
        if limit is not None:
            lines.append(f"- **Limit**: {limit}")
        if search:
            lines.append(f"- **Search Filter**: `{search}`")
        if total_count is not None:
            lines.append(f"- **Total Roles**: {total_count}")

        lines.append("")

        if roles_list:
            lines.append("### Available CSP Roles\n")
            for idx, r in enumerate(roles_list, 1):
                role_id = r.get("id", "N/A")
                name = r.get("name", "Unknown Role")
                description = r.get("description", "No description provided")
                role_type = r.get("role_type") or r.get("type") or "System"
                role_type_badge = "⚙️ Custom" if str(role_type).lower() == "custom" else "🏛️ System"
                perm_count = r.get("permission_count")
                if perm_count is None and isinstance(r.get("permissions"), list):
                    perm_count = len(r["permissions"])
                perm_str = f" ({perm_count} permissions)" if perm_count is not None else ""

                lines.append(
                    f"{idx}. **{name}** (`ID: {role_id}`) — {role_type_badge}{perm_str}\n"
                    f"   - **Description**: {description}"
                )
            lines.append("")
        else:
            lines.append("No CSP roles found matching the query criteria.\n")

        lines.append(f"```json\n{json.dumps(data, indent=2)}\n```")
        return "\n".join(lines)

    @server.tool(
        name="get_role_details",
        description=(
            "Retrieve granular permissions and detailed configuration for a specific "
            "Aqua Security CSP role by ID or Name."
        ),
    )
    async def get_role_details(
        role_id: int | str,
    ) -> str:
        """Retrieve full details and granular permission matrix for a specific CSP role."""
        clean_id = str(role_id).strip()

        try:
            response = await client.get(f"/cspm/v2/roles/{clean_id}")
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to Get Role (Client / Network Error)\n\n"
                f"- **Role ID**: `{clean_id}`\n"
                f"- **Error**: {exc}\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 Role Not Found or Error (HTTP {response.status_code})\n\n"
                f"- **Role ID**: `{clean_id}`\n\n"
                f"```json\n{err_str}\n```"
            )

        data = response.json()
        role_obj = data.get("data", data) if isinstance(data, dict) else {}
        if not isinstance(role_obj, dict):
            role_obj = {}

        rid = role_obj.get("id", clean_id)
        name = role_obj.get("name", "Unknown Role")
        description = role_obj.get("description", "No description provided")
        role_type = role_obj.get("role_type") or role_obj.get("type") or "System"
        role_type_badge = "⚙️ Custom Role" if str(role_type).lower() == "custom" else "🏛️ System Role"
        author = role_obj.get("author") or role_obj.get("created_by") or "system"
        created_at = role_obj.get("created_at") or role_obj.get("created") or "N/A"
        updated_at = role_obj.get("updated_at") or role_obj.get("updated") or "N/A"
        permissions = role_obj.get("permissions", [])

        matrix_md = _format_permissions_matrix(permissions)

        return (
            f"# 🛡️ Role Details: {name}\n\n"
            f"- **Role ID**: `{rid}`\n"
            f"- **Type**: {role_type_badge}\n"
            f"- **Description**: {description}\n"
            f"- **Author / Created By**: `{author}`\n"
            f"- **Created At**: `{created_at}`\n"
            f"- **Updated At**: `{updated_at}`\n"
            f"- **Total Permissions**: {len(permissions)}\n\n"
            f"### Granular Permissions Matrix\n\n"
            f"{matrix_md}\n\n"
            f"### Full Role Definition\n"
            f"```json\n{json.dumps(data, indent=2)}\n```"
        )

    @server.tool(
        name="list_application_scopes",
        description=(
            "List defined Aqua Security application scopes with summary expressions, "
            "resource categories, and pagination support."
        ),
    )
    async def list_application_scopes(
        limit: int | None = None,
        offset: int = 0,
        search: str | None = None,
    ) -> str:
        """Query application scopes defined across the Aqua Security account."""
        params: dict[str, Any] = {
            "offset": offset,
        }
        if limit is not None:
            params["limit"] = limit
        if search:
            params["search"] = search.strip()

        try:
            response = await client.get("/cspm/v2/scopes", params=params)
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to List Application Scopes (Client / Network Error)\n\n"
                f"- **Error**: {exc}\n"
                f"- **Endpoint**: `GET /cspm/v2/scopes`\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 Failed to List Application Scopes (HTTP {response.status_code})\n\n"
                f"```json\n{err_str}\n```"
            )

        data = response.json()
        scopes_list = (
            data.get("data", [])
            if isinstance(data, dict)
            else (data if isinstance(data, list) else [])
        )
        total_count = data.get("total_count") if isinstance(data, dict) else None

        lines = [
            "# 🌐 Aqua Security Application Scopes\n",
            f"- **Scopes on Page**: {len(scopes_list)}",
            f"- **Offset**: {offset}",
        ]
        if limit is not None:
            lines.append(f"- **Limit**: {limit}")
        if search:
            lines.append(f"- **Search Filter**: `{search}`")
        if total_count is not None:
            lines.append(f"- **Total Scopes**: {total_count}")

        lines.append("")

        if scopes_list:
            lines.append("### Defined Application Scopes\n")
            for idx, s in enumerate(scopes_list, 1):
                scope_id = s.get("id", "N/A")
                name = s.get("name", "Unnamed Scope")
                description = s.get("description", "No description provided")
                categories = s.get("categories", [])
                cat_str = ", ".join(categories) if categories else "None"
                expression = s.get("expression")
                expr_str = f" | Expression: `{expression}`" if expression else ""
                variables = s.get("variables", [])
                var_count_str = f" ({len(variables)} filter rules)" if variables else ""

                lines.append(
                    f"{idx}. **{name}** (`ID: {scope_id}`){var_count_str}{expr_str}\n"
                    f"   - **Description**: {description}\n"
                    f"   - **Categories**: {cat_str}"
                )
            lines.append("")
        else:
            lines.append("No application scopes found matching the query criteria.\n")

        lines.append(f"```json\n{json.dumps(data, indent=2)}\n```")
        return "\n".join(lines)

    @server.tool(
        name="get_application_scope",
        description=(
            "Retrieve detailed configuration, boolean filter expressions, and resource "
            "rules for a specific Aqua Security application scope by ID."
        ),
    )
    async def get_application_scope(
        scope_id: int | str,
    ) -> str:
        """Retrieve full definition, categories, and resource filter expressions for an application scope."""
        clean_id = str(scope_id).strip()

        try:
            response = await client.get(f"/cspm/v2/scopes/{clean_id}")
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to Get Application Scope (Client / Network Error)\n\n"
                f"- **Scope ID**: `{clean_id}`\n"
                f"- **Error**: {exc}\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 Application Scope Not Found or Error (HTTP {response.status_code})\n\n"
                f"- **Scope ID**: `{clean_id}`\n\n"
                f"```json\n{err_str}\n```"
            )

        data = response.json()
        scope_obj = data.get("data", data) if isinstance(data, dict) else {}
        if not isinstance(scope_obj, dict):
            scope_obj = {}

        sid = scope_obj.get("id", clean_id)
        name = scope_obj.get("name", "Unnamed Scope")
        description = scope_obj.get("description", "No description provided")
        author = scope_obj.get("author") or scope_obj.get("created_by") or "N/A"
        categories = scope_obj.get("categories", [])
        categories_str = ", ".join(categories) if categories else "None"
        created_at = scope_obj.get("created_at") or scope_obj.get("created") or "N/A"
        updated_at = scope_obj.get("updated_at") or scope_obj.get("updated") or "N/A"
        expression = scope_obj.get("expression")
        variables = scope_obj.get("variables", [])

        filter_md = _format_resource_filters(variables=variables, expression=expression)

        return (
            f"# 🌐 Application Scope: {name}\n\n"
            f"- **Scope ID**: `{sid}`\n"
            f"- **Description**: {description}\n"
            f"- **Author / Created By**: `{author}`\n"
            f"- **Categories**: {categories_str}\n"
            f"- **Created At**: `{created_at}`\n"
            f"- **Updated At**: `{updated_at}`\n\n"
            f"### Resource Filter Expressions & Criteria\n\n"
            f"{filter_md}\n\n"
            f"### Full Scope Definition\n"
            f"```json\n{json.dumps(data, indent=2)}\n```"
        )
