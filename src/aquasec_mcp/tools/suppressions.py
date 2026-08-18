"""Supply Chain Suppression Rules tools for Aqua Security EU Cloud."""

from __future__ import annotations

import json
from typing import Any

from mcp.server import MCPServer

from aquasec_mcp.client import AquaClient
from aquasec_mcp.guardrail import GuardrailEngine, ReadOnlyError


def _build_controls(
    check: str | None = None,
    controls: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Resolve and construct standard control definitions for a suppression rule."""
    if controls is not None:
        return controls
    if not check:
        return []

    clean_check = check.strip()
    if clean_check.upper().startswith("CVE-"):
        return [
            {
                "type": "cveByIds",
                "scan_type": "vulnerability",
                "cve_ids": [clean_check],
            }
        ]
    return [
        {
            "type": "misconfigurations",
            "scan_type": "manifest",
            "checks": [{"id": clean_check}],
        }
    ]


def _build_scope(
    repository: str | None = None,
    branch: str | None = None,
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve and construct standard scope definitions for a suppression rule."""
    if scope is not None:
        return scope

    vars_list: list[dict[str, str]] = []
    expr_parts: list[str] = []

    if repository and repository.strip() not in ("all_repositories", "*"):
        vars_list.append({"attribute": "repository.name", "value": repository.strip()})
        expr_parts.append(f"v{len(vars_list)}")

    if branch and branch.strip():
        vars_list.append({"attribute": "repository.branch", "value": branch.strip()})
        expr_parts.append(f"v{len(vars_list)}")

    if not vars_list:
        return {
            "expression": "v1",
            "variables": [{"attribute": "repository.name", "value": "*"}],
        }

    return {
        "expression": " && ".join(expr_parts),
        "variables": vars_list,
    }


def register_suppression_tools(
    server: MCPServer,
    client: AquaClient,
    guardrail: GuardrailEngine,
) -> None:
    """Register supply chain suppression tools (read & staged mutations) to the MCP server."""

    @server.tool(
        name="list_suppressions",
        description=(
            "List and query Aqua Security supply chain suppression rules with optional filtering "
            "by search keyword, repository, check ID, branch, scope, status, pagination, and sorting."
        ),
    )
    async def list_suppressions(
        search: str | None = None,
        repository: str | None = None,
        check: str | None = None,
        branch: str | None = None,
        scope: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
        order_by: str | None = None,
    ) -> str:
        """Query suppression rules from Aqua Security EU Cloud."""
        params: dict[str, Any] = {
            "page": page,
            "page_size": page_size,
        }
        if search:
            params["search"] = search
        if repository:
            params["repository"] = repository
        if check:
            params["check"] = check
        if branch:
            params["branch"] = branch
        if scope:
            params["scope"] = scope
        if status:
            params["status"] = status
        if order_by:
            params["order_by"] = order_by

        try:
            response = await client.get("/supply_chain/v2/build/suppressions", params=params)
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to List Suppression Rules (Client / Network Error)\n\n"
                f"- **Error**: {exc}\n"
                f"- **Endpoint**: `GET /supply_chain/v2/build/suppressions`\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 Failed to List Suppression Rules (HTTP {response.status_code})\n\n"
                f"```json\n{err_str}\n```"
            )

        data = response.json()
        rules = data.get("data", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        total_count = data.get("total_count", len(rules)) if isinstance(data, dict) else len(rules)
        current_page = data.get("current_page", page) if isinstance(data, dict) else page

        lines = [
            "# 🛡️ Supply Chain Suppression Rules\n",
            f"- **Total Rules**: {total_count}",
            f"- **Current Page**: {current_page} (Page Size: {page_size})",
            f"- **Returned on Page**: {len(rules)}\n",
        ]

        if rules:
            lines.append("### Rules Overview\n")
            for idx, rule in enumerate(rules, 1):
                rule_id = rule.get("policy_id") or rule.get("id", "N/A")
                rule_name = rule.get("name", "Unnamed")
                enabled_str = "✅ Enabled" if rule.get("enable", True) else "⏸️ Disabled"
                desc = rule.get("description", "No description")
                lines.append(f"{idx}. **{rule_name}** (`{rule_id}`) — {enabled_str}\n   - *Description*: {desc}")
            lines.append("")

        lines.append(f"```json\n{json.dumps(data, indent=2)}\n```")
        return "\n".join(lines)

    @server.tool(
        name="get_suppression",
        description="Retrieve detailed attributes of a specific Aqua Security supply chain suppression rule by its ID.",
    )
    async def get_suppression(suppression_id: str) -> str:
        """Retrieve full details of a specific suppression rule by ID."""
        clean_id = suppression_id.strip()
        try:
            response = await client.get(f"/supply_chain/v2/build/suppressions/{clean_id}")
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to Get Suppression Rule (Client / Network Error)\n\n"
                f"- **Suppression ID**: `{clean_id}`\n"
                f"- **Error**: {exc}\n"
            )

        if not response.is_success:
            try:
                err_data = response.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = response.text
            return (
                f"# 🔴 Suppression Rule Not Found or Error (HTTP {response.status_code})\n\n"
                f"- **Suppression ID**: `{clean_id}`\n\n"
                f"```json\n{err_str}\n```"
            )

        rule = response.json()
        rule_id = rule.get("policy_id") or rule.get("id", clean_id)
        rule_name = rule.get("name", "Unnamed")
        enabled_str = "✅ Enabled" if rule.get("enable", True) else "⏸️ Disabled"
        desc = rule.get("description", "No description")
        created_by = rule.get("created_by", "Unknown")
        created_at = rule.get("created", "N/A")
        updated_at = rule.get("updated", "N/A")
        controls = rule.get("controls", [])
        scope_obj = rule.get("scope", {})

        return (
            f"# 🛡️ Suppression Rule: {rule_name}\n\n"
            f"- **Rule ID**: `{rule_id}`\n"
            f"- **Status**: {enabled_str}\n"
            f"- **Description**: {desc}\n"
            f"- **Created By**: {created_by} at `{created_at}`\n"
            f"- **Last Updated**: `{updated_at}`\n"
            f"- **Controls Count**: {len(controls)}\n"
            f"- **Scope Expression**: `{scope_obj.get('expression', 'N/A')}`\n\n"
            f"### Full Rule Details\n"
            f"```json\n{json.dumps(rule, indent=2)}\n```"
        )

    @server.tool(
        name="create_suppression",
        description=(
            "Stage the creation of an Aqua Security supply chain suppression rule. "
            "Returns an impact diff preview and a 5-minute confirmation token. "
            "Requires explicit confirmation via `execute_confirmed_action` to apply."
        ),
    )
    async def create_suppression(
        name: str,
        description: str = "",
        reason: str | None = None,
        comment: str | None = None,
        enable: bool = True,
        controls: list[dict[str, Any]] | None = None,
        scope: dict[str, Any] | None = None,
        repository: str | None = None,
        check: str | None = None,
        branch: str | None = None,
    ) -> str:
        """Stage creation of a new suppression rule with impact preview."""
        resolved_controls = _build_controls(check=check, controls=controls)
        resolved_scope = _build_scope(repository=repository, branch=branch, scope=scope)

        # Merge description/reason/comment
        final_description = description
        if not final_description:
            if reason:
                final_description = reason
            elif comment:
                final_description = comment

        payload: dict[str, Any] = {
            "name": name,
            "description": final_description,
            "enable": enable,
            "controls": resolved_controls,
            "scope": resolved_scope,
        }

        field_changes: dict[str, Any] = {
            "name": name,
            "description": final_description,
            "enable": enable,
            "controls_count": len(resolved_controls),
            "scope": resolved_scope,
        }
        if repository:
            field_changes["repository"] = repository
        if check:
            field_changes["check"] = check
        if branch:
            field_changes["branch"] = branch
        if reason:
            field_changes["reason"] = reason
        if comment:
            field_changes["comment"] = comment

        try:
            res_create: str = guardrail.stage_mutation(
                action_type="create_suppression",
                target_resource=f"suppression:{name}",
                description=f"Create suppression rule '{name}'",
                http_method="POST",
                path="/supply_chain/v2/build/suppressions",
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
        name="update_suppression",
        description=(
            "Stage updates to an existing Aqua Security supply chain suppression rule "
            "(e.g. modify name, description, comment, enable/disable status, scope, branch, or controls). "
            "Fetches the existing suppression to construct a complete schema-compliant PUT payload, "
            "merging only requested modifications. "
            "Returns an impact diff preview and a 5-minute confirmation token. "
            "Requires explicit confirmation via `execute_confirmed_action` to apply."
        ),
    )
    async def update_suppression(
        suppression_id: str,
        name: str | None = None,
        description: str | None = None,
        comment: str | None = None,
        reason: str | None = None,
        enable: bool | None = None,
        controls: list[dict[str, Any]] | None = None,
        scope: dict[str, Any] | None = None,
        repository: str | None = None,
        branch: str | None = None,
        check: str | None = None,
        status: str | None = None,
    ) -> str:
        """Stage modification of an existing suppression rule with impact preview."""
        if guardrail.config.read_only:
            return (
                "# ⛔ READ-ONLY MODE: Action Staging Blocked\n\n"
                "Cannot stage action: AQUA_READ_ONLY is enabled. "
                "All state-modifying operations are unconditionally blocked."
            )

        clean_id = suppression_id.strip()

        # 1. Fetch existing suppression rule by ID
        try:
            get_resp = await client.get(f"/supply_chain/v2/build/suppressions/{clean_id}")
        except Exception as exc:  # noqa: BLE001
            return (
                f"# 🔴 Failed to Fetch Existing Suppression Rule (Client / Network Error)\n\n"
                f"- **Suppression ID**: `{clean_id}`\n"
                f"- **Error**: {exc}\n"
            )

        if not get_resp.is_success:
            try:
                err_data = get_resp.json()
                err_str = json.dumps(err_data, indent=2)
            except Exception:  # noqa: BLE001
                err_str = get_resp.text
            return (
                f"# 🔴 Suppression Rule Not Found or Error (HTTP {get_resp.status_code})\n\n"
                f"- **Suppression ID**: `{clean_id}`\n\n"
                f"```json\n{err_str}\n```"
            )

        # 2. Extract existing suppression data
        raw_data = get_resp.json()
        if isinstance(raw_data, dict) and "data" in raw_data and isinstance(raw_data["data"], dict):
            existing_rule = raw_data["data"]
        elif isinstance(raw_data, dict):
            existing_rule = raw_data
        else:
            existing_rule = {}

        # 3. Build PUT payload using only fields accepted by UpdateBuildSecuritySuppression schema
        # Required fields: name, description, enable, controls, scope
        payload: dict[str, Any] = {
            "name": existing_rule.get("name", ""),
            "description": existing_rule.get("description", ""),
            "enable": existing_rule.get("enable", True),
            "controls": existing_rule.get("controls", []),
            "scope": existing_rule.get("scope") or _build_scope(),
        }

        # Allowed optional fields in UpdateBuildSecuritySuppression
        for opt_key in (
            "enforce",
            "fail_build",
            "fail_pr",
            "enforcement_schedule",
            "clear_schedule",
            "type",
            "policy_id",
        ):
            if opt_key in existing_rule and existing_rule[opt_key] is not None:
                payload[opt_key] = existing_rule[opt_key]

        # 4. Merge caller-requested changes into PUT payload
        field_changes: dict[str, Any] = {"suppression_id": clean_id}

        if name is not None:
            payload["name"] = name
            field_changes["name"] = name

        final_desc: str | None = None
        if description is not None:
            final_desc = description
        elif comment is not None:
            final_desc = comment
        elif reason is not None:
            final_desc = reason

        if final_desc is not None:
            payload["description"] = final_desc
            field_changes["description"] = final_desc
        if comment is not None:
            field_changes["comment"] = comment
        if reason is not None:
            field_changes["reason"] = reason

        resolved_enable = enable
        if status is not None:
            if status.lower() == "enabled":
                resolved_enable = True
            elif status.lower() == "disabled":
                resolved_enable = False

        if resolved_enable is not None:
            payload["enable"] = resolved_enable
            field_changes["enable"] = resolved_enable
        if status is not None:
            field_changes["status"] = status

        if controls is not None or check is not None:
            resolved_controls = _build_controls(check=check, controls=controls)
            payload["controls"] = resolved_controls
            field_changes["controls_count"] = len(resolved_controls)
        if check is not None:
            field_changes["check"] = check

        if scope is not None or repository is not None or branch is not None:
            resolved_scope = _build_scope(repository=repository, branch=branch, scope=scope)
            payload["scope"] = resolved_scope
            field_changes["scope"] = resolved_scope
        if repository is not None:
            field_changes["repository"] = repository
        if branch is not None:
            field_changes["branch"] = branch

        # 5. Stage the mutation
        try:
            res_update: str = guardrail.stage_mutation(
                action_type="update_suppression",
                target_resource=f"suppression:{clean_id}",
                description=f"Update suppression rule '{clean_id}'",
                http_method="PUT",
                path=f"/supply_chain/v2/build/suppressions/{clean_id}",
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
        name="delete_suppression",
        description=(
            "Stage the deletion of an Aqua Security supply chain suppression rule by ID. "
            "Returns an impact diff preview and a 5-minute confirmation token. "
            "Requires explicit confirmation via `execute_confirmed_action` to apply."
        ),
    )
    async def delete_suppression(
        suppression_id: str,
    ) -> str:
        """Stage deletion of a suppression rule with impact preview."""
        clean_id = suppression_id.strip()
        field_changes: dict[str, Any] = {"suppression_id": clean_id}

        try:
            res_del: str = guardrail.stage_mutation(
                action_type="delete_suppression",
                target_resource=f"suppression:{clean_id}",
                description=f"Delete suppression rule '{clean_id}'",
                http_method="DELETE",
                path=f"/supply_chain/v2/build/suppressions/{clean_id}",
                field_changes=field_changes,
            )
            return res_del
        except ReadOnlyError as err:
            return (
                f"# ⛔ READ-ONLY MODE: Action Staging Blocked\n\n"
                f"{err}"
            )

    @server.tool(
        name="import_suppressions",
        description=(
            "Stage bulk import of one or multiple Aqua Security supply chain suppression rules "
            "with dry-run pre-validation. "
            "Returns an impact diff preview with rule count and a 5-minute confirmation token. "
            "Requires explicit confirmation via `execute_confirmed_action` to apply."
        ),
    )
    async def import_suppressions(
        data: list[dict[str, Any]],
        replace: bool = True,
    ) -> str:
        """Stage bulk import of suppression rules with dry-run schema pre-validation."""
        if not data:
            return (
                "# ⚠️ Import Cancelled: Empty Data\n\n"
                "The `data` array contains no suppression rule definitions to import."
            )

        # Dry-run validation of input items
        invalid_entries: list[str] = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                invalid_entries.append(f"Item #{i+1} is not a valid dictionary/object.")
            elif not item.get("name"):
                invalid_entries.append(f"Item #{i+1} is missing the required 'name' attribute.")

        if invalid_entries:
            return (
                f"# ❌ Dry-Run Verification Failed ({len(invalid_entries)} validation errors)\n\n"
                + "\n".join(f"- {err}" for err in invalid_entries)
                + "\n\nPlease fix the rule definitions and retry the import."
            )

        sample_names = [rule.get("name", f"rule-{i+1}") for i, rule in enumerate(data[:5])]
        field_changes: dict[str, Any] = {
            "total_rules_to_import": len(data),
            "dry_run_validation": "passed",
            "replace_existing": replace,
            "sample_rules": sample_names,
        }

        payload: dict[str, Any] = {
            "replace": replace,
            "data": data,
        }

        try:
            res_import: str = guardrail.stage_mutation(
                action_type="import_suppressions",
                target_resource=f"suppressions:import:{len(data)}_rules",
                description=f"Bulk import {len(data)} suppression rules (replace={replace})",
                http_method="POST",
                path="/supply_chain/v2/build/suppressions/import",
                params={"replace": replace},
                field_changes=field_changes,
                payload=payload,
            )
            return res_import
        except ReadOnlyError as err:
            return (
                f"# ⛔ READ-ONLY MODE: Action Staging Blocked\n\n"
                f"{err}"
            )
