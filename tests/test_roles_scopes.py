"""High-seam integration tests for Aqua Security Account Management: Roles & Application Scopes tools."""

from __future__ import annotations

import pytest
import respx

from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig
from aquasec_mcp.server import create_mcp_server
from tests.conftest import extract_tool_text


@pytest.fixture
def mock_auth() -> respx.Route:
    return respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "mock_valid_jwt_token"},
    )


# ---------------------------------------------------------------------------
# 1. list_roles tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_roles_success(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    roles_data = [
        {
            "id": 1,
            "name": "Administrator",
            "description": "Full access to all Aqua Security CSPM and Supply Chain resources",
            "role_type": "system",
            "author": "system",
            "permission_count": 45,
            "permissions": [
                "account_mgmt.users.read",
                "account_mgmt.users.write",
                "ssc.suppression_rules.read",
                "ssc.suppression_rules.write",
            ],
            "updated_at": "2025-01-01T00:00:00Z",
        },
        {
            "id": 2,
            "name": "Auditor",
            "description": "Read-only access for compliance audit and reporting",
            "role_type": "system",
            "author": "system",
            "permission_count": 18,
            "permissions": [
                "account_mgmt.users.read",
                "ssc.suppression_rules.read",
            ],
            "updated_at": "2025-01-01T00:00:00Z",
        },
        {
            "id": 10,
            "name": "DevSecOps Engineer",
            "description": "Custom role for CI/CD pipeline scanning and policy inspection",
            "role_type": "custom",
            "author": "secops@example.com",
            "permission_count": 12,
            "permissions": [
                "ssc.suppression_rules.read",
                "ssc.suppression_rules.write",
            ],
            "updated_at": "2025-02-10T15:30:00Z",
        },
    ]

    roles_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles").respond(
        status_code=200,
        json={
            "status": 200,
            "total_count": 3,
            "data": roles_data,
        },
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool(
        "list_roles",
        {
            "limit": 20,
            "offset": 0,
            "search": "DevSecOps",
        },
    )
    text = extract_tool_text(result)

    assert "🛡️ Aqua Security CSP Roles" in text
    assert "Roles on Page**: 3" in text
    assert "Total Roles**: 3" in text
    assert "Administrator" in text
    assert "Full access to all Aqua Security CSPM" in text
    assert "Auditor" in text
    assert "DevSecOps Engineer" in text
    assert "Custom" in text or "custom" in text

    assert roles_route.call_count == 1
    req = roles_route.calls[0].request
    assert req.url.params["limit"] == "20"
    assert req.url.params["offset"] == "0"
    assert req.url.params["search"] == "DevSecOps"


@pytest.mark.asyncio
@respx.mock
async def test_list_roles_empty(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles").respond(
        status_code=200,
        json={"status": 200, "total_count": 0, "data": []},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_roles", {})
    text = extract_tool_text(result)

    assert "🛡️ Aqua Security CSP Roles" in text
    assert "No CSP roles found" in text


@pytest.mark.asyncio
@respx.mock
async def test_list_roles_http_error(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles").respond(
        status_code=500,
        json={"message": "Internal server error fetching roles"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_roles", {})
    text = extract_tool_text(result)

    assert "🔴 Failed to List Roles" in text
    assert "HTTP 500" in text
    assert "Internal server error fetching roles" in text


@pytest.mark.asyncio
@respx.mock
async def test_list_roles_network_error(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles").mock(
        side_effect=Exception("Connection timeout")
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_roles", {})
    text = extract_tool_text(result)

    assert "🔴 Failed to List Roles (Client / Network Error)" in text
    assert "Connection timeout" in text


# ---------------------------------------------------------------------------
# 2. get_role_details tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_get_role_details_success_by_id(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    role_payload = {
        "id": 1,
        "name": "Administrator",
        "description": "Super administrator with all permissions",
        "role_type": "system",
        "author": "system",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z",
        "permissions": [
            "account_mgmt.users.read",
            "account_mgmt.users.write",
            "account_mgmt.apikeys.read",
            "account_mgmt.apikeys.write",
            "ssc.suppression_rules.read",
            "ssc.suppression_rules.write",
            "inventory.cloud_accounts.read",
        ],
    }

    role_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles/1").respond(
        status_code=200,
        json={"status": 200, "data": role_payload},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_role_details", {"role_id": 1})
    text = extract_tool_text(result)

    assert "🛡️ Role Details: Administrator" in text
    assert "Role ID**: `1`" in text
    assert "Super administrator with all permissions" in text
    assert "account_mgmt.users.read" in text
    assert "ssc.suppression_rules.write" in text
    assert "inventory.cloud_accounts.read" in text
    assert "Permissions Matrix" in text or "Permissions Breakdown" in text

    assert role_route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_get_role_details_structured_permissions_matrix(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    role_payload = {
        "id": 5,
        "name": "Security Analyst",
        "description": "Analyst role with read/write access to suppressions and read-only access to users",
        "role_type": "custom",
        "author": "admin@example.com",
        "permissions": [
            {"module": "Account Management", "action": "read", "resource": "users"},
            {"module": "Supply Chain Security", "action": "read", "resource": "suppression_rules"},
            {"module": "Supply Chain Security", "action": "write", "resource": "suppression_rules"},
        ],
    }

    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles/5").respond(
        status_code=200,
        json={"status": 200, "data": role_payload},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_role_details", {"role_id": "5"})
    text = extract_tool_text(result)

    assert "🛡️ Role Details: Security Analyst" in text
    assert "Account Management" in text
    assert "Supply Chain Security" in text
    assert "suppression_rules" in text


@pytest.mark.asyncio
@respx.mock
async def test_get_role_details_not_found(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles/999").respond(
        status_code=404,
        json={"message": "Role not found"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_role_details", {"role_id": "999"})
    text = extract_tool_text(result)

    assert "🔴 Role Not Found or Error (HTTP 404)" in text
    assert "Role ID**: `999`" in text
    assert "Role not found" in text


@pytest.mark.asyncio
@respx.mock
async def test_get_role_details_network_error(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles/123").mock(
        side_effect=Exception("Timeout reading role")
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_role_details", {"role_id": 123})
    text = extract_tool_text(result)

    assert "🔴 Failed to Get Role (Client / Network Error)" in text
    assert "Timeout reading role" in text


# ---------------------------------------------------------------------------
# 3. list_application_scopes tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_application_scopes_success(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    scopes_data = [
        {
            "id": 1,
            "name": "Production-EU",
            "description": "All European production Kubernetes clusters and repositories",
            "author": "secops@example.com",
            "categories": ["production", "eu-central-1"],
            "expression": "v1 && v2",
            "variables": [
                {"attribute": "kubernetes.cluster.name", "value": "prod-eu-*"},
                {"attribute": "repository.name", "value": "org/prod-*"},
            ],
            "updated_at": "2025-01-15T10:00:00Z",
        },
        {
            "id": 2,
            "name": "Staging-Global",
            "description": "Global staging environment infrastructure",
            "author": "devops@example.com",
            "categories": ["staging"],
            "expression": "v1",
            "variables": [
                {"attribute": "environment", "value": "staging"},
            ],
            "updated_at": "2025-02-01T12:00:00Z",
        },
    ]

    scopes_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/scopes").respond(
        status_code=200,
        json={
            "status": 200,
            "total_count": 2,
            "data": scopes_data,
        },
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool(
        "list_application_scopes",
        {
            "limit": 10,
            "offset": 0,
            "search": "Production",
        },
    )
    text = extract_tool_text(result)

    assert "🌐 Aqua Security Application Scopes" in text
    assert "Scopes on Page**: 2" in text
    assert "Total Scopes**: 2" in text
    assert "Production-EU" in text
    assert "All European production Kubernetes clusters" in text
    assert "Staging-Global" in text
    assert "prod-eu-*" in text or "v1 && v2" in text

    assert scopes_route.call_count == 1
    req = scopes_route.calls[0].request
    assert req.url.params["limit"] == "10"
    assert req.url.params["offset"] == "0"
    assert req.url.params["search"] == "Production"


@pytest.mark.asyncio
@respx.mock
async def test_list_application_scopes_empty(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/scopes").respond(
        status_code=200,
        json={"status": 200, "total_count": 0, "data": []},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_application_scopes", {})
    text = extract_tool_text(result)

    assert "🌐 Aqua Security Application Scopes" in text
    assert "No application scopes found" in text


@pytest.mark.asyncio
@respx.mock
async def test_list_application_scopes_http_error(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/scopes").respond(
        status_code=502,
        json={"message": "Bad gateway"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_application_scopes", {})
    text = extract_tool_text(result)

    assert "🔴 Failed to List Application Scopes (HTTP 502)" in text
    assert "Bad gateway" in text


@pytest.mark.asyncio
@respx.mock
async def test_list_application_scopes_network_error(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/scopes").mock(
        side_effect=Exception("Network error on scopes")
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_application_scopes", {})
    text = extract_tool_text(result)

    assert "🔴 Failed to List Application Scopes (Client / Network Error)" in text
    assert "Network error on scopes" in text


# ---------------------------------------------------------------------------
# 4. get_application_scope tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_get_application_scope_success(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    scope_data = {
        "id": 1,
        "name": "Production-EU",
        "description": "All European production Kubernetes clusters and supply chain assets",
        "author": "secops@example.com",
        "categories": ["production", "eu-central-1", "critical"],
        "created_at": "2024-06-01T10:00:00Z",
        "updated_at": "2025-01-15T10:00:00Z",
        "expression": "v1 && (v2 || v3)",
        "variables": [
            {
                "id": "v1",
                "attribute": "cloud.provider",
                "operator": "equals",
                "value": "AWS",
            },
            {
                "id": "v2",
                "attribute": "kubernetes.cluster.name",
                "operator": "matches",
                "value": "prod-eu-*",
            },
            {
                "id": "v3",
                "attribute": "repository.name",
                "operator": "in",
                "value": "org/payment-service, org/auth-service",
            },
        ],
    }

    scope_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/scopes/1").respond(
        status_code=200,
        json={"status": 200, "data": scope_data},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_application_scope", {"scope_id": 1})
    text = extract_tool_text(result)

    assert "🌐 Application Scope: Production-EU" in text
    assert "Scope ID**: `1`" in text
    assert "secops@example.com" in text
    assert "production, eu-central-1, critical" in text
    assert "v1 && (v2 || v3)" in text
    assert "cloud.provider" in text
    assert "kubernetes.cluster.name" in text
    assert "prod-eu-*" in text
    assert "org/payment-service" in text

    assert scope_route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_get_application_scope_not_found(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/scopes/404").respond(
        status_code=404,
        json={"message": "Application scope not found"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_application_scope", {"scope_id": "404"})
    text = extract_tool_text(result)

    assert "🔴 Application Scope Not Found or Error (HTTP 404)" in text
    assert "Scope ID**: `404`" in text
    assert "Application scope not found" in text


@pytest.mark.asyncio
@respx.mock
async def test_get_application_scope_network_error(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/scopes/123").mock(
        side_effect=Exception("Failed to fetch scope")
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_application_scope", {"scope_id": 123})
    text = extract_tool_text(result)

    assert "🔴 Failed to Get Application Scope (Client / Network Error)" in text
    assert "Failed to fetch scope" in text
