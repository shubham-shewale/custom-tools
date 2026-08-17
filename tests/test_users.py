"""High-seam integration tests for Aqua Security Account Management: Users tools."""

from __future__ import annotations

import json

import pytest
import respx

from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig
from aquasec_mcp.guardrail import GuardrailEngine
from aquasec_mcp.server import create_mcp_server
from tests.conftest import extract_token_from_diff as _extract_token_from_diff
from tests.conftest import extract_tool_text


@pytest.fixture
def mock_auth() -> respx.Route:
    return respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "mock_valid_jwt_token"},
    )


# ---------------------------------------------------------------------------
# 1. list_users tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_users_success(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    users_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=200,
        json={
            "status": 200,
            "total_count": 2,
            "data": [
                {
                    "id": 101,
                    "email": "admin@example.com",
                    "account_admin": True,
                    "confirmed": True,
                    "csp_roles": ["Administrator", "Compliance Officer"],
                    "created": "2025-01-10T08:30:00Z",
                },
                {
                    "id": 102,
                    "email": "analyst@example.com",
                    "account_admin": False,
                    "confirmed": True,
                    "csp_roles": ["Auditor"],
                    "created": "2025-02-14T11:20:00Z",
                },
            ],
        },
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool(
        "list_users",
        {
            "limit": 50,
            "offset": 0,
            "expand": "roles,group,account",
        },
    )
    text = extract_tool_text(result)

    assert "👥 Aqua Security Users" in text
    assert "Users on Page**: 2" in text
    assert "Total Users**: 2" in text
    assert "admin@example.com" in text
    assert "👑 Admin" in text
    assert "Administrator, Compliance Officer" in text
    assert "analyst@example.com" in text
    assert "👤 Standard User" in text
    assert "Auditor" in text

    assert users_route.call_count == 1
    req = users_route.calls[0].request
    assert req.url.params["limit"] == "50"
    assert req.url.params["offset"] == "0"
    assert req.url.params["expand"] == "roles,group,account"


@pytest.mark.asyncio
@respx.mock
async def test_list_users_empty(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=200,
        json={"status": 200, "total_count": 0, "data": []},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_users", {})
    text = extract_tool_text(result)

    assert "👥 Aqua Security Users" in text
    assert "Users on Page**: 0" in text
    assert "Total Users**: 0" in text
    assert "No users found matching the query criteria." in text


@pytest.mark.asyncio
@respx.mock
async def test_list_users_api_error(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=500,
        json={"message": "Internal database error"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_users", {})
    text = extract_tool_text(result)

    assert "Failed to List Users (HTTP 500)" in text
    assert "Internal database error" in text


# ---------------------------------------------------------------------------
# 2. get_user tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_get_user_success(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    user_id = 101
    user_route = respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/{user_id}").respond(
        status_code=200,
        json={
            "status": 200,
            "data": {
                "id": 101,
                "email": "secops-lead@example.com",
                "account_admin": True,
                "confirmed": True,
                "created": "2025-01-10T08:30:00Z",
                "csp_roles": ["Administrator", "Scanner"],
                "groups": [{"id": 1, "name": "Global Security"}],
                "accounts": [{"id": 5001, "name": "Production EU"}],
                "last_signin_attempt": "2026-02-17T15:00:00Z",
                "count_failed_signin": 0,
            },
        },
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_user", {"user_id": user_id, "expand": "roles,group,account"})
    text = extract_tool_text(result)

    assert "👤 User Profile: secops-lead@example.com" in text
    assert "User ID**: `101`" in text
    assert "👑 Admin" in text
    assert "Administrator, Scanner" in text
    assert "Global Security" in text
    assert "Production EU" in text
    assert "2025-01-10T08:30:00Z" in text

    assert user_route.call_count == 1
    req = user_route.calls[0].request
    assert req.url.params["expand"] == "roles,group,account"


@pytest.mark.asyncio
@respx.mock
async def test_get_user_not_found(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/9999").respond(
        status_code=404,
        json={"message": "User not found with ID 9999"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_user", {"user_id": 9999})
    text = extract_tool_text(result)

    assert "User Not Found or Error (HTTP 404)" in text
    assert "9999" in text
    assert "User not found with ID 9999" in text


@pytest.mark.asyncio
@respx.mock
async def test_get_user_network_error(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/101").mock(
        side_effect=Exception("Connection reset by peer")
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_user", {"user_id": 101})
    text = extract_tool_text(result)

    assert "Failed to Get User (Client / Network Error)" in text
    assert "Connection reset by peer" in text


# ---------------------------------------------------------------------------
# 3. create_user tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_create_user_staging_and_confirmed_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    create_route = respx.post("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=200,
        json={
            "status": 200,
            "data": {
                "id": 201,
                "email": "new.devops@example.com",
                "account_admin": False,
                "csp_roles": ["Scanner", "Auditor"],
                "confirmed": False,
                "created": "2026-02-17T16:00:00Z",
            },
        },
    )

    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    # 1. Staging phase
    stage_result = await server.call_tool(
        "create_user",
        {
            "email": "new.devops@example.com",
            "account_admin": False,
            "csp_roles": ["Scanner", "Auditor"],
            "mfa_enabled": True,
        },
    )
    diff_text = extract_tool_text(stage_result)

    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    assert "create_user" in diff_text
    assert "user:new.devops@example.com" in diff_text
    assert "new.devops@example.com" in diff_text
    assert "Scanner" in diff_text
    assert "Auditor" in diff_text
    assert "execute_confirmed_action" in diff_text
    # Aqua API must NOT have been called yet
    assert create_route.call_count == 0

    token = _extract_token_from_diff(diff_text)
    assert len(token) > 20

    # 2. Confirmed execution phase
    exec_result = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    exec_text = extract_tool_text(exec_result)

    assert "Action Executed Successfully" in exec_text
    assert "HTTP Status**: `200`" in exec_text
    assert "new.devops@example.com" in exec_text
    assert "201" in exec_text

    # Now Aqua API must have received the POST request
    assert create_route.call_count == 1
    req_body = json.loads(create_route.calls[0].request.content.decode("utf-8"))
    assert req_body["email"] == "new.devops@example.com"
    assert req_body["account_admin"] is False
    assert req_body["csp_roles"] == ["Scanner", "Auditor"]
    assert req_body["mfa_enabled"] is True

    # 3. Token cannot be replayed
    replay_result = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    replay_text = extract_tool_text(replay_result)
    assert "Invalid or Expired Confirmation Token" in replay_text


@pytest.mark.asyncio
async def test_create_user_readonly_blocked() -> None:
    read_only_config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        read_only=True,
    )
    client = AquaClient(config=read_only_config)
    guardrail = GuardrailEngine(config=read_only_config, client=client)
    server = create_mcp_server(config=read_only_config, client=client, guardrail_engine=guardrail)

    result = await server.call_tool(
        "create_user",
        {
            "email": "blocked@example.com",
            "account_admin": True,
        },
    )
    text = extract_tool_text(result)

    assert "READ-ONLY MODE: Action Staging Blocked" in text
    assert "AQUA_READ_ONLY is enabled" in text


# ---------------------------------------------------------------------------
# 4. update_user tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_update_user_staging_and_confirmed_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    user_id = 301
    update_route = respx.put(f"https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/{user_id}").respond(
        status_code=200,
        json={"status": 200, "message": "User updated successfully"},
    )

    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    # 1. Staging phase
    stage_result = await server.call_tool(
        "update_user",
        {
            "user_id": user_id,
            "csp_roles": ["Administrator", "Auditor"],
            "account_admin": True,
            "mfa_enabled": True,
            "mfa_reset": False,
            "send_new_plugins": True,
        },
    )
    diff_text = extract_tool_text(stage_result)

    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    assert "update_user" in diff_text
    assert f"user:{user_id}" in diff_text
    assert "Administrator" in diff_text
    assert "Auditor" in diff_text
    assert f"PUT /cspm/v2/users/{user_id}" in diff_text
    assert update_route.call_count == 0

    token = _extract_token_from_diff(diff_text)
    assert len(token) > 20

    # 2. Confirmed execution phase
    exec_result = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    exec_text = extract_tool_text(exec_result)

    assert "Action Executed Successfully" in exec_text
    assert "HTTP Status**: `200`" in exec_text
    assert "User updated successfully" in exec_text

    # Verify Aqua API received the PUT request with payload
    assert update_route.call_count == 1
    req_body = json.loads(update_route.calls[0].request.content.decode("utf-8"))
    assert req_body["csp_roles"] == ["Administrator", "Auditor"]
    assert req_body["account_admin"] is True
    assert req_body["mfa_enabled"] is True
    assert req_body["mfa_reset"] is False
    assert req_body["send_new_plugins"] is True

    # 3. Purged token replay fails
    replay_result = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    replay_text = extract_tool_text(replay_result)
    assert "Invalid or Expired Confirmation Token" in replay_text


@pytest.mark.asyncio
async def test_update_user_readonly_blocked() -> None:
    read_only_config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        read_only=True,
    )
    client = AquaClient(config=read_only_config)
    guardrail = GuardrailEngine(config=read_only_config, client=client)
    server = create_mcp_server(config=read_only_config, client=client, guardrail_engine=guardrail)

    result = await server.call_tool(
        "update_user",
        {
            "user_id": 101,
            "account_admin": True,
        },
    )
    text = extract_tool_text(result)

    assert "READ-ONLY MODE: Action Staging Blocked" in text
    assert "AQUA_READ_ONLY is enabled" in text


@pytest.mark.asyncio
async def test_update_user_no_fields_specified(base_config: AquaConfig) -> None:
    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    result = await server.call_tool("update_user", {"user_id": 101})
    text = extract_tool_text(result)

    assert "No Updates Specified" in text
    assert "101" in text
    assert len(guardrail.store.list_active_actions()) == 0


# ---------------------------------------------------------------------------
# 5. delete_user tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_delete_user_staging_and_confirmed_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    user_id = 401
    delete_route = respx.delete(f"https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/{user_id}").respond(
        status_code=200,
        json={"status": 200, "message": "User removed successfully"},
    )

    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    # 1. Staging phase
    stage_result = await server.call_tool("delete_user", {"user_id": user_id})
    diff_text = extract_tool_text(stage_result)

    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    assert "delete_user" in diff_text
    assert f"user:{user_id}" in diff_text
    assert f"DELETE /cspm/v2/users/{user_id}" in diff_text
    assert delete_route.call_count == 0

    token = _extract_token_from_diff(diff_text)
    assert len(token) > 20

    # 2. Confirmed execution phase
    exec_result = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    exec_text = extract_tool_text(exec_result)

    assert "Action Executed Successfully" in exec_text
    assert "HTTP Status**: `200`" in exec_text
    assert "User removed successfully" in exec_text

    # Verify Aqua API received the DELETE request
    assert delete_route.call_count == 1

    # 3. Purged token replay fails
    replay_result = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    replay_text = extract_tool_text(replay_result)
    assert "Invalid or Expired Confirmation Token" in replay_text


@pytest.mark.asyncio
async def test_delete_user_readonly_blocked() -> None:
    read_only_config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        read_only=True,
    )
    client = AquaClient(config=read_only_config)
    guardrail = GuardrailEngine(config=read_only_config, client=client)
    server = create_mcp_server(config=read_only_config, client=client, guardrail_engine=guardrail)

    result = await server.call_tool("delete_user", {"user_id": 101})
    text = extract_tool_text(result)

    assert "READ-ONLY MODE: Action Staging Blocked" in text
    assert "AQUA_READ_ONLY is enabled" in text


# ---------------------------------------------------------------------------
# 6. Additional Edge Cases & Staged Action Lifecycle for Users
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_users_with_list_expansion(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    users_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=200,
        json={"status": 200, "data": []},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_users", {"expand": ["roles", "group", "account"]})
    assert "👥 Aqua Security Users" in extract_tool_text(result)

    assert users_route.call_count == 1
    req = users_route.calls[0].request
    assert req.url.params["expand"] == "roles,group,account"


@pytest.mark.asyncio
@respx.mock
async def test_list_users_network_error(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").mock(
        side_effect=Exception("Network timeout connecting to Aqua EU")
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_users", {})
    text = extract_tool_text(result)
    assert "Failed to List Users (Client / Network Error)" in text
    assert "Network timeout" in text


@pytest.mark.asyncio
@respx.mock
async def test_get_user_forbidden_error(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/123").respond(
        status_code=403,
        json={"message": "Access denied: insufficient permissions to view this user"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_user", {"user_id": 123})
    text = extract_tool_text(result)
    assert "User Not Found or Error (HTTP 403)" in text
    assert "Access denied" in text


@pytest.mark.asyncio
@respx.mock
async def test_create_user_api_error_on_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    respx.post("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=409,
        json={"message": "The email address is already associated with a user in this account."},
    )

    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    stage_res = await server.call_tool(
        "create_user",
        {"email": "existing@example.com", "account_admin": False},
    )
    token = _extract_token_from_diff(extract_tool_text(stage_res))

    exec_res = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    exec_text = extract_tool_text(exec_res)
    assert "Action Execution Failed (API Error)" in exec_text
    assert "HTTP Status**: `409`" in exec_text
    assert "already associated with a user" in exec_text


@pytest.mark.asyncio
@respx.mock
async def test_update_user_api_error_on_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    respx.put("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/888").respond(
        status_code=422,
        json={"message": "Invalid role name specified in csp_roles"},
    )

    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    stage_res = await server.call_tool(
        "update_user",
        {"user_id": 888, "csp_roles": ["NonExistentRole"]},
    )
    token = _extract_token_from_diff(extract_tool_text(stage_res))

    exec_res = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    exec_text = extract_tool_text(exec_res)
    assert "Action Execution Failed (API Error)" in exec_text
    assert "HTTP Status**: `422`" in exec_text
    assert "Invalid role name" in exec_text


@pytest.mark.asyncio
@respx.mock
async def test_delete_user_api_error_on_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    respx.delete("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users/1").respond(
        status_code=403,
        json={"message": "Forbidden - cannot remove self or cannot remove primary admin users"},
    )

    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    stage_res = await server.call_tool("delete_user", {"user_id": 1})
    token = _extract_token_from_diff(extract_tool_text(stage_res))

    exec_res = await server.call_tool(
        "execute_confirmed_action",
        {"confirmation_token": token},
    )
    exec_text = extract_tool_text(exec_res)
    assert "Action Execution Failed (API Error)" in exec_text
    assert "HTTP Status**: `403`" in exec_text
    assert "cannot remove primary admin users" in exec_text


@pytest.mark.asyncio
@respx.mock
async def test_cancel_staged_user_mutation(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    stage_res = await server.call_tool(
        "create_user",
        {"email": "to-cancel@example.com", "account_admin": False},
    )
    token = _extract_token_from_diff(extract_tool_text(stage_res))
    assert len(guardrail.store.list_active_actions()) == 1

    cancel_res = await server.call_tool("cancel_staged_action", {"confirmation_token": token})
    cancel_text = extract_tool_text(cancel_res)
    assert "🗑️ Staged Action Cancelled" in cancel_text
    assert "to-cancel@example.com" in cancel_text
    assert len(guardrail.store.list_active_actions()) == 0


@pytest.mark.asyncio
@respx.mock
async def test_list_staged_actions_with_user_mutations(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    client = AquaClient(config=base_config)
    guardrail = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=guardrail)

    await server.call_tool("create_user", {"email": "user1@example.com", "account_admin": False})
    await server.call_tool("update_user", {"user_id": 100, "account_admin": True})
    await server.call_tool("delete_user", {"user_id": 200})

    list_res = await server.call_tool("list_staged_actions", {})
    list_text = extract_tool_text(list_res)

    assert "Total pending actions: **3**" in list_text
    assert "user:user1@example.com" in list_text
    assert "user:100" in list_text
    assert "user:200" in list_text



