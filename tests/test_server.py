import time

import httpx
import pytest
import respx
from mcp.types import CallToolResult

from aquasec_mcp.auth import AquaToken
from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig
from aquasec_mcp.guardrail import GuardrailEngine
from aquasec_mcp.server import create_mcp_server
from tests.conftest import extract_tool_text


@pytest.mark.asyncio
@respx.mock
async def test_check_aqua_connection_tool_success() -> None:
    config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "mock_jwt_token_eu"},
    )

    client = AquaClient(config=config)
    server = create_mcp_server(config=config, client=client)

    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    assert "check_aqua_connection" in tool_names
    assert "execute_confirmed_action" in tool_names
    assert "cancel_staged_action" in tool_names
    assert "list_staged_actions" in tool_names
    assert "list_suppressions" in tool_names
    assert "get_suppression" in tool_names
    assert "create_suppression" in tool_names
    assert "update_suppression" in tool_names
    assert "delete_suppression" in tool_names
    assert "import_suppressions" in tool_names
    assert "list_users" in tool_names
    assert "get_user" in tool_names
    assert "create_user" in tool_names
    assert "update_user" in tool_names
    assert "delete_user" in tool_names

    result = await server.call_tool("check_aqua_connection", {})
    text = extract_tool_text(result)
    assert "🟢 Aqua Security EU Connection: Successful" in text
    assert "EU (eu-central-1)" in text
    assert "https://eu-central-1.edge.cloud.aquasec.com" in text
    assert '"status": "connected"' in text
    assert "mock_jwt_token_eu" not in text  # JWT token content should not be exposed raw


@pytest.mark.asyncio
@respx.mock
async def test_check_aqua_connection_missing_credentials() -> None:
    config = AquaConfig(
        api_key=None,
        api_secret=None,
    )
    client = AquaClient(config=config)
    server = create_mcp_server(config=config, client=client)

    result = await server.call_tool("check_aqua_connection", {})
    text = extract_tool_text(result)
    assert "🔴 Aqua Security EU Connection: Failed" in text
    assert "AQUA_API_KEY and AQUA_API_SECRET must be set" in text
    assert "Troubleshooting" in text
    assert '"status": "failed"' in text


@pytest.mark.asyncio
@respx.mock
async def test_check_aqua_connection_auth_failure() -> None:
    config = AquaConfig(
        api_key="bad-key",
        api_secret="bad-secret",
    )
    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=403,
        json={"message": "Invalid credentials or signature"},
    )

    client = AquaClient(config=config)
    server = create_mcp_server(config=config, client=client)

    result = await server.call_tool("check_aqua_connection", {})
    text = extract_tool_text(result)
    assert "🔴 Aqua Security EU Connection: Failed" in text
    assert "403" in text


@pytest.mark.asyncio
@respx.mock
async def test_check_aqua_connection_proactive_refresh_at_mcp_seam() -> None:
    config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
    )
    client = AquaClient(config=config)
    # Seed client auth manager with a token that expires in 2 minutes (proactive refresh triggered)
    client.auth_manager._cached_token = AquaToken(
        token="expiring_token", expires_at=time.time() + 120
    )

    token_route = respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "new_proactive_refreshed_jwt"},
    )

    server = create_mcp_server(config=config, client=client)
    result = await server.call_tool("check_aqua_connection", {})

    assert isinstance(result, CallToolResult)
    assert not result.is_error
    assert token_route.call_count == 1
    assert client.auth_manager.cached_token == "new_proactive_refreshed_jwt"


@pytest.mark.asyncio
@respx.mock
async def test_client_reactive_401_seam_with_mock_transport() -> None:
    config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
    )
    client = AquaClient(config=config)
    client.auth_manager._cached_token = AquaToken(
        token="stale_jwt_token", expires_at=time.time() + 3600
    )

    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "fresh_jwt_token_recovered"},
    )

    api_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/roles")
    api_route.side_effect = [
        httpx.Response(401, json={"message": "Unauthorized"}),
        httpx.Response(200, json={"data": [{"name": "Administrator"}]}),
    ]

    response = await client.get("/cspm/v2/roles")
    assert response.status_code == 200
    assert response.json()["data"][0]["name"] == "Administrator"
    assert api_route.call_count == 2
    assert api_route.calls[0].request.headers["Authorization"] == "Bearer stale_jwt_token"
    assert api_route.calls[1].request.headers["Authorization"] == "Bearer fresh_jwt_token_recovered"


@pytest.mark.asyncio
@respx.mock
async def test_guardrail_mcp_tool_flow_list_execute_cancel() -> None:
    config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"data": "mock_jwt_token"},
    )
    mutation_route = respx.post("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=201,
        json={"status": "success", "user_id": 999, "email": "engineer@example.com"},
    )

    client = AquaClient(config=config)
    engine = GuardrailEngine(config=config, client=client)
    server = create_mcp_server(config=config, client=client, guardrail_engine=engine)

    # 1. list_staged_actions when empty
    list_res1 = await server.call_tool("list_staged_actions", {})
    assert "No staged actions pending confirmation" in extract_tool_text(list_res1)

    # 2. Stage 2 actions in the engine
    engine.stage_mutation(
        action_type="create_user",
        target_resource="user:engineer@example.com",
        description="Create engineer user",
        http_method="POST",
        path="/cspm/v2/users",
        field_changes={"email": "engineer@example.com", "roles": ["Scanner"]},
        payload={"email": "engineer@example.com", "roles": ["Scanner"]},
    )
    engine.stage_mutation(
        action_type="delete_user",
        target_resource="user:old@example.com",
        description="Delete old user",
        http_method="DELETE",
        path="/cspm/v2/users/123",
        field_changes={"user_id": 123},
    )

    actions = engine.store.list_active_actions()
    assert len(actions) == 2
    token_create = actions[0].confirmation_token
    token_delete = actions[1].confirmation_token

    # 3. list_staged_actions shows both
    list_res2 = await server.call_tool("list_staged_actions", {})
    list_text2 = extract_tool_text(list_res2)
    assert token_create in list_text2
    assert token_delete in list_text2
    assert "user:engineer@example.com" in list_text2

    # 4. Cancel the delete action
    cancel_res = await server.call_tool("cancel_staged_action", {"confirmation_token": token_delete})
    cancel_text = extract_tool_text(cancel_res)
    assert "🗑️ Staged Action Cancelled" in cancel_text
    assert token_delete in cancel_text

    # 5. Execute confirmed create action
    exec_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": token_create})
    exec_text = extract_tool_text(exec_res)
    assert "✅ Action Executed Successfully" in exec_text
    assert "user_id" in exec_text
    assert mutation_route.call_count == 1

    # 6. Replay execution should fail
    replay_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": token_create})
    replay_text = extract_tool_text(replay_res)
    assert "❌ Invalid or Expired Confirmation Token" in replay_text


@pytest.mark.asyncio
async def test_guardrail_mcp_tool_read_only_killswitch() -> None:
    config = AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        read_only=True,
    )
    client = AquaClient(config=config)
    engine = GuardrailEngine(config=config, client=client)
    server = create_mcp_server(config=config, client=client, guardrail_engine=engine)

    exec_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": "any-token"})
    assert "⛔ READ-ONLY MODE" in extract_tool_text(exec_res)
