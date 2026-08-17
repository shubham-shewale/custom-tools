import time

import httpx
import pytest
import respx
from mcp.types import CallToolResult, TextContent

from aquasec_mcp.auth import AquaToken
from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig
from aquasec_mcp.server import create_mcp_server


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

    result = await server.call_tool("check_aqua_connection", {})
    assert isinstance(result, CallToolResult)
    assert not result.is_error
    assert len(result.content) > 0
    first_block = result.content[0]
    assert isinstance(first_block, TextContent)
    text = first_block.text
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
    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    first_block = result.content[0]
    assert isinstance(first_block, TextContent)
    text = first_block.text
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
    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    first_block = result.content[0]
    assert isinstance(first_block, TextContent)
    text = first_block.text
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
