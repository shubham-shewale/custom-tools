import pytest
import respx
from mcp.types import CallToolResult, TextContent

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
    assert "mock_jwt_token_eu" not in text  # JWT secret should not be leaked raw


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
