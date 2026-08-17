import httpx
import pytest
import respx

from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig


@pytest.mark.asyncio
@respx.mock
async def test_client_request_with_bearer_token() -> None:
    config = AquaConfig(
        api_key="my-key",
        api_secret="my-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "valid.jwt.token"},
    )
    api_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=200,
        json={"data": [{"id": 1, "name": "Admin"}]},
    )

    async with AquaClient(config=config) as client:
        response = await client.request("GET", "/cspm/v2/users")
        assert response.status_code == 200
        assert response.json()["data"][0]["name"] == "Admin"

    assert api_route.call_count == 1
    assert api_route.calls.last.request.headers["Authorization"] == "Bearer valid.jwt.token"


@pytest.mark.asyncio
@respx.mock
async def test_client_reactive_401_retry_recovery() -> None:
    config = AquaConfig(
        api_key="my-key",
        api_secret="my-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )

    # First token call returns expired/initial token
    token_route = respx.post("https://eu-1.api.cloudsploit.com/v2/tokens")
    token_route.side_effect = [
        httpx.Response(200, json={"status": 200, "data": "stale_token_1"}),
        httpx.Response(200, json={"status": 200, "data": "fresh_token_2"}),
    ]

    # API endpoint returns 401 on first try (with stale_token_1), and 200 on retry (with fresh_token_2)
    api_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users")
    api_route.side_effect = [
        httpx.Response(401, json={"message": "Token expired"}),
        httpx.Response(200, json={"data": [{"id": 2, "name": "Security Officer"}]}),
    ]

    async with AquaClient(config=config) as client:
        response = await client.get("/cspm/v2/users")
        assert response.status_code == 200
        assert response.json()["data"][0]["name"] == "Security Officer"

    # API should have been called twice (once failed 401, once succeeded 200)
    assert api_route.call_count == 2
    assert api_route.calls[0].request.headers["Authorization"] == "Bearer stale_token_1"
    assert api_route.calls[1].request.headers["Authorization"] == "Bearer fresh_token_2"


@pytest.mark.asyncio
@respx.mock
async def test_client_reactive_401_stops_after_single_retry() -> None:
    config = AquaConfig(
        api_key="my-key",
        api_secret="my-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )

    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "token"},
    )
    api_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/cspm/v2/users").respond(
        status_code=401,
        json={"message": "Permanent Unauthorized"},
    )

    async with AquaClient(config=config) as client:
        response = await client.get("/cspm/v2/users")
        assert response.status_code == 401

    # Should not infinite loop: 1 initial attempt + 1 retry = 2 calls
    assert api_route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_check_connection_success() -> None:
    config = AquaConfig(
        api_key="my-key",
        api_secret="my-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "valid_token_xyz"},
    )

    async with AquaClient(config=config) as client:
        result = await client.check_connection()

    assert result["status"] == "connected"
    assert result["region"] == "EU (eu-central-1)"
    assert result["base_url"] == "https://eu-central-1.edge.cloud.aquasec.com"
    assert result["token_url"] == "https://eu-1.api.cloudsploit.com/v2/tokens"
    assert result["authenticated"] is True
    assert "token_expires_at" in result
