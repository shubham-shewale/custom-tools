import hashlib
import hmac
import json
import time

import httpx
import pytest
import respx

from aquasec_mcp.auth import AquaAuthError, AquaAuthManager, AquaToken
from aquasec_mcp.config import AquaConfig


def test_token_expiration() -> None:
    now = time.time()
    # Expiring in 10 minutes (600s) -> not expired with 300s buffer
    fresh_token = AquaToken(token="valid_jwt", expires_at=now + 600)
    assert fresh_token.is_expired(buffer_seconds=300) is False

    # Expiring in 4 minutes (240s) -> expired with 300s buffer (proactive refresh trigger)
    soon_expiring_token = AquaToken(token="valid_jwt", expires_at=now + 240)
    assert soon_expiring_token.is_expired(buffer_seconds=300) is True

    # Already expired in the past
    past_token = AquaToken(token="valid_jwt", expires_at=now - 10)
    assert past_token.is_expired(buffer_seconds=300) is True


def test_hmac_signature_generation() -> None:
    config = AquaConfig(
        api_key="my-api-key",
        api_secret="my-super-secret",
    )
    auth = AquaAuthManager(config)

    timestamp = 1770000000
    method = "POST"
    path = "/v2/tokens"
    body = '{"validity":720,"allowed_endpoints":["ANY:*"]}'

    expected_str = f"{timestamp}{method}{path}{body}"
    expected_sig = hmac.new(
        b"my-super-secret",
        expected_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    sig = auth.generate_signature(timestamp=timestamp, method=method, path=path, body=body)
    assert sig == expected_sig

    headers = auth.build_auth_headers(timestamp=timestamp, method=method, path=path, body=body)
    assert headers == {
        "Content-Type": "application/json",
        "X-API-Key": "my-api-key",
        "X-Timestamp": "1770000000",
        "X-Signature": expected_sig,
    }


@pytest.mark.asyncio
@respx.mock
async def test_acquire_token_success() -> None:
    config = AquaConfig(
        api_key="my-api-key",
        api_secret="my-super-secret",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
    auth = AquaAuthManager(config)

    fake_jwt = "header.payload.signature"
    route = respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": fake_jwt},
    )

    async with httpx.AsyncClient() as client:
        token = await auth.get_valid_token(client)

    assert token == fake_jwt
    assert route.call_count == 1

    # Verify request payload and headers sent
    request = route.calls.last.request
    assert request.headers["X-API-Key"] == "my-api-key"
    assert "X-Timestamp" in request.headers
    assert "X-Signature" in request.headers
    assert json.loads(request.content) == {
        "validity": 720,
        "allowed_endpoints": ["ANY:*"],
    }

    # Second call should use cached token without calling API again
    async with httpx.AsyncClient() as client:
        cached_token = await auth.get_valid_token(client)
    assert cached_token == fake_jwt
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_proactive_token_refresh() -> None:
    config = AquaConfig(
        api_key="my-api-key",
        api_secret="my-super-secret",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
    auth = AquaAuthManager(config)

    # Pre-populate cache with a token that expires in 2 minutes (within 5m buffer)
    auth._cached_token = AquaToken(token="expiring_soon_jwt", expires_at=time.time() + 120)

    fresh_jwt = "fresh.jwt.token"
    route = respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": fresh_jwt},
    )

    async with httpx.AsyncClient() as client:
        token = await auth.get_valid_token(client)

    assert token == fresh_jwt
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_invalidate_token_and_force_refresh() -> None:
    config = AquaConfig(
        api_key="my-api-key",
        api_secret="my-super-secret",
    )
    auth = AquaAuthManager(config)
    auth._cached_token = AquaToken(token="active_jwt", expires_at=time.time() + 36000)

    auth.invalidate_token()
    assert auth._cached_token is None

    route = respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "new_jwt_after_invalidation"},
    )

    async with httpx.AsyncClient() as client:
        token = await auth.get_valid_token(client)

    assert token == "new_jwt_after_invalidation"
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_acquire_token_error_handling() -> None:
    config = AquaConfig(
        api_key="my-api-key",
        api_secret="my-super-secret",
    )
    auth = AquaAuthManager(config)

    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=403,
        json={"message": "Invalid credentials or signature"},
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(AquaAuthError, match="Failed to acquire Aqua token: 403"):
            await auth.get_valid_token(client)
