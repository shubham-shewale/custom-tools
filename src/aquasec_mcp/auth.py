"""Authentication and token lifecycle management for Aqua Security EU Cloud."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from aquasec_mcp.config import AquaConfig


class AquaAuthError(Exception):
    """Raised when Aqua authentication or token retrieval fails."""


@dataclass
class AquaToken:
    """Represents a cached Aqua JWT token and its expiration timestamp."""

    token: str
    expires_at: float

    def is_expired(self, buffer_seconds: float = 300.0) -> bool:
        """Return True if the token is expired or will expire within buffer_seconds."""
        return time.time() + buffer_seconds >= self.expires_at


def _decode_jwt_exp(token: str) -> float | None:
    """Attempt to extract the 'exp' claim from a JWT payload without signature verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Add necessary padding for base64 decoding
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload: dict[str, Any] = json.loads(payload_bytes)
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, KeyError, IndexError):
        return None


class AquaAuthManager:
    """Manages Aqua HMAC-SHA256 request signing and in-memory JWT token caching."""

    def __init__(self, config: AquaConfig, token_validity_minutes: int = 720) -> None:
        self.config = config
        self.token_validity_minutes = token_validity_minutes
        self._cached_token: AquaToken | None = None

    def generate_signature(self, timestamp: int, method: str, path: str, body: str) -> str:
        """Compute HMAC-SHA256 hex signature over Timestamp + Method + Path + JSONBody."""
        if not self.config.api_secret:
            raise AquaAuthError("Cannot generate signature: AQUA_API_SECRET is not configured")

        string_to_sign = f"{timestamp}{method}{path}{body}"
        signature = hmac.new(
            self.config.api_secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return signature

    def build_auth_headers(
        self, timestamp: int, method: str, path: str, body: str
    ) -> dict[str, str]:
        """Construct standard Aqua HTTP headers with API key, timestamp, and HMAC signature."""
        if not self.config.api_key:
            raise AquaAuthError("Cannot build auth headers: AQUA_API_KEY is not configured")

        signature = self.generate_signature(
            timestamp=timestamp, method=method, path=path, body=body
        )
        return {
            "Content-Type": "application/json",
            "X-API-Key": self.config.api_key,
            "X-Timestamp": str(timestamp),
            "X-Signature": signature,
        }

    async def acquire_token(self, http_client: httpx.AsyncClient) -> str:
        """Perform signed request to Aqua token endpoint and cache the resulting JWT."""
        self.config.validate_credentials()

        parsed_url = urlparse(self.config.token_url)
        path = parsed_url.path or "/v2/tokens"
        method = "POST"
        timestamp = int(time.time())

        payload = {
            "validity": self.token_validity_minutes,
            "allowed_endpoints": ["ANY:*"],
        }
        # Compact JSON encoding without extra whitespace
        body_str = json.dumps(payload, separators=(",", ":"))
        headers = self.build_auth_headers(
            timestamp=timestamp,
            method=method,
            path=path,
            body=body_str,
        )

        try:
            response = await http_client.post(
                self.config.token_url,
                headers=headers,
                content=body_str,
                timeout=self.config.request_timeout,
            )
        except Exception as exc:
            raise AquaAuthError(f"Network error while acquiring Aqua token: {exc}") from exc

        if response.status_code != 200:
            raise AquaAuthError(
                f"Failed to acquire Aqua token: {response.status_code} - {response.text}"
            )

        data = response.json()
        raw_token: Any = data.get("data") if isinstance(data, dict) else None
        if not raw_token:
            if isinstance(data, dict) and "token" in data:
                raw_token = data["token"]
            elif isinstance(data, str):
                raw_token = data
            else:
                raise AquaAuthError(f"Unexpected token response structure: {data}")

        token_str = str(raw_token)
        jwt_exp = _decode_jwt_exp(token_str)
        if jwt_exp is not None:
            expires_at = jwt_exp
        else:
            expires_at = time.time() + (self.token_validity_minutes * 60)

        self._cached_token = AquaToken(token=token_str, expires_at=expires_at)
        return token_str

    async def get_valid_token(
        self, http_client: httpx.AsyncClient, force_refresh: bool = False
    ) -> str:
        """Return a valid cached JWT token or acquire a new one proactively."""
        if (
            force_refresh
            or self._cached_token is None
            or self._cached_token.is_expired(buffer_seconds=300.0)
        ):
            return await self.acquire_token(http_client)
        return self._cached_token.token

    def invalidate_token(self) -> None:
        """Clear cached token, forcing re-authentication on the next request."""
        self._cached_token = None
