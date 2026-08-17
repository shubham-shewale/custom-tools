"""Asynchronous HTTP client for Aqua Security APIs with Bearer token injection and reactive 401 retry."""

from __future__ import annotations

import types
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin

import httpx
from typing_extensions import Self

from aquasec_mcp.auth import AquaAuthManager
from aquasec_mcp.config import AquaConfig


class AquaClient:
    """High-level asynchronous client for interacting with Aqua Security EU APIs."""

    def __init__(
        self,
        config: AquaConfig | None = None,
        auth_manager: AquaAuthManager | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config or AquaConfig.from_env()
        self.auth_manager = auth_manager or AquaAuthManager(self.config)
        self._http_client = http_client
        self._owns_http_client = http_client is None

    async def __aenter__(self) -> Self:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.config.request_timeout)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        """Close underlying HTTP client if created internally."""
        if self._owns_http_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def _ensure_client(self) -> httpx.AsyncClient:
        """Return the active HTTP client or create a new one."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.config.request_timeout)
        return self._http_client

    def _build_url(self, path_or_url: str) -> str:
        """Resolve a full endpoint URL from a relative path or absolute URL."""
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        base = self.config.base_url.rstrip("/") + "/"
        path = path_or_url.lstrip("/")
        return str(urljoin(base, path))

    async def request(
        self,
        method: str,
        path_or_url: str,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an authenticated HTTP request to Aqua APIs with reactive 401 retry."""
        client = self._ensure_client()
        url = self._build_url(path_or_url)
        req_headers = dict(headers or {})

        # 1. Acquire current valid token (proactively refreshed if expiring soon)
        token = await self.auth_manager.get_valid_token(client)
        req_headers["Authorization"] = f"Bearer {token}"

        response = await client.request(
            method=method,
            url=url,
            headers=req_headers,
            **kwargs,
        )

        # 2. Reactive 401 recovery: invalidate token and retry once with a fresh token
        if response.status_code == 401:
            self.auth_manager.invalidate_token()
            new_token = await self.auth_manager.get_valid_token(client, force_refresh=True)
            req_headers["Authorization"] = f"Bearer {new_token}"
            response = await client.request(
                method=method,
                url=url,
                headers=req_headers,
                **kwargs,
            )

        return response

    async def get(
        self,
        path_or_url: str,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an authenticated GET request."""
        return await self.request("GET", path_or_url, headers=headers, params=params, **kwargs)

    async def post(
        self,
        path_or_url: str,
        json: Any | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an authenticated POST request."""
        return await self.request("POST", path_or_url, headers=headers, json=json, **kwargs)

    async def put(
        self,
        path_or_url: str,
        json: Any | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an authenticated PUT request."""
        return await self.request("PUT", path_or_url, headers=headers, json=json, **kwargs)

    async def patch(
        self,
        path_or_url: str,
        json: Any | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an authenticated PATCH request."""
        return await self.request("PATCH", path_or_url, headers=headers, json=json, **kwargs)

    async def delete(
        self,
        path_or_url: str,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an authenticated DELETE request."""
        return await self.request("DELETE", path_or_url, headers=headers, **kwargs)

    async def check_connection(self) -> dict[str, Any]:
        """Verify credentials and connectivity by acquiring/validating a token."""
        client = self._ensure_client()
        token = await self.auth_manager.get_valid_token(client)

        return {
            "status": "connected",
            "region": "EU (eu-central-1)",
            "base_url": self.config.base_url,
            "token_url": self.config.token_url,
            "authenticated": bool(token),
            "token_validity_minutes": self.auth_manager.token_validity_minutes,
            "token_expires_at": self.auth_manager.token_expires_at,
        }
