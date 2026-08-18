"""Configuration loader for Aqua Security MCP Server."""

from __future__ import annotations

import os

from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel, Field


class AquaConfig(BaseModel):
    """Configuration settings for Aqua Security API and MCP Server."""

    api_key: str | None = Field(default=None, description="Aqua API Key")
    api_secret: str | None = Field(default=None, description="Aqua API Secret")
    base_url: str = Field(
        default="https://eu-central-1.edge.cloud.aquasec.com",
        description="Aqua CSPM/Supply Chain base API endpoint (defaults to EU region)",
    )
    token_url: str = Field(
        default="https://eu-1.api.cloudsploit.com/v2/tokens",
        description="Aqua CloudSploit Token authentication endpoint (defaults to EU region)",
    )
    read_only: bool = Field(
        default=False,
        description="Global read-only guardrail flag blocking all mutating operations",
    )
    request_timeout: float = Field(
        default=30.0,
        description="HTTP client timeout in seconds",
    )

    @classmethod
    def from_env(cls, env_file: str | None = None) -> AquaConfig:
        """Instantiate configuration from environment variables and .env file."""
        if env_file:
            load_dotenv(dotenv_path=env_file, override=True)
        else:
            dotenv_path = find_dotenv(usecwd=True)
            if dotenv_path:
                load_dotenv(dotenv_path=dotenv_path)
            else:
                load_dotenv()
        read_only_raw = os.getenv("AQUA_READ_ONLY", "false").strip().lower()
        read_only = read_only_raw in ("true", "1", "yes", "on")

        timeout_raw = os.getenv("AQUA_REQUEST_TIMEOUT")
        request_timeout = float(timeout_raw) if timeout_raw else 30.0

        return cls(
            api_key=os.getenv("AQUA_API_KEY"),
            api_secret=os.getenv("AQUA_API_SECRET"),
            base_url=os.getenv("AQUA_BASE_URL", "https://eu-central-1.edge.cloud.aquasec.com"),
            token_url=os.getenv("AQUA_TOKEN_URL", "https://eu-1.api.cloudsploit.com/v2/tokens"),
            read_only=read_only,
            request_timeout=request_timeout,
        )

    def validate_credentials(self) -> None:
        """Ensure both API key and Secret are provided when attempting auth."""
        if not self.api_key or not self.api_secret:
            raise ValueError("AQUA_API_KEY and AQUA_API_SECRET must be set")
