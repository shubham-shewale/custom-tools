"""Pytest fixtures and test support utilities for Aqua Security MCP server tests."""

from __future__ import annotations

from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent

from aquasec_mcp.config import AquaConfig


def extract_tool_text(result: Any) -> str:
    """Safely extract string text content from an MCP CallToolResult."""
    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    first_block = result.content[0]
    assert isinstance(first_block, TextContent)
    return str(first_block.text)


@pytest.fixture
def base_config() -> AquaConfig:
    """Default test configuration with dummy credentials."""
    return AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
