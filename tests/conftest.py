"""Pytest fixtures and test support utilities for Aqua Security MCP server tests."""

from __future__ import annotations

import json
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


def extract_token_from_diff(text: str) -> str:
    """Extract the UUID confirmation token from impact diff output."""
    for line in text.splitlines():
        if "- **Confirmation Token**:" in line:
            return line.split("`")[1].strip()
    start = text.find("```json\n")
    if start != -1:
        end = text.find("\n```", start + 8)
        if end != -1:
            json_str = text[start + 8 : end]
            data = json.loads(json_str)
            if isinstance(data, dict) and "confirmation_token" in data:
                return str(data["confirmation_token"])
    raise ValueError(f"Could not extract confirmation token from:\n{text}")


@pytest.fixture
def base_config() -> AquaConfig:
    """Default test configuration with dummy credentials."""
    return AquaConfig(
        api_key="test-api-key",
        api_secret="test-api-secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
