"""Two-Phase Staged Confirmation Guardrail Engine for Aqua Security MCP Server."""

from __future__ import annotations

import datetime
import json
import time
import uuid
from typing import Any

from pydantic import BaseModel, Field

from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig


class ReadOnlyError(Exception):
    """Raised when a state-modifying action is attempted while AQUA_READ_ONLY is enabled."""


class StagedAction(BaseModel):
    """Represents an intercepted, pending state-modifying action awaiting user confirmation."""

    confirmation_token: str = Field(description="Unique UUID confirmation token for this staged action")
    action_type: str = Field(description="Semantic action name, e.g. create_suppression, update_user")
    target_resource: str = Field(description="Resource identifier, e.g. suppression:123 or user:admin@example.com")
    description: str = Field(description="Human-readable summary of the intended operation")
    http_method: str = Field(description="Target HTTP verb (POST, PUT, PATCH, DELETE)")
    path: str = Field(description="API endpoint path or URL")
    field_changes: dict[str, Any] = Field(default_factory=dict, description="Key-value mapping of proposed changes")
    payload: Any | None = Field(default=None, description="Optional JSON request body payload")
    params: dict[str, Any] | None = Field(default=None, description="Optional query parameters")
    headers: dict[str, str] | None = Field(default=None, description="Optional extra request headers")
    created_at: float = Field(default_factory=time.time, description="Unix timestamp of creation")
    expires_at: float = Field(description="Unix timestamp of token expiration")

    def is_expired(self) -> bool:
        """Return True if the current time exceeds the expiration timestamp."""
        return time.time() >= self.expires_at

    def time_remaining_seconds(self) -> float:
        """Return the number of seconds remaining until expiration, bounded below by 0."""
        return max(0.0, self.expires_at - time.time())


def format_impact_diff(action: StagedAction) -> str:
    """Format a StagedAction into a clear, human-readable impact diff preview with instructions."""
    exp_dt = datetime.datetime.fromtimestamp(action.expires_at, tz=datetime.timezone.utc)
    exp_str = exp_dt.isoformat()
    remaining = int(action.time_remaining_seconds())
    remaining_mins = remaining // 60
    remaining_secs = remaining % 60

    structured_data = {
        "status": "pending_confirmation",
        "confirmation_token": action.confirmation_token,
        "action_type": action.action_type,
        "target_resource": action.target_resource,
        "description": action.description,
        "http_request": f"{action.http_method} {action.path}",
        "field_changes": action.field_changes,
        "expires_at_utc": exp_str,
        "time_remaining": f"{remaining_mins}m {remaining_secs}s",
    }

    changes_formatted = json.dumps(action.field_changes, indent=2)

    return (
        f"# ⚠️ ACTION PENDING CONFIRMATION\n\n"
        f"> **Safety Notice**: This mutating operation is staged in memory and requires explicit confirmation. "
        f"No changes have been sent to Aqua Security EU Cloud.\n\n"
        f"### Action Details\n"
        f"- **Confirmation Token**: `{action.confirmation_token}`\n"
        f"- **Action Type**: `{action.action_type}`\n"
        f"- **Target Resource**: `{action.target_resource}`\n"
        f"- **HTTP Request**: `{action.http_method} {action.path}`\n"
        f"- **Description**: {action.description}\n"
        f"- **Expires At (UTC)**: `{exp_str}` (~{remaining_mins}m {remaining_secs}s remaining)\n\n"
        f"### Proposed Changes (Impact Diff)\n"
        f"```json\n{changes_formatted}\n```\n\n"
        f"### Next Steps\n"
        f"- **To Confirm & Execute**:\n"
        f"  `execute_confirmed_action(confirmation_token=\"{action.confirmation_token}\")`\n"
        f"- **To Discard / Cancel**:\n"
        f"  `cancel_staged_action(confirmation_token=\"{action.confirmation_token}\")`\n\n"
        f"```json\n{json.dumps(structured_data, indent=2)}\n```"
    )


class StagedActionStore:
    """In-memory store for pending staged actions with 5-minute TTL expiration and automatic cleanup."""

    def __init__(self, default_ttl_seconds: float = 300.0) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self._store: dict[str, StagedAction] = {}

    def cleanup_expired(self) -> int:
        """Purge all expired actions from the store and return the number of purged actions."""
        expired_keys = [token for token, action in self._store.items() if action.is_expired()]
        for token in expired_keys:
            del self._store[token]
        return len(expired_keys)

    def stage_action(
        self,
        action_type: str,
        target_resource: str,
        description: str,
        http_method: str,
        path: str,
        field_changes: dict[str, Any],
        payload: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ttl_seconds: float | None = None,
    ) -> StagedAction:
        """Create and store a new StagedAction with a unique confirmation token."""
        self.cleanup_expired()
        token = str(uuid.uuid4())
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        now = time.time()
        expires_at = now + ttl

        action = StagedAction(
            confirmation_token=token,
            action_type=action_type,
            target_resource=target_resource,
            description=description,
            http_method=http_method.upper(),
            path=path,
            field_changes=field_changes,
            payload=payload,
            params=params,
            headers=headers,
            created_at=now,
            expires_at=expires_at,
        )
        self._store[token] = action
        return action

    def get_action(self, confirmation_token: str) -> StagedAction | None:
        """Retrieve a staged action if it exists and has not expired; cleans up if expired."""
        action = self._store.get(confirmation_token)
        if action is None:
            return None
        if action.is_expired():
            del self._store[confirmation_token]
            return None
        return action

    def delete_action(self, confirmation_token: str) -> bool:
        """Delete an action by confirmation token. Return True if it was present, False otherwise."""
        if confirmation_token in self._store:
            del self._store[confirmation_token]
            return True
        return False

    def list_active_actions(self) -> list[StagedAction]:
        """Return all active (non-expired) staged actions, sorted by creation time."""
        self.cleanup_expired()
        return sorted(self._store.values(), key=lambda a: a.created_at)

    def clear(self) -> None:
        """Remove all actions from the store."""
        self._store.clear()


class GuardrailEngine:
    """Coordinates mutation interception, staged diff formatting, and confirmed execution."""

    def __init__(
        self,
        config: AquaConfig | None = None,
        client: AquaClient | None = None,
        store: StagedActionStore | None = None,
    ) -> None:
        self.config = config or AquaConfig.from_env()
        self.client = client or AquaClient(config=self.config)
        self.store = store or StagedActionStore()

    def stage_mutation(
        self,
        action_type: str,
        target_resource: str,
        description: str,
        http_method: str,
        path: str,
        field_changes: dict[str, Any],
        payload: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ttl_seconds: float | None = None,
    ) -> str:
        """Validate read-only mode, stage the mutation, and return the impact diff preview."""
        if self.config.read_only:
            raise ReadOnlyError(
                "Cannot stage action: AQUA_READ_ONLY is enabled. "
                "All state-modifying operations are unconditionally blocked."
            )

        staged_action = self.store.stage_action(
            action_type=action_type,
            target_resource=target_resource,
            description=description,
            http_method=http_method,
            path=path,
            field_changes=field_changes,
            payload=payload,
            params=params,
            headers=headers,
            ttl_seconds=ttl_seconds,
        )
        return format_impact_diff(staged_action)

    async def execute_confirmed_action(self, confirmation_token: str) -> str:
        """Validate token, execute the staged HTTP request via AquaClient, purge token, and return response."""
        if self.config.read_only:
            return (
                "# ⛔ READ-ONLY MODE: Execution Blocked\n\n"
                "The server is running with `AQUA_READ_ONLY=true`. "
                "No state-modifying actions can be executed."
            )

        token_clean = confirmation_token.strip()
        action = self.store.get_action(token_clean)
        if action is None:
            return (
                "# ❌ Invalid or Expired Confirmation Token\n\n"
                f"Confirmation token `{token_clean}` was not found in the staged actions store "
                "or has expired (5-minute TTL).\n\n"
                "Use `list_staged_actions()` to view active pending confirmations."
            )

        try:
            response = await self.client.request(
                method=action.http_method,
                path_or_url=action.path,
                params=action.params,
                json=action.payload,
                headers=action.headers,
            )
        except Exception as exc:  # noqa: BLE001
            return (
                f"# ❌ Action Execution Failed (Network / Client Error)\n\n"
                f"- **Action Type**: `{action.action_type}`\n"
                f"- **Target Resource**: `{action.target_resource}`\n"
                f"- **Error**: {exc}\n"
            )
        finally:
            # Always delete token to prevent replay attacks regardless of HTTP status
            self.store.delete_action(token_clean)

        try:
            resp_data = response.json()
            resp_body_formatted = json.dumps(resp_data, indent=2)
        except (json.JSONDecodeError, ValueError):
            resp_body_formatted = response.text

        status_header = (
            "# ✅ Action Executed Successfully"
            if response.is_success
            else "# ❌ Action Execution Failed (API Error)"
        )
        body_label = "Response Data" if response.is_success else "Response Error"

        return (
            f"{status_header}\n\n"
            f"- **Action Type**: `{action.action_type}`\n"
            f"- **Target Resource**: `{action.target_resource}`\n"
            f"- **HTTP Request**: `{action.http_method} {action.path}`\n"
            f"- **HTTP Status**: `{response.status_code}`\n\n"
            f"### {body_label}\n"
            f"```json\n{resp_body_formatted}\n```"
        )

    def cancel_staged_action(self, confirmation_token: str) -> str:
        """Cancel a pending staged action and purge it from memory."""
        token_clean = confirmation_token.strip()
        action = self.store.get_action(token_clean)
        if action is None:
            return (
                f"# ⚠️ Action Not Found or Already Expired\n\n"
                f"Confirmation token `{token_clean}` was not found in the active staged action queue."
            )

        self.store.delete_action(token_clean)
        return (
            f"# 🗑️ Staged Action Cancelled\n\n"
            f"- **Confirmation Token**: `{token_clean}`\n"
            f"- **Action Type**: `{action.action_type}`\n"
            f"- **Target Resource**: `{action.target_resource}`\n"
            f"- **Description**: {action.description}\n"
            f"- **Status**: Cancelled & purged from memory. No changes were sent to Aqua Security."
        )

    def list_staged_actions(self) -> str:
        """List all currently active staged actions pending operator confirmation."""
        actions = self.store.list_active_actions()
        if not actions:
            return (
                "# 📋 Active Staged Actions\n\n"
                "No staged actions pending confirmation."
            )

        lines = [
            "# 📋 Active Staged Actions Pending Confirmation\n",
            f"Total pending actions: **{len(actions)}**\n",
        ]
        for idx, act in enumerate(actions, 1):
            exp_dt = datetime.datetime.fromtimestamp(act.expires_at, tz=datetime.timezone.utc)
            rem = int(act.time_remaining_seconds())
            lines.append(
                f"### {idx}. `{act.action_type}` on `{act.target_resource}`\n"
                f"- **Token**: `{act.confirmation_token}`\n"
                f"- **Request**: `{act.http_method} {act.path}`\n"
                f"- **Expires At (UTC)**: `{exp_dt.isoformat()}` (~{rem // 60}m {rem % 60}s remaining)\n"
                f"- **Description**: {act.description}\n"
                f"- **Changes**: `{json.dumps(act.field_changes)}`\n"
            )

        lines.append(
            "\n### Management Instructions\n"
            "- To confirm an action: `execute_confirmed_action(confirmation_token=\"<token>\")`\n"
            "- To cancel an action: `cancel_staged_action(confirmation_token=\"<token>\")`\n"
        )
        return "\n".join(lines)
