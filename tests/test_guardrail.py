import time
import uuid

import pytest
import respx

from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig
from aquasec_mcp.guardrail import (
    GuardrailEngine,
    ReadOnlyError,
    StagedAction,
    StagedActionStore,
    format_impact_diff,
)


def test_staged_action_creation_and_expiration() -> None:
    action = StagedAction(
        confirmation_token=str(uuid.uuid4()),
        action_type="create_suppression",
        target_resource="suppression:rule-1",
        description="Create suppression rule for rule-1",
        http_method="POST",
        path="/v2/build/rules/suppressions",
        field_changes={"rule_name": "rule-1", "reason": "False positive"},
        created_at=time.time(),
        expires_at=time.time() + 300.0,
    )
    assert not action.is_expired()
    assert action.time_remaining_seconds() > 250.0

    expired_action = StagedAction(
        confirmation_token=str(uuid.uuid4()),
        action_type="delete_suppression",
        target_resource="suppression:rule-2",
        description="Delete suppression rule for rule-2",
        http_method="DELETE",
        path="/v2/build/rules/suppressions/rule-2",
        field_changes={"deleted": True},
        created_at=time.time() - 400.0,
        expires_at=time.time() - 100.0,
    )
    assert expired_action.is_expired()
    assert expired_action.time_remaining_seconds() == 0.0


def test_staged_action_store_crud_and_ttl() -> None:
    store = StagedActionStore(default_ttl_seconds=300.0)

    # 1. Stage an action
    staged = store.stage_action(
        action_type="update_user",
        target_resource="user:alice@example.com",
        description="Update roles for alice@example.com",
        http_method="PUT",
        path="/cspm/v2/users/123",
        field_changes={"csp_roles": ["Administrator"]},
        payload={"csp_roles": ["Administrator"]},
    )
    assert staged.confirmation_token is not None
    assert uuid.UUID(staged.confirmation_token)
    assert staged.action_type == "update_user"

    # 2. Get action by token
    retrieved = store.get_action(staged.confirmation_token)
    assert retrieved is not None
    assert retrieved.target_resource == "user:alice@example.com"

    # 3. List active actions
    active = store.list_active_actions()
    assert len(active) == 1
    assert active[0].confirmation_token == staged.confirmation_token

    # 4. Delete action
    assert store.delete_action(staged.confirmation_token) is True
    assert store.get_action(staged.confirmation_token) is None
    assert store.delete_action(staged.confirmation_token) is False
    assert len(store.list_active_actions()) == 0


def test_staged_action_store_expiration_cleanup() -> None:
    store = StagedActionStore(default_ttl_seconds=1.0)
    # Stage with short TTL
    staged = store.stage_action(
        action_type="create_user",
        target_resource="user:bob@example.com",
        description="Create user bob@example.com",
        http_method="POST",
        path="/cspm/v2/users",
        field_changes={"email": "bob@example.com"},
        ttl_seconds=0.01,
    )
    time.sleep(0.05)

    # Should be purged upon access
    assert store.get_action(staged.confirmation_token) is None
    assert len(store.list_active_actions()) == 0


def test_format_impact_diff_output() -> None:
    token = str(uuid.uuid4())
    action = StagedAction(
        confirmation_token=token,
        action_type="create_suppression",
        target_resource="suppression:rule-99",
        description="Create supply chain suppression rule for CVE-2023-1234",
        http_method="POST",
        path="/v2/build/rules/suppressions",
        field_changes={
            "rule_name": "rule-99",
            "check": "CVE-2023-1234",
            "scope": "repository",
            "reason": "False Positive",
        },
        payload={"name": "rule-99", "check": "CVE-2023-1234"},
        created_at=time.time(),
        expires_at=time.time() + 300.0,
    )
    preview = format_impact_diff(action)
    assert "⚠️ ACTION PENDING CONFIRMATION" in preview
    assert token in preview
    assert "create_suppression" in preview
    assert "suppression:rule-99" in preview
    assert "POST" in preview
    assert "/v2/build/rules/suppressions" in preview
    assert "CVE-2023-1234" in preview
    assert "execute_confirmed_action" in preview
    assert "cancel_staged_action" in preview
    assert "```json" in preview


@pytest.mark.asyncio
@respx.mock
async def test_guardrail_engine_stage_and_execute_confirmed_action() -> None:
    config = AquaConfig(
        api_key="key",
        api_secret="secret",
        base_url="https://eu-central-1.edge.cloud.aquasec.com",
        token_url="https://eu-1.api.cloudsploit.com/v2/tokens",
    )
    respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"data": "mock_jwt"},
    )
    respx.post("https://eu-central-1.edge.cloud.aquasec.com/v2/build/rules/suppressions").respond(
        status_code=201,
        json={"status": "created", "id": "supp_123"},
    )

    client = AquaClient(config=config)
    engine = GuardrailEngine(config=config, client=client)

    # 1. Stage mutation
    preview = engine.stage_mutation(
        action_type="create_suppression",
        target_resource="suppression:new-rule",
        description="Create new suppression rule",
        http_method="POST",
        path="/v2/build/rules/suppressions",
        field_changes={"name": "new-rule"},
        payload={"name": "new-rule"},
    )
    assert "⚠️ ACTION PENDING CONFIRMATION" in preview
    actions = engine.store.list_active_actions()
    assert len(actions) == 1
    token = actions[0].confirmation_token

    # 2. Execute confirmed action
    result = await engine.execute_confirmed_action(token)
    assert "✅ Action Executed Successfully" in result
    assert "201" in result
    assert "supp_123" in result

    # 3. Token should now be consumed / deleted
    assert engine.store.get_action(token) is None
    replay_result = await engine.execute_confirmed_action(token)
    assert "❌ Invalid or Expired Confirmation Token" in replay_result


@pytest.mark.asyncio
async def test_guardrail_engine_read_only_rejection() -> None:
    config = AquaConfig(
        api_key="key",
        api_secret="secret",
        read_only=True,
    )
    client = AquaClient(config=config)
    engine = GuardrailEngine(config=config, client=client)

    with pytest.raises(ReadOnlyError, match="AQUA_READ_ONLY is enabled"):
        engine.stage_mutation(
            action_type="delete_suppression",
            target_resource="suppression:123",
            description="Delete suppression",
            http_method="DELETE",
            path="/v2/build/rules/suppressions/123",
            field_changes={"deleted": True},
        )

    # Calling execute with read_only enabled should also fail safely
    result = await engine.execute_confirmed_action("some-token")
    assert "⛔ READ-ONLY MODE" in result


@pytest.mark.asyncio
async def test_guardrail_engine_cancel_and_list_actions() -> None:
    config = AquaConfig(api_key="key", api_secret="secret")
    client = AquaClient(config=config)
    engine = GuardrailEngine(config=config, client=client)

    # Empty list
    empty_list = engine.list_staged_actions()
    assert "No staged actions pending confirmation" in empty_list

    # Stage two actions
    engine.stage_mutation(
        action_type="create_user",
        target_resource="user:alice@example.com",
        description="Add alice",
        http_method="POST",
        path="/cspm/v2/users",
        field_changes={"email": "alice@example.com"},
    )
    engine.stage_mutation(
        action_type="create_user",
        target_resource="user:bob@example.com",
        description="Add bob",
        http_method="POST",
        path="/cspm/v2/users",
        field_changes={"email": "bob@example.com"},
    )
    active = engine.store.list_active_actions()
    assert len(active) == 2
    token_alice = active[0].confirmation_token
    token_bob = active[1].confirmation_token

    listed = engine.list_staged_actions()
    assert token_alice in listed
    assert token_bob in listed
    assert "user:alice@example.com" in listed
    assert "user:bob@example.com" in listed

    # Cancel one action
    cancel_result = engine.cancel_staged_action(token_alice)
    assert "🗑️ Staged Action Cancelled" in cancel_result
    assert token_alice in cancel_result

    # Cancelling again should report not found
    cancel_again = engine.cancel_staged_action(token_alice)
    assert "⚠️ Action Not Found or Already Expired" in cancel_again

    # Remaining list
    remaining = engine.list_staged_actions()
    assert token_alice not in remaining
    assert token_bob in remaining
