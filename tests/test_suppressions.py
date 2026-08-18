"""High-seam integration tests for Aqua Security Supply Chain Suppression tools."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from aquasec_mcp.client import AquaClient
from aquasec_mcp.config import AquaConfig
from aquasec_mcp.guardrail import GuardrailEngine
from aquasec_mcp.server import create_mcp_server
from tests.conftest import extract_token_from_diff as _extract_token_from_diff
from tests.conftest import extract_tool_text


@pytest.fixture
def mock_auth() -> respx.Route:
    return respx.post("https://eu-1.api.cloudsploit.com/v2/tokens").respond(
        status_code=200,
        json={"status": 200, "data": "mock_valid_jwt_token"},
    )


# ---------------------------------------------------------------------------
# 1. list_suppressions tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_suppressions_success(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    suppressions_route = respx.get("https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions").respond(
        status_code=200,
        json={
            "current_page": 1,
            "next_page": 2,
            "returned_count": 2,
            "total_count": 5,
            "data": [
                {
                    "policy_id": "rule-uuid-1",
                    "name": "Silence CVE-2023-1234 in backend",
                    "description": "Dev dependency only",
                    "enable": True,
                    "created_by": "sec-team@example.com",
                    "controls": [{"type": "cveByIds", "scan_type": "vulnerability"}],
                },
                {
                    "policy_id": "rule-uuid-2",
                    "name": "Silence test cert finding in staging",
                    "description": "Temporary staging exemption",
                    "enable": False,
                    "created_by": "qa-lead@example.com",
                    "controls": [{"type": "misconfigurations", "scan_type": "manifest"}],
                },
            ],
        },
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool(
        "list_suppressions",
        {
            "search": "CVE-2023",
            "repository": "my-org/backend-repo",
            "check": "CVE-2023-1234",
            "branch": "main",
            "scope": "repository",
            "status": "enabled",
            "page": 1,
            "page_size": 10,
            "order_by": "-created",
        },
    )
    text = extract_tool_text(result)

    assert "🛡️ Supply Chain Suppression Rules" in text
    assert "Total Rules**: 5" in text
    assert "Silence CVE-2023-1234 in backend" in text
    assert "rule-uuid-1" in text
    assert "✅ Enabled" in text
    assert "Silence test cert finding in staging" in text
    assert "⏸️ Disabled" in text

    # Verify query params were passed accurately to Aqua API
    assert suppressions_route.call_count == 1
    req = suppressions_route.calls[0].request
    assert req.url.params["search"] == "CVE-2023"
    assert req.url.params["repository"] == "my-org/backend-repo"
    assert req.url.params["check"] == "CVE-2023-1234"
    assert req.url.params["branch"] == "main"
    assert req.url.params["scope"] == "repository"
    assert req.url.params["status"] == "enabled"
    assert req.url.params["page"] == "1"
    assert req.url.params["page_size"] == "10"
    assert req.url.params["order_by"] == "-created"


@pytest.mark.asyncio
@respx.mock
async def test_list_suppressions_empty_results(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions").respond(
        status_code=200,
        json={"current_page": 1, "next_page": 0, "returned_count": 0, "total_count": 0, "data": []},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_suppressions", {})
    text = extract_tool_text(result)
    assert "Total Rules**: 0" in text
    assert "Returned on Page**: 0" in text


@pytest.mark.asyncio
@respx.mock
async def test_list_suppressions_api_error(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    respx.get("https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions").respond(
        status_code=500,
        json={"error": "Internal server error querying database"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("list_suppressions", {})
    text = extract_tool_text(result)
    assert "Failed to List Suppression Rules (HTTP 500)" in text
    assert "Internal server error" in text


# ---------------------------------------------------------------------------
# 2. get_suppression tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_get_suppression_success(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    rule_id = "8f3e2a9b-1234-4a5b-9c8d-123456789abc"
    respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=200,
        json={
            "policy_id": rule_id,
            "name": "Suppress AWS Hardcoded Secret Finding in Tests",
            "description": "Dummy mock key in unit test fixtures",
            "enable": True,
            "policy_type": "suppression",
            "created": "2026-01-15T10:00:00Z",
            "updated": "2026-02-01T12:00:00Z",
            "created_by": "alice@example.com",
            "updated_by": "bob@example.com",
            "controls": [
                {
                    "type": "misconfigurations",
                    "scan_type": "manifest",
                    "checks": [{"id": "AVD-AWS-0001"}],
                }
            ],
            "scope": {
                "expression": "v1",
                "variables": [{"attribute": "repository.name", "value": "security-tests"}],
            },
        },
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_suppression", {"suppression_id": rule_id})
    text = extract_tool_text(result)

    assert "Suppress AWS Hardcoded Secret Finding in Tests" in text
    assert rule_id in text
    assert "✅ Enabled" in text
    assert "Dummy mock key in unit test fixtures" in text
    assert "alice@example.com" in text
    assert "Controls Count**: 1" in text
    assert "Scope Expression**: `v1`" in text
    assert "AVD-AWS-0001" in text


@pytest.mark.asyncio
@respx.mock
async def test_get_suppression_not_found(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    rule_id = "missing-rule-id"
    respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=404,
        json={"message": "Suppression rule not found"},
    )

    client = AquaClient(config=base_config)
    server = create_mcp_server(config=base_config, client=client)

    result = await server.call_tool("get_suppression", {"suppression_id": rule_id})
    text = extract_tool_text(result)
    assert "Suppression Rule Not Found or Error (HTTP 404)" in text
    assert rule_id in text


# ---------------------------------------------------------------------------
# 3. create_suppression staged confirmation tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_create_suppression_staged_flow_and_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    create_route = respx.post("https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions").respond(
        status_code=201,
        json={
            "policy_id": "new-rule-uuid-999",
            "name": "Silence CVE-2024-0001",
            "status": "created",
        },
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    # 1. Call create_suppression with comment and reason
    create_res = await server.call_tool(
        "create_suppression",
        {
            "name": "Silence CVE-2024-0001",
            "reason": "False positive in internal test tool",
            "comment": "Audited by Security Team",
            "check": "CVE-2024-0001",
            "repository": "infra/deployer",
            "branch": "main",
        },
    )
    diff_text = extract_tool_text(create_res)

    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    assert "create_suppression" in diff_text
    assert "suppression:Silence CVE-2024-0001" in diff_text
    assert "Silence CVE-2024-0001" in diff_text
    assert "infra/deployer" in diff_text
    assert "Audited by Security Team" in diff_text
    assert create_route.call_count == 0  # CRITICAL: Aqua endpoint has not been called!

    token = _extract_token_from_diff(diff_text)
    assert len(token) > 0

    # 2. Confirm and execute
    exec_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": token})
    exec_text = extract_tool_text(exec_res)

    assert "✅ Action Executed Successfully" in exec_text
    assert "new-rule-uuid-999" in exec_text
    assert create_route.call_count == 1

    # Verify payload received by mock Aqua endpoint
    req_body = json.loads(create_route.calls[0].request.content)
    assert req_body["name"] == "Silence CVE-2024-0001"
    assert req_body["enable"] is True
    assert req_body["controls"][0]["scan_type"] == "vulnerability"
    assert req_body["controls"][0]["cve_ids"] == ["CVE-2024-0001"]
    assert req_body["scope"]["variables"][0]["value"] == "infra/deployer"
    assert req_body["scope"]["variables"][1]["value"] == "main"

    # 3. Token must be purged after execution (no replay attacks)
    replay_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": token})
    assert "❌ Invalid or Expired Confirmation Token" in extract_tool_text(replay_res)


# ---------------------------------------------------------------------------
# 4. update_suppression staged confirmation tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_update_suppression_staged_flow_and_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    rule_id = "target-update-uuid-456"
    existing_rule = {
        "policy_id": rule_id,
        "name": "Original Suppression Rule Name",
        "description": "Original suppression description",
        "enable": True,
        "policy_type": "suppression",
        "created": "2026-01-15T10:00:00Z",
        "updated": "2026-02-01T12:00:00Z",
        "created_by": "alice@example.com",
        "updated_by": "bob@example.com",
        "controls": [
            {
                "type": "misconfigurations",
                "scan_type": "manifest",
                "checks": [{"id": "AVD-AWS-0001"}],
            }
        ],
        "scope": {
            "expression": "v1",
            "variables": [{"attribute": "repository.name", "value": "old-repo"}],
        },
    }

    respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=200,
        json=existing_rule,
    )

    update_route = respx.put(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=200,
        json={"policy_id": rule_id, "status": "updated"},
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    # 1. Stage update with comment, status, repository
    update_res = await server.call_tool(
        "update_suppression",
        {
            "suppression_id": rule_id,
            "comment": "Updated rationale for suppression",
            "status": "disabled",
            "repository": "frontend-app",
        },
    )
    diff_text = extract_tool_text(update_res)
    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    assert f"suppression:{rule_id}" in diff_text
    assert update_route.call_count == 0

    token = _extract_token_from_diff(diff_text)

    # Verify staged action in store contains complete PUT payload with preserved and updated fields
    staged_action = engine.store.get_action(token)
    assert staged_action is not None
    assert isinstance(staged_action.payload, dict)
    staged_payload = staged_action.payload
    assert staged_payload["name"] == "Original Suppression Rule Name"  # preserved
    assert staged_payload["description"] == "Updated rationale for suppression"  # updated
    assert staged_payload["enable"] is False  # updated
    assert staged_payload["controls"] == existing_rule["controls"]  # preserved
    assert staged_payload["scope"]["variables"][0]["value"] == "frontend-app"  # updated
    # Verify read-only server fields are not in the payload
    for server_field in ("created", "updated", "created_by", "updated_by", "policy_type"):
        assert server_field not in staged_payload

    # 2. Execute confirmation
    exec_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": token})
    exec_text = extract_tool_text(exec_res)
    assert "✅ Action Executed Successfully" in exec_text
    assert update_route.call_count == 1

    req_body = json.loads(update_route.calls[0].request.content)
    assert req_body["name"] == "Original Suppression Rule Name"
    assert req_body["description"] == "Updated rationale for suppression"
    assert req_body["enable"] is False
    assert req_body["controls"] == existing_rule["controls"]
    assert req_body["scope"]["variables"][0]["value"] == "frontend-app"
    for server_field in ("created", "updated", "created_by", "updated_by", "policy_type"):
        assert server_field not in req_body


@pytest.mark.asyncio
@respx.mock
async def test_update_suppression_single_field_enable_preserves_all_other_fields(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    rule_id = "single-field-update-uuid-111"
    existing_rule = {
        "policy_id": rule_id,
        "name": "Production CVE Suppression",
        "description": "Risk accepted by secops team",
        "enable": True,
        "policy_type": "suppression",
        "created": "2026-01-10T08:00:00Z",
        "updated": "2026-01-10T08:00:00Z",
        "created_by": "secops@example.com",
        "updated_by": "secops@example.com",
        "controls": [
            {
                "type": "cveByIds",
                "scan_type": "vulnerability",
                "cve_ids": ["CVE-2024-12345"],
            }
        ],
        "scope": {
            "expression": "v1 && v2",
            "variables": [
                {"attribute": "repository.name", "value": "backend-service"},
                {"attribute": "repository.branch", "value": "main"},
            ],
        },
    }

    respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=200,
        json=existing_rule,
    )

    update_route = respx.put(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=200,
        json={"policy_id": rule_id, "status": "updated"},
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    # Update ONLY enable field
    update_res = await server.call_tool(
        "update_suppression",
        {
            "suppression_id": rule_id,
            "enable": False,
        },
    )
    diff_text = extract_tool_text(update_res)
    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    token = _extract_token_from_diff(diff_text)

    # Confirm and execute
    await server.call_tool("execute_confirmed_action", {"confirmation_token": token})
    assert update_route.call_count == 1

    req_body = json.loads(update_route.calls[0].request.content)
    # Changed field
    assert req_body["enable"] is False
    # Preserved required fields
    assert req_body["name"] == "Production CVE Suppression"
    assert req_body["description"] == "Risk accepted by secops team"
    assert req_body["controls"] == existing_rule["controls"]
    assert req_body["scope"] == existing_rule["scope"]
    # Excluded server-generated fields
    assert "created" not in req_body
    assert "updated" not in req_body
    assert "created_by" not in req_body
    assert "updated_by" not in req_body
    assert "policy_type" not in req_body


@pytest.mark.asyncio
@respx.mock
async def test_update_suppression_data_wrapper_format(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    rule_id = "wrapped-data-rule-222"
    existing_rule_data = {
        "policy_id": rule_id,
        "name": "Old Rule Name",
        "description": "Original Desc",
        "enable": False,
        "controls": [],
        "scope": {"expression": "v1", "variables": [{"attribute": "repository.name", "value": "*"}]},
    }

    # API returns {"data": {...}} wrapper
    respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=200,
        json={"data": existing_rule_data},
    )

    update_route = respx.put(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=200,
        json={"policy_id": rule_id},
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    update_res = await server.call_tool(
        "update_suppression",
        {
            "suppression_id": rule_id,
            "name": "New Rule Name",
        },
    )
    token = _extract_token_from_diff(extract_tool_text(update_res))
    await server.call_tool("execute_confirmed_action", {"confirmation_token": token})

    req_body = json.loads(update_route.calls[0].request.content)
    assert req_body["name"] == "New Rule Name"
    assert req_body["description"] == "Original Desc"
    assert req_body["enable"] is False
    assert req_body["controls"] == []
    assert req_body["scope"] == existing_rule_data["scope"]


@pytest.mark.asyncio
@respx.mock
async def test_update_suppression_not_found(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    rule_id = "non-existent-rule-id"
    respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=404,
        json={"message": "Suppression rule not found"},
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    update_res = await server.call_tool(
        "update_suppression",
        {
            "suppression_id": rule_id,
            "name": "Updated Name",
        },
    )
    text = extract_tool_text(update_res)
    assert "🔴 Suppression Rule Not Found or Error (HTTP 404)" in text
    assert rule_id in text
    # No action should be staged in the store
    assert len(engine.store.list_active_actions()) == 0


@pytest.mark.asyncio
@respx.mock
async def test_update_suppression_network_error(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    rule_id = "network-fail-id"
    respx.get(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    update_res = await server.call_tool(
        "update_suppression",
        {
            "suppression_id": rule_id,
            "name": "Updated Name",
        },
    )
    text = extract_tool_text(update_res)
    assert "🔴 Failed to Fetch Existing Suppression Rule (Client / Network Error)" in text
    assert rule_id in text
    assert len(engine.store.list_active_actions()) == 0


# ---------------------------------------------------------------------------
# 5. delete_suppression staged confirmation tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_delete_suppression_staged_flow_and_execution(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    rule_id = "target-delete-uuid-789"
    delete_route = respx.delete(f"https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/{rule_id}").respond(
        status_code=204,
        content=b"",
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    # 1. Stage deletion
    del_res = await server.call_tool(
        "delete_suppression",
        {
            "suppression_id": rule_id,
        },
    )
    diff_text = extract_tool_text(del_res)
    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    assert "delete_suppression" in diff_text
    assert f"suppression:{rule_id}" in diff_text
    assert delete_route.call_count == 0

    token = _extract_token_from_diff(diff_text)

    # 2. Execute deletion
    exec_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": token})
    exec_text = extract_tool_text(exec_res)
    assert "✅ Action Executed Successfully" in exec_text
    assert delete_route.call_count == 1


# ---------------------------------------------------------------------------
# 6. import_suppressions staged confirmation tests & Dry-Run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_import_suppressions_dry_run_and_staged_flow(
    base_config: AquaConfig, mock_auth: respx.Route
) -> None:
    import_route = respx.post("https://eu-central-1.edge.cloud.aquasec.com/supply_chain/v2/build/suppressions/import").respond(
        status_code=204,
        content=b"",
    )

    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    # 1. Test empty import data safeguard
    empty_res = await server.call_tool("import_suppressions", {"data": []})
    assert "Import Cancelled: Empty Data" in extract_tool_text(empty_res)
    assert len(engine.store.list_active_actions()) == 0

    # 2. Test invalid dry-run verification
    invalid_res = await server.call_tool(
        "import_suppressions",
        {"data": [{"description": "Missing name"}]},
    )
    assert "Dry-Run Verification Failed" in extract_tool_text(invalid_res)
    assert len(engine.store.list_active_actions()) == 0

    # 3. Stage import with 2 valid rules
    sample_rules = [
        {"name": "Rule 1", "description": "Imported rule 1", "enable": True},
        {"name": "Rule 2", "description": "Imported rule 2", "enable": False},
    ]
    import_res = await server.call_tool(
        "import_suppressions",
        {"data": sample_rules, "replace": True},
    )
    diff_text = extract_tool_text(import_res)
    assert "⚠️ ACTION PENDING CONFIRMATION" in diff_text
    assert "import_suppressions" in diff_text
    assert "total_rules_to_import\": 2" in diff_text
    assert import_route.call_count == 0

    token = _extract_token_from_diff(diff_text)

    # 4. Execute import
    exec_res = await server.call_tool("execute_confirmed_action", {"confirmation_token": token})
    assert "✅ Action Executed Successfully" in extract_tool_text(exec_res)
    assert import_route.call_count == 1
    assert import_route.calls[0].request.url.params["replace"] == "true"


# ---------------------------------------------------------------------------
# 7. Cancellation flow & Read-only safeguard tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_suppression_staging_cancellation(base_config: AquaConfig, mock_auth: respx.Route) -> None:
    client = AquaClient(config=base_config)
    engine = GuardrailEngine(config=base_config, client=client)
    server = create_mcp_server(config=base_config, client=client, guardrail_engine=engine)

    res = await server.call_tool("delete_suppression", {"suppression_id": "rule-to-cancel"})
    token = _extract_token_from_diff(extract_tool_text(res))

    assert len(engine.store.list_active_actions()) == 1

    cancel_res = await server.call_tool("cancel_staged_action", {"confirmation_token": token})
    assert "🗑️ Staged Action Cancelled" in extract_tool_text(cancel_res)
    assert len(engine.store.list_active_actions()) == 0


@pytest.mark.asyncio
async def test_suppressions_read_only_mode_blocks_staging() -> None:
    config = AquaConfig(
        api_key="test-key",
        api_secret="test-secret",
        read_only=True,
    )
    client = AquaClient(config=config)
    engine = GuardrailEngine(config=config, client=client)
    server = create_mcp_server(config=config, client=client, guardrail_engine=engine)

    # All mutating operations must return Read-Only rejection
    c_res = await server.call_tool("create_suppression", {"name": "Blocked Create"})
    assert "⛔ READ-ONLY MODE: Action Staging Blocked" in extract_tool_text(c_res)

    u_res = await server.call_tool("update_suppression", {"suppression_id": "123", "name": "Blocked Update"})
    assert "⛔ READ-ONLY MODE: Action Staging Blocked" in extract_tool_text(u_res)

    d_res = await server.call_tool("delete_suppression", {"suppression_id": "123"})
    assert "⛔ READ-ONLY MODE: Action Staging Blocked" in extract_tool_text(d_res)

    i_res = await server.call_tool("import_suppressions", {"data": [{"name": "r1"}]})
    assert "⛔ READ-ONLY MODE: Action Staging Blocked" in extract_tool_text(i_res)

    assert len(engine.store.list_active_actions()) == 0
