# Spec: Aqua Security MCP Server

## Problem Statement

Security engineers and DevOps teams using AI assistants (such as Claude, Antigravity, or Cursor) need to inspect and manage Aqua Security supply chain findings, suppression rules, user accounts, and roles without constantly switching contexts to the Aqua web console. However, allowing autonomous LLM agents to directly modify enterprise security configurations poses a severe risk: an unconfirmed or hallucinated tool call could inadvertently silence critical vulnerability alerts or alter user permissions. Furthermore, Aqua Security's European cloud infrastructure requires HMAC-SHA256 authenticated short-lived JWT tokens, which introduces complexity and latency if authentication is not managed seamlessly.

## Solution

A simple, fast, and lightweight Model Context Protocol (MCP) server written in Python that exposes dedicated tools for Aqua Security EU Cloud. The server integrates a strict Two-Phase Staged Confirmation guardrail on all state-mutating operations (create, update, delete, import). Every mutation generates an impact assessment diff and a short-lived confirmation token, requiring explicit operator approval before hitting live Aqua endpoints. The server manages HMAC-SHA256 signature exchanges, automatically acquires 12-hour JWT tokens, and caches/refreshes them in-memory to ensure zero-latency tool executions and uninterrupted multi-hour workflows.

## User Stories

1. As a security engineer, I want the MCP server to authenticate automatically to the Aqua EU endpoint using my API key and secret, so that I don't have to manually manage session tokens or timestamps.
2. As a DevOps engineer, I want tokens to be requested with a 12-hour validity and refreshed in-memory before expiry, so that long-running AI sessions remain responsive and never fail due to token timeouts.
3. As a platform administrator, I want an automatic retry mechanism when an API call encounters an unexpected 401 Unauthorized status, so that transient token invalidations are resolved transparently.
4. As a security team lead, I want any creation of a supply chain suppression rule to return a preview diff and confirmation token rather than immediately applying the change, so that unconfirmed alert silences cannot occur.
5. As a security team lead, I want any modification or deletion of a suppression rule to require explicit token confirmation, so that active security policies cannot be accidentally removed or loosened.
6. As an AI assistant user, I want to execute a confirmed action by submitting its confirmation token, so that I can apply verified changes to the Aqua platform.
7. As an AI assistant user, I want to cancel a staged action or list pending staged actions, so that I maintain full situational awareness and control over pending mutations.
8. As a compliance officer, I want the ability to enable a global read-only mode via environment configuration, so that all write and mutation attempts are unconditionally blocked in audit-only environments.
9. As a security analyst, I want to list and search supply chain suppression rules filtered by repository, check, branch, scope, or status, so that I can audit suppressed risks quickly.
10. As a security analyst, I want to inspect the detailed attributes of a specific suppression rule by its ID, so that I understand why a finding was exempted.
11. As a security engineer, I want to import suppression rules with dry-run verification, so that bulk policies can be safely migrated or restored.
12. As an identity administrator, I want to list users across the Aqua account with expandable roles, group, and account details, so that I can audit user access and privileges.
13. As an identity administrator, I want to inspect details of a specific user account by ID, so that I can verify their assigned roles and MFA status.
14. As an identity administrator, I want creating, updating, or removing a user account to be protected by the staged confirmation guardrail, so that access changes are strictly verified before execution.
15. As a security auditor, I want to list available CSP roles and inspect role permission sets, so that I can evaluate role definitions before assigning them to users.
16. As a security architect, I want to list and retrieve application scopes, so that I can inspect the organizational boundaries configured in Aqua.
17. As an operator running the MCP server locally or in CI, I want stdio transport support, so that the server integrates out-of-the-box with Claude Desktop, Antigravity, and other MCP clients.
18. As a developer, I want clear, structured markdown summaries alongside JSON tool outputs, so that responses are easy for both humans and language models to understand.

## Implementation Decisions

### Modular Architecture
- Built on the official Python `mcp` SDK using `FastMCP` for asynchronous JSON-RPC protocol handling, schema auto-generation, and stdio transport.
- Uses `httpx.AsyncClient` with connection pooling and configurable request timeouts for fast, non-blocking HTTP interactions.
- Input models, query parameters, and staged payload objects are validated with `Pydantic` v2 schemas.

### Authentication & Token Lifecycle
- Credentials loaded from environment variables (`AQUA_API_KEY`, `AQUA_API_SECRET`, optional `AQUA_BASE_URL`, optional `AQUA_TOKEN_URL`).
- Defaults to the European cloud region: API at `https://eu-central-1.edge.cloud.aquasec.com` and Auth token endpoint at `https://eu-1.api.cloudsploit.com/v2/tokens`.
- Token requests calculate HMAC-SHA256 hex signatures over `Timestamp + Method + Path + JSONBody` with validity configured for 720 minutes (12 hours).
- Auth client tracks `expires_at` and proactively requests a fresh token 5 minutes before expiration.
- On HTTP 401 responses, the cached token is purged and re-acquired on a single transparent retry.

### Staged Confirmation Guardrail Protocol
- Any mutating operation (`create_*`, `update_*`, `delete_*`, `import_*`) routes through the guardrail engine.
- Instead of calling Aqua directly, the engine validates the request, generates a structured impact diff (displaying operation type, target resource, and parameter deltas), assigns a cryptographically unique 5-minute UUID confirmation token, and stores the staged action in an in-memory TTL cache.
- The tool returns a human-readable prompt warning `⚠️ ACTION PENDING CONFIRMATION` with the diff and token.
- Companion tools `execute_confirmed_action`, `cancel_staged_action`, and `list_staged_actions` manage the staged queue.
- When `AQUA_READ_ONLY=true` is set, all mutating tools immediately fail with a policy error.

### Tool Surface Specification

#### Supply Chain Suppressions
- `list_suppressions`: Query suppression rules with filtering by search term, repository name, check ID, branch, scope (`repository`, `pipeline`, `all`), status, page number, and page size.
- `get_suppression`: Retrieve full rule details by `suppression_id`.
- `create_suppression`: Stage creation of a suppression rule (rule name, check, repository, scope, reason, comment).
- `update_suppression`: Stage updates to an existing rule's scope, status, or comment.
- `delete_suppression`: Stage deletion of a suppression rule by ID.
- `import_suppressions`: Stage bulk import of suppression rules.

#### Account Management: Users
- `list_users`: List user accounts with optional query expansion (`roles`, `group`, `account`), limit, and offset.
- `get_user`: Retrieve a specific user by ID with optional expansions.
- `create_user`: Stage creation of a new user account with email, `csp_roles`, and `account_admin` flag.
- `update_user`: Stage update of user `csp_roles`, `account_admin`, or `mfa_enabled` status.
- `delete_user`: Stage removal of a user by ID.

#### Account Management: Roles & Application Scopes
- `list_roles`: List available CSP roles and permission definitions.
- `get_role_details`: Retrieve granular permissions associated with a specific role name or ID.
- `list_application_scopes`: List defined application scopes.
- `get_application_scope`: Retrieve scope definitions and resource filters for a specific scope ID.

#### Guardrail Tools
- `execute_confirmed_action`: Accepts `confirmation_token`, validates expiration, dispatches the HTTP request to Aqua EU API, purges the token, and returns the live response.
- `cancel_staged_action`: Discards a staged action from memory.
- `list_staged_actions`: Returns all currently active pending confirmation tokens and their summaries.

## Testing Decisions

- **Single High Testing Seam**: Tests will be conducted strictly at the highest public boundary—the FastMCP server JSON-RPC interface. Tests will invoke MCP tools through standard tool calls and assert on returned output contents and status.
- **Mock HTTP Transport**: Aqua Security EU API and Auth endpoints will be mocked using `httpx.MockTransport` / `respx` to test deterministic success, validation errors, token expiration, 401 retries, and network errors without requiring live external network connectivity.
- **Testing Focus**:
  - Auth: HMAC signature accuracy, token caching, proactive refresh prior to 12h expiration, and reactive 401 retry.
  - Guardrail: Verifying that calling mutating tools never calls the Aqua mock API until `execute_confirmed_action` is invoked with a valid token.
  - Read-Only Mode: Verifying that `AQUA_READ_ONLY=true` blocks mutation staging.
  - CRUD operations across suppressions, users, roles, and scopes.

## Out of Scope

- API Key management (`/cspm/v2/apikeys`) and Personal Access Token (PAT) lifecycle management (`/cspm/v2/pat`).
- US and APAC regional endpoints (EU `eu-central-1` is explicitly locked as default).
- Direct database or on-premise container scanners.
- Continuous background policy syncing or webhook listeners.

## Further Notes

- References:
  - [`CONTEXT.md`](file:///Users/shubhamshewale/Documents/antigravity/custom-tools/CONTEXT.md)
  - [ADR 0001: Staged Confirmation Guardrail](file:///Users/shubhamshewale/Documents/antigravity/custom-tools/docs/adr/0001-staged-confirmation-guardrail.md)
  - [ADR 0002: EU Token Lifecycle & Re-Authentication](file:///Users/shubhamshewale/Documents/antigravity/custom-tools/docs/adr/0002-eu-token-lifecycle-and-reauth.md)
