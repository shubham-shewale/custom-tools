# 02 — Two-Phase Staged Confirmation Guardrail Engine

**What to build:** An in-memory guardrail engine and companion MCP management tools that intercept state-modifying requests, compute an impact assessment diff, assign a 5-minute confirmation token, and require explicit confirmed execution before contacting the Aqua API, with a global read-only safety killswitch.

**Blocked by:** 01 — Project Foundation, EU Auth Client & Token Lifecycle with Tracer Tool

**Status:** ready-for-agent

- [ ] In-memory staged action store supporting 5-minute TTL expiration and automatic cleanup of expired tokens.
- [ ] Structured impact diff formatter that outputs a clear, human-readable `⚠️ ACTION PENDING CONFIRMATION` preview containing action type, target ID, and field changes.
- [ ] `execute_confirmed_action(confirmation_token)` tool that validates token, executes the staged HTTP request via the auth client, invalidates the token, and returns the response.
- [ ] `cancel_staged_action(confirmation_token)` tool that deletes a staged action from the store.
- [ ] `list_staged_actions()` tool that displays all active pending confirmations.
- [ ] `AQUA_READ_ONLY=true` environment flag support that immediately rejects all write/stage attempts.
- [ ] High-seam integration tests verifying staging, preview generation, confirmed execution, token expiry, cancellation, and read-only rejection.
