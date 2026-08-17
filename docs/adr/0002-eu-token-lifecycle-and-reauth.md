# EU Token Lifecycle and Automatic Re-Authentication

## Context
Aqua Security APIs require HMAC-SHA256 signed requests to `/v2/tokens` to obtain short-lived JWT bearer tokens before accessing CSPM and Supply Chain endpoints in the European region (`eu-central-1`). Frequent re-authentication on every MCP tool call introduces latency, while token expiration during long-running agent sessions leads to unexpected request failures.

## Decision
1. **EU Region Defaults**: Default the API endpoint to `https://eu-central-1.edge.cloud.aquasec.com` and the token signing endpoint to `https://eu-1.api.cloudsploit.com/v2/tokens`, configurable via environment variables (`AQUA_API_KEY`, `AQUA_API_SECRET`, `AQUA_BASE_URL`, `AQUA_TOKEN_URL`).
2. **12-Hour Token Validity**: Request tokens with a 720-minute (12-hour) validity window (`{"validity": 720, "allowed_endpoints": ["ANY:*"]}`).
3. **Proactive In-Memory Cache**: The MCP server caches the JWT in memory and evaluates expiry before each request. If `now >= expires_at - 300s`, the server transparently generates a fresh HMAC signature and acquires a new token before executing the tool call.
4. **Reactive 401 Recovery**: If any endpoint returns `401 Unauthorized`, the token cache is cleared and a fresh token is acquired on a single automatic retry.

## Consequences
- Eliminates auth overhead on consecutive tool calls.
- Guarantees seamless multi-hour agent sessions without manual re-login.
- Completely abstracts HMAC cryptographic signing away from the LLM tool interface.
