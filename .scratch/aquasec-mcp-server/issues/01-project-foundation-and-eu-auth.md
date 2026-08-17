# 01 — Project Foundation, EU Auth Client & Token Lifecycle with Tracer Tool

**What to build:** An MCP server entrypoint and authentication manager that loads Aqua Security credentials, automatically computes HMAC-SHA256 signatures to obtain a 12-hour JWT token from the Aqua EU authentication service, proactively refreshes cached tokens before expiration, and exposes a connection check tool to verify live connectivity.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] Python package configured with dependencies (`mcp`, `httpx`, `pydantic`) and CLI executable entrypoint.
- [ ] Configuration loader supporting `AQUA_API_KEY`, `AQUA_API_SECRET`, defaulting to EU region endpoints (`https://eu-central-1.edge.cloud.aquasec.com` and `https://eu-1.api.cloudsploit.com/v2/tokens`).
- [ ] HMAC-SHA256 request signer requesting token with `validity: 720` (12 hours).
- [ ] In-memory token cache with proactive refresh when within 5 minutes of expiration.
- [ ] Reactive 401 retry handler that purges expired token and acquires a new one.
- [ ] FastMCP server running over stdio exposing a `check_aqua_connection` health check tool.
- [ ] High-seam integration tests verifying tool invocation and token exchange against mocked HTTP transport.
