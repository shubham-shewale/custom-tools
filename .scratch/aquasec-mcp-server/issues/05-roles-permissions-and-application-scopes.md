# 05 — Account Management: Roles, Permissions & Application Scopes

**What to build:** MCP inspection tools to list and query Aqua Security CSP roles, permission definitions, and application scopes, delivering clean markdown permission matrices and resource filter summaries.

**Blocked by:** 01 — Project Foundation, EU Auth Client & Token Lifecycle with Tracer Tool

**Status:** ready-for-agent

- [ ] `list_roles` tool returning available CSP roles and summary descriptions.
- [ ] `get_role_details` tool retrieving granular permissions associated with a specific role name or ID.
- [ ] `list_application_scopes` tool retrieving defined application scopes across the account.
- [ ] `get_application_scope` tool returning detailed scope configuration and resource filter expressions.
- [ ] High-seam integration tests verifying role and scope tool queries and output formatting against mock Aqua endpoints.
