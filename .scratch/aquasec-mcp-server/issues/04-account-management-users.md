# 04 — Account Management: Users (Read & Staged Mutations)

**What to build:** MCP tools to list, query, add, modify, and remove Aqua Security user accounts and assign CSP roles, with all user lifecycle mutations enforced through the two-phase staged confirmation guardrail.

**Blocked by:** 02 — Two-Phase Staged Confirmation Guardrail Engine

**Status:** ready-for-agent

- [ ] `list_users` tool supporting pagination (`limit`, `offset`) and resource expansion (`roles`, `group`, `account`).
- [ ] `get_user` tool retrieving detailed user profile by ID with expansions.
- [ ] `create_user` tool staging addition of a new user with `email`, `csp_roles`, `account_admin`, and `mfa_enabled` parameters.
- [ ] `update_user` tool staging modifications to user roles, admin status, or MFA settings.
- [ ] `delete_user` tool staging removal of a user account.
- [ ] High-seam integration tests verifying user query, staged mutation generation, and confirmed execution against mock Aqua endpoints.
