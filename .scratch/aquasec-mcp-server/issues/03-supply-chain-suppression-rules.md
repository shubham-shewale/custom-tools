# 03 — Supply Chain Suppression Rules (Read & Staged Mutations)

**What to build:** MCP tools to list, inspect, create, update, delete, and import Aqua Security supply chain suppression rules, where all mutating actions are protected by the two-phase staged confirmation guardrail.

**Blocked by:** 02 — Two-Phase Staged Confirmation Guardrail Engine

**Status:** ready-for-agent

- [ ] `list_suppressions` tool with support for `search`, `repository`, `check`, `branch`, `scope`, `status`, `page`, `page_size`, and `order_by` query parameters.
- [ ] `get_suppression` tool retrieving complete rule details by `suppression_id`.
- [ ] `create_suppression` tool staging creation of a suppression rule and returning a preview diff with confirmation token.
- [ ] `update_suppression` tool staging updates to rule scope, branch, status, or comment.
- [ ] `delete_suppression` tool staging deletion of a suppression rule.
- [ ] `import_suppressions` tool staging bulk rule imports.
- [ ] High-seam integration tests verifying read operations and full staged-to-confirmed execution flows against mock Aqua endpoints.
