---
name: aquasec-account-review
description: Review Aqua Security users, roles, permissions, and application scopes for duplication, excess access, and portal hygiene. Use when asked to audit, clean up, deduplicate, simplify, or improve Aqua account management. Analysis is read-only; never make a change without explicit approval.
---

# AquaSec Account Review

Audit Aqua account access through the Aqua MCP, propose a cleaner target state, and apply only explicitly approved changes.

## Process

### 1. Inspect

Use the Aqua MCP as the source of truth.

Start with:
- `check_aqua_connection`
- `list_staged_actions`
- all users via `list_users`
- roles via `list_roles` + `get_role_details`
- application scopes via `list_application_scopes` + `get_application_scope` where relevant

Stay read-only during this phase. Do not use shell, curl, or direct Aqua API calls to bypass the MCP.

### 2. Find cleanup opportunities

Compare normalized role permission sets and user assignments. Look for:
- duplicate permissions in a role;
- custom roles with identical or near-identical permissions;
- roles that are strict subsets of other roles;
- user role assignments that add no effective permissions;
- unnecessary `account_admin` exposure;
- unconfirmed/MFA/stale-account signals when the MCP exposes them;
- duplicate, overly broad, or poorly named application scopes;
- unclear role/scope naming and descriptions.

Treat exact set matches as facts. Treat semantic similarity or business intent as a hypothesis requiring owner validation.

Do not call a role or scope "unused" unless the inventory proves it. Say "no assignments observed" when that is all the data shows.

### 3. Record the analysis

Create or update:

`docs/aquasec-account-review.md`

Keep it concise. Include:
- inventory summary;
- findings with evidence;
- recommended target state;
- numbered proposed changes (`AM-001`, `AM-002`, ...);
- items blocked by missing MCP capabilities;
- approval/execution status for any change attempted.

Never write secrets or confirmation tokens to the document.

### 4. Present recommendations

Group findings into:
- **Safe cleanup** — strong evidence, low ambiguity;
- **Needs owner validation** — technically plausible but business intent is unknown;
- **Blocked by MCP** — improvement is valid but no supported mutation tool exists.

For each proposed change show the target, current state, proposed state, access impact, and rollback.

Then stop and ask the user which change IDs they approve.

A request such as "clean this up" or "fix everything" is approval to analyze, not approval to mutate.

### 5. Apply approved changes

Only act on explicitly approved change IDs.

Before staging a change, re-read the target and stop if its state has drifted.

Use only MCP mutation tools. The current MCP can change user-side account settings/role assignments, but role definitions and application scopes are read-only unless the repo exposes mutation tools for them.

After the MCP stages a change, show the staged diff and ask for explicit approval again before calling `execute_confirmed_action`.

Never execute an unapproved staged action.

### 6. Verify

After execution, re-read the affected resource and verify the intended state.

Update `docs/aquasec-account-review.md` with the result and any remaining recommendations. Do not silently make corrective changes if verification fails.

## Target state

Prefer:
- fewer, clearly named job-function roles;
- no duplicate custom permission sets;
- no redundant user role assignments without a documented reason;
- minimal account-wide admin access;
- clear, narrowly-scoped application scopes;
- role/scope names and descriptions that communicate purpose and ownership.
