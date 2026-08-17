# Aqua Security MCP Server

Model Context Protocol (MCP) server providing structured tools for managing Aqua Security EU accounts (users, roles) and supply chain security suppression rules with strict safety guardrails.

## Language

**Suppression Rule**:
A policy rule that silences or exempts specific security findings (e.g., CVE vulnerabilities, hardcoded secrets, misconfigurations) across code repositories or build pipelines.
_Avoid_: Whitelist, exception filter, ignore rule

**Guardrail**:
A protective execution gate requiring explicit operator confirmation before applying state-changing or destructive API actions.
_Avoid_: Permission bypass, sanity check

**Staged Action**:
A validated mutation request stored temporarily in memory awaiting operator approval before being sent to the Aqua API.
_Avoid_: Draft, pending edit

**Confirmation Token**:
A short-lived (5-minute TTL) unique identifier issued when an action is staged, required to execute the mutation.
_Avoid_: OTP, auth token, session key

**JWT Token**:
A bearer token with a 12-hour validity generated via HMAC-SHA256 signature exchange against the Aqua authentication endpoint, automatically refreshed in-memory prior to expiration.
_Avoid_: API secret, session cookie

**CSP Role**:
A named permission set or role (e.g. `Administrator`, `Auditor`, `Scanner`) assigned to an Aqua user account governing CSPM and supply chain access.
_Avoid_: Access level, user group, privilege
