# Staged Confirmation Token Guardrail

## Context
The Aqua Security MCP Server provides tools to query and mutate sensitive security configurations (such as silencing supply chain vulnerability alerts and modifying user roles/access). Unconfirmed or accidental mutations triggered by autonomous LLM agents can introduce severe security risks or disrupt compliance posture.

## Decision
All state-modifying operations (create, update, delete) will use a **Two-Phase Staged Confirmation Token** pattern:
1. When an agent calls a mutating tool, the server validates inputs, generates a structured dry-run impact diff, and stores the staged action in memory with a short-lived UUID `confirmation_token` (5-minute TTL).
2. The server returns the preview diff and token without modifying the Aqua API.
3. The LLM must present the preview to the user and call `execute_confirmed_action(confirmation_token=...)` only after explicit confirmation is obtained.
4. An environment variable `AQUA_READ_ONLY=true` provides an unconditional server-wide safeguard that rejects all mutation requests.

## Consequences
- Prevents unprompted or hallucinated edits from altering live Aqua infrastructure.
- Decouples tool parameter inspection from host-specific UI approval limitations.
- Requires agents to perform a two-step sequence for write operations.
