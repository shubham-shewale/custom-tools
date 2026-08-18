# Aqua Security MCP Server

Model Context Protocol (MCP) server for Aqua Security European Cloud (`eu-central-1`) with automatic HMAC-SHA256 token authentication and strict two-phase staged confirmation guardrails for mutative operations.

---

## 🌟 Key Features

- **Automated Aqua EU Cloud Authentication**: Automatic HMAC-SHA256 signature generation and 12-hour session token lifecycle with pro-active re-authentication (60m window).
- **Two-Phase Staged Confirmation Guardrail**: All state-modifying actions (`POST`, `PUT`, `DELETE`) are staged in-memory with a 5-minute confirmation token and human-readable diff preview before execution.
- **Global Read-Only Guardrail**: Ability to lock the server in read-only mode (`AQUA_READ_ONLY=true`) to block any mutation requests.
- **Full Domain Coverage**:
  - **Connection**: Diagnostics and authentication status verification.
  - **Supply Chain Suppressions**: Search, inspect, create, update, and delete suppression rules.
  - **Account Management (Users)**: List, inspect, create, update, delete users, and reset user passwords.
  - **Roles, Permissions & Scopes**: Inspect RBAC roles, permission sets, and application scopes.

---

## 📦 Requirements & Dependencies

### Prerequisites
- **Python**: `>= 3.10`
- **Package Manager**: [`uv`](https://github.com/astral-sh/uv) (recommended) or `pip` / `python -m venv`
- **Aqua Security API Credentials**: API Key and API Secret with EU region access.

### Core Dependencies
- `mcp>=1.0.0` - Official Model Context Protocol Python SDK
- `httpx>=0.27.0` - Async HTTP client for Aqua API communication
- `pydantic>=2.0.0` - Data validation and configuration management

### Dev & Testing Dependencies
- `pytest>=8.0.0`, `pytest-asyncio>=0.23.0`
- `respx>=0.21.0` - Mocking HTTP calls in tests
- `mypy>=1.10.0` - Static type checking
- `ruff>=0.5.0` - Linting and code formatting

---

## ⚙️ Configuration & Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `AQUA_API_KEY` | **Yes** | — | Aqua Security API Key / User ID |
| `AQUA_API_SECRET` | **Yes** | — | Aqua Security API Secret for HMAC-SHA256 signature |
| `AQUA_BASE_URL` | No | `https://eu-central-1.edge.cloud.aquasec.com` | Base API endpoint for Aqua CSPM & Supply Chain |
| `AQUA_TOKEN_URL` | No | `https://eu-1.api.cloudsploit.com/v2/tokens` | Aqua CloudSploit Token endpoint for EU region |
| `AQUA_READ_ONLY` | No | `false` | When set to `true` / `1`, blocks all write operations |
| `AQUA_REQUEST_TIMEOUT` | No | `30.0` | HTTP request timeout in seconds |

---

## 🚀 Setup Instructions

### Option 1: Using `uv` (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/shubham-shewale/custom-tools.git
   cd custom-tools
   ```

2. **Install dependencies and create virtual environment**:
   ```bash
   uv sync
   ```

3. **Set environment variables**:
   ```bash
   export AQUA_API_KEY="your-api-key"
   export AQUA_API_SECRET="your-api-secret"
   ```

4. **Run the MCP server**:
   ```bash
   uv run aquasec-mcp
   ```

---

### Option 2: Using standard `pip` and `venv`

1. **Clone and enter the directory**:
   ```bash
   git clone https://github.com/shubham-shewale/custom-tools.git
   cd custom-tools
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install the package in editable mode**:
   ```bash
   pip install -e .
   ```

4. **Run the server**:
   ```bash
   export AQUA_API_KEY="your-api-key"
   export AQUA_API_SECRET="your-api-secret"
   aquasec-mcp
   ```

---

## 🔌 MCP Client Configuration

### Claude Desktop Configuration
Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aqua-security": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/custom-tools",
        "run",
        "aquasec-mcp"
      ],
      "env": {
        "AQUA_API_KEY": "your-aqua-api-key",
        "AQUA_API_SECRET": "your-aqua-api-secret",
        "AQUA_READ_ONLY": "false"
      }
    }
  }
}
```

### Antigravity / Cursor / Custom MCP Client
```json
{
  "mcpServers": {
    "aqua-security": {
      "command": "python",
      "args": ["-m", "aquasec_mcp.cli"],
      "env": {
        "AQUA_API_KEY": "your-aqua-api-key",
        "AQUA_API_SECRET": "your-aqua-api-secret"
      }
    }
  }
}
```

---

## 🛠️ Available MCP Tools

### 1. Connection & Diagnostics
- `check_aqua_connection` — Tests credentials, validates HMAC token exchange against EU endpoints, and verifies connectivity.

### 2. Guardrails & Mutation Confirmation
- `list_staged_actions` — Lists all active mutations awaiting operator approval.
- `execute_confirmed_action(confirmation_token)` — Validates token and executes the staged action against the live Aqua API.
- `cancel_staged_action(confirmation_token)` — Cancels a pending mutation and deletes the token.

### 3. Supply Chain Security Suppression Rules
- `list_suppressions` — Lists and searches suppression rules with optional filtering.
- `get_suppression(policy_id)` — Retrieves full details of a specific suppression rule.
- `create_suppression(...)` — Stages creation of a new suppression rule (requires confirmation).
- `update_suppression(...)` — Stages updates to an existing rule with diff preview (requires confirmation).
- `delete_suppression(policy_id)` — Stages deletion of a suppression rule (requires confirmation).

### 4. Account Management (Users)
- `list_users` — Lists all user accounts with pagination and filtering.
- `get_user(user_id)` — Fetches detailed user information.
- `create_user(...)` — Stages creation of a new user account (requires confirmation).
- `update_user(...)` — Stages updates to an existing user (requires confirmation).
- `delete_user(user_id)` — Stages deletion of a user account (requires confirmation).
- `reset_user_password(user_id)` — Stages user password reset (requires confirmation).

### 5. Roles, Permissions & Application Scopes
- `list_roles` — Lists all available RBAC roles.
- `get_role(role_name)` — Retrieves permissions and details for a role.
- `list_permissions` — Lists all system permissions.
- `list_application_scopes` — Lists application scopes.
- `get_application_scope(scope_name)` — Fetches scope details and assigned artifacts.

---

## 🧪 Running Tests & Quality Checks

Run the full test suite (78 tests):
```bash
uv run pytest
# or with active venv:
pytest
```

Type checking and linting:
```bash
uv run mypy src
uv run ruff check .
```

---

## 📄 License

Internal / Proprietary.
