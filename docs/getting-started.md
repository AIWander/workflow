---
title: "Workflow MCP Server — API Discovery, Credential Vault, and 2FA Automation for AI Agents"
description: "Getting started guide for the Workflow Rust MCP server. Gives Claude and other AI agents 37 tools for API discovery, DPAPI-secured credential management, flow recording/replay, watch/polling, data piping, workflow chains, and TOTP/HOTP 2FA automation over the Model Context Protocol."
keywords:
  - MCP server
  - model context protocol server
  - rust mcp server
  - Claude Desktop MCP
  - Claude Code MCP
  - 2FA MCP
  - TOTP MCP
  - OTP automation
  - HOTP generator
  - credential management DPAPI
  - credential vault
  - API replay
  - API pattern learning
  - flow recording
  - recorded flows
  - watch polling
  - data pipeline MCP
  - workflow automation
---

# Getting Started with Workflow

Workflow is a Rust MCP server that provides 37 tools for end-to-end automation across seven modules: API Discovery, Credential Vault (DPAPI-encrypted), Flow Recording/Replay, Watch/Polling, Data Piping, Workflow Chains, and TOTP/HOTP 2FA generation. It ships as a single binary with no runtime dependencies and connects to Claude Desktop, Claude Code, or any MCP-compatible client over standard JSON-RPC on stdin/stdout.

Credentials are encrypted at rest using Windows DPAPI, meaning secrets never leave the machine in plaintext and are bound to the current Windows user profile. No external vault, no environment variables, no config files with secrets in the clear.

## Installation

### Prerequisites

- **Rust toolchain** (stable, 2021 edition or later) --- only needed if building from source
- **Windows 10/11** (DPAPI credential vault requires the Windows Data Protection API)

### Build from source

```bash
git clone https://github.com/AIWander/workflow.git
cd workflow
cargo build --release -p workflow
```

The output binary lands at `target/release/workflow.exe`. It is a single file with no runtime dependencies.

### Pre-built binaries

Download the latest Windows binaries from the [Releases page](https://github.com/AIWander/workflow/releases/latest):
- `workflow-v1.3.5-x64.exe` --- Windows x64
- `workflow-v1.3.5-aarch64.exe` --- Windows ARM64

### Configure for Claude Desktop

Add the server to your Claude Desktop config at `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "workflow": {
      "command": "C:/path/to/workflow.exe",
      "args": []
    }
  }
}
```

### Configure for Claude Code

Add it to `~/.claude/mcp.json` (global) or `.mcp.json` (per-project):

```json
{
  "mcpServers": {
    "workflow": {
      "command": "C:/path/to/workflow.exe",
      "args": []
    }
  }
}
```

Restart Claude Desktop or Claude Code after editing. The 37 tools will appear in your tool list.

## Architecture Overview

```
workflow.exe  (MCP tool server, stdin/stdout JSON-RPC)
  |
  +-- api         API Discovery: store, call, test, list, delete learned API patterns
  +-- credential  Credential Vault: DPAPI-encrypted store, get, list, delete, refresh
  +-- flow        Flow Recording: record, replay, adapt, dispatch multi-step sequences
  +-- watch       Watch/Polling: define, schedule, and check for changes on resources
  +-- pipe        Data Piping: transform and test data between steps
  +-- chain       Workflow Chains: define, run, and monitor multi-step workflows
  +-- totp        TOTP/HOTP: register secrets, generate one-time codes for 2FA
```

All seven modules compile into one binary. The MCP server reads JSON-RPC requests from stdin, dispatches to the appropriate module, and returns results on stdout.

## Tool Modules and Usage Examples

Every example below shows the raw JSON-RPC call. When using Claude Desktop or Claude Code, the client builds these calls automatically from natural-language requests.

### API Discovery (5 tools)

Store learned API patterns and replay them. The agent observes an API interaction (from a browser session, docs, or manual input), stores the pattern, and replays it on demand.

**Store an API pattern:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "api_store",
  "arguments": {
    "name": "get_user",
    "method": "GET",
    "url": "https://api.example.com/users/{id}",
    "headers": {"Authorization": "Bearer {{token}}"}
  }
}}
```

**Call a stored API:**

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
  "name": "api_call",
  "arguments": {"name": "get_user", "params": {"id": "42", "token": "abc123"}}
}}
```

Other tools: `api_list` (enumerate stored patterns), `api_test` (dry-run with validation), `api_delete` (remove a pattern).

### Credential Vault (5 tools)

All credentials are encrypted at rest using Windows DPAPI. They are bound to the current Windows user profile --- no other user or machine can decrypt them.

**Store a credential:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "credential_store",
  "arguments": {"name": "github_token", "value": "ghp_xxxxxxxxxxxx", "tags": ["github", "api"]}
}}
```

**Retrieve a credential:**

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
  "name": "credential_get",
  "arguments": {"name": "github_token"}
}}
```

Other tools: `credential_list` (enumerate by tag), `credential_delete`, `credential_refresh` (rotate a stored value).

### Flow Recording (8 tools)

Record multi-step sequences, then replay or adapt them. Flows capture the tool name and arguments for each step, enabling deterministic replay or AI-driven adaptation.

**Record a flow:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "flow_record_start",
  "arguments": {"name": "login_sequence"}
}}
```

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
  "name": "flow_record_step",
  "arguments": {"tool": "api_call", "arguments": {"name": "auth_login", "params": {"user": "admin"}}}
}}
```

```json
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
  "name": "flow_record_stop",
  "arguments": {}
}}
```

**Replay a recorded flow:**

```json
{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
  "name": "flow_replay",
  "arguments": {"name": "login_sequence"}
}}
```

Other tools: `flow_adapt` (modify a recorded flow for a new context), `flow_dispatch` (run a flow with parameter overrides), `flow_list`, `flow_delete`.

### Watch/Polling (5 tools)

Define watches on resources and poll for changes. Watches can trigger actions when conditions are met.

**Define a watch:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "watch_define",
  "arguments": {
    "name": "price_monitor",
    "target": "https://api.example.com/price",
    "interval_secs": 300,
    "condition": "changed"
  }
}}
```

**Check a watch manually:**

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
  "name": "watch_check",
  "arguments": {"name": "price_monitor"}
}}
```

Other tools: `watch_list`, `watch_schedule` (set cron-like schedules), `watch_delete`.

### Data Piping (2 tools)

Transform data between steps using jq-style expressions or built-in transforms.

**Pipe and transform data:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "transform_pipe",
  "arguments": {
    "input": "{\"users\": [{\"name\": \"Alice\"}, {\"name\": \"Bob\"}]}",
    "expression": ".users[].name"
  }
}}
```

Use `pipe_test` to validate a transform expression without executing side effects.

### Workflow Chains (5 tools)

Define multi-step workflows that chain tools together with conditional branching and error handling.

**Define and run a workflow:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "workflow_define",
  "arguments": {
    "name": "deploy_check",
    "steps": [
      {"tool": "api_call", "arguments": {"name": "health_check"}},
      {"tool": "watch_check", "arguments": {"name": "deploy_status"}},
      {"tool": "credential_get", "arguments": {"name": "slack_webhook"}}
    ]
  }
}}
```

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
  "name": "workflow_run",
  "arguments": {"name": "deploy_check"}
}}
```

Other tools: `workflow_list`, `workflow_status` (check run history), `workflow_delete`.

### TOTP/2FA (6 tools)

Register TOTP/HOTP secrets and generate one-time codes on demand. Secrets are stored in the DPAPI-encrypted credential vault.

**Register a TOTP secret:**

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
  "name": "totp_register",
  "arguments": {"name": "github_2fa", "secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30}
}}
```

**Register from an otpauth:// URI** (e.g., scanned from a QR code):

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
  "name": "totp_register_from_uri",
  "arguments": {"uri": "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"}
}}
```

**Generate a TOTP code:**

```json
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
  "name": "totp_generate",
  "arguments": {"name": "github_2fa"}
}}
```

**Generate an HOTP code** (counter-based):

```json
{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
  "name": "hotp_generate",
  "arguments": {"name": "hardware_token", "counter": 7}
}}
```

Other tools: `totp_list` (enumerate registered secrets), `totp_delete`.

## Common Workflows

**Learn an API from a browser session.** Use the Hands MCP server to observe network requests via `browser_get_all_network`, then pass the captured endpoints to `api_store`. Future calls use `api_call` with stored patterns --- no manual API docs needed.

**Automate 2FA login.** Store the TOTP secret with `totp_register` or `totp_register_from_uri`. At login time, call `totp_generate` to get the current code, then pipe it into a flow that fills the 2FA field. The entire login sequence can be recorded with `flow_record_start` and replayed with `flow_replay`.

**Record and replay a multi-step flow.** Start recording with `flow_record_start`, execute each step normally, then `flow_record_stop`. Later, `flow_replay` runs the exact sequence. Use `flow_adapt` to modify the flow for different environments (staging vs. production) without re-recording.

**Watch for changes and trigger actions.** Define a watch with `watch_define` targeting an API endpoint or resource. Use `watch_schedule` to poll on an interval. When `watch_check` detects a change, trigger a workflow chain with `workflow_run` to notify, log, or act on the change.

## Tips and Troubleshooting

**DPAPI is Windows-only.** The credential vault requires Windows DPAPI. On non-Windows platforms, credential_store and credential_get will return an error. All other modules (API, flow, watch, pipe, chain, TOTP) work cross-platform.

**TOTP timing matters.** TOTP codes are time-based with a default 30-second window. If codes are rejected, verify the system clock is accurate. Use `totp_generate` as close to the submission moment as possible.

**Use workflow chains for complex sequences.** If you find yourself calling more than three tools in sequence, define a workflow chain. This gives you error handling, status tracking, and replayability.

**Credential rotation.** Use `credential_refresh` to update a stored credential value without deleting and re-creating. This preserves any flows or API patterns that reference the credential by name.

**Flow adaptation.** `flow_adapt` rewrites a recorded flow's parameters without changing its structure. Use it to switch between environments (e.g., swap base URLs from staging to production) or update credentials referenced in the flow.

**Data piping validation.** Always test transform expressions with `pipe_test` before using them in a workflow chain. This catches syntax errors without triggering downstream side effects.

## Further Reading

- [README](../README.md) --- full tool list, architecture details, and changelog
- [Model Context Protocol specification](https://modelcontextprotocol.io/) --- the protocol Workflow implements
- [Windows DPAPI documentation](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi) --- how credential encryption works under the hood
