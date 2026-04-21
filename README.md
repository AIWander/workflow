# Workflow MCP Server

[![CI](https://github.com/josephwander-arch/workflow/actions/workflows/ci.yml/badge.svg)](https://github.com/josephwander-arch/workflow/actions/workflows/ci.yml)

API pattern storage and replay, DPAPI-encrypted credential vault, data transform pipelines, watch polling, and workflow chains — all through one MCP server. Single Rust binary, 37 tools, zero runtime dependencies.

**Part of [CPC](https://github.com/josephwander-arch) (Copy Paste Compute)** — a multi-agent AI orchestration platform. Related repos: [manager](https://github.com/josephwander-arch/manager) · [local](https://github.com/josephwander-arch/local) · [hands](https://github.com/josephwander-arch/hands) · [cpc-paths](https://github.com/josephwander-arch/cpc-paths) · [cpc-breadcrumbs](https://github.com/josephwander-arch/cpc-breadcrumbs)

**Workflow is the graduation pipeline partner for [hands](https://github.com/josephwander-arch/hands).** Use hands to automate a browser task once, capture the underlying API calls with `hands:browser_learn_api`, store them with `workflow:api_store`, then replay via direct HTTP forever. No browser needed on future runs. 100x faster.

## What's New — v1.3.5

- **v1.3.5** — Clippy + dead_code cleanup: removed 2 crate-level allows, added targeted item-level allows with justification.
- **v1.3.4** — Fixed 69 UTF-8 mojibake sequences in skill reference files (em-dashes + arrows). Documentation-only patch.
- **v1.3.3** — Cargo.toml metadata cleanup (license, repository, description fields).
- **v1.3.1** — Two-Entry sentinel keyring probe on startup. Detects mock backends that don't persist across instances.
- **v1.3.0** — Cross-platform OS keyring storage (Windows Credential Manager, macOS Keychain, Linux Secret Service). `migrate_dpapi_to_keyring` tool for one-time migration from legacy DPAPI. Linux headless guard.

<details>
<summary>Older releases</summary>

- **v1.2.5** — TOTP DPAPI fix + monorepo sync. Null-byte stripping after DPAPI decrypt.
- **v1.2.1** — Meta-tool dispatch fixes, credential round-trip hardening, TOTP module (6 tools).
- **v1.1.1** — Initial public release. 31 tools across 7 modules.

</details>

See [CHANGELOG.md](CHANGELOG.md) for full details.

## The Graduation Pipeline

```
Day 1: Browser automation (hands MCP server)
        ↓ hands:browser_learn_api extracts endpoint patterns from network traffic
Day 2: Store patterns (workflow:api_store)
        ↓ Named pattern with URL template, headers, credential reference
Day N: Direct HTTP replay (workflow:api_call)
        ↓ No browser. No Chrome. No selectors. Just HTTP.
```

**The economics:**
- Browser session: ~3-5 seconds startup + page load + interaction + fragile selectors
- API call: ~50-200ms, no browser process, no DOM, no breakage from UI redesigns

**Production proof:** 24+ stored API patterns in daily use against healthcare payer FHIR endpoints. Once a pattern is stored, future calls run direct-to-HTTP — no browser window opens.

## Capabilities

### PRODUCTION (stable, battle-tested)

| Category | Tools | Description |
|----------|-------|-------------|
| API Patterns | `api_store`, `api_call`, `api_list`, `api_test`, `api_delete` | Store discovered API patterns with URL templates and credential references, replay via direct HTTP |
| Credentials | `credential_store`, `credential_get`, `credential_list`, `credential_delete`, `credential_refresh` | Windows DPAPI-encrypted credential vault. Store by name, reference from API patterns. OAuth refresh support. |
| Transforms | `transform_pipe`, `pipe_test` | JSON transform pipelines: pick, rename, flatten, filter, template, group_by, math. Chain operations sequentially. |
| Watches | `watch_define`, `watch_list`, `watch_check`, `watch_schedule`, `watch_delete` | Define polling conditions, trigger actions when conditions are met |
| Workflows | `workflow_define`, `workflow_run`, `workflow_list`, `workflow_status`, `workflow_delete` | Trigger-action chains composing watches, API calls, and transforms |

### EXPERIMENTAL (functionally complete, not production-validated)

| Category | Tools | Description |
|----------|-------|-------------|
| Flows | `flow_record_start`, `flow_record_step`, `flow_record_stop`, `flow_replay`, `flow_adapt`, `flow_dispatch`, `flow_list`, `flow_delete` | Record and replay multi-step MCP tool sequences. 1 test flow stored, never run in production. Use for prototyping. A follow-up release will harden based on real-world usage. |

**37 tools total** across 7 modules.

## Install

### Windows x64

1. Download `workflow-v1.3.5-x64.exe` from the [latest release](https://github.com/josephwander-arch/workflow/releases/latest).
2. Rename to `workflow.exe` and place in `%LOCALAPPDATA%\CPC\servers\`.
3. Add to your `claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "workflow": {
         "command": "%LOCALAPPDATA%\\CPC\\servers\\workflow.exe"
       }
     }
   }
   ```
4. Restart Claude Desktop.

---

### Windows ARM64

1. Download `workflow-v1.3.5-aarch64.exe` from the [latest release](https://github.com/josephwander-arch/workflow/releases/latest).
2. Rename to `workflow.exe` and place in `%LOCALAPPDATA%\CPC\servers\`.
3. Add to your `claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "workflow": {
         "command": "%LOCALAPPDATA%\\CPC\\servers\\workflow.exe"
       }
     }
   }
   ```
4. Restart Claude Desktop.

---

### Prerequisites

- **Windows 10/11** — credential encryption requires Windows. On other platforms, credentials are stored unencrypted (development/testing only).
- No Node.js, no Python, no runtime dependencies.
- **Keyring integration** — credentials are stored in the OS keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service).

For full per-machine setup (paths, credential vault setup, DPAPI notes), see [`docs/per_machine_setup.md`](./docs/per_machine_setup.md).

### Build from Source

```bash
git clone https://github.com/josephwander-arch/workflow.git
cd workflow
cargo build --release
```

Binary appears at `target/release/workflow.exe`. Requires Rust stable toolchain — nightly is not required.

## Quickstart — The Graduation Flow

This is the core use case. You've been using hands to automate a browser task. Now graduate it to a direct API call.

### Step 1: Discover the API (hands)

```
hands:browser_launch()
hands:browser_navigate(url: "https://portal.example-health.com")
# ... interact with the page ...
hands:browser_learn_api()  → extracts endpoint patterns
```

### Step 2: Store credentials and pattern (workflow)

```
workflow:credential_store(
  name: "payer_token",
  value: "<captured_bearer_token>",
  credential_type: "bearer",
  service: "example_health"
)

workflow:api_store(
  name: "payer_member_search",
  url_pattern: "https://api.example-health.com/fhir/Patient?name={name}",
  method: "GET",
  credential_ref: "payer_token",
  notes: "Discovered via browser_learn_api 2026-03-15"
)
```

### Step 3: Test it

```
workflow:api_test(name: "payer_member_search", params: {"name": "Smith"})
```

### Step 4: Use it forever — no browser

```
workflow:api_call(name: "payer_member_search", params: {"name": "Jones"})
```

When the API breaks (token expired, endpoint changed), the response includes a `fallback_hint` telling you to go back to the browser. Re-discover, re-graduate.

## Key Concepts

### Credential by Reference

Never hardcode tokens in API patterns. Store credentials by name in the DPAPI-encrypted vault, reference them via `credential_ref` in `api_store`. When tokens rotate, update one credential — all patterns that reference it automatically get the new value.

### Execution Model

`flow_replay`, `watch_check`, and `workflow_run` return **execution plans**, not results. They tell your session what tools to call with what parameters. Your session executes the plan. This is by design — workflow doesn't have access to other MCP servers.

### Data Storage

All data lives in `C:\CPC\workflows\` as JSON files with atomic writes (write to `.tmp`, then rename). Safe against crashes mid-write.

## Recommended CLAUDE.md Instructions

See `skills/workflow-recommended-instructions.md` for a copy-paste block to add to your CLAUDE.md. Covers the credential-by-reference mandate, graduation discipline, and experimental flow warnings.

## Examples

See the `examples/` directory:
- `graduation_pipeline.md` — Full hands-to-workflow graduation walkthrough
- `credential_storage.md` — DPAPI vault patterns and token rotation
- `api_pattern_replay.md` — Advanced API patterns with transforms

## Pairs With: hands MCP Server

Workflow and hands are designed as two halves of the same pipeline.

| Scenario | Use |
|----------|-----|
| First time doing a task | hands (browser) |
| Task has a known API pattern | workflow (api_call) |
| API call fails / token expired | hands (browser re-auth) then workflow (credential_store) |
| Need to transform API response | workflow (transform_pipe) |
| Need to poll for changes | workflow (watch_define) |

---

## Compatible With

`workflow` runs standalone for API pattern replay, credential storage, watches, and transform pipelines. It pairs naturally with the rest of the CPC stack when you want end-to-end automation.

- Pair with [hands](https://github.com/josephwander-arch/hands) for browser-side discovery (`browser_learn_api` captures the network traffic that workflow then stores and replays).
- Pair with [local](https://github.com/josephwander-arch/local) when pipelines need local shell, file, or transform steps between API calls.
- Pair with [manager](https://github.com/josephwander-arch/manager) to wrap workflow's replay tools in delegated tasks with breadcrumb tracking.

Host clients: Claude Desktop (`claude_desktop_config.json`), Claude Code (`~/.claude/mcp.json`), OpenAI Codex CLI, Gemini CLI, or any MCP-compatible host. The skill file at `skills/workflow.md` works standalone too — load it as an Anthropic skill for no-server behavioral guidance (planning, review, discipline reminders).

### First-run tip for Claude clients

Turn on **tools always loaded** in Claude's tool settings. Workflow exposes 37 tools across 7 modules — API patterns, credentials, transforms, watches, workflows, flows — and first-run discovery can miss subsets if lazy-loading is on. Always-loaded makes the full surface visible immediately.

## Failure modes

Most workflow failures happen when a stored pattern drifts from the live service. The tools try to detect this and point you back to the right recovery path:

- **Stored API pattern expired (401/403)** — `api_call` response includes a `fallback_hint` pointing back to hands for re-discovery. Re-auth in the browser, `credential_store` the new token, and the same pattern works again.
- **Endpoint moved or schema changed** — `api_call` returns a non-auth error (404, 400, unexpected shape). The pattern itself is stale; re-run `browser_learn_api` on the updated flow and overwrite with `api_store`.
- **Keyring unavailable (Linux headless)** — `credential_store` refuses to store unencrypted secrets on Linux without Secret Service. Install a keyring backend or mark the environment dev-only.
- **Transform pipeline silently drops fields** — usually a `pick` stage with a wrong key. Use `pipe_test` to run the pipeline against a sample payload and inspect each stage's output.
- **Workflow chain stuck** — `workflow_run` returns an execution plan, not results. If a step never executes, confirm the host session is actually dispatching the plan's tool calls.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

Issues welcome; PRs considered but this is primarily maintained as part of the CPC stack.

## Contact

Joseph Wander — josephwander@gmail.com
GitHub: [github.com/josephwander-arch](https://github.com/josephwander-arch/)
