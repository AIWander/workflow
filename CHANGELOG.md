# Changelog

## [1.2.1] - 2026-04-15 — Phase C Fix3

### Fixed
- **Meta-tool dispatch fixes** — inline atomic rewrites replace nested dispatch pattern that caused double-execution in flow replay
- **Credential round-trip** — DPAPI null-byte stripping and explicit error messages on decrypt failure

### Added
- **TOTP module** (`totp.rs`) — `totp_register`, `totp_register_from_uri`, `totp_generate`, `totp_list`, `totp_delete`, `hotp_generate`. HMAC-based one-time passwords with DPAPI-encrypted secret storage.

## v1.1.1 — 2026-04-11

Initial public release. 31 tools across 7 modules.

### PRODUCTION (stable, battle-tested)

- **API Pattern Storage & Replay** — `api_store`, `api_call`, `api_list`, `api_test`, `api_delete`. Store discovered API patterns with URL templates, credential references, and placeholder substitution. Replay via direct HTTP. 24+ patterns in daily production use across Humana, Aetna, and UnitedHealthcare/Optum FHIR endpoints.
- **Credential Vault** — `credential_store`, `credential_get`, `credential_list`, `credential_delete`, `credential_refresh`. Windows DPAPI-encrypted credential storage. Credentials referenced by name from API patterns — rotate once, all patterns follow. OAuth refresh_token flow with automatic token endpoint storage.
- **Data Transform Pipelines** — `transform_pipe`, `pipe_test`. JSON transform chains: pick, rename, flatten, filter, template, group_by, math. Sequential operation chaining with intermediate result inspection.
- **Watch / Polling** — `watch_define`, `watch_list`, `watch_check`, `watch_schedule`, `watch_delete`. Define polling conditions with check tools, condition expressions, active hours, and action flow triggers.
- **Workflow Chains** — `workflow_define`, `workflow_run`, `workflow_list`, `workflow_status`, `workflow_delete`. Trigger-action chains composing watches, API calls, and transforms. Per-step failure handling (stop/skip/retry).
- **Frontmatter Lint** — `frontmatter_lint_query`. Read-only query against the CPC frontmatter lint report (summary, file, drift modes).

### EXPERIMENTAL (functionally complete, not production-validated)

- **Flow Recording & Replay** — `flow_record_start`, `flow_record_step`, `flow_record_stop`, `flow_replay`, `flow_adapt`, `flow_dispatch`, `flow_list`, `flow_delete`. Record multi-step MCP tool sequences and replay them as execution plans. Adaptive replay with failure analysis. 1 test flow stored to date, never run in production. Use for prototyping. A follow-up release will harden based on real-world usage.

### Infrastructure

- Atomic JSON file writes (write `.tmp`, then rename) — safe against mid-write crashes
- DPAPI encryption for all credential values on Windows; unencrypted fallback on non-Windows (dev only)
- `fallback_hint` in API call failures directing back to browser re-discovery
- All data stored in `C:\CPC\workflows\` as flat JSON files
- Single Rust binary, zero runtime dependencies
- ARM64 and x64 native builds
