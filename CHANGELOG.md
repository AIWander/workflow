# Changelog

## v1.3.5 - 2026-04-17

### Changed

- **Clippy + dead_code cleanup** -- removed 2 crate-level `#![allow(...)]` suppressions, replaced with targeted item-level `#[allow(...)]` with justification comments where suppression is still needed.

## v1.3.4 - 2026-04-16

### Fixed
- **`skills/workflow.md`** + **`skills/workflow/skill.md`** — repaired 69 UTF-8 mojibake sequences (48 em-dashes, 21 arrows) that were double-encoded. Rendered text unchanged; source bytes now clean.

### Notes
- No functional changes. Documentation-only patch.

## v1.3.3 - 2026-04-16

### Changed
- Added `license = "Apache-2.0"` field to Cargo.toml (metadata fix caught in pre-Stage-F audit)
- Added `repository` + `description` fields to Cargo.toml

### Notes
- No functional or API changes. Patch release for crates.io metadata cleanup.

## [1.3.1] - 2026-04-15 — Two-Entry Sentinel Probe

### Changed
- **`keyring_store::probe()`** — replaced single-Entry round-trip with a two-Entry sentinel. Writes a timestamped value via one `Entry` instance, drops it, then reads via a fresh `Entry` with the same service+user. Detects mock backends that pass single-Entry round-trips but don't persist across instances. The old comment-only defense in CHANGELOG (noting `features = ["windows-native"]` requirement) is superseded by this runtime check.
- **`docs/per_machine_setup.md`** — added Two-Tier Storage section documenting the metadata/secrets split, startup probe behavior, and per-machine migration steps.
- License: `MIT` → `Apache-2.0` (backport to match other CPC repos).
- Version bumped to `1.3.1`.

### Also includes (Stage C2, previously unreleased)
- **`storage.rs`** — legacy-fallback path resolution: existing `C:\CPC\workflows\` continues to be used; new installs resolve via `cpc_paths::data_path("workflow")`.

### Tests
- Added `test_keyring_probe_succeeds` — calls `probe()` on the live backend, verifies two-Entry persistence round-trip passes.

## [1.3.0] - 2026-04-15 — Cross-Platform OS Keyring + DPAPI Migration Tool

### Added
- **Cross-platform OS keyring storage** — Credentials and TOTP secrets now stored in Windows Credential Manager, macOS Keychain, or Linux Secret Service via the `keyring` crate. Never stored as plaintext in JSON files.
- **`migrate_dpapi_to_keyring` tool** — Idempotent migration from legacy Windows DPAPI storage to OS keyring. Reports `{migrated_credentials, migrated_totp, errors:[]}`. One-time operation after upgrading.
- **cpc-paths v0.1.0 dependency** — Added as diagnostic dep for Stage C cpc-paths integration pass. No path resolution changes; workflow continues to store data at `C:\CPC\workflows\`.
- **Linux headless guard** — On startup, probes keyring availability. If unavailable and `CPC_WORKFLOW_DISABLE_SECRETS=1` is set, credential/TOTP tools disable gracefully. Otherwise exits with clear error message.
- New modules: `keyring_store.rs`, `dpapi_legacy.rs`, `migrate.rs`

### Changed
- `credential.rs` — New entries use keyring only; reads fall back to DPAPI for legacy entries. `CredentialMeta.encrypted_value` is now `Option<String>` (omitted from JSON when None). `client_secret_encrypted` follows same pattern.
- `totp.rs` — Same keyring migration. `TotpEntry.encrypted_secret` is now `Option<String>`. `secret_hash` integrity field retained.
- All 11 tool descriptions updated: "Windows DPAPI" → "OS-native secret store (Windows Credential Manager, macOS Keychain, Linux Secret Service)".
- Version bumped to `1.3.0`.

### Backward Compatibility
- Existing DPAPI-encrypted credentials and TOTP secrets continue to work via transparent fallback — no forced migration.
- Server startup logs a warning if legacy entries are detected: run `workflow:migrate_dpapi_to_keyring` to opt-in to migration.

### Tests
- 16 RFC algorithm tests retained unchanged.
- 3 DPAPI pipeline tests renamed to `test_keyring_roundtrip_*` and updated for keyring storage.
- 6 new tests: `test_keyring_probe_succeeds`, `test_secret_hash_verification`, `test_migration_tool_idempotent`, `test_migration_tool_dpapi_to_keyring` (Windows-only).
- All 22 tests pass.

**Note:** keyring v3 requires explicit `features = ["windows-native"]` — default features use an in-memory mock backend.

## [1.2.5] - 2026-04-15 — TOTP DPAPI Fix + Monorepo Sync

### Fixed
- **TOTP DPAPI roundtrip** (`totp.rs`, `credential.rs`) — strip null bytes after DPAPI decrypt, explicit errors on encrypt/decrypt failure, pipeline tracing. Fixes TOTP codes failing silently after credential storage on some Windows builds.
- **`src/credential.rs`** — hardened error propagation for credential get/store/refresh paths

### Changed
- All 9 source files updated from monorepo HEAD (api_store, credential, flow, main, pipe, storage, totp, watch, workflow)
- `Cargo.toml`: version bumped to `1.2.5` (post-v1.2.2 unified baseline, pre-CI)
- `src/frontmatter.rs` removed (not needed in public distribution)

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
