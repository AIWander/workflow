# Contributing to Workflow MCP Server

## How to Contribute

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run `cargo test` and `cargo clippy`
5. Commit with a clear message
6. Open a pull request

## Architecture

Workflow is a single Rust binary that serves MCP over stdio. The codebase is organized into tool modules:

- `src/tools/api.rs` — API pattern storage and replay
- `src/tools/credentials.rs` — DPAPI-encrypted credential vault
- `src/tools/flows.rs` — Flow recording and replay (experimental)
- `src/tools/watches.rs` — Watch/polling definitions
- `src/tools/workflows.rs` — Trigger-action workflow chains
- `src/tools/transforms.rs` — JSON transform pipelines
- `src/tools/lint.rs` — Frontmatter lint query

## Build

```bash
# x64
cargo build --release --target x86_64-pc-windows-msvc

# ARM64
cargo build --release --target aarch64-pc-windows-msvc
```

## Guidelines

- No runtime dependencies beyond Rust std and Windows APIs
- All credential storage must use DPAPI on Windows
- Atomic file writes (write `.tmp`, then rename)
- Every tool must return structured JSON
- Experimental features must be clearly marked in tool descriptions and docs

## Reporting Issues

Open an issue at [github.com/AIWander/workflow](https://github.com/AIWander/workflow/issues) or email josephwander@gmail.com.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
