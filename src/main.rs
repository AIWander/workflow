// Clippy and dead_code blanket allows removed — 2026-04-17 cleanup pass
//! Workflow MCP Server — Orchestration for API discovery, flow recording/replay,
//! credential vault, scheduled watches, workflow chains.
//! 32 tools across 8 modules. Stdio JSON-RPC transport.
//! v1.3.1: Two-entry sentinel probe replaces single-entry probe.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

mod api_store;
mod credential;
mod dashboard_endpoint;
mod dpapi_legacy;
mod flow;
mod keyring_store;
mod migrate;
mod pipe;
mod storage;
mod totp;
mod watch;
mod workflow;

use storage::JsonStore;

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    method: Option<String>,
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

// ============ TOOL DEFINITIONS ============

const CRED_STORE_DESC: &str =
    "Save a credential securely via the OS-native secret store (Windows Credential Manager, \
     macOS Keychain, Linux Secret Service). The value is encrypted by the OS and never stored \
     as plaintext in this server's files.";

const CRED_GET_DESC: &str =
    "Retrieve a stored credential from the OS-native secret store (Windows Credential Manager, \
     macOS Keychain, Linux Secret Service). Only succeeds for the same OS user who stored it.";

const CRED_LIST_DESC: &str = "List stored credentials (names and types only, never values). \
     Entries with legacy_dpapi=true should be migrated via workflow:migrate_dpapi_to_keyring.";

const CRED_DELETE_DESC: &str =
    "Remove a stored credential from both the OS-native secret store and the metadata file.";

const CRED_REFRESH_DESC: &str =
    "Refresh an OAuth token using stored refresh_token. New tokens are stored in the OS-native \
     secret store. Stores token_url/client_id on first use for subsequent refreshes.";

const TOTP_REGISTER_DESC: &str =
    "Register a TOTP/2FA secret for code generation. Secret is stored in the OS-native secret \
     store (Windows Credential Manager, macOS Keychain, Linux Secret Service) — never in plaintext.";

const TOTP_REGISTER_URI_DESC: &str =
    "Register a TOTP/HOTP entry from an otpauth:// URI (as found in QR codes). Parses all \
     parameters automatically. Secret stored in the OS-native secret store.";

const TOTP_GENERATE_DESC: &str =
    "Generate a current TOTP code for a registered entry. Returns the 6/8-digit code and \
     seconds until expiry. Secret retrieved from OS-native secret store.";

const TOTP_LIST_DESC: &str =
    "List all registered TOTP/HOTP entries (names, issuers, accounts). Never returns secrets. \
     Entries with legacy_dpapi=true should be migrated via workflow:migrate_dpapi_to_keyring.";

const TOTP_DELETE_DESC: &str =
    "Remove a registered TOTP/HOTP entry from both the OS-native secret store and metadata file.";

const HOTP_GENERATE_DESC: &str =
    "Generate an HOTP code for a registered HOTP entry. Secret retrieved from OS-native secret \
     store. Auto-increments the counter after generation.";

const MIGRATE_DESC: &str =
    "Migrate legacy Windows DPAPI-encrypted credentials and TOTP secrets to the OS-native keyring. \
     Idempotent — safe to run multiple times. Only needed once after upgrading to v1.3.0. \
     Returns {migrated_credentials, migrated_totp, errors: [...]}.";

fn get_all_tool_definitions() -> Vec<Value> {
    let mut tools = Vec::new();

    // --- API Discovery Storage & Replay (5 tools) ---
    tools.push(tool_def("api_store",
        "Save a discovered API pattern for later replay via HTTP. Store URL patterns with placeholders, headers, auth, and body templates.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Human-readable name, e.g. 'github_list_repos'" },
                "url_pattern": { "type": "string", "description": "URL with {placeholders}, e.g. 'https://api.example.com/users/{id}'" },
                "method": { "type": "string", "description": "HTTP method: GET, POST, PUT, DELETE, PATCH" },
                "headers": { "type": "object", "description": "Request headers (auth tokens, content-type)" },
                "body_template": { "description": "Request body template for POST/PUT" },
                "response_shape": { "type": "array", "items": { "type": "string" }, "description": "Expected response keys" },
                "credential_ref": { "type": "string", "description": "Name of stored credential for auth header" },
                "notes": { "type": "string", "description": "How this API was discovered, what it does" }
            },
            "required": ["name", "url_pattern", "method"]
        })));

    tools.push(tool_def("api_call",
        "Execute a stored API pattern directly via HTTP. Resolves URL placeholders, injects credentials, returns response. On failure includes fallback_hint for browser UI replay.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Name of stored API" },
                "params": { "type": "object", "description": "Values to fill URL placeholders, e.g. {\"id\": \"123\"}" },
                "body": { "description": "Override body template" },
                "headers": { "type": "object", "description": "Additional/override headers" },
                "credential_ref": { "type": "string", "description": "Override credential to use" }
            },
            "required": ["name"]
        })));

    tools.push(tool_def(
        "api_list",
        "List all stored API patterns with name, method, URL pattern, and last used timestamp.",
        json!({
            "type": "object",
            "properties": {
                "filter": { "type": "string", "description": "Regex filter on name or URL" }
            }
        }),
    ));

    tools.push(tool_def("api_test",
        "Validate a stored API still works by making a test call. Returns works/status/response_time.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "API name to test" },
                "params": { "type": "object", "description": "Placeholder values for test call" }
            },
            "required": ["name"]
        })));

    tools.push(tool_def(
        "api_delete",
        "Remove a stored API pattern.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "API name to delete" }
            },
            "required": ["name"]
        }),
    ));

    // --- Credential Vault (5 tools) ---
    tools.push(tool_def("credential_store", CRED_STORE_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Reference name, e.g. 'github_token'" },
                "value": { "type": "string", "description": "The secret value (token, password, API key)" },
                "credential_type": { "type": "string", "enum": ["bearer", "api_key", "basic", "cookie", "custom"], "description": "Type determines how the credential is injected into requests" },
                "service": { "type": "string", "description": "Service name for organization" },
                "notes": { "type": "string", "description": "Description" }
            },
            "required": ["name", "value"]
        })));

    tools.push(tool_def(
        "credential_get",
        CRED_GET_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Credential name to retrieve" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def(
        "credential_list",
        CRED_LIST_DESC,
        json!({
            "type": "object",
            "properties": {
                "service": { "type": "string", "description": "Filter by service" }
            }
        }),
    ));

    tools.push(tool_def(
        "credential_delete",
        CRED_DELETE_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Credential name to delete" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def("credential_refresh", CRED_REFRESH_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Name of the credential to refresh" },
                "token_url": { "type": "string", "description": "OAuth token endpoint (required on first use, stored after)" },
                "client_id": { "type": "string", "description": "OAuth client ID (required on first use, stored after)" },
                "client_secret": { "type": "string", "description": "OAuth client secret (optional, stored in OS keyring)" }
            },
            "required": ["name"]
        })));

    // --- Flow Recording & Replay (8 tools) ---
    tools.push(tool_def(
        "flow_record_start",
        "Begin recording a flow — a replayable sequence of MCP tool calls.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Flow name, e.g. 'login_to_dashboard'" },
                "description": { "type": "string", "description": "What this flow does" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def("flow_record_step",
        "Add a step to the currently recording flow.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Flow name being recorded" },
                "tool_name": { "type": "string", "description": "The MCP tool that was called, e.g. 'hands:browser_click'" },
                "tool_params": { "description": "The params that were passed to the tool" },
                "result_summary": { "type": "string", "description": "Brief summary of what happened" },
                "screenshot_path": { "type": "string", "description": "Path to a checkpoint screenshot" },
                "expected_url": { "type": "string", "description": "Expected URL at this point" },
                "expected_text": { "type": "string", "description": "Expected text visible on page" }
            },
            "required": ["name", "tool_name", "tool_params"]
        })));

    tools.push(tool_def(
        "flow_record_stop",
        "Finish recording a flow. Marks it as ready for replay.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Flow name to stop recording" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def("flow_replay",
        "Replay a recorded flow. Returns step-by-step execution plan for the calling session to execute. Does NOT execute tools directly — returns what to execute.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Flow name to replay" },
                "adapt_on_failure": { "type": "boolean", "default": true, "description": "If a step fails, analyze and suggest adaptation" },
                "dry_run": { "type": "boolean", "default": false, "description": "Just list steps without executing" },
                "start_from_step": { "type": "integer", "description": "Resume from a specific step number" }
            },
            "required": ["name"]
        })));

    tools.push(tool_def("flow_adapt",
        "Analyze a failed flow step and suggest an adapted version. Compare failure against recorded checkpoint.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Flow name" },
                "failed_step": { "type": "integer", "description": "Step index that failed" },
                "screenshot_path": { "type": "string", "description": "Screenshot taken at point of failure" },
                "error_message": { "type": "string", "description": "The error from the failed step" }
            },
            "required": ["name", "failed_step", "screenshot_path", "error_message"]
        })));

    tools.push(tool_def("flow_dispatch",
        "Register a flow to run on a schedule. Creates a dispatch entry for the scheduled-tasks server.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Flow name to dispatch" },
                "schedule": { "type": "string", "description": "Cron expression or interval, e.g. '0 8 * * 1-5' or 'every 2h'" },
                "enabled": { "type": "boolean", "default": true },
                "notify_on_failure": { "type": "boolean", "default": true }
            },
            "required": ["name", "schedule"]
        })));

    tools.push(tool_def(
        "flow_list",
        "List all recorded flows with status, step count, and dispatch info.",
        json!({
            "type": "object",
            "properties": {
                "filter": { "type": "string", "description": "Regex filter on name or description" }
            }
        }),
    ));

    tools.push(tool_def(
        "flow_delete",
        "Remove a recorded flow and its dispatch schedule.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Flow name to delete" }
            },
            "required": ["name"]
        }),
    ));

    // --- Watch / Polling (5 tools) ---
    tools.push(tool_def("watch_define",
        "Define a condition to watch for by polling an MCP tool periodically.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Watch name, e.g. 'check_email_count'" },
                "check_tool": { "type": "string", "description": "MCP tool to call for checking, e.g. 'hands:browser_get_text'" },
                "check_params": { "description": "Params for the check tool" },
                "condition": { "type": "string", "description": "Expression to evaluate against result, e.g. 'result.length > 0' or 'result != last_result'" },
                "action_flow": { "type": "string", "description": "Name of a flow to trigger when condition is true" },
                "poll_interval_seconds": { "type": "integer", "default": 300, "description": "How often to check (default: 5 min)" },
                "active_hours": { "type": "string", "description": "e.g. '08:00-18:00' to only check during business hours" }
            },
            "required": ["name", "check_tool", "check_params", "condition"]
        })));

    tools.push(tool_def(
        "watch_list",
        "List all defined watches with their status, last check time, and poll intervals.",
        json!({
            "type": "object",
            "properties": {}
        }),
    ));

    tools.push(tool_def("watch_check",
        "Manually trigger a watch check now. Returns check instructions for the calling session to execute.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Watch name to check" }
            },
            "required": ["name"]
        })));

    tools.push(tool_def(
        "watch_schedule",
        "Register a watch with the scheduled-tasks server for unattended polling.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Name of a defined watch" },
                "enabled": { "type": "boolean", "default": true }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def(
        "watch_delete",
        "Remove a watch and its schedule.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Watch name to delete" }
            },
            "required": ["name"]
        }),
    ));

    // --- Data Piping (2 tools) ---
    tools.push(tool_def("transform_pipe",
        "Transform JSON data between workflow steps. Apply pick, rename, flatten, filter, template, group_by, and math operations in sequence.",
        json!({
            "type": "object",
            "properties": {
                "input": { "description": "JSON data to transform" },
                "operations": {
                    "type": "array",
                    "description": "Array of transform operations: pick, rename, flatten, filter, template, group_by, math",
                    "items": {
                        "type": "object",
                        "properties": {
                            "op": { "type": "string", "enum": ["pick", "rename", "flatten", "filter", "template", "group_by", "math"] }
                        },
                        "required": ["op"]
                    }
                }
            },
            "required": ["input", "operations"]
        })));

    tools.push(tool_def("pipe_test",
        "Test a transform pipeline with sample data. Optionally shows intermediate results after each step for debugging.",
        json!({
            "type": "object",
            "properties": {
                "input": { "description": "Sample input data" },
                "operations": { "type": "array", "description": "Same as transform_pipe" },
                "show_intermediate": { "type": "boolean", "default": false, "description": "Show result after each step" }
            },
            "required": ["input", "operations"]
        })));

    // --- Workflow Chains (5 tools) ---
    tools.push(tool_def("workflow_define",
        "Define a trigger → action chain. Compose watches, flows, and API calls into automated workflows.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Workflow name, e.g. 'new_invoice_to_sheets'" },
                "trigger": {
                    "type": "object",
                    "description": "Trigger definition",
                    "properties": {
                        "type": { "type": "string", "enum": ["watch", "schedule", "manual"] },
                        "ref": { "type": "string", "description": "Watch name or cron expression" }
                    },
                    "required": ["type"]
                },
                "steps": {
                    "type": "array",
                    "description": "Array of workflow steps",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tool_name": { "type": "string" },
                            "params": {},
                            "on_fail": { "type": "string", "enum": ["stop", "skip", "retry"], "default": "stop" }
                        },
                        "required": ["tool_name"]
                    }
                },
                "description": { "type": "string" }
            },
            "required": ["name", "trigger", "steps"]
        })));

    tools.push(tool_def(
        "workflow_run",
        "Manually execute a workflow. Returns step-by-step execution plan.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Workflow name to run" },
                "start_from": { "type": "integer", "description": "Resume from step N" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def(
        "workflow_list",
        "List all defined workflows with trigger type, step count, and run history.",
        json!({
            "type": "object",
            "properties": {}
        }),
    ));

    tools.push(tool_def(
        "workflow_status",
        "Get detailed status and run history for a workflow.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Workflow name" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def(
        "workflow_delete",
        "Remove a workflow definition.",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Workflow name to delete" }
            },
            "required": ["name"]
        }),
    ));

    // --- TOTP / 2FA (6 tools) ---
    tools.push(tool_def("totp_register", TOTP_REGISTER_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Human-readable name, e.g. 'github_2fa'" },
                "secret": { "type": "string", "description": "Base32-encoded secret (from the 2FA setup page)" },
                "algorithm": { "type": "string", "enum": ["SHA1", "SHA256", "SHA512"], "default": "SHA1", "description": "HMAC algorithm" },
                "digits": { "type": "integer", "enum": [6, 8], "default": 6, "description": "Code length" },
                "period": { "type": "integer", "default": 30, "description": "Time step in seconds" },
                "issuer": { "type": "string", "description": "Service name (e.g. 'GitHub')" },
                "account": { "type": "string", "description": "Account identifier (e.g. 'user@example.com')" }
            },
            "required": ["name", "secret"]
        })));

    tools.push(tool_def("totp_register_from_uri", TOTP_REGISTER_URI_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Human-readable name for this entry" },
                "uri": { "type": "string", "description": "otpauth:// URI, e.g. 'otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub'" }
            },
            "required": ["name", "uri"]
        })));

    tools.push(tool_def(
        "totp_generate",
        TOTP_GENERATE_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Name of the registered TOTP entry" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def(
        "totp_list",
        TOTP_LIST_DESC,
        json!({
            "type": "object",
            "properties": {}
        }),
    ));

    tools.push(tool_def(
        "totp_delete",
        TOTP_DELETE_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Name of the entry to delete" }
            },
            "required": ["name"]
        }),
    ));

    tools.push(tool_def(
        "hotp_generate",
        HOTP_GENERATE_DESC,
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Name of the registered HOTP entry" }
            },
            "required": ["name"]
        }),
    ));

    // --- Migration (1 tool) ---
    tools.push(tool_def(
        "migrate_dpapi_to_keyring",
        MIGRATE_DESC,
        json!({
            "type": "object",
            "properties": {}
        }),
    ));

    tools
}

fn tool_def(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    })
}

// ============ TOOL DISPATCH ============

fn handle_tool_call(name: &str, args: &Value, store: &JsonStore) -> Value {
    match name {
        // API tools
        n @ ("api_store" | "api_call" | "api_list" | "api_test" | "api_delete") => {
            api_store::handle(n, args, store)
        }

        // Credential tools
        n @ ("credential_store" | "credential_get" | "credential_list" | "credential_delete"
        | "credential_refresh") => credential::handle(n, args, store),

        // Flow tools
        n @ ("flow_record_start" | "flow_record_step" | "flow_record_stop" | "flow_replay"
        | "flow_adapt" | "flow_dispatch" | "flow_list" | "flow_delete") => {
            flow::handle(n, args, store)
        }

        // Pipe tools (no store needed)
        n @ ("transform_pipe" | "pipe_test") => pipe::handle(n, args),

        // Watch tools
        n @ ("watch_define" | "watch_list" | "watch_check" | "watch_schedule" | "watch_delete") => {
            watch::handle(n, args, store)
        }

        // Workflow tools
        n @ ("workflow_define" | "workflow_run" | "workflow_list" | "workflow_status"
        | "workflow_delete") => workflow::handle(n, args, store),

        // TOTP / 2FA tools
        n @ ("totp_register"
        | "totp_register_from_uri"
        | "totp_generate"
        | "totp_list"
        | "totp_delete"
        | "hotp_generate") => totp::handle(n, args, store),

        // Migration tool
        "migrate_dpapi_to_keyring" => migrate::migrate_dpapi_to_keyring(store),

        _ => json!({"error": format!("Unknown tool: {}", name)}),
    }
}

// ============ MCP STDIO SERVER ============

fn handle_request(request: &JsonRpcRequest, store: &JsonStore) -> Option<JsonRpcResponse> {
    let id = request.id.clone().unwrap_or(Value::Null);
    let method = request.method.as_deref().unwrap_or("");

    if method.starts_with("notifications/") {
        return None;
    }

    let response = match method {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "workflow",
                    "version": "1.3.2",
                    "description": "Workflow orchestration: API storage/replay, OS-keyring credential vault, flow recording, watches, chains"
                }
            })),
            error: None,
        },

        "tools/list" => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({ "tools": get_all_tool_definitions() })),
            error: None,
        },

        "tools/call" => {
            let params = request.params.as_ref();
            let tool_name = params
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let tool_args = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(json!({}));

            let result = handle_tool_call(tool_name, &tool_args, store);

            JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|_| result.to_string())
                    }]
                })),
                error: None,
            }
        }

        _ => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(json!({
                "code": -32601,
                "message": format!("Method not found: {}", method)
            })),
        },
    };

    Some(response)
}

fn main() {
    // Orphan-process prevention: kill this process tree when parent dies.
    if let Err(e) = cpc_paths::process::ensure_kill_on_parent_death() {
        eprintln!("[warn] job-object setup failed: {e}");
    }

    let _ = std::fs::write(
        std::env::temp_dir().join("workflow_mcp_started.txt"),
        format!(
            "Workflow MCP started at {:?}\nPID: {}\n",
            std::time::SystemTime::now(),
            std::process::id()
        ),
    );

    // Create tokio runtime for async HTTP calls (reqwest)
    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    let _guard = _rt.enter();

    // Spawn HTTP dashboard endpoint (127.0.0.1:9103 by default)
    dashboard_endpoint::spawn();

    let store = JsonStore::new();
    if let Err(e) = store.ensure_dir() {
        eprintln!("[workflow] Failed to create data directory: {}", e);
    }

    // Probe OS keyring availability
    if let Err(e) = keyring_store::probe() {
        if std::env::var("CPC_WORKFLOW_DISABLE_SECRETS").is_ok() {
            eprintln!(
                "[workflow] Keyring unavailable — secrets tools disabled per CPC_WORKFLOW_DISABLE_SECRETS. \
                 Credential and TOTP tools will return errors. Other workflow tools are functional."
            );
            keyring_store::SECRETS_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
        } else {
            eprintln!(
                "[workflow] Keyring unavailable: {}. \
                 Set CPC_WORKFLOW_DISABLE_SECRETS=1 to run without credential tools, \
                 or install gnome-keyring / KeePassXC on Linux.",
                e
            );
            std::process::exit(1);
        }
    }

    // Check for legacy DPAPI entries and warn
    if !keyring_store::is_disabled() {
        migrate::check_and_warn_legacy(&store);
    }

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(response) = handle_request(&request, &store) {
            let response_str = serde_json::to_string(&response).unwrap_or_default();
            let mut out = stdout.lock();
            let _ = writeln!(out, "{}", response_str);
            let _ = out.flush();
        }
    }
}
