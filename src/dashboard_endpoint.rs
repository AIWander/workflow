//! HTTP dashboard endpoint for the workflow server.
//!
//! GET /api/status → JSON: credentials, totp, api_patterns, flows, watches
//!
//! Port: CPC_DASHBOARD_PORT_WORKFLOW env var, default 9103.
//! Binds 127.0.0.1 only. Falls back through +5 ports if primary is taken.
//! Graceful: if all ports fail, logs a warning — MCP continues normally.
//!
//! SECURITY: credential names are safe identifiers (e.g. "github_token").
//! NEVER include credential values, secrets, or tokens in any response.

use serde_json::{json, Value};
use std::thread;

use crate::api_store::ApiStore;
use crate::credential::CredentialStore;
use crate::flow::FlowStore;
use crate::storage::JsonStore;
use crate::totp::TotpStore;
use crate::watch::WatchStore;

const DEFAULT_PORT: u16 = 9103;
const ENV_PORT: &str = "CPC_DASHBOARD_PORT_WORKFLOW";

/// Spawn the dashboard HTTP server on an isolated thread.
pub fn spawn() {
    thread::Builder::new()
        .name("workflow-dashboard".into())
        .spawn(move || {
            let base_port: u16 = std::env::var(ENV_PORT)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_PORT);

            let server = match try_bind(base_port) {
                Some(s) => s,
                None => {
                    eprintln!(
                        "[workflow/dashboard] Could not bind on ports {}–{}. \
                         MCP continues without dashboard endpoint.",
                        base_port,
                        base_port + 5
                    );
                    return;
                }
            };

            let port = server
                .server_addr()
                .to_ip()
                .map(|a| a.port())
                .unwrap_or(base_port);
            eprintln!(
                "[workflow/dashboard] Listening on http://127.0.0.1:{}/api/status",
                port
            );

            for request in server.incoming_requests() {
                handle_request(request);
            }
        })
        .ok();
}

fn try_bind(base_port: u16) -> Option<tiny_http::Server> {
    for port in base_port..base_port + 6 {
        let addr = format!("127.0.0.1:{}", port);
        if let Ok(s) = tiny_http::Server::http(&addr) {
            return Some(s);
        }
    }
    None
}

fn cors_headers() -> Vec<tiny_http::Header> {
    vec![
        "Access-Control-Allow-Origin: *".parse().unwrap(),
        "Access-Control-Allow-Methods: GET, OPTIONS"
            .parse()
            .unwrap(),
        "Access-Control-Allow-Headers: Content-Type"
            .parse()
            .unwrap(),
        "Content-Type: application/json".parse().unwrap(),
    ]
}

fn respond(request: tiny_http::Request, status: u16, body: Value) {
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let mut response = tiny_http::Response::from_string(body_str).with_status_code(status);
    for h in cors_headers() {
        response = response.with_header(h);
    }
    let _ = request.respond(response);
}

fn handle_request(request: tiny_http::Request) {
    let method = request.method().as_str().to_uppercase();
    let url = request.url().split('?').next().unwrap_or("").to_string();

    match (method.as_str(), url.as_str()) {
        ("GET", "/api/status") => respond(request, 200, build_status()),
        ("OPTIONS", _) => respond(request, 204, json!({})),
        _ => respond(request, 404, json!({"error": "Not found"})),
    }
}

// ── Status builder ─────────────────────────────────────────────────────────────

fn build_status() -> Value {
    let store = JsonStore::new();

    json!({
        "server": "workflow",
        "version": "1.3.2",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "credentials": build_credentials(&store),
        "totp": build_totp(&store),
        "api_patterns": build_api_patterns(&store),
        "flows": build_flows(&store),
        "watches": build_watches(&store),
    })
}

fn build_credentials(store: &JsonStore) -> Value {
    let data: CredentialStore = store.load_or_default("credentials.json");
    let count = data.credentials.len();

    let mut by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for c in &data.credentials {
        *by_type.entry(c.credential_type.clone()).or_insert(0) += 1;
    }

    // Names only — NEVER values
    let names: Vec<&str> = data.credentials.iter().map(|c| c.name.as_str()).collect();

    json!({
        "count": count,
        "by_type": by_type,
        "names": names
    })
}

fn build_totp(store: &JsonStore) -> Value {
    let data: TotpStore = store.load_or_default("totp.json");
    let count = data.entries.len();

    let entries: Vec<Value> = data
        .entries
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "issuer": e.issuer,
                "account": e.account
            })
        })
        .collect();

    json!({
        "count": count,
        "entries": entries
    })
}

fn build_api_patterns(store: &JsonStore) -> Value {
    let data: ApiStore = store.load_or_default("apis.json");
    let count = data.apis.len();

    let last_used = data
        .apis
        .iter()
        .filter_map(|a| a.last_used.as_deref())
        .max()
        .map(String::from);

    json!({
        "count": count,
        "last_used": last_used
    })
}

fn build_flows(store: &JsonStore) -> Value {
    let data: FlowStore = store.load_or_default("flows.json");
    let count = data.flows.len();

    // Find the most recently run flow
    let last_run = data
        .flows
        .iter()
        .filter_map(|f| {
            f.last_run
                .as_deref()
                .map(|ts| (f.name.as_str(), f.last_result.as_deref(), ts))
        })
        .max_by_key(|(_, _, ts)| *ts)
        .map(|(name, result, ts)| {
            json!({
                "name": name,
                "status": result.unwrap_or("unknown"),
                "ts": ts
            })
        });

    json!({
        "count": count,
        "last_run": last_run
    })
}

fn build_watches(store: &JsonStore) -> Value {
    let data: WatchStore = store.load_or_default("watches.json");
    let active_count = data.watches.iter().filter(|w| w.is_active).count();

    let watches: Vec<Value> = data
        .watches
        .iter()
        .map(|w| {
            json!({
                "name": w.name,
                "last_check": w.last_check,
                "condition": w.condition
            })
        })
        .collect();

    json!({
        "active_count": active_count,
        "watches": watches
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_has_required_fields() {
        let status = build_status();
        assert_eq!(status["server"], "workflow");
        assert_eq!(status["version"], "1.3.2");
        assert!(status["timestamp"].is_string());
        assert!(status["credentials"].is_object());
        assert!(status["credentials"]["count"].is_number());
        assert!(status["totp"].is_object());
        assert!(status["api_patterns"].is_object());
        assert!(status["flows"].is_object());
        assert!(status["watches"].is_object());
        assert!(status["watches"]["active_count"].is_number());
    }

    #[test]
    fn test_port_fallback_range() {
        let base = DEFAULT_PORT;
        let range: Vec<u16> = (base..base + 6).collect();
        assert_eq!(range.len(), 6);
        assert_eq!(range[0], 9103);
        assert_eq!(range[5], 9108);
    }

    #[test]
    fn test_credentials_never_includes_values() {
        // The credential status must not expose any value/secret/token fields.
        let store = JsonStore::new();
        let creds = build_credentials(&store);
        let cred_str = serde_json::to_string(&creds).unwrap_or_default();
        // "names" is fine, but the actual values should never appear.
        assert!(
            !cred_str.contains("\"value\""),
            "credential values must not appear in status"
        );
        assert!(
            !cred_str.contains("\"secret\""),
            "secrets must not appear in status"
        );
    }
}
