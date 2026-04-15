//! Credential Vault — OS-native keyring storage (Windows Credential Manager,
//! macOS Keychain, Linux Secret Service). Back-compat read from legacy DPAPI entries.
//! 5 tools: credential_store, credential_get, credential_list, credential_delete, credential_refresh

use crate::keyring_store;
use crate::storage::JsonStore;
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CredentialStore {
    pub credentials: Vec<CredentialMeta>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialMeta {
    pub name: String,
    pub credential_type: String,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at: String,
    /// Legacy DPAPI-encrypted value. Present only in pre-v1.3.0 entries.
    /// Reads fall back to this when keyring has no entry. Run migrate_dpapi_to_keyring to clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_value: Option<String>,
    /// For OAuth refresh
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Legacy DPAPI-encrypted client secret. Cleared on migrate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_encrypted: Option<String>,
}

pub const FILE: &str = "credentials.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
    if keyring_store::is_disabled() {
        return json!({"error": "Credential tools are disabled — keyring unavailable on this system. Set CPC_WORKFLOW_DISABLE_SECRETS=1 suppresses startup exit but disables these tools."});
    }
    match tool {
        "credential_store" => credential_store(args, store),
        "credential_get" => credential_get(args, store),
        "credential_list" => credential_list(args, store),
        "credential_delete" => credential_delete(args, store),
        "credential_refresh" => credential_refresh(args, store),
        _ => json!({"error": format!("Unknown credential tool: {}", tool)}),
    }
}

/// Get a decrypted credential value by name (used by api_store and credential_refresh).
/// Tries keyring first; falls back to DPAPI decrypt of legacy encrypted_value if needed.
pub fn get_credential_value(name: &str, store: &JsonStore) -> Result<String> {
    // Try keyring
    if let Some(v) = keyring_store::get_or_none("cred", name)? {
        return Ok(v);
    }
    // Fall back to legacy DPAPI
    let data: CredentialStore = store.load_or_default(FILE);
    let cred = data.credentials.iter().find(|c| c.name == name)
        .ok_or_else(|| anyhow::anyhow!("Credential '{}' not found", name))?;
    match &cred.encrypted_value {
        Some(enc) => {
            let bytes = base64_decode(enc)?;
            let decrypted = crate::dpapi_legacy::dpapi_decrypt(&bytes)?;
            let trimmed = crate::dpapi_legacy::strip_trailing_nulls(&decrypted);
            Ok(String::from_utf8(trimmed)?)
        }
        None => Err(anyhow::anyhow!("Credential '{}' has no value in keyring or legacy store", name)),
    }
}

/// Get credential type by name.
pub fn get_credential_type(name: &str, store: &JsonStore) -> Option<String> {
    let data: CredentialStore = store.load_or_default(FILE);
    data.credentials.iter().find(|c| c.name == name).map(|c| c.credential_type.clone())
}

fn credential_store(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let value = match args.get("value").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return json!({"error": "value is required"}),
    };
    let credential_type = args.get("credential_type").and_then(|v| v.as_str()).unwrap_or("bearer").to_string();
    let service = args.get("service").and_then(|v| v.as_str()).map(String::from);
    let notes = args.get("notes").and_then(|v| v.as_str()).map(String::from);

    // Store secret in OS keyring
    if let Err(e) = keyring_store::set("cred", &name, value) {
        return json!({"error": format!("Keyring store failed: {}", e)});
    }

    let mut data: CredentialStore = store.load_or_default(FILE);
    data.credentials.retain(|c| c.name != name);

    data.credentials.push(CredentialMeta {
        name: name.clone(),
        credential_type,
        service,
        notes,
        created_at: Utc::now().to_rfc3339(),
        encrypted_value: None, // new entries use keyring only
        token_url: None,
        client_id: None,
        client_secret_encrypted: None,
    });

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "name": name, "hint": "Value stored in OS-native secret store (Windows Credential Manager / macOS Keychain / Linux Secret Service)."}),
        Err(e) => json!({"error": format!("Failed to save metadata: {}", e)}),
    }
}

fn credential_get(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let data: CredentialStore = store.load_or_default(FILE);
    let cred = match data.credentials.iter().find(|c| c.name == name) {
        Some(c) => c,
        None => return json!({"error": format!("Credential '{}' not found", name)}),
    };

    let value = match get_credential_value(name, store) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("Failed to read credential: {}", e)}),
    };

    json!({
        "name": cred.name,
        "value": value,
        "credential_type": cred.credential_type,
        "service": cred.service,
    })
}

fn credential_list(args: &Value, store: &JsonStore) -> Value {
    let data: CredentialStore = store.load_or_default(FILE);
    let service_filter = args.get("service").and_then(|v| v.as_str());

    let creds: Vec<Value> = data.credentials.iter()
        .filter(|c| {
            if let Some(svc) = service_filter {
                c.service.as_deref() == Some(svc)
            } else {
                true
            }
        })
        .map(|c| json!({
            "name": c.name,
            "credential_type": c.credential_type,
            "service": c.service,
            "created_at": c.created_at,
            "legacy_dpapi": c.encrypted_value.is_some(),
        }))
        .collect();

    json!({"credentials": creds, "count": creds.len()})
}

fn credential_delete(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let mut data: CredentialStore = store.load_or_default(FILE);
    let before = data.credentials.len();
    data.credentials.retain(|c| c.name != name);

    if data.credentials.len() == before {
        return json!({"error": format!("Credential '{}' not found", name)});
    }

    // Remove from keyring (no-op if not there)
    let _ = keyring_store::delete("cred", name);
    let _ = keyring_store::delete("cred", &format!("{}:client_secret", name));

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "deleted": name}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn credential_refresh(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };

    let mut data: CredentialStore = store.load_or_default(FILE);
    let cred = match data.credentials.iter_mut().find(|c| c.name == name) {
        Some(c) => c,
        None => return json!({"error": format!("Credential '{}' not found", name)}),
    };

    // Update token_url/client_id if provided
    if let Some(url) = args.get("token_url").and_then(|v| v.as_str()) {
        cred.token_url = Some(url.to_string());
    }
    if let Some(cid) = args.get("client_id").and_then(|v| v.as_str()) {
        cred.client_id = Some(cid.to_string());
    }
    if let Some(cs) = args.get("client_secret").and_then(|v| v.as_str()) {
        if let Err(e) = keyring_store::set("cred", &format!("{}:client_secret", name), cs) {
            return json!({"error": format!("Failed to store client_secret: {}", e)});
        }
        // Clear legacy DPAPI field if it was there
        cred.client_secret_encrypted = None;
    }

    let token_url = match &cred.token_url {
        Some(u) => u.clone(),
        None => return json!({"error": "token_url is required (provide on first refresh, stored after)"}),
    };
    let client_id = match &cred.client_id {
        Some(c) => c.clone(),
        None => return json!({"error": "client_id is required (provide on first refresh, stored after)"}),
    };

    let _ = store.save(FILE, &data);

    // Read current value (refresh token) via keyring with DPAPI fallback
    let refresh_token = match get_credential_value(&name, store) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("Failed to read current credential: {}", e)}),
    };

    // Read client_secret: try keyring first, fall back to legacy DPAPI
    let client_secret = keyring_store::get_or_none("cred", &format!("{}:client_secret", &name))
        .ok().flatten()
        .or_else(|| {
            let data: CredentialStore = store.load_or_default(FILE);
            let cred = data.credentials.iter().find(|c| c.name == name)?;
            let enc = cred.client_secret_encrypted.as_ref()?;
            let bytes = base64_decode(enc).ok()?;
            let decrypted = crate::dpapi_legacy::dpapi_decrypt(&bytes).ok()?;
            let trimmed = crate::dpapi_legacy::strip_trailing_nulls(&decrypted);
            String::from_utf8(trimmed).ok()
        });

    let cred_name = name.clone();

    // Do the OAuth refresh
    let rt = tokio::runtime::Handle::current();
    let result = rt.block_on(async {
        let client = reqwest::Client::new();
        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token),
            ("client_id".to_string(), client_id),
        ];
        if let Some(cs) = client_secret {
            form.push(("client_secret".to_string(), cs));
        }

        match client.post(&token_url).form(&form).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                serde_json::from_str::<Value>(&body).unwrap_or(json!({"raw": body}))
            }
            Err(e) => json!({"error": format!("Refresh request failed: {}", e)}),
        }
    });

    if let Some(new_token) = result.get("access_token").and_then(|v| v.as_str()) {
        // Store the new token in keyring
        if let Err(e) = keyring_store::set("cred", &cred_name, new_token) {
            return json!({"error": format!("Failed to store refreshed token: {}", e)});
        }
        // If the JSON entry had a legacy encrypted_value, clear it since keyring now has the value
        let mut data: CredentialStore = store.load_or_default(FILE);
        if let Some(cred) = data.credentials.iter_mut().find(|c| c.name == cred_name) {
            cred.encrypted_value = None;
        }
        let _ = store.save(FILE, &data);

        let expiry = result.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(0);
        json!({
            "refreshed": true,
            "new_expiry_seconds": expiry,
            "error": null,
        })
    } else {
        json!({
            "refreshed": false,
            "error": result.get("error").or(result.get("raw")).cloned(),
            "hint": "Refresh failed — re-authenticate via browser to get a new token.",
        })
    }
}

// ============ Base64 Helpers (still used by tests and legacy compat) ============

pub fn base64_encode(data: &[u8]) -> String {
    data_encoding::BASE64.encode(data)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    data_encoding::BASE64.decode(clean.as_bytes())
        .map_err(|e| anyhow::anyhow!("Base64 decode error: {}", e))
}

// ============ Legacy detection ============

/// Returns true if any credential entry still has a legacy DPAPI-encrypted value.
pub fn has_legacy_entries(store: &JsonStore) -> bool {
    let data: CredentialStore = store.load_or_default(FILE);
    data.credentials.iter().any(|c| c.encrypted_value.is_some() || c.client_secret_encrypted.is_some())
}
