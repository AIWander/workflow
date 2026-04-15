//! Credential Vault — DPAPI-encrypted credential storage
//! 5 tools: credential_store, credential_get, credential_list, credential_delete, credential_refresh

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
    /// Base64-encoded DPAPI-encrypted value
    pub encrypted_value: String,
    /// For OAuth refresh
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret_encrypted: Option<String>,
}

const FILE: &str = "credentials.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
    match tool {
        "credential_store" => credential_store(args, store),
        "credential_get" => credential_get(args, store),
        "credential_list" => credential_list(args, store),
        "credential_delete" => credential_delete(args, store),
        "credential_refresh" => credential_refresh(args, store),
        _ => json!({"error": format!("Unknown credential tool: {}", tool)}),
    }
}

/// Helper: get a decrypted credential value by name (used by api_store)
pub fn get_credential_value(name: &str, store: &JsonStore) -> Result<String> {
    let data: CredentialStore = store.load_or_default(FILE);
    let cred = data.credentials.iter().find(|c| c.name == name)
        .ok_or_else(|| anyhow::anyhow!("Credential '{}' not found", name))?;
    let encrypted = base64_decode(&cred.encrypted_value)?;
    let decrypted = dpapi_decrypt(&encrypted)?;
    Ok(String::from_utf8(decrypted)?)
}

/// Helper: get credential type by name
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

    // Encrypt with DPAPI
    let encrypted = match dpapi_encrypt(value.as_bytes()) {
        Ok(e) => e,
        Err(e) => return json!({"error": format!("Encryption failed: {}", e)}),
    };
    let encoded = base64_encode(&encrypted);

    let mut data: CredentialStore = store.load_or_default(FILE);
    data.credentials.retain(|c| c.name != name);

    data.credentials.push(CredentialMeta {
        name: name.clone(),
        credential_type,
        service,
        notes,
        created_at: Utc::now().to_rfc3339(),
        encrypted_value: encoded,
        token_url: None,
        client_id: None,
        client_secret_encrypted: None,
    });

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "name": name, "hint": "Value encrypted via DPAPI — only this Windows user can decrypt it."}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
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

    let encrypted = match base64_decode(&cred.encrypted_value) {
        Ok(e) => e,
        Err(e) => return json!({"error": format!("Base64 decode failed: {}", e)}),
    };

    let decrypted = match dpapi_decrypt(&encrypted) {
        Ok(d) => d,
        Err(e) => return json!({"error": format!("Decryption failed: {}", e)}),
    };

    let value = String::from_utf8(decrypted).unwrap_or_else(|_| "<binary>".into());

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

    // Update token_url/client_id if provided (stored for future refreshes)
    if let Some(url) = args.get("token_url").and_then(|v| v.as_str()) {
        cred.token_url = Some(url.to_string());
    }
    if let Some(cid) = args.get("client_id").and_then(|v| v.as_str()) {
        cred.client_id = Some(cid.to_string());
    }
    if let Some(cs) = args.get("client_secret").and_then(|v| v.as_str()) {
        if let Ok(enc) = dpapi_encrypt(cs.as_bytes()) {
            cred.client_secret_encrypted = Some(base64_encode(&enc));
        }
    }

    let token_url = match &cred.token_url {
        Some(u) => u.clone(),
        None => return json!({"error": "token_url is required (provide on first refresh, stored after)"}),
    };
    let client_id = match &cred.client_id {
        Some(c) => c.clone(),
        None => return json!({"error": "client_id is required (provide on first refresh, stored after)"}),
    };

    // Get current value as refresh token
    let refresh_token = match base64_decode(&cred.encrypted_value)
        .and_then(|e| dpapi_decrypt(&e))
        .and_then(|d| String::from_utf8(d).map_err(|e| anyhow::anyhow!("{}", e)))
    {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("Failed to read current credential: {}", e)}),
    };

    let client_secret = cred.client_secret_encrypted.as_ref().and_then(|enc| {
        base64_decode(enc).ok().and_then(|e| dpapi_decrypt(&e).ok())
            .and_then(|d| String::from_utf8(d).ok())
    });

    let cred_name = cred.name.clone();
    let _ = store.save(FILE, &data);

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
        // Store the new token
        if let Ok(encrypted) = dpapi_encrypt(new_token.as_bytes()) {
            let mut data: CredentialStore = store.load_or_default(FILE);
            if let Some(cred) = data.credentials.iter_mut().find(|c| c.name == cred_name) {
                cred.encrypted_value = base64_encode(&encrypted);
            }
            let _ = store.save(FILE, &data);
        }
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

// ============ DPAPI Helpers ============

#[cfg(windows)]
pub fn dpapi_encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    unsafe {
        CryptProtectData(
            &mut input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;

        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        Ok(result)
    }
}

#[cfg(windows)]
pub fn dpapi_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    unsafe {
        CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;

        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        Ok(result)
    }
}

#[cfg(not(windows))]
pub fn dpapi_encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    // Non-Windows fallback: no encryption (development only)
    Ok(plaintext.to_vec())
}

#[cfg(not(windows))]
pub fn dpapi_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    Ok(ciphertext.to_vec())
}

pub fn base64_encode(data: &[u8]) -> String {
    // Phase C fix3: replaced custom base64 with data_encoding::BASE64 to eliminate
    // potential encode/decode roundtrip corruption (suspected root cause of TOTP bug).
    data_encoding::BASE64.encode(data)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    // Phase C fix3: replaced custom base64 with data_encoding::BASE64.
    // Tolerant decode: strip whitespace before decoding.
    let clean: String = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    data_encoding::BASE64.decode(clean.as_bytes())
        .map_err(|e| anyhow::anyhow!("Base64 decode error: {}", e))
}
