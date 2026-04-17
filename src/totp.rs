//! TOTP/HOTP implementation — RFC 6238 / RFC 4226
//! With otpauth:// URI parsing per Google Authenticator spec.
//! Storage via OS-native keyring (v1.3.0+). Legacy DPAPI fallback for pre-v1.3.0 entries.

use crate::credential::base64_decode;
use crate::keyring_store;
use crate::storage::JsonStore;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

type HmacSha1 = Hmac<sha1::Sha1>;
type HmacSha256 = Hmac<sha2::Sha256>;
type HmacSha512 = Hmac<sha2::Sha512>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEntry {
    pub name: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    /// Legacy DPAPI-encrypted secret. Present only in pre-v1.3.0 entries.
    /// New entries store the secret in keyring only (this field is None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_secret: Option<String>,
    #[serde(default)]
    pub counter: Option<u64>,
    pub otp_type: String, // "totp" or "hotp"
    pub created_at: String,
    /// SHA-256 hash of the plaintext base32 secret for integrity verification.
    #[serde(default)]
    pub secret_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TotpStore {
    pub entries: Vec<TotpEntry>,
}

pub const FILE: &str = "totp.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
    if keyring_store::is_disabled() {
        return json!({"error": "TOTP tools are disabled — keyring unavailable on this system."});
    }
    match tool {
        "totp_register" => totp_register(args, store),
        "totp_register_from_uri" => totp_register_from_uri(args, store),
        "totp_generate" => totp_generate(args, store),
        "totp_list" => totp_list(args, store),
        "totp_delete" => totp_delete(args, store),
        "hotp_generate" => hotp_generate(args, store),
        _ => json!({"error": format!("Unknown TOTP tool: {}", tool)}),
    }
}

// ============ CORE ALGORITHM ============

/// Decode a base32-encoded secret to raw bytes.
fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .flat_map(|c| c.to_uppercase())
        .collect();
    data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .map_err(|e| format!("Base32 decode error: {}", e))
}

fn hmac_compute(algorithm: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match algorithm.to_uppercase().as_str() {
        "SHA1" => {
            let mut mac = HmacSha1::new_from_slice(key)
                .map_err(|e| format!("HMAC-SHA1 init error: {}", e))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "SHA256" => {
            let mut mac = HmacSha256::new_from_slice(key)
                .map_err(|e| format!("HMAC-SHA256 init error: {}", e))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "SHA512" => {
            let mut mac = HmacSha512::new_from_slice(key)
                .map_err(|e| format!("HMAC-SHA512 init error: {}", e))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(format!("Unsupported algorithm: {}", algorithm)),
    }
}

fn hotp(secret: &[u8], counter: u64, algorithm: &str, digits: u32) -> Result<String, String> {
    let counter_bytes = counter.to_be_bytes();
    let hash = hmac_compute(algorithm, secret, &counter_bytes)?;

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    let modulus = 10u32.pow(digits);
    let code = binary % modulus;
    Ok(format!("{:0>width$}", code, width = digits as usize))
}

fn totp(
    secret: &[u8],
    time: u64,
    period: u64,
    algorithm: &str,
    digits: u32,
) -> Result<String, String> {
    let counter = time / period;
    hotp(secret, counter, algorithm, digits)
}

// ============ OTPAUTH URI PARSING ============

fn parse_otpauth_uri(uri: &str) -> Result<ParsedUri, String> {
    if !uri.starts_with("otpauth://") {
        return Err("URI must start with otpauth://".into());
    }

    let rest = &uri[10..];

    let (otp_type, rest) = rest.split_once('/').ok_or("Missing OTP type in URI")?;

    let otp_type = otp_type.to_lowercase();
    if otp_type != "totp" && otp_type != "hotp" {
        return Err(format!("Unknown OTP type: {}", otp_type));
    }

    let (label_encoded, query) = if let Some((l, q)) = rest.split_once('?') {
        (l, q)
    } else {
        return Err("Missing query parameters (at least secret is required)".into());
    };

    let label = url_decode(label_encoded);

    let (label_issuer, account) = if let Some((i, a)) = label.split_once(':') {
        (Some(i.to_string()), Some(a.trim().to_string()))
    } else {
        (None, Some(label.to_string()))
    };

    let mut secret = None;
    let mut algorithm = "SHA1".to_string();
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut issuer = label_issuer;
    let mut counter = None;

    for param in query.split('&') {
        if let Some((key, val)) = param.split_once('=') {
            match key.to_lowercase().as_str() {
                "secret" => secret = Some(val.to_string()),
                "algorithm" => algorithm = val.to_uppercase(),
                "digits" => digits = val.parse().unwrap_or(6),
                "period" => period = val.parse().unwrap_or(30),
                "issuer" => issuer = Some(url_decode(val)),
                "counter" => counter = val.parse().ok(),
                _ => {}
            }
        }
    }

    let secret = secret.ok_or("Missing 'secret' parameter in URI")?;
    decode_base32(&secret)?;

    if otp_type == "hotp" && counter.is_none() {
        return Err("HOTP URI requires 'counter' parameter".into());
    }

    Ok(ParsedUri {
        otp_type,
        secret,
        algorithm,
        digits,
        period,
        issuer,
        account,
        counter,
    })
}

struct ParsedUri {
    otp_type: String,
    secret: String,
    algorithm: String,
    digits: u32,
    period: u64,
    issuer: Option<String>,
    account: Option<String>,
    counter: Option<u64>,
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h = chars.next().unwrap_or(0);
            let l = chars.next().unwrap_or(0);
            if let (Some(hv), Some(lv)) = (hex_val(h), hex_val(l)) {
                result.push((hv << 4 | lv) as char);
            } else {
                result.push('%');
                result.push(h as char);
                result.push(l as char);
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============ TOOL HANDLERS ============

fn register_entry(
    name: String,
    secret_base32: &str,
    algorithm: String,
    digits: u32,
    period: u64,
    issuer: Option<String>,
    account: Option<String>,
    otp_type: String,
    counter: Option<u64>,
    store: &JsonStore,
) -> Value {
    if let Err(e) = decode_base32(secret_base32) {
        return json!({"error": format!("Invalid base32 secret: {}", e)});
    }

    // Compute integrity hash before storage
    let secret_hash = sha256_hex(secret_base32.as_bytes());

    // Store secret in OS keyring
    if let Err(e) = keyring_store::set("totp", &name, secret_base32) {
        return json!({"error": format!("Keyring store failed: {}", e)});
    }

    let mut data: TotpStore = store.load_or_default(FILE);
    data.entries.retain(|e| e.name != name);

    data.entries.push(TotpEntry {
        name: name.clone(),
        algorithm,
        digits,
        period,
        issuer: issuer.clone(),
        account: account.clone(),
        encrypted_secret: None, // new entries use keyring only
        counter,
        otp_type: otp_type.clone(),
        created_at: Utc::now().to_rfc3339(),
        secret_hash: Some(secret_hash),
    });

    match store.save(FILE, &data) {
        Ok(_) => json!({
            "success": true,
            "name": name,
            "type": otp_type,
            "issuer": issuer,
            "account": account,
            "hint": "Secret stored in OS-native secret store (Windows Credential Manager / macOS Keychain / Linux Secret Service)."
        }),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn totp_register(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let secret = match args.get("secret").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({"error": "secret (base32) is required"}),
    };
    let algorithm = args
        .get("algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("SHA1")
        .to_uppercase();
    let digits = args.get("digits").and_then(|v| v.as_u64()).unwrap_or(6) as u32;
    let period = args.get("period").and_then(|v| v.as_u64()).unwrap_or(30);
    let issuer = args
        .get("issuer")
        .and_then(|v| v.as_str())
        .map(String::from);
    let account = args
        .get("account")
        .and_then(|v| v.as_str())
        .map(String::from);

    register_entry(
        name,
        secret,
        algorithm,
        digits,
        period,
        issuer,
        account,
        "totp".into(),
        None,
        store,
    )
}

fn totp_register_from_uri(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let uri = match args.get("uri").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return json!({"error": "uri (otpauth://) is required"}),
    };

    let parsed = match parse_otpauth_uri(uri) {
        Ok(p) => p,
        Err(e) => return json!({"error": format!("URI parse error: {}", e)}),
    };

    register_entry(
        name,
        &parsed.secret,
        parsed.algorithm,
        parsed.digits,
        parsed.period,
        parsed.issuer,
        parsed.account,
        parsed.otp_type,
        parsed.counter,
        store,
    )
}

/// Read the TOTP secret for an entry: try keyring first, fall back to legacy DPAPI.
fn get_totp_secret(entry: &TotpEntry) -> Result<String, String> {
    // Try keyring
    match keyring_store::get_or_none("totp", &entry.name) {
        Ok(Some(s)) => return Ok(s),
        Ok(None) => {} // not in keyring — check legacy
        Err(e) => return Err(format!("Keyring read error: {}", e)),
    }

    // Fall back to legacy DPAPI
    match &entry.encrypted_secret {
        Some(enc) => {
            let bytes = base64_decode(enc).map_err(|e| format!("Base64 decode failed: {}", e))?;
            let decrypted = crate::dpapi_legacy::dpapi_decrypt(&bytes)
                .map_err(|e| format!("DPAPI decrypt failed: {}", e))?;
            let trimmed = crate::dpapi_legacy::strip_trailing_nulls(&decrypted);
            let s = String::from_utf8(trimmed)
                .map_err(|e| format!("DPAPI decrypted bytes are not valid UTF-8: {}", e))?;
            let s = s.trim().to_string();
            if s.is_empty() {
                return Err(
                    "DPAPI decrypted to empty string — secret was not stored correctly".into(),
                );
            }
            Ok(s)
        }
        None => Err(format!(
            "TOTP secret for '{}' not found in keyring or legacy store. Re-register the entry.",
            entry.name
        )),
    }
}

fn totp_generate(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let data: TotpStore = store.load_or_default(FILE);
    let entry = match data.entries.iter().find(|e| e.name == name) {
        Some(e) => e,
        None => return json!({"error": format!("TOTP entry '{}' not found", name)}),
    };

    if entry.otp_type == "hotp" {
        return json!({"error": "Use hotp_generate for HOTP entries"});
    }

    let secret_b32 = match get_totp_secret(entry) {
        Ok(s) => s,
        Err(e) => return json!({"error": e}),
    };

    // Integrity check
    if let Some(ref expected_hash) = entry.secret_hash {
        let actual_hash = sha256_hex(secret_b32.as_bytes());
        if actual_hash != *expected_hash {
            eprintln!(
                "[totp] INTEGRITY CHECK FAILED for '{}': hash mismatch\n  expected: {}\n  actual:   {}",
                name, expected_hash, actual_hash
            );
            return json!({
                "error": format!(
                    "Secret integrity check failed for '{}' — stored secret does not match recorded hash. Re-register the secret.",
                    name
                ),
                "hash_expected": expected_hash,
                "hash_actual": actual_hash,
            });
        }
    }

    let secret = match decode_base32(&secret_b32) {
        Ok(s) => s,
        Err(e) => {
            return json!({"error": format!("Base32 decode failed on '{}': {}", secret_b32, e)})
        }
    };

    let now = Utc::now().timestamp() as u64;
    let code = match totp(&secret, now, entry.period, &entry.algorithm, entry.digits) {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("TOTP generation failed: {}", e)}),
    };

    let elapsed = now % entry.period;
    let valid_for = entry.period - elapsed;

    json!({
        "code": code,
        "valid_for_seconds": valid_for,
        "name": name,
        "issuer": entry.issuer,
    })
}

fn totp_list(_args: &Value, store: &JsonStore) -> Value {
    let data: TotpStore = store.load_or_default(FILE);
    let entries: Vec<Value> = data
        .entries
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "type": e.otp_type,
                "algorithm": e.algorithm,
                "digits": e.digits,
                "period": e.period,
                "issuer": e.issuer,
                "account": e.account,
                "created_at": e.created_at,
                "legacy_dpapi": e.encrypted_secret.is_some(),
            })
        })
        .collect();

    json!({"entries": entries, "count": entries.len()})
}

fn totp_delete(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let mut data: TotpStore = store.load_or_default(FILE);
    let before = data.entries.len();
    data.entries.retain(|e| e.name != name);

    if data.entries.len() == before {
        return json!({"error": format!("TOTP entry '{}' not found", name)});
    }

    // Remove from keyring (no-op if not there)
    let _ = keyring_store::delete("totp", name);

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "deleted": name}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn hotp_generate(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };

    let mut data: TotpStore = store.load_or_default(FILE);
    let entry = match data.entries.iter_mut().find(|e| e.name == name) {
        Some(e) => e,
        None => return json!({"error": format!("HOTP entry '{}' not found", name)}),
    };

    if entry.otp_type != "hotp" {
        return json!({"error": "Use totp_generate for TOTP entries"});
    }

    let counter = entry.counter.unwrap_or(0);

    let secret_b32 = match get_totp_secret(entry) {
        Ok(s) => s,
        Err(e) => return json!({"error": e}),
    };

    let secret = match decode_base32(&secret_b32) {
        Ok(s) => s,
        Err(e) => {
            return json!({"error": format!("Base32 decode failed on '{}': {}", secret_b32, e)})
        }
    };

    let code = match hotp(&secret, counter, &entry.algorithm, entry.digits) {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("HOTP generation failed: {}", e)}),
    };

    entry.counter = Some(counter + 1);

    match store.save(FILE, &data) {
        Ok(_) => json!({
            "code": code,
            "counter_used": counter,
            "next_counter": counter + 1,
            "name": name,
        }),
        Err(e) => json!({"error": format!("Failed to save updated counter: {}", e)}),
    }
}

// ============ Helpers ============

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Returns true if any TOTP entry still has a legacy DPAPI-encrypted secret.
pub fn has_legacy_entries(store: &JsonStore) -> bool {
    let data: TotpStore = store.load_or_default(FILE);
    data.entries.iter().any(|e| e.encrypted_secret.is_some())
}

// ============ TESTS ============

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{base64_decode, base64_encode};
    use std::sync::Mutex;

    /// Serialize all tests that touch the shared JSON files on disk.
    /// Prevents load→modify→save races when cargo test runs threads concurrently.
    static STORE_LOCK: Mutex<()> = Mutex::new(());

    const RFC_SECRET_ASCII: &[u8] = b"12345678901234567890";
    const RFC_SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    const RFC_SECRET_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn test_hotp_rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, exp) in expected.iter().enumerate() {
            let code = hotp(RFC_SECRET_ASCII, counter as u64, "SHA1", 6).unwrap();
            assert_eq!(
                &code, exp,
                "HOTP counter={} expected={} got={}",
                counter, exp, code
            );
        }
    }

    #[test]
    fn test_totp_rfc6238_sha1() {
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for &(time, expected) in cases {
            let code = totp(RFC_SECRET_ASCII, time, 30, "SHA1", 8).unwrap();
            assert_eq!(
                code, expected,
                "TOTP SHA1 time={} expected={} got={}",
                time, expected, code
            );
        }
    }

    #[test]
    fn test_totp_rfc6238_sha256() {
        let cases: &[(u64, &str)] = &[
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];
        for &(time, expected) in cases {
            let code = totp(RFC_SECRET_SHA256, time, 30, "SHA256", 8).unwrap();
            assert_eq!(
                code, expected,
                "TOTP SHA256 time={} expected={} got={}",
                time, expected, code
            );
        }
    }

    #[test]
    fn test_totp_rfc6238_sha512() {
        let cases: &[(u64, &str)] = &[
            (59, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];
        for &(time, expected) in cases {
            let code = totp(RFC_SECRET_SHA512, time, 30, "SHA512", 8).unwrap();
            assert_eq!(
                code, expected,
                "TOTP SHA512 time={} expected={} got={}",
                time, expected, code
            );
        }
    }

    #[test]
    fn test_totp_6_digit() {
        let code = totp(RFC_SECRET_ASCII, 59, 30, "SHA1", 6).unwrap();
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_parse_otpauth_totp_uri() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.otp_type, "totp");
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.algorithm, "SHA1");
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
        assert_eq!(parsed.issuer.as_deref(), Some("Example"));
        assert_eq!(parsed.account.as_deref(), Some("alice@google.com"));
        assert!(parsed.counter.is_none());
    }

    #[test]
    fn test_parse_otpauth_hotp_uri() {
        let uri = "otpauth://hotp/Service:user@example.com?secret=JBSWY3DPEHPK3PXP&counter=42";
        let parsed = parse_otpauth_uri(uri).unwrap();
        assert_eq!(parsed.otp_type, "hotp");
        assert_eq!(parsed.counter, Some(42));
    }

    #[test]
    fn test_parse_otpauth_missing_secret() {
        let uri = "otpauth://totp/Test?algorithm=SHA1";
        assert!(parse_otpauth_uri(uri).is_err());
    }

    #[test]
    fn test_parse_otpauth_hotp_missing_counter() {
        let uri = "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP";
        assert!(parse_otpauth_uri(uri).is_err());
    }

    #[test]
    fn test_base32_decode() {
        let decoded = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(&decoded, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_base32_decode_with_spaces_and_lowercase() {
        let decoded = decode_base32("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(&decoded, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_known_totp_code() {
        let secret = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        let code = totp(&secret, 0, 30, "SHA1", 6).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_jbswy3dpehpk3pxp_at_epoch() {
        let secret = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(secret, b"Hello!\xDE\xAD\xBE\xEF");

        let code = totp(&secret, 1776197214, 30, "SHA1", 6).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        let hotp_code = hotp(&secret, 59206573, "SHA1", 6).unwrap();
        assert_eq!(
            code, hotp_code,
            "totp(time/period) must equal hotp(counter)"
        );
        assert_eq!(
            code, "459480",
            "TOTP JBSWY3DPEHPK3PXP@1776197214 should be 459480"
        );
    }

    #[test]
    fn test_strip_trailing_nulls_compat() {
        // Verify the helper still works (used in dpapi_legacy)
        assert_eq!(
            crate::dpapi_legacy::strip_trailing_nulls(b"hello\0\0\0"),
            b"hello"
        );
        assert_eq!(
            crate::dpapi_legacy::strip_trailing_nulls(b"hello"),
            b"hello"
        );
        assert_eq!(crate::dpapi_legacy::strip_trailing_nulls(b""), b"");
    }

    // ── Keyring round-trip tests (adapted from Phase C fix2 DPAPI tests) ──

    #[test]
    fn test_keyring_roundtrip_register_generate() {
        let _g = STORE_LOCK.lock().unwrap();
        // Full pipeline: register → keyring store → retrieve → generate
        let store = JsonStore::new();
        let _ = handle("totp_delete", &json!({"name": "__test_kr_rg__"}), &store);

        let reg = handle(
            "totp_register",
            &json!({
                "name": "__test_kr_rg__",
                "secret": "JBSWY3DPEHPK3PXP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
            }),
            &store,
        );
        assert_eq!(reg["success"], true, "Register failed: {:?}", reg);

        let gen = handle("totp_generate", &json!({"name": "__test_kr_rg__"}), &store);
        assert!(gen.get("error").is_none(), "Generate failed: {:?}", gen);
        let code = gen["code"].as_str().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        let secret_bytes = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        let now = Utc::now().timestamp() as u64;
        let expected = totp(&secret_bytes, now, 30, "SHA1", 6).unwrap();
        assert_eq!(
            code, expected,
            "Keyring pipeline code '{}' != direct code '{}'",
            code, expected
        );

        let _ = handle("totp_delete", &json!({"name": "__test_kr_rg__"}), &store);
    }

    #[test]
    fn test_keyring_roundtrip_from_uri() {
        let _g = STORE_LOCK.lock().unwrap();
        let store = JsonStore::new();
        let _ = handle("totp_delete", &json!({"name": "__test_kr_uri__"}), &store);

        let reg = handle(
            "totp_register_from_uri",
            &json!({
                "name": "__test_kr_uri__",
                "uri": "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
            }),
            &store,
        );
        assert_eq!(reg["success"], true, "URI register failed: {:?}", reg);

        let gen = handle("totp_generate", &json!({"name": "__test_kr_uri__"}), &store);
        assert!(gen.get("error").is_none(), "Generate failed: {:?}", gen);
        let code = gen["code"].as_str().unwrap();

        let secret_bytes = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        let now = Utc::now().timestamp() as u64;
        let expected = totp(&secret_bytes, now, 30, "SHA1", 6).unwrap();
        assert_eq!(
            code, expected,
            "URI pipeline code '{}' != direct code '{}'",
            code, expected
        );

        let _ = handle("totp_delete", &json!({"name": "__test_kr_uri__"}), &store);
    }

    #[test]
    fn test_keyring_no_cross_contamination() {
        let _g = STORE_LOCK.lock().unwrap();
        let store = JsonStore::new();
        let secrets = [
            ("__test_kr_a__", "JBSWY3DPEHPK3PXP"),
            ("__test_kr_b__", "GEZDGNBVGY3TQOJQ"),
        ];

        for (name, secret) in &secrets {
            let _ = handle("totp_delete", &json!({"name": name}), &store);
            let r = handle(
                "totp_register",
                &json!({
                    "name": name, "secret": secret,
                }),
                &store,
            );
            assert_eq!(r["success"], true, "Register failed for {}: {:?}", name, r);
        }

        let now = Utc::now().timestamp() as u64;
        for (name, secret) in &secrets {
            let gen = handle("totp_generate", &json!({"name": name}), &store);
            assert!(
                gen.get("error").is_none(),
                "Generate failed for {}: {:?}",
                name,
                gen
            );
            let code = gen["code"].as_str().unwrap();
            let raw = decode_base32(secret).unwrap();
            let expected = totp(&raw, now, 30, "SHA1", 6).unwrap();
            assert_eq!(
                code, expected,
                "Cross-contamination: {} expected {} got {}",
                name, expected, code
            );
        }

        for (name, _) in &secrets {
            let _ = handle("totp_delete", &json!({"name": name}), &store);
        }
    }

    #[test]
    fn test_keyring_probe_succeeds() {
        // Verify keyring is functional on this platform.
        // Mark #[ignore] in CI environments without a running secret service daemon.
        let result = keyring_store::probe();
        assert!(result.is_ok(), "Keyring probe failed: {:?}", result.err());
    }

    #[test]
    fn test_secret_hash_verification() {
        let _g = STORE_LOCK.lock().unwrap();
        let store = JsonStore::new();
        let _ = handle("totp_delete", &json!({"name": "__test_kr_hash__"}), &store);

        let reg = handle(
            "totp_register",
            &json!({
                "name": "__test_kr_hash__",
                "secret": "JBSWY3DPEHPK3PXP",
            }),
            &store,
        );
        assert_eq!(reg["success"], true, "Register failed: {:?}", reg);

        let data: TotpStore = store.load_or_default(FILE);
        let entry = data
            .entries
            .iter()
            .find(|e| e.name == "__test_kr_hash__")
            .unwrap();
        assert!(entry.secret_hash.is_some(), "secret_hash should be set");
        assert!(
            entry.encrypted_secret.is_none(),
            "encrypted_secret should be None for new entries"
        );

        let gen = handle(
            "totp_generate",
            &json!({"name": "__test_kr_hash__"}),
            &store,
        );
        assert!(gen.get("error").is_none(), "Generate failed: {:?}", gen);

        let _ = handle("totp_delete", &json!({"name": "__test_kr_hash__"}), &store);
    }

    #[test]
    fn test_base64_roundtrip_binary() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            &[0u8; 256],
            &(0..=255).collect::<Vec<u8>>(),
            b"JBSWY3DPEHPK3PXP",
        ];
        for (i, data) in test_cases.iter().enumerate() {
            let encoded = base64_encode(data);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(
                data.to_vec(),
                decoded,
                "Base64 roundtrip failed for case {}: {} bytes",
                i,
                data.len()
            );
        }
    }

    // ── Migration tests ──

    #[test]
    #[cfg(windows)]
    fn test_migration_tool_idempotent() {
        let _g = STORE_LOCK.lock().unwrap();
        // Create a legacy DPAPI-encrypted TOTP entry, run migrate twice, verify idempotent.
        let store = JsonStore::new();
        let test_name = "__test_migrate_totp_idem__";
        let _ = handle("totp_delete", &json!({"name": test_name}), &store);
        let _ = keyring_store::delete("totp", test_name);

        // Create a real DPAPI-encrypted entry directly
        let plaintext_secret = "JBSWY3DPEHPK3PXP";
        let encrypted = crate::dpapi_legacy::dpapi_encrypt(plaintext_secret.as_bytes()).unwrap();
        let encoded = base64_encode(&encrypted);
        let hash = {
            use sha2::Digest;
            sha2::Sha256::digest(plaintext_secret.as_bytes())
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        };

        let mut data: TotpStore = store.load_or_default(FILE);
        data.entries.retain(|e| e.name != test_name);
        data.entries.push(TotpEntry {
            name: test_name.into(),
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
            encrypted_secret: Some(encoded),
            counter: None,
            otp_type: "totp".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            secret_hash: Some(hash),
        });
        store.save(FILE, &data).unwrap();

        // Run migration twice
        let r1 = crate::migrate::migrate_dpapi_to_keyring(&store);
        assert!(
            r1.get("errors")
                .and_then(|e| e.as_array())
                .map_or(true, |a| a.is_empty()),
            "Migration 1 had errors: {:?}",
            r1
        );
        assert!(
            r1["migrated_totp"].as_u64().unwrap_or(0) >= 1,
            "Expected at least 1 TOTP migrated: {:?}",
            r1
        );

        let r2 = crate::migrate::migrate_dpapi_to_keyring(&store);
        assert!(
            r2.get("errors")
                .and_then(|e| e.as_array())
                .map_or(true, |a| a.is_empty()),
            "Migration 2 (idempotent) had errors: {:?}",
            r2
        );
        assert_eq!(
            r2["migrated_totp"].as_u64().unwrap_or(99),
            0,
            "Expected 0 TOTP migrated on second run: {:?}",
            r2
        );

        // Verify keyring has the secret
        let kr = keyring_store::get("totp", test_name).unwrap();
        assert_eq!(
            kr, plaintext_secret,
            "Keyring secret mismatch after migration"
        );

        // Verify JSON no longer has encrypted_secret
        let data2: TotpStore = store.load_or_default(FILE);
        let e = data2.entries.iter().find(|e| e.name == test_name).unwrap();
        assert!(
            e.encrypted_secret.is_none(),
            "encrypted_secret should be cleared after migration"
        );

        // Cleanup
        let _ = handle("totp_delete", &json!({"name": test_name}), &store);
    }

    #[test]
    #[cfg(windows)]
    fn test_migration_tool_dpapi_to_keyring() {
        let _g = STORE_LOCK.lock().unwrap();
        // Create a DPAPI-encrypted credential entry, run migrate, verify keyring has plaintext.
        use crate::credential::{CredentialMeta, CredentialStore};
        let store = JsonStore::new();
        let test_name = "__test_migrate_cred__";
        let _ = keyring_store::delete("cred", test_name);

        let plaintext = "super_secret_value_12345";
        let encrypted = crate::dpapi_legacy::dpapi_encrypt(plaintext.as_bytes()).unwrap();
        let encoded = base64_encode(&encrypted);

        let mut cdata: CredentialStore = store.load_or_default(crate::credential::FILE);
        cdata.credentials.retain(|c| c.name != test_name);
        cdata.credentials.push(CredentialMeta {
            name: test_name.into(),
            credential_type: "bearer".into(),
            service: None,
            notes: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            encrypted_value: Some(encoded),
            token_url: None,
            client_id: None,
            client_secret_encrypted: None,
        });
        store.save(crate::credential::FILE, &cdata).unwrap();

        let result = crate::migrate::migrate_dpapi_to_keyring(&store);
        assert!(
            result
                .get("errors")
                .and_then(|e| e.as_array())
                .map_or(true, |a| a.is_empty()),
            "Migration had errors: {:?}",
            result
        );
        assert!(
            result["migrated_credentials"].as_u64().unwrap_or(0) >= 1,
            "Expected at least 1 credential migrated: {:?}",
            result
        );

        let kr = keyring_store::get("cred", test_name).unwrap();
        assert_eq!(
            kr, plaintext,
            "Keyring value mismatch: expected '{}', got '{}'",
            plaintext, kr
        );

        let cdata2: CredentialStore = store.load_or_default(crate::credential::FILE);
        let c = cdata2
            .credentials
            .iter()
            .find(|c| c.name == test_name)
            .unwrap();
        assert!(
            c.encrypted_value.is_none(),
            "encrypted_value should be cleared after migration"
        );

        // Cleanup
        let _ = keyring_store::delete("cred", test_name);
        let mut cdata3: CredentialStore = store.load_or_default(crate::credential::FILE);
        cdata3.credentials.retain(|c| c.name != test_name);
        let _ = store.save(crate::credential::FILE, &cdata3);
    }
}
