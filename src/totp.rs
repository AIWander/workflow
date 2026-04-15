//! TOTP/HOTP implementation — RFC 6238 / RFC 4226
//! With otpauth:// URI parsing per Google Authenticator spec.
//! Storage via DPAPI-protected credential store.

use crate::credential::{dpapi_encrypt, dpapi_decrypt, base64_encode, base64_decode};
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
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub encrypted_secret: String,
    pub counter: Option<u64>,
    pub otp_type: String, // "totp" or "hotp"
    pub created_at: String,
    /// SHA-256 hash of the plaintext base32 secret for integrity verification.
    /// Added in Phase C fix3 to detect DPAPI roundtrip corruption.
    #[serde(default)]
    pub secret_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TotpStore {
    pub entries: Vec<TotpEntry>,
}

const FILE: &str = "totp.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
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
    // Strip spaces and uppercase
    let clean: String = input.chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .flat_map(|c| c.to_uppercase())
        .collect();
    data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .map_err(|e| format!("Base32 decode error: {}", e))
}

/// Compute HMAC with the specified algorithm.
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

/// HOTP: RFC 4226 — HMAC-based One-Time Password
fn hotp(secret: &[u8], counter: u64, algorithm: &str, digits: u32) -> Result<String, String> {
    let counter_bytes = counter.to_be_bytes();
    let hash = hmac_compute(algorithm, secret, &counter_bytes)?;

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    let modulus = 10u32.pow(digits);
    let code = binary % modulus;
    Ok(format!("{:0>width$}", code, width = digits as usize))
}

/// TOTP: RFC 6238 — Time-based One-Time Password
fn totp(secret: &[u8], time: u64, period: u64, algorithm: &str, digits: u32) -> Result<String, String> {
    let counter = time / period;
    hotp(secret, counter, algorithm, digits)
}

// ============ OTPAUTH URI PARSING ============

/// Parse an otpauth:// URI into components.
/// Format: otpauth://TYPE/LABEL?PARAMS
/// LABEL can be ISSUER:ACCOUNT or just ACCOUNT
fn parse_otpauth_uri(uri: &str) -> Result<ParsedUri, String> {
    if !uri.starts_with("otpauth://") {
        return Err("URI must start with otpauth://".into());
    }

    let rest = &uri[10..]; // skip "otpauth://"

    // Split type from label+params
    let (otp_type, rest) = rest.split_once('/')
        .ok_or("Missing OTP type in URI")?;

    let otp_type = otp_type.to_lowercase();
    if otp_type != "totp" && otp_type != "hotp" {
        return Err(format!("Unknown OTP type: {}", otp_type));
    }

    // Split label from query params
    let (label_encoded, query) = if let Some((l, q)) = rest.split_once('?') {
        (l, q)
    } else {
        return Err("Missing query parameters (at least secret is required)".into());
    };

    // URL-decode the label
    let label = url_decode(label_encoded);

    // Parse issuer:account from label
    let (label_issuer, account) = if let Some((i, a)) = label.split_once(':') {
        (Some(i.to_string()), Some(a.trim().to_string()))
    } else {
        (None, Some(label.to_string()))
    };

    // Parse query parameters
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
                _ => {} // ignore unknown params
            }
        }
    }

    let secret = secret.ok_or("Missing 'secret' parameter in URI")?;

    // Validate the secret is valid base32
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

/// Minimal percent-decoding for URI labels.
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
    // Validate secret
    if let Err(e) = decode_base32(secret_base32) {
        return json!({"error": format!("Invalid base32 secret: {}", e)});
    }

    // Compute integrity hash BEFORE encryption
    let secret_hash = sha256_hex(secret_base32.as_bytes());

    // Encrypt secret with DPAPI
    let encrypted = match dpapi_encrypt(secret_base32.as_bytes()) {
        Ok(e) => e,
        Err(e) => return json!({"error": format!("Encryption failed: {}", e)}),
    };
    let encoded = base64_encode(&encrypted);

    // Phase C fix3: roundtrip self-test — immediately decrypt and verify
    {
        let rt_encrypted = match base64_decode(&encoded) {
            Ok(e) => e,
            Err(e) => return json!({"error": format!("Roundtrip base64 decode failed: {}", e)}),
        };
        let rt_decrypted = match dpapi_decrypt(&rt_encrypted) {
            Ok(d) => d,
            Err(e) => return json!({"error": format!("Roundtrip DPAPI decrypt failed: {}", e)}),
        };
        let rt_trimmed = strip_trailing_nulls(&rt_decrypted);
        let rt_hash = sha256_hex(&rt_trimmed);
        if rt_hash != secret_hash {
            eprintln!(
                "[totp] ROUNDTRIP CORRUPTION DETECTED!\n  original ({} bytes): {:02x?}\n  recovered ({} bytes): {:02x?}",
                secret_base32.as_bytes().len(), &secret_base32.as_bytes()[..secret_base32.len().min(32)],
                rt_trimmed.len(), &rt_trimmed[..rt_trimmed.len().min(32)]
            );
            return json!({
                "error": "DPAPI roundtrip corruption detected — encrypted secret does not decrypt to original. This may indicate a Windows encoding issue.",
                "original_len": secret_base32.len(),
                "recovered_len": rt_trimmed.len(),
                "hash_expected": secret_hash,
                "hash_got": rt_hash,
            });
        }
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
        encrypted_secret: encoded,
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
            "hint": "Secret encrypted via DPAPI — only this Windows user can generate codes."
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
    let algorithm = args.get("algorithm").and_then(|v| v.as_str()).unwrap_or("SHA1").to_uppercase();
    let digits = args.get("digits").and_then(|v| v.as_u64()).unwrap_or(6) as u32;
    let period = args.get("period").and_then(|v| v.as_u64()).unwrap_or(30);
    let issuer = args.get("issuer").and_then(|v| v.as_str()).map(String::from);
    let account = args.get("account").and_then(|v| v.as_str()).map(String::from);

    register_entry(name, secret, algorithm, digits, period, issuer, account, "totp".into(), None, store)
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

    // Decrypt secret — trace each pipeline stage for diagnosis
    let encrypted = match base64_decode(&entry.encrypted_secret) {
        Ok(e) => {
            eprintln!("[totp] base64_decode: {} bytes from stored secret", e.len());
            e
        }
        Err(e) => return json!({"error": format!("Base64 decode failed: {}", e)}),
    };
    let decrypted = match dpapi_decrypt(&encrypted) {
        Ok(d) => {
            eprintln!("[totp] dpapi_decrypt: {} bytes, hex[..16]: {:02x?}",
                d.len(), &d[..d.len().min(16)]);
            d
        }
        Err(e) => return json!({"error": format!("Decryption failed: {}", e)}),
    };
    // Strip trailing null bytes (DPAPI may pad) and validate UTF-8
    let trimmed = strip_trailing_nulls(&decrypted);
    let secret_b32 = match String::from_utf8(trimmed) {
        Ok(s) => {
            eprintln!("[totp] recovered base32 string: '{}' ({} chars)", s, s.len());
            s
        }
        Err(e) => return json!({"error": format!(
            "DPAPI decrypted {} bytes but they are not valid UTF-8: {}. \
             Hex: {:02x?}",
            decrypted.len(), e, &decrypted[..decrypted.len().min(32)]
        )}),
    };
    let secret_b32 = secret_b32.trim().to_string();
    if secret_b32.is_empty() {
        return json!({"error": "DPAPI decrypted to empty string — secret was not stored correctly"});
    }

    // Phase C fix3: verify integrity hash if available
    if let Some(ref expected_hash) = entry.secret_hash {
        let actual_hash = sha256_hex(secret_b32.as_bytes());
        if actual_hash != *expected_hash {
            eprintln!(
                "[totp] INTEGRITY CHECK FAILED for '{}': hash mismatch\n  expected: {}\n  actual:   {}\n  recovered b32: '{}'",
                name, expected_hash, actual_hash, secret_b32
            );
            return json!({
                "error": format!(
                    "Secret integrity check failed for '{}' — DPAPI decrypted bytes do not match stored hash. Re-register the secret.",
                    name
                ),
                "hash_expected": expected_hash,
                "hash_actual": actual_hash,
            });
        }
    }

    let secret = match decode_base32(&secret_b32) {
        Ok(s) => {
            eprintln!("[totp] base32_decode: {} raw secret bytes", s.len());
            s
        }
        Err(e) => return json!({"error": format!("Base32 decode failed on '{}': {}", secret_b32, e)}),
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
    let entries: Vec<Value> = data.entries.iter().map(|e| json!({
        "name": e.name,
        "type": e.otp_type,
        "algorithm": e.algorithm,
        "digits": e.digits,
        "period": e.period,
        "issuer": e.issuer,
        "account": e.account,
        "created_at": e.created_at,
    })).collect();

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

    // Decrypt secret (same pipeline as totp_generate)
    let encrypted = match base64_decode(&entry.encrypted_secret) {
        Ok(e) => e,
        Err(e) => return json!({"error": format!("Base64 decode failed: {}", e)}),
    };
    let decrypted = match dpapi_decrypt(&encrypted) {
        Ok(d) => d,
        Err(e) => return json!({"error": format!("Decryption failed: {}", e)}),
    };
    let trimmed = strip_trailing_nulls(&decrypted);
    let secret_b32 = match String::from_utf8(trimmed) {
        Ok(s) => s,
        Err(e) => return json!({"error": format!(
            "DPAPI decrypted {} bytes but not valid UTF-8: {}", decrypted.len(), e
        )}),
    };
    let secret_b32 = secret_b32.trim().to_string();
    if secret_b32.is_empty() {
        return json!({"error": "DPAPI decrypted to empty string — secret was not stored correctly"});
    }
    let secret = match decode_base32(&secret_b32) {
        Ok(s) => s,
        Err(e) => return json!({"error": format!("Base32 decode failed on '{}': {}", secret_b32, e)}),
    };

    let code = match hotp(&secret, counter, &entry.algorithm, entry.digits) {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("HOTP generation failed: {}", e)}),
    };

    // Increment counter
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

/// Compute SHA-256 hex digest of a byte slice (for integrity verification).
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Strip trailing null bytes from DPAPI output.
/// Windows DPAPI sometimes pads string-type data with null terminators.
fn strip_trailing_nulls(data: &[u8]) -> Vec<u8> {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    data[..end].to_vec()
}

// ============ TESTS ============

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test secret: "12345678901234567890" as ASCII bytes
    const RFC_SECRET_ASCII: &[u8] = b"12345678901234567890";
    // Same secret for SHA256 test (padded to 32 bytes per RFC 6238 Appendix B)
    const RFC_SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    // Same secret for SHA512 test (padded to 64 bytes per RFC 6238 Appendix B)
    const RFC_SECRET_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn test_hotp_rfc4226_vectors() {
        // RFC 4226 Appendix D — HOTP test values for secret "12345678901234567890"
        let expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ];
        for (counter, exp) in expected.iter().enumerate() {
            let code = hotp(RFC_SECRET_ASCII, counter as u64, "SHA1", 6).unwrap();
            assert_eq!(&code, exp, "HOTP counter={} expected={} got={}", counter, exp, code);
        }
    }

    #[test]
    fn test_totp_rfc6238_sha1() {
        // RFC 6238 Appendix B — SHA1 test vectors (8 digits)
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
            assert_eq!(code, expected, "TOTP SHA1 time={} expected={} got={}", time, expected, code);
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
            assert_eq!(code, expected, "TOTP SHA256 time={} expected={} got={}", time, expected, code);
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
            assert_eq!(code, expected, "TOTP SHA512 time={} expected={} got={}", time, expected, code);
        }
    }

    #[test]
    fn test_totp_6_digit() {
        // 6-digit variant of RFC 6238 time=59: last 6 digits of "94287082" = "287082"
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
        // "Hello!" in base32 = "JBSWY3DPEE"
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
        // Using the well-known test secret "JBSWY3DPEHPK3PXP" ("Hello!\xDE\xAD\xBE\xEF")
        // at a fixed time, verify deterministic output
        let secret = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        let code = totp(&secret, 0, 30, "SHA1", 6).unwrap();
        // Counter = 0/30 = 0, so this is HOTP(secret, 0)
        // Just verify it's 6 digits
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_jbswy3dpehpk3pxp_at_epoch() {
        // Phase C fix1: reproduction test case from live bug report.
        // Secret JBSWY3DPEHPK3PXP at epoch 1776197214, period=30, SHA1, 6 digits.
        // Counter = 1776197214 / 30 = 59206573
        // Verify the TOTP core algorithm produces a deterministic 6-digit code
        // and matches the RFC reference implementation output.
        let secret = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(secret, b"Hello!\xDE\xAD\xBE\xEF");

        let code = totp(&secret, 1776197214, 30, "SHA1", 6).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        // Verify the hotp function directly with this counter
        let hotp_code = hotp(&secret, 59206573, "SHA1", 6).unwrap();
        assert_eq!(code, hotp_code, "totp(time/period) must equal hotp(counter)");

        // The reference implementation says "459480" for this input.
        // If this assertion fails, the bug is in the TOTP math.
        // If it passes, the live bug is in the DPAPI encrypt/decrypt pipeline.
        assert_eq!(code, "459480", "TOTP JBSWY3DPEHPK3PXP@1776197214 should be 459480");
    }

    // ── Phase C fix2: DPAPI pipeline integration tests ──

    #[test]
    fn test_strip_trailing_nulls() {
        assert_eq!(strip_trailing_nulls(b"hello\0\0\0"), b"hello");
        assert_eq!(strip_trailing_nulls(b"hello"), b"hello");
        assert_eq!(strip_trailing_nulls(b"\0\0"), b"");
        assert_eq!(strip_trailing_nulls(b""), b"");
    }

    #[test]
    fn test_dpapi_roundtrip_register_generate() {
        // Full pipeline: register → store → retrieve → generate
        // On non-Windows, DPAPI is passthrough. On Windows, exercises real DPAPI.
        let store = JsonStore::new();
        // Clean up any prior test entry
        let _ = handle("totp_delete", &json!({"name": "__test_fix2__"}), &store);

        // Register with known secret
        let reg_result = handle("totp_register", &json!({
            "name": "__test_fix2__",
            "secret": "JBSWY3DPEHPK3PXP",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        }), &store);
        assert_eq!(reg_result["success"], true, "Register failed: {:?}", reg_result);

        // Generate — should produce a valid 6-digit code
        let gen_result = handle("totp_generate", &json!({"name": "__test_fix2__"}), &store);
        assert!(gen_result.get("error").is_none(), "Generate failed: {:?}", gen_result);
        let code = gen_result["code"].as_str().unwrap();
        assert_eq!(code.len(), 6, "Code should be 6 digits, got: {}", code);
        assert!(code.chars().all(|c| c.is_ascii_digit()), "Code not all digits: {}", code);

        // Verify against direct computation (bypass DPAPI)
        let secret_bytes = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        let now = Utc::now().timestamp() as u64;
        let expected = totp(&secret_bytes, now, 30, "SHA1", 6).unwrap();
        assert_eq!(code, expected, "DPAPI pipeline code '{}' != direct code '{}'", code, expected);

        // Cleanup
        let _ = handle("totp_delete", &json!({"name": "__test_fix2__"}), &store);
    }

    #[test]
    fn test_dpapi_roundtrip_from_uri() {
        // Same as above but using otpauth:// URI registration path
        let store = JsonStore::new();
        let _ = handle("totp_delete", &json!({"name": "__test_fix2_uri__"}), &store);

        let reg_result = handle("totp_register_from_uri", &json!({
            "name": "__test_fix2_uri__",
            "uri": "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        }), &store);
        assert_eq!(reg_result["success"], true, "URI register failed: {:?}", reg_result);

        let gen_result = handle("totp_generate", &json!({"name": "__test_fix2_uri__"}), &store);
        assert!(gen_result.get("error").is_none(), "Generate failed: {:?}", gen_result);
        let code = gen_result["code"].as_str().unwrap();

        let secret_bytes = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        let now = Utc::now().timestamp() as u64;
        let expected = totp(&secret_bytes, now, 30, "SHA1", 6).unwrap();
        assert_eq!(code, expected, "URI pipeline code '{}' != direct code '{}'", code, expected);

        let _ = handle("totp_delete", &json!({"name": "__test_fix2_uri__"}), &store);
    }

    #[test]
    fn test_dpapi_no_cross_contamination() {
        // Register multiple secrets, verify each generates its own code
        let store = JsonStore::new();
        let secrets = [
            ("__test_multi_a__", "JBSWY3DPEHPK3PXP"),        // Hello!\xDE\xAD\xBE\xEF
            ("__test_multi_b__", "GEZDGNBVGY3TQOJQ"),          // 12345678901234
        ];

        for (name, secret) in &secrets {
            let _ = handle("totp_delete", &json!({"name": name}), &store);
            let r = handle("totp_register", &json!({
                "name": name, "secret": secret,
            }), &store);
            assert_eq!(r["success"], true);
        }

        let now = Utc::now().timestamp() as u64;
        for (name, secret) in &secrets {
            let gen = handle("totp_generate", &json!({"name": name}), &store);
            let code = gen["code"].as_str().unwrap();
            let raw = decode_base32(secret).unwrap();
            let expected = totp(&raw, now, 30, "SHA1", 6).unwrap();
            assert_eq!(code, expected, "Cross-contamination: {} expected {} got {}", name, expected, code);
        }

        for (name, _) in &secrets {
            let _ = handle("totp_delete", &json!({"name": name}), &store);
        }
    }

    // ── Phase C fix3: base64 roundtrip and integrity verification tests ──

    #[test]
    fn test_base64_roundtrip_binary() {
        // Verify base64 encode/decode roundtrip for arbitrary binary data
        // (simulates DPAPI ciphertext which is arbitrary bytes)
        use crate::credential::{base64_encode, base64_decode};
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
                data.to_vec(), decoded,
                "Base64 roundtrip failed for case {}: {} bytes", i, data.len()
            );
        }
    }

    #[test]
    fn test_secret_hash_verification() {
        // Verify that register stores a hash and generate checks it
        let store = JsonStore::new();
        let _ = handle("totp_delete", &json!({"name": "__test_fix3_hash__"}), &store);

        let reg = handle("totp_register", &json!({
            "name": "__test_fix3_hash__",
            "secret": "JBSWY3DPEHPK3PXP",
        }), &store);
        assert_eq!(reg["success"], true, "Register failed: {:?}", reg);

        // Verify hash was stored
        let data: TotpStore = store.load_or_default(FILE);
        let entry = data.entries.iter().find(|e| e.name == "__test_fix3_hash__").unwrap();
        assert!(entry.secret_hash.is_some(), "secret_hash should be set on new entries");

        // Verify generate succeeds (hash matches)
        let gen = handle("totp_generate", &json!({"name": "__test_fix3_hash__"}), &store);
        assert!(gen.get("error").is_none(), "Generate failed: {:?}", gen);

        let _ = handle("totp_delete", &json!({"name": "__test_fix3_hash__"}), &store);
    }
}
