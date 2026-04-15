//! Migration tool: DPAPI → OS keyring.
//! One-time migration for pre-v1.3.0 credentials and TOTP secrets.
//! Idempotent: entries already migrated (no encrypted_value/encrypted_secret) are skipped.

use crate::credential::{base64_decode, CredentialStore};
use crate::keyring_store;
use crate::storage::JsonStore;
use crate::totp::TotpStore;
use serde_json::{json, Value};

/// Migrate all legacy DPAPI-encrypted credentials and TOTP secrets to the OS keyring.
///
/// For each credential entry with `encrypted_value`:
///   1. DPAPI-decrypt the value.
///   2. Store via keyring under "cred:{name}".
///   3. If keyring already has a value, verify it matches (abort if mismatch to prevent data loss).
///   4. Clear `encrypted_value` from the JSON entry.
///
/// For each TOTP entry with `encrypted_secret`: same flow under "totp:{name}".
///
/// Returns: `{migrated_credentials, migrated_totp, errors: [...]}`
pub fn migrate_dpapi_to_keyring(store: &JsonStore) -> Value {
    let mut migrated_creds: u32 = 0;
    let mut migrated_totp: u32 = 0;
    let mut errors: Vec<String> = Vec::new();

    // ── Credentials ──
    let mut cdata: CredentialStore = store.load_or_default(crate::credential::FILE);
    let mut creds_changed = false;

    for cred in &mut cdata.credentials {
        // Migrate main value
        if let Some(ref enc) = cred.encrypted_value.clone() {
            match migrate_one_value("cred", &cred.name, enc) {
                Ok(()) => {
                    cred.encrypted_value = None;
                    migrated_creds += 1;
                    creds_changed = true;
                }
                Err(e) => {
                    errors.push(format!("credential '{}': {}", cred.name, e));
                }
            }
        }

        // Migrate client_secret if present
        if let Some(ref enc) = cred.client_secret_encrypted.clone() {
            let key = format!("{}:client_secret", cred.name);
            match migrate_one_value("cred", &key, enc) {
                Ok(()) => {
                    cred.client_secret_encrypted = None;
                    creds_changed = true;
                }
                Err(e) => {
                    errors.push(format!("credential '{}' client_secret: {}", cred.name, e));
                }
            }
        }
    }

    if creds_changed {
        if let Err(e) = store.save(crate::credential::FILE, &cdata) {
            errors.push(format!("Failed to save credentials.json after migration: {}", e));
        }
    }

    // ── TOTP ──
    let mut tdata: TotpStore = store.load_or_default(crate::totp::FILE);
    let mut totp_changed = false;

    for entry in &mut tdata.entries {
        if let Some(ref enc) = entry.encrypted_secret.clone() {
            match migrate_one_value("totp", &entry.name, enc) {
                Ok(()) => {
                    entry.encrypted_secret = None;
                    migrated_totp += 1;
                    totp_changed = true;
                }
                Err(e) => {
                    errors.push(format!("totp '{}': {}", entry.name, e));
                }
            }
        }
    }

    if totp_changed {
        if let Err(e) = store.save(crate::totp::FILE, &tdata) {
            errors.push(format!("Failed to save totp.json after migration: {}", e));
        }
    }

    json!({
        "migrated_credentials": migrated_creds,
        "migrated_totp": migrated_totp,
        "errors": errors,
    })
}

/// Decrypt one DPAPI-encrypted base64 value and store it in the keyring.
/// If keyring already has a value, verify it matches before considering done.
/// Returns Ok(()) on success (including "already migrated" idempotent path).
fn migrate_one_value(namespace: &str, name: &str, enc: &str) -> Result<(), String> {
    // DPAPI-decrypt the legacy value
    let bytes = base64_decode(enc).map_err(|e| format!("base64 decode: {}", e))?;
    let decrypted = crate::dpapi_legacy::dpapi_decrypt(&bytes)
        .map_err(|e| {
            #[cfg(not(windows))]
            let _ = e;
            #[cfg(not(windows))]
            return "DPAPI decrypt not available on non-Windows — migrate on the original Windows machine".to_string();
            #[cfg(windows)]
            format!("DPAPI decrypt: {}", e)
        })?;
    let trimmed = crate::dpapi_legacy::strip_trailing_nulls(&decrypted);
    let plaintext = String::from_utf8(trimmed)
        .map_err(|e| format!("decrypted bytes not UTF-8: {}", e))?;
    let plaintext = plaintext.trim().to_string();

    // Check if keyring already has a value
    match keyring_store::get_or_none(namespace, name) {
        Ok(Some(existing)) => {
            if existing != plaintext {
                return Err(format!(
                    "keyring already has a DIFFERENT value for this entry — refusing to overwrite to prevent data loss. \
                     Delete the keyring entry manually first."
                ));
            }
            // Already migrated with same value — idempotent, no error
            Ok(())
        }
        Ok(None) => {
            keyring_store::set(namespace, name, &plaintext)
                .map_err(|e| format!("keyring store: {}", e))
        }
        Err(e) => Err(format!("keyring read: {}", e)),
    }
}

/// Check all JSON files for legacy DPAPI entries and log a warning if any are found.
/// Called at server startup.
pub fn check_and_warn_legacy(store: &JsonStore) {
    let has_cred = crate::credential::has_legacy_entries(store);
    let has_totp = crate::totp::has_legacy_entries(store);

    if has_cred || has_totp {
        eprintln!(
            "[workflow] Legacy DPAPI credentials detected. \
             Run workflow:migrate_dpapi_to_keyring to migrate to the OS-native keyring. \
             Existing credentials will continue to work via DPAPI fallback until migrated."
        );
    }
}
