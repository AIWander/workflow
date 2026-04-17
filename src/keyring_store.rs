//! Thin wrapper over `keyring` crate for workflow-mcp.
//! Namespaces entries under service "cpc-workflow".
//! On server startup, call `probe()` to fail fast if OS keyring is unavailable.

use anyhow::{Context, Result};
use keyring::Entry;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SERVICE: &str = "cpc-workflow";

/// Set to true at startup if keyring is unavailable and CPC_WORKFLOW_DISABLE_SECRETS is set.
/// Credential/TOTP tools check this and return a helpful error when true.
pub static SECRETS_DISABLED: AtomicBool = AtomicBool::new(false);

pub fn is_disabled() -> bool {
    SECRETS_DISABLED.load(Ordering::Relaxed)
}

/// Store a secret under a (namespace, name) pair.
/// namespace is "cred" or "totp". name is the user-facing entry name.
pub fn set(namespace: &str, name: &str, secret: &str) -> Result<()> {
    let entry =
        Entry::new(SERVICE, &format!("{namespace}:{name}")).context("creating keyring entry")?;
    entry
        .set_password(secret)
        .context("storing secret in keyring")?;
    Ok(())
}

/// Retrieve a secret. Returns None if the entry does not exist.
/// Other keyring errors are propagated.
pub fn get_or_none(namespace: &str, name: &str) -> Result<Option<String>> {
    let entry =
        Entry::new(SERVICE, &format!("{namespace}:{name}")).context("creating keyring entry")?;
    match entry.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("keyring read error: {}", e)),
    }
}

/// Retrieve a secret, returning an error if not found.
pub fn get(namespace: &str, name: &str) -> Result<String> {
    get_or_none(namespace, name)?
        .ok_or_else(|| anyhow::anyhow!("No keyring entry for {namespace}:{name}"))
}

/// Delete a secret. No-ops silently if the entry does not exist.
pub fn delete(namespace: &str, name: &str) -> Result<()> {
    let entry =
        Entry::new(SERVICE, &format!("{namespace}:{name}")).context("creating keyring entry")?;
    match entry.delete_credential() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("keyring delete error: {}", e)),
    }
}

/// Platform capability probe. Call on server startup to fail fast if keyring is unavailable
/// (e.g., headless Linux with no Secret Service daemon).
/// On Windows and macOS this always succeeds.
///
/// Uses a two-Entry sentinel: writes via one Entry instance, drops it, then reads via a fresh
/// Entry with the same service+user. Mock backends keep in-process state, so a single-Entry
/// round-trip can pass while mock is active. Creating a second instance exposes mock behavior
/// because real OS backends (Windows Credential Manager, macOS Keychain, Linux Secret Service)
/// persist across Entry instances while mock backends may not.
pub fn probe() -> Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // Unique per-invocation target prevents parallel test collisions
    let probe_user = format!("probe_{}", nanos);
    let sentinel = format!("sentinel_{}", nanos);

    // Write via first Entry instance
    let writer =
        Entry::new("cpc_workflow_probe", &probe_user).context("probe: creating writer entry")?;
    writer
        .set_password(&sentinel)
        .context("probe: set failed")?;
    drop(writer);

    // Read via a fresh Entry instance — catches mock backends
    let reader =
        Entry::new("cpc_workflow_probe", &probe_user).context("probe: creating reader entry")?;
    let read = reader.get_password().context("probe: get failed")?;

    // Cleanup — ignore errors
    let _ = reader.delete_credential();

    anyhow::ensure!(
        read == sentinel,
        "keyring two-entry sentinel mismatch: backend does not persist across Entry instances (mock backend?)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that the OS keyring backend persists data across Entry instances.
    /// Passes on Windows (Credential Manager), macOS (Keychain), and Linux with Secret Service.
    #[test]
    fn test_keyring_probe_succeeds() {
        probe().expect("keyring probe should succeed on a machine with a real OS keyring backend");
    }
}
