//! Thin wrapper over `keyring` crate for workflow-mcp.
//! Namespaces entries under service "cpc-workflow".
//! On server startup, call `probe()` to fail fast if OS keyring is unavailable.

use anyhow::{Context, Result};
use keyring::Entry;
use std::sync::atomic::{AtomicBool, Ordering};

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
    let entry = Entry::new(SERVICE, &format!("{namespace}:{name}"))
        .context("creating keyring entry")?;
    entry.set_password(secret)
        .context("storing secret in keyring")?;
    Ok(())
}

/// Retrieve a secret. Returns None if the entry does not exist.
/// Other keyring errors are propagated.
pub fn get_or_none(namespace: &str, name: &str) -> Result<Option<String>> {
    let entry = Entry::new(SERVICE, &format!("{namespace}:{name}"))
        .context("creating keyring entry")?;
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
    let entry = Entry::new(SERVICE, &format!("{namespace}:{name}"))
        .context("creating keyring entry")?;
    match entry.delete_credential() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("keyring delete error: {}", e)),
    }
}

/// Platform capability probe. Call on server startup to fail fast if keyring is unavailable
/// (e.g., headless Linux with no Secret Service daemon).
/// On Windows and macOS this always succeeds.
pub fn probe() -> Result<()> {
    let test_entry = Entry::new(SERVICE, "__probe__")
        .context("creating probe entry")?;
    test_entry.set_password("probe")
        .context("probe: set failed")?;
    let read = test_entry.get_password()
        .context("probe: get failed")?;
    anyhow::ensure!(read == "probe", "keyring round-trip mismatch");
    test_entry.delete_credential()
        .context("probe: delete failed")?;
    Ok(())
}
