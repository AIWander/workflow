//! Shared JSON file storage layer with atomic writes.
//! Resolves the workflow data directory via legacy-fallback:
//!   1. C:\CPC\workflows — if it exists with recognizable data (Joe's machine)
//!   2. cpc_paths::data_path("workflow") — fresh installs

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};

const LEGACY_DIR: &str = r"C:\CPC\workflows";

/// Resolve the workflow data directory.
///
/// Priority:
/// 1. Legacy `C:\CPC\workflows` — if it exists AND contains a known workflow file.
///    Existing installs (Joe's machine) keep their current path unchanged.
/// 2. `cpc_paths::data_path("workflow")` — new installs use the cross-platform default.
///
/// Falls back to `LEGACY_DIR` if both fail (ensures the server never hard-crashes on startup).
fn resolve_workflow_dir() -> Result<PathBuf> {
    _resolve_workflow_dir(Path::new(LEGACY_DIR))
}

/// Testable inner resolver — takes `legacy` as parameter so tests can inject tempdirs.
pub(crate) fn _resolve_workflow_dir(legacy: &Path) -> Result<PathBuf> {
    if legacy.exists() && has_workflow_data(legacy) {
        return Ok(legacy.to_path_buf());
    }
    cpc_paths::data_path("workflow")
}

/// Returns true if `dir` contains at least one file that workflow is known to create.
/// An empty-but-existing legacy dir falls through to cpc-paths.
pub(crate) fn has_workflow_data(dir: &Path) -> bool {
    for marker in &[
        "credentials.json",
        "totp.json",
        "flows.json",
        "workflows.json",
    ] {
        if dir.join(marker).exists() {
            return true;
        }
    }
    false
}

pub struct JsonStore {
    base_dir: PathBuf,
}

impl JsonStore {
    pub fn new() -> Self {
        let base_dir = resolve_workflow_dir().unwrap_or_else(|_| PathBuf::from(LEGACY_DIR));
        Self { base_dir }
    }

    pub fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.base_dir)
            .with_context(|| format!("Failed to create {}", self.base_dir.display()))
    }

    pub fn load<T: DeserializeOwned>(&self, filename: &str) -> Result<T> {
        let path = self.base_dir.join(filename);
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&data).with_context(|| format!("Failed to parse {}", path.display()))
    }

    pub fn load_or_default<T: DeserializeOwned + Default>(&self, filename: &str) -> T {
        self.load(filename).unwrap_or_default()
    }

    pub fn save<T: Serialize>(&self, filename: &str, data: &T) -> Result<()> {
        self.ensure_dir()?;
        let path = self.base_dir.join(filename);
        let tmp = self.base_dir.join(format!("{}.tmp", filename));
        let json = serde_json::to_string_pretty(data).context("Failed to serialize")?;
        std::fs::write(&tmp, &json)
            .with_context(|| format!("Failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("Failed to rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    #[allow(dead_code)] // Useful diagnostic accessor
    pub fn path(&self, filename: &str) -> PathBuf {
        self.base_dir.join(filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that touch the filesystem to avoid race conditions.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_legacy_path_wins() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // Create a known workflow marker file — simulates Joe's machine
        std::fs::write(dir.path().join("credentials.json"), "{}").unwrap();

        let result = _resolve_workflow_dir(dir.path()).unwrap();
        assert_eq!(
            result,
            dir.path(),
            "legacy dir with marker should be returned as-is"
        );
    }

    #[test]
    fn test_no_legacy_falls_through() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // Empty tempdir — no marker files

        assert!(
            !has_workflow_data(dir.path()),
            "empty dir must not be detected as legacy data"
        );
        // Resolver should fall through (we verify has_workflow_data returns false;
        // the cpc_paths call outcome depends on system config which we don't control in unit tests)
    }

    #[test]
    fn test_all_markers_detected() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();

        for marker in &[
            "credentials.json",
            "totp.json",
            "flows.json",
            "workflows.json",
        ] {
            let path = dir.path().join(marker);
            std::fs::write(&path, "{}").unwrap();
            assert!(
                has_workflow_data(dir.path()),
                "marker {} should be detected",
                marker
            );
            std::fs::remove_file(&path).unwrap();
        }
    }
}
