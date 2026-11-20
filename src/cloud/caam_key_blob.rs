//! SA-15B development-only CAAM black-key/blob provider.
//!
//! This module manages randomly generated BLACK KEYS and their `.bb` blobs,
//! not existing `DeviceIdentity.device_secret` credentials. Calls are explicit,
//! never invoked at startup, and do not grant production trust. The device's
//! HAB fuse was observed OPEN. Do not use these keys as production identities.

use anyhow::{Context, Result, ensure};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const KEY_DIR: &str = "/data/caam";
const CAAM_KEYGEN: &str = "/usr/bin/caam-keygen";
const TEST_PREFIX: &str = "hlaxs-sa15b-";

#[derive(Debug, Clone)]
pub struct CaamKeyFiles {
    pub protected_key: PathBuf,
    pub sealed_blob: PathBuf,
}

/// Distinct from the cloud credential store: this is only a key generator.
pub struct CaamDevelopmentKeyProvider;

fn valid_test_name(name: &str) -> bool {
    name.starts_with(TEST_PREFIX)
        && name.len() <= 80
        && name.len() > TEST_PREFIX.len()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn verify_private_nonempty_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("missing CAAM output: {}", path.display()))?;
    ensure!(metadata.is_file() && !metadata.file_type().is_symlink(), "CAAM output is not a regular file");
    ensure!(metadata.len() > 0 && metadata.len() < 4096, "invalid CAAM output length");
    ensure!(metadata.permissions().mode() & 0o077 == 0, "insecure CAAM output permissions");
    Ok(())
}

fn ensure_safe_dir() -> Result<()> {
    let metadata = fs::symlink_metadata(KEY_DIR).context("inspect CAAM key directory")?;
    ensure!(metadata.is_dir() && !metadata.file_type().is_symlink(), "unsafe CAAM key directory");
    ensure!(metadata.permissions().mode() & 0o022 == 0, "CAAM key directory is group/world writable");
    ensure!(Path::new("/dev/caam-keygen").exists(), "CAAM keygen device absent");
    ensure!(Path::new(CAAM_KEYGEN).exists(), "CAAM keygen utility absent");
    Ok(())
}

fn run_keygen(args: &[&str]) -> Result<()> {
    // Fixed shell code: arguments are passed as positional parameters, never
    // interpolated into shell source. Child process umask prevents 0644 keys.
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg("umask 077; exec /usr/bin/caam-keygen \"$@\"")
        .arg("hlaxs-caam")
        .args(args)
        .status()
        .context("launch CAAM keygen")?;
    ensure!(status.success(), "CAAM keygen command failed");
    Ok(())
}

impl CaamDevelopmentKeyProvider {
    /// Produces a NEW random AES-256 CAAM test key and its blob.
    /// CAAM may return a misleading exit status; both files are verified.
    pub fn create_random_test_key(name: &str) -> Result<CaamKeyFiles> {
        ensure!(valid_test_name(name), "invalid development key name");
        ensure_safe_dir()?;
        let key = Path::new(KEY_DIR).join(name);
        let blob = Path::new(KEY_DIR).join(format!("{name}.bb"));
        ensure!(!key.exists() && !blob.exists(), "CAAM test files already exist");
        run_keygen(&["create", name, "ccm", "-s", "32"])?;
        verify_private_nonempty_file(&key)?;
        verify_private_nonempty_file(&blob)?;
        Ok(CaamKeyFiles { protected_key: key, sealed_blob: blob })
    }

    /// Recover a protected test key from a sealed blob already in /data/caam.
    /// Does not compare the underlying secret or assert boot persistence.
    pub fn import_test_key(blob: &Path, restored_name: &str) -> Result<PathBuf> {
        ensure!(valid_test_name(restored_name), "invalid restored key name");
        ensure_safe_dir()?;
        let canonical_dir = fs::canonicalize(KEY_DIR)?;
        let canonical_blob = fs::canonicalize(blob).context("read CAAM blob path")?;
        ensure!(canonical_blob.parent() == Some(canonical_dir.as_path()), "CAAM blob outside key directory");
        ensure!(canonical_blob.extension().and_then(|s| s.to_str()) == Some("bb"), "not a CAAM blob");
        let output = Path::new(KEY_DIR).join(restored_name);
        ensure!(!output.exists(), "restored CAAM test key already exists");
        let blob_arg = canonical_blob.to_str().context("non-UTF8 CAAM blob path")?;
        run_keygen(&["import", blob_arg, restored_name])?;
        verify_private_nonempty_file(&output)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_must_be_explicitly_development_scoped() {
        assert!(valid_test_name("hlaxs-sa15b-test_123"));
        assert!(!valid_test_name("production-key"));
        assert!(!valid_test_name("hlaxs-sa15b-"));
        assert!(!valid_test_name("hlaxs-sa15b-../etc"));
        assert!(!valid_test_name("hlaxs-sa15b-foo/bar"));
    }

    #[test]
    fn dev_provider_cannot_run_without_actual_caam_hardware() {
        // No automatic hardware operation: name validation is the only shared
        // logic tested on WSL. The real generator is only called explicitly.
        assert!(!valid_test_name("arbitrary-name"));
    }
}
