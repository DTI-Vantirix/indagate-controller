//! SA-15Z: lab-only persistent CAAM blob -> common SA-15Y identity dispatcher.
//!
//! Compiled into the actual cloud agent, but NOT called by its startup/load/save
//! paths. No environment variable, cloud request, or cutover marker enables it.
//! This is a development key provider, NOT a production key hierarchy or
//! hardware anti-rollback proof (HAB is open on the current controller).

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::caam_afalg_wrapper::CaamAfAlgDevelopmentWrapper;
use crate::cloud::sa15u_agent_sealed_store::Sa15uLabStore;
use crate::cloud::sa15y_runtime_backend::{self, IdentityLocation};
use anyhow::{Context, Result, ensure};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const BLOB_FILE: &str = "wrapped-key.bb";
const BLOB_LEN: u64 = 112; // CAAM CCM wrapped key blob measured on this SightPas device.
const KEYGEN: &str = "/usr/bin/caam-keygen";
const KEY_ROOT: &str = "/data/caam";

fn validate_private_lab(root: &Path) -> Result<PathBuf> {
    // Strong path restriction precedes any filesystem access to blob data.
    Sa15uLabStore::new(root)?;
    let meta = fs::symlink_metadata(root).context("inspect SA-15Z lab directory")?;
    ensure!(meta.is_dir() && !meta.file_type().is_symlink()
        && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "CAAM lab directory must be root owned and private");
    let blob = root.join(BLOB_FILE);
    let bm = fs::symlink_metadata(&blob).context("inspect CAAM wrapped-key blob")?;
    ensure!(bm.is_file() && !bm.file_type().is_symlink() && bm.nlink() == 1
        && bm.uid() == unsafe { libc::geteuid() } && bm.mode() & 0o077 == 0 && bm.len() == BLOB_LEN,
        "CAAM wrapped-key blob must be private, regular, single-link and exact length");
    Ok(blob)
}

struct EphemeralBlackKey { path: PathBuf }
impl Drop for EphemeralBlackKey {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("SA-15Z temporary CAAM black key cleanup failed: {e}");
            }
        }
    }
}

/// Reimport a durable lab CAAM blob to an unpredictable, temporary black-key
/// pathname; do not print, return or persist that black key. Always remove it
/// on normal process unwinding, including an operation that returns an error.
/// A SIGKILL/power loss may leave an ephemeral CAAM artifact; before production
/// deployment this requires a boot-time controlled cleanup service.
pub fn with_restored_lab_caam<T>(
    root: &Path,
    action: impl FnOnce(&CaamAfAlgDevelopmentWrapper) -> Result<T>,
) -> Result<T> {
    ensure!(unsafe { libc::geteuid() } == 0, "native CAAM lab requires root");
    let blob = validate_private_lab(root)?;
    let key_name = format!("hlaxs-sa15f-z-{}", uuid::Uuid::new_v4());
    let black_path = Path::new(KEY_ROOT).join(&key_name);
    ensure!(!black_path.exists(), "temporary CAAM key name collision");
    let output = Command::new(KEYGEN)
        .arg("import")
        .arg(&blob)
        .arg(&key_name)
        .output().context("launch CAAM key import utility")?;
    // Own the random pathname only AFTER a successful import. A failing command
    // might have created the file; cleanup that exact unpredictable pathname.
    let temporary = EphemeralBlackKey { path: black_path };
    ensure!(output.status.success()
        && !String::from_utf8_lossy(&output.stdout).contains("Failed")
        && !String::from_utf8_lossy(&output.stderr).contains("Failed"),
        "CAAM key import failed (output withheld)");
    let wrapper = CaamAfAlgDevelopmentWrapper::from_test_key_file(&temporary.path)?;
    let outcome = action(&wrapper);
    drop(wrapper);
    // Explicitly check cleanup, rather than returning PASS if Drop merely logs
    // a failed removal. On error Drop still retries that one random pathname.
    fs::remove_file(&temporary.path).context("remove temporary CAAM black key")?;
    std::mem::forget(temporary);
    outcome
}

/// Read the same full DeviceIdentity (including pending certificate and command
/// fields) used by the real agent, through the real SA-15Y shared dispatcher.
/// Missing or invalid sealed data is an error, never plaintext fallback.
pub fn load_lab_with_caam(root: &Path) -> Result<(u64, DeviceIdentity)> {
    with_restored_lab_caam(root, |wrapper| {
        sa15y_runtime_backend::load(IdentityLocation::SealedLab { root, wrapper })?
            .context("missing CAAM-sealed full identity; no legacy fallback")
    })
}

/// Atomically update the full identity in the lab via the same SA-15Y dispatcher
/// as the real agent. Stale generation and incorrect CAAM key fail closed.
pub fn save_lab_with_caam(
    root: &Path, identity: &DeviceIdentity, expected_previous: u64,
) -> Result<u64> {
    with_restored_lab_caam(root, |wrapper| {
        sa15y_runtime_backend::save(
            IdentityLocation::SealedLab { root, wrapper }, identity, expected_previous,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt;

    fn test_lab() -> PathBuf {
        let root=Path::new("/tmp").join(format!("hlaxs-sa15u-lab-sa15z-{}",uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    #[test]
    fn production_directory_rejected_before_key_import() {
        assert!(load_lab_with_caam(Path::new("/var/lib/highline-nexus")).is_err());
    }
    #[test]
    fn missing_blob_fails_closed() {
        let lab=test_lab();
        assert!(validate_private_lab(&lab).is_err());
        fs::remove_dir(&lab).unwrap();
    }
    #[test]
    fn blob_symlink_rejected() {
        let lab=test_lab();
        symlink("/dev/null",lab.join(BLOB_FILE)).unwrap();
        assert!(validate_private_lab(&lab).is_err());
        fs::remove_file(lab.join(BLOB_FILE)).unwrap();
        fs::remove_dir(&lab).unwrap();
    }
    #[test]
    fn incorrect_blob_length_rejected() {
        let lab=test_lab();
        File::create(lab.join(BLOB_FILE)).unwrap();
        assert!(validate_private_lab(&lab).is_err());
        fs::remove_file(lab.join(BLOB_FILE)).unwrap();
        fs::remove_dir(&lab).unwrap();
    }
    #[test]
    fn nonprivate_lab_directory_rejected() {
        let lab=test_lab();
        fs::set_permissions(&lab,fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_private_lab(&lab).is_err());
        fs::set_permissions(&lab,fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(&lab).unwrap();
    }
    #[test]
    fn native_without_blob_cannot_create_sealed_identity() {
        let lab=test_lab();
        let result=load_lab_with_caam(&lab);
        assert!(result.is_err());
        fs::remove_dir(&lab).unwrap();
    }
}
