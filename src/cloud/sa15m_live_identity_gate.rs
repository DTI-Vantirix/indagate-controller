//! SA-15M: fail-closed legacy identity mode gate.
//!
//! DEVELOPMENT SOURCE ONLY: no controller deployment or sealed-mode activation.
//! The live agent continues to use the SA-15K legacy JSON store by default.
//! If a sealed cutover marker exists or an unsupported mode is requested,
//! legacy I/O and credential rotation are refused rather than falling back.
//!
//! IMPORTANT: This gate does NOT implement sealed storage, durable interprocess
//! locks, rollback resistance, power-loss guarantees or a live migration. It
//! cannot make a concurrent cutover safe: a separate process could publish a
//! marker between this check and subsequent I/O. Production cutover requires
//! a stopped/quiesced service, atomic mode protocol, and tested recovery.

use anyhow::{Context, Result, bail, ensure};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

const MODE_ENV: &str = "HLAXS_IDENTITY_STORAGE_MODE";
const MARKER_NAME: &str = "cutover.json";

/// This release deliberately supports only the original legacy JSON path.
/// Even a seemingly valid `sealed` request is rejected until a separately
/// reviewed storage implementation exists. No key or credential is read.
fn verify_requested_mode(mode: Option<&OsStr>) -> Result<()> {
    match mode {
        None => Ok(()),
        Some(value) if value == OsStr::new("legacy") => Ok(()),
        _ => bail!("unsupported identity storage mode; sealed mode not enabled in SA-15M"),
    }
}

/// Called before *each* live legacy identity read/write and before cloud
/// operations that could initiate or finalize credential rotation.
/// This is a fail-closed safety guard, not a cutover implementation.
pub fn enforce_legacy_mode(identity_path: &Path) -> Result<()> {
    let requested: Option<OsString> = std::env::var_os(MODE_ENV);
    enforce_legacy_mode_with_setting(identity_path, requested.as_deref())
}

fn enforce_legacy_mode_with_setting(identity_path: &Path, requested: Option<&OsStr>) -> Result<()> {
    verify_requested_mode(requested)?;
    ensure!(identity_path.file_name() == Some(OsStr::new("device.json")),
        "identity path must be device.json");
    let parent = identity_path.parent().context("identity directory missing")?;
    let parent_meta = match fs::symlink_metadata(parent) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("inspect identity directory before legacy I/O"),
    };
    ensure!(parent_meta.is_dir() && !parent_meta.file_type().is_symlink(),
        "identity directory must be a real directory");
    let marker = parent.join(MARKER_NAME);
    match fs::symlink_metadata(&marker) {
        Ok(_) => bail!("encrypted identity cutover marker exists; refusing legacy credentials"),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("inspect encrypted identity cutover marker"),
    }
}

/// Metadata-only migration eligibility check for future designs. It is NOT
/// authorization to migrate; SA-15I's live-migration guard remains disabled.
pub fn idle_metadata_required_for_future_cutover(
    pending_certificate_id: Option<&str>,
    pending_rotation_command_id: Option<&str>,
) -> Result<()> {
    ensure!(pending_certificate_id.is_none() && pending_rotation_command_id.is_none(),
        "pending credential rotation must settle before any future cutover");
    Ok(())
}

/// This stage does not contain a successful live encrypted-mode path.
pub fn authorize_live_sealed_mode() -> Result<()> {
    bail!("SA-15M live sealed identity mode is disabled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    struct Fixture { root: PathBuf }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "hlaxs-sa15m-lab-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            Self { root }
        }
        fn identity(&self) -> PathBuf { self.root.join("device.json") }
        fn marker(&self) -> PathBuf { self.root.join(MARKER_NAME) }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }

    #[test]
    fn default_and_explicit_legacy_modes_allow_absent_marker() {
        let f = Fixture::new();
        assert!(enforce_legacy_mode_with_setting(&f.identity(), None).is_ok());
        assert!(enforce_legacy_mode_with_setting(&f.identity(), Some(OsStr::new("legacy"))).is_ok());
    }
    #[test]
    fn sealed_and_unknown_modes_never_enable_legacy_fallback() {
        let f = Fixture::new();
        for request in ["sealed", "encrypted", "", "legacy ", "auto", "sealed-dev"] {
            assert!(enforce_legacy_mode_with_setting(&f.identity(), Some(OsStr::new(request))).is_err());
        }
    }
    #[test]
    fn marker_blocks_plaintext_even_when_it_is_corrupt() {
        let f = Fixture::new();
        File::create(f.marker()).unwrap();
        assert!(enforce_legacy_mode_with_setting(&f.identity(), None).is_err());
    }
    #[test]
    fn symlink_marker_blocks_plaintext() {
        let f = Fixture::new();
        symlink("/dev/null", f.marker()).unwrap();
        assert!(enforce_legacy_mode_with_setting(&f.identity(), None).is_err());
    }
    #[test]
    fn missing_enrollment_parent_is_allowed_but_sealed_mode_is_not() {
        let f = Fixture::new();
        let new_identity = f.root.join("new").join("device.json");
        assert!(enforce_legacy_mode_with_setting(&new_identity, None).is_ok());
        assert!(enforce_legacy_mode_with_setting(&new_identity, Some(OsStr::new("sealed"))).is_err());
    }
    #[test]
    fn symlink_directory_and_wrong_filename_are_refused() {
        let f = Fixture::new();
        let link = f.root.join("linked");
        symlink(&f.root, &link).unwrap();
        assert!(enforce_legacy_mode_with_setting(&link.join("device.json"), None).is_err());
        assert!(enforce_legacy_mode_with_setting(&f.root.join("other.json"), None).is_err());
    }
    #[test]
    fn pending_metadata_never_qualifies_for_future_cutover() {
        assert!(idle_metadata_required_for_future_cutover(None, None).is_ok());
        assert!(idle_metadata_required_for_future_cutover(Some("certificate"), None).is_err());
        assert!(idle_metadata_required_for_future_cutover(None, Some("command")).is_err());
        assert!(idle_metadata_required_for_future_cutover(Some("certificate"), Some("command")).is_err());
    }
    #[test]
    fn no_public_live_sealed_mode_authorization() {
        assert!(authorize_live_sealed_mode().is_err());
    }
}
