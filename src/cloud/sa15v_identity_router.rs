//! SA-15V: actual cloud-agent identity I/O integration boundary (SOURCE ONLY).
//!
//! The real agent's load_identity() and save_identity_atomic() call this router.
//! This release intentionally supports LEGACY storage only.  SA-15M rejects
//! encrypted mode and a cutover marker. No automatic plaintext fallback exists
//! after a marker, and NO real credential encryption/migration occurs here.
//!
//! Previous SA-15U proves complete DeviceIdentity sealing in a disposable lab;
//! this small runtime seam is the next prerequisite for an explicit future
//! versioned cutover. It does not introduce a mixed-format state machine.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::sa15k_legacy_identity_store::LegacyJsonStore;
use crate::cloud::sa15m_live_identity_gate::enforce_legacy_mode;
use anyhow::{ensure, Result};
use std::path::Path;

pub fn load_legacy(path: &Path) -> Result<Option<DeviceIdentity>> {
    // The agent also invokes the guard at its callsite, intentionally. No
    // changes to its existing runtime behavior or mode selection in SA-15V.
    enforce_legacy_mode(path)?;
    LegacyJsonStore::new(path).load()
}

pub fn save_legacy(path: &Path, identity: &DeviceIdentity) -> Result<()> {
    enforce_legacy_mode(path)?;
    LegacyJsonStore::new(path).save(identity)
}

/// Read-only metadata assessment for the *future* migration gate.
/// Deliberately NOT part of live load/save: changing legacy rotation semantics
/// is unsafe until the complete migration transaction is implemented.
pub fn future_cutover_idle(identity: &DeviceIdentity) -> Result<()> {
    ensure!(identity.pending_certificate_id.is_none()
        && identity.pending_rotation_command_id.is_none(),
        "pending credential rotation must settle before migration");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    fn fixture() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "sa15v-synthetic-device".into(),
            controller_id: "sa15v-synthetic-controller".into(),
            organization_id: "sa15v-synthetic-organization".into(),
            site_id: "sa15v-synthetic-site".into(),
            hardware_profile: "sa15v-synthetic-hardware".into(),
            device_secret: "SA15V_SYNTHETIC_SECRET_ONLY_1234567890_ABCDEF".into(),
            pending_certificate_id: None,
            pending_rotation_command_id: None,
        }
    }
    struct Lab { root: PathBuf, path: PathBuf }
    impl Lab {
        fn new() -> Self {
            let root = PathBuf::from("/tmp")
                .join(format!("hlaxs-sa15v-lab-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("device.json");
            Self { root, path }
        }
        fn marker(&self) -> PathBuf { self.root.join("cutover.json") }
    }
    impl Drop for Lab {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }

    #[test]
    fn real_deviceidentity_roundtrip_via_agent_router() {
        let l = Lab::new();
        let original = fixture();
        save_legacy(&l.path, &original).unwrap();
        let decoded = load_legacy(&l.path).unwrap().unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(),
                   serde_json::to_value(&original).unwrap());
        assert_eq!(fs::metadata(&l.path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    #[test]
    fn missing_identity_does_not_enroll_automatically() {
        let l = Lab::new();
        assert!(load_legacy(&l.path).unwrap().is_none());
        assert!(!l.path.exists());
    }
    #[test]
    fn prepared_certificate_only_roundtrip() {
        let l = Lab::new(); let mut identity = fixture();
        identity.pending_certificate_id = Some("sa15v-test-cert".into());
        save_legacy(&l.path, &identity).unwrap();
        let recovered = load_legacy(&l.path).unwrap().unwrap();
        assert_eq!(recovered.pending_certificate_id, identity.pending_certificate_id);
        assert!(recovered.pending_rotation_command_id.is_none());
        assert!(future_cutover_idle(&recovered).is_err());
    }
    #[test]
    fn prepared_certificate_plus_command_roundtrip() {
        let l = Lab::new(); let mut identity = fixture();
        identity.pending_certificate_id = Some("sa15v-test-cert".into());
        identity.pending_rotation_command_id = Some("sa15v-test-command".into());
        save_legacy(&l.path, &identity).unwrap();
        let recovered = load_legacy(&l.path).unwrap().unwrap();
        assert_eq!(recovered.pending_rotation_command_id, identity.pending_rotation_command_id);
        assert!(future_cutover_idle(&recovered).is_err());
    }
    #[test]
    fn successive_writes_keep_latest_identity() {
        let l = Lab::new();
        save_legacy(&l.path, &fixture()).unwrap();
        let mut newer = fixture();
        newer.device_secret = "SA15V_REPLACEMENT_SYNTHETIC_SECRET_ABCDEFGHIJKL".into();
        save_legacy(&l.path, &newer).unwrap();
        assert_eq!(load_legacy(&l.path).unwrap().unwrap().device_secret,
                   newer.device_secret);
    }
    #[test]
    fn corrupt_identity_is_error_not_missing() {
        let l = Lab::new();
        fs::write(&l.path, b"{broken").unwrap();
        fs::set_permissions(&l.path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_legacy(&l.path).is_err());
    }
    #[test]
    fn marker_blocks_existing_identity_read_and_overwrite() {
        let l = Lab::new();
        save_legacy(&l.path, &fixture()).unwrap();
        let original = fs::read(&l.path).unwrap();
        File::create(l.marker()).unwrap();
        assert!(load_legacy(&l.path).is_err());
        assert!(save_legacy(&l.path, &fixture()).is_err());
        assert_eq!(fs::read(&l.path).unwrap(), original);
    }
    #[test]
    fn marker_blocks_initial_enrollment_write() {
        let l = Lab::new();
        File::create(l.marker()).unwrap();
        assert!(save_legacy(&l.path, &fixture()).is_err());
        assert!(!l.path.exists());
    }
    #[test]
    fn symlink_marker_never_triggers_plaintext_fallback() {
        let l = Lab::new();
        symlink("/dev/null", l.marker()).unwrap();
        assert!(load_legacy(&l.path).is_err());
        assert!(save_legacy(&l.path, &fixture()).is_err());
    }
    #[test]
    fn future_cutover_only_idle_credentials() {
        assert!(future_cutover_idle(&fixture()).is_ok());
        let mut f = fixture();
        f.pending_certificate_id = Some("cert".into());
        assert!(future_cutover_idle(&f).is_err());
        f.pending_certificate_id = None;
        f.pending_rotation_command_id = Some("cmd".into());
        assert!(future_cutover_idle(&f).is_err());
    }
    #[test]
    fn router_rejects_wrong_filename_and_relative_path() {
        let l = Lab::new();
        assert!(save_legacy(&l.root.join("other.json"), &fixture()).is_err());
        assert!(load_legacy(Path::new("device.json")).is_err());
    }
}
