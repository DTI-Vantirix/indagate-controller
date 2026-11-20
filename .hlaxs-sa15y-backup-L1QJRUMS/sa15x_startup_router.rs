//! SA-15X: guarded startup identity boundary for the REAL cloud agent.
//!
//! Production-facing load/save still delegate only to the SA-15V LEGACY backend,
//! with SA-15M's sealed-cutover protection checked at agent startup AND each
//! identity operation. No live sealed-mode authorization exists in this stage.
//!
//! A separate read-only startup PREVIEW exercises SA-15U sealed full-identity
//! recovery with the same DeviceIdentity type, strictly in an isolated lab.
//! Neither a preview result nor a cutover marker can authorize live commands.
//! This is a source-only integration, NOT deployment-safe encrypted cutover.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::hybrid_secret_envelope::DataKeyWrapper;
use crate::cloud::sa15u_agent_sealed_store::Sa15uLabStore;
use crate::cloud::sa15v_identity_router;
use crate::cloud::sa15m_live_identity_gate;
use anyhow::{Context, Result, ensure};
use std::path::Path;

/// Invoked before starting the cloud-agent identity lifecycle. Will block
/// attempts to use sealed mode or legacy mode after a cutover marker.
pub fn startup_preflight(live_identity_path: &Path) -> Result<()> {
    sa15m_live_identity_gate::enforce_legacy_mode(live_identity_path)
}

/// Real cloud-agent load function. The active live mode is intentionally legacy.
pub fn load_identity(live_identity_path: &Path) -> Result<Option<DeviceIdentity>> {
    startup_preflight(live_identity_path)?;
    sa15v_identity_router::load_legacy(live_identity_path)
}

/// Real cloud-agent save function. All current enrollment/rotation writers
/// remain routed here, and pending metadata is not silently discarded.
pub fn save_identity(live_identity_path: &Path, identity: &DeviceIdentity) -> Result<()> {
    startup_preflight(live_identity_path)?;
    sa15v_identity_router::save_legacy(live_identity_path, identity)
}

/// Read-only encrypted startup PREVIEW. SA-15U limits root to an exclusively
/// created /tmp or /var/tmp `hlaxs-sa15u-lab-*` directory and admits ONLY
/// approved disposable device/controller scopes. This function does not
/// participate in live startup, enrollment, command polling, rotation or ACK.
/// `wrapper` is provided by the isolated test; the live agent has no CAAM key.
pub fn preview_sealed_startup<W: DataKeyWrapper>(
    lab_root: &Path, wrapper: &W,
) -> Result<(u64, DeviceIdentity)> {
    let store = Sa15uLabStore::new(lab_root)?;
    let (generation, identity) = store.load(wrapper)?
        .context("sealed startup preview: encrypted disposable identity missing")?;
    ensure!(generation > 0, "sealed preview: invalid generation");
    // SA-15U validates scope + the complete decrypted identity including
    // pending credential metadata. No fallback if CAAM/authentication fails.
    Ok((generation, identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct Lab { root: PathBuf, path: PathBuf }
    impl Lab {
        fn new(name: &str) -> Self {
            let root = PathBuf::from("/tmp").join(format!(
                "hlaxs-sa15u-lab-sa15x-{name}-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("device.json");
            Self { root, path }
        }
    }
    impl Drop for Lab {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }
    fn fixture() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "hlaxs-sa15u-fixture-device-sa15x".into(),
            controller_id: "hlaxs-sa15u-fixture-controller-sa15x".into(),
            organization_id: "hlaxs-sa15x-lab-organization".into(),
            site_id: "hlaxs-sa15x-lab-site".into(),
            device_secret: format!("HNXD_{}", "b7".repeat(32)),
            hardware_profile: "hlaxs-sa15x-lab-profile".into(),
            pending_certificate_id: None,
            pending_rotation_command_id: None,
        }
    }
    struct FakeWrapper;
    // Unit-test only; NEVER actual CAAM, never usable in live startup.
    impl DataKeyWrapper for FakeWrapper {
        fn wrap_32(&self, dek: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut out = *dek;
            for (i, byte) in out.iter_mut().enumerate() {
                *byte ^= iv[i % 16] ^ 0x9d;
            }
            Ok(out)
        }
        fn unwrap_32(&self, value: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(value, iv)
        }
    }
    #[test]
    fn actual_agent_legacy_identity_roundtrip() {
        let l = Lab::new("legacy");
        let record = fixture();
        save_identity(&l.path, &record).unwrap();
        let recovered = load_identity(&l.path).unwrap().unwrap();
        assert_eq!(serde_json::to_value(recovered).unwrap(),
                   serde_json::to_value(record).unwrap());
    }
    #[test]
    fn no_identity_is_not_implicitly_enrolled() {
        let l = Lab::new("missing");
        assert!(load_identity(&l.path).unwrap().is_none());
    }
    #[test]
    fn marker_rejects_startup_and_legacy_mutation() {
        let l = Lab::new("marker");
        save_identity(&l.path, &fixture()).unwrap();
        let previous = fs::read(&l.path).unwrap();
        File::create(l.root.join("cutover.json")).unwrap();
        assert!(startup_preflight(&l.path).is_err());
        assert!(load_identity(&l.path).is_err());
        assert!(save_identity(&l.path, &fixture()).is_err());
        assert_eq!(previous, fs::read(&l.path).unwrap());
    }
    #[test]
    fn symlink_marker_rejects_startup() {
        let l = Lab::new("symlink");
        symlink("/dev/null",l.root.join("cutover.json")).unwrap();
        assert!(startup_preflight(&l.path).is_err());
    }
    #[test]
    fn pending_rotation_roundtrip_is_not_lost_by_router() {
        let l = Lab::new("pending");
        let mut record = fixture();
        record.device_secret = format!("HNXD_{}", "1e".repeat(32));
        record.pending_certificate_id = Some("lab-pending-cert".into());
        record.pending_rotation_command_id = Some("lab-pending-command".into());
        save_identity(&l.path, &record).unwrap();
        let found = load_identity(&l.path).unwrap().unwrap();
        assert_eq!(found.pending_certificate_id, record.pending_certificate_id);
        assert_eq!(found.pending_rotation_command_id, record.pending_rotation_command_id);
        assert_eq!(found.device_secret, record.device_secret);
    }
    #[test]
    fn sealed_lab_preview_reads_actual_full_identity() {
        let l = Lab::new("preview");
        let st = Sa15uLabStore::new(&l.root).unwrap();
        let record = fixture();
        assert_eq!(st.write(&FakeWrapper, &record, 0, false).unwrap(), 1);
        let (generation, recovered) = preview_sealed_startup(&l.root, &FakeWrapper).unwrap();
        assert_eq!(generation, 1);
        assert_eq!(serde_json::to_value(record).unwrap(),
                   serde_json::to_value(recovered).unwrap());
        assert!(!l.path.exists()); // Never writes plaintext legacy identity.
    }
    #[test]
    fn sealed_lab_preview_recovers_pending_full_identity() {
        let l = Lab::new("pendingpreview");
        let st = Sa15uLabStore::new(&l.root).unwrap();
        let mut record = fixture();
        st.write(&FakeWrapper, &record, 0, false).unwrap();
        record.pending_certificate_id = Some("lab-cert".into());
        record.pending_rotation_command_id = Some("lab-command".into());
        record.device_secret = format!("HNXD_{}", "71".repeat(32));
        st.write(&FakeWrapper, &record, 1, false).unwrap();
        let (generation, recovered) = preview_sealed_startup(&l.root, &FakeWrapper).unwrap();
        assert_eq!(generation, 2);
        assert_eq!(serde_json::to_value(record).unwrap(),
                   serde_json::to_value(recovered).unwrap());
    }
    #[test]
    fn sealed_lab_preview_rejects_invalid_key_and_corruption() {
        let l = Lab::new("corrupt");
        let st = Sa15uLabStore::new(&l.root).unwrap();
        st.write(&FakeWrapper, &fixture(), 0, false).unwrap();
        let p = l.root.join("sealed-identity.json");
        let mut data = fs::read(&p).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        fs::write(&p, data).unwrap();
        assert!(preview_sealed_startup(&l.root, &FakeWrapper).is_err());
    }
    #[test]
    fn production_path_cannot_be_used_for_sealed_lab_preview() {
        let path = Path::new("/var/lib/highline-nexus");
        assert!(preview_sealed_startup(path, &FakeWrapper).is_err());
    }
    #[test]
    fn simulated_sealed_env_must_not_enable_live_mode() {
        let l = Lab::new("sealedmode");
        // Avoid mutating process environment across parallel Rust tests. The
        // underlying SA-15M gate proves explicit sealed mode is rejected.
        assert!(sa15m_live_identity_gate::authorize_live_sealed_mode().is_err());
        assert!(startup_preflight(&l.path).is_ok());
    }
}
