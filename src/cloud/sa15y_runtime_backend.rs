//! SA-15Y: common identity storage dispatcher for the real cloud-agent callsites.
//!
//! The live agent chooses Legacy explicitly and never derives a storage mode
//! from the environment, a network command, or a cutover marker. Development
//! sealed mode is constrained by SA-15U to an existing private lab directory
//! immediately under /tmp or /var/tmp and a known synthetic device identity.
//!
//! This is NOT a live migration, production CAAM provisioning, or an authorized
//! encrypted agent deployment. It puts legacy load/save and sealed-lab load/save
//! behind the same typed interface so future controlled cutover can use the seam.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::hybrid_secret_envelope::DataKeyWrapper;
use crate::cloud::sa15u_agent_sealed_store::Sa15uLabStore;
use crate::cloud::sa15v_identity_router;
use anyhow::{bail, ensure, Result};
use std::path::Path;

/// Never selects a mode implicitly: callers must construct the exact location.
/// The sealed variant is deliberately a test-only path rather than an on-disk
/// production backend.
pub enum IdentityLocation<'a, W: DataKeyWrapper> {
    Legacy { identity_path: &'a Path },
    SealedLab { root: &'a Path, wrapper: &'a W },
}

/// A legacy record has no monotonically increasing sealed generation; it is
/// represented as generation zero, distinct from sealed generations >= 1.
pub fn load<'a, W: DataKeyWrapper>(
    location: IdentityLocation<'a, W>,
) -> Result<Option<(u64, DeviceIdentity)>> {
    match location {
        IdentityLocation::Legacy { identity_path } => {
            let identity = sa15v_identity_router::load_legacy(identity_path)?;
            Ok(identity.map(|value| (0, value)))
        }
        IdentityLocation::SealedLab { root, wrapper } => {
            Sa15uLabStore::new(root)?.load(wrapper)
        }
    }
}

/// `expected_generation` applies to sealed updates, which compare against the
/// latest durable sealed generation. Legacy files have no generation field and
/// therefore explicitly require zero rather than feigning anti-rollback.
pub fn save<'a, W: DataKeyWrapper>(
    location: IdentityLocation<'a, W>,
    identity: &DeviceIdentity,
    expected_generation: u64,
) -> Result<u64> {
    match location {
        IdentityLocation::Legacy { identity_path } => {
            ensure!(expected_generation == 0, "legacy backend cannot carry sealed generation");
            sa15v_identity_router::save_legacy(identity_path, identity)?;
            Ok(0)
        }
        IdentityLocation::SealedLab { root, wrapper } => {
            Sa15uLabStore::new(root)?.write(wrapper, identity, expected_generation, false)
        }
    }
}

/// This key cannot encrypt or decrypt anything. It exists solely to fix the
/// live agent's type parameter to the legacy branch without providing CAAM.
struct NoLiveKey;
impl DataKeyWrapper for NoLiveKey {
    fn wrap_32(&self, _dek: &[u8; 32], _iv: &[u8; 16]) -> Result<[u8; 32]> {
        bail!("live encrypted backend has not been authorized")
    }
    fn unwrap_32(&self, _data: &[u8; 32], _iv: &[u8; 16]) -> Result<[u8; 32]> {
        bail!("live encrypted backend has not been authorized")
    }
}

/// Called by the real SA-15X cloud-agent startup path. Never sealed.
pub fn load_live_legacy(path: &Path) -> Result<Option<DeviceIdentity>> {
    Ok(load(IdentityLocation::<NoLiveKey>::Legacy { identity_path: path })?
        .map(|(_, identity)| identity))
}

/// Called by the real cloud-agent enrollment and rotation persistence paths.
/// No sealed write is possible through this API.
pub fn save_live_legacy(path: &Path, identity: &DeviceIdentity) -> Result<()> {
    save(IdentityLocation::<NoLiveKey>::Legacy { identity_path: path }, identity, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct TestKey;
    // No real CAAM in WSL unit tests. SA-15W already verified native
    // CAAM wrapping on i.MX8MP; this wrapper only exercises dispatch.
    impl DataKeyWrapper for TestKey {
        fn wrap_32(&self, dek: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut out = *dek;
            for (i, byte) in out.iter_mut().enumerate() { *byte ^= iv[i % 16] ^ 0xa3; }
            Ok(out)
        }
        fn unwrap_32(&self, value: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(value, iv)
        }
    }

    struct Lab { root: PathBuf }
    impl Lab {
        fn new() -> Self {
            let root = PathBuf::from("/tmp").join(format!(
                "hlaxs-sa15u-lab-sa15y-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root }
        }
        fn legacy(&self) -> PathBuf { self.root.join("device.json") }
        fn sealed(&self) -> IdentityLocation<'_, TestKey> {
            // TestKey is a unit-scoped zero-size value with static lifetime.
            static KEY: TestKey = TestKey;
            IdentityLocation::SealedLab { root: &self.root, wrapper: &KEY }
        }
    }
    impl Drop for Lab { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

    fn fixture() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "hlaxs-sa15u-fixture-device-sa15y".into(),
            controller_id: "hlaxs-sa15u-fixture-controller-sa15y".into(),
            organization_id: "hlaxs-sa15y-test-org".into(),
            site_id: "hlaxs-sa15y-test-site".into(),
            hardware_profile: "hlaxs-sa15y-lab-hardware".into(),
            device_secret: format!("HNXD_{}", "ab".repeat(32)),
            pending_certificate_id: None,
            pending_rotation_command_id: None,
        }
    }
    fn same(a: &DeviceIdentity, b: &DeviceIdentity) -> bool {
        serde_json::to_value(a).unwrap() == serde_json::to_value(b).unwrap()
    }
    #[test]
    fn live_agent_calls_shared_legacy_dispatch_without_using_key() {
        let lab = Lab::new(); let record=fixture();
        save_live_legacy(&lab.legacy(), &record).unwrap();
        let found=load_live_legacy(&lab.legacy()).unwrap().unwrap();
        assert!(same(&record,&found));
        assert!(!lab.root.join("sealed-identity.json").exists());
    }
    #[test]
    fn sealed_dispatch_roundtrip_never_writes_plaintext_identity() {
        let lab=Lab::new(); let record=fixture();
        assert_eq!(save(lab.sealed(), &record, 0).unwrap(), 1);
        let (generation,recovered)=load(lab.sealed()).unwrap().unwrap();
        assert_eq!(generation,1);assert!(same(&record,&recovered));
        assert!(!lab.legacy().exists());
        let raw=fs::read_to_string(lab.root.join("sealed-identity.json")).unwrap();
        assert!(!raw.contains(&record.device_secret));
        assert!(!raw.contains(&record.organization_id));
    }
    #[test]
    fn sealed_pending_rotation_save_recover_finalize_and_stale_reject() {
        let lab=Lab::new(); let mut r=fixture();
        assert_eq!(save(lab.sealed(),&r,0).unwrap(),1);
        r.device_secret=format!("HNXD_{}","bc".repeat(32));
        r.pending_certificate_id=Some("sa15y-certificate".into());
        r.pending_rotation_command_id=Some("sa15y-command".into());
        assert_eq!(save(lab.sealed(),&r,1).unwrap(),2);
        assert!(same(&r,&load(lab.sealed()).unwrap().unwrap().1));
        assert!(save(lab.sealed(),&r,1).is_err());
        r.pending_certificate_id=None;r.pending_rotation_command_id=None;
        assert_eq!(save(lab.sealed(),&r,2).unwrap(),3);
        let (generation,out)=load(lab.sealed()).unwrap().unwrap();
        assert_eq!(generation,3);assert!(same(&r,&out));
    }
    #[test]
    fn sealed_corruption_fails_without_plaintext_fallback() {
        let lab=Lab::new();let r=fixture();
        save(lab.sealed(),&r,0).unwrap();
        let path=lab.root.join("sealed-identity.json");
        fs::write(&path,b"{corrupted").unwrap();
        assert!(load(lab.sealed()).is_err());
        assert!(!lab.legacy().exists());
    }
    #[test]
    fn legacy_marker_still_prevents_startup_load_and_save() {
        let lab=Lab::new();let r=fixture();
        save_live_legacy(&lab.legacy(),&r).unwrap();
        File::create(lab.root.join("cutover.json")).unwrap();
        assert!(load_live_legacy(&lab.legacy()).is_err());
        assert!(save_live_legacy(&lab.legacy(),&r).is_err());
    }
    #[test]
    fn sealed_mode_cannot_point_to_production_path() {
        let key=TestKey;
        let production=Path::new("/var/lib/highline-nexus");
        assert!(load(IdentityLocation::SealedLab {root:production,wrapper:&key}).is_err());
        assert!(save(IdentityLocation::SealedLab {root:production,wrapper:&key},&fixture(),0).is_err());
    }
    #[test]
    fn legacy_rejects_fake_sealed_generation() {
        let lab=Lab::new();let key=TestKey;
        assert!(save(IdentityLocation::<TestKey>::Legacy {identity_path:&lab.legacy()},&fixture(),1).is_err());
        // The explicit key exists but no sealed file can be created by live API.
        let _=key;
        assert!(!lab.root.join("sealed-identity.json").exists());
    }
    #[test]
    fn symlink_cutover_marker_blocks_live_even_if_sealed_lab_exists() {
        let lab=Lab::new();let r=fixture();
        save(lab.sealed(),&r,0).unwrap();
        symlink("/dev/null", lab.root.join("cutover.json")).unwrap();
        assert!(load_live_legacy(&lab.legacy()).is_err());
        assert!(save_live_legacy(&lab.legacy(),&r).is_err());
    }
}
