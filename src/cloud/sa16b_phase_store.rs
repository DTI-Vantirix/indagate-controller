//! SA-16B: one phase-aware lifecycle implementation used by the *real* agent
//! through LegacyLive, and by the restricted CAAM-sealed lab backend.
//!
//! This is a source integration, not authorization for live sealed cutover.
//! The real agent still selects LegacyLive explicitly at its three call sites.
//! The sealed path is constrained to SA-15U's private disposable lab root;
//! neither environment variables nor cloud commands choose a backend.
//! Generation is crash-consistent under one writer, NOT hardware anti-rollback
//! and NOT an interprocess CAS lock.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::hybrid_secret_envelope::DataKeyWrapper;
use crate::cloud::sa15y_runtime_backend::{self, IdentityLocation};
use crate::cloud::sa15z_caam_runtime;
use crate::cloud::sa16a_identity_lifecycle::validate_startup_state;
use anyhow::{ensure, Context, Result};
use std::path::Path;

pub trait IdentityBackend {
    fn load(&self) -> Result<Option<(u64, DeviceIdentity)>>;
    fn save(&self, identity: &DeviceIdentity, expected: u64) -> Result<u64>;
}

/// Only this backend is selected by the actual cloud agent at SA-16B.
pub struct LegacyLive<'a> { pub identity_path: &'a Path }
impl IdentityBackend for LegacyLive<'_> {
    fn load(&self) -> Result<Option<(u64, DeviceIdentity)>> {
        Ok(sa15y_runtime_backend::load_live_legacy(self.identity_path)?
            .map(|identity| (0, identity)))
    }
    fn save(&self, identity: &DeviceIdentity, expected: u64) -> Result<u64> {
        ensure!(expected == 0, "legacy storage cannot use sealed generation");
        sa15y_runtime_backend::save_live_legacy(self.identity_path, identity)?;
        Ok(0)
    }
}

/// Offline/WLS development adapter. Test wrappers are not cryptographic roots.
/// SA-15U validates ownership, exact allowed path, and disposable identity.
pub struct SealedLab<'a, W: DataKeyWrapper> {
    pub root: &'a Path,
    pub wrapper: &'a W,
}
impl<W: DataKeyWrapper> IdentityBackend for SealedLab<'_, W> {
    fn load(&self) -> Result<Option<(u64, DeviceIdentity)>> {
        sa15y_runtime_backend::load(IdentityLocation::SealedLab {
            root: self.root, wrapper: self.wrapper,
        })
    }
    fn save(&self, identity: &DeviceIdentity, expected: u64) -> Result<u64> {
        sa15y_runtime_backend::save(IdentityLocation::SealedLab {
            root: self.root, wrapper: self.wrapper,
        }, identity, expected)
    }
}

/// Real CAAM key-blob restoration, but ONLY for an SA-15U disposable lab.
/// The underlying SA-15Z provider reimports the key separately for each
/// operation and explicitly refuses /var/lib/highline-nexus.
pub struct RestoredCaamLab<'a> { pub root: &'a Path }
impl IdentityBackend for RestoredCaamLab<'_> {
    fn load(&self) -> Result<Option<(u64, DeviceIdentity)>> {
        sa15z_caam_runtime::with_restored_lab_caam(self.root, |wrapper| {
            sa15y_runtime_backend::load(IdentityLocation::SealedLab {
                root: self.root, wrapper,
            })
        })
    }
    fn save(&self, identity: &DeviceIdentity, expected: u64) -> Result<u64> {
        sa15z_caam_runtime::save_lab_with_caam(self.root, identity, expected)
    }
}

fn identical(a: &DeviceIdentity, b: &DeviceIdentity) -> Result<bool> {
    Ok(serde_json::to_value(a)? == serde_json::to_value(b)?)
}
fn same_scope(a: &DeviceIdentity, b: &DeviceIdentity) -> bool {
    a.device_id == b.device_id && a.controller_id == b.controller_id
        && a.organization_id == b.organization_id && a.site_id == b.site_id
        && a.hardware_profile == b.hardware_profile
}
fn valid_command(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

/// Never changes cloud state. A restart can use this after decrypting a
/// disposable sealed identity and before attempting commit/ACK replay.
pub fn recover<B: IdentityBackend>(backend: &B) -> Result<Option<(u64, DeviceIdentity)>> {
    let found = backend.load()?;
    if let Some((_, record)) = &found { validate_startup_state(record)?; }
    Ok(found)
}

fn save_and_confirm<B: IdentityBackend>(
    backend: &B, identity: &DeviceIdentity, expected: u64,
) -> Result<u64> {
    let next = backend.save(identity, expected).context("persist identity phase")?;
    let (observed, stored) = recover(backend)?
        .context("identity disappeared after durable write")?;
    ensure!(next == observed && identical(identity, &stored)?,
        "authenticated identity phase readback mismatch");
    Ok(next)
}

/// Initial enrollment. Caller must ensure a single writer; the sealed
/// generation check is not a process-shared lock.
pub fn enroll<B: IdentityBackend>(backend: &B, identity: &DeviceIdentity) -> Result<u64> {
    validate_startup_state(identity)?;
    ensure!(identity.pending_certificate_id.is_none()
        && identity.pending_rotation_command_id.is_none(),
        "enrollment contains pending rotation metadata");
    ensure!(recover(backend)?.is_none(), "existing enrollment may not be overwritten");
    save_and_confirm(backend, identity, 0)
}

/// Cloud /prepare has completed, but /commit MUST NOT run until this returns.
pub fn prepare<B: IdentityBackend>(
    backend: &B, previous: &DeviceIdentity, replacement: &DeviceIdentity,
    command_id: &str,
) -> Result<u64> {
    validate_startup_state(previous)?;
    validate_startup_state(replacement)?;
    ensure!(previous.pending_certificate_id.is_none()
        && previous.pending_rotation_command_id.is_none(),
        "a second rotation cannot begin while one is pending");
    ensure!(same_scope(previous, replacement), "rotation changes identity binding");
    ensure!(previous.device_secret != replacement.device_secret,
        "rotation must change the credential");
    ensure!(valid_command(command_id), "invalid command id");
    ensure!(replacement.pending_certificate_id.is_some()
        && replacement.pending_rotation_command_id.as_deref() == Some(command_id),
        "prepared credential missing certificate or command binding");
    let (generation, stored) = recover(backend)?
        .context("rotation requires an enrolled identity")?;
    ensure!(identical(&stored, previous)?,
        "durable identity changed since rotation preparation");
    save_and_confirm(backend, replacement, generation)
}

/// Called by agent only AFTER actual cloud commit and command ACK succeeded.
/// If persistence fails, the stored pending record remains for restart replay.
pub fn finalize<B: IdentityBackend>(backend: &B, finalized: &DeviceIdentity) -> Result<u64> {
    validate_startup_state(finalized)?;
    ensure!(finalized.pending_certificate_id.is_none()
        && finalized.pending_rotation_command_id.is_none(),
        "cannot finalize with pending fields");
    let (generation, current) = recover(backend)?
        .context("cannot finalize without a prepared record")?;
    ensure!(current.pending_certificate_id.is_some(),
        "finalization requires pending rotation");
    ensure!(same_scope(&current, finalized)
        && current.device_secret == finalized.device_secret,
        "finalization changes device scope or credential");
    save_and_confirm(backend, finalized, generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    struct FakeWrapper(u8);
    impl DataKeyWrapper for FakeWrapper {
        fn wrap_32(&self, key: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut out = *key;
            for (i,b) in out.iter_mut().enumerate() { *b ^= iv[i % 16] ^ self.0; }
            Ok(out)
        }
        fn unwrap_32(&self, wrapped: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(wrapped, iv)
        }
    }
    struct Lab { root: PathBuf, legacy_path: PathBuf }
    impl Lab {
        fn new() -> Self {
            let root=PathBuf::from("/tmp").join(format!(
                "hlaxs-sa15u-lab-sa16b-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
            let legacy_path=root.join("device.json");
            Self { root, legacy_path }
        }
        fn legacy(&self) -> LegacyLive<'_> { LegacyLive{identity_path: &self.legacy_path} }
        fn sealed<'a>(&'a self, key: &'a FakeWrapper) -> SealedLab<'a, FakeWrapper> {
            SealedLab{root:&self.root,wrapper:key}
        }
    }
    impl Drop for Lab { fn drop(&mut self) { let _=fs::remove_dir_all(&self.root); } }
    fn original() -> DeviceIdentity {
        DeviceIdentity {
            device_id:"hlaxs-sa15u-fixture-device-sa16b".into(),
            controller_id:"hlaxs-sa15u-fixture-controller-sa16b".into(),
            organization_id:"sa16b-org".into(), site_id:"sa16b-site".into(),
            device_secret:format!("HNXD_{}", "ab".repeat(32)),
            hardware_profile:"sa16b-controller".into(),
            pending_certificate_id:None, pending_rotation_command_id:None,
        }
    }
    fn prepared() -> DeviceIdentity {
        let mut r=original();
        r.device_secret=format!("HNXD_{}", "ce".repeat(32));
        r.pending_certificate_id=Some("sa16b-pending-certificate".into());
        r.pending_rotation_command_id=Some("sa16b-original-command".into());
        r
    }
    fn finalized() -> DeviceIdentity {
        let mut r=prepared();r.pending_certificate_id=None;
        r.pending_rotation_command_id=None;r
    }
    #[test]
    fn sealed_phases_share_agent_semantics_and_generation() {
        let lab=Lab::new();let key=FakeWrapper(0x31);let s=lab.sealed(&key);
        assert_eq!(enroll(&s,&original()).unwrap(),1);
        assert_eq!(prepare(&s,&original(),&prepared(),"sa16b-original-command").unwrap(),2);
        assert_eq!(recover(&s).unwrap().unwrap().1.pending_certificate_id.as_deref(),Some("sa16b-pending-certificate"));
        assert_eq!(finalize(&s,&finalized()).unwrap(),3);
        let (g,id)=recover(&s).unwrap().unwrap();
        assert_eq!(g,3);assert!(identical(&id,&finalized()).unwrap());
        assert!(!lab.root.join("device.json").exists());
    }
    #[test]
    fn legacy_phases_use_same_functions_and_keep_generation_zero() {
        let lab=Lab::new();let l=lab.legacy();
        assert_eq!(enroll(&l,&original()).unwrap(),0);
        assert_eq!(prepare(&l,&original(),&prepared(),"sa16b-original-command").unwrap(),0);
        assert_eq!(finalize(&l,&finalized()).unwrap(),0);
        assert_eq!(recover(&l).unwrap().unwrap().0,0);
        assert!(!lab.root.join("sealed-identity.json").exists());
    }
    #[test]
    fn sealed_duplicate_enrollment_cannot_overwrite() {
        let lab=Lab::new();let key=FakeWrapper(0x32);let s=lab.sealed(&key);
        enroll(&s,&original()).unwrap();
        assert!(enroll(&s,&prepared()).is_err());
        assert!(enroll(&s,&original()).is_err());
    }
    #[test]
    fn sealed_preparation_rejects_stale_identity() {
        let lab=Lab::new();let key=FakeWrapper(0x33);let s=lab.sealed(&key);
        enroll(&s,&original()).unwrap();
        let mut stale=original();stale.device_secret=format!("HNXD_{}", "da".repeat(32));
        assert!(prepare(&s,&stale,&prepared(),"sa16b-original-command").is_err());
        assert_eq!(recover(&s).unwrap().unwrap().0,1);
    }
    #[test]
    fn sealed_preparation_rejects_command_and_scope_mismatch() {
        let lab=Lab::new();let key=FakeWrapper(0x34);let s=lab.sealed(&key);
        enroll(&s,&original()).unwrap();
        assert!(prepare(&s,&original(),&prepared(),"wrong-command").is_err());
        let mut changed=prepared();changed.site_id="different-site".into();
        assert!(prepare(&s,&original(),&changed,"sa16b-original-command").is_err());
        assert_eq!(recover(&s).unwrap().unwrap().0,1);
    }
    #[test]
    fn sealed_second_rotation_is_rejected() {
        let lab=Lab::new();let key=FakeWrapper(0x35);let s=lab.sealed(&key);
        enroll(&s,&original()).unwrap();
        prepare(&s,&original(),&prepared(),"sa16b-original-command").unwrap();
        assert!(prepare(&s,&prepared(),&prepared(),"sa16b-original-command").is_err());
        assert_eq!(recover(&s).unwrap().unwrap().0,2);
    }
    #[test]
    fn sealed_finalization_requires_prepared_identity() {
        let lab=Lab::new();let key=FakeWrapper(0x36);let s=lab.sealed(&key);
        enroll(&s,&original()).unwrap();
        assert!(finalize(&s,&original()).is_err());
        prepare(&s,&original(),&prepared(),"sa16b-original-command").unwrap();
        let mut changed=finalized();changed.device_secret=format!("HNXD_{}", "dd".repeat(32));
        assert!(finalize(&s,&changed).is_err());
        assert_eq!(recover(&s).unwrap().unwrap().0,2);
    }
    #[test]
    fn sealed_tamper_rejected_without_plaintext_fallback() {
        let lab=Lab::new();let key=FakeWrapper(0x37);let s=lab.sealed(&key);
        enroll(&s,&original()).unwrap();
        fs::write(lab.root.join("sealed-identity.json"),b"{bad-record").unwrap();
        assert!(recover(&s).is_err());
        assert!(!lab.root.join("device.json").exists());
        assert!(prepare(&s,&original(),&prepared(),"sa16b-original-command").is_err());
    }
    #[test]
    fn incorrect_wrapper_does_not_open_record() {
        let lab=Lab::new();let key=FakeWrapper(0x38);let wrong=FakeWrapper(0x55);
        enroll(&lab.sealed(&key),&original()).unwrap();
        assert!(recover(&lab.sealed(&wrong)).is_err());
    }
    #[test]
    fn encrypted_record_does_not_include_scope_or_secret_in_plaintext() {
        let lab=Lab::new();let key=FakeWrapper(0x39);let s=lab.sealed(&key);
        enroll(&s,&original()).unwrap();
        let raw=fs::read_to_string(lab.root.join("sealed-identity.json")).unwrap();
        assert!(!raw.contains(&original().device_secret));
        assert!(!raw.contains(&original().organization_id));
        assert!(!raw.contains(&original().site_id));
    }
    #[test]
    fn production_path_refused_by_caam_adapter_before_keygen() {
        assert!(RestoredCaamLab{root:Path::new("/var/lib/highline-nexus")}.load().is_err());
    }
    #[test]
    fn missing_caam_blob_fails_closed_in_private_lab() {
        let lab=Lab::new();
        assert!(RestoredCaamLab{root:&lab.root}.load().is_err());
    }
    #[test]
    fn legacy_cutover_marker_rejects_lifecycle() {
        let lab=Lab::new();let l=lab.legacy();
        enroll(&l,&original()).unwrap();
        fs::write(lab.root.join("cutover.json"),b"").unwrap();
        assert!(recover(&l).is_err());
        assert!(prepare(&l,&original(),&prepared(),"sa16b-original-command").is_err());
    }
}
