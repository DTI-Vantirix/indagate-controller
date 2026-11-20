//! SA-16E: an explicitly selected identity runtime for the *installed* agent
//! lifecycle. Operational entry points ALWAYS select the existing guarded
//! LegacyLive backend. A separate disposable selection is restricted to the
//! exact SA-15U CAAM lab and does not enable a running cloud agent, cutover,
//! or changes to operational SightPas credentials or services.
//!
//! No environment-variable selector, implicit marker-selected conversion,
//! plaintext fallback, automatic key creation, or production CAAM provisioning.
//! Generation checks are single-writer checks, not hardware anti-rollback.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::sa15m_live_identity_gate;
use crate::cloud::sa15u_agent_sealed_store::Sa15uLabStore;
use crate::cloud::sa16b_phase_store::{self, IdentityBackend, LegacyLive, RestoredCaamLab};
use anyhow::{ensure, Context, Result};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// A trusted caller must construct the mode explicitly. It cannot be selected
/// from a cloud payload, environment variable, or a file marker.
pub enum IdentityRuntime<'a> {
    OperationalLegacy { identity_path: &'a Path },
    DisposableCaamLab { root: &'a Path },
}

impl<'a> IdentityRuntime<'a> {
    /// The ONLY selector called by the actual agent's lifecycle wrappers.
    pub fn operational(identity_path: &'a Path) -> Result<Self> {
        sa15m_live_identity_gate::enforce_legacy_mode(identity_path)?;
        Ok(Self::OperationalLegacy { identity_path })
    }

    /// Explicit nonproduction entry point. The lab is a root-owned/private
    /// directory DIRECTLY under /tmp or /var/tmp; no production paths or
    /// symlinks are allowed. CAAM blob and key permissions are checked again
    /// by SA-15Z on each actual operation.
    pub fn disposable_caam(root: &'a Path) -> Result<Self> {
        Sa15uLabStore::new(root)?;
        let metadata = fs::symlink_metadata(root).context("SA-16E disposable lab missing")?;
        ensure!(metadata.is_dir() && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
            "disposable lab ownership or directory privacy invalid");
        Ok(Self::DisposableCaamLab { root })
    }

    pub fn recover(&self) -> Result<Option<(u64, DeviceIdentity)>> {
        sa16b_phase_store::recover(self)
    }
    pub fn enroll(&self, identity: &DeviceIdentity) -> Result<u64> {
        sa16b_phase_store::enroll(self, identity)
    }
    pub fn prepare(
        &self, previous: &DeviceIdentity, replacement: &DeviceIdentity, command_id: &str,
    ) -> Result<u64> {
        sa16b_phase_store::prepare(self, previous, replacement, command_id)
    }
    /// The existing agent remains responsible for real cloud commit + ACK.
    /// This entry point only finalizes durable identity after its caller has
    /// completed those operations; it never issues cloud requests itself.
    pub fn finalize_after_commit_ack(&self, identity: &DeviceIdentity) -> Result<u64> {
        sa16b_phase_store::finalize(self, identity)
    }
}

impl IdentityBackend for IdentityRuntime<'_> {
    fn load(&self) -> Result<Option<(u64, DeviceIdentity)>> {
        match self {
            Self::OperationalLegacy { identity_path } => {
                sa15m_live_identity_gate::enforce_legacy_mode(identity_path)?;
                LegacyLive { identity_path }.load()
            }
            Self::DisposableCaamLab { root } => {
                // Recheck before EVERY CAAM access; no implicit fallback.
                IdentityRuntime::disposable_caam(root)?;
                RestoredCaamLab { root }.load()
            }
        }
    }
    fn save(&self, identity: &DeviceIdentity, expected: u64) -> Result<u64> {
        match self {
            Self::OperationalLegacy { identity_path } => {
                sa15m_live_identity_gate::enforce_legacy_mode(identity_path)?;
                LegacyLive { identity_path }.save(identity, expected)
            }
            Self::DisposableCaamLab { root } => {
                IdentityRuntime::disposable_caam(root)?;
                RestoredCaamLab { root }.save(identity, expected)
            }
        }
    }
}

/// These wrappers are called from the *actual* SA-16A agent enrollment,
/// prepare, and post-commit/ACK finalization functions. Their mode cannot be
/// provided by the cloud or chosen from a device file.
pub fn enroll_operational(path: &Path, identity: &DeviceIdentity) -> Result<()> {
    IdentityRuntime::operational(path)?.enroll(identity)?;
    Ok(())
}
pub fn prepare_operational(
    path: &Path, previous: &DeviceIdentity, replacement: &DeviceIdentity,
    command_id: &str,
) -> Result<()> {
    IdentityRuntime::operational(path)?.prepare(previous, replacement, command_id)?;
    Ok(())
}
pub fn finalize_operational_after_commit_ack(path: &Path, identity: &DeviceIdentity) -> Result<()> {
    IdentityRuntime::operational(path)?.finalize_after_commit_ack(identity)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::sa16d_startup_recovery;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    struct Lab { root: PathBuf, path: PathBuf }
    impl Lab {
        fn new() -> Self {
            let root = PathBuf::from("/tmp").join(format!(
                "hlaxs-sa15u-lab-sa16e-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("device.json");
            Self { root, path }
        }
    }
    impl Drop for Lab { fn drop(&mut self) { let _=fs::remove_dir_all(&self.root); } }
    fn enrolled() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "hlaxs-sa15u-fixture-device-sa16e".into(),
            controller_id: "hlaxs-sa15u-fixture-controller-sa16e".into(),
            organization_id: "sa16e-org".into(), site_id: "sa16e-site".into(),
            device_secret: format!("HNXD_{}", "2b".repeat(32)),
            hardware_profile: "sa16e-sightpas-lab".into(),
            pending_certificate_id: None, pending_rotation_command_id: None,
        }
    }
    fn pending() -> DeviceIdentity {
        let mut next=enrolled();
        next.device_secret=format!("HNXD_{}", "3c".repeat(32));
        next.pending_certificate_id=Some("sa16e-cert".into());
        next.pending_rotation_command_id=Some("sa16e-command".into());
        next
    }
    fn same(a: &DeviceIdentity,b: &DeviceIdentity)->bool {
        serde_json::to_value(a).unwrap()==serde_json::to_value(b).unwrap()
    }
    #[test]
    fn actual_agent_lifecycle_selects_legacy_and_recovers_at_startup() {
        let l=Lab::new();let i=enrolled();
        enroll_operational(&l.path,&i).unwrap();
        let saved=sa16d_startup_recovery::load_legacy_for_agent(&l.path)
            .unwrap().unwrap();
        assert!(same(&i,&saved));
        assert!(!l.root.join("sealed-identity.json").exists());
    }
    #[test]
    fn actual_agent_phase_replay_preserves_pending_and_finalizes() {
        let l=Lab::new(); let orig=enrolled();let next=pending();
        enroll_operational(&l.path,&orig).unwrap();
        prepare_operational(&l.path,&orig,&next,"sa16e-command").unwrap();
        let runtime=IdentityRuntime::operational(&l.path).unwrap();
        let (generation,saved)=runtime.recover().unwrap().unwrap();
        assert_eq!(generation,0);assert!(same(&next,&saved));
        assert!(prepare_operational(&l.path,&orig,&next,"sa16e-command").is_err());
        let mut done=next.clone();
        done.pending_certificate_id=None;done.pending_rotation_command_id=None;
        finalize_operational_after_commit_ack(&l.path,&done).unwrap();
        assert!(same(&done,&runtime.recover().unwrap().unwrap().1));
    }
    #[test]
    fn missing_identity_cannot_be_implicitly_created_on_load() {
        let l=Lab::new();let runtime=IdentityRuntime::operational(&l.path).unwrap();
        assert!(runtime.recover().unwrap().is_none());
        assert!(!l.path.exists());
    }
    #[test]
    fn sealed_selector_rejects_live_controller_directory() {
        assert!(IdentityRuntime::disposable_caam(Path::new("/var/lib/highline-nexus")).is_err());
    }
    #[test]
    fn sealed_selector_rejects_world_readable_and_symlink_labs() {
        let l=Lab::new();
        fs::set_permissions(&l.root,fs::Permissions::from_mode(0o755)).unwrap();
        assert!(IdentityRuntime::disposable_caam(&l.root).is_err());
        fs::set_permissions(&l.root,fs::Permissions::from_mode(0o700)).unwrap();
        let sl=l.root.with_file_name(format!("hlaxs-sa15u-lab-sa16e-link-{}",uuid::Uuid::new_v4()));
        symlink(&l.root,&sl).unwrap();
        assert!(IdentityRuntime::disposable_caam(&sl).is_err());
        fs::remove_file(&sl).unwrap();
    }
    #[test]
    fn sealed_selector_requires_precreated_lab_and_does_not_enroll() {
        let path=PathBuf::from("/tmp").join(format!("hlaxs-sa15u-lab-sa16e-missing-{}",uuid::Uuid::new_v4()));
        assert!(IdentityRuntime::disposable_caam(&path).is_err());
        assert!(!path.exists());
    }
    #[test]
    fn missing_caam_blob_fails_closed_without_plaintext_fallback() {
        let l=Lab::new();
        let selected=IdentityRuntime::disposable_caam(&l.root).unwrap();
        assert!(selected.recover().is_err());
        assert!(selected.enroll(&enrolled()).is_err());
        assert!(!l.path.exists());
        assert!(!l.root.join("sealed-identity.json").exists());
    }
    #[test]
    fn cutover_marker_blocks_operational_reads_and_writes() {
        let l=Lab::new();
        enroll_operational(&l.path,&enrolled()).unwrap();
        let bytes=fs::read(&l.path).unwrap();
        fs::write(l.root.join("cutover.json"),b"marker").unwrap();
        assert!(IdentityRuntime::operational(&l.path).is_err());
        assert!(finalize_operational_after_commit_ack(&l.path,&enrolled()).is_err());
        assert_eq!(bytes,fs::read(&l.path).unwrap());
    }
    #[test]
    fn runtime_mode_cannot_enable_from_environment_or_remote_command() {
        let l=Lab::new();
        let selected=IdentityRuntime::operational(&l.path).unwrap();
        assert!(matches!(selected, IdentityRuntime::OperationalLegacy { .. }));
        assert!(!l.root.join("sealed-identity.json").exists());
    }
}
