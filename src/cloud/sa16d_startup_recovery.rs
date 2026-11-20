//! SA-16D: real agent startup loads through the existing SA-16B phase engine.
//!
//! Live startup is explicitly LegacyLive and rejects sealed cutover markers.
//! The CAAM branch is a READ-ONLY inspection of an isolated SA-15U lab,
//! not a production identity loader, selector, migration, or deployment gate.
//! No environment flag, cloud payload, or on-disk marker enables sealed live mode.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::sa15m_live_identity_gate;
use crate::cloud::sa16a_identity_lifecycle::validate_startup_state;
use crate::cloud::sa16b_phase_store::{self, LegacyLive, RestoredCaamLab};
use anyhow::{ensure, Context, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPhase {
    Enrolled,
    PreparedCertificateOnly,
    PreparedWithCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupCheckpoint {
    pub generation: u64,
    pub phase: RecoveryPhase,
}

/// Classifies persisted state without logging, modifying, or exporting any secret.
/// A certificate-only state can follow a crash between cloud /prepare and the
/// original rotation-command association. The EXISTING agent replay logic handles
/// that state; this module neither commits nor acknowledges cloud operations.
fn checkpoint(generation: u64, identity: &DeviceIdentity) -> Result<StartupCheckpoint> {
    validate_startup_state(identity)?;
    let phase = match (
        identity.pending_certificate_id.as_ref(),
        identity.pending_rotation_command_id.as_ref(),
    ) {
        (None, None) => RecoveryPhase::Enrolled,
        (Some(_), None) => RecoveryPhase::PreparedCertificateOnly,
        (Some(_), Some(_)) => RecoveryPhase::PreparedWithCommand,
        (None, Some(_)) => anyhow::bail!("pending command without certificate"),
    };
    Ok(StartupCheckpoint { generation, phase })
}

/// Called by the ACTUAL SA-15X agent startup `load_identity` function.
/// The only accepted operational backend is the same LegacyLive used by
/// SA-16B enrollment, prepare and finalization. Startup now recovers and
/// validates through the SAME phase engine rather than a separate direct load.
pub fn load_legacy_for_agent(identity_path: &Path) -> Result<Option<DeviceIdentity>> {
    sa15m_live_identity_gate::enforce_legacy_mode(identity_path)
        .context("SA-16D live legacy startup guard")?;
    let recovered = sa16b_phase_store::recover(&LegacyLive { identity_path })?;
    match recovered {
        None => Ok(None),
        Some((generation, identity)) => {
            ensure!(generation == 0, "legacy runtime returned a sealed generation");
            let _state = checkpoint(generation, &identity)?;
            Ok(Some(identity))
        }
    }
}

/// Separate CAAM-only PREVIEW. This cannot access the live identity directory:
/// the existing SA-15Z provider rejects production paths before key import.
/// No identity or device secret is returned; just generation and rotation phase.
/// Do not use this function to authorize production startup.
pub fn preview_restored_caam_checkpoint(lab_root: &Path) -> Result<StartupCheckpoint> {
    let (generation, identity) = sa16b_phase_store::recover(
        &RestoredCaamLab { root: lab_root },
    )?.context("SA-16D sealed-lab identity missing")?;
    ensure!(generation > 0, "sealed identity must have positive generation");
    checkpoint(generation, &identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::sa16b_phase_store::{self, LegacyLive};
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct Lab { root: PathBuf, identity_path: PathBuf }
    impl Lab {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "hlaxs-sa16d-startup-{}", uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let identity_path = root.join("device.json");
            Self { root, identity_path }
        }
        fn backend(&self) -> LegacyLive<'_> {
            LegacyLive { identity_path: &self.identity_path }
        }
    }
    impl Drop for Lab {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }
    fn initial() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "hlaxs-sa16d-device".into(),
            controller_id: "hlaxs-sa16d-controller".into(),
            organization_id: "hlaxs-sa16d-org".into(),
            site_id: "hlaxs-sa16d-site".into(),
            device_secret: format!("HNXD_{}", "11".repeat(32)),
            hardware_profile: "hlaxs-sa16d-lab".into(),
            pending_certificate_id: None,
            pending_rotation_command_id: None,
        }
    }
    fn pending() -> DeviceIdentity {
        let mut i = initial();
        i.device_secret = format!("HNXD_{}", "22".repeat(32));
        i.pending_certificate_id = Some("hlaxs-sa16d-new-cert".into());
        i.pending_rotation_command_id = Some("hlaxs-sa16d-command".into());
        i
    }
    #[test]
    fn actual_agent_load_uses_real_shared_phase_backend() {
        let lab=Lab::new();
        sa16b_phase_store::enroll(&lab.backend(), &initial()).unwrap();
        let recovered=load_legacy_for_agent(&lab.identity_path).unwrap().unwrap();
        assert_eq!(serde_json::to_value(&recovered).unwrap(), serde_json::to_value(initial()).unwrap());
        assert_eq!(checkpoint(0,&recovered).unwrap().phase,RecoveryPhase::Enrolled);
    }
    #[test]
    fn startup_recovers_durable_prepared_rotation() {
        let lab=Lab::new();
        sa16b_phase_store::enroll(&lab.backend(), &initial()).unwrap();
        sa16b_phase_store::prepare(&lab.backend(), &initial(), &pending(), "hlaxs-sa16d-command").unwrap();
        let recovered=load_legacy_for_agent(&lab.identity_path).unwrap().unwrap();
        assert_eq!(recovered.pending_rotation_command_id, pending().pending_rotation_command_id);
        assert_eq!(checkpoint(0,&recovered).unwrap().phase,RecoveryPhase::PreparedWithCommand);
    }
    #[test]
    fn certificate_only_state_is_recognized_for_existing_replay() {
        let mut record=pending();
        record.pending_rotation_command_id=None;
        assert_eq!(checkpoint(0,&record).unwrap().phase,RecoveryPhase::PreparedCertificateOnly);
    }
    #[test]
    fn orphan_command_rejected_before_networking() {
        let mut record=pending();
        record.pending_certificate_id=None;
        assert!(checkpoint(0,&record).is_err());
    }
    #[test]
    fn missing_enrollment_does_not_trigger_implicit_creation() {
        let lab=Lab::new();
        assert!(load_legacy_for_agent(&lab.identity_path).unwrap().is_none());
        assert!(!lab.identity_path.exists());
    }
    #[test]
    fn committed_cutover_marker_blocks_legacy_startup() {
        let lab=Lab::new();
        sa16b_phase_store::enroll(&lab.backend(), &initial()).unwrap();
        let bytes=fs::read(&lab.identity_path).unwrap();
        fs::write(lab.root.join("cutover.json"),b"marker").unwrap();
        assert!(load_legacy_for_agent(&lab.identity_path).is_err());
        assert_eq!(bytes,fs::read(&lab.identity_path).unwrap());
    }
    #[test]
    fn symlink_marker_blocks_legacy_startup() {
        let lab=Lab::new();
        symlink("/dev/null",lab.root.join("cutover.json")).unwrap();
        assert!(load_legacy_for_agent(&lab.identity_path).is_err());
    }
    #[test]
    fn sealed_caam_preview_refuses_production_directory() {
        assert!(preview_restored_caam_checkpoint(Path::new("/var/lib/highline-nexus")).is_err());
    }
    #[test]
    fn sealed_caam_preview_does_not_create_missing_identity() {
        let lab=Lab::new();
        assert!(preview_restored_caam_checkpoint(&lab.root).is_err());
        assert!(!lab.root.join("sealed-identity.json").exists());
    }
    #[test]
    fn malformed_secret_rejected_even_if_pending_fields_are_well_formed() {
        let mut record=pending(); record.device_secret="invalid".into();
        assert!(checkpoint(0,&record).is_err());
    }
}
