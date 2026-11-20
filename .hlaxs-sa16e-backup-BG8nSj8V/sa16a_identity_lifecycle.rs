//! SA-16A: real agent enrollment / prepare / commit-ACK persistence boundary.
//!
//! This module is called by real agent lifecycle sites. It deliberately selects
//! the existing LEGACY backend only; CAAM encrypted storage is not authorized
//! for the operational controller by this stage. All I/O is through the
//! SA-15Y shared dispatcher. No cloud calls, process exit, or service control.
//!
//! On restart, the original agent's idempotent cloud commit/ACK recovery stays
//! intact. Do not introduce an alternate commit or ACK procedure here.
use crate::cloud::agent::DeviceIdentity;
use crate::cloud::sa15y_runtime_backend;
use anyhow::{ensure, Context, Result};
use std::path::Path;

fn valid_secret(value: &str) -> bool {
    (32..=4096).contains(&value.len()) && !value.chars().any(char::is_control)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn same_scope(a: &DeviceIdentity, b: &DeviceIdentity) -> bool {
    a.device_id == b.device_id && a.controller_id == b.controller_id
        && a.organization_id == b.organization_id && a.site_id == b.site_id
        && a.hardware_profile == b.hardware_profile
}

fn same_identity(a: &DeviceIdentity, b: &DeviceIdentity) -> Result<bool> {
    Ok(serde_json::to_value(a)? == serde_json::to_value(b)?)
}

pub fn validate_startup_state(identity: &DeviceIdentity) -> Result<()> {
    ensure!(valid_id(&identity.device_id)
        && valid_id(&identity.controller_id)
        && valid_id(&identity.organization_id)
        && valid_id(&identity.site_id)
        && valid_id(&identity.hardware_profile), "invalid device identity scope");
    ensure!(valid_secret(&identity.device_secret), "invalid device credential shape");
    if let Some(cert) = &identity.pending_certificate_id {
        ensure!(valid_id(cert), "invalid pending rotation certificate");
    }
    if let Some(command) = &identity.pending_rotation_command_id {
        ensure!(valid_id(command), "invalid pending rotation command");
        ensure!(identity.pending_certificate_id.is_some(),
            "pending command without pending certificate");
    }
    Ok(())
}

pub fn persist_enrollment(path: &Path, identity: &DeviceIdentity) -> Result<()> {
    // The real agent explicitly selects LEGACY. The phase validation and
    // persistence logic is shared with sealed CAAM LAB tests, never auto-cutover.
    crate::cloud::sa16b_phase_store::enroll(
        &crate::cloud::sa16b_phase_store::LegacyLive { identity_path: path }, identity,
    )?;
    Ok(())
}

pub fn persist_prepared(
    path: &Path, previous: &DeviceIdentity, replacement: &DeviceIdentity,
    command_id: &str,
) -> Result<()> {
    crate::cloud::sa16b_phase_store::prepare(
        &crate::cloud::sa16b_phase_store::LegacyLive { identity_path: path },
        previous, replacement, command_id,
    )?;
    Ok(())
}

pub fn persist_finalized(path: &Path, finalized: &DeviceIdentity) -> Result<()> {
    crate::cloud::sa16b_phase_store::finalize(
        &crate::cloud::sa16b_phase_store::LegacyLive { identity_path: path }, finalized,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Lab { dir: PathBuf, path: PathBuf }
    impl Lab {
        fn new() -> Self {
            let dir=std::env::temp_dir().join(format!("hlaxs-sa16a-{}",uuid::Uuid::new_v4()));
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();
            let path=dir.join("device.json"); Self {dir,path}
        }
    }
    impl Drop for Lab { fn drop(&mut self) {let _=fs::remove_dir_all(&self.dir);} }
    fn original() -> DeviceIdentity {
        DeviceIdentity {
            device_id:"sa16a-device".into(), controller_id:"sa16a-controller".into(),
            organization_id:"sa16a-org".into(), site_id:"sa16a-site".into(),
            hardware_profile:"sa16a-fixture".into(),
            device_secret:format!("HNXD_{}","10".repeat(32)),
            pending_certificate_id:None, pending_rotation_command_id:None,
        }
    }
    fn replacement() -> DeviceIdentity {
        let mut candidate=original();
        candidate.device_secret=format!("HNXD_{}","20".repeat(32));
        candidate.pending_certificate_id=Some("sa16a-new-cert".into());
        candidate.pending_rotation_command_id=Some("sa16a-command".into());
        candidate
    }
    #[test]
    fn enrollment_uses_real_common_backend_and_recovers() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        assert!(same_identity(&original(),&sa15y_runtime_backend::load_live_legacy(&lab.path).unwrap().unwrap()).unwrap());
    }
    #[test]
    fn enrollment_never_overwrites_existing_credential() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        let before=fs::read(&lab.path).unwrap();
        let mut different=original();
        different.device_secret=format!("HNXD_{}","f0".repeat(32));
        assert!(persist_enrollment(&lab.path,&different).is_err());
        assert_eq!(before,fs::read(&lab.path).unwrap());
    }
    #[test]
    fn pending_command_without_certificate_fails_closed() {
        let mut identity=original();identity.pending_rotation_command_id=Some("orphan".into());
        assert!(validate_startup_state(&identity).is_err());
    }
    #[test]
    fn recovered_pending_certificate_without_command_is_valid() {
        let mut identity=original();identity.pending_certificate_id=Some("cert-only".into());
        assert!(validate_startup_state(&identity).is_ok());
    }
    #[test]
    fn prepare_persists_new_secret_before_commit() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        persist_prepared(&lab.path,&original(),&replacement(),"sa16a-command").unwrap();
        let saved=sa15y_runtime_backend::load_live_legacy(&lab.path).unwrap().unwrap();
        assert!(same_identity(&saved,&replacement()).unwrap());
    }
    #[test]
    fn prepare_rejects_stale_in_memory_identity() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        let mut stale=original();stale.device_secret=format!("HNXD_{}","30".repeat(32));
        assert!(persist_prepared(&lab.path,&stale,&replacement(),"sa16a-command").is_err());
        assert!(same_identity(&original(),&sa15y_runtime_backend::load_live_legacy(&lab.path).unwrap().unwrap()).unwrap());
    }
    #[test]
    fn prepare_rejects_mismatched_scope_and_pending_command() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        let mut modified=replacement();modified.controller_id="other-controller".into();
        assert!(persist_prepared(&lab.path,&original(),&modified,"sa16a-command").is_err());
        assert!(persist_prepared(&lab.path,&original(),&replacement(),"different-command").is_err());
    }
    #[test]
    fn second_rotation_is_forbidden_while_pending() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        persist_prepared(&lab.path,&original(),&replacement(),"sa16a-command").unwrap();
        let saved=sa15y_runtime_backend::load_live_legacy(&lab.path).unwrap().unwrap();
        assert!(persist_prepared(&lab.path,&saved,&replacement(),"sa16a-command").is_err());
    }
    #[test]
    fn finalize_requires_prepared_record_and_same_credential() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        assert!(persist_finalized(&lab.path,&original()).is_err());
        persist_prepared(&lab.path,&original(),&replacement(),"sa16a-command").unwrap();
        let mut wrong=original();wrong.device_secret=format!("HNXD_{}","ee".repeat(32));
        assert!(persist_finalized(&lab.path,&wrong).is_err());
    }
    #[test]
    fn finalize_clears_pending_and_is_durable() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        persist_prepared(&lab.path,&original(),&replacement(),"sa16a-command").unwrap();
        let mut finalized=replacement();finalized.pending_certificate_id=None;
        finalized.pending_rotation_command_id=None;
        persist_finalized(&lab.path,&finalized).unwrap();
        assert!(same_identity(&finalized,&sa15y_runtime_backend::load_live_legacy(&lab.path).unwrap().unwrap()).unwrap());
    }
    #[test]
    fn malformed_or_orphaned_pending_state_rejected() {
        let mut r=replacement();r.pending_certificate_id=None;
        assert!(validate_startup_state(&r).is_err());
        r.pending_certificate_id=Some("cert".into());r.device_secret="bad".into();
        assert!(validate_startup_state(&r).is_err());
    }
    #[test]
    fn cutover_marker_blocks_lifecycle_writes() {
        let lab=Lab::new();persist_enrollment(&lab.path,&original()).unwrap();
        File::create(lab.dir.join("cutover.json")).unwrap();
        assert!(persist_prepared(&lab.path,&original(),&replacement(),"sa16a-command").is_err());
        assert!(persist_enrollment(&lab.path,&original()).is_err());
    }
    #[test]
    fn symlink_marker_blocks_enrollment() {
        let lab=Lab::new();symlink("/dev/null",lab.dir.join("cutover.json")).unwrap();
        assert!(persist_enrollment(&lab.path,&original()).is_err());
    }
}
