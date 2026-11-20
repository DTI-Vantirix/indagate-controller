//! SA-15I: read-only lifecycle integration contract for HLAXS device identity.
//!
//! The live cloud agent still reads /var/lib/highline-nexus/device.json,
//! performs existing shared-secret authentication and rotates credentials
//! using its original journal/prepare/commit/ACK workflow.
//!
//! This bridge NEVER accepts the live device_secret, does not read or write
//! production identity files, never decrypts credentials, and exposes no
//! migration function that can succeed. A future stage must explicitly
//! implement/validate production migration and recovery.
//!
//! The optional runtime hook evaluates legacy *metadata* only. Its synthetic
//! sealed-snapshot comparison runs in unit tests, not during live startup.

use crate::cloud::sa15h_staged_store::IdentitySnapshot;
use anyhow::{Result, bail, ensure};

#[derive(Clone, Copy)]
pub struct LegacyMetadata<'a> {
    pub device_id: &'a str,
    pub controller_id: &'a str,
    pub pending_certificate_id: Option<&'a str>,
    pub pending_rotation_command_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryRoute {
    ExistingActive,
    PendingReplacementMustCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnlyDecision {
    pub route: RecoveryRoute,
    pub synthetic_snapshot_checked: bool,
    // Intentionally ALWAYS false; never infer migration permission from
    // the presence of CAAM or successful lab tests.
    pub live_migration_permitted: bool,
}

fn valid_nonsecret_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

/// Evaluate existing lifecycle metadata without opening or handling secrets.
///
/// `synthetic_shadow` is only a caller-supplied, explicitly synthetic
/// SA-15H snapshot. Live startup always passes None. A matching shape
/// does NOT imply authentication, authorization or durability.
pub fn audit_metadata(
    legacy: LegacyMetadata<'_>,
    synthetic_shadow: Option<&IdentitySnapshot>,
) -> Result<ReadOnlyDecision> {
    ensure!(valid_nonsecret_id(legacy.device_id)
        && valid_nonsecret_id(legacy.controller_id), "invalid identity metadata");
    if let Some(cert) = legacy.pending_certificate_id {
        ensure!(valid_nonsecret_id(cert), "invalid pending certificate metadata");
    }
    if let Some(command) = legacy.pending_rotation_command_id {
        ensure!(valid_nonsecret_id(command), "invalid pending rotation metadata");
    }
    // Existing agent requires a prepared certificate before any command may
    // be acknowledged as an unfinished rotation.
    ensure!(legacy.pending_certificate_id.is_some()
        || legacy.pending_rotation_command_id.is_none(), "orphaned pending rotation command");

    let route = if legacy.pending_certificate_id.is_some() {
        RecoveryRoute::PendingReplacementMustCommit
    } else {
        RecoveryRoute::ExistingActive
    };

    if let Some(snapshot) = synthetic_shadow {
        snapshot.validate()?;
        ensure!(snapshot.controller_id == legacy.controller_id
            && snapshot.object_id == legacy.device_id, "synthetic snapshot scope mismatch");
        ensure!(snapshot.pending.is_some() == legacy.pending_certificate_id.is_some(),
            "synthetic snapshot and legacy rotation phase disagree");
        if let Some(pending) = &snapshot.pending {
            ensure!(legacy.pending_certificate_id == Some(pending.certificate_id.as_str()),
                "pending certificate mismatch");
            // SA-15H's lab snapshot always requires a command id. The legacy
            // agent also supports pending certificate with no command id;
            // that case cannot be migrated using the current lab schema.
            ensure!(legacy.pending_rotation_command_id == Some(pending.command_id.as_str()),
                "pending command mismatch or unsupported no-command rotation");
            let selected = snapshot.recovery_credential()?;
            ensure!(std::ptr::eq(selected, &pending.replacement),
                "pending recovery would select old active credential");
        } else {
            let selected = snapshot.recovery_credential()?;
            ensure!(std::ptr::eq(selected, &snapshot.active),
                "active recovery selected the wrong credential");
        }
    }

    Ok(ReadOnlyDecision {
        route,
        synthetic_snapshot_checked: synthetic_shadow.is_some(),
        live_migration_permitted: false,
    })
}

/// Explicit fail-closed guard for any future attempted live migration.
/// Not feature- or environment-variable-controlled.
pub fn authorize_live_migration() -> Result<()> {
    bail!("SA-15I live credential migration is disabled by design")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::hybrid_secret_envelope::{
        DataKeyWrapper, seal_development_hybrid,
    };
    use crate::cloud::sa15h_staged_store::IdentitySnapshot;
    use anyhow::Result;

    struct SyntheticWrapper;
    impl DataKeyWrapper for SyntheticWrapper {
        fn wrap_32(&self, key: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut v = *key;
            for (idx, b) in v.iter_mut().enumerate() { *b ^= iv[idx % 16] ^ 0x92; }
            Ok(v)
        }
        fn unwrap_32(&self, data: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(data, iv)
        }
    }
    fn meta<'a>(cert: Option<&'a str>, cmd: Option<&'a str>) -> LegacyMetadata<'a> {
        LegacyMetadata {
            device_id: "device_I", controller_id: "controller_I",
            pending_certificate_id: cert, pending_rotation_command_id: cmd,
        }
    }
    fn env(label: &[u8]) -> crate::cloud::hybrid_secret_envelope::HybridSecretEnvelope {
        seal_development_hybrid(&SyntheticWrapper, "hlaxs-sa15e-sa15i-fixture",
            "controller_I", "device_I", label).unwrap()
    }
    fn active() -> IdentitySnapshot {
        IdentitySnapshot::initial("controller_I", "device_I", env(b"SYNTHETIC_SA15I_OLD")).unwrap()
    }
    fn pending() -> IdentitySnapshot {
        active().stage("cert_I", "command_I", env(b"SYNTHETIC_SA15I_NEW")).unwrap()
    }
    #[test]
    fn default_legacy_active_remains_plaintext_path_without_migration() {
        let d = audit_metadata(meta(None, None), None).unwrap();
        assert_eq!(d.route, RecoveryRoute::ExistingActive);
        assert!(!d.synthetic_snapshot_checked && !d.live_migration_permitted);
    }
    #[test]
    fn legacy_pending_requires_new_credential_commit() {
        let d = audit_metadata(meta(Some("cert_I"), Some("command_I")), None).unwrap();
        assert_eq!(d.route, RecoveryRoute::PendingReplacementMustCommit);
        assert!(!d.live_migration_permitted);
    }
    #[test]
    fn orphan_command_fails_closed() {
        assert!(audit_metadata(meta(None, Some("command_I")), None).is_err());
    }
    #[test]
    fn synthetic_active_snapshot_agrees_with_legacy_active() {
        let d = audit_metadata(meta(None, None), Some(&active())).unwrap();
        assert!(d.synthetic_snapshot_checked && !d.live_migration_permitted);
    }
    #[test]
    fn pending_shadow_routes_to_replacement_not_old_active() {
        let d = audit_metadata(meta(Some("cert_I"), Some("command_I")), Some(&pending())).unwrap();
        assert_eq!(d.route, RecoveryRoute::PendingReplacementMustCommit);
        assert!(d.synthetic_snapshot_checked && !d.live_migration_permitted);
    }
    #[test]
    fn mismatched_scope_or_phase_or_ids_fail_closed() {
        let current = active();
        let staged = pending();
        assert!(audit_metadata(meta(None, None), Some(&staged)).is_err());
        assert!(audit_metadata(meta(Some("cert_I"), Some("command_I")), Some(&current)).is_err());
        assert!(audit_metadata(meta(Some("wrong_cert"), Some("command_I")), Some(&staged)).is_err());
        assert!(audit_metadata(meta(Some("cert_I"), Some("wrong_command")), Some(&staged)).is_err());
        let mismatch = LegacyMetadata { controller_id: "other_controller", ..meta(None, None) };
        assert!(audit_metadata(mismatch, Some(&current)).is_err());
    }
    #[test]
    fn no_command_pending_is_diagnostic_only_not_current_lab_migration() {
        assert_eq!(audit_metadata(meta(Some("cert_I"), None), None).unwrap().route,
            RecoveryRoute::PendingReplacementMustCommit);
        assert!(audit_metadata(meta(Some("cert_I"), None), Some(&pending())).is_err());
    }
    #[test]
    fn cannot_enable_live_migration() {
        assert!(authorize_live_migration().is_err());
    }
}
