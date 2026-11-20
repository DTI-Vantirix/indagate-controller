//! SA-15J: strictly synthetic migration + restart/reconciliation lab.
//!
//! This module is NOT connected to the live cloud agent. It refuses production
//! IDs, production secrets, and paths outside isolated /tmp or /var/tmp lab roots.
//! No real device.json is ever opened. The existing SA-15I production migration
//! guard stays permanently disabled by this package.
//!
//! Critical: the legacy agent persists the *replacement* device_secret while a
//! rotation is pending, so the previous active secret may no longer exist on
//! disk. Migration during pending rotation MUST be rejected. Let the existing
//! legacy commit/ACK/restart recovery finish before attempting any future
//! separately reviewed production cutover.

use crate::cloud::hybrid_secret_envelope::{DataKeyWrapper, open_development_hybrid, seal_development_hybrid};
use crate::cloud::sa15h_staged_store::{Fault, IdentitySnapshot, StagedLabStore};
use crate::cloud::sa15i_identity_bridge::{LegacyMetadata, RecoveryRoute, audit_metadata};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const SCHEMA: u8 = 1;
const MARKER: &str = "HLAXS_SA15J_SYNTHETIC_ONLY";
const DEVICE: &str = "hlaxs_sa15j_test_device";
const CONTROLLER: &str = "hlaxs_sa15j_test_controller";
const OLD: &str = "HLAXS_SA15J_SYNTHETIC_ONLY_OLD_SECRET_123456789";
const NEW: &str = "HLAXS_SA15J_SYNTHETIC_ONLY_NEW_SECRET_987654321";
const KEY_ID: &str = "hlaxs-sa15e-sa15j-fixture";
const LAB_PREFIX: &str = "hlaxs-sa15h-lab-sa15j-"; // SA-15H store enforces this prefix family.
const LEGACY: &str = "legacy-fixture.json";
const MAX_FIXTURE: u64 = 8192;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticLegacyFixture {
    pub schema: u8,
    pub synthetic_marker: String,
    pub device_id: String,
    pub controller_id: String,
    pub device_secret: String,
    pub pending_certificate_id: Option<String>,
    pub pending_rotation_command_id: Option<String>,
}

impl SyntheticLegacyFixture {
    pub fn active() -> Self {
        Self {
            schema: SCHEMA, synthetic_marker: MARKER.into(), device_id: DEVICE.into(),
            controller_id: CONTROLLER.into(), device_secret: OLD.into(),
            pending_certificate_id: None, pending_rotation_command_id: None,
        }
    }
    fn validate_synthetic(&self) -> Result<()> {
        ensure!(self.schema == SCHEMA && self.synthetic_marker == MARKER, "not an SA-15J fixture");
        ensure!(self.device_id == DEVICE && self.controller_id == CONTROLLER, "not synthetic scope");
        ensure!(self.device_secret == OLD || self.device_secret == NEW,
            "not an approved synthetic secret");
        Ok(())
    }
    /// A pending certificate means the disk already holds NEW, not necessarily OLD.
    /// Reject both with-command and certificate-only rotations.
    fn preflight_idle(&self) -> Result<()> {
        self.validate_synthetic()?;
        let decision = audit_metadata(LegacyMetadata {
            device_id: &self.device_id,
            controller_id: &self.controller_id,
            pending_certificate_id: self.pending_certificate_id.as_deref(),
            pending_rotation_command_id: self.pending_rotation_command_id.as_deref(),
        }, None)?;
        ensure!(decision.route == RecoveryRoute::ExistingActive,
            "pending legacy rotation must finish before migration");
        ensure!(!decision.live_migration_permitted, "unexpected live migration permission");
        Ok(())
    }
}

/// Synthetic-only local store; cannot be pointed at device.json or a generic directory.
pub struct Sa15jLab {
    store: StagedLabStore,
    fixture: PathBuf,
}

impl Sa15jLab {
    pub fn new(root: &Path) -> Result<Self> {
        let name = root.file_name().and_then(|n| n.to_str()).unwrap_or("");
        ensure!(name.starts_with(LAB_PREFIX), "SA-15J lab root prefix required");
        let store = StagedLabStore::new(root)?; // /tmp or /var/tmp only.
        Ok(Self { fixture: root.join(LEGACY), store })
    }

    pub fn create(&self) -> Result<()> { self.store.create() }
    pub fn cleanup(&self) -> Result<()> { self.store.cleanup() }

    pub fn write_fixture(&self, fixture: &SyntheticLegacyFixture) -> Result<()> {
        fixture.validate_synthetic()?;
        let data = serde_json::to_vec(fixture)?;
        ensure!(!data.is_empty() && data.len() as u64 <= MAX_FIXTURE, "fixture too large");
        let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.fixture).context("create synthetic legacy fixture")?;
        file.write_all(&data)?;
        file.sync_all()?;
        File::open(self.store.root())?.sync_all()?;
        Ok(())
    }

    pub fn read_fixture(&self) -> Result<SyntheticLegacyFixture> {
        let before = fs::symlink_metadata(&self.fixture).context("inspect synthetic fixture")?;
        ensure!(before.is_file() && !before.file_type().is_symlink() && before.nlink() == 1,
            "unsafe fixture type");
        ensure!(before.uid() == unsafe { libc::geteuid() } && before.mode() & 0o077 == 0,
            "unsafe fixture ownership or permissions");
        ensure!(before.len() > 0 && before.len() <= MAX_FIXTURE, "invalid fixture size");
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.fixture)?;
        let opened = file.metadata()?;
        ensure!(opened.ino() == before.ino() && opened.dev() == before.dev(),
            "fixture changed while opening");
        let mut buf = Vec::new();
        file.take(MAX_FIXTURE + 1).read_to_end(&mut buf)?;
        ensure!(!buf.is_empty() && buf.len() as u64 <= MAX_FIXTURE, "invalid fixture read length");
        let fixture: SyntheticLegacyFixture = serde_json::from_slice(&buf)?;
        fixture.validate_synthetic()?;
        Ok(fixture)
    }

    /// Converts a synthetic legacy fixture to a sealed snapshot, but intentionally
    /// RETAINS the legacy fixture until the encrypted snapshot is reopened and
    /// authenticated. SA-15H's Fault::BeforeRename models an interrupted write.
    pub fn stage_synthetic_migration<W: DataKeyWrapper>(&self, key: &W, fault: Fault) -> Result<()> {
        let legacy = self.read_fixture()?;
        legacy.preflight_idle()?;
        ensure!(!self.store.root().join("snapshot.json").exists(),
            "sealed snapshot already exists; migration is not an overwrite operation");
        let sealed = seal_development_hybrid(key, KEY_ID, CONTROLLER, DEVICE,
            legacy.device_secret.as_bytes())?;
        let snapshot = IdentitySnapshot::initial(CONTROLLER, DEVICE, sealed)?;
        self.store.write(&snapshot, fault)?;
        self.verify_migration(key)?;
        Ok(())
    }

    /// Explicitly validate the sealed snapshot before retiring the lab fixture.
    pub fn verify_migration<W: DataKeyWrapper>(&self, key: &W) -> Result<()> {
        let legacy = self.read_fixture()?;
        legacy.preflight_idle()?;
        let snapshot = self.store.load()?;
        ensure!(snapshot.pending.is_none() && snapshot.generation == 1,
            "not an initial, idle migration snapshot");
        let _decision = audit_metadata(LegacyMetadata {
            device_id: &legacy.device_id, controller_id: &legacy.controller_id,
            pending_certificate_id: None, pending_rotation_command_id: None,
        }, Some(&snapshot))?;
        let recovered = open_development_hybrid(key, KEY_ID, CONTROLLER, DEVICE,
            snapshot.recovery_credential()?)?;
        ensure!(recovered == legacy.device_secret.as_bytes(), "synthetic secret mismatch");
        Ok(())
    }

    /// Lab-only cutover: the synthetic plaintext fixture is removed ONLY after
    /// successful encrypted verification. Deletion is not secure media erasure.
    pub fn retire_fixture_after_verification<W: DataKeyWrapper>(&self, key: &W) -> Result<()> {
        self.verify_migration(key)?;
        fs::remove_file(&self.fixture)?;
        File::open(self.store.root())?.sync_all()?;
        Ok(())
    }

    /// Simulates a process restart using the sealed snapshot alone.
    pub fn recover_after_lab_cutover<W: DataKeyWrapper>(&self, key: &W) -> Result<LabRecovery> {
        ensure!(!self.fixture.exists(), "plaintext synthetic legacy fixture still present");
        let snapshot = self.store.load()?;
        ensure!(snapshot.controller_id == CONTROLLER && snapshot.object_id == DEVICE,
            "unexpected lab identity scope");
        let recovered = open_development_hybrid(key, KEY_ID, CONTROLLER, DEVICE,
            snapshot.recovery_credential()?)?;
        ensure!(recovered == OLD.as_bytes() || recovered == NEW.as_bytes(),
            "unrecognized synthetic lab credential");
        Ok(LabRecovery { generation: snapshot.generation, pending: snapshot.pending.is_some() })
    }

    pub fn snapshot(&self) -> Result<IdentitySnapshot> { self.store.load() }
    pub fn write_snapshot(&self, snapshot: &IdentitySnapshot) -> Result<()> {
        ensure!(snapshot.controller_id == CONTROLLER && snapshot.object_id == DEVICE,
            "unexpected lab identity scope");
        self.store.write(snapshot, Fault::None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabRecovery { pub generation: u64, pub pending: bool }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabRotationAction { AlreadyActive, RetryCommitWithReplacement, RetryAckWithReplacement, FinalizeAfterBothAccepted }

/// Model the legacy prepare/commit/ACK sequence. Booleans are TEST FIXTURES,
/// not server proofs, and do not authorize real credential changes.
pub fn plan_synthetic_rotation(snapshot: &IdentitySnapshot, commit_ok: bool, ack_ok: bool)
    -> Result<LabRotationAction>
{
    snapshot.validate()?;
    ensure!(snapshot.controller_id == CONTROLLER && snapshot.object_id == DEVICE,
        "not SA-15J synthetic scope");
    ensure!(!(ack_ok && !commit_ok), "ACK cannot precede commit");
    if let Some(pending) = &snapshot.pending {
        let selected = snapshot.recovery_credential()?;
        ensure!(std::ptr::eq(selected, &pending.replacement),
            "pending recovery must authenticate as replacement");
        if !commit_ok { Ok(LabRotationAction::RetryCommitWithReplacement) }
        else if !ack_ok { Ok(LabRotationAction::RetryAckWithReplacement) }
        else { Ok(LabRotationAction::FinalizeAfterBothAccepted) }
    } else {
        ensure!(!commit_ok && !ack_ok, "unexpected rotation outcome without pending state");
        Ok(LabRotationAction::AlreadyActive)
    }
}

pub fn finalize_synthetic_rotation(snapshot: &IdentitySnapshot, commit_ok: bool, ack_ok: bool)
    -> Result<IdentitySnapshot>
{
    ensure!(plan_synthetic_rotation(snapshot, commit_ok, ack_ok)?
        == LabRotationAction::FinalizeAfterBothAccepted,
        "cannot finalize until synthetic commit AND ACK both succeeded");
    snapshot.finalize()
}

/// Intentional impossibility: no live identity migration in SA-15J.
pub fn authorize_live_migration() -> Result<()> {
    bail!("SA-15J is synthetic-only; live migration remains disabled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::hybrid_secret_envelope::{HybridSecretEnvelope, seal_development_hybrid};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct FakeWrapper;
    impl DataKeyWrapper for FakeWrapper {
        fn wrap_32(&self, key: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut out = *key;
            for (idx, b) in out.iter_mut().enumerate() { *b ^= iv[idx % 16] ^ 0x71; }
            Ok(out)
        }
        fn unwrap_32(&self, data: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(data, iv)
        }
    }
    fn lab() -> Sa15jLab {
        let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("{LAB_PREFIX}{}-{n}", std::process::id()));
        let lab = Sa15jLab::new(&root).unwrap(); lab.create().unwrap(); lab
    }
    fn env(secret: &str) -> HybridSecretEnvelope {
        seal_development_hybrid(&FakeWrapper, KEY_ID, CONTROLLER, DEVICE, secret.as_bytes()).unwrap()
    }
    fn initial_sealed() -> IdentitySnapshot {
        IdentitySnapshot::initial(CONTROLLER, DEVICE, env(OLD)).unwrap()
    }
    #[test]
    fn idle_fixture_can_migrate_and_recover_after_lab_retirement() {
        let l = lab(); l.write_fixture(&SyntheticLegacyFixture::active()).unwrap();
        l.stage_synthetic_migration(&FakeWrapper, Fault::None).unwrap();
        assert!(l.fixture.exists()); // No plaintext removal before verification.
        l.retire_fixture_after_verification(&FakeWrapper).unwrap();
        assert!(!l.fixture.exists());
        assert_eq!(l.recover_after_lab_cutover(&FakeWrapper).unwrap(), LabRecovery { generation: 1, pending: false });
        l.cleanup().unwrap();
    }
    #[test]
    fn interruption_before_rename_preserves_legacy_fixture_and_no_sealed_snapshot() {
        let l = lab(); l.write_fixture(&SyntheticLegacyFixture::active()).unwrap();
        assert!(l.stage_synthetic_migration(&FakeWrapper, Fault::BeforeRename).is_err());
        assert!(l.fixture.exists());
        assert!(l.snapshot().is_err());
        assert!(l.recover_after_lab_cutover(&FakeWrapper).is_err());
        l.cleanup().unwrap();
    }
    #[test]
    fn pending_certificate_and_command_blocks_migration() {
        let l = lab(); let mut fixture = SyntheticLegacyFixture::active();
        fixture.device_secret = NEW.into();
        fixture.pending_certificate_id = Some("cert_SA15J".into());
        fixture.pending_rotation_command_id = Some("command_SA15J".into());
        l.write_fixture(&fixture).unwrap();
        assert!(l.stage_synthetic_migration(&FakeWrapper, Fault::None).is_err());
        assert!(l.snapshot().is_err()); l.cleanup().unwrap();
    }
    #[test]
    fn certificate_only_pending_blocks_migration() {
        let l = lab(); let mut fixture = SyntheticLegacyFixture::active();
        fixture.device_secret = NEW.into();
        fixture.pending_certificate_id = Some("cert_SA15J".into());
        l.write_fixture(&fixture).unwrap();
        assert!(l.stage_synthetic_migration(&FakeWrapper, Fault::None).is_err());
        l.cleanup().unwrap();
    }
    #[test]
    fn orphaned_rotation_command_blocks_migration() {
        let l = lab(); let mut fixture = SyntheticLegacyFixture::active();
        fixture.pending_rotation_command_id = Some("command_SA15J".into());
        l.write_fixture(&fixture).unwrap();
        assert!(l.stage_synthetic_migration(&FakeWrapper, Fault::None).is_err());
        l.cleanup().unwrap();
    }
    #[test]
    fn non_synthetic_fixture_is_rejected_before_writing() {
        let l = lab(); let mut fixture = SyntheticLegacyFixture::active();
        fixture.device_secret = "REAL_DEVICE_SECRET_DONT_TOUCH".into();
        assert!(l.write_fixture(&fixture).is_err());
        fixture = SyntheticLegacyFixture::active(); fixture.device_id = "production-device".into();
        assert!(l.write_fixture(&fixture).is_err());
        fixture = SyntheticLegacyFixture::active(); fixture.synthetic_marker = "anything".into();
        assert!(l.write_fixture(&fixture).is_err());
        l.cleanup().unwrap();
    }
    #[test]
    fn snapshot_is_private_and_excludes_synthetic_plaintext() {
        let l = lab(); l.write_fixture(&SyntheticLegacyFixture::active()).unwrap();
        l.stage_synthetic_migration(&FakeWrapper, Fault::None).unwrap();
        let snapshot_path = l.store.root().join("snapshot.json");
        let encoded = fs::read(&snapshot_path).unwrap();
        assert!(!encoded.windows(OLD.len()).any(|bytes| bytes == OLD.as_bytes()));
        assert_eq!(fs::metadata(&snapshot_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&l.fixture).unwrap().permissions().mode() & 0o777, 0o600);
        l.cleanup().unwrap();
    }
    #[test]
    fn existing_snapshot_cannot_be_overwritten_by_migration() {
        let l = lab(); l.write_fixture(&SyntheticLegacyFixture::active()).unwrap();
        l.stage_synthetic_migration(&FakeWrapper, Fault::None).unwrap();
        assert!(l.stage_synthetic_migration(&FakeWrapper, Fault::None).is_err());
        l.cleanup().unwrap();
    }
    #[test]
    fn missing_or_wrong_wrapping_key_prevents_fixture_retirement() {
        struct Wrong;
        impl DataKeyWrapper for Wrong {
            fn wrap_32(&self, key: &[u8; 32], _: &[u8; 16]) -> Result<[u8; 32]> { Ok(*key) }
            fn unwrap_32(&self, data: &[u8; 32], _: &[u8; 16]) -> Result<[u8; 32]> { Ok(*data) }
        }
        let l = lab(); l.write_fixture(&SyntheticLegacyFixture::active()).unwrap();
        l.stage_synthetic_migration(&FakeWrapper, Fault::None).unwrap();
        assert!(l.retire_fixture_after_verification(&Wrong).is_err());
        assert!(l.fixture.exists()); l.cleanup().unwrap();
    }
    #[test]
    fn cloud_commit_and_ack_model_requires_correct_order() {
        let pending = initial_sealed().stage("cert_SA15J", "cmd_SA15J", env(NEW)).unwrap();
        assert_eq!(plan_synthetic_rotation(&pending, false, false).unwrap(),
            LabRotationAction::RetryCommitWithReplacement);
        assert_eq!(plan_synthetic_rotation(&pending, true, false).unwrap(),
            LabRotationAction::RetryAckWithReplacement);
        assert_eq!(plan_synthetic_rotation(&pending, true, true).unwrap(),
            LabRotationAction::FinalizeAfterBothAccepted);
        assert!(plan_synthetic_rotation(&pending, false, true).is_err());
        assert!(finalize_synthetic_rotation(&pending, true, false).is_err());
        let done = finalize_synthetic_rotation(&pending, true, true).unwrap();
        assert!(done.pending.is_none() && done.generation == 2);
        assert_eq!(plan_synthetic_rotation(&done, false, false).unwrap(), LabRotationAction::AlreadyActive);
    }
    #[test]
    fn corrupt_pending_never_downgrades_to_old_credential() {
        let mut pending = initial_sealed().stage("cert_SA15J", "cmd_SA15J", env(NEW)).unwrap();
        pending.pending.as_mut().unwrap().replacement.wrapped_dek.clear();
        assert!(pending.recovery_credential().is_err());
        assert!(plan_synthetic_rotation(&pending, false, false).is_err());
    }
    #[test]
    fn cannot_point_lab_at_live_identity_or_generic_paths() {
        assert!(Sa15jLab::new(Path::new("/var/lib/highline-nexus")).is_err());
        assert!(Sa15jLab::new(Path::new("/tmp/hlaxs-sa15h-lab-native")).is_err());
        assert!(Sa15jLab::new(Path::new("/var/tmp/production-device.json")).is_err());
    }
    #[test]
    fn live_migration_guard_cannot_be_enabled() {
        assert!(authorize_live_migration().is_err());
        assert!(crate::cloud::sa15i_identity_bridge::authorize_live_migration().is_err());
    }
}
