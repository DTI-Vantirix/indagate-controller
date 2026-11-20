//! SA-15N: synthetic, disk-backed encrypted cutover and rotation replay LAB.
//!
//! No call sites in the live controller agent. No production migration.
//! The cloud is a LOCAL MOCK persisted in a lab file, NOT the real API.
//! The wrapped-key implementation below is a FAKE test fixture; CAAM is
//! validated separately by SA-15G/H and NOT exercised in these unit tests.
//!
//! Caveats: quiescence here is simulated, not a real interprocess lock;
//! file fsync tests are not unexpected-power-loss testing; offline rollback
//! of all files is not prevented; HAB is open on the current lab controller.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::hybrid_secret_envelope::DataKeyWrapper;
use crate::cloud::sa15l_sealed_identity_lab::{
    SealedFullIdentity, open_synthetic, seal_synthetic, synthetic_active,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const PREFIX: &str = "hlaxs-sa15n-lab-";
const LEGACY: &str = "device.json";
const SEALED: &str = "sealed-identity.json";
const MARKER: &str = "cutover.json";
const MOCK_CLOUD: &str = "mock-cloud.json";
const MAX_FILE: u64 = 64 * 1024;
const CERT: &str = "hlaxs-sa15n-synthetic-cert-2";
const COMMAND: &str = "hlaxs-sa15n-synthetic-command-2";
const NEW: &str = "SYNTHETIC_SA15L_NEW_SECRET_09876543210987654321";

/// Only an explicitly named fixture key is used. This XOR implementation is
/// deliberately NOT SECURE and must never be used in real credential storage.
struct FakeWrapper;
impl DataKeyWrapper for FakeWrapper {
    fn wrap_32(&self, key: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
        let mut out = *key;
        for (i, b) in out.iter_mut().enumerate() { *b ^= iv[i % 16] ^ 0x49; }
        Ok(out)
    }
    fn unwrap_32(&self, key: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
        self.wrap_32(key, iv)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u8,
    generation: u64,
    record: SealedFullIdentity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CutoverMarker {
    schema: u8,
    mode: String,
    minimum_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemotePhase { Prepared, Committed, Acknowledged }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MockCloud {
    schema: u8,
    phase: RemotePhase,
    certificate_id: String,
    command_id: String,
    /// A lab-only version flag, not real cloud authentication.
    next_credential_version: u8,
}

/// A hard-coded synthetic directory is required; no alternate path is accepted.
struct Lab {
    root: PathBuf,
    /// Simulated maintenance quiescence (not an operating system process lock).
    mock_agent_quiesced: bool,
}

impl Lab {
    fn new(path: &Path) -> Result<Self> {
        ensure!(path.parent() == Some(Path::new("/tmp")), "SA-15N is /tmp-only");
        let name = path.file_name().and_then(|x| x.to_str()).unwrap_or("");
        ensure!(name.starts_with(PREFIX) && name.len() <= 100 &&
            name.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'-'),
            "SA-15N synthetic root required");
        Ok(Self { root: path.to_owned(), mock_agent_quiesced: false })
    }

    fn create(&self) -> Result<()> {
        fs::create_dir(&self.root).context("create exclusive synthetic lab")?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        self.check_root()?;
        self.sync_directory()
    }

    fn check_root(&self) -> Result<()> {
        let m = fs::symlink_metadata(&self.root)?;
        ensure!(m.is_dir() && !m.file_type().is_symlink() &&
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "unsafe synthetic lab root");
        Ok(())
    }

    fn sync_directory(&self) -> Result<()> {
        File::open(&self.root)?.sync_all().context("sync synthetic lab dir")
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        ensure!([LEGACY, SEALED, MARKER, MOCK_CLOUD].contains(&name), "unexpected lab file");
        self.check_root()?;
        Ok(self.root.join(name))
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let p = self.path(name)?;
        let before = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("stat lab file"),
        };
        Self::check_file(&before)?;
        let mut f = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&p)?;
        let after = f.metadata()?;
        Self::check_file(&after)?;
        ensure!(before.ino() == after.ino() && before.dev() == after.dev(),
            "lab record switched during read");
        let mut data = Vec::new();
        f.take(MAX_FILE + 1).read_to_end(&mut data)?;
        ensure!(!data.is_empty() && data.len() as u64 <= MAX_FILE, "bad lab record length");
        Ok(Some(data))
    }

    fn check_file(m: &fs::Metadata) -> Result<()> {
        ensure!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1 &&
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0 &&
            m.len() > 0 && m.len() <= MAX_FILE, "unsafe synthetic lab file");
        Ok(())
    }

    /// Atomic replacement in a SINGLE-WRITER simulated lab. Not a production
    /// concurrency/locking implementation. Sync file before rename, then dir.
    fn publish<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.path(name)?;
        // Refuse to replace a dangerous or corrupt existing record.
        if self.read(name)?.is_some() { /* validated existing inode */ }
        let data = serde_json::to_vec(value)?;
        ensure!(!data.is_empty() && data.len() as u64 <= MAX_FILE, "invalid output length");
        let temp = self.root.join(format!(".sa15n-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&temp)?;
            f.write_all(&data)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&temp, &path)?;
            self.sync_directory()?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(&temp); }
        result
    }

    fn load_json<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        self.read(name)?
            .map(|bytes| serde_json::from_slice(&bytes).context("invalid synthetic record"))
            .transpose()
    }

    fn validate_fixture(id: &DeviceIdentity) -> Result<()> {
        let orig = synthetic_active();
        ensure!(id.device_id == orig.device_id && id.controller_id == orig.controller_id &&
            id.organization_id == orig.organization_id && id.site_id == orig.site_id &&
            id.hardware_profile == orig.hardware_profile, "non-synthetic identity refused");
        ensure!(id.device_secret == orig.device_secret || id.device_secret == NEW,
            "non-synthetic secret refused");
        ensure!(id.pending_rotation_command_id.is_none() || id.pending_certificate_id.is_some(),
            "orphan rotation command");
        Ok(())
    }

    fn write_legacy(&self, id: &DeviceIdentity) -> Result<()> {
        Self::validate_fixture(id)?;
        ensure!(self.read(LEGACY)?.is_none() && self.read(MARKER)?.is_none(),
            "legacy record already present or cutover exists");
        self.publish(LEGACY, id)
    }

    fn legacy(&self) -> Result<DeviceIdentity> {
        let id: DeviceIdentity = self.load_json(LEGACY)?.context("legacy fixture missing")?;
        Self::validate_fixture(&id)?;
        Ok(id)
    }

    fn read_sealed(&self) -> Result<(DeviceIdentity, u64)> {
        let snapshot: Snapshot = self.load_json(SEALED)?.context("sealed snapshot missing")?;
        ensure!(snapshot.schema == 1 && snapshot.generation > 0, "invalid generation");
        // SA-15L binds the generation both inside authenticated plaintext
        // and outside the envelope. Recheck this extra outer wrapper.
        let inside_gen = serde_json::to_value(&snapshot.record)?
            .get("generation").and_then(|v| v.as_u64())
            .context("sealed generation missing")?;
        ensure!(inside_gen == snapshot.generation, "unauthenticated generation mismatch");
        let id = open_synthetic(&FakeWrapper, &snapshot.record)?;
        Self::validate_fixture(&id)?;
        Ok((id, snapshot.generation))
    }

    fn write_sealed(&self, id: &DeviceIdentity, generation: u64) -> Result<()> {
        Self::validate_fixture(id)?;
        let record = seal_synthetic(&FakeWrapper, id, generation)?;
        self.publish(SEALED, &Snapshot { schema: 1, generation, record })
    }

    fn recover(&self) -> Result<(DeviceIdentity, u64)> {
        match self.load_json::<CutoverMarker>(MARKER)? {
            None => Ok((self.legacy()?, 0)),
            Some(marker) => {
                ensure!(marker.schema == 1 && marker.mode == "sealed" &&
                    marker.minimum_generation == 1, "invalid cutover marker");
                let (id, generation) = self.read_sealed()?;
                ensure!(generation >= marker.minimum_generation, "snapshot below cutover floor");
                Ok((id, generation))
            }
        }
    }

    fn quiesce_simulated_agent(&mut self) { self.mock_agent_quiesced = true; }

    fn stage_cutover(&self) -> Result<()> {
        ensure!(self.mock_agent_quiesced, "simulated agent must be quiesced");
        ensure!(self.read(MARKER)?.is_none() && self.read(SEALED)?.is_none(),
            "cannot stage duplicate cutover");
        let id = self.legacy()?;
        ensure!(id.pending_certificate_id.is_none() && id.pending_rotation_command_id.is_none(),
            "pending rotation blocks cutover");
        self.write_sealed(&id, 1)?;
        self.verify_stage()
    }

    fn verify_stage(&self) -> Result<()> {
        ensure!(self.read(MARKER)?.is_none(), "already cut over");
        let id = self.legacy()?;
        ensure!(id.pending_certificate_id.is_none() && id.pending_rotation_command_id.is_none(),
            "pending rotation blocks cutover");
        let (sealed, generation) = self.read_sealed()?;
        ensure!(generation == 1 && serde_json::to_vec(&id)? == serde_json::to_vec(&sealed)?,
            "staged identity differs from legacy");
        Ok(())
    }

    fn commit_cutover(&self) -> Result<()> {
        ensure!(self.mock_agent_quiesced, "simulated agent must be quiesced");
        self.verify_stage()?;
        self.publish(MARKER, &CutoverMarker {
            schema: 1, mode: "sealed".into(), minimum_generation: 1,
        })?;
        let _ = self.recover()?;
        Ok(())
    }

    fn ensure_cutover(&self) -> Result<()> {
        ensure!(self.read(MARKER)?.is_some(), "no committed cutover");
        let _ = self.recover()?;
        Ok(())
    }

    fn mock_cloud(&self) -> Result<MockCloud> {
        let c: MockCloud = self.load_json(MOCK_CLOUD)?.context("mock cloud not prepared")?;
        ensure!(c.schema == 1 && c.certificate_id == CERT &&
            c.command_id == COMMAND && c.next_credential_version == 2,
            "unexpected mock cloud transaction");
        Ok(c)
    }

    fn mock_prepare(&self) -> Result<()> {
        self.ensure_cutover()?;
        ensure!(self.read(MOCK_CLOUD)?.is_none(), "mock prepare already exists");
        let (id, generation) = self.recover()?;
        ensure!(generation == 1 && id.pending_certificate_id.is_none() &&
            id.pending_rotation_command_id.is_none() &&
            id.device_secret == synthetic_active().device_secret,
            "rotation already active or pending");
        self.publish(MOCK_CLOUD, &MockCloud {
            schema: 1, phase: RemotePhase::Prepared,
            certificate_id: CERT.into(), command_id: COMMAND.into(),
            next_credential_version: 2,
        })
    }

    /// NEW is persisted locally BEFORE this mock service can commit it.
    fn stage_prepared_rotation(&self) -> Result<()> {
        self.ensure_cutover()?;
        ensure!(self.mock_cloud()?.phase == RemotePhase::Prepared,
            "remote prepare required");
        let (mut id, generation) = self.recover()?;
        ensure!(generation == 1 && id.pending_certificate_id.is_none() &&
            id.pending_rotation_command_id.is_none(), "rotation already pending");
        id.device_secret = NEW.into();
        id.pending_certificate_id = Some(CERT.into());
        id.pending_rotation_command_id = Some(COMMAND.into());
        self.write_sealed(&id, 2)
    }

    fn pending(&self) -> Result<(DeviceIdentity, u64)> {
        let (id, generation) = self.recover()?;
        ensure!(generation == 2 && id.device_secret == NEW &&
            id.pending_certificate_id.as_deref() == Some(CERT) &&
            id.pending_rotation_command_id.as_deref() == Some(COMMAND),
            "durable replacement credential required");
        Ok((id, generation))
    }

    fn mock_commit(&self) -> Result<()> {
        self.pending()?; // never commit if NEW was not durably staged
        let mut cloud = self.mock_cloud()?;
        match cloud.phase {
            RemotePhase::Prepared => {
                cloud.phase = RemotePhase::Committed;
                self.publish(MOCK_CLOUD, &cloud)
            }
            RemotePhase::Committed | RemotePhase::Acknowledged => Ok(()),
        }
    }

    fn mock_ack(&self) -> Result<()> {
        self.pending()?;
        let mut cloud = self.mock_cloud()?;
        match cloud.phase {
            RemotePhase::Prepared => bail!("cannot ACK before remote commit"),
            RemotePhase::Committed => {
                cloud.phase = RemotePhase::Acknowledged;
                self.publish(MOCK_CLOUD, &cloud)
            }
            RemotePhase::Acknowledged => Ok(()),
        }
    }

    fn finalize(&self) -> Result<()> {
        let (mut id, generation) = self.pending()?;
        ensure!(self.mock_cloud()?.phase == RemotePhase::Acknowledged,
            "cannot finalize before committed ACK");
        id.pending_certificate_id = None;
        id.pending_rotation_command_id = None;
        self.write_sealed(&id, generation + 1)
    }

    /// Simulates a restart/replay of existing prepare -> commit -> ACK order.
    /// An unreachable MOCK cloud preserves pending NEW and returns an error.
    fn replay(&self, mock_network_available: bool) -> Result<()> {
        self.ensure_cutover()?;
        let (id, generation) = self.recover()?;
        if generation >= 3 && id.pending_certificate_id.is_none() &&
            id.pending_rotation_command_id.is_none() { return Ok(()); }
        self.pending()?;
        ensure!(mock_network_available, "mock network unavailable; pending NEW retained");
        self.mock_commit()?;
        self.mock_ack()?;
        self.finalize()
    }

    fn remove_legacy_fixture(&self) -> Result<()> {
        self.ensure_cutover()?;
        let p = self.path(LEGACY)?;
        ensure!(self.read(LEGACY)?.is_some(), "legacy fixture missing");
        fs::remove_file(p)?;
        self.sync_directory()
    }
}

/// There is no code path from this module that authorizes live migration.
#[allow(dead_code)]
pub fn authorize_live_sa15n_cutover() -> Result<()> {
    bail!("SA-15N has no live encrypted cutover implementation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture { root: PathBuf }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("{PREFIX}{}", uuid::Uuid::new_v4()));
            Lab::new(&root).unwrap().create().unwrap();
            Self { root }
        }
        fn session(&self) -> Lab { Lab::new(&self.root).unwrap() }
        fn initial(&self) {
            self.session().write_legacy(&synthetic_active()).unwrap();
        }
        fn cutover(&self) {
            self.initial();
            let mut l = self.session();
            l.quiesce_simulated_agent();
            l.stage_cutover().unwrap();
            l.commit_cutover().unwrap();
        }
        fn staged_new(&self) {
            self.cutover();
            self.session().mock_prepare().unwrap();
            self.session().stage_prepared_rotation().unwrap();
        }
        fn current(&self) -> (DeviceIdentity, u64) {
            self.session().recover().unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }

    #[test]
    fn legacy_is_read_before_any_cutover_marker() {
        let f = Fixture::new(); f.initial();
        assert_eq!(f.current().1, 0);
        assert_eq!(f.current().0.device_secret, synthetic_active().device_secret);
    }
    #[test]
    fn quiescence_is_required_for_stage_and_commit() {
        let f = Fixture::new(); f.initial();
        assert!(f.session().stage_cutover().is_err());
        let mut l = f.session(); l.quiesce_simulated_agent(); l.stage_cutover().unwrap();
        assert!(f.session().commit_cutover().is_err());
        assert_eq!(f.current().1, 0);
    }
    #[test]
    fn crash_before_marker_keeps_legacy_authoritative() {
        let f = Fixture::new(); f.initial();
        let mut l = f.session(); l.quiesce_simulated_agent(); l.stage_cutover().unwrap();
        assert!(l.read(SEALED).unwrap().is_some());
        assert!(l.read(MARKER).unwrap().is_none());
        assert_eq!(f.current().1, 0);
    }
    #[test]
    fn marker_commit_switches_to_encrypted_identity() {
        let f = Fixture::new(); f.cutover();
        assert_eq!(f.current().1, 1);
        f.session().remove_legacy_fixture().unwrap();
        assert_eq!(f.current().1, 1);
    }
    #[test]
    fn pending_certificate_only_blocks_migration() {
        let f = Fixture::new();
        let mut id = synthetic_active(); id.pending_certificate_id = Some("fixture-cert".into());
        f.session().write_legacy(&id).unwrap();
        let mut l = f.session(); l.quiesce_simulated_agent();
        assert!(l.stage_cutover().is_err());
    }
    #[test]
    fn pending_command_blocks_migration() {
        let f = Fixture::new();
        let mut id = synthetic_active(); id.pending_certificate_id = Some("fixture-cert".into());
        id.pending_rotation_command_id = Some("fixture-command".into());
        f.session().write_legacy(&id).unwrap();
        let mut l = f.session(); l.quiesce_simulated_agent();
        assert!(l.stage_cutover().is_err());
    }
    #[test]
    fn stage_must_be_reverified_after_source_changes() {
        let f = Fixture::new(); f.initial();
        let mut l = f.session(); l.quiesce_simulated_agent(); l.stage_cutover().unwrap();
        let mut id = synthetic_active(); id.pending_certificate_id = Some("changed".into());
        l.publish(LEGACY, &id).unwrap();
        assert!(l.commit_cutover().is_err());
    }
    #[test]
    fn corrupted_sealed_after_marker_never_falls_back_to_plaintext() {
        let f = Fixture::new(); f.cutover();
        fs::write(f.root.join(SEALED), b"{bad").unwrap();
        assert!(f.session().recover().is_err());
    }
    #[test]
    fn missing_sealed_after_marker_never_falls_back() {
        let f = Fixture::new(); f.cutover();
        fs::remove_file(f.root.join(SEALED)).unwrap();
        assert!(f.session().recover().is_err());
    }
    #[test]
    fn malformed_or_symlinked_marker_fails_closed() {
        let f = Fixture::new(); f.cutover();
        let marker = f.root.join(MARKER);
        fs::write(&marker, b"not-json").unwrap();
        assert!(f.session().recover().is_err());
        fs::remove_file(&marker).unwrap();
        symlink("/dev/null", &marker).unwrap();
        assert!(f.session().recover().is_err());
    }
    #[test]
    fn tampered_encrypted_snapshot_detected() {
        let f = Fixture::new(); f.cutover();
        let mut data: serde_json::Value = f.session().load_json(SEALED).unwrap().unwrap();
        data["generation"] = serde_json::json!(55);
        f.session().publish(SEALED, &data).unwrap();
        assert!(f.session().recover().is_err());
    }
    #[test]
    fn cloud_prepare_alone_does_not_replace_old_local_credential() {
        let f = Fixture::new(); f.cutover();
        f.session().mock_prepare().unwrap();
        assert_eq!(f.current().1, 1);
        assert_eq!(f.current().0.device_secret, synthetic_active().device_secret);
        assert!(f.session().mock_commit().is_err());
    }
    #[test]
    fn no_remote_commit_before_pending_local_durability() {
        let f = Fixture::new(); f.cutover(); f.session().mock_prepare().unwrap();
        assert!(f.session().mock_commit().is_err());
        assert_eq!(f.session().mock_cloud().unwrap().phase, RemotePhase::Prepared);
    }
    #[test]
    fn restart_after_local_stage_replays_commit_ack_and_finalization() {
        let f = Fixture::new(); f.staged_new();
        assert_eq!(f.current().1, 2);
        assert_eq!(f.current().0.device_secret, NEW);
        f.session().replay(true).unwrap();
        let (id, generation) = f.current();
        assert_eq!(generation, 3);
        assert_eq!(id.device_secret, NEW);
        assert!(id.pending_certificate_id.is_none() && id.pending_rotation_command_id.is_none());
        assert_eq!(f.session().mock_cloud().unwrap().phase, RemotePhase::Acknowledged);
    }
    #[test]
    fn restart_after_remote_commit_replays_ack_then_finalization() {
        let f = Fixture::new(); f.staged_new();
        f.session().mock_commit().unwrap();
        assert_eq!(f.session().mock_cloud().unwrap().phase, RemotePhase::Committed);
        f.session().replay(true).unwrap();
        assert_eq!(f.current().1, 3);
    }
    #[test]
    fn restart_after_ack_only_finalizes_local_state() {
        let f = Fixture::new(); f.staged_new();
        f.session().mock_commit().unwrap(); f.session().mock_ack().unwrap();
        f.session().replay(true).unwrap();
        assert_eq!(f.current().1, 3);
    }
    #[test]
    fn network_outage_keeps_pending_replacement_durable() {
        let f = Fixture::new(); f.staged_new();
        assert!(f.session().replay(false).is_err());
        assert_eq!(f.current().1, 2);
        assert_eq!(f.current().0.pending_certificate_id.as_deref(), Some(CERT));
        assert_eq!(f.session().mock_cloud().unwrap().phase, RemotePhase::Prepared);
    }
    #[test]
    fn replay_is_idempotent_after_completion() {
        let f = Fixture::new(); f.staged_new();
        f.session().replay(true).unwrap();
        f.session().replay(true).unwrap();
        assert_eq!(f.current().1, 3);
    }
    #[test]
    fn duplicate_prepare_or_stage_is_rejected() {
        let f = Fixture::new(); f.staged_new();
        assert!(f.session().mock_prepare().is_err());
        assert!(f.session().stage_prepared_rotation().is_err());
    }
    #[test]
    fn corrupt_mock_cloud_cannot_clear_pending_state() {
        let f = Fixture::new(); f.staged_new();
        fs::write(f.root.join(MOCK_CLOUD), b"corrupt").unwrap();
        assert!(f.session().replay(true).is_err());
        assert_eq!(f.current().1, 2);
    }
    #[test]
    fn forged_cloud_ack_does_not_allow_out_of_order_finalization() {
        let f = Fixture::new(); f.staged_new();
        assert!(f.session().mock_ack().is_err());
        assert!(f.session().finalize().is_err());
        assert_eq!(f.current().1, 2);
    }
    #[test]
    fn real_identity_and_real_paths_are_never_accepted() {
        assert!(Lab::new(Path::new("/var/lib/highline-nexus")).is_err());
        assert!(Lab::new(Path::new("/tmp/my-real-controller")).is_err());
        let f = Fixture::new();
        let mut real = synthetic_active(); real.device_id = "real-device".into();
        assert!(f.session().write_legacy(&real).is_err());
        assert!(authorize_live_sa15n_cutover().is_err());
    }
    #[test]
    fn symlink_root_and_world_readable_files_are_refused() {
        let f = Fixture::new(); f.initial();
        fs::set_permissions(f.root.join(LEGACY), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.session().recover().is_err());
        let link = format!("{PREFIX}{}", uuid::Uuid::new_v4());
        let linked_path = Path::new("/tmp").join(link);
        symlink(&f.root, &linked_path).unwrap();
        assert!(Lab::new(&linked_path).unwrap().recover().is_err());
        fs::remove_file(&linked_path).unwrap();
    }
}
