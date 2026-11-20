//! SA-15H lab-only crash-consistent encrypted identity snapshot store.
//!
//! No live enrollment, device.json, relay, or cloud agent hooks.
//! Snapshots contain ONLY authenticated encrypted envelopes and non-secret
//! rotation metadata. Power-failure durability depends on the underlying
//! filesystem honoring fsync; sudden-power-loss recovery is NOT yet tested.
//! A monotonic generation is NOT anti-rollback protection without RPMB or
//! another hardware monotonic counter.

use crate::cloud::hybrid_secret_envelope::HybridSecretEnvelope;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA: u8 = 1;
const MAX_RECORD: u64 = 64 * 1024;
const SNAPSHOT: &str = "snapshot.json";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub certificate_id: String,
    pub command_id: String,
    pub generation: u64,
    pub replacement: HybridSecretEnvelope,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySnapshot {
    pub schema: u8,
    pub controller_id: String,
    pub object_id: String,
    pub generation: u64,
    pub active: HybridSecretEnvelope,
    pub pending: Option<Pending>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 160 &&
        id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl IdentitySnapshot {
    pub fn initial(controller: &str, object: &str, active: HybridSecretEnvelope) -> Result<Self> {
        let s = Self {
            schema: SCHEMA, controller_id: controller.into(), object_id: object.into(),
            generation: 1, active, pending: None,
        };
        s.validate()?;
        Ok(s)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == SCHEMA, "unsupported snapshot schema");
        ensure!(valid_id(&self.controller_id) && valid_id(&self.object_id), "invalid snapshot scope");
        ensure!(self.generation > 0, "invalid generation");
        self.active.validate_for(&self.controller_id, &self.object_id)?;
        if let Some(p) = &self.pending {
            ensure!(valid_id(&p.certificate_id) && valid_id(&p.command_id), "invalid pending metadata");
            ensure!(p.generation == self.generation.checked_add(1).context("generation overflow")?,
                "pending generation mismatch");
            p.replacement.validate_for(&self.controller_id, &self.object_id)?;
        }
        Ok(())
    }

    pub fn stage(&self, cert: &str, command: &str, replacement: HybridSecretEnvelope) -> Result<Self> {
        self.validate()?;
        ensure!(self.pending.is_none(), "pending rotation must be resolved first");
        let mut next = self.clone();
        next.pending = Some(Pending {
            certificate_id: cert.into(), command_id: command.into(),
            generation: self.generation.checked_add(1).context("generation overflow")?,
            replacement,
        });
        next.validate()?;
        Ok(next)
    }

    /// When a pending credential exists, startup must use it for commit/ACK,
    /// NOT silently fall back to an older active credential.
    pub fn recovery_credential(&self) -> Result<&HybridSecretEnvelope> {
        self.validate()?;
        Ok(match &self.pending { Some(p) => &p.replacement, None => &self.active })
    }

    pub fn finalize(&self) -> Result<Self> {
        self.validate()?;
        let pending = self.pending.as_ref().context("no pending rotation")?;
        let mut next = self.clone();
        next.active = pending.replacement.clone();
        next.generation = pending.generation;
        next.pending = None;
        next.validate()?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault { None, BeforeRename }

#[derive(Clone)]
pub struct StagedLabStore { root: PathBuf }

impl StagedLabStore {
    pub fn new(root: &Path) -> Result<Self> {
        // Explicit lab directory; never accept the real controller identity path.
        let parent = root.parent().context("missing lab parent")?;
        ensure!(parent == Path::new("/var/tmp") || parent == Path::new("/tmp"),
            "lab store allowed only directly under /var/tmp or /tmp");
        let name = root.file_name().and_then(|x| x.to_str()).unwrap_or("");
        ensure!(name.starts_with("hlaxs-sa15h-lab-") && name.len() <= 110
                && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "unsafe lab root name");
        Ok(Self { root: root.into() })
    }

    pub fn create(&self) -> Result<()> {
        fs::create_dir(&self.root).context("create exclusive SA-15H lab directory")?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        self.check_dir()?;
        self.sync_dir()?;
        Ok(())
    }

    fn check_dir(&self) -> Result<()> {
        let m = fs::symlink_metadata(&self.root).context("inspect lab directory")?;
        ensure!(m.is_dir() && !m.file_type().is_symlink(), "invalid lab directory");
        ensure!(m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "lab directory ownership or permissions invalid");
        Ok(())
    }

    fn sync_dir(&self) -> Result<()> { File::open(&self.root)?.sync_all().context("fsync lab directory") }

    pub fn root(&self) -> &Path { &self.root }

    pub fn load(&self) -> Result<IdentitySnapshot> {
        self.check_dir()?;
        let path = self.root.join(SNAPSHOT);
        let meta = fs::symlink_metadata(&path).context("inspect snapshot")?;
        ensure!(meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
            "unsafe snapshot inode");
        ensure!(meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "unsafe snapshot owner/mode");
        ensure!(meta.len() > 0 && meta.len() <= MAX_RECORD, "snapshot size invalid");
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path)?;
        file.take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
        ensure!(!bytes.is_empty() && bytes.len() as u64 <= MAX_RECORD, "snapshot length invalid");
        let record: IdentitySnapshot = serde_json::from_slice(&bytes).context("decode snapshot")?;
        record.validate()?;
        Ok(record)
    }

    pub fn write(&self, snapshot: &IdentitySnapshot, fault: Fault) -> Result<()> {
        self.check_dir()?;
        snapshot.validate()?;
        let encoded = serde_json::to_vec(snapshot)?;
        ensure!(!encoded.is_empty() && encoded.len() as u64 <= MAX_RECORD,
            "snapshot would exceed maximum size");
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let tmp = self.root.join(format!(".snapshot-{}-{unique}.tmp", std::process::id()));
        let mut f = OpenOptions::new().create_new(true).write(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        f.write_all(&encoded)?;
        f.sync_all()?;
        drop(f);
        if fault == Fault::BeforeRename {
            // A deliberately abandoned, fully written .tmp simulates a crash
            // before the atomic rename. Readers must ignore this temp file.
            bail!("SA-15H simulated interruption before rename");
        }
        fs::rename(&tmp, self.root.join(SNAPSHOT))?;
        self.sync_dir()?;
        Ok(())
    }

    /// Clean up ONLY our verified isolated lab directory; never live data.
    pub fn cleanup(&self) -> Result<()> {
        self.check_dir()?;
        fs::remove_dir_all(&self.root).context("remove SA-15H lab files")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::hybrid_secret_envelope::{DataKeyWrapper, seal_development_hybrid};
    struct Fixture;
    impl DataKeyWrapper for Fixture {
        fn wrap_32(&self, key: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut v = *key;
            for (i, x) in v.iter_mut().enumerate() { *x ^= iv[i % 16] ^ 0x95; }
            Ok(v)
        }
        fn unwrap_32(&self, data: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> { self.wrap_32(data, iv) }
    }
    fn env(bytes: &[u8]) -> HybridSecretEnvelope {
        seal_development_hybrid(&Fixture, "hlaxs-sa15e-h-fixture", "controller_H", "object_H", bytes).unwrap()
    }
    fn fixture() -> IdentitySnapshot { IdentitySnapshot::initial("controller_H", "object_H", env(b"synthetic-old")).unwrap() }
    fn store() -> StagedLabStore {
        let root = std::env::temp_dir().join(format!("hlaxs-sa15h-lab-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let store = StagedLabStore::new(&root).unwrap(); store.create().unwrap(); store
    }
    #[test] fn initial_round_trip_and_private_file() {
        let s = store(); s.write(&fixture(), Fault::None).unwrap();
        assert_eq!(s.load().unwrap().generation, 1);
        assert_eq!(fs::metadata(s.root().join(SNAPSHOT)).unwrap().mode() & 0o777, 0o600);
        s.cleanup().unwrap();
    }
    #[test] fn pending_requires_new_recovery_credential() {
        let s = fixture().stage("cert_H", "cmd_H", env(b"synthetic-new")).unwrap();
        assert!(s.pending.is_some());
        assert_eq!(s.recovery_credential().unwrap().secret.ciphertext_and_tag,
            s.pending.as_ref().unwrap().replacement.secret.ciphertext_and_tag);
        let final_state = s.finalize().unwrap();
        assert!(final_state.pending.is_none() && final_state.generation == 2);
    }
    #[test] fn interrupted_stage_keeps_old_snapshot() {
        let s = store(); s.write(&fixture(), Fault::None).unwrap();
        let prepared = s.load().unwrap().stage("cert_H", "cmd_H", env(b"synthetic-new")).unwrap();
        assert!(s.write(&prepared, Fault::BeforeRename).is_err());
        let original = s.load().unwrap();
        assert!(original.pending.is_none() && original.generation == 1);
        s.write(&prepared, Fault::None).unwrap();
        assert!(s.load().unwrap().pending.is_some());
        s.cleanup().unwrap();
    }
    #[test] fn invalid_pending_never_falls_back() {
        let mut s = fixture().stage("cert_H", "cmd_H", env(b"synthetic-new")).unwrap();
        s.pending.as_mut().unwrap().replacement.wrapped_dek.clear();
        assert!(s.recovery_credential().is_err());
    }
    #[test] fn directory_restriction_and_generation_checks() {
        assert!(StagedLabStore::new(Path::new("/var/lib/highline-nexus")).is_err());
        assert!(StagedLabStore::new(Path::new("/var/tmp/something-else")).is_err());
        let mut s = fixture(); s.generation = 0; assert!(s.validate().is_err());
        let mut s = fixture().stage("cert_H", "cmd_H", env(b"new")).unwrap();
        s.pending.as_mut().unwrap().generation = 77;
        assert!(s.validate().is_err());
    }
    #[test] fn snapshot_does_not_serialize_test_secret() {
        let encoded = serde_json::to_vec(&fixture()).unwrap();
        assert!(!encoded.windows(b"synthetic-old".len()).any(|w| w == b"synthetic-old"));
    }
}
