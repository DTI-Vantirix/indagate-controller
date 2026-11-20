//! SA-15K — legacy JSON persistence adapter for the existing cloud agent.
//!
//! This module does NOT encrypt secrets. It preserves the exact JSON schema of
//! the current controller DeviceIdentity and the existing cloud protocol.
//! No CAAM key or cloud identity is opened here, and no migration exists.
//!
//! SAFETY: /var/lib/highline-nexus/device.json remains a plaintext secret.
//! Do not deploy SA-15K without a controlled rollout and backups; the current
//! stage tests source integration on the development machine ONLY.

use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_IDENTITY_BYTES: u64 = 64 * 1024;

pub struct LegacyJsonStore {
    path: PathBuf,
}

impl LegacyJsonStore {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }

    fn parent(&self) -> Result<&Path> {
        ensure!(self.path.file_name().is_some_and(|s| s == std::ffi::OsStr::new("device.json")),
            "identity store accepts device.json only");
        ensure!(self.path.is_absolute(), "identity store requires absolute path");
        self.path.parent().context("identity has no parent directory")
    }

    fn verify_directory(parent: &Path) -> Result<()> {
        let m = fs::symlink_metadata(parent).context("inspect identity directory")?;
        ensure!(m.is_dir() && !m.file_type().is_symlink(),
            "identity directory is not a regular directory");
        ensure!(m.uid() == unsafe { libc::geteuid() },
            "identity directory must belong to the running service user");
        Ok(())
    }

    fn validate_file(meta: &fs::Metadata) -> Result<()> {
        ensure!(meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
            "identity file must be a private regular single-link file");
        ensure!(meta.uid() == unsafe { libc::geteuid() }, "identity file owner mismatch");
        ensure!(meta.mode() & 0o077 == 0, "identity file is accessible to group/others");
        ensure!(meta.len() > 0 && meta.len() <= MAX_IDENTITY_BYTES,
            "identity file size is invalid");
        Ok(())
    }

    /// No fallback from corrupt, replaced, or missing live identity files.
    /// The caller retains its existing enrolled / unenrolled behavior.
    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        let parent = self.parent()?;
        // Preserve the legacy unenrolled state: a missing identity directory
        // means no device.json exists yet, not an authentication failure.
        match fs::symlink_metadata(parent) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("inspect identity parent"),
            Ok(_) => Self::verify_directory(parent)?,
        }
        let before = match fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("inspect identity metadata"),
        };
        Self::validate_file(&before)?;

        let file = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path).context("open legacy identity")?;
        let opened = file.metadata()?;
        Self::validate_file(&opened)?;
        ensure!(before.ino() == opened.ino() && before.dev() == opened.dev(),
            "identity file changed during opening");

        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(MAX_IDENTITY_BYTES + 1)
            .read_to_end(&mut bytes).context("read legacy identity")?;
        ensure!(!bytes.is_empty() && bytes.len() as u64 <= MAX_IDENTITY_BYTES,
            "identity changed size during read");
        let record = serde_json::from_slice(&bytes).context("decode legacy identity")?;
        Ok(Some(record))
    }

    /// Atomic replacement with fsync of both the new file and directory.
    /// Keeps original serialization; NEVER writes a sealed format or migrated
    /// record. Interrupted .tmp files are ignored by load().
    pub fn save<T: Serialize>(&self, record: &T) -> Result<()> {
        let parent = self.parent()?;
        fs::create_dir_all(parent).context("create legacy identity directory")?;
        Self::verify_directory(parent)?;
        match fs::symlink_metadata(&self.path) {
            Ok(m) => Self::validate_file(&m)?,
            Err(e) if e.kind() == ErrorKind::NotFound => {},
            Err(e) => return Err(e).context("inspect existing identity"),
        }

        let bytes = serde_json::to_vec_pretty(record)?;
        ensure!(!bytes.is_empty() && bytes.len() as u64 <= MAX_IDENTITY_BYTES,
            "identity serialization exceeds size limit");
        let name = format!(".device.json.{}.tmp", uuid::Uuid::new_v4());
        let tmp = parent.join(name);
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true).write(true).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&tmp).context("create exclusive identity staging file")?;
            file.write_all(&bytes).context("write staged identity")?;
            file.sync_all().context("fsync staged identity")?;
            drop(file);
            fs::rename(&tmp, &self.path).context("atomically replace identity")?;
            File::open(parent)?.sync_all().context("fsync identity directory")?;
            Ok(())
        })();
        if result.is_err() {
            // Removes only this invocation's unique temporary file.
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct SyntheticIdentity {
        device_id: String,
        controller_id: String,
        device_secret: String,
        pending_certificate_id: Option<String>,
        pending_rotation_command_id: Option<String>,
    }

    fn id() -> SyntheticIdentity {
        SyntheticIdentity {
            device_id: "synthetic-device-K".into(),
            controller_id: "synthetic-controller-K".into(),
            device_secret: "SYNTHETIC_ONLY_DO_NOT_ENROLL_1234567890".into(),
            pending_certificate_id: None,
            pending_rotation_command_id: None,
        }
    }
    struct Lab { path: PathBuf, root: PathBuf }
    impl Lab {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "hlaxs-sa15k-lab-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self { path: root.join("device.json"), root }
        }
        fn store(&self) -> LegacyJsonStore { LegacyJsonStore::new(&self.path) }
    }
    impl Drop for Lab {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }

    #[test]
    fn existing_legacy_json_schema_is_preserved() {
        let lab = Lab::new(); let record = id();
        lab.store().save(&record).unwrap();
        assert_eq!(lab.store().load::<SyntheticIdentity>().unwrap(), Some(record.clone()));
        assert_eq!(fs::read(&lab.path).unwrap(), serde_json::to_vec_pretty(&record).unwrap());
        assert_eq!(fs::metadata(&lab.path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    #[test]
    fn missing_file_is_not_auto_migrated_or_generated() {
        let lab = Lab::new();
        assert_eq!(lab.store().load::<SyntheticIdentity>().unwrap(), None);
        assert!(!lab.path.exists());
    }
    #[test]
    fn missing_parent_directory_is_unenrolled_not_an_error() {
        let lab = Lab::new();
        let child = lab.root.join("missing").join("device.json");
        assert!(LegacyJsonStore::new(&child).load::<SyntheticIdentity>().unwrap().is_none());
    }
    #[test]
    fn second_generation_atomically_replaces_first() {
        let lab = Lab::new(); let mut newer = id();
        lab.store().save(&id()).unwrap();
        newer.device_secret = "SYNTHETIC_REPLACEMENT_ABCDEFGHIJKLMNOPQRSTUVWXYZ".into();
        newer.pending_certificate_id = Some("certK".into());
        newer.pending_rotation_command_id = Some("cmdK".into());
        lab.store().save(&newer).unwrap();
        assert_eq!(lab.store().load::<SyntheticIdentity>().unwrap(), Some(newer));
        assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 1);
    }
    #[test]
    fn certificate_only_pending_is_roundtripped_without_inventing_command() {
        let lab = Lab::new(); let mut candidate = id();
        candidate.pending_certificate_id = Some("cert-without-command".into());
        lab.store().save(&candidate).unwrap();
        let recovered = lab.store().load::<SyntheticIdentity>().unwrap().unwrap();
        assert_eq!(recovered.pending_certificate_id, candidate.pending_certificate_id);
        assert_eq!(recovered.pending_rotation_command_id, None);
    }
    #[test]
    fn abandoned_partial_staging_file_is_ignored() {
        let lab = Lab::new(); lab.store().save(&id()).unwrap();
        fs::write(lab.root.join(".device.json.interrupted.tmp"), b"broken").unwrap();
        assert_eq!(lab.store().load::<SyntheticIdentity>().unwrap(), Some(id()));
    }
    #[test]
    fn symlink_identity_rejected_without_following_target() {
        let lab = Lab::new();
        let target = lab.root.join("external");
        fs::write(&target, serde_json::to_vec_pretty(&id()).unwrap()).unwrap();
        symlink(&target, &lab.path).unwrap();
        assert!(lab.store().load::<SyntheticIdentity>().is_err());
        assert!(lab.store().save(&id()).is_err());
    }
    #[test]
    fn group_readable_identity_fails_closed() {
        let lab = Lab::new(); lab.store().save(&id()).unwrap();
        fs::set_permissions(&lab.path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(lab.store().load::<SyntheticIdentity>().is_err());
        assert!(lab.store().save(&id()).is_err());
    }
    #[test]
    fn malformed_identity_does_not_fall_back() {
        let lab = Lab::new(); lab.store().save(&id()).unwrap();
        fs::write(&lab.path, b"{not json").unwrap();
        assert!(lab.store().load::<SyntheticIdentity>().is_err());
    }
    #[test]
    fn sealed_manifest_is_not_treated_as_legacy_identity() {
        let lab = Lab::new();
        fs::write(&lab.path, br#"{"schema":1,"sealed_identity":"not-supported"}"#).unwrap();
        fs::set_permissions(&lab.path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(lab.store().load::<SyntheticIdentity>().is_err());
    }
    #[test]
    fn non_identity_file_name_rejected() {
        let lab = Lab::new();
        let bad = LegacyJsonStore::new(&lab.root.join("snapshot.json"));
        assert!(bad.load::<SyntheticIdentity>().is_err());
        assert!(bad.save(&id()).is_err());
    }
    #[test]
    fn oversized_existing_file_rejected() {
        let lab = Lab::new();
        fs::write(&lab.path, vec![0x41; (MAX_IDENTITY_BYTES + 1) as usize]).unwrap();
        fs::set_permissions(&lab.path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(lab.store().load::<SyntheticIdentity>().is_err());
        assert!(lab.store().save(&id()).is_err());
    }
}
