//! SA-15L: synthetic-only complete-device-identity encryption and cutover rehearsal.
//!
//! The previous SA-15E/SA-15H snapshots protected a secret; this lab also
//! protects site, organization, profile and rotation metadata INSIDE AEAD.
//! There is NO production migration function. Does not read the live identity.
//! No cloud request, controller deployment, CAAM provisioning or fuse changes.
//!
//! IMPORTANT: A file-based cutover marker is not hardware anti-rollback.
//! Open-HAB CAAM remains development-only. A real cutover needs explicit
//! operational approval, recovery testing, and rollback-resistant trust.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::hybrid_secret_envelope::{
    DataKeyWrapper, HybridSecretEnvelope, open_development_hybrid, seal_development_hybrid,
};
use crate::cloud::sa15k_legacy_identity_store::LegacyJsonStore;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::ffi::CString;
use std::path::{Path, PathBuf};

const SCHEMA: u8 = 1;
const CONTROLLER: &str = "hlaxs_sa15l_synthetic_controller";
const DEVICE: &str = "hlaxs_sa15l_synthetic_device";
const ORG: &str = "hlaxs_sa15l_synthetic_organization";
const SITE: &str = "hlaxs_sa15l_synthetic_site";
const PROFILE: &str = "hlaxs_sa15l_synthetic_profile";
const KEY: &str = "hlaxs-sa15e-sa15l-fixture";
const OLD: &str = "SYNTHETIC_SA15L_OLD_SECRET_12345678901234567890";
const NEW: &str = "SYNTHETIC_SA15L_NEW_SECRET_09876543210987654321";
const MAX_RECORD: u64 = 64 * 1024;
const SEALED_NAME: &str = "sealed-identity.json";
const MARKER_NAME: &str = "cutover.json";
const LEGACY_NAME: &str = "device.json";
const ROOT_PREFIX: &str = "hlaxs-sa15l-lab-";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InnerRecord {
    generation: u64,
    identity: DeviceIdentity,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedFullIdentity {
    schema: u8,
    controller_id: String,
    device_id: String,
    generation: u64,
    encrypted_identity: HybridSecretEnvelope,
}

fn validate_fixture(id: &DeviceIdentity) -> Result<()> {
    ensure!(id.device_id == DEVICE && id.controller_id == CONTROLLER,
        "SA-15L accepts synthetic scope only");
    ensure!(id.organization_id == ORG && id.site_id == SITE && id.hardware_profile == PROFILE,
        "SA-15L accepts synthetic scope only");
    ensure!(id.device_secret == OLD || id.device_secret == NEW,
        "SA-15L accepts synthetic credentials only");
    ensure!(id.pending_rotation_command_id.is_none() || id.pending_certificate_id.is_some(),
        "orphan pending rotation command is invalid");
    for id in [id.pending_certificate_id.as_deref(), id.pending_rotation_command_id.as_deref()].into_iter().flatten() {
        ensure!(!id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control),
            "invalid pending metadata");
    }
    Ok(())
}

pub fn synthetic_active() -> DeviceIdentity {
    DeviceIdentity {
        device_id: DEVICE.into(), controller_id: CONTROLLER.into(),
        organization_id: ORG.into(), site_id: SITE.into(),
        device_secret: OLD.into(), hardware_profile: PROFILE.into(),
        pending_certificate_id: None, pending_rotation_command_id: None,
    }
}

impl SealedFullIdentity {
    fn validate(&self) -> Result<()> {
        ensure!(self.schema == SCHEMA && self.generation > 0,
            "unsupported sealed identity schema or generation");
        ensure!(self.controller_id == CONTROLLER && self.device_id == DEVICE,
            "unexpected sealed identity scope");
        self.encrypted_identity.validate_for(CONTROLLER, DEVICE)
    }
}

/// Synthetic-only sealing. Not callable with a real controller identity.
/// Only the scope and generation appear outside the authenticated payload;
/// they are repeated inside and compared after AEAD opens.
pub fn seal_synthetic<W: DataKeyWrapper>(
    wrapper: &W, identity: &DeviceIdentity, generation: u64,
) -> Result<SealedFullIdentity> {
    validate_fixture(identity)?;
    ensure!(generation > 0, "invalid generation");
    let payload = serde_json::to_vec(&InnerRecord { generation, identity: identity.clone() })?;
    ensure!(payload.len() as u64 <= MAX_RECORD, "synthetic payload too large");
    let encrypted_identity = seal_development_hybrid(wrapper, KEY, CONTROLLER, DEVICE, &payload)?;
    let outer = SealedFullIdentity {
        schema: SCHEMA, controller_id: CONTROLLER.into(), device_id: DEVICE.into(),
        generation, encrypted_identity,
    };
    outer.validate()?;
    Ok(outer)
}

pub fn open_synthetic<W: DataKeyWrapper>(
    wrapper: &W, sealed: &SealedFullIdentity,
) -> Result<DeviceIdentity> {
    sealed.validate()?;
    let bytes = open_development_hybrid(wrapper, KEY, CONTROLLER, DEVICE,
        &sealed.encrypted_identity)?;
    ensure!(!bytes.is_empty() && bytes.len() as u64 <= MAX_RECORD, "invalid opened size");
    let inner: InnerRecord = serde_json::from_slice(&bytes).context("decode authenticated identity")?;
    ensure!(inner.generation == sealed.generation, "sealed generation mismatch");
    validate_fixture(&inner.identity)?;
    Ok(inner.identity)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode { Sealed }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CutoverMarker { schema: u8, mode: Mode, generation: u64 }

/// This local path boundary is exclusively for deterministic lab rehearsal.
/// It intentionally cannot represent /var/lib/highline-nexus or a custom path.
pub struct Sa15lLab { root: PathBuf }

impl Sa15lLab {
    pub fn new(root: &Path) -> Result<Self> {
        let parent = root.parent().context("missing lab parent")?;
        ensure!(parent == Path::new("/tmp") || parent == Path::new("/var/tmp"),
            "only top-level /tmp or /var/tmp lab roots are allowed");
        let name = root.file_name().and_then(|n| n.to_str()).unwrap_or("");
        ensure!(name.starts_with(ROOT_PREFIX) && name.len() <= 100 &&
            name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "invalid SA-15L lab directory name");
        Ok(Self { root: root.into() })
    }

    pub fn create(&self) -> Result<()> {
        fs::create_dir(&self.root).context("create exclusive SA-15L lab root")?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        self.check_root()?;
        self.sync_dir()
    }

    fn check_root(&self) -> Result<()> {
        let m = fs::symlink_metadata(&self.root)?;
        ensure!(m.is_dir() && !m.file_type().is_symlink() &&
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "unsafe SA-15L lab root");
        Ok(())
    }

    fn sync_dir(&self) -> Result<()> { File::open(&self.root)?.sync_all().context("fsync lab directory") }

    fn lab_path(&self, name: &str) -> Result<PathBuf> {
        ensure!([SEALED_NAME, MARKER_NAME, LEGACY_NAME].contains(&name), "unexpected lab file");
        self.check_root()?;
        Ok(self.root.join(name))
    }

    fn inspect(meta: &fs::Metadata) -> Result<()> {
        ensure!(meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
            "unsafe lab file type");
        ensure!(meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "unsafe lab file ownership or permissions");
        ensure!(meta.len() > 0 && meta.len() <= MAX_RECORD, "invalid lab file size");
        Ok(())
    }

    fn read_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.lab_path(name)?;
        let before = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("stat lab record"),
        };
        Self::inspect(&before)?;
        let mut f = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path).context("open lab record")?;
        let after = f.metadata()?;
        Self::inspect(&after)?;
        ensure!(before.ino() == after.ino() && before.dev() == after.dev(),
            "lab record changed during open");
        let mut bytes = Vec::new();
        f.take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
        ensure!(!bytes.is_empty() && bytes.len() as u64 <= MAX_RECORD,
            "lab record read size invalid");
        Ok(Some(bytes))
    }

    fn atomic_create(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.lab_path(name)?;
        ensure!(!bytes.is_empty() && bytes.len() as u64 <= MAX_RECORD, "lab record invalid size");
        ensure!(fs::symlink_metadata(&path).is_err_and(|e| e.kind() == ErrorKind::NotFound),
            "lab artifact already exists");
        let tmp = self.root.join(format!(".sa15l-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new().create_new(true).write(true).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            // Atomic no-replace rename: unlike hard_link(), this never
            // publishes a record with a temporary extra hard link. A crash
            // cannot strand the committed inode with nlink=2.
            let source = CString::new(tmp.as_os_str().as_bytes())?;
            let target = CString::new(path.as_os_str().as_bytes())?;
            let rc = unsafe { libc::renameat2(libc::AT_FDCWD, source.as_ptr(),
                libc::AT_FDCWD, target.as_ptr(), libc::RENAME_NOREPLACE) };
            if rc != 0 { return Err(std::io::Error::last_os_error()).context("publish exclusive lab record"); }
            self.sync_dir()?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(&tmp); }
        result
    }

    pub fn create_legacy(&self, fixture: &DeviceIdentity) -> Result<()> {
        validate_fixture(fixture)?;
        ensure!(self.read_file(MARKER_NAME)?.is_none(), "lab already cut over");
        ensure!(self.read_file(LEGACY_NAME)?.is_none(), "legacy fixture already exists");
        LegacyJsonStore::new(&self.lab_path(LEGACY_NAME)?).save(fixture)
    }

    fn read_legacy(&self) -> Result<DeviceIdentity> {
        LegacyJsonStore::new(&self.lab_path(LEGACY_NAME)?)
            .load::<DeviceIdentity>()?
            .context("synthetic legacy identity missing")
            .and_then(|id| { validate_fixture(&id)?; Ok(id) })
    }

    /// Initial migration must never start during ANY pending rotation,
    /// including certificate-only pending state (supported by legacy agent).
    pub fn stage_from_idle_legacy<W: DataKeyWrapper>(&self, key: &W) -> Result<()> {
        ensure!(self.read_file(MARKER_NAME)?.is_none(), "already cut over");
        ensure!(self.read_file(SEALED_NAME)?.is_none(), "sealed staging already exists");
        let id = self.read_legacy()?;
        ensure!(id.pending_certificate_id.is_none() && id.pending_rotation_command_id.is_none(),
            "legacy pending rotation must settle before cutover");
        let sealed = seal_synthetic(key, &id, 1)?;
        self.atomic_create(SEALED_NAME, &serde_json::to_vec(&sealed)?)?;
        self.verify_staged(key)
    }

    fn read_sealed(&self) -> Result<SealedFullIdentity> {
        let bytes = self.read_file(SEALED_NAME)?.context("sealed snapshot missing")?;
        let sealed: SealedFullIdentity = serde_json::from_slice(&bytes)?;
        sealed.validate()?;
        Ok(sealed)
    }

    pub fn verify_staged<W: DataKeyWrapper>(&self, key: &W) -> Result<()> {
        let legacy = self.read_legacy()?;
        ensure!(legacy.pending_certificate_id.is_none() && legacy.pending_rotation_command_id.is_none(),
            "legacy rotation is pending");
        let recovered = open_synthetic(key, &self.read_sealed()?)?;
        ensure!(serde_json::to_vec(&legacy)? == serde_json::to_vec(&recovered)?,
            "encrypted synthetic identity mismatches legacy");
        Ok(())
    }

    /// After publishing this marker, recovery ALWAYS selects sealed. It NEVER
    /// retries device.json on a missing or corrupt sealed file. This marker is
    /// lab-only and NOT rollback-resistant against offline disk modification.
    pub fn cutover<W: DataKeyWrapper>(&self, key: &W) -> Result<()> {
        ensure!(self.read_file(MARKER_NAME)?.is_none(), "already cut over");
        self.verify_staged(key)?;
        let marker = CutoverMarker { schema: SCHEMA, mode: Mode::Sealed, generation: 1 };
        self.atomic_create(MARKER_NAME, &serde_json::to_vec(&marker)?)?;
        let _ = self.recover(key)?;
        Ok(())
    }

    pub fn recover<W: DataKeyWrapper>(&self, key: &W) -> Result<DeviceIdentity> {
        match self.read_file(MARKER_NAME)? {
            None => self.read_legacy(),
            Some(data) => {
                let marker: CutoverMarker = serde_json::from_slice(&data)?;
                ensure!(marker.schema == SCHEMA && marker.mode == Mode::Sealed,
                    "invalid cutover marker");
                let sealed = self.read_sealed()?;
                ensure!(marker.generation == sealed.generation,
                    "cutover generation mismatch");
                open_synthetic(key, &sealed)
            }
        }
    }

    /// Does not assert secure deletion from flash media.
    pub fn retire_lab_plaintext<W: DataKeyWrapper>(&self, key: &W) -> Result<()> {
        ensure!(self.read_file(MARKER_NAME)?.is_some(), "cutover not committed");
        let _ = self.recover(key)?;
        let path = self.lab_path(LEGACY_NAME)?;
        let _ = self.read_file(LEGACY_NAME)?.context("legacy fixture missing")?;
        fs::remove_file(path)?;
        self.sync_dir()
    }

    pub fn cleanup(&self) -> Result<()> {
        self.check_root()?;
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct FakeWrapper;
    impl DataKeyWrapper for FakeWrapper {
        fn wrap_32(&self, k: &[u8;32], iv: &[u8;16]) -> Result<[u8;32]> {
            let mut v = *k;
            for (i, b) in v.iter_mut().enumerate() { *b ^= iv[i % 16] ^ 0x49; }
            Ok(v)
        }
        fn unwrap_32(&self, k: &[u8;32], iv: &[u8;16]) -> Result<[u8;32]> {
            self.wrap_32(k, iv)
        }
    }
    struct BadWrapper;
    impl DataKeyWrapper for BadWrapper {
        fn wrap_32(&self, _: &[u8;32], _: &[u8;16]) -> Result<[u8;32]> { bail!("wrong test key") }
        fn unwrap_32(&self, _: &[u8;32], _: &[u8;16]) -> Result<[u8;32]> { bail!("wrong test key") }
    }
    struct FixtureLab { lab: Sa15lLab }
    impl FixtureLab {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("{ROOT_PREFIX}{}", uuid::Uuid::new_v4()));
            let lab = Sa15lLab::new(&path).unwrap();
            lab.create().unwrap();
            Self { lab }
        }
    }
    impl Drop for FixtureLab { fn drop(&mut self) { let _ = self.lab.cleanup(); } }
    fn same(a: &DeviceIdentity, b: &DeviceIdentity) -> bool {
        serde_json::to_vec(a).unwrap() == serde_json::to_vec(b).unwrap()
    }
    fn staged() -> FixtureLab {
        let f = FixtureLab::new();
        f.lab.create_legacy(&synthetic_active()).unwrap();
        f.lab.stage_from_idle_legacy(&FakeWrapper).unwrap();
        f
    }
    #[test] fn full_record_roundtrip_and_metadata_is_not_plaintext() {
        let id = synthetic_active();
        let sealed = seal_synthetic(&FakeWrapper, &id, 1).unwrap();
        let bytes = serde_json::to_vec(&sealed).unwrap();
        for needle in [OLD, ORG, SITE, PROFILE, "device_secret"] {
            assert!(!String::from_utf8_lossy(&bytes).contains(needle));
        }
        assert!(same(&id, &open_synthetic(&FakeWrapper, &sealed).unwrap()));
    }
    #[test] fn generation_tampering_is_rejected() {
        let mut sealed = seal_synthetic(&FakeWrapper, &synthetic_active(), 1).unwrap();
        sealed.generation = 2;
        assert!(open_synthetic(&FakeWrapper, &sealed).is_err());
    }
    #[test] fn envelope_tampering_and_wrong_key_fail_closed() {
        let mut sealed = seal_synthetic(&FakeWrapper, &synthetic_active(), 1).unwrap();
        sealed.encrypted_identity.secret.ciphertext_and_tag[0] ^= 1;
        assert!(open_synthetic(&FakeWrapper, &sealed).is_err());
        let intact = seal_synthetic(&FakeWrapper, &synthetic_active(), 1).unwrap();
        assert!(open_synthetic(&BadWrapper, &intact).is_err());
    }
    #[test] fn wrong_scope_and_unexpected_fields_rejected() {
        let mut sealed = seal_synthetic(&FakeWrapper, &synthetic_active(), 1).unwrap();
        sealed.device_id = "other-device".into();
        assert!(open_synthetic(&FakeWrapper, &sealed).is_err());
        let json = serde_json::to_string(&seal_synthetic(&FakeWrapper, &synthetic_active(), 1).unwrap()).unwrap();
        assert!(serde_json::from_str::<SealedFullIdentity>(&json.replacen("{", "{\"device_secret\":\"bad\",", 1)).is_err());
    }
    #[test] fn pending_certificate_only_cannot_be_migrated() {
        let f = FixtureLab::new();
        let mut id = synthetic_active();
        id.pending_certificate_id = Some("cert-only".into());
        f.lab.create_legacy(&id).unwrap();
        assert!(f.lab.stage_from_idle_legacy(&FakeWrapper).is_err());
    }
    #[test] fn pending_certificate_and_command_cannot_be_migrated() {
        let f = FixtureLab::new();
        let mut id = synthetic_active();
        id.device_secret = NEW.into();
        id.pending_certificate_id = Some("cert-pending".into());
        id.pending_rotation_command_id = Some("cmd-pending".into());
        f.lab.create_legacy(&id).unwrap();
        assert!(f.lab.stage_from_idle_legacy(&FakeWrapper).is_err());
    }
    #[test] fn command_without_certificate_is_invalid() {
        let mut id = synthetic_active();
        id.pending_rotation_command_id = Some("orphan".into());
        assert!(seal_synthetic(&FakeWrapper, &id, 1).is_err());
    }
    #[test] fn before_cutover_marker_recovery_uses_legacy() {
        let f = staged();
        let id = f.lab.recover(&BadWrapper).unwrap(); // no sealed key required yet
        assert!(same(&synthetic_active(), &id));
    }
    #[test] fn after_marker_recovery_uses_sealed_and_plaintext_can_retire() {
        let f = staged();
        f.lab.cutover(&FakeWrapper).unwrap();
        f.lab.retire_lab_plaintext(&FakeWrapper).unwrap();
        assert!(f.lab.read_file(LEGACY_NAME).unwrap().is_none());
        assert!(same(&synthetic_active(), &f.lab.recover(&FakeWrapper).unwrap()));
    }
    #[test] fn corrupted_sealed_after_marker_never_falls_back_to_legacy() {
        let f = staged(); f.lab.cutover(&FakeWrapper).unwrap();
        fs::write(f.lab.lab_path(SEALED_NAME).unwrap(), b"{corrupt").unwrap();
        assert!(f.lab.read_file(LEGACY_NAME).unwrap().is_some());
        assert!(f.lab.recover(&FakeWrapper).is_err());
    }
    #[test] fn missing_sealed_after_marker_never_falls_back_to_legacy() {
        let f = staged(); f.lab.cutover(&FakeWrapper).unwrap();
        fs::remove_file(f.lab.lab_path(SEALED_NAME).unwrap()).unwrap();
        assert!(f.lab.recover(&FakeWrapper).is_err());
    }
    #[test] fn forged_marker_state_and_permissions_are_rejected() {
        let f = staged(); f.lab.cutover(&FakeWrapper).unwrap();
        let p = f.lab.lab_path(MARKER_NAME).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.lab.recover(&FakeWrapper).is_err());
    }
    #[test] fn symlinked_sealed_record_is_rejected() {
        let f = staged(); f.lab.cutover(&FakeWrapper).unwrap();
        let p = f.lab.lab_path(SEALED_NAME).unwrap();
        fs::remove_file(&p).unwrap();
        symlink(f.lab.lab_path(LEGACY_NAME).unwrap(), &p).unwrap();
        assert!(f.lab.recover(&FakeWrapper).is_err());
    }
    #[test] fn cannot_stage_twice_or_cutover_twice() {
        let f = staged();
        assert!(f.lab.stage_from_idle_legacy(&FakeWrapper).is_err());
        f.lab.cutover(&FakeWrapper).unwrap();
        assert!(f.lab.cutover(&FakeWrapper).is_err());
    }
    #[test] fn synthetic_pending_metadata_is_preserved_inside_aead() {
        let mut id = synthetic_active();
        id.device_secret = NEW.into();
        id.pending_certificate_id = Some("test-cert".into());
        // Legacy agent allows certificate-only pending rotation.
        let sealed = seal_synthetic(&FakeWrapper, &id, 2).unwrap();
        let recovered = open_synthetic(&FakeWrapper, &sealed).unwrap();
        assert!(same(&id, &recovered));
        assert!(!serde_json::to_string(&sealed).unwrap().contains("test-cert"));
    }
    #[test] fn live_paths_and_real_identity_are_refused() {
        assert!(Sa15lLab::new(Path::new("/var/lib/highline-nexus")).is_err());
        assert!(Sa15lLab::new(Path::new("/tmp/any-old-name")).is_err());
        let mut real = synthetic_active();
        real.device_id = "actual-controller-id".into();
        assert!(seal_synthetic(&FakeWrapper, &real, 1).is_err());
    }
}
