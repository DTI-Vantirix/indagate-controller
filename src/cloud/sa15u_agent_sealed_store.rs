//! SA-15U: isolated, agent-compatible sealed DeviceIdentity storage.
//!
//! This module uses the ACTUAL agent::DeviceIdentity struct rather than a
//! reduced test credential; it encrypts the complete record, including
//! organization/site/profile and pending rotation IDs, under authenticated
//! encryption.  Files can ONLY be created under an exclusive /tmp or /var/tmp
//! hlaxs-sa15u-lab-* directory. Live /var/lib/highline-nexus is inaccessible.
//!
//! No production cutover implementation, hardware root of trust or durable
//! power-loss quiescence is claimed. No runtime agent callsite uses this module.
//! The current agent remains on SA-15K legacy storage behind SA-15M guard.

use crate::cloud::agent::DeviceIdentity;
use crate::cloud::hybrid_secret_envelope::{
    DataKeyWrapper, HybridSecretEnvelope, open_development_hybrid, seal_development_hybrid,
};
use anyhow::{Context, Result, ensure, bail};
use serde::{Serialize, Deserialize};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const VERSION: u8 = 1;
const MAX_FILE: u64 = 64 * 1024;
const NAME: &str = "sealed-identity.json";
const KEY: &str = "hlaxs-sa15e-sa15u-full-identity";
const DISPOSABLE_DEVICE: &str = "e259087a-0647-41f4-82d7-6841513bc41c";
const DISPOSABLE_CONTROLLER: &str = "93be1d68-170a-4564-a9b7-6c71817a0e2d";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inner {
    generation: u64,
    identity: DeviceIdentity,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedAgentIdentity {
    schema: u8,
    controller_id: String,
    device_id: String,
    generation: u64,
    encrypted: HybridSecretEnvelope,
}

fn valid_disposable_scope(id: &DeviceIdentity) -> bool {
    (id.device_id.starts_with("hlaxs-sa15u-fixture-")
      && id.controller_id.starts_with("hlaxs-sa15u-fixture-"))
    || (id.device_id == DISPOSABLE_DEVICE && id.controller_id == DISPOSABLE_CONTROLLER)
}

fn validate_identity(identity: &DeviceIdentity) -> Result<()> {
    ensure!(valid_disposable_scope(identity), "SA-15U requires an allowed disposable test identity");
    for name in [&identity.device_id, &identity.controller_id, &identity.organization_id,
                 &identity.site_id, &identity.hardware_profile] {
        ensure!(!name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control),
            "invalid identity scope metadata");
    }
    ensure!(identity.device_secret.len() >= 32 && identity.device_secret.len() <= 256,
        "invalid disposable credential length");
    ensure!(!identity.device_secret.chars().any(char::is_control), "invalid credential text");
    ensure!(identity.pending_rotation_command_id.is_none() || identity.pending_certificate_id.is_some(),
        "orphan pending rotation command");
    for value in [identity.pending_certificate_id.as_deref(),
                  identity.pending_rotation_command_id.as_deref()].into_iter().flatten() {
        ensure!(!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
            "invalid pending rotation metadata");
    }
    Ok(())
}

fn validate_outer(record: &SealedAgentIdentity) -> Result<()> {
    ensure!(record.schema == VERSION && record.generation > 0,
        "unsupported sealed identity schema/generation");
    ensure!((record.device_id.starts_with("hlaxs-sa15u-fixture-")
             && record.controller_id.starts_with("hlaxs-sa15u-fixture-"))
           || (record.device_id == DISPOSABLE_DEVICE && record.controller_id == DISPOSABLE_CONTROLLER),
           "non-disposable sealed scope rejected");
    record.encrypted.validate_for(&record.controller_id, &record.device_id)
}

/// Encrypt the FULL agent identity including rotation metadata. No plaintext
/// metadata except controller/device binding and generation is serialized.
pub fn seal_development_agent_identity<W: DataKeyWrapper>(
    wrapper: &W, identity: &DeviceIdentity, generation: u64,
) -> Result<SealedAgentIdentity> {
    validate_identity(identity)?;
    ensure!(generation > 0, "invalid generation");
    let raw = serde_json::to_vec(&Inner { generation, identity: identity.clone() })?;
    ensure!(!raw.is_empty() && raw.len() as u64 <= MAX_FILE,
        "oversized encrypted identity input");
    let encrypted = seal_development_hybrid(wrapper, KEY, &identity.controller_id,
        &identity.device_id, &raw)?;
    let out = SealedAgentIdentity {
        schema: VERSION, controller_id: identity.controller_id.clone(),
        device_id: identity.device_id.clone(), generation, encrypted,
    };
    validate_outer(&out)?;
    Ok(out)
}

pub fn open_development_agent_identity<W: DataKeyWrapper>(
    wrapper: &W, record: &SealedAgentIdentity,
) -> Result<DeviceIdentity> {
    validate_outer(record)?;
    let raw = open_development_hybrid(wrapper, KEY, &record.controller_id,
        &record.device_id, &record.encrypted)?;
    ensure!(!raw.is_empty() && raw.len() as u64 <= MAX_FILE,
        "invalid decrypted identity size");
    let inner: Inner = serde_json::from_slice(&raw).context("decode authenticated agent identity")?;
    ensure!(inner.generation == record.generation
        && inner.identity.controller_id == record.controller_id
        && inner.identity.device_id == record.device_id,
        "authenticated identity scope/generation mismatch");
    validate_identity(&inner.identity)?;
    Ok(inner.identity)
}

/// Crash-consistent LAB storage of the full sealed identity. Must be used with
/// a stopped/quiesced writer; it is not an interprocess lock or anti-rollback.
/// Both the directory name and its location are strictly constrained.
pub struct Sa15uLabStore { root: PathBuf }
impl Sa15uLabStore {
    pub fn new(root: &Path) -> Result<Self> {
        ensure!(root.is_absolute(), "lab root must be absolute");
        let parent = root.parent().context("missing lab parent")?;
        ensure!(parent == Path::new("/tmp") || parent == Path::new("/var/tmp"),
            "SA-15U may only write directly below /tmp or /var/tmp");
        let name = root.file_name().and_then(OsStr::to_str).context("invalid lab directory")?;
        ensure!(name.starts_with("hlaxs-sa15u-lab-") && name.len() > 20 && name.len() < 120
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid SA-15U lab directory name");
        Ok(Self { root: root.to_path_buf() })
    }
    fn path(&self) -> PathBuf { self.root.join(NAME) }
    fn check_root(&self) -> Result<()> {
        let m = fs::symlink_metadata(&self.root).context("lab directory missing")?;
        ensure!(m.is_dir() && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
            "lab directory ownership/privacy invalid");
        Ok(())
    }
    fn check_record(m: &fs::Metadata) -> Result<()> {
        ensure!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0 && m.len() > 0 && m.len() <= MAX_FILE,
            "sealed record integrity/privacy check failed");
        Ok(())
    }
    pub fn create(&self) -> Result<()> {
        fs::create_dir(&self.root).context("exclusive SA-15U lab creation failed")?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        self.check_root()?;
        File::open(self.root.parent().context("lab parent")?)?.sync_all()?;
        Ok(())
    }
    pub fn load<W: DataKeyWrapper>(&self, wrapper: &W) -> Result<Option<(u64, DeviceIdentity)>> {
        self.check_root()?;
        let path = self.path();
        let before = match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("inspect encrypted record"),
            Ok(m) => m,
        };
        Self::check_record(&before)?;
        let mut f = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path).context("open encrypted record without following symlink")?;
        let opened = f.metadata()?;
        Self::check_record(&opened)?;
        ensure!(before.ino() == opened.ino() && before.dev() == opened.dev(),
            "sealed record replaced during open");
        let mut raw = Vec::new();
        f.take(MAX_FILE + 1).read_to_end(&mut raw)?;
        ensure!(!raw.is_empty() && raw.len() as u64 <= MAX_FILE, "invalid sealed record length");
        let record: SealedAgentIdentity = serde_json::from_slice(&raw)
            .context("malformed encrypted identity; NEVER fallback to plaintext")?;
        let identity = open_development_agent_identity(wrapper, &record)?;
        Ok(Some((record.generation, identity)))
    }
    /// Writes a strictly subsequent generation. `expected_previous` is the
    /// generation observed by the caller; fail closed on stale writers.
    /// A simulated crash immediately before rename leaves the old record.
    pub fn write<W: DataKeyWrapper>(
        &self, wrapper: &W, identity: &DeviceIdentity,
        expected_previous: u64, interrupt_before_rename: bool,
    ) -> Result<u64> {
        self.check_root()?;
        let previous = self.load(wrapper)?;
        let current = previous.as_ref().map(|(generation, _)| *generation).unwrap_or(0);
        ensure!(current == expected_previous && current < u64::MAX,
            "sealed generation conflict / stale writer");
        if let Some((_, old)) = previous {
            ensure!(old.controller_id == identity.controller_id && old.device_id == identity.device_id,
                "identity scope may not change during replacement");
        }
        let next = current + 1;
        let record = seal_development_agent_identity(wrapper, identity, next)?;
        let raw = serde_json::to_vec(&record)?;
        ensure!(raw.len() as u64 <= MAX_FILE, "serialized sealed record too large");
        let tmp = self.root.join(format!(".sa15u-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new().create_new(true).write(true).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&tmp).context("exclusive encrypted staging file")?;
            f.write_all(&raw)?;
            f.sync_all()?;
            drop(f);
            if interrupt_before_rename { bail!("SA-15U simulated crash before rename") }
            fs::rename(&tmp, self.path())?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(&tmp); }
        result?;
        Ok(next)
    }
    pub fn cleanup(&self) -> Result<()> {
        self.check_root()?;
        // Restrict cleanup to known SA-15U files, refuse arbitrary contents.
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let n = name.to_str().context("unexpected non-UTF8 lab entry")?;
            ensure!(n == NAME || (n.starts_with(".sa15u-") && n.ends_with(".tmp")),
                "unexpected file in SA-15U lab directory: refusing cleanup");
            let m = fs::symlink_metadata(entry.path())?;
            ensure!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1,
                "unexpected object type in lab directory");
            fs::remove_file(entry.path())?;
        }
        fs::remove_dir(&self.root)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct FakeWrapper;
    // Unit-test-only invertible wrapper; never used by runtime module.
    impl DataKeyWrapper for FakeWrapper {
        fn wrap_32(&self, dek: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut out = *dek;
            for (i,b) in out.iter_mut().enumerate() { *b ^= iv[i%16] ^ 0x95; }
            Ok(out)
        }
        fn unwrap_32(&self, data: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(data, iv)
        }
    }
    struct WrongWrapper;
    impl DataKeyWrapper for WrongWrapper {
        fn wrap_32(&self, dek: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut out = *dek;
            for (i,b) in out.iter_mut().enumerate() { *b ^= iv[i%16] ^ 0x05; }
            Ok(out)
        }
        fn unwrap_32(&self, data: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(data, iv)
        }
    }
    fn id() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "hlaxs-sa15u-fixture-device".into(),
            controller_id: "hlaxs-sa15u-fixture-controller".into(),
            organization_id: "hlaxs-sa15u-fixture-organization".into(),
            site_id: "hlaxs-sa15u-fixture-site".into(),
            device_secret: "HNXD_TEST_FIXTURE_SECRET_1234567890ABCDEF0123456789".into(),
            hardware_profile: "hlaxs-sa15u-fixture-hardware".into(),
            pending_certificate_id: None, pending_rotation_command_id: None,
        }
    }
    fn root() -> PathBuf {
        Path::new("/tmp").join(format!("hlaxs-sa15u-lab-{}", uuid::Uuid::new_v4()))
    }
    struct Lab { store: Sa15uLabStore }
    impl Lab {
        fn new() -> Self {
            let store = Sa15uLabStore::new(&root()).unwrap();
            store.create().unwrap();
            Self { store }
        }
    }
    impl Drop for Lab { fn drop(&mut self) { let _ = self.store.cleanup(); } }

    #[test] fn full_identity_roundtrip() {
        let s = seal_development_agent_identity(&FakeWrapper,&id(),1).unwrap();
        let out = open_development_agent_identity(&FakeWrapper,&s).unwrap();
        assert_eq!(serde_json::to_value(&out).unwrap(),serde_json::to_value(id()).unwrap());
    }
    #[test] fn seal_contains_no_plaintext_fields_or_secret() {
        let s=seal_development_agent_identity(&FakeWrapper,&id(),1).unwrap();
        let json=serde_json::to_string(&s).unwrap();
        let fixture = id();
        for secret in [&fixture.device_secret[..], "organization_id", "site_id", "hardware_profile", "pending_certificate_id"] {
            assert!(!json.contains(secret));
        }
    }
    #[test] fn scope_and_generation_tampering_rejected() {
        let s=seal_development_agent_identity(&FakeWrapper,&id(),1).unwrap();
        let mut other=s.clone();other.generation=3;
        assert!(open_development_agent_identity(&FakeWrapper,&other).is_err());
        let mut other=s;other.device_id="hlaxs-sa15u-fixture-evil".into();
        assert!(open_development_agent_identity(&FakeWrapper,&other).is_err());
    }
    #[test] fn wrong_wrapping_key_fails_closed() {
        let s=seal_development_agent_identity(&FakeWrapper,&id(),1).unwrap();
        assert!(open_development_agent_identity(&WrongWrapper,&s).is_err());
    }
    #[test] fn pending_certificate_only_roundtrip() {
        let mut d=id();d.pending_certificate_id=Some("cert-prepare".into());
        let s=seal_development_agent_identity(&FakeWrapper,&d,1).unwrap();
        let out=open_development_agent_identity(&FakeWrapper,&s).unwrap();
        assert_eq!(out.pending_certificate_id,d.pending_certificate_id);
        assert!(out.pending_rotation_command_id.is_none());
    }
    #[test] fn pending_certificate_and_command_roundtrip() {
        let mut d=id();d.pending_certificate_id=Some("cert-prepare".into());
        d.pending_rotation_command_id=Some("cmd-rotation".into());
        let out=open_development_agent_identity(&FakeWrapper,&
            seal_development_agent_identity(&FakeWrapper,&d,1).unwrap()).unwrap();
        assert_eq!(out.pending_rotation_command_id,d.pending_rotation_command_id);
    }
    #[test] fn orphan_command_rejected() {
        let mut d=id();d.pending_rotation_command_id=Some("bad".into());
        assert!(seal_development_agent_identity(&FakeWrapper,&d,1).is_err());
    }
    #[test] fn real_operational_scope_rejected() {
        let mut d=id();d.device_id="device-in-the-field".into();
        assert!(seal_development_agent_identity(&FakeWrapper,&d,1).is_err());
    }
    #[test] fn isolated_store_create_and_recover() {
        let l=Lab::new();
        assert!(l.store.load(&FakeWrapper).unwrap().is_none());
        assert_eq!(l.store.write(&FakeWrapper,&id(),0,false).unwrap(),1);
        let (g, recovered)=l.store.load(&FakeWrapper).unwrap().unwrap();
        assert_eq!(g,1);assert_eq!(recovered.device_secret,id().device_secret);
    }
    #[test] fn simulated_interruption_keeps_old_snapshot() {
        let l=Lab::new(); l.store.write(&FakeWrapper,&id(),0,false).unwrap();
        let mut next=id();next.device_secret="HNXD_TEST_REPLACEMENT_0123456789ABCDEFGHIJKLMNOP".into();
        assert!(l.store.write(&FakeWrapper,&next,1,true).is_err());
        let (g,old)=l.store.load(&FakeWrapper).unwrap().unwrap();
        assert_eq!(g,1);assert_eq!(old.device_secret,id().device_secret);
    }
    #[test] fn restart_recovery_and_monotonic_generation() {
        let l=Lab::new();l.store.write(&FakeWrapper,&id(),0,false).unwrap();
        let mut next=id();next.pending_certificate_id=Some("cert".into());
        l.store.write(&FakeWrapper,&next,1,false).unwrap();
        let reopened=Sa15uLabStore::new(&l.store.root).unwrap();
        let (g,after)=reopened.load(&FakeWrapper).unwrap().unwrap();
        assert_eq!(g,2);assert_eq!(after.pending_certificate_id,Some("cert".into()));
        assert!(reopened.write(&FakeWrapper,&id(),1,false).is_err());
    }
    #[test] fn reject_symlinked_and_group_readable_sealed_file() {
        let l=Lab::new(); l.store.write(&FakeWrapper,&id(),0,false).unwrap();
        let f=l.store.path();fs::set_permissions(&f, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(l.store.load(&FakeWrapper).is_err());
        // Restore before testing link replacement and clean-up.
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&f).unwrap();symlink("/dev/null",&f).unwrap();
        assert!(l.store.load(&FakeWrapper).is_err());
        fs::remove_file(f).unwrap();
    }
    #[test] fn malformed_sealed_json_never_falls_back() {
        let l=Lab::new();fs::write(l.store.path(),b"{broken").unwrap();
        fs::set_permissions(l.store.path(),fs::Permissions::from_mode(0o600)).unwrap();
        assert!(l.store.load(&FakeWrapper).is_err());
    }
    #[test] fn refuses_path_outside_lab_root() {
        assert!(Sa15uLabStore::new(Path::new("/var/lib/highline-nexus")).is_err());
        assert!(Sa15uLabStore::new(Path::new("/home/user/hlaxs-sa15u-lab-test")).is_err());
    }
}
