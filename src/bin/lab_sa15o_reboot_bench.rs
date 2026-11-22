//! SA-15O native ARM reboot-persistence test: synthetic-only staged encrypted snapshots.
//! Run subcommands in separate processes from the supplied runner.
//! Do NOT deploy as the live agent. No real credentials or production paths.
#[path = "../cloud/secret_envelope.rs"]
pub mod secret_envelope;
#[path = "../cloud/hybrid_secret_envelope.rs"]
pub mod hybrid_secret_envelope;
#[path = "../cloud/caam_afalg_wrapper.rs"]
pub mod caam_afalg_wrapper;
#[path = "../cloud/sa15h_staged_store.rs"]
pub mod sa15h_staged_store;
mod cloud {
    pub use crate::hybrid_secret_envelope;
    pub use crate::secret_envelope;
}

use anyhow::{Context, Result, ensure};
use caam_afalg_wrapper::CaamAfAlgDevelopmentWrapper;
use hybrid_secret_envelope::{open_development_hybrid, seal_development_hybrid};
use sa15h_staged_store::{Fault, StagedLabStore};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const LAB: &str = "/var/tmp/hlaxs-sa15h-lab-sa15o";
const BLOB_NAME: &str = "wrapped-key.bb";
const CAAM_DIR: &str = "/data/caam";
const KEYGEN: &str = "/usr/bin/caam-keygen";
const CTRL: &str = "hlaxs_sa15o_test_controller";
const OBJECT: &str = "hlaxs_sa15o_test_identity";
const WRAP_ID: &str = "hlaxs-sa15e-sa15o-lab-key";
const OLD_SECRET: &[u8] = b"HLAXS_SA15O_SYNTHETIC_ORIGINAL_ONLY";
const NEW_SECRET: &[u8] = b"HLAXS_SA15O_SYNTHETIC_REPLACEMENT_ONLY";

struct DeleteOnDrop(Vec<PathBuf>);
impl Drop for DeleteOnDrop {
    fn drop(&mut self) { for p in &self.0 { let _ = fs::remove_file(p); } }
}
fn key_name(kind: &str) -> Result<String> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(format!("hlaxs-sa15f-h-{kind}-{}-{stamp}", std::process::id()))
}
fn run_keygen(args: &[&str]) -> Result<()> {
    let out = Command::new(KEYGEN).args(args).output().context("execute CAAM keygen")?;
    ensure!(out.status.success() && !String::from_utf8_lossy(&out.stderr).contains("Failed")
        && !String::from_utf8_lossy(&out.stdout).contains("Failed"), "CAAM key operation failed");
    Ok(())
}
fn check_file(path: &Path, length: u64) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1,
        "unsafe test artifact");
    ensure!(m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "unsafe test artifact permissions");
    ensure!(m.len() == length, "wrong CAAM artifact size");
    Ok(())
}
fn store() -> Result<StagedLabStore> { StagedLabStore::new(Path::new(LAB)) }
fn blob_path() -> PathBuf { Path::new(LAB).join(BLOB_NAME) }
fn write_blob(from: &Path) -> Result<()> {
    check_file(from, 112)?;
    let dest = blob_path();
    let mut input = File::open(from)?;
    let mut output = OpenOptions::new().create_new(true).write(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(&dest)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    check_file(&dest, 112)?;
    File::open(LAB)?.sync_all()?;
    Ok(())
}
fn with_imported_key<T>(f: impl FnOnce(&CaamAfAlgDevelopmentWrapper) -> Result<T>) -> Result<T> {
    let blob = blob_path(); check_file(&blob, 112)?;
    let restored_name = key_name("restore")?;
    let restored_path = Path::new(CAAM_DIR).join(&restored_name);
    ensure!(!restored_path.exists(), "restored CAAM key already exists");
    let _cleanup = DeleteOnDrop(vec![restored_path.clone()]);
    run_keygen(&["import", blob.to_str().context("non-UTF8 test blob")?, &restored_name])?;
    check_file(&restored_path, 64)?;
    let key = CaamAfAlgDevelopmentWrapper::from_test_key_file(&restored_path)?;
    f(&key)
}
fn init() -> Result<()> {
    let st = store()?;
    st.create().context("lab already exists; inspect before retry; runner cleanup is isolated")?;
    let base = key_name("init")?;
    let black = Path::new(CAAM_DIR).join(&base);
    let blob = Path::new(CAAM_DIR).join(format!("{base}.bb"));
    ensure!(!black.exists() && !blob.exists(), "CAAM key filename collision");
    let _cleanup = DeleteOnDrop(vec![black.clone(), blob.clone()]);
    run_keygen(&["create", &base, "ccm", "-s", "32"])?;
    check_file(&black, 64)?;
    write_blob(&blob)?;
    let key = CaamAfAlgDevelopmentWrapper::from_test_key_file(&black)?;
    let e = seal_development_hybrid(&key, WRAP_ID, CTRL, OBJECT, OLD_SECRET)?;
    let record = sa15h_staged_store::IdentitySnapshot::initial(CTRL, OBJECT, e)?;
    st.write(&record, Fault::None)?;
    let serialized = fs::read(st.root().join("snapshot.json"))?;
    for secret in [OLD_SECRET, NEW_SECRET] {
        ensure!(!serialized.windows(secret.len()).any(|w| w == secret), "plaintext leaked into snapshot");
    }
    println!("INITIAL ATOMIC ENCRYPTED SNAPSHOT: PASS");
    Ok(())
}
fn recover() -> Result<()> {
    let record = store()?.load()?;
    ensure!(record.controller_id == CTRL && record.object_id == OBJECT, "wrong recovery scope");
    let expected = if record.pending.is_some() || record.generation == 2 { NEW_SECRET } else { OLD_SECRET };
    with_imported_key(|key| {
        let recovered = open_development_hybrid(key, WRAP_ID, CTRL, OBJECT, record.recovery_credential()?)?;
        ensure!(recovered == expected, "synthetic credential did not match expected state");
        Ok(())
    })?;
    println!("NATIVE CAAM SEPARATE-PROCESS RECOVERY: PASS (generation={}, pending={})",
        record.generation, record.pending.is_some());
    Ok(())
}
fn stage(fault: Fault) -> Result<()> {
    let st = store()?;
    let old = st.load()?;
    ensure!(old.generation == 1 && old.pending.is_none(), "unexpected snapshot state before staging");
    let prepared = with_imported_key(|key| {
        let replacement = seal_development_hybrid(key, WRAP_ID, CTRL, OBJECT, NEW_SECRET)?;
        old.stage("hlaxs_sa15h_test_cert", "hlaxs_sa15h_test_command", replacement)
    })?;
    if fault == Fault::BeforeRename {
        ensure!(st.write(&prepared, fault).is_err(), "expected injected fault");
        let visible = st.load()?;
        ensure!(visible.pending.is_none() && visible.generation == 1,
            "interrupted staging unexpectedly changed committed snapshot");
        println!("SIMULATED STAGING CRASH BEFORE RENAME: PASS (old snapshot retained)");
        Ok(())
    } else {
        st.write(&prepared, fault)?;
        println!("DURABLY STAGED REPLACEMENT ENVELOPE: PASS");
        Ok(())
    }
}
fn finalize() -> Result<()> {
    let st = store()?;
    let staged = st.load()?;
    ensure!(staged.pending.is_some(), "expected pending rotation");
    // Lab only: real cloud integration MUST commit and acknowledge with
    // authenticated server responses before finalizing/revoking old secret.
    st.write(&staged.finalize()?, Fault::None)?;
    println!("ATOMIC FINALIZED SYNTHETIC SNAPSHOT: PASS");
    Ok(())
}
fn cleanup() -> Result<()> { store()?.cleanup()?; println!("ISOLATED SA-15H LAB CLEANUP: PASS"); Ok(()) }
fn go() -> Result<()> {
    ensure!(std::env::consts::ARCH == "aarch64" && unsafe { libc::geteuid() } == 0,
        "test only on ARM64 controller as root");
    ensure!(Path::new("/dev/caam-keygen").exists(), "CAAM interface missing");
    let action = std::env::args().nth(1).context("use init|recover|stage-fault|stage|finalize|cleanup")?;
    match action.as_str() {
        "init" => init(),
        "recover" => recover(),
        "stage-fault" => stage(Fault::BeforeRename),
        "stage" => stage(Fault::None),
        "finalize" => finalize(),
        "cleanup" => cleanup(),
        _ => anyhow::bail!("unsupported SA-15H lab action"),
    }
}
fn main() {
    if let Err(e) = go() { eprintln!("SA-15O ERROR: {e:#}"); std::process::exit(1); }
}
