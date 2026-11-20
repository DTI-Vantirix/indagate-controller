//! SA-15W: ARM64 CAAM bench exercising the *actual SA-15U module* in isolated lab storage.
//!
//! This stand-alone binary includes the exact SA-15U source and a serialization-
//! compatible, build-checked DeviceIdentity fixture type. It is NOT the cloud agent.
//! It has no cloud API client, relay controls or production storage write path.
#[path = "../cloud/secret_envelope.rs"]
pub mod secret_envelope;
#[path = "../cloud/hybrid_secret_envelope.rs"]
pub mod hybrid_secret_envelope;
#[path = "../cloud/caam_afalg_wrapper.rs"]
pub mod caam_afalg_wrapper;

// The main agent is a binary-only module and cannot be pulled into a standalone
// native utility without starting all of its runtime dependencies. The CI/build
// script compares this fixture's fields against the agent's real definition.
mod cloud {
    pub use crate::hybrid_secret_envelope;
    pub use crate::secret_envelope;
    pub mod agent {
        use serde::{Deserialize, Serialize};
        #[derive(Clone, Serialize, Deserialize)]
        pub struct DeviceIdentity {
            pub device_id: String,
            pub controller_id: String,
            pub organization_id: String,
            pub site_id: String,
            pub device_secret: String,
            pub hardware_profile: String,
            #[serde(default)]
            pub pending_certificate_id: Option<String>,
            #[serde(default)]
            pub pending_rotation_command_id: Option<String>,
        }
    }
}
#[path = "../cloud/sa15u_agent_sealed_store.rs"]
pub mod sa15u_agent_sealed_store;

use anyhow::{Context, Result, bail, ensure};
use caam_afalg_wrapper::CaamAfAlgDevelopmentWrapper;
use cloud::agent::DeviceIdentity;
use sa15u_agent_sealed_store::{Sa15uLabStore, SealedAgentIdentity, open_development_agent_identity};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const LAB: &str = "/var/tmp/hlaxs-sa15u-lab-sa15w-full-identity";
const BLOB: &str = "wrapped-key.bb";
const CAAM_DIR: &str = "/data/caam";
const KEYGEN: &str = "/usr/bin/caam-keygen";
const DEVICE: &str = "hlaxs-sa15u-fixture-device-sa15w";
const CONTROLLER: &str = "hlaxs-sa15u-fixture-controller-sa15w";
const ORG: &str = "hlaxs-sa15w-synthetic-organization";
const SITE: &str = "hlaxs-sa15w-synthetic-site";
const HW: &str = "hlaxs-sa15w-synthetic-hardware-profile";
const CERT: &str = "hlaxs-sa15w-synthetic-pending-certificate";
const COMMAND: &str = "hlaxs-sa15w-synthetic-rotation-command";

fn old_secret() -> String { format!("HNXD_{}", "11".repeat(32)) }
fn new_secret() -> String { format!("HNXD_{}", "22".repeat(32)) }
fn fixture(pending: bool, new: bool) -> DeviceIdentity {
    DeviceIdentity {
        device_id: DEVICE.to_string(),
        controller_id: CONTROLLER.to_string(),
        organization_id: ORG.to_string(),
        site_id: SITE.to_string(),
        device_secret: if new { new_secret() } else { old_secret() },
        hardware_profile: HW.to_string(),
        pending_certificate_id: if pending { Some(CERT.to_string()) } else { None },
        pending_rotation_command_id: if pending { Some(COMMAND.to_string()) } else { None },
    }
}
fn matches(expected: &DeviceIdentity, actual: &DeviceIdentity) -> Result<()> {
    ensure!(serde_json::to_value(expected)? == serde_json::to_value(actual)?,
        "authenticated full DeviceIdentity fields do not match the expected fixture");
    Ok(())
}
fn store() -> Result<Sa15uLabStore> { Sa15uLabStore::new(Path::new(LAB)) }
fn blob_path() -> PathBuf { Path::new(LAB).join(BLOB) }
struct RemoveOnDrop(Vec<PathBuf>);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        for path in &self.0 {
            if let Err(e) = fs::remove_file(path) {
                eprintln!("SA-15W CAAM temporary key removal: {}", e);
            }
        }
    }
}
fn key_name(phase: &str) -> Result<String> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let name = format!("hlaxs-sa15f-h-sa15w-{phase}-{}-{stamp}", std::process::id());
    ensure!(name.len() < 100, "CAAM test key name too long");
    Ok(name)
}
fn keygen(args: &[&str]) -> Result<()> {
    let output = Command::new(KEYGEN).args(args).output().context("execute CAAM key utility")?;
    ensure!(output.status.success()
        && !String::from_utf8_lossy(&output.stdout).contains("Failed")
        && !String::from_utf8_lossy(&output.stderr).contains("Failed"),
        "CAAM key utility failed (output withheld to avoid exposing key materials)");
    Ok(())
}
fn private_file(p: &Path, length: u64) -> Result<()> {
    let m = fs::symlink_metadata(p).context("inspect CAAM test file")?;
    ensure!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1
        && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0
        && m.len() == length, "CAAM test file permissions/type/size invalid");
    Ok(())
}
fn copy_blob(source: &Path) -> Result<()> {
    private_file(source, 112)?;
    let mut infile = File::open(source)?;
    let mut outfile = OpenOptions::new().create_new(true).write(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(blob_path())?;
    std::io::copy(&mut infile, &mut outfile)?;
    outfile.sync_all()?;
    private_file(&blob_path(), 112)?;
    File::open(LAB)?.sync_all()?;
    Ok(())
}
fn with_key<T>(action: impl FnOnce(&CaamAfAlgDevelopmentWrapper) -> Result<T>) -> Result<T> {
    let blob = blob_path(); private_file(&blob,112)?;
    let name = key_name("import")?;
    let black = Path::new(CAAM_DIR).join(&name);
    ensure!(!black.exists(), "CAAM key collision");
    let _cleanup = RemoveOnDrop(vec![black.clone()]);
    keygen(&["import", blob.to_str().context("invalid path")?, &name])?;
    private_file(&black,64)?;
    action(&CaamAfAlgDevelopmentWrapper::from_test_key_file(&black)?)
}
fn init() -> Result<()> {
    let st=store()?;
    st.create().context("SA-15W lab already present; use --cleanup only after inspection")?;
    let name=key_name("create")?;
    let black=Path::new(CAAM_DIR).join(&name);
    let wrapped=Path::new(CAAM_DIR).join(format!("{name}.bb"));
    ensure!(!black.exists() && !wrapped.exists(), "CAAM temp filename collision");
    let _cleanup=RemoveOnDrop(vec![black.clone(),wrapped.clone()]);
    keygen(&["create",&name,"ccm","-s","32"])?;
    private_file(&black,64)?;
    copy_blob(&wrapped)?;
    let wrapper=CaamAfAlgDevelopmentWrapper::from_test_key_file(&black)?;
    ensure!(st.write(&wrapper,&fixture(false,false),0,false)? == 1,
        "unexpected initial generation");
    let raw=fs::read(Path::new(LAB).join("sealed-identity.json"))?;
    for sensitive in [old_secret(), new_secret(), ORG.into(), SITE.into(), HW.into(),
                      "pending_certificate_id".into(), "device_secret".into()] {
        ensure!(!raw.windows(sensitive.len()).any(|w| w==sensitive.as_bytes()),
            "plaintext full-identity data present in sealed artifact");
    }
    println!("SA-15W CAAM FULL DEVICEIDENTITY SEAL: PASS (generation=1)");
    Ok(())
}
fn recover(expected_generation:u64, pending:bool, new:bool) -> Result<()> {
    with_key(|key| {
        let (generation,found)=store()?.load(key)?.context("sealed identity missing")?;
        ensure!(generation==expected_generation,"unexpected sealed generation");
        matches(&fixture(pending,new),&found)?;
        Ok(())
    })?;
    println!("SA-15W SEPARATE-PROCESS CAAM FULL IDENTITY RECOVERY: PASS (generation={expected_generation}, pending={pending})");
    Ok(())
}
fn interrupted_prepare() -> Result<()> {
    with_key(|key| {
        let st=store()?;
        let (generation,current)=st.load(key)?.context("initial identity missing")?;
        ensure!(generation==1,"unexpected initial generation");
        matches(&fixture(false,false),&current)?;
        ensure!(st.write(key,&fixture(true,true),1,true).is_err(),
            "simulated power interruption unexpectedly committed write");
        let (after,unchanged)=st.load(key)?.context("identity lost after interrupted write")?;
        ensure!(after==1,"interrupted write changed generation");
        matches(&fixture(false,false),&unchanged)?;
        Ok(())
    })?;
    println!("SA-15W INTERRUPTED ROTATION WRITE: PASS (original identity retained)");
    Ok(())
}
fn prepare() -> Result<()> {
    with_key(|key| {
        let st=store()?;
        let (generation,old)=st.load(key)?.context("initial identity missing")?;
        ensure!(generation==1,"wrong phase for prepare");
        matches(&fixture(false,false),&old)?;
        ensure!(st.write(key,&fixture(true,true),1,false)?==2,"pending generation not persisted");
        Ok(())
    })?;
    println!("SA-15W ENCRYPTED PENDING ROTATION PERSISTED: PASS (generation=2)");
    Ok(())
}
fn tamper_checks() -> Result<()> {
    with_key(|key| {
        let st=store()?;
        let (generation,original)=st.load(key)?.context("pending identity missing")?;
        ensure!(generation==2,"tamper test requires pending stage");
        matches(&fixture(true,true),&original)?;
        let raw=fs::read(Path::new(LAB).join("sealed-identity.json"))?;
        ensure!(raw.len() <= 65536,"oversized sealed record");
        let record:SealedAgentIdentity=serde_json::from_slice(&raw)?;
        let mut tampered=serde_json::to_value(&record)?;
        tampered["generation"]=serde_json::json!(generation+1);
        let malformed:SealedAgentIdentity=serde_json::from_value(tampered)?;
        ensure!(open_development_agent_identity(key,&malformed).is_err(),
            "generation tampering was not rejected");
        let mut wrong_scope=serde_json::to_value(&record)?;
        wrong_scope["device_id"]=serde_json::json!("hlaxs-sa15u-fixture-device-other");
        let changed:SealedAgentIdentity=serde_json::from_value(wrong_scope)?;
        ensure!(open_development_agent_identity(key,&changed).is_err(),
            "identity scope tampering was not rejected");
        Ok(())
    })?;
    println!("SA-15W NATIVE AUTHENTICATED GENERATION/SCOPE REJECTION: PASS");
    Ok(())
}
fn finalize() -> Result<()> {
    // SYNTHETIC ONLY. Never call a live cloud commit/ack here.
    with_key(|key| {
        let st=store()?;
        let (generation,pending)=st.load(key)?.context("pending identity missing")?;
        ensure!(generation==2,"finalization requires generation 2");
        matches(&fixture(true,true),&pending)?;
        ensure!(st.write(key,&fixture(false,true),2,false)?==3,"finalization not persisted");
        // Repeat with stale generation; must not replace the sealed record.
        ensure!(st.write(key,&fixture(false,false),1,false).is_err(),
            "stale writer unexpectedly succeeded");
        Ok(())
    })?;
    println!("SA-15W SYNTHETIC ROTATION FINALIZATION + STALE WRITE REJECTION: PASS (generation=3)");
    Ok(())
}
fn cleanup() -> Result<()> {
    let blob=blob_path();
    private_file(&blob,112)?;
    fs::remove_file(&blob).context("remove fixed SA-15W lab wrapped key")?;
    File::open(LAB)?.sync_all()?;
    store()?.cleanup()?;
    println!("SA-15W ISOLATED LAB CLEANUP: PASS");
    Ok(())
}
fn run() -> Result<()> {
    ensure!(std::env::consts::ARCH=="aarch64" && unsafe {libc::geteuid()}==0,
        "SA-15W requires root on the disposable ARM64 hardware test");
    ensure!(Path::new("/dev/caam-keygen").exists(),"CAAM device unavailable");
    let command=std::env::args().nth(1).context("required SA-15W phase")?;
    match command.as_str() {
        "init"=>init(),
        "recover-initial"=>recover(1,false,false),
        "interrupt-before-rename"=>interrupted_prepare(),
        "prepare"=>prepare(),
        "recover-pending"=>recover(2,true,true),
        "tamper"=>tamper_checks(),
        "finalize"=>finalize(),
        "recover-final"=>recover(3,false,true),
        "cleanup"=>cleanup(),
        _=>bail!("unknown SA-15W phase"),
    }
}
fn main() {
    if let Err(e)=run() {eprintln!("SA-15W ERROR: {e:#}");std::process::exit(1)}
}
