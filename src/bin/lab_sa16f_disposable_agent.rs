//! SA-16F: separate one-shot disposable cloud check-in process on SightPas.
//! Uses the installed SA-16E explicit runtime AND SA-16B phase engine to recover
//! the actual DeviceIdentity field layout (checked against agent source by builder).
//! Does NOT start the operational cloud agent or run any door/relay code.
//! Does NOT poll or claim commands, rotate credentials, or contact live identity paths.
//! The only successful cloud mutation is /v1/checkin for the fixed disposable
//! SA-15S controller. Not a production cutover, rollback proof, or power-loss test.

#[path = "../cloud/secret_envelope.rs"] pub mod secret_envelope;
#[path = "../cloud/hybrid_secret_envelope.rs"] pub mod hybrid_secret_envelope;
#[path = "../cloud/caam_afalg_wrapper.rs"] pub mod caam_afalg_wrapper;
mod cloud {
    pub use crate::secret_envelope;
    pub use crate::hybrid_secret_envelope;
    pub use crate::caam_afalg_wrapper;
    pub use crate::sa15u_agent_sealed_store;
    pub use crate::sa15y_runtime_backend;
    pub use crate::sa15z_caam_runtime;
    pub use crate::sa16a_identity_lifecycle;
    pub use crate::sa16b_phase_store;
    pub use crate::sa15m_live_identity_gate;
    pub use crate::sa16e_explicit_runtime;
    // Standalone bench has no operational legacy identity I/O. Compile-time
    // adapter blocks any attempt to reach live identity through the fixture.
    pub mod sa15v_identity_router {
        use crate::cloud::agent::DeviceIdentity;
        use anyhow::{Result,bail};
        use std::path::Path;
        pub fn load_legacy(_: &Path) -> Result<Option<DeviceIdentity>> { bail!("SA-16F: legacy disabled") }
        pub fn save_legacy(_: &Path, _: &DeviceIdentity) -> Result<()> { bail!("SA-16F: legacy disabled") }
    }
    pub mod agent {
        use serde::{Deserialize,Serialize};
        #[derive(Clone,Serialize,Deserialize)]
        pub struct DeviceIdentity {
            pub device_id:String,
            pub controller_id:String,
            pub organization_id:String,
            pub site_id:String,
            pub device_secret:String,
            pub hardware_profile:String,
            #[serde(default)] pub pending_certificate_id:Option<String>,
            #[serde(default)] pub pending_rotation_command_id:Option<String>,
        }
    }
}
#[path = "../cloud/sa15m_live_identity_gate.rs"] pub mod sa15m_live_identity_gate;
#[path = "../cloud/sa15u_agent_sealed_store.rs"] pub mod sa15u_agent_sealed_store;
#[path = "../cloud/sa15y_runtime_backend.rs"] pub mod sa15y_runtime_backend;
#[path = "../cloud/sa15z_caam_runtime.rs"] pub mod sa15z_caam_runtime;
#[path = "../cloud/sa16a_identity_lifecycle.rs"] pub mod sa16a_identity_lifecycle;
#[path = "../cloud/sa16b_phase_store.rs"] pub mod sa16b_phase_store;
#[path = "../cloud/sa16e_explicit_runtime.rs"] pub mod sa16e_explicit_runtime;

use anyhow::{bail,ensure,Context,Result};
use caam_afalg_wrapper::CaamAfAlgDevelopmentWrapper;
use cloud::agent::DeviceIdentity;
use sa15u_agent_sealed_store::Sa15uLabStore;
use sa16e_explicit_runtime::IdentityRuntime;
use serde::Deserialize;
use std::fs::{self,File,OpenOptions};
use std::io::{Read,Write};
use std::os::unix::fs::{MetadataExt,OpenOptionsExt};
use std::path::{Path,PathBuf};
use std::process::Command;
use std::time::{Duration,SystemTime,UNIX_EPOCH};

const LAB: &str = "/var/tmp/hlaxs-sa15u-lab-sa16f-disposable-agent";
const BLOB: &str = "wrapped-key.bb";
const KEYGEN: &str = "/usr/bin/caam-keygen";
const CAAM_DIR: &str = "/data/caam";
const CONTROLLER: &str = "93be1d68-170a-4564-a9b7-6c71817a0e2d";
const DEVICE: &str = "e259087a-0647-41f4-82d7-6841513bc41c";
const ORG: &str = "811b47e7-a529-4c2e-9f6b-4e0939825517";
const SITE: &str = "1b6b02c7-fb83-44f0-8f43-d71f1caa8c68";
/// The server to call, from `INDAGATE_SERVER_URL`. There is no built-in address.
fn checkin_url() -> String {
    let base = std::env::var("INDAGATE_SERVER_URL").expect("set INDAGATE_SERVER_URL to the server address");
    format!("{}/v1/checkin", base.trim_end_matches('/'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisposableCredential { controller_id:String,device_id:String,certificate_id:String,device_secret:String }
impl DisposableCredential {
    fn validate(&self)->Result<()> {
        ensure!(self.controller_id==CONTROLLER && self.device_id==DEVICE,"invalid disposable identity binding");
        uuid::Uuid::parse_str(&self.certificate_id).context("invalid active certificate ID")?;
        ensure!(self.device_secret.starts_with("HNXD_") && self.device_secret.len()==69
            && self.device_secret.as_bytes()[5..].iter().all(u8::is_ascii_hexdigit),
            "invalid disposable credential format");
        Ok(())
    }
}
struct DeleteOnDrop(Vec<PathBuf>);
impl Drop for DeleteOnDrop { fn drop(&mut self){ for p in &self.0 {
    if let Err(e)=fs::remove_file(p) { if e.kind()!=std::io::ErrorKind::NotFound { eprintln!("SA-16F CAAM ephemeral key cleanup error"); } }
} } }
fn key_name(phase:&str)->Result<String> {
    let n=SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let name=format!("hlaxs-sa15f-h-sa16f-{phase}-{}-{n}",std::process::id());
    ensure!(name.len()<100,"CAAM temporary name too long");
    Ok(name)
}
fn caam(args:&[&str])->Result<()> {
    let output=Command::new(KEYGEN).args(args).output().context("run CAAM keygen")?;
    ensure!(output.status.success() && !String::from_utf8_lossy(&output.stdout).contains("Failed")
        && !String::from_utf8_lossy(&output.stderr).contains("Failed"),"CAAM key operation unsuccessful");
    Ok(())
}
fn private_file(path:&Path,expected:u64)->Result<()> {
    let m=fs::symlink_metadata(path).context("inspect disposable CAAM artifact")?;
    ensure!(m.is_file() && !m.file_type().is_symlink() && m.nlink()==1
        && m.uid()==unsafe{libc::geteuid()} && m.mode()&0o077==0 && m.len()==expected,
        "CAAM artifact not a private regular file of expected size");
    Ok(())
}
fn lab()->Result<Sa15uLabStore>{Sa15uLabStore::new(Path::new(LAB))}
fn provision()->Result<()> {
    let mut raw=Vec::new();
    std::io::stdin().take(16*1024+1).read_to_end(&mut raw)?;
    ensure!(!raw.is_empty() && raw.len()<=16*1024,"invalid private credential stream size");
    let credential:DisposableCredential=serde_json::from_slice(&raw).context("invalid private credential stream")?;
    credential.validate()?;
    let store=lab()?;
    store.create().context("SA-16F lab exists: do not overwrite; inspect or use --cleanup")?;
    let name=key_name("new")?;
    let black=Path::new(CAAM_DIR).join(&name);
    let bb=Path::new(CAAM_DIR).join(format!("{name}.bb"));
    ensure!(!black.exists() && !bb.exists(),"CAAM key name collision");
    let _on_drop=DeleteOnDrop(vec![black.clone(),bb.clone()]);
    caam(&["create",&name,"ccm","-s","32"])?;
    private_file(&black,64)?;private_file(&bb,112)?;
    let mut source=File::open(&bb)?;
    let output_path=Path::new(LAB).join(BLOB);
    let mut output=OpenOptions::new().create_new(true).write(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&output_path)?;
    std::io::copy(&mut source,&mut output)?;output.sync_all()?;drop(output);
    private_file(&output_path,112)?;
    File::open(LAB)?.sync_all()?;
    let _wrapper=CaamAfAlgDevelopmentWrapper::from_test_key_file(&black)?;
    let record=DeviceIdentity{
        device_id:credential.device_id,controller_id:credential.controller_id,
        organization_id:ORG.into(),site_id:SITE.into(),device_secret:credential.device_secret,
        hardware_profile:"hlaxs-sa16f-disposable-only".into(),
        pending_certificate_id:None,pending_rotation_command_id:None,
    };
    let runtime=IdentityRuntime::disposable_caam(Path::new(LAB))?;
    ensure!(runtime.enroll(&record)?==1,"unexpected generation on disposable enrollment");
    let encrypted=fs::read(Path::new(LAB).join("sealed-identity.json"))?;
    ensure!(!encrypted.windows(record.device_secret.len())
        .any(|w|w==record.device_secret.as_bytes()),"plaintext secret in encrypted artifact");
    println!("SA-16F ENROLL VIA ACTUAL SA-16E DISPOSABLE RUNTIME: PASS (generation=1)");
    Ok(())
}
async fn checkin()->Result<()> {
    let runtime=IdentityRuntime::disposable_caam(Path::new(LAB))?;
    let (generation,identity)=runtime.recover()?.context("disposable identity missing")?;
    ensure!(generation==1 && identity.device_id==DEVICE && identity.controller_id==CONTROLLER
        && identity.organization_id==ORG && identity.site_id==SITE
        && identity.pending_certificate_id.is_none() && identity.pending_rotation_command_id.is_none(),
        "disposable startup identity/phase mismatch");
    println!("SA-16F SEPARATE-PROCESS SEALED STARTUP RECOVERY: PASS (generation={generation})");
    let client=reqwest::Client::builder().timeout(Duration::from_secs(25)).build()?;
    let request=serde_json::json!({
        "software":{"agent_version":"hlaxs-sa16f-disposable-0.1"},
        "runtime":{"uptime_seconds":0},
        "configuration":{"applied_version":0},
        "network":{"primary":"sa16f-disposable"},
        "health":{"sa16f_disposable_agent":true,"sealed_identity_generation":generation},
    });
    let resp=client.post(checkin_url()).header("x-nexus-device-id",DEVICE)
        .header("x-nexus-device-secret",&identity.device_secret)
        .json(&request).send().await.context("real cloud disposable check-in request")?;
    let status=resp.status();
    // Do not print the body on failures: it may change or contain unwanted data.
    ensure!(status.as_u16()==200,"disposable cloud check-in failed (HTTP {})",status);
    let body:serde_json::Value=resp.json().await.context("parse check-in response")?;
    ensure!(body.get("success").and_then(|x|x.as_bool())==Some(true)
        && body.pointer("/data/applied_config_version").is_some(),
        "cloud check-in did not return expected success envelope");
    println!("SA-16F NATIVE DISPOSABLE CLOUD CHECK-IN: PASS (HTTP 200)");
    Ok(())
}
fn cleanup()->Result<()> {
    let root=Path::new(LAB);
    let store=lab()?;
    // Never recurse /var/tmp or touch unrelated paths. Unexpected files stop cleanup.
    let expected=["wrapped-key.bb","sealed-identity.json"];
    for entry in fs::read_dir(root)? {
        let e=entry?;
        let name=e.file_name();
        let s=name.to_str().context("non-UTF8 file in disposable directory")?;
        ensure!(expected.contains(&s)|| (s.starts_with(".sa15u-")&&s.ends_with(".tmp")),
            "unexpected lab artifact; refusing cleanup");
    }
    private_file(&root.join(BLOB),112)?;
    fs::remove_file(root.join(BLOB))?;
    store.cleanup()?;
    println!("SA-16F PRIVATE LAB CLEANUP: PASS");
    Ok(())
}
#[tokio::main]
async fn main(){
    if let Err(e)=run().await {eprintln!("SA-16F ERROR: {e:#}");std::process::exit(1);}
}
async fn run()->Result<()> {
    ensure!(std::env::consts::ARCH=="aarch64" && unsafe{libc::geteuid()}==0,
        "SA-16F requires root on the isolated SightPas ARM64 bench");
    ensure!(Path::new("/dev/caam-keygen").exists(),"CAAM not present");
    match std::env::args().nth(1).as_deref() {
        Some("provision")=>provision(),
        Some("checkin")=>checkin().await,
        Some("cleanup")=>cleanup(),
        _=>bail!("usage: disposable agent provision|checkin|cleanup"),
    }
}
