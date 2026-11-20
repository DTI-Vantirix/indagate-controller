//! SA-15T: Native CAAM-backed real Supabase authentication with a disposable SA-15S identity.
//! STRICT TEST ONLY. Cannot read /var/lib/highline-nexus; no relay or live service interaction.
//! Deliberately does NOT rotate credentials, claim commands, or modify controller cloud state.
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

use anyhow::{Context, Result, bail, ensure};
use caam_afalg_wrapper::CaamAfAlgDevelopmentWrapper;
use hybrid_secret_envelope::{open_development_hybrid, seal_development_hybrid};
use sa15h_staged_store::{Fault, IdentitySnapshot, StagedLabStore};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LAB: &str = "/var/tmp/hlaxs-sa15h-lab-sa15t-cloud";
const KEYGEN: &str = "/usr/bin/caam-keygen";
const CAAM_DIR: &str = "/data/caam";
const BLOB_NAME: &str = "wrapped-key.bb";
const CONTROLLER: &str = "93be1d68-170a-4564-a9b7-6c71817a0e2d";
const DEVICE: &str = "e259087a-0647-41f4-82d7-6841513bc41c";
const WRAP_ID: &str = "hlaxs-sa15e-sa15t-cloud-bench";
/// The server to call, from `INDAGATE_SERVER_URL`. There is no built-in address.
fn endpoint() -> String {
    let base = std::env::var("INDAGATE_SERVER_URL").expect("set INDAGATE_SERVER_URL to the server address");
    format!("{}/v1/credential/rotate/commit", base.trim_end_matches('/'))
}
const WRONG_CERTIFICATE: &str = "00000000-0000-4000-8000-000000000000";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DisposableCredential {
    controller_id: String,
    device_id: String,
    certificate_id: String,
    device_secret: String,
}
impl DisposableCredential {
    fn validate(&self) -> Result<()> {
        ensure!(self.controller_id == CONTROLLER && self.device_id == DEVICE,
            "refusing non-SA-15S-disposable controller identity");
        ensure!(uuid::Uuid::parse_str(&self.certificate_id).is_ok(), "invalid SA-15S certificate ID");
        ensure!(self.certificate_id != WRONG_CERTIFICATE, "invalid SA-15S certificate ID");
        ensure!(self.device_secret.starts_with("HNXD_") && self.device_secret.len() == 69
            && self.device_secret.as_bytes()[5..].iter().all(u8::is_ascii_hexdigit),
            "invalid disposable credential format");
        Ok(())
    }
}

struct DeleteOnDrop(Vec<PathBuf>);
impl Drop for DeleteOnDrop {
    fn drop(&mut self) {
        for p in &self.0 {
            if p.exists() && fs::remove_file(p).is_err() {
                eprintln!("WARNING: failed cleaning an ephemeral SA-15T CAAM key file");
            }
        }
    }
}
fn key_name(purpose: &str) -> Result<String> {
    Ok(format!("hlaxs-sa15f-h-sa15t-{purpose}-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()))
}
fn keygen(args: &[&str]) -> Result<()> {
    let out = Command::new(KEYGEN).args(args).output().context("invoke CAAM utility")?;
    ensure!(out.status.success() && !String::from_utf8_lossy(&out.stdout).contains("Failed")
        && !String::from_utf8_lossy(&out.stderr).contains("Failed"), "CAAM key operation failed");
    Ok(())
}
fn check_private(path: &Path, size: u64) -> Result<()> {
    let m = fs::symlink_metadata(path).context("inspect CAAM artifact")?;
    ensure!(m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1,
        "unexpected CAAM artifact file type");
    ensure!(m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "CAAM artifact not private");
    ensure!(m.len() == size, "unexpected CAAM artifact size");
    Ok(())
}
fn store() -> Result<StagedLabStore> { StagedLabStore::new(Path::new(LAB)) }
fn blob_path() -> PathBuf { Path::new(LAB).join(BLOB_NAME) }
fn persist_wrapped_blob(from: &Path) -> Result<()> {
    check_private(from, 112)?;
    let mut input = File::open(from)?;
    let mut output = OpenOptions::new().create_new(true).write(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(blob_path())?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    check_private(&blob_path(), 112)?;
    File::open(LAB)?.sync_all()?;
    Ok(())
}
fn with_imported_key<T>(op: impl FnOnce(&CaamAfAlgDevelopmentWrapper) -> Result<T>) -> Result<T> {
    let blob = blob_path(); check_private(&blob, 112)?;
    let name = key_name("restore")?;
    let black = Path::new(CAAM_DIR).join(&name);
    ensure!(!black.exists(), "collision with imported test key");
    let _cleanup = DeleteOnDrop(vec![black.clone()]);
    keygen(&["import", blob.to_str().context("invalid blob path")?, &name])?;
    check_private(&black, 64)?;
    let wrapper = CaamAfAlgDevelopmentWrapper::from_test_key_file(&black)?;
    op(&wrapper)
}
fn provision() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin().take(16 * 1024 + 1).read_to_end(&mut input)?;
    ensure!(!input.is_empty() && input.len() <= 16 * 1024, "invalid credential stream size");
    let credential: DisposableCredential = serde_json::from_slice(&input)
        .context("decode credential stream (content not displayed)")?;
    credential.validate()?;
    // The lab directory is exclusive and cannot refer to the live identity path.
    let st = store()?;
    st.create().context("SA-15T lab already exists; inspect or cleanup before retry")?;
    let name = key_name("create")?;
    let black = Path::new(CAAM_DIR).join(&name);
    let blob = Path::new(CAAM_DIR).join(format!("{name}.bb"));
    ensure!(!black.exists() && !blob.exists(), "collision with disposable CAAM key");
    let _cleanup = DeleteOnDrop(vec![black.clone(), blob.clone()]);
    keygen(&["create", &name, "ccm", "-s", "32"])?;
    check_private(&black, 64)?;
    persist_wrapped_blob(&blob)?;
    let wrapper = CaamAfAlgDevelopmentWrapper::from_test_key_file(&black)?;
    let sealed = seal_development_hybrid(&wrapper, WRAP_ID, CONTROLLER, DEVICE,
        &serde_json::to_vec(&credential)?)?;
    st.write(&IdentitySnapshot::initial(CONTROLLER, DEVICE, sealed)?, Fault::None)?;
    let serialized = fs::read(st.root().join("snapshot.json"))?;
    ensure!(!serialized.windows(credential.device_secret.len()).any(|w| w == credential.device_secret.as_bytes()),
        "DISPOSABLE SECRET LEAKED INTO ENCRYPTED RECORD");
    println!("SA-15T CAAM ENCRYPTED DISPOSABLE IDENTITY: PASS");
    Ok(())
}
fn load_decrypted() -> Result<DisposableCredential> {
    let record = store()?.load()?;
    ensure!(record.controller_id == CONTROLLER && record.object_id == DEVICE && record.pending.is_none(),
        "unexpected SA-15T lab identity state");
    with_imported_key(|wrapper| {
        let bytes = open_development_hybrid(wrapper, WRAP_ID, CONTROLLER, DEVICE,
            record.recovery_credential()?)?;
        let credential: DisposableCredential = serde_json::from_slice(&bytes)?;
        credential.validate()?;
        Ok(credential)
    })
}
async fn check_cloud() -> Result<()> {
    let credential = load_decrypted()?;
    println!("SA-15T SEPARATE-PROCESS CAAM DECRYPTION: PASS");
    let client = reqwest::Client::builder().timeout(Duration::from_secs(25)).build()?;
    // An intentionally wrong certificate ID proves device authentication without
    // preparing/committing a rotation, claiming commands, or retrieving site data.
    let body = serde_json::json!({"certificate_id": WRONG_CERTIFICATE});
    let result = client.post(endpoint())
        .header("x-nexus-device-id", DEVICE)
        .header("x-nexus-device-secret", &credential.device_secret)
        .json(&body).send().await.context("HTTPS test with CAAM-unsealed disposable credential")?;
    ensure!(result.status().as_u16() == 409,
        "real cloud authentication did not return expected non-mutating 409 (HTTP {})", result.status());
    println!("SA-15T NATIVE RUST REAL CLOUD AUTHENTICATION: PASS (HTTP 409 wrong certificate)");
    let mut bogus = credential.device_secret.clone();
    bogus.replace_range(5..6, if &bogus[5..6] == "0" {"1"} else {"0"});
    let rejected = client.post(endpoint())
        .header("x-nexus-device-id", DEVICE)
        .header("x-nexus-device-secret", bogus)
        .json(&body).send().await.context("HTTPS negative authentication test")?;
    ensure!(rejected.status().as_u16() == 401,
        "wrong credential was not rejected (HTTP {})", rejected.status());
    println!("SA-15T WRONG CREDENTIAL REJECTED: PASS (HTTP 401)");
    println!("=== SA-15T RESULT: PASS — NATIVE CAAM SEALED CREDENTIAL + REAL MAIN CLOUD ===");
    Ok(())
}
fn cleanup() -> Result<()> {
    store()?.cleanup()?;
    println!("SA-15T PRIVATE TEST STORE CLEANUP: PASS");
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("SA-15T ERROR: {e:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    ensure!(std::env::consts::ARCH == "aarch64" && unsafe { libc::geteuid() } == 0,
        "SA-15T requires root on the SightPas ARM64 bench");
    ensure!(Path::new("/dev/caam-keygen").exists(), "CAAM unavailable");
    let action = std::env::args().nth(1).context("expected provision|verify|cleanup")?;
    match action.as_str() {
        "provision" => provision(),
        "verify" => check_cloud().await,
        "cleanup" => cleanup(),
        _ => bail!("invalid lab action"),
    }
}
