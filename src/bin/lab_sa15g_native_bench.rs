//! SA-15G: synthetic, isolated native Rust test of existing SA-15C/E/F modules.
//! NOT the live cloud agent. No credential, relay, network, boot or fuse writes.
//! Target: aarch64 Linux SightPas controller with CAAM and tk(cbc(aes)).

// Reuse the actual modules from the controller project without adding a lib
// crate or changing the live application's module tree.
#[path = "../cloud/secret_envelope.rs"]
pub mod secret_envelope;
#[path = "../cloud/hybrid_secret_envelope.rs"]
pub mod hybrid_secret_envelope;
#[path = "../cloud/caam_afalg_wrapper.rs"]
pub mod caam_afalg_wrapper;

// Satisfy their existing crate::cloud::... imports from this isolated binary.
mod cloud {
    pub use crate::hybrid_secret_envelope;
    pub use crate::secret_envelope;
}

use anyhow::{Context, Result, ensure};
use caam_afalg_wrapper::CaamAfAlgDevelopmentWrapper;
use hybrid_secret_envelope::{
    open_development_hybrid, seal_development_hybrid, HybridSecretEnvelope,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const KEY_DIR: &str = "/data/caam";
const KEYGEN: &str = "/usr/bin/caam-keygen";
const CONTROLLER: &str = "hlaxs_sa15g_test_controller";
const OBJECT: &str = "hlaxs_sa15g_test_object";
const WRAPPING_ID: &str = "hlaxs-sa15e-native-test";

struct Cleanup {
    paths: Vec<PathBuf>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        // Only unique, previously collision-checked disposable names.
        let mut failed = false;
        for path in &self.paths {
            if path.exists() {
                if fs::remove_file(path).is_err() { failed = true; }
            }
        }
        if failed {
            eprintln!("WARNING: disposable test-key cleanup incomplete; inspect /data/caam for hlaxs-sa15f-g- prefixed files");
        } else {
            println!("DISPOSABLE CAAM FILE CLEANUP: COMPLETE");
        }
    }
}

fn verify_caam_output(path: &Path, len: u64) -> Result<()> {
    let meta = fs::symlink_metadata(path).context("inspect CAAM test output")?;
    ensure!(meta.is_file() && !meta.file_type().is_symlink(), "CAAM artifact is not a file");
    ensure!(meta.uid() == 0 && meta.permissions().mode() & 0o077 == 0,
        "CAAM artifact owner/permissions invalid");
    ensure!(meta.len() == len, "CAAM artifact length invalid");
    Ok(())
}

fn run_keygen(args: &[&str]) -> Result<()> {
    let out = Command::new(KEYGEN).args(args).output().context("execute CAAM key utility")?;
    // Observed this utility can exit 0 even after an output file creation error;
    // caller also MUST inspect output artifacts.
    ensure!(out.status.success(), "CAAM keygen returned failure");
    ensure!(out.stderr.is_empty() || !String::from_utf8_lossy(&out.stderr).contains("Failed"),
        "CAAM keygen reported failure on stderr");
    ensure!(out.stdout.is_empty() || !String::from_utf8_lossy(&out.stdout).contains("Failed"),
        "CAAM keygen reported failure on stdout");
    Ok(())
}

fn test() -> Result<()> {
    println!("=== HLAXS SA-15G NATIVE RUST CAAM BENCH ===");
    println!("SCOPE: disposable synthetic credential; NO live cloud identity or controller-service changes");
    ensure!(std::env::consts::ARCH == "aarch64", "native bench must run on ARM64 controller");
    ensure!(unsafe { libc::geteuid() } == 0, "root required for isolated CAAM bench");
    ensure!(Path::new("/dev/caam-keygen").exists() && Path::new(KEYGEN).is_file(),
        "CAAM tooling unavailable");
    let dir = fs::symlink_metadata(KEY_DIR).context("inspect CAAM directory")?;
    ensure!(dir.is_dir() && !dir.file_type().is_symlink() && dir.uid() == 0
        && dir.permissions().mode() & 0o022 == 0, "unsafe CAAM key directory");

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    // Prefix deliberately matches the SA-15F key-file adapter's whitelist.
    let base = format!("hlaxs-sa15f-g-{}-{}", std::process::id(), stamp);
    let restored = format!("{base}-restored");
    let key_path = Path::new(KEY_DIR).join(&base);
    let blob_path = Path::new(KEY_DIR).join(format!("{base}.bb"));
    let restored_path = Path::new(KEY_DIR).join(&restored);
    for p in [&key_path, &blob_path, &restored_path] {
        ensure!(!p.exists() && fs::symlink_metadata(p).is_err(), "test key name collision");
    }
    let _cleanup = Cleanup { paths: vec![key_path.clone(), blob_path.clone(), restored_path.clone()] };

    run_keygen(&["create", &base, "ccm", "-s", "32"])?;
    verify_caam_output(&key_path, 64)?;
    verify_caam_output(&blob_path, 112)?;
    println!("CAAM CREATE + BLOB: PASS");

    let provider = CaamAfAlgDevelopmentWrapper::from_test_key_file(&key_path)?;
    let mut suffix = [0u8; 32];
    SystemRandom::new().fill(&mut suffix)
        .map_err(|_| anyhow::anyhow!("synthetic randomness unavailable"))?;
    let mut synthetic = b"HLAXS_SA15G_SYNTHETIC_".to_vec();
    synthetic.extend_from_slice(&suffix);

    let envelope = seal_development_hybrid(
        &provider, WRAPPING_ID, CONTROLLER, OBJECT, &synthetic,
    )?;
    ensure!(open_development_hybrid(&provider, WRAPPING_ID, CONTROLLER, OBJECT, &envelope)?
        == synthetic, "native Rust CAAM wrap/open mismatch");
    println!("NATIVE RUST CAAM WRAP + AES-GCM OPEN: PASS");

    let mut tampered: HybridSecretEnvelope = envelope.clone();
    tampered.wrapped_dek[0] ^= 1;
    ensure!(open_development_hybrid(&provider, WRAPPING_ID, CONTROLLER, OBJECT, &tampered)
        .is_err(), "tampered wrapped key accepted");
    let mut tampered = envelope.clone();
    tampered.secret.ciphertext_and_tag[0] ^= 1;
    ensure!(open_development_hybrid(&provider, WRAPPING_ID, CONTROLLER, OBJECT, &tampered)
        .is_err(), "tampered ciphertext accepted");
    ensure!(open_development_hybrid(&provider, WRAPPING_ID, "hlaxs_sa15g_wrong", OBJECT, &envelope)
        .is_err(), "wrong controller accepted");
    println!("NATIVE RUST TAMPER + BINDING REJECTION: PASS");

    let json = serde_json::to_vec(&envelope)?;
    ensure!(!json.windows(b"HLAXS_SA15G_SYNTHETIC_".len()).any(|w| w == b"HLAXS_SA15G_SYNTHETIC_"),
        "plaintext appeared in serialized envelope");
    println!("SERIALIZED ENVELOPE CONTAINS NO SYNTHETIC PLAINTEXT: PASS");

    // Drop the original black-key file and reconstruct from blob using the
    // same CAAM interface used by SA-14C/SA-15F hardware benches.
    drop(provider);
    fs::remove_file(&key_path)?;
    run_keygen(&["import", blob_path.to_str().context("non-UTF8 blob path")?, &restored])?;
    verify_caam_output(&restored_path, 64)?;
    let imported = CaamAfAlgDevelopmentWrapper::from_test_key_file(&restored_path)?;
    ensure!(open_development_hybrid(&imported, WRAPPING_ID, CONTROLLER, OBJECT, &envelope)?
        == synthetic, "blob imported key cannot authenticate credential");
    println!("NATIVE RUST RESTORED BLACK-KEY OPEN: PASS");

    suffix.fill(0);
    synthetic.fill(0);
    println!("SA-15G RESULT: PASS — native Rust CAAM + authenticated envelope in this boot");
    println!("LIMIT: HAB is open; production device binding, reboot and power-loss recovery unverified");
    Ok(())
}

fn main() {
    if let Err(e) = test() {
        eprintln!("SA-15G RESULT: FAIL — {e:#}");
        std::process::exit(1);
    }
}
