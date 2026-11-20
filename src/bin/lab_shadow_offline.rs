//! Indagate Access v6: standalone local shadow-store acceptance utility.
//! NEVER invokes the controller's main(), agent(), hardware drivers or cloud ACK.
//! Only invoked explicitly from a WSL developer shell, not the SP4.

#[path = "../cloud/config_shadow.rs"]
mod config_shadow;

use anyhow::{Context, Result, bail, ensure};
use config_shadow::{ShadowState, ShadowStore};
use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const EXPECTED_VERSION: u64 = 6;
const PROFILE: &str = "HNX-HW-SP-ACP4WR6-R1";
const EXPECTED_HASH: &str = "3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e";
const MAX_INPUT: u64 = 2 * 1024 * 1024 + 1;

fn verify_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "refuse relative SQLite database paths");
    ensure!(path.file_name().is_some_and(|n| n == "snapshot.sqlite"), "refuse non-test database filename");
    let parent = path.parent().context("missing database parent")?;
    ensure!(parent.exists(), "temporary test directory does not exist");
    let canonical_parent = parent.canonicalize().context("invalid test directory")?;
    let temp_dir = env::temp_dir().canonicalize().context("invalid system temp directory")?;
    ensure!(canonical_parent.starts_with(&temp_dir), "refuse database outside temporary directory");
    ensure!(canonical_parent.file_name().is_some_and(|n| n.to_string_lossy().starts_with("hlaxs-shadow-v6-")),
        "refuse directory without a test-only prefix");
    Ok(())
}

fn inspect(store: &ShadowStore, expected_state: ShadowState) -> Result<()> {
    let recovered = store.recover()?;
    ensure!(recovered.len() == 1, "expected exactly one shadow-only snapshot");
    let item = &recovered[0];
    ensure!(item.version == EXPECTED_VERSION && item.checksum == EXPECTED_HASH,
        "unexpected configuration version or hash in shadow database");
    ensure!(item.state == expected_state, "unexpected simulated state");
    println!("PASS: local SQLite re-open verified v{} shadow state {:?} (NOT physically applied)", item.version, item.state);
    Ok(())
}

fn main() -> Result<()> {
    ensure!(env::var("HLAXS_SHADOW_OFFLINE_ONLY").as_deref() == Ok("YES"),
        "explicit local-only safety guard missing");
    let args: Vec<String> = env::args().collect();
    ensure!(args.len() == 3, "usage: hlaxs-shadow-offline <stage|recover-staged|simulate-fail|recover-failed|simulate-success|recover-success|reject-corruption> /tmp/hlaxs-shadow-v6-*/snapshot.sqlite");
    let mode = args[1].as_str();
    let path = PathBuf::from(&args[2]);
    verify_path(&path)?;
    let mut db = ShadowStore::open(&path)?;
    match mode {
        "stage" => {
            let mut raw = Vec::new();
            io::stdin().take(MAX_INPUT).read_to_end(&mut raw).context("read JSON from standard input")?;
            ensure!(raw.len() <= 2 * 1024 * 1024, "oversized JSON response");
            let staged = db.stage_response(&raw, EXPECTED_VERSION, PROFILE)?;
            ensure!(staged.checksum == EXPECTED_HASH && staged.state == ShadowState::Staged,
                "staged snapshot did not match expected SP4 v6 data");
            println!("PASS: real v6 snapshot staged into test-only SQLite; no cloud ACK or hardware apply");
        }
        "recover-staged" => inspect(&db, ShadowState::Staged)?,
        "simulate-fail" => {
            let result = db.simulate_apply(EXPECTED_VERSION, true)?;
            ensure!(result.state == ShadowState::SimulatedFailed, "failure simulation not recorded");
            println!("PASS: simulated failure recorded locally; no cloud ACK");
        }
        "recover-failed" => inspect(&db, ShadowState::SimulatedFailed)?,
        "simulate-success" => {
            let result = db.simulate_apply(EXPECTED_VERSION, false)?;
            ensure!(result.state == ShadowState::SimulatedApplied, "success simulation not recorded");
            println!("PASS: simulated success recorded locally; no cloud ACK or real application");
        }
        "recover-success" => inspect(&db, ShadowState::SimulatedApplied)?,
        "reject-corruption" => {
            match db.recover() {
                Err(_) => println!("PASS: corrupted test-only SQLite snapshot correctly rejected"),
                Ok(_) => bail!("FAIL: corrupt shadow snapshot was accepted"),
            }
        }
        _ => bail!("unsupported local-only operation"),
    }
    Ok(())
}
