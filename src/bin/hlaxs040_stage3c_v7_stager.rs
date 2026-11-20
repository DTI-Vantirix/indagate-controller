//! HLAXS.Access 0.4 Stage 3C: isolated, non-actuating Rust v7 staging.
//! Authenticated config GET -> validate -> independent durable SQLite snapshot.
//! There is no config ACK, control write, systemd mutation or relay API here.
#![allow(dead_code)]

#[path = "../cloud/config_shadow.rs"]
mod config_shadow;

use anyhow::{Context, Result, anyhow, ensure};
use config_shadow::{ShadowState, ShadowStore};
use ring::digest::{Context as DigestContext, SHA256};
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const CONTROLLER: &str = "2722691f-f4db-4f42-b63d-dac94b06ec9e";
const ORG: &str = "48409aab-ec9b-4faf-9eb2-204611d09d8b";
const SITE: &str = "a96cb5a6-75f2-4f07-8232-7c405257cfbd";
const PROFILE: &str = "HNX-HW-SP-ACP4WR6-R1";
const BIN_SHA: &str = "c657b7df809da483a1b88812d6f19e974576fc185c6d72be388debb31595430f";
const CONFIG_SHA: &str = "7a89bb687b6eaa823c5d69c45b32529c4991d8e3e561cff6572d1a80e95320f6";
const ENDPOINT: &str = "https://gxwfuurzkdhxwxdbtdmt.supabase.co/functions/v1/nexus-device/v1/config";
const IDENTITY: &str = "/var/lib/highline-nexus/device.json";
const UNIT: &str = "highline-nexus-controller.service";
const STAGE_ROOT: &str = "/var/lib/hlaxs/access-stage3c-bench";
const STAGE_DB: &str = "/var/lib/hlaxs/access-stage3c-bench/v7-shadow.sqlite";
const TEST_HOLDER: &str = "Nexus Test Credential";
const LEVEL: &str = "2fb75404-53b2-4d89-9d14-4733f90105fd";
const SCHEDULE: &str = "15009b2d-1b2a-44fb-8bb6-7f79be6d16cd";
const EXPECTED_CREDENTIALS: [(&str, u64, u64); 2] = [
    ("af809ce6-4d03-42c8-8392-bf98112280fe", 5, 22271),
    ("d6727897-eb21-47b6-bbda-da4a963b57de", 95, 10773),
];

struct Identity { device_id: String, device_secret: String }

fn command(name: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(name).args(args).output().with_context(|| format!("cannot run {name}"))?;
    ensure!(out.status.success(), "device_preflight_command_failed");
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn digest_reader(mut f: File) -> Result<String> {
    let mut ctx = DigestContext::new(&SHA256);
    let mut buf = [0u8; 32768];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

fn private_identity() -> Result<Identity> {
    ensure!(unsafe { libc::geteuid() } == 0, "root_required");
    let mut f = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(IDENTITY)?;
    let meta = f.metadata()?;
    ensure!(meta.is_file() && meta.uid() == 0 && (meta.permissions().mode() & 0o077) == 0
        && meta.len() > 0 && meta.len() <= 4096, "unsafe_device_identity");
    let mut raw = Vec::new();
    f.take(4097).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 4096, "oversized_device_identity");
    let value: Value = serde_json::from_slice(&raw)?;
    ensure!(value.get("controller_id").and_then(Value::as_str) == Some(CONTROLLER) &&
        value.get("organization_id").and_then(Value::as_str) == Some(ORG) &&
        value.get("site_id").and_then(Value::as_str) == Some(SITE), "device_identity_wrong_scope");
    let device_id = value.get("device_id").and_then(Value::as_str)
        .ok_or_else(|| anyhow!("device_id_missing"))?;
    let device_secret = value.get("device_secret").and_then(Value::as_str)
        .ok_or_else(|| anyhow!("device_secret_missing"))?;
    ensure!(device_id.len() == 36 && device_id.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-'),
        "device_id_invalid");
    ensure!((16..=2048).contains(&device_secret.len()), "device_secret_invalid");
    ensure!(value.get("pending_certificate_id").is_none_or(Value::is_null) &&
        value.get("pending_rotation_command_id").is_none_or(Value::is_null), "identity_rotation_pending");
    Ok(Identity { device_id: device_id.to_owned(), device_secret: device_secret.to_owned() })
}

fn runtime_preflight() -> Result<()> {
    ensure!(command("systemctl", &["is-active", UNIT])? == "active", "controller_inactive");
    let pid: u32 = command("systemctl", &["show", "-p", "MainPID", "--value", UNIT])?
        .parse().context("invalid_controller_pid")?;
    ensure!(pid > 1, "invalid_controller_pid");
    let binary = digest_reader(File::open(format!("/proc/{pid}/exe"))?)?;
    ensure!(binary == BIN_SHA, "controller_binary_changed");
    let env = fs::read(format!("/proc/{pid}/environ"))?;
    let vars: Vec<&[u8]> = env.split(|b| *b == 0).collect();
    for required in [b"HLAXS_WIEGAND_EDGE_DIAGNOSTIC=1".as_slice(),
        b"HLAXS_V23_CAPTURE_UPLOAD=1".as_slice(),
        b"HLAXS040_UNIFIED_SHADOW=1".as_slice()]
    { ensure!(vars.iter().any(|value| *value == required), "strict_shadow_gate_missing"); }
    ensure!(!vars.iter().any(|value| *value == b"HLAXS040_OFFLINE_CACHE_ONLY=1".as_slice()),
        "offline_simulation_unexpected");
    println!("RUNNING_STAGE3B=VERIFIED_NONACTUATING");
    println!("RUNNING_SHA256={BIN_SHA}");
    Ok(())
}

fn require_private_storage() -> Result<()> {
    // Trust the existing /var/lib/hlaxs owner, never a symlink or writable parent.
    let ancestor = fs::symlink_metadata("/var/lib/hlaxs")?;
    ensure!(ancestor.file_type().is_dir() && ancestor.uid() == 0 &&
        ancestor.mode() & 0o022 == 0, "untrusted_shadow_storage_ancestor");
    match fs::symlink_metadata(STAGE_ROOT) {
        Ok(meta) => ensure!(meta.file_type().is_dir() && meta.uid() == 0 &&
            meta.mode() & 0o077 == 0, "untrusted_shadow_stage_directory"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(STAGE_ROOT)?;
        }
        Err(e) => return Err(e.into()),
    }
    match fs::symlink_metadata(STAGE_DB) {
        Ok(meta) => ensure!(meta.file_type().is_file() && meta.uid() == 0 &&
            meta.mode() & 0o077 == 0, "untrusted_shadow_database"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn a<'a>(obj: &'a Value, key: &str, n: usize) -> Result<&'a Vec<Value>> {
    let list = obj.get(key).and_then(Value::as_array).ok_or_else(|| anyhow!("missing_list_{key}"))?;
    ensure!(list.len() == n, "unexpected_list_size_{key}");
    Ok(list)
}

fn validate_candidate(data: &Value) -> Result<()> {
    ensure!(data.get("version").and_then(Value::as_u64) == Some(7), "not_desired_v7");
    ensure!(data.get("checksum").and_then(Value::as_str) == Some(CONFIG_SHA), "v7_checksum_changed");
    ensure!(data.get("hardware_profile").and_then(Value::as_str) == Some(PROFILE), "hardware_profile_mismatch");
    let cfg = data.get("configuration").ok_or_else(|| anyhow!("missing_config"))?;
    ensure!(cfg.get("controller").and_then(|x| x.get("id")).and_then(Value::as_str) == Some(CONTROLLER),
        "configuration_controller_mismatch");
    let creds = a(cfg, "credentials", 2)?;
    let present: HashSet<_> = creds.iter().map(|c| (
        c.get("id").and_then(Value::as_str),
        c.get("facility_code").and_then(Value::as_u64),
        c.get("card_code").and_then(Value::as_u64),
    )).collect();
    let wanted: HashSet<_> = EXPECTED_CREDENTIALS.iter().map(|(id,fc,card)|
        (Some(*id),Some(*fc),Some(*card))).collect();
    ensure!(present == wanted && creds.iter().all(|c|
        c.get("enabled").and_then(Value::as_bool) == Some(true) &&
        c.get("valid_from").is_none_or(Value::is_null) &&
        c.get("valid_until").is_none_or(Value::is_null) &&
        c.get("holder_name").and_then(Value::as_str) == Some(TEST_HOLDER)), "unexpected_credential_bindings");
    let doors=a(cfg,"doors",4)?;
    let door_channels: HashSet<_> = doors.iter().filter(|d|
        d.get("enabled").and_then(Value::as_bool) == Some(true))
        .filter_map(|d|d.get("channel").and_then(Value::as_u64)).collect();
    ensure!(door_channels == HashSet::from([0,1,2,3]), "unexpected_door_channels");
    let readers=a(cfg,"readers",4)?;
    let reader_numbers: HashSet<_> = readers.iter().filter(|r|
        r.get("protocol").and_then(Value::as_str) == Some("wiegand"))
        .filter_map(|r|r.get("reader_number").and_then(Value::as_u64)).collect();
    ensure!(reader_numbers == HashSet::from([1,2,3,4]), "unexpected_reader_mapping");
    let levels=a(cfg,"access_levels",1)?;
    ensure!(levels[0].get("id").and_then(Value::as_str) == Some(LEVEL) &&
        levels[0].get("enabled").and_then(Value::as_bool)==Some(true), "unexpected_access_level");
    let links=a(cfg,"credential_access_levels",2)?;
    let seen: HashSet<_> = links.iter().map(|v| (
        v.get("credential_id").and_then(Value::as_str),
        v.get("access_level_id").and_then(Value::as_str))).collect();
    ensure!(seen.len()==2 && EXPECTED_CREDENTIALS.iter().all(|(id,_,_)|
        seen.contains(&(Some(*id),Some(LEVEL)))), "unexpected_credential_access_links");
    let door_links=a(cfg,"access_level_doors",4)?;
    let door_rules: HashSet<_> = door_links.iter().map(|l| (
        l.get("access_level_id").and_then(Value::as_str),
        l.get("channel").and_then(Value::as_u64),
        l.get("schedule_id").and_then(Value::as_str))).collect();
    let expected_rules: HashSet<_> = (0..4).map(|c| (Some(LEVEL),Some(c),Some(SCHEDULE))).collect();
    ensure!(door_rules == expected_rules, "unexpected_access_door_links");
    let schedules=a(cfg,"schedules",1)?;
    ensure!(schedules[0].get("id").and_then(Value::as_str)==Some(SCHEDULE) &&
        schedules[0].get("definition") == Some(&serde_json::json!({"always":true})),
        "unexpected_access_schedule");
    // Additional signing/attestation is needed before mapping can be trusted for unlock.
    Ok(())
}

async fn fetch_config(identity: &Identity) -> Result<Value> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
    let mut res = client.get(ENDPOINT)
        .header("x-nexus-device-id", identity.device_id.as_str())
        .header("x-nexus-device-secret", identity.device_secret.as_str())
        .header("accept","application/json")
        .send().await?;
    ensure!(res.status().as_u16()==200, "authenticated_config_http_rejected");
    if let Some(n)=res.content_length(){ensure!(n<=350000,"cloud_config_oversize");}
    let mut b=Vec::new();
    while let Some(chunk)=res.chunk().await? {
        ensure!(b.len()+chunk.len()<=350000,"cloud_config_oversize");
        b.extend_from_slice(&chunk);
    }
    let value:Value=serde_json::from_slice(&b)?;
    ensure!(value.get("success").and_then(Value::as_bool)==Some(true),"cloud_response_not_successful");
    let data=value.get("data").ok_or_else(||anyhow!("cloud_config_data_missing"))?;
    validate_candidate(data)?;
    Ok(data.clone())
}

fn stage(data: &Value) -> Result<()> {
    require_private_storage()?;
    let raw=serde_json::to_vec(data)?;
    let mut store=ShadowStore::open(Path::new(STAGE_DB))?;
    let result=store.stage_response(&raw,7,PROFILE)?;
    ensure!(result.checksum==CONFIG_SHA && result.state==ShadowState::Staged,
        "durable_snapshot_state_not_staged");
    let recovered=store.recover()?;
    ensure!(recovered.iter().any(|r|r.version==7 && r.checksum==CONFIG_SHA && r.state==ShadowState::Staged),
        "durable_snapshot_recovery_failed");
    println!("STAGE3C_DURABLE_SHADOW_CONFIG=PASS");
    println!("CONFIG_VERSION=7");
    println!("CONFIG_SHA256={CONFIG_SHA}");
    println!("CREDENTIALS=FC5_22271_AND_FC95_10773");
    println!("ACCESS_RULES=FOUR_DOORS_24X7");
    println!("SHADOW_STAGE_DB={STAGE_DB}");
    println!("CONFIG_APPLIED_TO_LIVE_CONTROLLER=NO");
    println!("PRODUCTION_APPLIED_ACK_SENT=NO");
    println!("SIGNED_SHADOW_POLICY_V7=NOT_YET_ACTIVE");
    println!("RELAYS_AND_DOOR_OUTPUTS=UNTOUCHED");
    Ok(())
}

fn main() -> Result<()> {
    let arg=std::env::args().nth(1).ok_or_else(|| anyhow!("usage: --preflight | --stage-v7 | --verify-stage"))?;
    ensure!(std::env::args().len()==2, "exactly_one_argument_required");
    ensure!(["--preflight","--stage-v7","--verify-stage"].contains(&arg.as_str()),"unknown_argument");
    runtime_preflight()?;
    if arg=="--verify-stage" {
        require_private_storage()?;
        let store=ShadowStore::open(Path::new(STAGE_DB))?;
        let records=store.recover()?;
        ensure!(records.iter().any(|r|r.version==7 && r.checksum==CONFIG_SHA && r.state==ShadowState::Staged),"v7_staged_snapshot_missing");
        println!("STAGE3C_DURABLE_RECOVERY=PASS");
    } else {
        let identity=private_identity()?;
        println!("DEVICE_IDENTITY=VERIFIED_PRIVATE_IN_SCOPE");
        if arg=="--stage-v7" {
            let rt=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            let data=rt.block_on(fetch_config(&identity))?;
            println!("AUTHENTICATED_CONFIG_FETCH=PASS");
            validate_candidate(&data)?;
            stage(&data)?;
        } else {
            println!("STAGE3C_PREFLIGHT=PASS");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn checksum_and_scope_must_match() {
        assert!(validate_candidate(&serde_json::json!({"version":7,"checksum":"incorrect"})).is_err());
        assert!(validate_candidate(&serde_json::json!({"version":6,"checksum":CONFIG_SHA})).is_err());
    }
    #[test] fn live_service_hash_and_nonactuating_guards_embedded() {
        assert_eq!(BIN_SHA.len(),64);
        assert!(ENDPOINT.ends_with("/v1/config"));
        assert!(STAGE_DB.contains("stage3c-bench"));
    }
}
