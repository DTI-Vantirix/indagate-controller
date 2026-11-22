//! Indagate Access: fail-closed, filesystem-backed configuration SHADOW staging.
//!
//! This module is intentionally UNWIRED from cloud::agent::run(). It never
//! applies a real configuration, changes the access-control DB, performs GPIO,
//! sends cloud acknowledgments, or touches the legacy monitor.
//! The host controller must explicitly opt in to a later audited integration.

use anyhow::{Context, Result, anyhow, bail, ensure};
use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOTS: i64 = 16;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ShadowState {
    Staged,
    SimulatedApplied,
    SimulatedFailed,
}

impl ShadowState {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::SimulatedApplied => "simulated_applied",
            Self::SimulatedFailed => "simulated_failed",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "staged" => Ok(Self::Staged),
            "simulated_applied" => Ok(Self::SimulatedApplied),
            "simulated_failed" => Ok(Self::SimulatedFailed),
            _ => bail!("unrecognized shadow state"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ShadowSnapshot {
    pub version: u64,
    pub checksum: String,
    pub state: ShadowState,
}

pub struct ShadowStore {
    connection: Connection,
}

impl ShadowStore {
    /// Open an independent SQLite file. Never pass the live access-control DB.
    /// The parent directory must be owner-private to protect WAL/SHM files too.
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path.parent().ok_or_else(|| anyhow!("shadow DB requires parent directory"))?;
        if !parent.exists() {
            fs::create_dir_all(parent).context("create private shadow directory")?;
            fs::set_permissions(parent, Permissions::from_mode(0o700))?;
        }
        let permissions = fs::metadata(parent)?.permissions().mode();
        ensure!(permissions & 0o077 == 0, "shadow directory must deny group/other access");
        if !path.exists() {
            let _file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        }
        ensure!(fs::metadata(path)?.permissions().mode() & 0o077 == 0,
            "shadow database must deny group/other access");
        let connection = Connection::open(path).context("open independent shadow DB")?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;\n\
             CREATE TABLE IF NOT EXISTS shadow_snapshots (\n\
               version INTEGER PRIMARY KEY CHECK (version > 0),\n\
               checksum TEXT NOT NULL CHECK (length(checksum)=64),\n\
               profile TEXT NOT NULL,\n\
               canonical_json TEXT NOT NULL,\n\
               state TEXT NOT NULL CHECK (state IN ('staged','simulated_applied','simulated_failed')),\n\
               created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\n\
               updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP\n\
             );"
        )?;
        Ok(Self { connection })
    }

    /// Stage an already downloaded cloud response `data` object, never an
    /// API envelope with `success`. No live cloud ACK can be produced here.
    /// All validation happens before a single atomic SQLite transaction.
    pub fn stage_response(&mut self, raw: &[u8], expected_version: u64, profile: &str)
        -> Result<ShadowSnapshot>
    {
        ensure!(!raw.is_empty() && raw.len() <= MAX_ENVELOPE_BYTES,
            "truncated or oversized response");
        ensure!(expected_version > 0 && expected_version <= i64::MAX as u64,
            "invalid desired version");
        ensure!(!profile.trim().is_empty(), "missing hardware profile");
        let data: Value = serde_json::from_slice(raw).context("invalid or truncated JSON")?;
        let object = data.as_object().ok_or_else(|| anyhow!("configuration response is not an object"))?;
        ensure!(object.get("version").and_then(Value::as_u64) == Some(expected_version),
            "stale or mismatched desired version");
        ensure!(object.get("hardware_profile").and_then(Value::as_str) == Some(profile),
            "hardware profile mismatch");
        let checksum = object.get("checksum").and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing config checksum"))?;
        ensure!(checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "invalid checksum format");
        let config = object.get("configuration")
            .ok_or_else(|| anyhow!("missing configuration"))?;
        validate_sp4_shape(config)?;
        let canonical = pg_jsonb_canonical(config)?;
        let computed = digest(&SHA256, canonical.as_bytes());
        let actual: String = computed.as_ref().iter().map(|v| format!("{v:02x}")).collect();
        ensure!(actual == checksum, "configuration checksum mismatch");

        let tx = self.connection.transaction()?;
        let latest: Option<i64> = tx.query_row(
            "SELECT MAX(version) FROM shadow_snapshots", [], |row| row.get(0))?;
        if let Some(latest) = latest {
            ensure!(expected_version as i64 >= latest, "stale configuration snapshot");
        }
        let previous: Option<(String, String)> = tx.query_row(
            "SELECT checksum,state FROM shadow_snapshots WHERE version=?1",
            [expected_version as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let state = if let Some((existing_checksum, existing_state)) = previous {
            ensure!(existing_checksum == checksum, "immutable version checksum changed");
            ShadowState::parse(&existing_state)?
        } else {
            tx.execute(
                "INSERT INTO shadow_snapshots(version,checksum,profile,canonical_json,state) VALUES (?1,?2,?3,?4,'staged')",
                params![expected_version as i64, checksum, profile, canonical],
            )?;
            ShadowState::Staged
        };
        // Only bound disk growth; reject rather than deleting past forensic history.
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM shadow_snapshots", [], |row| row.get(0))?;
        ensure!(count <= MAX_SNAPSHOTS, "shadow snapshot history limit reached");
        tx.commit()?;
        Ok(ShadowSnapshot {version: expected_version, checksum: checksum.to_owned(), state})
    }

    /// Diagnostic-only simulation. Does not write production config, compute
    /// an access decision, set cloud_config_version, or generate an ACK.
    pub fn simulate_apply(&mut self, version: u64, should_fail: bool) -> Result<ShadowSnapshot> {
        ensure!(version > 0 && version <= i64::MAX as u64, "invalid simulated version");
        let tx = self.connection.transaction()?;
        let row: (String, String, String) = tx.query_row(
            "SELECT checksum,canonical_json,state FROM shadow_snapshots WHERE version=?1",
            [version as i64], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).context("missing staged snapshot")?;
        let (checksum, canonical, status) = row;
        let old_state = ShadowState::parse(&status)?;
        let digest = digest(&SHA256, canonical.as_bytes());
        let actual: String = digest.as_ref().iter().map(|v| format!("{v:02x}")).collect();
        ensure!(actual == checksum, "staged snapshot corrupted");
        let state = if should_fail {ShadowState::SimulatedFailed} else {ShadowState::SimulatedApplied};
        if old_state == ShadowState::SimulatedApplied && should_fail {
            bail!("cannot downgrade simulated success to failure");
        }
        tx.execute(
            "UPDATE shadow_snapshots SET state=?2,updated_at=CURRENT_TIMESTAMP WHERE version=?1",
            params![version as i64, state.as_str()],
        )?;
        tx.commit()?;
        Ok(ShadowSnapshot {version, checksum, state})
    }

    /// Verify staged data from disk on every startup; do not trust the state
    /// label until the stored canonical payload has passed its hash check.
    pub fn recover(&self) -> Result<Vec<ShadowSnapshot>> {
        let mut query = self.connection.prepare(
            "SELECT version,checksum,canonical_json,state FROM shadow_snapshots ORDER BY version"
        )?;
        let rows = query.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?,
                row.get::<_, String>(2)?, row.get::<_, String>(3)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (v, checksum, canonical, state) = row?;
            ensure!(v > 0 && checksum.len() == 64, "invalid stored snapshot metadata");
            let parsed: Value = serde_json::from_str(&canonical).context("stored stage is malformed")?;
            let normalized = pg_jsonb_canonical(&parsed)?;
            ensure!(normalized == canonical, "stored stage canonicalization altered");
            let calculated = digest(&SHA256, canonical.as_bytes());
            let actual: String = calculated.as_ref().iter().map(|x| format!("{x:02x}")).collect();
            ensure!(actual == checksum, "stored stage checksum mismatch");
            result.push(ShadowSnapshot {
                version: v as u64,
                checksum,
                state: ShadowState::parse(&state)?,
            });
        }
        Ok(result)
    }
}

fn validate_sp4_shape(config: &Value) -> Result<()> {
    let obj = config.as_object().ok_or_else(|| anyhow!("configuration must be an object"))?;
    let doors = obj.get("doors").and_then(Value::as_array).ok_or_else(|| anyhow!("missing doors"))?;
    ensure!(doors.len() == 4, "SP4 requires exactly four doors");
    let mut channels = HashSet::new();
    for door in doors {
        let obj = door.as_object().ok_or_else(|| anyhow!("invalid door"))?;
        let channel = obj.get("channel").and_then(Value::as_u64).ok_or_else(|| anyhow!("invalid door channel"))?;
        ensure!(channel < 4 && channels.insert(channel), "out-of-range or duplicate door channel");
        let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
        ensure!(!name.trim().is_empty(), "door name required");
        let unlock_ms = obj.get("unlock_ms").and_then(Value::as_u64).unwrap_or(5000);
        ensure!((100..=600_000).contains(&unlock_ms), "invalid unlock_ms");
    }
    for key in ["readers", "inputs", "outputs"] {
        ensure!(obj.get(key).and_then(Value::as_array).is_some(), "missing resource array {key}");
    }
    Ok(())
}

/// PostgreSQL JSONB::text uses ascending UTF-8 key length followed by binary
/// lexical order, with commas/colons followed by spaces. Reject floating
/// numbers until dedicated numeric-text conformance tests are available.
/// This intentionally FAILS CLOSED rather than accepting mismatched hashes.
fn pg_jsonb_canonical(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::String(s) => Ok(serde_json::to_string(s)?),
        Value::Number(n) => {
            ensure!(!n.is_f64(), "floating JSON number not supported by shadow verifier");
            Ok(n.to_string())
        }
        Value::Array(a) => {
            let items = a.iter().map(pg_jsonb_canonical).collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", items.join(", ")))
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a,b| a.as_bytes().len().cmp(&b.as_bytes().len()).then_with(|| a.as_bytes().cmp(b.as_bytes())));
            let mut items = Vec::new();
            for key in keys {
                items.push(format!("{}: {}", serde_json::to_string(key)?,
                    pg_jsonb_canonical(o.get(key).context("missing canonical map key")?)?));
            }
            Ok(format!("{{{}}}", items.join(", ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn scratch() -> PathBuf {
        let p = std::env::temp_dir().join(format!("hlaxs-shadow-{}", Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, Permissions::from_mode(0o700)).unwrap();
        p.join("stage.sqlite")
    }
    fn fixture(version: u64) -> Vec<u8> {
        let config = json!({
            "doors": [
                {"channel":0,"name":"A","unlock_ms":5000},
                {"channel":1,"name":"B","unlock_ms":5000},
                {"channel":2,"name":"C","unlock_ms":5000},
                {"channel":3,"name":"D","unlock_ms":5000}
            ],
            "readers":[],"inputs":[],"outputs":[],"credentials":[]
        });
        let canonical = pg_jsonb_canonical(&config).unwrap();
        let hash = digest(&SHA256, canonical.as_bytes());
        let checksum: String = hash.as_ref().iter().map(|x| format!("{x:02x}")).collect();
        json!({"version":version,"hardware_profile":"HNX-HW-SP-ACP4WR6-R1",
            "checksum":checksum,"configuration":config}).to_string().into_bytes()
    }
    const PROFILE: &str = "HNX-HW-SP-ACP4WR6-R1";
    #[test]
    fn postgres_jsonb_golden() {
        let v = json!({"z":1,"aa":[{"long":5,"x":true}],"a":null});
        let canonical = pg_jsonb_canonical(&v).unwrap();
        assert_eq!(canonical, r#"{"a": null, "z": 1, "aa": [{"x": true, "long": 5}]}"#);
        let hash = digest(&SHA256, canonical.as_bytes());
        let actual: String = hash.as_ref().iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(actual, "5691e0142835c5d716d8bd8f25edd660a50922fe0f1837e3942e06bab296b651");
    }
    #[test]
    fn stages_then_recovers_across_restart_without_real_apply() {
        let path = scratch();
        let first = fixture(6);
        {
            let mut db = ShadowStore::open(&path).unwrap();
            let staged = db.stage_response(&first, 6, PROFILE).unwrap();
            assert_eq!(staged.state, ShadowState::Staged);
            let same = db.stage_response(&first, 6, PROFILE).unwrap();
            assert_eq!(same.state, ShadowState::Staged);
            db.simulate_apply(6, false).unwrap();
        }
        let db = ShadowStore::open(&path).unwrap();
        let records = db.recover().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, ShadowState::SimulatedApplied);
        assert!(db.connection.prepare("SELECT name FROM sqlite_master WHERE name='controller_config'").unwrap()
            .exists([]).unwrap() == false);
    }
    #[test]
    fn rejects_interrupted_corrupt_and_wrong_version() {
        let path = scratch();
        let mut db = ShadowStore::open(&path).unwrap();
        let first = fixture(7);
        assert!(db.stage_response(&first[..30],7,PROFILE).is_err());
        assert!(db.stage_response(&first,8,PROFILE).is_err());
        let mut bad: Value = serde_json::from_slice(&first).unwrap();
        bad["checksum"] = Value::String("f".repeat(64));
        assert!(db.stage_response(bad.to_string().as_bytes(),7,PROFILE).is_err());
        assert!(db.recover().unwrap().is_empty());
    }
    #[test]
    fn rejects_profile_schema_and_duplicate_version_tampering() {
        let path = scratch();
        let mut db = ShadowStore::open(&path).unwrap();
        let good = fixture(5);
        assert!(db.stage_response(&good,5,"OTHER-MODEL").is_err());
        db.stage_response(&good,5,PROFILE).unwrap();
        let changed = fixture(6);
        let mut bad: Value = serde_json::from_slice(&changed).unwrap();
        bad["configuration"]["doors"][0]["channel"] = json!(1);
        assert!(db.stage_response(bad.to_string().as_bytes(),6,PROFILE).is_err());
        assert_eq!(db.recover().unwrap().len(),1);
    }
    #[test]
    fn failed_simulation_then_success_has_no_ack() {
        let path = scratch();
        let mut db = ShadowStore::open(&path).unwrap();
        db.stage_response(&fixture(1),1,PROFILE).unwrap();
        assert_eq!(db.simulate_apply(1,true).unwrap().state,ShadowState::SimulatedFailed);
        assert_eq!(db.simulate_apply(1,false).unwrap().state,ShadowState::SimulatedApplied);
        assert!(db.simulate_apply(1,true).is_err());
        let stages = db.recover().unwrap();
        assert_eq!(stages.len(),1);
        // This module has NO authenticated_post, RPC call or cloud ACK API.
    }
    #[test]
    fn tampered_sqlite_snapshot_refused_at_recovery() {
        let path = scratch();
        let mut db = ShadowStore::open(&path).unwrap();
        db.stage_response(&fixture(2),2,PROFILE).unwrap();
        db.connection.execute("UPDATE shadow_snapshots SET canonical_json='{}' WHERE version=2",[]).unwrap();
        assert!(db.recover().is_err());
        assert!(db.simulate_apply(2,false).is_err());
    }
    #[test]
    fn refuses_floating_point_hashes_until_verified() {
        assert!(pg_jsonb_canonical(&json!({"float":0.25})).is_err());
    }
    #[test]
    fn sqlite_insert_failure_leaves_no_partial_stage() {
        let path = scratch();
        let mut db = ShadowStore::open(&path).unwrap();
        db.connection.execute_batch(
            "CREATE TRIGGER shadow_simulated_failure BEFORE INSERT ON shadow_snapshots \
             BEGIN SELECT RAISE(ABORT, 'simulated disk interruption'); END;"
        ).unwrap();
        assert!(db.stage_response(&fixture(8), 8, PROFILE).is_err());
        assert!(db.recover().unwrap().is_empty());
    }
    #[test]
    fn refuses_partial_oversized_and_malformed_input() {
        let path = scratch();
        let mut db = ShadowStore::open(&path).unwrap();
        assert!(db.stage_response(b"{",1,PROFILE).is_err());
        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert!(db.stage_response(&oversized,1,PROFILE).is_err());
        assert!(db.stage_response(b"null",1,PROFILE).is_err());
        assert_eq!(db.recover().unwrap().len(),0);
    }
    #[test]
    fn already_staged_newer_version_rejects_stale_download() {
        let path = scratch();
        let mut db = ShadowStore::open(&path).unwrap();
        db.stage_response(&fixture(10),10,PROFILE).unwrap();
        assert!(db.stage_response(&fixture(9),9,PROFILE).is_err());
        assert_eq!(db.recover().unwrap().len(),1);
    }

}
