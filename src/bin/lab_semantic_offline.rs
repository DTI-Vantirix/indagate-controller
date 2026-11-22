//! Indagate Access v6: standalone SEMANTIC and PLAN simulation in WSL only.
//! Never invoked by controller main, never reaches cloud or physical devices.
//! ALL persisted data lives in disposable owner-private /tmp directory.

#[path = "../cloud/config_semantics.rs"]
mod config_semantics;

use anyhow::{anyhow, bail, ensure, Context, Result};
use config_semantics::{checksum, pg_jsonb_canonical, plan_change, validate_configuration, ChangePlan, SP4_PROFILE, SP4_V6_CHECKSUM};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const CONTROLLER_ID: &str = "2722691f-f4db-4f42-b63d-dac94b06ec9e";
const V6: u64 = 6;
const V7: u64 = 7;
const MAX_BYTES: u64 = 2 * 1024 * 1024 + 1;

struct PlanStore { connection: Connection }
#[derive(Debug)]
struct StoredPlan {base_version:u64,target_version:u64,base_checksum:String,target_checksum:String,
    base_json:String,target_json:String,fingerprint:String,changed_sections_json:String,
    status:String,simulated_active_version:u64}

fn file_guard(path: &Path) -> Result<()> {
    ensure!(path.is_absolute() && path.file_name().is_some_and(|x| x=="plan.sqlite"),
        "test-only plan.sqlite absolute pathname required");
    let parent = path.parent().context("missing plan DB directory")?;
    let cwd_parent = parent.canonicalize().context("test directory missing")?;
    let temp = env::temp_dir().canonicalize()?;
    ensure!(cwd_parent.starts_with(&temp) && cwd_parent != temp,
        "refuse any plan database outside private system temp subdirectory");
    ensure!(cwd_parent.file_name().is_some_and(|x| x.to_string_lossy().starts_with("hlaxs-semantic-v6-")),
        "non-test directory name rejected");
    ensure!(fs::metadata(&cwd_parent)?.permissions().mode() & 0o077 == 0,
        "plan parent directory must deny group/other access");
    if path.exists() {
        ensure!(!fs::symlink_metadata(path)?.file_type().is_symlink(), "plan database symlink not allowed");
        ensure!(fs::metadata(path)?.permissions().mode() & 0o077 == 0,"plan database must be owner private");
    }
    Ok(())
}

impl PlanStore {
    fn open(path:&Path)->Result<Self> {
        file_guard(path)?;
        if !path.exists() {
            let _file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        }
        let conn=Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=4000;
           CREATE TABLE IF NOT EXISTS anchor(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             base_version INTEGER NOT NULL CHECK(base_version>0),
             base_checksum TEXT NOT NULL,
             base_json TEXT NOT NULL);
           CREATE TABLE IF NOT EXISTS plan(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             target_version INTEGER NOT NULL,
             target_checksum TEXT NOT NULL,
             target_json TEXT NOT NULL,
             fingerprint TEXT NOT NULL,
             changed_sections_json TEXT NOT NULL,
             status TEXT NOT NULL CHECK(status IN('planned','simulated_failed','simulated_success','simulated_rolled_back')),
             simulated_active_version INTEGER NOT NULL);")?;
        Ok(Self{connection:conn})
    }
    fn stage(&mut self, base:&Value, candidate:&Value, plan:&ChangePlan)->Result<()> {
        let base_json=pg_jsonb_canonical(base)?;
        let target_json=pg_jsonb_canonical(candidate)?;
        let changed=serde_json::to_string(&plan.changed_sections)?;
        let tx=self.connection.transaction()?;
        // Never overwrite an anchor or rebase an existing plan. These files are
        // generated once per disposable test run and then treated as immutable.
        let existing:i64=tx.query_row("SELECT count(*) FROM anchor",[],|r|r.get(0))?;
        ensure!(existing==0,"plan or isolated v6 reference anchor already exists");
        tx.execute("INSERT INTO anchor(singleton,base_version,base_checksum,base_json) VALUES (1,?1,?2,?3)",
            params![plan.base_version as i64,plan.base_checksum,base_json])?;
        tx.execute("INSERT INTO plan(singleton,target_version,target_checksum,target_json,fingerprint,changed_sections_json,status,simulated_active_version)
            VALUES(1,?1,?2,?3,?4,?5,'planned',?6)",
            params![plan.target_version as i64,plan.target_checksum,target_json,plan.fingerprint,changed,plan.base_version as i64])?;
        tx.commit()?;
        Ok(())
    }
    fn recover(&self)->Result<StoredPlan> {
        let anchors: Vec<(i64,String,String)> = {
            let mut statement = self.connection.prepare("SELECT base_version,base_checksum,base_json FROM anchor")?;
            let rows=statement.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            rows.collect::<std::result::Result<Vec<_>,_>>()?
        };
        ensure!(anchors.len()==1,"missing/duplicated isolated v6 reference anchor");
        let (base_version,base_checksum,base_json)=&anchors[0];
        ensure!(*base_version==V6 as i64 && base_checksum==SP4_V6_CHECKSUM,"anchor identity was altered");
        let candidate = self.connection.query_row(
            "SELECT target_version,target_checksum,target_json,fingerprint,changed_sections_json,status,simulated_active_version FROM plan WHERE singleton=1",[],
            |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,
                r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,i64>(6)?))).optional()?;
        let (target_version,target_checksum,target_json,fingerprint,changed_sections_json,status,active)=
            candidate.ok_or_else(||anyhow!("missing planned change"))?;
        ensure!(target_version==V7 as i64,"target version tampered");
        let base:Value=serde_json::from_str(base_json).context("corrupted anchor JSON")?;
        let target:Value=serde_json::from_str(&target_json).context("corrupted candidate JSON")?;
        ensure!(pg_jsonb_canonical(&base)?==*base_json,"anchor canonical bytes altered");
        ensure!(pg_jsonb_canonical(&target)?==target_json,"candidate canonical bytes altered");
        ensure!(checksum(&base)?==*base_checksum,"anchor checksum corrupted");
        ensure!(checksum(&target)?==target_checksum,"candidate checksum corrupted");
        let expected=plan_change(&base,&target,*base_version as u64,target_version as u64)?;
        ensure!(fingerprint==expected.fingerprint && changed_sections_json==serde_json::to_string(&expected.changed_sections)?,
            "planned change fingerprint/summary corrupted");
        ensure!(["planned","simulated_failed","simulated_success","simulated_rolled_back"].contains(&status.as_str()),"plan state invalid");
        let expected_active=if status=="simulated_success" {V7} else {V6};
        ensure!(active==expected_active as i64,"reference anchor/simulated active pointer inconsistent");
        Ok(StoredPlan{base_version:V6,target_version:V7,base_checksum:base_checksum.to_owned(),
            target_checksum,target_json,base_json:base_json.to_owned(),fingerprint,changed_sections_json,status,
            simulated_active_version:active as u64})
    }
    fn interrupt_success(&mut self)->Result<()> {
        ensure!(self.recover()?.status=="planned","interruption test needs planned state");
        let tx=self.connection.transaction()?;
        tx.execute("UPDATE plan SET status='simulated_success',simulated_active_version=7 WHERE singleton=1",[])?;
        // A simulated process crash/power interruption before SQLite COMMIT.
        tx.rollback()?;
        ensure!(self.recover()?.status=="planned","uncommitted interrupted simulation persisted unexpectedly");
        Ok(())
    }
    fn simulate(&mut self, next:&str)->Result<()> {
        let was=self.recover()?;
        let (allowed, active)=match next {
            "simulated_failed" => (was.status=="planned",V6),
            "simulated_success" => (was.status=="planned" || was.status=="simulated_failed",V7),
            "simulated_rolled_back" => (was.status=="simulated_success",V6),
            _ => bail!("unsupported simulation transition"),
        };
        ensure!(allowed,"simulated transition not allowed");
        let tx=self.connection.transaction()?;
        tx.execute("UPDATE plan SET status=?1,simulated_active_version=?2 WHERE singleton=1",
            params![next,active as i64])?;
        tx.commit()?;
        Ok(())
    }
}

fn checked_envelope(raw:&[u8])->Result<Value> {
    ensure!(!raw.is_empty() && raw.len() <= 2 * 1024 * 1024,"missing or oversized v6 JSON");
    let response:Value=serde_json::from_slice(raw).context("truncated or invalid envelope")?;
    ensure!(response.get("version").and_then(Value::as_u64)==Some(V6),"unexpected SP4 snapshot version");
    ensure!(response.get("hardware_profile").and_then(Value::as_str)==Some(SP4_PROFILE),"unexpected hardware profile");
    ensure!(response.get("checksum").and_then(Value::as_str)==Some(SP4_V6_CHECKSUM),"unexpected immutable snapshot hash");
    let config=response.get("configuration").ok_or_else(||anyhow!("missing configuration"))?;
    if let Some(controller)=config.get("controller") {
        if let Some(id)=controller.get("id") {
            ensure!(id.as_str()==Some(CONTROLLER_ID),"controller identity did not match real v6 snapshot");
        }
    }
    ensure!(checksum(config)?==SP4_V6_CHECKSUM,"checksum bytes mismatch");
    validate_configuration(config)?;
    Ok(config.to_owned())
}

fn main()->Result<()> {
    ensure!(env::var("HLAXS_SEMANTIC_OFFLINE_ONLY").as_deref()==Ok("YES"),"missing explicit offline-only environment guard");
    let args:Vec<String>=env::args().collect();
    ensure!(args.len()==3,"expected <stage|recover-planned|interrupt-success|mark-failed|recover-failed|mark-success|recover-success|rollback|recover-rolled-back|reject-corruption> /tmp/hlaxs-semantic-v6-*/plan.sqlite");
    let mode=args[1].as_str();
    let path=PathBuf::from(&args[2]);
    file_guard(&path)?;
    let mut db=PlanStore::open(&path)?;
    match mode {
        "stage"=>{
            let mut raw=Vec::new();
            io::stdin().take(MAX_BYTES).read_to_end(&mut raw)?;
            let base=checked_envelope(&raw)?;
            let count=validate_configuration(&base)?;
            let mut proposal=base.clone();
            let first = proposal.get_mut("doors").and_then(Value::as_array_mut)
                .and_then(|doors| doors.iter_mut().find(|d| d.get("channel").and_then(Value::as_u64)==Some(0)))
                .ok_or_else(||anyhow!("no door 0 to create test-only candidate"))?;
            let current=first.get("unlock_ms").and_then(Value::as_u64).unwrap_or(5000);
            let next=if current >= 600_000 {current-100} else {current+100};
            first["unlock_ms"]=json!(next);
            let plan=plan_change(&base,&proposal,V6,V7)?;
            ensure!(plan.base_checksum==SP4_V6_CHECKSUM,"unexpected base hash in generated plan");
            db.stage(&base,&proposal,&plan)?;
            println!("PASS: actual v6 semantic checks; doors={} readers={} inputs={} outputs={} credentials={} access_levels={} schedules={} holidays={}",
                count.doors,count.readers,count.inputs,count.outputs,count.credentials,count.access_levels,count.schedules,count.holidays);
            println!("PASS: hypothetical v7 change plan staged locally; sections={} (values redacted)",plan.changed_sections.join(","));
            println!("PASS: offline v6 reference anchor persisted separately; no physical/config/cloud action");
        },
        "interrupt-success" => {db.interrupt_success()?;println!("PASS: uncommitted simulated success rolled back; v6 anchor preserved");},
        "mark-failed" => {db.simulate("simulated_failed")?;println!("PASS: simulated failure recorded, v6 remains offline v6 reference");},
        "mark-success" => {db.simulate("simulated_success")?;println!("PASS: test-only success pointer advanced to hypothetical v7; v6 rollback anchor preserved");},
        "rollback" => {db.simulate("simulated_rolled_back")?;println!("PASS: simulated rollback returned pointer to v6 without losing original snapshot");},
        "recover-planned" | "recover-failed" | "recover-success" | "recover-rolled-back" => {
            let plan=db.recover()?;
            let expected=match mode {
                "recover-planned"=>"planned",
                "recover-failed"=>"simulated_failed",
                "recover-success"=>"simulated_success",
                "recover-rolled-back"=>"simulated_rolled_back",
                _=>unreachable!(),
            };
            ensure!(plan.status==expected,"unexpected persisted simulated state");
            let _ = (&plan.base_json,&plan.target_json,&plan.fingerprint,&plan.changed_sections_json);
            ensure!(plan.base_version==V6 && plan.target_version==V7 && plan.base_checksum==SP4_V6_CHECKSUM && plan.target_checksum.len()==64,
                "unexpected simulated plan identity");
            println!("PASS: restart recovery verified {:?}, active simulated version {} (never physical)",plan.status,plan.simulated_active_version);
        },
        "reject-corruption" => {
            if db.recover().is_ok() {bail!("corrupted plan was unexpectedly accepted");}
            println!("PASS: tampered local plan payload failed recovery verification");
        },
        _ => bail!("unsupported local-only mode"),
    }
    Ok(())
}
