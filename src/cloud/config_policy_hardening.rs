//! Strictly local-only HLAXS.Access policy hardening and MOCK audit receipts.
//! Not registered by controller main/cloud agent. Contains NO GPIO, relays,
//! command delivery, network clients, physical actuator traits or cloud ACK.
use anyhow::{anyhow, ensure, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::HashSet;
use super::{config_decision_offline, config_semantics};

pub const POLICY_VERSION: &str = "hlaxs-deny-only-2026-10-v1";

// Deliberately explicit: these are requirements, NOT undocumented parity fixes.
pub const REQUIREMENTS: [(&str, &str); 4] = [
    ("HLAXS-POL-001", "An unscheduled link cannot bypass a configured holiday"),
    ("HLAXS-POL-002", "A disabled reader must not authorize access"),
    ("HLAXS-POL-003", "A missing reader must not authorize access"),
    ("HLAXS-POL-004", "A reader mapped to the wrong door must not authorize access"),
];

#[derive(Clone)]
pub struct MockSnapshot {
    pub version: u64,
    pub checksum: String,
    pub config: Value,
}
impl MockSnapshot {
    pub fn build(version:u64, cfg:Value) -> Result<Self> {
        ensure!(version > 0, "zero configuration version refused");
        config_semantics::validate_configuration(&cfg)?;
        let checksum=config_semantics::checksum(&cfg)?;
        Ok(Self {version,checksum,config:cfg})
    }
    pub fn verify(&self) -> bool {
        self.version > 0 && config_semantics::validate_configuration(&self.config).is_ok()
            && config_semantics::checksum(&self.config).ok().as_deref() == Some(self.checksum.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub would_grant: bool,
    pub reason: &'static str, // redacted fixed reason only
    pub reader: u64,
    pub door_channel: Option<u64>,
    pub version: u64,
}
#[derive(Default)]
pub struct MockRecorder { pub events: Vec<Receipt> }
impl MockRecorder {
    fn record(&mut self,receipt:Receipt) -> Receipt {
        self.events.push(receipt);
        receipt
    }
}
/// No output interface exists: only an in-memory receipt, never a command.
/// Requires an exact externally supplied expected version+digest binding.
pub fn observe(
    snapshot:&MockSnapshot, expected_version:u64, expected_checksum:&str,
    probe:&config_decision_offline::Probe, recorder:&mut MockRecorder,
) -> Receipt {
    let mut result=Receipt {would_grant:false,reason:"configuration_untrusted",reader:probe.reader_number,
        door_channel:None,version:snapshot.version};
    if !snapshot.verify() { return recorder.record(result); }
    if snapshot.version!=expected_version || snapshot.checksum!=expected_checksum {
        result.reason="configuration_stale";
        return recorder.record(result);
    }
    let decision=config_decision_offline::evaluate(&snapshot.config,probe);
    result.reason=decision.reason;
    result.would_grant=decision.allowed;
    // Only simulated and redacted. Never a GPIO index or physical I/O call.
    result.door_channel=if decision.allowed {Some(probe.reader_number-1)} else {None};
    recorder.record(result)
}

/// Disposable synthetic-only SQLite ledger, NOT the actual device/production DB.
/// The owner of this struct is the standalone local test executable.
pub struct SyntheticJournal {conn:Connection}
impl SyntheticJournal {
    pub fn open(conn:Connection)->Result<Self> {
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS offline_snapshots (
            version INTEGER PRIMARY KEY CHECK(version>0), sha TEXT NOT NULL, json TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS offline_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), anchor_version INTEGER NOT NULL,
            active_version INTEGER NOT NULL, pending_version INTEGER, phase TEXT NOT NULL);")?;
        Ok(Self{conn})
    }
    pub fn initialize(&mut self,anchor:&MockSnapshot)->Result<()> {
        ensure!(anchor.verify(),"invalid synthetic anchor");
        let tx=self.conn.transaction()?;
        let n:i64=tx.query_row("SELECT count(*) FROM offline_state",[],|r|r.get(0))?;
        ensure!(n==0,"existing synthetic journal cannot be silently replaced");
        tx.execute("INSERT INTO offline_snapshots(version,sha,json) VALUES(?1,?2,?3)",params![anchor.version as i64,anchor.checksum,
            serde_json::to_string(&anchor.config)?])?;
        tx.execute("INSERT INTO offline_state(singleton,anchor_version,active_version,pending_version,phase)
           VALUES(1,?1,?1,NULL,'anchored')",[anchor.version as i64])?;
        tx.commit()?;
        Ok(())
    }
    fn state(&self)->Result<(u64,u64,Option<u64>,String)> {
        let (a,v,p,s):(i64,i64,Option<i64>,String)=self.conn.query_row(
            "SELECT anchor_version,active_version,pending_version,phase FROM offline_state WHERE singleton=1",[],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        ensure!(a>0&&v>0&&p.is_none_or(|x|x>0),"invalid simulated version pointer");
        Ok((a as u64,v as u64,p.map(|x|x as u64),s))
    }
    fn get(&self,v:u64)->Result<MockSnapshot>{
        let (sha,json):(String,String)=self.conn.query_row(
            "SELECT sha,json FROM offline_snapshots WHERE version=?1",[v as i64],
            |r|Ok((r.get(0)?,r.get(1)?)))?;
        let snap=MockSnapshot{version:v,checksum:sha,config:serde_json::from_str(&json)?};
        ensure!(snap.verify(),"corrupted synthetic journal snapshot");
        Ok(snap)
    }
    pub fn recover(&self)->Result<(MockSnapshot, String)>{
        let (anchor,active,pending,phase)=self.state()?;
        ensure!(matches!(phase.as_str(),"anchored"|"planned"|"simulated_failed"|"simulated_applied"|"simulated_rolled_back"),"unknown journal state");
        self.get(anchor)?;
        let active_cfg=self.get(active)?;
        ensure!((phase=="anchored" && pending.is_none() && active==anchor)
           || (phase=="planned" && pending.is_some() && active==anchor)
           || (phase=="simulated_failed" && pending.is_some() && active==anchor)
           || (phase=="simulated_applied" && pending==Some(active) && active==anchor+1)
           || (phase=="simulated_rolled_back" && pending.is_some() && active==anchor),
           "unexpected simulated state/version relationship");
        if let Some(v)=pending { self.get(v)?; }
        let actual_count:i64=self.conn.query_row("SELECT count(*) FROM offline_snapshots",[],|r|r.get(0))?;
        let mut ids=HashSet::new();ids.insert(anchor);if let Some(v)=pending {ids.insert(v);}
        ensure!(actual_count==ids.len() as i64,"unexpected extra versions in journal");
        Ok((active_cfg,phase))
    }
    pub fn plan(&mut self, next:&MockSnapshot)->Result<()> {
        ensure!(next.verify(),"invalid planned candidate");
        let (a,v,p,s)=self.state()?;
        ensure!(s=="anchored" && a==v && p.is_none(),"cannot replace a pending plan");
        ensure!(next.version==v.checked_add(1).ok_or_else(||anyhow!("version overflow"))?,
            "candidate must be exactly next version");
        let base=self.get(a)?;
        let _plan=config_semantics::plan_change(&base.config,&next.config,base.version,next.version)?;
        let tx=self.conn.transaction()?;
        tx.execute("INSERT INTO offline_snapshots(version,sha,json) VALUES(?1,?2,?3)",
            params![next.version as i64,next.checksum,serde_json::to_string(&next.config)?])?;
        tx.execute("UPDATE offline_state SET pending_version=?1,phase='planned' WHERE singleton=1",
            [next.version as i64])?;
        tx.commit()?;
        Ok(())
    }
    pub fn interrupted_success(&mut self)->Result<()> {
        let (_a,active,p,s)=self.state()?;
        ensure!(s=="planned" && p.is_some(),"not planned");
        let tx=self.conn.transaction()?;
        tx.execute("UPDATE offline_state SET active_version=?1,phase='simulated_applied' WHERE singleton=1",
            [p.unwrap() as i64])?;
        // Crash simulation: transaction dropped without commit. This is *not* a physical apply.
        drop(tx);
        let (v,phase)=self.recover()?;
        ensure!(v.version==active && phase=="planned","interrupted SQLite transaction leaked");
        Ok(())
    }
    pub fn fail(&mut self)->Result<()> {
        let (_a,v,p,s)=self.state()?;
        ensure!(s=="planned" && p.is_some(),"not planned");
        let tx=self.conn.transaction()?;
        tx.execute("UPDATE offline_state SET phase='simulated_failed' WHERE singleton=1",[])?;
        tx.commit()?;
        ensure!(self.recover()?.0.version==v,"failure changed active version");Ok(())
    }
    pub fn apply_mock(&mut self)->Result<()> {
        let (a,v,p,s)=self.state()?;
        ensure!(s=="planned"||s=="simulated_failed","no planned candidate to simulate");
        ensure!(v==a && p==Some(a+1),"invalid pending version");
        self.get(p.unwrap())?;
        let tx=self.conn.transaction()?;
        tx.execute("UPDATE offline_state SET active_version=?1,phase='simulated_applied' WHERE singleton=1",
            [p.unwrap() as i64])?;
        tx.commit()?;Ok(())
    }
    pub fn rollback(&mut self)->Result<()> {
        let (a,v,p,s)=self.state()?;
        ensure!(s=="simulated_applied" && p==Some(v),"not simulated applied");
        self.get(a)?;
        let tx=self.conn.transaction()?;
        tx.execute("UPDATE offline_state SET active_version=?1,phase='simulated_rolled_back' WHERE singleton=1",
            [a as i64])?;
        tx.commit()?;Ok(())
    }
}

/// Synthetic dummy credentials only. Never a real device snapshot.
pub fn synthetic_fixture()->Value {
        let pin_pairs=[[("gpiochip3",23),("gpiochip3",25)],[("gpiochip3",26),("gpiochip0",15)],
                       [("gpiochip4",10),("gpiochip4",26)],[("gpiochip4",27),("gpiochip4",11)]];
        let readers:Vec<Value>=pin_pairs.iter().enumerate().map(|(i,pins)|json!({
            "reader_number":i+1,"protocol":"wiegand","configuration":{
               "d0":{"chip":pins[0].0,"line":pins[0].1},
               "d1":{"chip":pins[1].0,"line":pins[1].1},"format":"Wiegand-26"}})).collect();
        json!({"controller":{"id":"synthetic-only"},
          "doors":[{"channel":0,"name":"D0","enabled":true,"unlock_ms":5000},
                   {"channel":1,"name":"D1","enabled":true,"unlock_ms":5000},
                   {"channel":2,"name":"D2","enabled":true,"unlock_ms":5000},
                   {"channel":3,"name":"D3","enabled":true,"unlock_ms":5000}],
          "readers":readers,"inputs":[],"outputs":[],
          "credentials":[
             {"id":"synthetic-1","enabled":true,"facility_code":41,"card_code":1001},
             {"id":"synthetic-2","enabled":true,"facility_code":41,"card_code":1002},
             {"id":"synthetic-3","enabled":true,"facility_code":41,"card_code":1003},
             {"id":"synthetic-4","enabled":true,"facility_code":41,"card_code":1004}],
          "access_levels":[{"id":"L1","name":"One","enabled":true},
                           {"id":"L2","name":"Two","enabled":true},
                           {"id":"L3","name":"Three","enabled":true},
                           {"id":"L4","name":"Four","enabled":true}],
          "credential_access_levels":[
              {"credential_id":"synthetic-1","access_level_id":"L1"},
              {"credential_id":"synthetic-2","access_level_id":"L2"},
              {"credential_id":"synthetic-3","access_level_id":"L3"},
              {"credential_id":"synthetic-4","access_level_id":"L4"}],
          "access_level_doors":[
              {"access_level_id":"L1","channel":0,"schedule_id":"S1"},
              {"access_level_id":"L2","channel":1,"schedule_id":"S1"},
              {"access_level_id":"L3","channel":2,"schedule_id":"S1"},
              {"access_level_id":"L4","channel":3,"schedule_id":"S1"}],
          "schedules":[{"id":"S1","name":"24x7","timezone":"America/New_York",
                        "definition":{"always":true}}],
          "holidays":[],"access_rules":[],"settings":{}})
    }

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use serde_json::json;

    const FIXED:&str="2026-10-19T13:30:00Z";
    fn p(reader:u64,card:u64)->config_decision_offline::Probe {
        config_decision_offline::Probe{reader_number:reader,facility_code:41,card_code:card,
            at_utc:FIXED.parse::<DateTime<Utc>>().unwrap()}
    }
    fn fixture()->Value { synthetic_fixture() }

    fn state(cfg:Value,version:u64)->MockSnapshot {MockSnapshot::build(version,cfg).unwrap()}
    fn check(cfg:&Value, reader:u64, card:u64)->Receipt {
        let s=state(cfg.clone(),6);let mut rec=MockRecorder::default();
        observe(&s,6,&s.checksum,&p(reader,card),&mut rec)
    }
    #[test] fn cross_reader_door_matrix_16_cases() {
        let cfg=fixture();
        for reader in 1..=4 {for card_index in 1..=4 {
            let result=check(&cfg,reader,1000+card_index);
            assert_eq!(result.would_grant,reader==card_index,"reader/card separation {reader},{card_index}");
            assert_eq!(result.door_channel,if result.would_grant {Some(reader-1)} else {None});
        }}
    }
    #[test] fn disabled_each_reader_denied_independently(){
        for reader in 1..=4 {let mut x=fixture();x["readers"][(reader-1) as usize]["enabled"]=json!(false);
            assert!(!check(&x,reader,1000+reader).would_grant);
            for other in 1..=4 {if other!=reader {assert!(check(&x,other,1000+other).would_grant);}}
        }
    }
    #[test] fn missing_reader_fails_closed(){
        for reader in 1..=4 {let mut x=fixture();x["readers"].as_array_mut().unwrap().retain(|r|
            r["reader_number"].as_u64()!=Some(reader));
            assert!(!check(&x,reader,1000+reader).would_grant);
        }
    }
    #[test] fn bad_reader_mapping_fails_closed(){
        for reader in 1..=4 {let mut x=fixture();x["readers"][(reader-1) as usize]["door_channel"]=json!(reader%4);
            assert!(!check(&x,reader,1000+reader).would_grant);
        }
    }
    #[test] fn unscheduled_link_deny_holiday_is_never_bypassed(){
        let mut x=fixture();x["access_level_doors"][0]["schedule_id"]=Value::Null;
        x["holidays"]=json!([{"id":"holiday-1","holiday_date":"2026-10-19","behavior":"deny"}]);
        let r=check(&x,1,1001);assert!(!r.would_grant);
    }
    #[test] fn default_deny_if_wrong_card_or_facility(){
        assert!(!check(&fixture(),1,1999).would_grant);
        let s=state(fixture(),6);let mut rec=MockRecorder::default();let mut probe=p(1,1001);probe.facility_code=42;
        assert!(!observe(&s,6,&s.checksum,&probe,&mut rec).would_grant);
    }
    #[test] fn stale_version_and_digest_never_record_grant(){
        let s=state(fixture(),6);let mut rec=MockRecorder::default();
        assert!(!observe(&s,5,&s.checksum,&p(1,1001),&mut rec).would_grant);
        assert!(!observe(&s,6,"deadbeef",&p(1,1001),&mut rec).would_grant);
        assert!(rec.events.iter().all(|r|r.door_channel.is_none()));
    }
    #[test] fn corrupted_snapshot_never_records_grant(){
        let mut s=state(fixture(),6);s.config["doors"][0]["unlock_ms"]=json!(7000);
        assert!(!observe(&s,6,&s.checksum,&p(1,1001),&mut MockRecorder::default()).would_grant);
    }
    #[test] fn unsupported_rule_never_records_grant(){
        let mut s=state(fixture(),6);s.config["access_rules"]=json!([{"unsupported":true}]);
        assert!(!observe(&s,6,&s.checksum,&p(1,1001),&mut MockRecorder::default()).would_grant);
    }
    #[test] fn synthetic_journal_persists_and_recovers(){
        let db=Connection::open_in_memory().unwrap();let mut j=SyntheticJournal::open(db).unwrap();
        let s=state(fixture(),6);j.initialize(&s).unwrap();
        let mut next=s.config.clone();next["doors"][0]["unlock_ms"]=json!(5100);
        let n=state(next,7);j.plan(&n).unwrap();
        assert_eq!(j.recover().unwrap().1,"planned");
        j.interrupted_success().unwrap();assert_eq!(j.recover().unwrap().0.version,6);
        j.fail().unwrap();assert_eq!(j.recover().unwrap().1,"simulated_failed");
        j.apply_mock().unwrap();assert_eq!(j.recover().unwrap().0.version,7);
        j.rollback().unwrap();assert_eq!(j.recover().unwrap().0.version,6);
        assert_eq!(j.recover().unwrap().1,"simulated_rolled_back");
    }
    #[test] fn synthetic_journal_reopen_on_disk_and_reject_corruption(){
        use std::time::{SystemTime,UNIX_EPOCH};
        use std::fs::{self, OpenOptions};
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let suffix=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir=std::env::temp_dir().join(format!("hlaxs-hardening-test-{}-{}",std::process::id(),suffix));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();
        let path=dir.join("synthetic.sqlite");
        drop(OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap());
        let work=(||->Result<()> {
            let mut j=SyntheticJournal::open(Connection::open(&path)?)?;
            j.initialize(&state(fixture(),6))?;
            let mut next=fixture();next["doors"][0]["unlock_ms"]=json!(6000);
            j.plan(&state(next,7))?;
            drop(j);
            let mut j=SyntheticJournal::open(Connection::open(&path)?)?;
            ensure!(j.recover()?.1=="planned","restart recovery failed");
            j.apply_mock()?;
            drop(j);
            let mut j=SyntheticJournal::open(Connection::open(&path)?)?;
            ensure!(j.recover()?.0.version==7,"simulated version not persisted");
            j.conn.execute("UPDATE offline_snapshots SET json=replace(json,'6000','7000') WHERE version=7",[])?;
            ensure!(j.recover().is_err(),"corrupted journal unexpectedly passed");
            Ok(())
        })();
        let _=fs::remove_file(&path);let _=fs::remove_dir(&dir);
        work.unwrap();
    }
    #[test] fn journal_refuses_stale_plan_and_rebase(){
        let db=Connection::open_in_memory().unwrap();let mut j=SyntheticJournal::open(db).unwrap();
        let s=state(fixture(),6);j.initialize(&s).unwrap();
        let mut next=fixture();next["doors"][0]["unlock_ms"]=json!(6100);
        assert!(j.plan(&state(next.clone(),6)).is_err());
        j.plan(&state(next,7)).unwrap();assert!(j.plan(&state(fixture(),8)).is_err());
    }
    #[test] fn deterministic_1024_seeded_negative_probes(){
        let cfg=fixture();let s=state(cfg,6);let mut recorder=MockRecorder::default();
        let mut seed:u64=0x9e3779b97f4a7c15;
        for index in 0..1024_u64 {
            seed=seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let reader=(seed%4)+1;
            let card=if index%3==0 {9000+(seed%1000)} else {1001+((seed>>10)%4)};
            let probe=p(reader,card);
            let observed=observe(&s,6,&s.checksum,&probe,&mut recorder);
            let expected=card >=1001 && card<=1004 && reader==card-1000;
            assert_eq!(observed.would_grant,expected,"seeded probe {index}");
        }
        assert_eq!(recorder.events.len(),1024);
        assert!(recorder.events.iter().all(|e|!e.would_grant || e.door_channel==Some(e.reader-1)));
    }
    #[test] fn safe_receipt_debug_contains_no_credential_ids(){
        let cfg=fixture();let result=check(&cfg,1,1001);let printed=format!("{:?}",result);
        assert!(!printed.contains("synthetic-1"));assert!(!printed.contains("1001"));
        assert!(result.would_grant);
    }
    #[test] fn requirements_all_have_unique_ids(){
        let mut set=HashSet::new();for (code,desc) in REQUIREMENTS {assert!(set.insert(code));assert!(!desc.is_empty());}
        assert_eq!(set.len(),4);
    }
}
