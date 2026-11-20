//! Local-only differential policy test. NEVER load into controller agent.
//! The legacy modules are verbatim developer source with ONLY Utc::now replaced
//! by a deterministic test clock. The installer independently pins their hashes.
use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::env;
use std::io::{self, Read};

#[path = "../cloud/config_semantics.rs"]
mod config_semantics;
#[path = "../cloud/config_decision_offline.rs"]
mod config_decision_offline;

mod test_clock {
    use chrono::{DateTime, Utc};
    use std::cell::RefCell;
    thread_local! { static FIXED_UTC: RefCell<Option<DateTime<Utc>>> = const { RefCell::new(None) }; }
    pub fn set(at: DateTime<Utc>) { FIXED_UTC.with(|v| *v.borrow_mut() = Some(at)); }
    pub fn now() -> DateTime<Utc> {
        FIXED_UTC.with(|v| v.borrow().as_ref().expect("offline test clock not initialized").to_owned())
    }
}

// Preserved copies of original source, with only the clock substitution.
mod legacy {
    pub mod schedule { include!("../cloud/hlaxs_policy_ref_schedule.rs"); }
    pub mod engine { include!("../cloud/hlaxs_policy_ref_engine.rs"); }
}

const CONTROLLER: &str = "2722691f-f4db-4f42-b63d-dac94b06ec9e";
const V6_SHA: &str = "3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e";
const PROFILE: &str = "HNX-HW-SP-ACP4WR6-R1";
const T: &str = "2026-10-19T13:30:00Z"; // Monday, 09:30 America/New_York

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expectation { Parity, SafetyDelta }

#[derive(Debug)]
struct Case {
    name: &'static str,
    cfg: Value,
    reader: u64,
    facility: u64,
    card: u64,
    at: &'static str,
    expected: Expectation,
}

fn as_list<'a>(cfg: &'a Value, section: &str) -> Result<&'a Vec<Value>> {
    cfg.get(section).and_then(Value::as_array).ok_or_else(|| anyhow!("invalid synthetic {}", section))
}
fn s<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or_else(|| anyhow!("missing synthetic {}",key))
}
fn b(v: &Value, key: &str) -> i64 { if v.get(key).and_then(Value::as_bool)==Some(true) { 1 } else { 0 } }
fn opt_s(v: &Value, key: &str) -> Option<String> { v.get(key).and_then(Value::as_str).map(str::to_owned) }

/// This is an ephemeral in-memory projection of validated JSON onto the exact
/// tables/columns queried by the checked-in legacy source. It is NOT the
/// production SQLite DB and does not initialize monitor.service or GPIO.
fn project_to_legacy(cfg: &Value) -> Result<Connection> {
    let db=Connection::open_in_memory()?;
    db.execute_batch(r#"
        CREATE TABLE door_config (channel INTEGER PRIMARY KEY,name TEXT NOT NULL,enabled INTEGER NOT NULL);
        CREATE TABLE credentials (id TEXT PRIMARY KEY, facility_code INTEGER NOT NULL, card_code INTEGER NOT NULL,
            enabled INTEGER NOT NULL, holder_name TEXT, valid_from TEXT,valid_until TEXT,
            UNIQUE(facility_code,card_code));
        CREATE TABLE access_levels (id TEXT PRIMARY KEY,name TEXT NOT NULL,enabled INTEGER NOT NULL);
        CREATE TABLE credential_access_levels (credential_id TEXT NOT NULL,access_level_id TEXT NOT NULL,
            PRIMARY KEY(credential_id,access_level_id));
        CREATE TABLE access_level_doors (access_level_id TEXT NOT NULL,channel INTEGER NOT NULL,schedule_id TEXT,
            PRIMARY KEY(access_level_id,channel));
        CREATE TABLE schedules (id TEXT PRIMARY KEY,timezone TEXT NOT NULL,definition_json TEXT NOT NULL);
        CREATE TABLE holidays (id TEXT PRIMARY KEY,holiday_date TEXT NOT NULL,behavior TEXT NOT NULL,schedule_id TEXT);
    "#)?;
    for d in as_list(cfg,"doors")? {
        db.execute("INSERT INTO door_config (channel,name,enabled) VALUES(?1,?2,?3)",
            params![d.get("channel").and_then(Value::as_u64).context("door channel")?,s(d,"name")?,b(d,"enabled")])?;
    }
    for c in as_list(cfg,"credentials")? {
        db.execute("INSERT INTO credentials (id,facility_code,card_code,enabled,holder_name,valid_from,valid_until) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![s(c,"id")?,c.get("facility_code").and_then(Value::as_u64).context("facility")?,
                c.get("card_code").and_then(Value::as_u64).context("card")?,b(c,"enabled"),
                opt_s(c,"holder_name"),opt_s(c,"valid_from"),opt_s(c,"valid_until")])?;
    }
    for lvl in as_list(cfg,"access_levels")? {
        db.execute("INSERT INTO access_levels (id,name,enabled) VALUES(?1,?2,?3)",
            params![s(lvl,"id")?,s(lvl,"name")?,b(lvl,"enabled")])?;
    }
    for l in as_list(cfg,"credential_access_levels")? {
        db.execute("INSERT INTO credential_access_levels(credential_id,access_level_id) VALUES(?1,?2)",
            params![s(l,"credential_id")?,s(l,"access_level_id")?])?;
    }
    for l in as_list(cfg,"access_level_doors")? {
        db.execute("INSERT INTO access_level_doors(access_level_id,channel,schedule_id) VALUES(?1,?2,?3)",
            params![s(l,"access_level_id")?,l.get("channel").and_then(Value::as_u64).context("link channel")?,opt_s(l,"schedule_id")])?;
    }
    for schedule in as_list(cfg,"schedules")? {
        db.execute("INSERT INTO schedules (id,timezone,definition_json) VALUES(?1,?2,?3)",
            params![s(schedule,"id")?,s(schedule,"timezone")?,
                serde_json::to_string(schedule.get("definition").context("definition")?)?])?;
    }
    for (i,holiday) in as_list(cfg,"holidays")?.iter().enumerate() {
        let id=opt_s(holiday,"id").unwrap_or_else(||format!("h{i}"));
        db.execute("INSERT INTO holidays (id,holiday_date,behavior,schedule_id) VALUES(?1,?2,?3,?4)",
            params![id,s(holiday,"holiday_date")?,s(holiday,"behavior")?,
                opt_s(holiday,"override_schedule_id").or_else(||opt_s(holiday,"schedule_id"))])?;
    }
    Ok(db)
}

fn baseline() -> Value {
    json!({
        "doors":[
            {"channel":0,"name":"Test D0","enabled":true,"unlock_ms":5000},
            {"channel":1,"name":"Test D1","enabled":true,"unlock_ms":5000},
            {"channel":2,"name":"Test D2","enabled":true,"unlock_ms":5000},
            {"channel":3,"name":"Test D3","enabled":true,"unlock_ms":5000}],
        "readers":[{"reader_number":1,"protocol":"wiegand","configuration":{
            "d0":{"chip":"gpiochip3","line":23},"d1":{"chip":"gpiochip3","line":25},"format":"Wiegand-26"}}],
        "inputs":[],"outputs":[],"credentials":[{"id":"test-credential","enabled":true,
            "facility_code":41,"card_code":1234,"valid_from":"2026-10-01T00:00:00Z",
            "valid_until":"2026-12-01T00:00:00Z"}],
        "access_levels":[{"id":"test-level","name":"Synthetic Level","enabled":true}],
        "credential_access_levels":[{"credential_id":"test-credential","access_level_id":"test-level"}],
        "access_level_doors":[{"access_level_id":"test-level","channel":0,"schedule_id":"test-schedule"}],
        "schedules":[{"id":"test-schedule","name":"Test 24x7","timezone":"America/New_York","definition":{"always":true}}],
        "holidays":[],"access_rules":[],"settings":{}
    })
}
fn case(name:&'static str,cfg:Value,expected:Expectation) -> Case {
    Case {name,cfg,expected,reader:1,facility:41,card:1234,at:T}
}
fn scenarios() -> Vec<Case> {
    use Expectation::{Parity,SafetyDelta};
    let mut out=Vec::new();
    out.push(case("baseline_24x7",baseline(),Parity));
    { let mut c=baseline(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"09:00","end":"17:00"}]}); out.push(case("weekly_inside",c,Parity)); }
    { let mut c=baseline(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"10:00","end":"17:00"}]}); out.push(case("weekly_outside",c,Parity)); }
    { let mut c=baseline(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"09:00","end":"09:30"}]}); out.push(case("end_exclusive",c,Parity)); }
    { let mut c=baseline(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"00:00","end":"24:00"}]}); out.push(case("full_day",c,Parity)); }
    { let mut c=baseline(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"23:00","end":"02:00"}]}); let mut x=case("overnight_carry",c,Parity);x.at="2026-10-20T05:00:00Z";out.push(x); }
    { let mut c=baseline(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"23:00","end":"02:00"}]});out.push(case("overnight_outside",c,Parity)); }
    { let mut c=baseline(); c["schedules"][0]["definition"]=json!({"sunday":[{"start":"01:00","end":"01:30"}]});
      let mut x=case("dst_fall_first",c.clone(),Parity);x.at="2026-11-01T05:15:00Z";out.push(x);
      let mut x=case("dst_fall_second",c.clone(),Parity);x.at="2026-11-01T06:15:00Z";out.push(x);
      let mut x=case("dst_fall_outside",c,Parity);x.at="2026-11-01T07:15:00Z";out.push(x); }
    { let mut c=baseline();c["holidays"]=json!([{"id":"holiday1","holiday_date":"2026-10-19","behavior":"deny"}]);out.push(case("holiday_deny",c,Parity)); }
    { let mut c=baseline();c["schedules"][0]["definition"]=json!({"monday":[]});c["holidays"]=json!([{"id":"holiday1","holiday_date":"2026-10-19","behavior":"allow"}]);out.push(case("holiday_allow",c,Parity)); }
    { let mut c=baseline();c["schedules"][0]["definition"]=json!({"monday":[]});c["schedules"].as_array_mut().unwrap().push(json!({"id":"other-schedule","name":"Override","timezone":"America/New_York","definition":{"always":true}}));c["holidays"]=json!([{"id":"holiday1","holiday_date":"2026-10-19","behavior":"use_schedule","schedule_id":"other-schedule"}]);out.push(case("holiday_override",c,Parity)); }
    { let mut c=baseline();c["credentials"][0]["enabled"]=json!(false);out.push(case("disabled_credential",c,Parity)); }
    { let mut c=baseline();c["access_levels"][0]["enabled"]=json!(false);out.push(case("disabled_access_level",c,Parity)); }
    { let mut c=baseline();c["doors"][0]["enabled"]=json!(false);out.push(case("disabled_door",c,Parity)); }
    { let mut c=baseline();c["credential_access_levels"]=json!([]);out.push(case("missing_membership",c,Parity)); }
    { let mut c=baseline();c["access_level_doors"]=json!([]);out.push(case("missing_door_permission",c,Parity)); }
    { let mut x=case("unknown_facility",baseline(),Parity);x.facility=42;out.push(x); }
    { let mut x=case("unknown_card",baseline(),Parity);x.card=7777;out.push(x); }
    { let mut x=case("not_yet_valid",baseline(),Parity);x.at="2026-09-30T23:59:59Z";out.push(x); }
    { let mut x=case("expired",baseline(),Parity);x.at="2026-12-01T00:00:00Z";out.push(x); }
    { let mut c=baseline();c["schedules"][0]["definition"]=json!({"monday":[]});out.push(case("no_matching_schedule",c,Parity)); }
    { let mut c=baseline();c["access_level_doors"][0]["schedule_id"]=Value::Null;out.push(case("no_schedule_no_holidays",c,Parity)); }
    // The following differences are INTENTIONAL gates requiring user review.
    { let mut c=baseline();c["access_level_doors"][0]["schedule_id"]=Value::Null;c["holidays"]=json!([{"id":"holiday1","holiday_date":"2026-10-19","behavior":"deny"}]);out.push(case("delta_unscheduled_holiday_deny",c,SafetyDelta)); }
    { let mut c=baseline();c["readers"][0]["enabled"]=json!(false);out.push(case("delta_disabled_reader_not_checked_by_legacy",c,SafetyDelta)); }
    { let mut c=baseline();c["readers"]=json!([]);out.push(case("delta_missing_reader_not_checked_by_legacy",c,SafetyDelta)); }
    { let mut c=baseline();c["readers"][0]["door_channel"]=json!(1);out.push(case("delta_bad_reader_door_claim",c,SafetyDelta)); }
    // No access path permitted on door1, even though the legacy knows the door.
    { let mut x=case("other_door_no_grant",baseline(),Parity);x.reader=2;out.push(x); }
    out
}

struct Outcome { modern: bool, legacy: bool, legacy_reason: String, modern_reason: &'static str }
fn compare(cfg:&Value,reader:u64,facility:u64,card:u64,at:DateTime<Utc>)->Result<Outcome> {
    ensure!((1..=4).contains(&reader),"test reader channel outside synthetic range");
    ensure!(facility<=u8::MAX as u64 && card<=u16::MAX as u64, "test credential outside legacy type range");
    test_clock::set(at);
    let db=project_to_legacy(cfg)?;
    let legacy=legacy::engine::evaluate(&db,facility as u8,card as u16,(reader-1) as u8)?;
    let old=matches!(legacy.decision,legacy::engine::AccessDecision::Grant);
    let modern=config_decision_offline::evaluate(cfg,&config_decision_offline::Probe{reader_number:reader,facility_code:facility,card_code:card,at_utc:at});
    Ok(Outcome{modern:modern.allowed,legacy:old,legacy_reason:legacy.reason,modern_reason:modern.reason})
}
fn validate_case(c:&Case)->Result<bool> {
    let at:DateTime<Utc>=c.at.parse().context("invalid fixture UTC")?;
    let o=compare(&c.cfg,c.reader,c.facility,c.card,at)?;
    // Strongest security invariant: a new grant rejected by the legacy is a hard stop.
    if o.modern && !o.legacy { bail!("UNSAFE POLICY DRIFT in scenario {}: new grant vs legacy deny",c.name); }
    match c.expected {
        Expectation::Parity => ensure!(o.modern==o.legacy,"POLICY DRIFT in {}: legacy {}, new {} (legacy_reason={},modern_reason={})",c.name,o.legacy,o.modern,o.legacy_reason,o.modern_reason),
        Expectation::SafetyDelta => ensure!(!o.modern && o.legacy,"expected conservative difference not reproduced in {}: legacy {}, new {}",c.name,o.legacy,o.modern),
    }
    Ok(c.expected == Expectation::SafetyDelta)
}
fn fixture_gate()->Result<()> {
    let all=scenarios();
    let mut parity=0;
    let mut deltas=Vec::new();
    for c in &all {
        if validate_case(c)? { deltas.push(c.name); } else { parity+=1; }
    }
    println!("PASS: legacy source vs new evaluator: {parity} strict-parity scenarios, zero new grants opposed by legacy");
    for label in &deltas { println!("REVIEW_REQUIRED: conservative policy difference: {label} (legacy grant; offline deny)"); }
    println!("PASS: {} intentionally conservative differences isolated for explicit review",deltas.len());
    Ok(())
}
fn real_v6_gate(envelope:Value)->Result<()> {
    ensure!(envelope.get("version").and_then(Value::as_u64)==Some(6),"unexpected version");
    ensure!(envelope.get("controller_id").and_then(Value::as_str)==Some(CONTROLLER),"unexpected controller identity");
    ensure!(envelope.get("hardware_profile").and_then(Value::as_str)==Some(PROFILE),"unexpected hardware profile");
    ensure!(envelope.get("checksum").and_then(Value::as_str)==Some(V6_SHA),"unexpected config digest");
    let cfg=envelope.get("configuration").context("missing real configuration")?;
    ensure!(config_semantics::checksum(cfg)?==V6_SHA,"real config canonical checksum mismatch");
    config_semantics::validate_configuration(cfg)?;
    let at:DateTime<Utc>="2026-10-19T19:30:00Z".parse()?;
    let cards=as_list(cfg,"credentials")?;
    let card=cards.first().context("immutable v6 credential fixture absent")?;
    let facility=card.get("facility_code").and_then(Value::as_u64).context("facility")?;
    let code=card.get("card_code").and_then(Value::as_u64).context("card number")?;
    let o=compare(cfg,1,facility,code,at)?;
    ensure!(!(o.modern&&!o.legacy),"real-v6 unsafe policy drift: new grant vs legacy deny");
    ensure!(o.modern==o.legacy,"real-v6 policy difference; do not reconcile automatically");
    println!("PASS: real pinned v6 comparison at fixed time: legacy and new decisions agree; identities redacted");
    // Differential on a local clone only, no cloud/production updates.
    let mut disabled=cfg.clone();
    for credential in disabled.get_mut("credentials").and_then(Value::as_array_mut).context("credentials")? {
        if credential.get("facility_code").and_then(Value::as_u64)==Some(facility)
        && credential.get("card_code").and_then(Value::as_u64)==Some(code) {
            credential["enabled"]=json!(false);
        }
    }
    let deny=compare(&disabled,1,facility,code,at)?;
    ensure!(!deny.modern && !deny.legacy,"real-v6 disabled clone unexpectedly granted");
    println!("PASS: real v6 disabled-credential clone denied by both engines");
    Ok(())
}
fn run()->Result<()> {
    ensure!(env::var("HLAXS_POLICY_CONFORMANCE_OFFLINE_ONLY").as_deref()==Ok("YES"),"offline guard required");
    let args:Vec<String>=env::args().collect();
    ensure!(args.len()==1 || (args.len()==2 && args[1]=="--read-only-v6-stdin"),"only optional read-only snapshot mode supported");
    fixture_gate()?;
    if args.len()==2 {
        let mut input=Vec::new();
        io::stdin().take(2*1024*1024+1).read_to_end(&mut input)?;
        ensure!(!input.is_empty() && input.len()<=2*1024*1024,"invalid envelope size");
        let envelope:Value=serde_json::from_slice(&input).context("invalid real snapshot envelope")?;
        real_v6_gate(envelope)?;
    }
    println!("RESULT: local reference-engine conformance completed. No controller, physical I/O, cloud ACK, or persistent database operations.");
    Ok(())
}
fn main(){
    let real_mode=std::env::args().any(|a| a == "--read-only-v6-stdin");
    if let Err(e)=run() {
        // Never emit identities or payload details in real snapshot mode.
        if real_mode {
            eprintln!("STOP: pinned read-only configuration parity failed; details redacted");
        } else {
            eprintln!("STOP: synthetic offline policy test failed: {e}");
        }
        std::process::exit(2);
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn legacy_fixture_comparison_gate() { fixture_gate().unwrap(); }
    #[test] fn expected_safety_deltas_are_deny_only() {
        for c in scenarios().iter().filter(|x|x.expected==Expectation::SafetyDelta) {
            assert!(validate_case(c).unwrap(),"expected a delta: {}",c.name);
        }
    }
    #[test] fn clock_is_repeatable() {
        let at:DateTime<Utc>=T.parse().unwrap();
        let a=compare(&baseline(),1,41,1234,at).unwrap();
        let b=compare(&baseline(),1,41,1234,at).unwrap();
        assert_eq!(a.modern,b.modern);assert_eq!(a.legacy,b.legacy);
    }
}
