//! Indagate Access developer-only simulated decision -> mock proposal -> memory sink.
//! NOT registered with controller main, cloud agent, HAL or any physical output.
#[path = "../cloud/config_semantics.rs"]
mod config_semantics;
#[path = "../cloud/config_decision_offline.rs"]
mod config_decision_offline;
#[path = "../cloud/config_policy_hardening.rs"]
mod config_policy_hardening;
#[path = "../cloud/config_mock_action.rs"]
mod config_mock_action;

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::{env,io::{self,Read}};
use uuid::Uuid;
use config_mock_action::{MockAuthority, MockRequest, MockRouter, MockSink, CONTRACT_VERSION, POLICY_VERSION};
use config_policy_hardening::MockSnapshot;

const SP4_ID:&str="2722691f-f4db-4f42-b63d-dac94b06ec9e";
const V6_SHA:&str="3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e";
const SP4_PROFILE:&str="HNX-HW-SP-ACP4WR6-R1";
const MAX_INPUT:usize=2*1024*1024;
const FIXED_UTC:&str="2026-10-19T19:30:00Z";

fn build_request(authority:&MockAuthority, id:u128,reader:u64,facility:u64,card:u64,now:DateTime<Utc>)->MockRequest {
    MockRequest {event_id:Uuid::from_u128(id).to_string(),controller_id:authority.controller_id.clone(),
      tenant_id:authority.tenant_id.clone(),site_id:authority.site_id.clone(),
      contract_version:CONTRACT_VERSION.into(),policy_version:POLICY_VERSION.into(),
      generation:authority.generation,expected_version:authority.snapshot.version,
      expected_checksum:authority.snapshot.checksum.clone(),reader_number:reader,
      facility_code:facility,card_code:card,captured_at:now,expires_at:now+Duration::milliseconds(2500)}
}

fn inspect(config:Value,version:u64,pinned_sha:&str,fixture:bool)->Result<()> {
    let snapshot=MockSnapshot::build(version,config)?;
    ensure!(snapshot.checksum==pinned_sha,"snapshot pinned checksum mismatch");
    let authority=MockAuthority {controller_id:SP4_ID.to_string(),tenant_id:"offline-test-tenant".into(),
       site_id:"offline-test-site".into(),generation:17,snapshot};
    ensure!(authority.trusted(),"untrusted offline authority");
    let credential=authority.snapshot.config.get("credentials")
        .and_then(Value::as_array).and_then(|v|v.first()).context("no fixture credential")?;
    let facility=credential.get("facility_code").and_then(Value::as_u64).context("fixture facility missing")?;
    let card=credential.get("card_code").and_then(Value::as_u64).context("fixture card missing")?;
    let now:DateTime<Utc>=FIXED_UTC.parse()?;
    let mut router=MockRouter::default();let mut sink=MockSink::default();
    let mut grants=0;
    let mut all_proposals=0;
    for reader in 1..=4 {
        let event=build_request(&authority,1000+reader as u128,reader,facility,card,now);
        let first=router.propose(&authority,event.clone(),now);
        if let Some(intent)=first.intent {
            all_proposals+=1;
            let recorded=sink.consume(&intent,&authority,now);
            ensure!(recorded.proposed,"mock sink refused a valid bound proposal");
            grants+=1;
            ensure!(!sink.consume(&intent,&authority,now).proposed,"mock sink replay accepted");
        }
        let replay=router.propose(&authority,event,now);
        ensure!(!replay.receipt.proposed && replay.intent.is_none(),"event replay accepted");
    }
    ensure!(grants==1 && all_proposals==1,"expected exactly one authorized mock reader for pinned fixture");
    let mut bad=build_request(&authority,2001,1,facility,65536,now);
    ensure!(!router.propose(&authority,bad.clone(),now).receipt.proposed,"invalid Wiegand value authorized");
    bad.event_id=Uuid::from_u128(2002).to_string();bad.card_code=card;bad.generation+=1;
    ensure!(!router.propose(&authority,bad.clone(),now).receipt.proposed,"stale generation authorized");
    bad.event_id=Uuid::from_u128(2003).to_string();bad.generation=authority.generation;
    bad.expected_checksum="bad".into();
    ensure!(!router.propose(&authority,bad,now).receipt.proposed,"checksum mismatch authorized");
    ensure!(sink.count()==2,"unexpected number of mock-only sink receipts");
    if fixture {println!("PASS: synthetic policy-to-proposal contract, scope, time and replay checks");}
    else {println!("PASS: real pinned SP4 v6 semantic+checksum; redacted mock-only proposal checks");}
    println!("PASS: invalid Wiegand, changed epoch and bad digest denied");
    println!("PASS: one NON-EXECUTABLE in-memory proposal and replay rejection; no identifiers printed");
    println!("RESULT: hardware-disconnected mock action contract ACCEPTED; NO physical outputs, device command, controller runtime, cloud ACK or production database writes.");
    Ok(())
}
fn main()->Result<()> {
    ensure!(env::var("HLAXS_MOCK_ACTION_OFFLINE_ONLY").ok().as_deref()==Some("YES"),
       "developer-only HLAXS_MOCK_ACTION_OFFLINE_ONLY=YES gate required");
    let args:Vec<_>=env::args().collect();ensure!(args.len()==2,"expected exactly one explicit offline mode");
    match args[1].as_str() {
        "--fixture"=>{
            let cfg=config_policy_hardening::synthetic_fixture();
            let sha=config_semantics::checksum(&cfg)?;
            inspect(cfg,6,&sha,true)
        }
        "--real-v6-stdin"=>{
            let mut bytes=Vec::new();
            io::stdin().take((MAX_INPUT+1) as u64).read_to_end(&mut bytes)?;
            ensure!(!bytes.is_empty()&&bytes.len()<=MAX_INPUT,"snapshot envelope size invalid");
            let env:Value=serde_json::from_slice(&bytes).context("invalid local JSON envelope")?;
            ensure!(env.get("controller_id").and_then(Value::as_str)==Some(SP4_ID),"controller identity mismatch");
            ensure!(env.get("hardware_profile").and_then(Value::as_str)==Some(SP4_PROFILE),"hardware profile mismatch");
            ensure!(env.get("version").and_then(Value::as_u64)==Some(6),"version pin mismatch");
            ensure!(env.get("checksum").and_then(Value::as_str)==Some(V6_SHA),"checksum pin mismatch");
            inspect(env.get("configuration").context("configuration missing")?.clone(),6,V6_SHA,false)
        }
        _=>bail!("not an approved mock-only CLI mode"),
    }
}
