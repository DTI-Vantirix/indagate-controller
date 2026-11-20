//! Developer-only authenticated synthetic reader -> durable mock proposal.
//! No device services, GPIO, HAL, relays, cloud control or production databases.
#[path = "../cloud/config_semantics.rs"]
mod config_semantics;
#[path = "../cloud/config_decision_offline.rs"]
mod config_decision_offline;
#[path = "../cloud/config_policy_hardening.rs"]
mod config_policy_hardening;
#[path = "../cloud/config_mock_action.rs"]
mod config_mock_action;
#[path = "../cloud/config_durable_reader_offline.rs"]
mod config_durable_reader_offline;

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Duration, Utc};
use config_mock_action::{MockAuthority,MockRequest,CONTRACT_VERSION,POLICY_VERSION};
use config_policy_hardening::MockSnapshot;
use config_durable_reader_offline::{ReaderBinding,ReaderKeyring,SignedFrame,SyntheticDurableJournal};
use rusqlite::Connection;
use serde_json::Value;
use std::{env,io::{self,Read}};
use uuid::Uuid;

const SP4_ID:&str="2722691f-f4db-4f42-b63d-dac94b06ec9e";
const V6_SHA:&str="3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e";
const SP4_PROFILE:&str="HNX-HW-SP-ACP4WR6-R1";
const FIXED_UTC:&str="2026-10-19T19:30:00Z";
const MAX_INPUT:usize=2*1024*1024;
fn event(a:&MockAuthority,number:u128,nonce:u64,facility:u64,card:u64,now:DateTime<Utc>,binding:&ReaderBinding)->Result<SignedFrame>{
    let request=MockRequest {event_id:Uuid::from_u128(number).to_string(),
        controller_id:a.controller_id.clone(),tenant_id:a.tenant_id.clone(),site_id:a.site_id.clone(),
        contract_version:CONTRACT_VERSION.into(),policy_version:POLICY_VERSION.into(),
        generation:a.generation,expected_version:a.snapshot.version,
        expected_checksum:a.snapshot.checksum.clone(),reader_number:1,
        facility_code:facility,card_code:card,
        captured_at:now,expires_at:now+Duration::milliseconds(2500)};
    SignedFrame::sign_dummy(request,nonce,binding)
}
fn inspect(config:Value,version:u64,pin:&str,real:bool)->Result<()> {
    let snapshot=MockSnapshot::build(version,config)?;
    ensure!(snapshot.checksum==pin,"offline snapshot checksum mismatch");
    let authority=MockAuthority{controller_id:SP4_ID.into(),tenant_id:"isolated-test-tenant".into(),
        site_id:"isolated-test-site".into(),generation:41,snapshot};
    ensure!(authority.trusted(),"untrusted isolated mock authority");
    let credential=authority.snapshot.config.get("credentials").and_then(Value::as_array)
        .and_then(|a|a.first()).context("no offline credential")?;
    let facility=credential.get("facility_code").and_then(Value::as_u64).context("missing offline facility")?;
    let card=credential.get("card_code").and_then(Value::as_u64).context("missing offline card")?;
    let now:DateTime<Utc>=FIXED_UTC.parse()?;
    let reader=ReaderBinding::dummy("dummy-reader-key-001",&authority,1,[0x42;32]);
    let mut ring=ReaderKeyring::new();ring.enroll_dummy(reader.clone())?;
    // Purely in-memory SQLite: the real SP4 payload and card never touch disk.
    let mut journal=SyntheticDurableJournal::open(Connection::open_in_memory()?)?;
    journal.initialize(&authority)?;
    let good=event(&authority,1001,1001,facility,card,now,&reader)?;
    let result=journal.process(&authority,&ring,good.clone(),now,false);
    ensure!(result.proposed,"expected one synthetic mock proposal");
    ensure!(!journal.process(&authority,&ring,good,now,false).proposed,"duplicate should fail closed");
    let mut tampered=event(&authority,1002,1002,facility,card,now,&reader)?;
    tampered.request.facility_code=65536;
    ensure!(!journal.process(&authority,&ring,tampered,now,false).proposed,"tampered synthetic event authorized");
    let invalid=event(&authority,1003,1003,facility,65536,now,&reader)?;
    ensure!(!journal.process(&authority,&ring,invalid,now,false).proposed,"invalid Wiegand authorized");
    let interrupted=event(&authority,1004,1004,facility,card,now,&reader)?;
    ensure!(!journal.process(&authority,&ring,interrupted.clone(),now,true).proposed,"interrupted synthetic event authorized");
    ensure!(!journal.process(&authority,&ring,interrupted,now,false).proposed,"interrupted event replay authorized");
    ensure!(journal.count()?==3,"unexpected count of isolated durable mock events");
    if real {println!("PASS: pinned real SP4 v6 checksum and semantics with synthetic reader test keys; read-only payload in memory");}
    else {println!("PASS: synthetic-only configuration and mock reader event authentication");}
    println!("PASS: single non-executable mock proposal; duplicate, tampered, invalid Wiegand and interrupted/replayed event denied");
    println!("PASS: SQLite replay journal checked in-memory; no real credentials or card identifiers logged");
    println!("RESULT: durable synthetic reader mock acceptance PASSED; NO physical actions, cloud writes, cloud ACK, device command or runtime integration.");
    Ok(())
}
fn main()->Result<()> {
    ensure!(env::var("HLAXS_DURABLE_READER_OFFLINE_ONLY").ok().as_deref()==Some("YES"),
            "standalone HLAXS_DURABLE_READER_OFFLINE_ONLY=YES gate required");
    let args:Vec<_>=env::args().collect();ensure!(args.len()==2,"expected one standalone fixture or stdin mode");
    match args[1].as_str() {
        "--fixture"=>{
            let config=config_policy_hardening::synthetic_fixture();
            let pin=config_semantics::checksum(&config)?;
            inspect(config,6,&pin,false)
        },
        "--real-v6-stdin"=>{
            let mut bytes=Vec::new();
            io::stdin().take((MAX_INPUT+1) as u64).read_to_end(&mut bytes)?;
            ensure!(!bytes.is_empty()&&bytes.len()<=MAX_INPUT,"offline v6 envelope size invalid");
            let envelope:Value=serde_json::from_slice(&bytes).context("invalid offline JSON envelope")?;
            ensure!(envelope.get("controller_id").and_then(Value::as_str)==Some(SP4_ID),"SP4 identity mismatch");
            ensure!(envelope.get("hardware_profile").and_then(Value::as_str)==Some(SP4_PROFILE),"hardware profile mismatch");
            ensure!(envelope.get("version").and_then(Value::as_u64)==Some(6),"SP4 version mismatch");
            ensure!(envelope.get("checksum").and_then(Value::as_str)==Some(V6_SHA),"SP4 checksum mismatch");
            inspect(envelope.get("configuration").context("configuration missing")?.clone(),6,V6_SHA,true)
        },
        _=>bail!("unsupported standalone mode"),
    }
}
