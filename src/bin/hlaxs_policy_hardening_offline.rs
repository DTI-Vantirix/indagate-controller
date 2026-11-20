//! Standalone local-only SP4 policy hardening and mock output receipt test CLI.
//! Do not register this file in main.rs, cloud/mod.rs or device cloud agent.
#[path = "../cloud/config_semantics.rs"]
mod config_semantics;
#[path = "../cloud/config_decision_offline.rs"]
mod config_decision_offline;
#[path = "../cloud/config_policy_hardening.rs"]
mod config_policy_hardening;

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::{env,io::{self,Read}};
use config_policy_hardening::{MockRecorder, MockSnapshot, observe};

const SP4_ID:&str="2722691f-f4db-4f42-b63d-dac94b06ec9e";
const V6_SHA:&str="3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e";
const SP4_PROFILE:&str="HNX-HW-SP-ACP4WR6-R1";
const MAX_INPUT:usize=2*1024*1024;
const FIXED_UTC:&str="2026-10-19T19:30:00Z";

fn analyze(cfg:Value,version:u64,sha:&str,fixture:bool)->Result<()> {
    let snap=MockSnapshot::build(version,cfg)?;
    ensure!(snap.checksum==sha,"snapshot canonical digest does not match pin");
    let cards=snap.config.get("credentials").and_then(Value::as_array).context("missing credentials list")?;
    let card=cards.first().context("no existing fixture credential")?;
    let facility=card.get("facility_code").and_then(Value::as_u64).context("invalid fixture facility number")?;
    let number=card.get("card_code").and_then(Value::as_u64).context("invalid fixture card number")?;
    let at:DateTime<Utc>=FIXED_UTC.parse()?;
    let mut sink=MockRecorder::default();
    let mut grant_count=0;
    for reader in 1..=4 {
        let p=config_decision_offline::Probe{reader_number:reader,facility_code:facility,card_code:number,at_utc:at};
        let r=observe(&snap,version,sha,&p,&mut sink);
        if r.would_grant {grant_count+=1;}
        let bad=config_decision_offline::Probe{card_code:65536,..p};
        ensure!(!observe(&snap,version,sha,&bad,&mut sink).would_grant,"invalid Wiegand-26 values unexpectedly granted");
    }
    let p=config_decision_offline::Probe{reader_number:1,facility_code:facility,card_code:number,at_utc:at};
    ensure!(!observe(&snap,version+1,sha,&p,&mut sink).would_grant,"stale-binding gate broken");
    ensure!(!observe(&snap,version,"0000000000000000000000000000000000000000000000000000000000000000",&p,&mut sink).would_grant,"wrong checksum gate broken");
    let mut disabled=snap.config.clone();
    disabled["credentials"][0]["enabled"]=json!(false);
    let disabled=MockSnapshot::build(version,disabled)?;
    ensure!(!observe(&disabled,version,&disabled.checksum,&p,&mut sink).would_grant,"disabled credential unexpectedly granted");
    ensure!(sink.events.len()==11,"unexpected mock receipt count");
    ensure!(sink.events.iter().all(|r|!r.would_grant || r.door_channel==Some(r.reader-1)),"mock channel mismatch");
    if fixture {
        println!("PASS: synthetic 4-reader policy test: grant/deny receipts recorded IN MEMORY ONLY");
    } else {
        println!("PASS: pinned real SP4 v6 semantic+checksum and offline mock policy requests (redacted)");
    }
    println!("PASS: 4 invalid-card probes denied; stale version, wrong hash and disabled-credential probes denied");
    println!("PASS: 11 redacted in-memory receipts; simulated grant count={grant_count} (NO physical output)");
    println!("RESULT: mock-only decision gate completed. No SP4, relay, GPIO, cloud ACK, config apply or service operation.");
    Ok(())
}

fn main()->Result<()> {
    ensure!(env::var("HLAXS_POLICY_HARDENING_OFFLINE_ONLY").ok().as_deref()==Some("YES"),
        "HLAXS_POLICY_HARDENING_OFFLINE_ONLY=YES must be set for developer-only run");
    let args:Vec<_>=env::args().collect();
    ensure!(args.len()==2,"only --fixture or --real-v6-stdin accepted");
    match args[1].as_str() {
        "--fixture"=>{
            let cfg=config_policy_hardening::synthetic_fixture();
            let sha=config_semantics::checksum(&cfg)?;
            analyze(cfg,6,&sha,true)
        }
        "--real-v6-stdin"=>{
            // Input is piped from the Python read-only snapshot driver, not a CLI path.
            let mut bytes=Vec::new();
            io::stdin().take((MAX_INPUT+1) as u64).read_to_end(&mut bytes)?;
            ensure!(!bytes.is_empty()&&bytes.len()<=MAX_INPUT,"stdin v6 envelope size invalid");
            let envelope:Value=serde_json::from_slice(&bytes).context("invalid local snapshot envelope")?;
            ensure!(envelope.get("controller_id").and_then(Value::as_str)==Some(SP4_ID),"wrong controller ID");
            ensure!(envelope.get("hardware_profile").and_then(Value::as_str)==Some(SP4_PROFILE),"wrong hardware profile");
            ensure!(envelope.get("version").and_then(Value::as_u64)==Some(6),"expected pinned v6 only");
            ensure!(envelope.get("checksum").and_then(Value::as_str)==Some(V6_SHA),"pinned checksum mismatch");
            let cfg=envelope.get("configuration").context("configuration missing")?.clone();
            analyze(cfg,6,V6_SHA,false)
        }
        _=>bail!("unrecognized local-only mode")
    }
}
