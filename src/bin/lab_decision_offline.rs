//! Independent WSL developer-only decision test executable. No external writes.
//! Build ONLY locally. It is not registered or invoked by the SP4 agent.
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::env;
use std::io::{self, Read};

#[path = "../cloud/config_semantics.rs"]
mod config_semantics;
#[path = "../cloud/config_decision_offline.rs"]
mod config_decision_offline;
use config_decision_offline::{Probe, evaluate};

const MAX_BYTES: u64 = 2 * 1024 * 1024 + 1;
const ID: &str = "HNX-HW-SP-ACP4WR6-R1";
const SHA: &str = "3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e";

fn run() -> Result<()> {
    ensure!(env::var("HLAXS_DECISION_OFFLINE_ONLY").as_deref()==Ok("YES"), "offline-only guard not enabled");
    ensure!(env::args().len()==1, "this executable takes no commands, paths, or physical options");
    let mut input=Vec::new();
    io::stdin().take(MAX_BYTES).read_to_end(&mut input)?;
    ensure!(!input.is_empty() && (input.len() as u64) < MAX_BYTES, "missing or oversized input");
    let envelope:Value=serde_json::from_slice(&input).context("invalid JSON envelope")?;
    ensure!(envelope.get("version").and_then(Value::as_u64)==Some(6),"not the pinned v6 snapshot");
    ensure!(envelope.get("hardware_profile").and_then(Value::as_str)==Some(ID),"wrong board model");
    ensure!(envelope.get("checksum").and_then(Value::as_str)==Some(SHA),"wrong immutable snapshot checksum");
    let cfg=envelope.get("configuration").context("missing configuration")?;
    ensure!(config_semantics::checksum(cfg)?==SHA,"snapshot checksum integrity mismatch");
    let summary=config_semantics::validate_configuration(cfg)?;
    let at:DateTime<Utc>="2026-10-19T19:30:00Z".parse()?;
    // Run one arbitrary nonmatch probe so unsupported schedule/holiday
    // semantics fail closed before touching even the local decision path.
    let health=evaluate(cfg,&Probe{reader_number:1,facility_code:255,card_code:65535,at_utc:at});
    ensure!(health.reason!="configuration_invalid","unsupported offline schedule/holiday definitions");
    println!("PASS: immutable real v6 checksum + semantic schema; doors={} readers={} inputs={} outputs={} schedules={} holidays={}",
        summary.doors,summary.readers,summary.inputs,summary.outputs,summary.schedules,summary.holidays);

    // Find an *existing* sample credential without ever printing it. The
    // real snapshot may legitimately DENY because it has expired or lacks a
    // door permission; neither is a failure of the offline reference engine.
    if let Some(sample)=cfg.get("credentials").and_then(Value::as_array).and_then(|v| v.first()) {
        if let (Some(facility), Some(card)) = (sample.get("facility_code").and_then(Value::as_u64), sample.get("card_code").and_then(Value::as_u64)) {
            let req=Probe { reader_number:1, facility_code:facility, card_code:card, at_utc:at };
            let baseline=evaluate(cfg,&req);
            println!("PASS: real v6 offline credential probe completed; simulated result={} reason={} (no identity logged)",
                if baseline.allowed {"grant"} else {"deny"}, baseline.reason);
            let bad=Probe{facility_code:256,..req};
            let blocked=evaluate(cfg,&bad);
            ensure!(!blocked.allowed && blocked.reason=="credential_invalid_format", "out-of-range credential did not fail closed");
            let mut modified=cfg.clone();
            let matching=modified.get_mut("credentials").and_then(Value::as_array_mut)
                .and_then(|c|c.iter_mut().find(|v| v.get("facility_code").and_then(Value::as_u64)==Some(facility)
                    && v.get("card_code").and_then(Value::as_u64)==Some(card)))
                .context("sample credential disappeared from local clone")?;
            matching["enabled"]=json!(false);
            let blocked=evaluate(&modified,&req);
            // If the door is disabled or no link exists, it may return an
            // earlier DENY reason. Never relax policy to make the test pass.
            ensure!(!blocked.allowed,"simulated disabled credential received a grant");
            println!("PASS: actual v6 input rejected invalid Wiegand-26 values and synthetic disabled-credential mutation");
        }
    }
    println!("RESULT: real v6 offline access-policy evaluation and deny-by-default probes completed. NO physical apply, I/O, cloud ACK or controller service.");
    Ok(())
}
fn main() {
    if let Err(_error) = run() {
        // Do not log credentials or detailed parsed input; callers receive
        // only a fixed failure marker. Rust unit test diagnostics are separate.
        eprintln!("STOP: offline evaluator acceptance failed (details suppressed)");
        std::process::exit(2);
    }
}
