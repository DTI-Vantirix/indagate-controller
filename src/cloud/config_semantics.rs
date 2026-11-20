//! HLAXS.Access semantic configuration validator + deterministic, read-only plan.
//!
//! NEVER invoked from the running agent. No GPIO, device commands, production DB,
//! network I/O, cloud ACK, or physical actuation API is present in this module.
//! Data intended for production must still pass hardware commissioning and
//! configuration schema approval. Unmodeled access_rules fail closed.

use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{DateTime, NaiveDate};
use ring::digest::{digest, SHA256};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashSet};

pub const SP4_PROFILE: &str = "HNX-HW-SP-ACP4WR6-R1";
pub const SP4_V6_CHECKSUM: &str = "3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticSummary {
    pub doors: usize,
    pub readers: usize,
    pub inputs: usize,
    pub outputs: usize,
    pub credentials: usize,
    pub access_levels: usize,
    pub schedules: usize,
    pub holidays: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePlan {
    pub base_version: u64,
    pub target_version: u64,
    pub base_checksum: String,
    pub target_checksum: String,
    pub changed_sections: Vec<String>,
    pub fingerprint: String,
}

fn obj<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| anyhow!("{label} must be an object"))
}
fn array<'a>(o: &'a Map<String, Value>, key: &str, required: bool) -> Result<&'a [Value]> {
    match o.get(key) {
        Some(Value::Array(items)) => Ok(items),
        None if !required => Ok(&[]),
        None => bail!("missing required {key} array"),
        _ => bail!("{key} must be an array"),
    }
}
fn id(o: &Map<String, Value>, key: &str, label: &str) -> Result<String> {
    let value = o.get(key).and_then(Value::as_str).unwrap_or("").trim();
    ensure!(!value.is_empty() && value.len() <= 256, "{label}.{key} missing/invalid");
    Ok(value.to_owned())
}
fn reference(o: &Map<String, Value>, key: &str, ids: &HashSet<String>, label: &str) -> Result<()> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if !s.is_empty() && ids.contains(s) => Ok(()),
        _ => bail!("{label}.{key} missing target or wrong type"),
    }
}
fn optional_door_reference(o: &Map<String, Value>, label: &str, door_ids: &HashSet<String>) -> Result<()> {
    if let Some(v) = o.get("door_channel") {
        if !v.is_null() {
            ensure!(v.as_u64().is_some_and(|x| x < 4), "{label} invalid door_channel");
        }
    }
    reference(o, "door_id", door_ids, label)
}
// SP4 v6 records use 1-based hardware numbering, not a top-level channel:
// reader_number (1..4), input_number (1..5), output_number (1..4).
// Door contacts and outputs also carry a 0-based configuration.channel;
// reader configurations do not, and the dedicated fire input must not.
// Do not infer a channel from array position: verify explicit identifiers.
fn pin(config: &Map<String, Value>, field: &str, chip: &str, line: u64, label: &str) -> Result<()> {
    let entry = obj(config.get(field).ok_or_else(|| anyhow!("{label}.{field} missing"))?, label)?;
    ensure!(entry.get("chip").and_then(Value::as_str) == Some(chip)
        && entry.get("line").and_then(Value::as_u64) == Some(line),
        "{label}.{field} does not match the pinned SP4 board profile");
    Ok(())
}
fn channel_for_hardware(
    row: &Map<String, Value>, key: &str, label: &str, limit: u64,
) -> Result<(u64, bool)> {
    let number_key = match key {
        "readers" => "reader_number",
        "inputs" => "input_number",
        "outputs" => "output_number",
        _ => bail!("unsupported resource kind"),
    };
    let numbered = row.get(number_key).is_some();
    let channel = if numbered {
        let number = row.get(number_key).and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("{label}.{number_key} must be a positive integer"))?;
        ensure!(number >= 1 && number <= limit, "{label}.{number_key} outside SP4 port range");
        number - 1
    } else {
        row.get("channel").and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("{label} missing explicit channel or numbered port"))?
    };
    ensure!(channel < limit, "{label} channel outside SP4 capabilities");
    if let Some(explicit) = row.get("channel") {
        ensure!(explicit.as_u64() == Some(channel), "{label} channel conflicts with numbered port");
    }
    let nested = row.get("configuration").map(|v| obj(v, label)).transpose()?;
    if let Some(inner) = nested {
        if let Some(explicit) = inner.get("channel") {
            ensure!(explicit.as_u64() == Some(channel), "{label} configuration.channel conflicts with port");
        }
    }
    // Existing fixed-board rows cannot silently omit the nested channel:
    // readers never had it; fire input has no door channel.
    if numbered && (key == "outputs" || (key == "inputs" && channel < 4)) {
        ensure!(nested.and_then(|c| c.get("channel")).and_then(Value::as_u64) == Some(channel),
            "{label} missing matching configuration.channel");
    }
    if numbered && key == "inputs" && channel == 4 {
        ensure!(nested.is_some_and(|c| c.get("channel").is_none()),
            "{label} fire input cannot claim a door channel");
    }
    Ok((channel, numbered))
}
fn validate_numbered_hardware(
    row: &Map<String, Value>, key: &str, label: &str, channel: u64,
) -> Result<()> {
    let cfg = obj(row.get("configuration")
        .ok_or_else(|| anyhow!("{label}.configuration missing"))?, label)?;
    match key {
        "readers" => {
            let pins = [
                (("gpiochip3", 23), ("gpiochip3", 25)),
                (("gpiochip3", 26), ("gpiochip0", 15)),
                (("gpiochip4", 10), ("gpiochip4", 26)),
                (("gpiochip4", 27), ("gpiochip4", 11)),
            ];
            let (d0,d1) = pins[channel as usize];
            pin(cfg, "d0", d0.0, d0.1, label)?;
            pin(cfg, "d1", d1.0, d1.1, label)?;
            ensure!(cfg.get("format").and_then(Value::as_str) == Some("Wiegand-26"),
                "{label} unsupported reader data format");
            ensure!(cfg.get("channel").is_none(),
                "{label} unexpected nested reader channel; use reader_number");
        }
        "inputs" => {
            let (chip,line,kind) = match channel {
                0 => ("gpiochip4", 12, "door_contact"),
                1 => ("gpiochip0", 8, "door_contact"),
                2 => ("gpiochip4", 28, "door_contact"),
                3 => ("gpiochip4", 29, "door_contact"),
                4 => ("gpiochip3", 21, "fire"),
                _ => bail!("{label} unsupported input"),
            };
            ensure!(row.get("input_type").and_then(Value::as_str) == Some(kind),
                "{label} input_type conflicts with port");
            ensure!(cfg.get("chip").and_then(Value::as_str) == Some(chip)
                && cfg.get("line").and_then(Value::as_u64) == Some(line)
                && cfg.get("active_raw").and_then(Value::as_u64) == Some(0),
                "{label} GPIO descriptor not equal to known SP4 profile");
        }
        "outputs" => {
            ensure!(row.get("output_type").and_then(Value::as_str) == Some("lock_relay"),
                "{label} unsupported output type");
            ensure!(cfg.get("backend").and_then(Value::as_str) == Some("DirectI2c")
                && cfg.get("i2c_device").and_then(Value::as_str) == Some("/dev/i2c-2")
                && cfg.get("address").and_then(Value::as_u64) == Some(32)
                && cfg.get("pca9534_line").and_then(Value::as_u64) == Some(channel + 4)
                && cfg.get("active_high").and_then(Value::as_bool) == Some(true),
                "{label} output descriptor not equal to known SP4 profile");
        }
        _ => bail!("unsupported resource kind"),
    }
    Ok(())
}
fn channels(rows: &[Value], key: &str, limit: u64, door_ids: &HashSet<String>) -> Result<()> {
    ensure!(rows.len() <= limit as usize, "{key} exceeds SP4 capabilities");
    let mut seen = HashSet::new();
    for (index, item) in rows.iter().enumerate() {
        let label = format!("{key}[{index}]");
        let o = obj(item, &label)?;
        let (channel, numbered) = channel_for_hardware(o, key, &label, limit)?;
        ensure!(seen.insert(channel), "{label} duplicate SP4 port assignment");
        optional_door_reference(o, &label, door_ids)?;
        if key == "readers" {
            let protocol = o.get("protocol").and_then(Value::as_str)
                .ok_or_else(|| anyhow!("{label} must declare reader protocol"))?;
            ensure!(protocol.eq_ignore_ascii_case("wiegand"), "{label} protocol not validated for SP4");
            if let Some(enabled) = o.get("enabled") {
                ensure!(enabled.is_boolean(), "{label} enabled must be boolean");
            }
        }
        // Numbered records describe real fixed-board resources. Demand their
        // documented metadata instead of only trusting a number or array slot.
        if numbered { validate_numbered_hardware(o, key, &label, channel)?; }
    }
    Ok(())
}

/// Strictly safe subset of the actual fixed-board and legacy normalized schema.
/// Unknown top-level descriptive metadata can remain, but populated unmodeled
/// access_rules are rejected, not silently assumed valid.
pub fn validate_configuration(config: &Value) -> Result<SemanticSummary> {
    let o = obj(config, "configuration")?;
    let doors = array(o, "doors", true)?;
    ensure!(doors.len() == 4, "SP4 must have exactly four doors");
    let mut seen_doors = HashSet::new();
    let mut door_ids = HashSet::new();
    for (n, door) in doors.iter().enumerate() {
        let label = format!("doors[{n}]");
        let d = obj(door, &label)?;
        let channel = d.get("channel").and_then(Value::as_u64).ok_or_else(|| anyhow!("{label} missing numeric channel"))?;
        ensure!(channel < 4 && seen_doors.insert(channel), "{label} duplicate/out-of-range door channel");
        let name = id(d, "name", &label)?;
        ensure!(name.len() <= 120, "{label} name too long");
        let unlock_ms = match d.get("unlock_ms") {
            Some(Value::Number(n)) => n.as_u64().ok_or_else(|| anyhow!("{label} invalid unlock_ms"))?,
            None => 5000,
            _ => bail!("{label} invalid unlock_ms"),
        };
        ensure!((100..=600_000).contains(&unlock_ms), "{label} unlock duration out of range");
        if let Some(v) = d.get("enabled") { ensure!(v.is_boolean(), "{label} enabled must be boolean"); }
        if let Some(v) = d.get("id") {
            let name = v.as_str().ok_or_else(|| anyhow!("{label} id must be string"))?;
            ensure!(!name.is_empty() && door_ids.insert(name.to_string()), "duplicate/empty door id");
        }
    }
    for channel in 0..4 { ensure!(seen_doors.contains(&channel), "missing SP4 door channel"); }
    let readers = array(o, "readers", true)?;
    let inputs = array(o, "inputs", true)?;
    let outputs = array(o, "outputs", true)?;
    channels(readers, "readers", 4, &door_ids)?;
    channels(inputs, "inputs", 5, &door_ids)?;
    channels(outputs, "outputs", 4, &door_ids)?;

    if let Some(settings) = o.get("settings") {
        let settings = obj(settings, "settings")?;
        if settings.get("physical_control_enabled").is_some_and(|v| v != &Value::Bool(false)) {
            bail!("physical_control_enabled is unsupported in offline semantic phase");
        }
    }

    let schedules = array(o, "schedules", false)?;
    let mut schedule_ids = HashSet::new();
    for (n, row) in schedules.iter().enumerate() {
        let label = format!("schedules[{n}]");
        let s = obj(row, &label)?;
        let k = id(s, "id", &label)?;
        ensure!(schedule_ids.insert(k), "duplicate schedule ID");
        id(s, "name", &label)?;
        if let Some(timezone) = s.get("timezone") {
            let zone = timezone.as_str().ok_or_else(|| anyhow!("{label} timezone must be string"))?;
            zone.parse::<chrono_tz::Tz>().map_err(|_| anyhow!("{label} timezone unknown"))?;
        }
        ensure!(s.get("definition").is_some_and(Value::is_object),
            "{label} must have an object schedule definition");
    }
    for (n, row) in doors.iter().enumerate() {
        let d = obj(row, "door")?;
        reference(d, "unlock_schedule_id", &schedule_ids, &format!("doors[{n}]"))?;
    }

    let credentials = array(o, "credentials", false)?;
    let mut credential_ids = HashSet::new();
    let mut card_pairs = HashSet::new();
    for (n, row) in credentials.iter().enumerate() {
        let label = format!("credentials[{n}]");
        let c = obj(row, &label)?;
        ensure!(credential_ids.insert(id(c, "id", &label)?), "duplicate credential ID");
        if let Some(v) = c.get("enabled") { ensure!(v.is_boolean(), "{label} enabled must be boolean"); }
        match (c.get("facility_code"), c.get("card_code")) {
            (Some(f), Some(k)) => {
                let facility = f.as_u64().ok_or_else(|| anyhow!("{label} invalid facility code"))?;
                let card = k.as_u64().ok_or_else(|| anyhow!("{label} invalid card code"))?;
                ensure!(facility <= 255 && card <= 65_535, "{label} exceeds supported Wiegand-26 range");
                ensure!(card_pairs.insert((facility,card)), "duplicate credential number");
            }
            (None,None) => bail!("{label} credential cannot be evaluated as Wiegand-26"),
            _ => bail!("{label} partial Wiegand credential identity"),
        }
        let mut valid_from = None;
        for key in ["valid_from", "valid_until"] {
            if let Some(v) = c.get(key).filter(|v| !v.is_null()) {
                let date = v.as_str().ok_or_else(|| anyhow!("{label}.{key} must be string"))?;
                let time = DateTime::parse_from_rfc3339(date).with_context(|| format!("{label}.{key} invalid RFC3339 date"))?;
                if key == "valid_from" { valid_from=Some(time); }
                else if let Some(start) = valid_from { ensure!(time >= start, "{label} validity end before start"); }
            }
        }
    }

    let levels = array(o, "access_levels", false)?;
    let mut level_ids = HashSet::new();
    for (n, row) in levels.iter().enumerate() {
        let label = format!("access_levels[{n}]");
        let l = obj(row, &label)?;
        ensure!(level_ids.insert(id(l, "id", &label)?), "duplicate access level ID");
        id(l, "name", &label)?;
    }
    let mapping = array(o, "credential_access_levels", false)?;
    let mut pairs = HashSet::new();
    for (n, row) in mapping.iter().enumerate() {
        let label = format!("credential_access_levels[{n}]");
        let m = obj(row, &label)?;
        let credential = id(m, "credential_id", &label)?;
        let level = id(m, "access_level_id", &label)?;
        ensure!(credential_ids.contains(&credential) && level_ids.contains(&level), "{label} orphan mapping");
        ensure!(pairs.insert((credential,level)), "duplicate credential/access-level mapping");
    }
    let mapping = array(o, "access_level_doors", false)?;
    let mut pairs = HashSet::new();
    for (n, row) in mapping.iter().enumerate() {
        let label = format!("access_level_doors[{n}]");
        let m = obj(row, &label)?;
        let level = id(m, "access_level_id", &label)?;
        ensure!(level_ids.contains(&level), "{label} unknown access level");
        let channel = m.get("channel").and_then(Value::as_u64).ok_or_else(|| anyhow!("{label} missing channel"))?;
        ensure!(channel < 4, "{label} invalid door channel");
        reference(m, "schedule_id", &schedule_ids, &label)?;
        let schedule = m.get("schedule_id").and_then(Value::as_str).unwrap_or("");
        ensure!(pairs.insert((level,channel,schedule.to_string())), "duplicate access-level/door/schedule mapping");
    }
    let holidays = array(o, "holidays", false)?;
    let mut holiday_ids = HashSet::new();
    for (n, row) in holidays.iter().enumerate() {
        let label = format!("holidays[{n}]");
        let h = obj(row, &label)?;
        ensure!(holiday_ids.insert(id(h, "id", &label)?), "duplicate holiday ID");
        let day = id(h, "holiday_date", &label)?;
        NaiveDate::parse_from_str(&day, "%Y-%m-%d").context("invalid holiday date")?;
        reference(h, "schedule_id", &schedule_ids, &label)?;
    }
    let rules = array(o, "access_rules", false)?;
    ensure!(rules.is_empty(), "nonempty access_rules format not yet validated: fail closed");
    // Do not claim other unvalidated types of wiring or schedule semantics are commissioned.
    Ok(SemanticSummary {doors:doors.len(),readers:readers.len(),inputs:inputs.len(),outputs:outputs.len(),
        credentials:credentials.len(),access_levels:levels.len(),schedules:schedules.len(),holidays:holidays.len()})
}

pub fn pg_jsonb_canonical(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::String(v) => Ok(serde_json::to_string(v)?),
        Value::Number(v) => {
            ensure!(!v.is_f64(), "unsupported floating point JSON number");
            Ok(v.to_string())
        }
        Value::Array(items) => {
            let mut parsed = Vec::with_capacity(items.len());
            for item in items { parsed.push(pg_jsonb_canonical(item)?); }
            Ok(format!("[{}]", parsed.join(", ")))
        }
        Value::Object(items) => {
            let mut keys: Vec<&String> = items.keys().collect();
            keys.sort_by(|a,b| a.as_bytes().len().cmp(&b.as_bytes().len())
                .then_with(|| a.as_bytes().cmp(b.as_bytes())));
            let mut parts = Vec::with_capacity(keys.len());
            for k in keys {
                parts.push(format!("{}: {}", serde_json::to_string(k)?,
                    pg_jsonb_canonical(items.get(k).ok_or_else(|| anyhow!("key disappeared"))?)?));
            }
            Ok(format!("{{{}}}",parts.join(", ")))
        }
    }
}
pub fn checksum(config: &Value) -> Result<String> {
    let canonical = pg_jsonb_canonical(config)?;
    Ok(digest(&SHA256, canonical.as_bytes()).as_ref().iter()
        .map(|v| format!("{v:02x}")).collect())
}

pub fn plan_change(base: &Value, candidate: &Value, base_version: u64, target_version: u64) -> Result<ChangePlan> {
    validate_configuration(base)?;
    validate_configuration(candidate)?;
    ensure!(base_version > 0 && target_version == base_version.checked_add(1).ok_or_else(|| anyhow!("version overflow"))?,
        "change plan requires exactly one newer version");
    let left = checksum(base)?;
    let right = checksum(candidate)?;
    ensure!(left != right, "unchanged candidate has no plan");
    let a = obj(base,"base")?;
    let b = obj(candidate,"candidate")?;
    let mut sections = BTreeSet::new();
    for key in a.keys().chain(b.keys()) {
        if a.get(key) != b.get(key) { sections.insert(key.to_owned()); }
    }
    let changed_sections: Vec<String> = sections.into_iter().collect();
    let fingerprint = digest(&SHA256,
        format!("hlaxs-plan-v1|{base_version}|{target_version}|{left}|{right}|{}",changed_sections.join(",")).as_bytes())
        .as_ref().iter().map(|v| format!("{v:02x}")).collect();
    Ok(ChangePlan{base_version,target_version,base_checksum:left,target_checksum:right,changed_sections,fingerprint})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        json!({
            "controller":{"id":"offline-only"},
            "doors":[
                {"channel":0,"name":"D0","unlock_ms":5000},
                {"channel":1,"name":"D1","unlock_ms":5000},
                {"channel":2,"name":"D2","unlock_ms":5000},
                {"channel":3,"name":"D3","unlock_ms":5000}],
            "readers":[{"channel":0,"protocol":"wiegand","door_channel":0}],
            "inputs":[{"channel":0,"door_channel":0}],
            "outputs":[{"channel":0,"door_channel":0}],
            "credentials":[{"id":"cred1","facility_code":41,"card_code":1234,"valid_from":"2026-10-01T00:00:00Z","valid_until":"2027-10-01T00:00:00Z"}],
            "access_levels":[{"id":"level1","name":"Employees"}],
            "credential_access_levels":[{"credential_id":"cred1","access_level_id":"level1"}],
            "access_level_doors":[{"access_level_id":"level1","channel":0,"schedule_id":"sched1"}],
            "schedules":[{"id":"sched1","name":"Business hours","timezone":"America/New_York","definition":{}}],
            "holidays":[{"id":"holiday1","name":"A","holiday_date":"2026-12-25","schedule_id":"sched1"}],
            "settings":{"simulation_only":true,"physical_control_enabled":false},"access_rules":[]
        })
    }
    #[test] fn accepts_established_normalized_relationships() { assert_eq!(validate_configuration(&fixture()).unwrap().doors,4); }
    #[test] fn rejects_orphan_schedule() { let mut x=fixture(); x["doors"][0]["unlock_schedule_id"]=json!("missing"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_duplicate_reader_channel() { let mut x=fixture(); x["readers"].as_array_mut().unwrap().push(json!({"channel":0})); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_unsupported_osdp() { let mut x=fixture(); x["readers"][0]["protocol"]=json!("osdp"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_reader_without_protocol() { let mut x=fixture(); x["readers"][0].as_object_mut().unwrap().remove("protocol"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_unsafe_settings() { let mut x=fixture(); x["settings"]["physical_control_enabled"]=json!(true); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_orphan_credential_access() { let mut x=fixture(); x["credential_access_levels"][0]["credential_id"]=json!("missing"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_orphan_access_level_door() { let mut x=fixture(); x["access_level_doors"][0]["access_level_id"]=json!("missing"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_invalid_credential_range() { let mut x=fixture(); x["credentials"][0]["facility_code"]=json!(256); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_missing_credential_number() { let mut x=fixture(); x["credentials"][0].as_object_mut().unwrap().remove("card_code"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_duplicate_card_value() { let mut x=fixture(); x["credentials"].as_array_mut().unwrap().push(json!({"id":"another","facility_code":41,"card_code":1234})); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_bad_credential_window() { let mut x=fixture(); x["credentials"][0]["valid_until"]=json!("2025-10-01T00:00:00Z"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_duplicate_mapping() { let mut x=fixture(); let duplicate=x["credential_access_levels"][0].clone(); x["credential_access_levels"].as_array_mut().unwrap().push(duplicate); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_unmodeled_access_rules() { let mut x=fixture(); x["access_rules"]=json!([{"unvalidated":"rule"}]); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_invalid_holiday_and_timezone() { let mut x=fixture(); x["holidays"][0]["holiday_date"]=json!("2026-02-30"); assert!(validate_configuration(&x).is_err()); let mut x=fixture(); x["schedules"][0]["timezone"]=json!("Bogus/Zone"); assert!(validate_configuration(&x).is_err()); }
    #[test] fn rejects_duplicate_and_wrong_channels() { let mut x=fixture(); x["doors"][1]["channel"]=json!(0); assert!(validate_configuration(&x).is_err()); let mut x=fixture(); x["inputs"][0]["channel"]=json!(5); assert!(validate_configuration(&x).is_err()); }
    #[test] fn plan_is_deterministic_and_redacted() { let x=fixture(); let mut y=x.clone(); y["doors"][0]["unlock_ms"]=json!(5100); let p=plan_change(&x,&y,6,7).unwrap(); let q=plan_change(&x,&y,6,7).unwrap(); assert_eq!(p,q); assert_eq!(p.changed_sections,vec!["doors"]); assert!(!format!("{:?}",p).contains("cred1")); assert!(plan_change(&x,&y,6,6).is_err()); }
    #[test] fn pg_jsonb_golden() { assert_eq!(checksum(&json!({"z":1,"aa":[{"long":5,"x":true}],"a":null})).unwrap(),"5691e0142835c5d716d8bd8f25edd660a50922fe0f1837e3942e06bab296b651"); }
    #[test] fn accepts_numbered_sp4_v6_hardware_profile() {
        let mut x = fixture();
        x["readers"] = json!([
            {"reader_number":1,"protocol":"wiegand","configuration":{
                "d0":{"chip":"gpiochip3","line":23},"d1":{"chip":"gpiochip3","line":25},"format":"Wiegand-26"}},
            {"reader_number":2,"protocol":"wiegand","configuration":{
                "d0":{"chip":"gpiochip3","line":26},"d1":{"chip":"gpiochip0","line":15},"format":"Wiegand-26"}},
            {"reader_number":3,"protocol":"wiegand","configuration":{
                "d0":{"chip":"gpiochip4","line":10},"d1":{"chip":"gpiochip4","line":26},"format":"Wiegand-26"}},
            {"reader_number":4,"protocol":"wiegand","configuration":{
                "d0":{"chip":"gpiochip4","line":27},"d1":{"chip":"gpiochip4","line":11},"format":"Wiegand-26"}}
        ]);
        x["inputs"] = json!([
            {"input_number":1,"input_type":"door_contact","configuration":{"channel":0,"chip":"gpiochip4","line":12,"active_raw":0}},
            {"input_number":2,"input_type":"door_contact","configuration":{"channel":1,"chip":"gpiochip0","line":8,"active_raw":0}},
            {"input_number":3,"input_type":"door_contact","configuration":{"channel":2,"chip":"gpiochip4","line":28,"active_raw":0}},
            {"input_number":4,"input_type":"door_contact","configuration":{"channel":3,"chip":"gpiochip4","line":29,"active_raw":0}},
            {"input_number":5,"input_type":"fire","configuration":{"chip":"gpiochip3","line":21,"active_raw":0}}
        ]);
        x["outputs"] = json!([
            {"output_number":1,"output_type":"lock_relay","configuration":{"channel":0,"backend":"DirectI2c","i2c_device":"/dev/i2c-2","address":32,"pca9534_line":4,"active_high":true}},
            {"output_number":2,"output_type":"lock_relay","configuration":{"channel":1,"backend":"DirectI2c","i2c_device":"/dev/i2c-2","address":32,"pca9534_line":5,"active_high":true}},
            {"output_number":3,"output_type":"lock_relay","configuration":{"channel":2,"backend":"DirectI2c","i2c_device":"/dev/i2c-2","address":32,"pca9534_line":6,"active_high":true}},
            {"output_number":4,"output_type":"lock_relay","configuration":{"channel":3,"backend":"DirectI2c","i2c_device":"/dev/i2c-2","address":32,"pca9534_line":7,"active_high":true}}
        ]);
        assert_eq!(validate_configuration(&x).unwrap().readers, 4);
        assert_eq!(validate_configuration(&x).unwrap().inputs, 5);
        assert_eq!(validate_configuration(&x).unwrap().outputs, 4);
    }
    #[test] fn rejects_numbered_reader_mismatched_channel_and_gpio() {
        let mut x=fixture();
        x["readers"][0]=json!({"reader_number":1,"channel":1,"protocol":"wiegand","configuration":{
            "d0":{"chip":"gpiochip3","line":23},"d1":{"chip":"gpiochip3","line":25},"format":"Wiegand-26"}});
        assert!(validate_configuration(&x).is_err());
        x["readers"][0].as_object_mut().unwrap().remove("channel");
        x["readers"][0]["configuration"]["d0"]["line"]=json!(999);
        assert!(validate_configuration(&x).is_err());
    }
    #[test] fn rejects_numbered_input_missing_or_wrong_nested_channel() {
        let mut x=fixture();
        x["inputs"][0]=json!({"input_number":1,"input_type":"door_contact","configuration":{
            "chip":"gpiochip4","line":12,"active_raw":0}});
        assert!(validate_configuration(&x).is_err());
        x["inputs"][0]["configuration"]["channel"]=json!(2);
        assert!(validate_configuration(&x).is_err());
    }
    #[test] fn rejects_numbered_output_conflicting_relay_line() {
        let mut x=fixture();
        x["outputs"][0]=json!({"output_number":1,"output_type":"lock_relay","configuration":{
            "channel":0,"backend":"DirectI2c","i2c_device":"/dev/i2c-2","address":32,"pca9534_line":7,"active_high":true}});
        assert!(validate_configuration(&x).is_err());
    }
    #[test] fn rejects_numbered_fire_input_claiming_door_channel() {
        let mut x=fixture();
        x["inputs"][0]=json!({"input_number":5,"input_type":"fire","configuration":{
            "channel":4,"chip":"gpiochip3","line":21,"active_raw":0}});
        assert!(validate_configuration(&x).is_err());
    }
    #[test] fn rejects_duplicate_numbered_reader_ports() {
        let mut x=fixture();
        x["readers"]=json!([
            {"reader_number":1,"protocol":"wiegand","configuration":{
                "d0":{"chip":"gpiochip3","line":23},"d1":{"chip":"gpiochip3","line":25},"format":"Wiegand-26"}},
            {"reader_number":1,"protocol":"wiegand","configuration":{
                "d0":{"chip":"gpiochip3","line":23},"d1":{"chip":"gpiochip3","line":25},"format":"Wiegand-26"}}
        ]);
        assert!(validate_configuration(&x).is_err());
    }
    #[test] fn refuses_unpinned_reader_format() {
        let mut x=fixture();
        x["readers"][0]=json!({"reader_number":1,"protocol":"wiegand","configuration":{
            "d0":{"chip":"gpiochip3","line":23},"d1":{"chip":"gpiochip3","line":25},"format":"Wiegand-34"}});
        assert!(validate_configuration(&x).is_err());
    }
}
