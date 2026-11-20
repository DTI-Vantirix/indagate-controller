//! Offline-only reference access-decision evaluator for HLAXS.Access SP4.
//! This file is NOT registered in cloud/mod.rs, agent.rs, or main.rs.
//! No I/O, no device commands, no relay, no cloud ACK, no production database.
//! It accepts a UTC test clock and a JSON configuration value; every result is
//! a redacted decision/reason, never a hardware action.
//!
//! Schedule schema modeled from the existing controller src/access/schedule.rs
//! (always + monday..sunday ranges, timezone, holiday deny/allow/use_schedule).
//! Additional conservative rules are documented in the package README.

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc, Weekday};
use chrono_tz::Tz;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub reader_number: u64, // SP4 reader 1..4
    pub facility_code: u64,
    pub card_code: u64,
    pub at_utc: DateTime<Utc>, // injected: never use wall clock implicitly
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: &'static str, // predefined, redacted; no card/holder details
}

fn deny(reason: &'static str) -> Decision { Decision { allowed: false, reason } }
fn grant() -> Decision { Decision { allowed: true, reason: "access_granted_offline" } }

fn list<'a>(config: &'a Value, field: &str) -> Option<&'a Vec<Value>> {
    config.get(field)?.as_array()
}
fn str_field<'a>(row: &'a Value, field: &str) -> Option<&'a str> {
    row.get(field)?.as_str()
}
fn enabled(row: &Value) -> bool { row.get("enabled").and_then(Value::as_bool) == Some(true) }
fn time_field(row: &Value, field: &str) -> Result<Option<DateTime<Utc>>, ()> {
    match row.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => DateTime::parse_from_rfc3339(v)
            .map(|x| Some(x.with_timezone(&Utc))).map_err(|_| ()),
        _ => Err(()),
    }
}

const DAYS: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

fn weekday_idx(day: Weekday) -> usize { day.num_days_from_monday() as usize }
fn hm(s: &str, allow_2400: bool) -> Option<u32> {
    let bytes = s.as_bytes();
    if bytes.len() != 5 || bytes[2] != b':' || !bytes[..2].iter().chain(bytes[3..].iter()).all(u8::is_ascii_digit) {
        return None;
    }
    let hour = s[..2].parse::<u32>().ok()?;
    let minute = s[3..].parse::<u32>().ok()?;
    if hour == 24 && minute == 0 && allow_2400 { return Some(1440); }
    if hour > 23 || minute > 59 { return None; }
    Some(hour * 60 + minute)
}
fn range_minutes(range: &Value) -> Result<(u32, u32), ()> {
    let o = range.as_object().ok_or(())?;
    if o.len() != 2 || !o.contains_key("start") || !o.contains_key("end") { return Err(()); }
    let start = hm(str_field(range, "start").ok_or(())?, false).ok_or(())?;
    let end = hm(str_field(range, "end").ok_or(())?, true).ok_or(())?;
    if start == end { return Err(()); }
    Ok((start, end))
}
fn schedule_def_ok(def: &Value) -> bool {
    let Some(o) = def.as_object() else { return false; };
    if o.keys().any(|k| k != "always" && !DAYS.contains(&k.as_str())) { return false; }
    let always = match o.get("always") { None => false, Some(Value::Bool(v)) => *v, _ => return false };
    for day in DAYS {
        if let Some(rows) = o.get(day) {
            let Some(rows) = rows.as_array() else { return false; };
            if always && !rows.is_empty() { return false; }
            if rows.len() > 100 { return false; }
            if rows.iter().any(|r| range_minutes(r).is_err()) { return false; }
        }
    }
    true
}
fn definitions_valid(config: &Value) -> bool {
    let Some(schedules) = list(config, "schedules") else { return false; };
    let mut ids = HashSet::new();
    for s in schedules {
        let Some(id) = str_field(s, "id") else { return false; };
        let Some(tz) = str_field(s, "timezone") else { return false; };
        if !ids.insert(id) || tz.parse::<Tz>().is_err() { return false; }
        if !s.get("definition").is_some_and(schedule_def_ok) { return false; }
    }
    let Some(holidays) = list(config, "holidays") else { return false; };
    for h in holidays {
        let Some(behavior) = str_field(h, "behavior") else { return false; };
        if !matches!(behavior, "deny" | "allow" | "use_schedule") { return false; }
        let Some(date) = str_field(h, "holiday_date") else { return false; };
        if chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err() { return false; }
        let override_old = str_field(h, "schedule_id");
        let override_new = str_field(h, "override_schedule_id");
        if override_old.is_some() && override_new.is_some() && override_old != override_new { return false; }
        let override_id = override_new.or(override_old);
        if behavior == "use_schedule" {
            if !override_id.is_some_and(|x| ids.contains(x)) { return false; }
        } else if override_id.is_some() { return false; }
    }
    true
}
fn schedule_by_id<'a>(cfg: &'a Value, id: &str) -> Option<&'a Value> {
    list(cfg, "schedules")?.iter().find(|s| str_field(s, "id") == Some(id))
}
fn weekly_active(def: &Value, day: Weekday, minute: u32) -> bool {
    if def.get("always").and_then(Value::as_bool) == Some(true) { return true; }
    let today = DAYS[weekday_idx(day)];
    let yesterday = DAYS[(weekday_idx(day) + 6) % 7];
    let matches_today = def.get(today).and_then(Value::as_array)
        .is_some_and(|rows| rows.iter().any(|r| {
            let (start, end) = range_minutes(r).expect("prevalidated schedule range");
            if start < end { minute >= start && minute < end } else { minute >= start }
        }));
    if matches_today { return true; }
    def.get(yesterday).and_then(Value::as_array)
        .is_some_and(|rows| rows.iter().any(|r| {
            let (start, end) = range_minutes(r).expect("prevalidated schedule range");
            start > end && minute < end
        }))
}

/// All holiday rows are site-scoped by their containing snapshot. On the local
/// date in the selected schedule's timezone, deny wins. Conflicting distinct
/// use_schedule overrides are refused, rather than depending on row order.
/// No holiday is evaluated when none match this schedule's local date.
fn schedule_allows(cfg: &Value, schedule_id: &str, at: DateTime<Utc>) -> Decision {
    let Some(s) = schedule_by_id(cfg, schedule_id) else { return deny("schedule_missing"); };
    let Some(tz) = str_field(s, "timezone").and_then(|x| x.parse::<Tz>().ok()) else {
        return deny("schedule_unsupported");
    };
    let local = tz.from_utc_datetime(&at.naive_utc());
    let local_day = local.date_naive().format("%Y-%m-%d").to_string();
    let mut has_allow = false;
    let mut override_id: Option<&str> = None;
    let Some(holidays) = list(cfg, "holidays") else { return deny("configuration_invalid"); };
    for h in holidays {
        if str_field(h, "holiday_date") != Some(local_day.as_str()) { continue; }
        match str_field(h, "behavior") {
            Some("deny") => return deny("holiday_denied"),
            Some("allow") => has_allow = true,
            Some("use_schedule") => {
                let next = str_field(h, "override_schedule_id").or_else(||str_field(h, "schedule_id"));
                match (override_id, next) {
                    (None, Some(v)) => override_id = Some(v),
                    (Some(a), Some(b)) if a == b => (),
                    _ => return deny("holiday_ambiguous"),
                }
            },
            _ => return deny("holiday_unsupported"),
        }
    }
    if let Some(id) = override_id {
        let Some(s) = schedule_by_id(cfg, id) else { return deny("schedule_missing"); };
        let Some(tz) = str_field(s, "timezone").and_then(|x| x.parse::<Tz>().ok()) else {
            return deny("schedule_unsupported");
        };
        let local = tz.from_utc_datetime(&at.naive_utc());
        let minute = local.hour() * 60 + local.minute();
        let Some(def) = s.get("definition") else { return deny("schedule_unsupported"); };
        return if weekly_active(def, local.weekday(), minute) { grant() } else { deny("schedule_inactive") };
    }
    if has_allow { return grant(); }
    let Some(def) = s.get("definition") else { return deny("schedule_unsupported"); };
    let minute = local.hour() * 60 + local.minute();
    if weekly_active(def, local.weekday(), minute) { grant() } else { deny("schedule_inactive") }
}

/// No optional boolean default grants. Numbered SP4 readers have no `enabled`
/// property in the verified v6 schema; they are assumed enabled only after the
/// pinned hardware metadata passes config_semantics::validate_configuration.
/// Returns redacted result. NEVER an actuation request.
pub fn evaluate(cfg: &Value, request: &Probe) -> Decision {
    if super::config_semantics::validate_configuration(cfg).is_err() || !definitions_valid(cfg) {
        return deny("configuration_invalid");
    }
    if request.reader_number < 1 || request.reader_number > 4 { return deny("reader_invalid"); }
    if request.facility_code > 255 || request.card_code > 65535 { return deny("credential_invalid_format"); }
    let Some(readers) = list(cfg, "readers") else { return deny("configuration_invalid"); };
    let reader = readers.iter().find(|r| {
        r.get("reader_number").and_then(Value::as_u64) == Some(request.reader_number) ||
        (r.get("reader_number").is_none() && r.get("channel").and_then(Value::as_u64) == Some(request.reader_number - 1))
    });
    let Some(reader) = reader else { return deny("reader_not_configured"); };
    if let Some(v) = reader.get("enabled") {
        if v.as_bool() != Some(true) { return deny("reader_disabled"); }
    } else if reader.get("reader_number").is_none() { return deny("reader_disabled"); }
    let channel = request.reader_number - 1;
    if reader.get("door_channel").is_some_and(|x| x.as_u64() != Some(channel)) {
        return deny("reader_door_mapping_invalid");
    }
    if let Some(door_id) = str_field(reader, "door_id") {
        if !list(cfg, "doors").is_some_and(|doors| doors.iter().any(|d| {
            d.get("channel").and_then(Value::as_u64) == Some(channel) &&
            str_field(d, "id") == Some(door_id)
        })) { return deny("reader_door_mapping_invalid"); }
    }
    let Some(door) = list(cfg, "doors").and_then(|doors| doors.iter().find(|d| d.get("channel").and_then(Value::as_u64) == Some(channel))) else {
        return deny("door_not_configured");
    };
    if !enabled(door) { return deny("door_disabled"); }
    let Some(credentials) = list(cfg, "credentials") else { return deny("configuration_invalid"); };
    let card = credentials.iter().find(|c| c.get("facility_code").and_then(Value::as_u64) == Some(request.facility_code)
        && c.get("card_code").and_then(Value::as_u64) == Some(request.card_code));
    let Some(card) = card else { return deny("credential_not_found"); };
    if !enabled(card) { return deny("credential_disabled"); }
    let Ok(start) = time_field(card, "valid_from") else { return deny("credential_time_invalid"); };
    let Ok(end) = time_field(card, "valid_until") else { return deny("credential_time_invalid"); };
    if start.is_some_and(|d| request.at_utc < d) { return deny("credential_not_yet_valid"); }
    if end.is_some_and(|d| request.at_utc >= d) { return deny("credential_expired"); }
    let Some(credential_id) = str_field(card, "id") else { return deny("configuration_invalid"); };
    let level_ids: HashSet<&str> = list(cfg, "credential_access_levels").into_iter().flatten()
        .filter(|link| str_field(link,"credential_id") == Some(credential_id))
        .filter_map(|link| str_field(link,"access_level_id"))
        .collect();
    if level_ids.is_empty() { return deny("door_not_allowed"); }
    let active_levels: HashSet<&str> = list(cfg,"access_levels").into_iter().flatten()
        .filter(|level| enabled(level))
        .filter_map(|level| str_field(level,"id"))
        .filter(|id| level_ids.contains(*id))
        .collect();
    if active_levels.is_empty() { return deny("door_not_allowed"); }
    let Some(links) = list(cfg,"access_level_doors") else { return deny("configuration_invalid"); };
    let mut had_permission = false;
    let mut schedule_denial: Option<&'static str> = None;
    let mut allowed_path = false;
    // Evaluate ALL applicable paths so an explicit holiday denial wins even
    // if another access level would otherwise allow (stronger than legacy).
    for link in links {
        let Some(level) = str_field(link, "access_level_id") else { continue; };
        if !active_levels.contains(level) || link.get("channel").and_then(Value::as_u64) != Some(channel) { continue; }
        had_permission = true;
        match link.get("schedule_id") {
            Some(Value::String(id)) if !id.is_empty() => {
                let d = schedule_allows(cfg,id,request.at_utc);
                if d.reason == "holiday_denied" || d.reason == "holiday_ambiguous" { return d; }
                if d.allowed { allowed_path = true; }
                else { schedule_denial = Some(d.reason); }
            },
            None | Some(Value::Null) => {
                // Without an associated schedule there is no defensible local
                // timezone for a holiday. Do not bypass configured holidays.
                if list(cfg,"holidays").is_some_and(|h| !h.is_empty()) {
                    // Treat unknown holiday timezone as an explicit veto,
                    // regardless of other mapped access-level paths.
                    return deny("schedule_missing_for_holiday");
                } else { allowed_path = true; }
            },
            _ => return deny("schedule_unsupported"),
        }
    }
    if !had_permission { return deny("door_not_allowed"); }
    if allowed_path { grant() } else { deny(schedule_denial.unwrap_or("schedule_inactive")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    const T: &str = "2026-10-19T13:30:00Z"; // Monday 09:30 New York (EDT)
    fn probe() -> Probe { Probe { reader_number:1, facility_code:41, card_code:1234, at_utc:T.parse().unwrap() } }
    fn fixture() -> Value {
        json!({
            "doors":[
                {"channel":0,"name":"D0","enabled":true,"unlock_ms":5000},
                {"channel":1,"name":"D1","enabled":true,"unlock_ms":5000},
                {"channel":2,"name":"D2","enabled":true,"unlock_ms":5000},
                {"channel":3,"name":"D3","enabled":true,"unlock_ms":5000}],
            "readers":[{"reader_number":1,"protocol":"wiegand","configuration":{
                "d0":{"chip":"gpiochip3","line":23},"d1":{"chip":"gpiochip3","line":25},"format":"Wiegand-26"}}],
            "inputs":[],"outputs":[],
            "credentials":[{"id":"card1","enabled":true,"facility_code":41,"card_code":1234,"valid_from":"2026-10-01T00:00:00Z","valid_until":"2026-11-01T00:00:00Z"}],
            "access_levels":[{"id":"level1","name":"Employees","enabled":true}],
            "credential_access_levels":[{"credential_id":"card1","access_level_id":"level1"}],
            "access_level_doors":[{"access_level_id":"level1","channel":0,"schedule_id":"schedule1"}],
            "schedules":[{"id":"schedule1","name":"24x7","timezone":"America/New_York","definition":{"always":true}}],
            "holidays":[],"settings":{},"access_rules":[]
        })
    }
    fn reason(c:&Value,p:&Probe)->&'static str { evaluate(c,p).reason }
    #[test] fn valid_card_granted_offline_only() { assert!(evaluate(&fixture(), &probe()).allowed); }
    #[test] fn unknown_card_denied() { let p=Probe{card_code:9999,..probe()};assert_eq!(reason(&fixture(),&p),"credential_not_found"); }
    #[test] fn unknown_facility_denied() { let p=Probe{facility_code:42,..probe()};assert_eq!(reason(&fixture(),&p),"credential_not_found"); }
    #[test] fn invalid_reader_denied() { let p=Probe{reader_number:5,..probe()};assert_eq!(reason(&fixture(),&p),"reader_invalid"); }
    #[test] fn unconfigured_reader_denied() { let p=Probe{reader_number:2,..probe()};assert_eq!(reason(&fixture(),&p),"reader_not_configured"); }
    #[test] fn disabled_reader_denied() { let mut c=fixture(); c["readers"][0]["enabled"]=json!(false); assert_eq!(reason(&c,&probe()),"reader_disabled"); }
    #[test] fn disabled_door_denied() { let mut c=fixture(); c["doors"][0]["enabled"]=json!(false);assert_eq!(reason(&c,&probe()),"door_disabled"); }
    #[test] fn disabled_credential_denied() {let mut c=fixture(); c["credentials"][0]["enabled"]=json!(false);assert_eq!(reason(&c,&probe()),"credential_disabled");}
    #[test] fn disabled_access_level_denied() {let mut c=fixture(); c["access_levels"][0]["enabled"]=json!(false);assert_eq!(reason(&c,&probe()),"door_not_allowed");}
    #[test] fn no_credential_membership_denied() {let mut c=fixture(); c["credential_access_levels"]=json!([]);assert_eq!(reason(&c,&probe()),"door_not_allowed");}
    #[test] fn missing_door_permission_denied() {let mut c=fixture(); c["access_level_doors"]=json!([]);assert_eq!(reason(&c,&probe()),"door_not_allowed");}
    #[test] fn before_credential_start_denied() {let p=Probe{at_utc:"2026-09-30T23:59:59Z".parse().unwrap(),..probe()};assert_eq!(reason(&fixture(),&p),"credential_not_yet_valid");}
    #[test] fn credential_valid_from_inclusive() {let p=Probe{at_utc:"2026-10-01T00:00:00Z".parse().unwrap(),..probe()};assert!(evaluate(&fixture(),&p).allowed);}
    #[test] fn credential_expiry_exclusive() {let p=Probe{at_utc:"2026-11-01T00:00:00Z".parse().unwrap(),..probe()};assert_eq!(reason(&fixture(),&p),"credential_expired");}
    #[test] fn invalid_wiegand_number_denied() {let p=Probe{facility_code:256,..probe()};assert_eq!(reason(&fixture(),&p),"credential_invalid_format");}
    #[test] fn weekly_inside_hours_grants() {
        let mut c=fixture(); c["schedules"][0]["definition"]=json!({"always":false,"monday":[{"start":"09:00","end":"17:00"}]});
        assert!(evaluate(&c,&probe()).allowed);
    }
    #[test] fn weekly_outside_hours_denies() {
        let mut c=fixture(); c["schedules"][0]["definition"]=json!({"always":false,"monday":[{"start":"10:00","end":"17:00"}]});
        assert_eq!(reason(&c,&probe()),"schedule_inactive");
    }
    #[test] fn weekday_boundary_end_is_exclusive() {
        let mut c=fixture(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"09:00","end":"09:30"}]});
        assert_eq!(reason(&c,&probe()),"schedule_inactive");
    }
    #[test] fn overnight_previous_day_carryover() {
        let mut c=fixture(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"23:00","end":"02:00"}]});
        let p=Probe{at_utc:"2026-10-20T05:00:00Z".parse().unwrap(),..probe()};
        assert!(evaluate(&c,&p).allowed); // Tue 01:00 New York
    }
    #[test] fn overnight_outside_range_denied() {
        let mut c=fixture(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"23:00","end":"02:00"}]});
        assert_eq!(reason(&c,&probe()),"schedule_inactive");
    }
    #[test] fn holiday_deny_trumps_24x7() {
        let mut c=fixture();c["holidays"]=json!([{"id":"holiday1","holiday_date":"2026-10-19","behavior":"deny"}]);
        assert_eq!(reason(&c,&probe()),"holiday_denied");
    }
    #[test] fn holiday_allow_overrides_inactive_schedule() {
        let mut c=fixture();c["schedules"][0]["definition"]=json!({"monday":[]});
        c["holidays"]=json!([{"id":"holiday1","holiday_date":"2026-10-19","behavior":"allow"}]);
        assert!(evaluate(&c,&probe()).allowed);
    }
    #[test] fn holiday_override_schedule_active() {
        let mut c=fixture();c["schedules"][0]["definition"]=json!({"monday":[]});
        c["schedules"].as_array_mut().unwrap().push(json!({"id":"schedule2","name":"custom","timezone":"America/New_York","definition":{"always":true}}));
        c["holidays"]=json!([{"id":"holiday1","holiday_date":"2026-10-19","behavior":"use_schedule","override_schedule_id":"schedule2"}]);
        assert!(evaluate(&c,&probe()).allowed);
    }
    #[test] fn holiday_override_inactive_stays_denied() {
        let mut c=fixture();c["schedules"][0]["definition"]=json!({"monday":[]});
        c["schedules"].as_array_mut().unwrap().push(json!({
            "id":"schedule2","name":"closed","timezone":"America/New_York","definition":{"monday":[]}}));
        c["holidays"]=json!([{"id":"h1","holiday_date":"2026-10-19","behavior":"use_schedule","override_schedule_id":"schedule2"}]);
        assert_eq!(reason(&c,&probe()),"schedule_inactive");
    }
    #[test] fn local_holiday_date_not_utc_date() {
        let mut c=fixture();c["holidays"]=json!([{"id":"h1","holiday_date":"2026-10-19","behavior":"deny"}]);
        let p=Probe{at_utc:"2026-10-20T00:30:00Z".parse().unwrap(),..probe()};
        assert_eq!(reason(&c,&p),"holiday_denied"); // October 19 at 20:30 in New York
    }
    #[test] fn holiday_deny_has_precedence_over_allow() {
        let mut c=fixture();c["holidays"]=json!([
            {"id":"h1","holiday_date":"2026-10-19","behavior":"allow"},
            {"id":"h2","holiday_date":"2026-10-19","behavior":"deny"}]);
        assert_eq!(reason(&c,&probe()),"holiday_denied");
    }
    #[test] fn unknown_holiday_behavior_fail_closed() {
        let mut c=fixture();c["holidays"]=json!([{"id":"h1","holiday_date":"2026-10-19","behavior":"override_all"}]);
        assert_eq!(reason(&c,&probe()),"configuration_invalid");
    }
    #[test] fn unknown_schedule_shape_fail_closed() {
        let mut c=fixture();c["schedules"][0]["definition"]=json!({"unverified_periods":[{"start":"09:00"}]});
        assert_eq!(reason(&c,&probe()),"configuration_invalid");
    }
    #[test] fn invalid_time_range_fail_closed() {
        let mut c=fixture();c["schedules"][0]["definition"]=json!({"monday":[{"start":"24:00","end":"12:00"}]});
        assert_eq!(reason(&c,&probe()),"configuration_invalid");
    }
    #[test] fn invalid_timezone_fail_closed() {
        let mut c=fixture();c["schedules"][0]["timezone"]=json!("Unknown/Nowhere");
        assert_eq!(reason(&c,&probe()),"configuration_invalid");
    }
    #[test] fn reader_misassigned_door_denied() {
        let mut c=fixture();c["readers"][0]["door_channel"]=json!(1);
        assert_eq!(reason(&c,&probe()),"reader_door_mapping_invalid");
    }
    #[test] fn holiday_without_schedule_is_denied() {
        let mut c=fixture();c["access_level_doors"][0]["schedule_id"]=Value::Null;
        c["holidays"]=json!([{"id":"h1","holiday_date":"2026-10-19","behavior":"deny"}]);
        assert_eq!(reason(&c,&probe()),"schedule_missing_for_holiday");
    }
    #[test] fn unsigned_config_fails_closed() {
        let mut c=fixture();c["credentials"][0]["card_code"]=json!(999999);
        assert_eq!(reason(&c,&probe()),"configuration_invalid");
    }
    #[test] fn conflicting_holiday_overrides_denied() {
        let mut c=fixture();
        c["schedules"].as_array_mut().unwrap().push(json!({"id":"schedule2","name":"other","timezone":"America/New_York","definition":{"always":true}}));
        c["holidays"]=json!([
            {"id":"h1","holiday_date":"2026-10-19","behavior":"use_schedule","schedule_id":"schedule1"},
            {"id":"h2","holiday_date":"2026-10-19","behavior":"use_schedule","schedule_id":"schedule2"}]);
        assert_eq!(reason(&c,&probe()),"holiday_ambiguous");
    }
    #[test] fn daylight_saving_transition_uses_utc_to_local() {
        let mut c=fixture();c["schedules"][0]["definition"]=json!({"sunday":[{"start":"01:00","end":"01:30"}]});
        c["credentials"][0]["valid_until"] = json!("2026-12-01T00:00:00Z");
        let p=Probe{at_utc:Utc.with_ymd_and_hms(2026,11,1,5,15,0).single().unwrap(),..probe()};
        assert!(evaluate(&c,&p).allowed);
        let p=Probe{at_utc:Utc.with_ymd_and_hms(2026,11,1,6,15,0).single().unwrap(),..probe()};
        assert!(evaluate(&c,&p).allowed); // Fall-back 01:15 occurs twice, both valid local clock time
        let p=Probe{at_utc:Utc.with_ymd_and_hms(2026,11,1,7,15,0).single().unwrap(),..probe()};
        assert_eq!(reason(&c,&p),"schedule_inactive");
    }
    #[test] fn holiday_deny_wins_even_with_an_unscheduled_allow_path() {
        let mut c=fixture();
        c["access_level_doors"].as_array_mut().unwrap().push(
            json!({"access_level_id":"level1","channel":0,"schedule_id":null}));
        c["holidays"]=json!([{"id":"h1","holiday_date":"2026-10-19","behavior":"deny"}]);
        assert!(!evaluate(&c,&probe()).allowed);
    }
    #[test] fn range_24h_end_is_accepted_as_the_full_day() {
        let mut c=fixture(); c["schedules"][0]["definition"]=json!({"monday":[{"start":"00:00","end":"24:00"}]});
        assert!(evaluate(&c,&probe()).allowed);
    }
    #[test] fn always_schedule_cannot_hide_conflicting_weekly_intervals() {
        let mut c=fixture();c["schedules"][0]["definition"]=json!({
            "always":true,"monday":[{"start":"09:00","end":"11:00"}]});
        assert_eq!(reason(&c,&probe()),"configuration_invalid");
    }
    #[test] fn holiday_allow_never_overrides_disabled_credential() {
        let mut c=fixture();c["credentials"][0]["enabled"]=json!(false);
        c["holidays"]=json!([{"id":"h1","holiday_date":"2026-10-19","behavior":"allow"}]);
        assert_eq!(reason(&c,&probe()),"credential_disabled");
    }
    #[test] fn alternative_active_access_schedule_can_grant() {
        let mut c=fixture();
        c["schedules"][0]["definition"]=json!({"monday":[]});
        c["schedules"].as_array_mut().unwrap().push(json!({
            "id":"schedule2","name":"second","timezone":"America/New_York","definition":{"always":true}}));
        c["access_level_doors"].as_array_mut().unwrap().push(json!({
            "access_level_id":"level1","channel":0,"schedule_id":"schedule2"}));
        assert!(evaluate(&c,&probe()).allowed);
    }
    #[test] fn no_unknown_access_rules() {
        let mut c=fixture();c["access_rules"]=json!([{"always":true}]);
        assert_eq!(reason(&c,&probe()),"configuration_invalid");
    }
}
