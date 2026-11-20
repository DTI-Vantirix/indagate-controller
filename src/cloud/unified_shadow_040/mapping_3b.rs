//! Stage 3B: signed bench policy credential/subject/door projection.
//! This module does NOT attest reader origin, trusted time, subject provenance,
//! or production authorization. It returns classifications only: never grants.
use serde_json::Value;
use super::sa10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assessment {
    pub class: &'static str,
    pub channel: Option<u64>,
    pub credential_binding: &'static str,
    pub subject_binding: &'static str,
    pub access_rule: &'static str,
}
impl Assessment {
    fn new(class: &'static str, channel: Option<u64>) -> Self {
        Self { class, channel, credential_binding: "NOT_RESOLVED",
            subject_binding: "NOT_RESOLVED", access_rule: "NOT_EVALUATED" }
    }
}

// These are opaque record references, not proof of an identified person.
// Require canonical lowercase non-nil UUID spelling, prohibit invented identities.
pub fn valid_reference(s: &str) -> bool {
    if s.len() != 36 || s == "00000000-0000-0000-0000-000000000000" { return false; }
    s.bytes().enumerate().all(|(i, b)| {
        if [8, 13, 18, 23].contains(&i) { b == b'-' }
        else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() }
    })
}

fn always_policy(s: &Value) -> bool {
    let Some(def) = s.get("definition").and_then(Value::as_object) else { return false; };
    // Do not reinterpret a complex/holiday/scheduled rule as unrestricted 24x7.
    def.len() == 1 && def.get("always").and_then(Value::as_bool) == Some(true)
}

pub fn assess(policy: &Value, reader_number: usize, bits: &str, overflow: bool) -> Assessment {
    if !(1..=4).contains(&reader_number) {
        return Assessment::new("AMBIGUOUS_OR_UNKNOWN_READER", None);
    }
    if overflow || bits.len() != 26 || !bits.bytes().all(|b| b == b'0' || b == b'1') {
        return Assessment::new("INVALID_OR_UNSUPPORTED_WIEGAND", None);
    }
    let Some(readers) = policy.get("readers").and_then(Value::as_array) else {
        return Assessment::new("MISSING_READER_MAP", None);
    };
    let matching: Vec<_> = readers.iter().filter(|r|
        r.get("number").and_then(Value::as_u64) == Some(reader_number as u64)).collect();
    if matching.len() != 1 { return Assessment::new("AMBIGUOUS_OR_UNKNOWN_READER", None); }
    let Some(channel) = matching[0].get("door_channel").and_then(Value::as_u64) else {
        return Assessment::new("DOOR_CHANNEL_UNBOUND", None);
    };
    let Some(raw) = u64::from_str_radix(bits, 2).ok() else {
        return Assessment::new("INVALID_OR_UNSUPPORTED_WIEGAND", Some(channel));
    };
    let Ok(decoded) = sa10::decode_h10301(raw, 26) else {
        return Assessment::new("INVALID_OR_UNSUPPORTED_WIEGAND", Some(channel));
    };
    let Some(creds) = policy.get("credentials").and_then(Value::as_array) else {
        return Assessment::new("MISSING_CREDENTIALS", Some(channel));
    };
    let same: Vec<_> = creds.iter().filter(|c|
        c.get("facility_code").and_then(Value::as_u64) == Some(decoded.facility as u64) &&
        c.get("card_code").and_then(Value::as_u64) == Some(decoded.card as u64)).collect();
    if same.len() > 1 { return Assessment::new("AMBIGUOUS_CREDENTIAL", Some(channel)); }
    let Some(cred) = same.first() else {
        return Assessment::new("UNKNOWN_CREDENTIAL", Some(channel));
    };
    let mut out = Assessment::new("UNDETERMINED", Some(channel));
    let Some(cid) = cred.get("id").and_then(Value::as_str) else {
        out.class = "MALFORMED_POLICY";
        return out;
    };
    if !valid_reference(cid) { out.class = "MALFORMED_POLICY"; return out; }
    out.credential_binding = "SIGNED_CREDENTIAL_REFERENCE_PRESENT";
    out.subject_binding = match cred.get("subject_id") {
        None | Some(Value::Null) => "MISSING_SIGNED_SUBJECT_REFERENCE",
        Some(Value::String(s)) if valid_reference(s) => "SIGNED_SUBJECT_REFERENCE_PRESENT_UNATTESTED",
        _ => "INVALID_SIGNED_SUBJECT_REFERENCE",
    };
    if out.subject_binding == "INVALID_SIGNED_SUBJECT_REFERENCE" {
        out.class = "MALFORMED_POLICY";
        return out;
    }
    if cred.get("enabled").and_then(Value::as_bool) != Some(true) {
        out.class = "DISABLED_CREDENTIAL";
        return out;
    }
    if cred.get("valid_from").is_some_and(|x| !x.is_null()) ||
        cred.get("valid_until").is_some_and(|x| !x.is_null()) {
        out.class = "CREDENTIAL_VALIDITY_WINDOW_NOT_VERIFIED";
        return out;
    }
    let Some(links) = policy.get("credential_access_levels").and_then(Value::as_array) else {
        out.class = "MALFORMED_POLICY"; return out;
    };
    let Some(levels) = policy.get("access_levels").and_then(Value::as_array) else {
        out.class = "MALFORMED_POLICY"; return out;
    };
    let Some(door_links) = policy.get("access_level_doors").and_then(Value::as_array) else {
        out.class = "MALFORMED_POLICY"; return out;
    };
    let Some(schedules) = policy.get("schedules").and_then(Value::as_array) else {
        out.class = "MALFORMED_POLICY"; return out;
    };
    let mut always_rules = 0usize;
    let mut unsupported = false;
    for link in links.iter().filter(|l|l.get("credential_id").and_then(Value::as_str)==Some(cid)) {
        let Some(level_id) = link.get("access_level_id").and_then(Value::as_str) else {
            unsupported = true; continue;
        };
        let level_matches: Vec<_> = levels.iter().filter(|l|
            l.get("id").and_then(Value::as_str) == Some(level_id)).collect();
        if level_matches.len() != 1 {unsupported = true; continue;}
        if level_matches[0].get("enabled").and_then(Value::as_bool) != Some(true) {continue;}
        for dl in door_links.iter().filter(|l|
            l.get("access_level_id").and_then(Value::as_str)==Some(level_id) &&
            l.get("channel").and_then(Value::as_u64)==Some(channel)) {
            let sid=dl.get("schedule_id").and_then(Value::as_str);
            let found:Vec<_>=schedules.iter().filter(|s|s.get("id").and_then(Value::as_str)==sid).collect();
            if found.len() == 1 && always_policy(found[0]) {always_rules += 1;}
            else {unsupported = true;}
        }
    }
    out.access_rule = if always_rules > 1 { "AMBIGUOUS_ACCESS_RULE" }
        else if unsupported { "UNSUPPORTED_OR_AMBIGUOUS_SCHEDULE" }
        else if always_rules == 1 { "MATCHING_24X7_RULE_UNTRUSTED_SOURCE" }
        else { "NO_ACCESS_RULE_FOR_DOOR" };
    out.class = out.access_rule;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const CID:&str="11111111-1111-1111-1111-111111111111";
    const SID:&str="22222222-2222-2222-2222-222222222222";
    const LID:&str="33333333-3333-3333-3333-333333333333";
    const TID:&str="44444444-4444-4444-4444-444444444444";
    fn frame(fc:u8,card:u16)->String {
        let data=((fc as u64)<<17)|((card as u64)<<1);
        let hi=(data>>13)&0xfff; let lo=(data>>1)&0xfff;
        let raw=data|(((hi.count_ones()%2) as u64)<<25)|((1-(lo.count_ones()%2) as u64));
        format!("{raw:026b}")
    }
    fn policy()->Value {json!({
        "readers":[{"number":2,"door_channel":1}],
        "credentials":[{"id":CID,"subject_id":SID,"enabled":true,"facility_code":5,"card_code":22271,
                        "valid_from":null,"valid_until":null}],
        "access_levels":[{"id":LID,"enabled":true}],
        "credential_access_levels":[{"credential_id":CID,"access_level_id":LID}],
        "access_level_doors":[{"access_level_id":LID,"channel":1,"schedule_id":TID}],
        "schedules":[{"id":TID,"timezone":"UTC","definition":{"always":true}}]
    })}
    fn report(p:&Value)->Assessment {assess(p,2,&frame(5,22271),false)}
    #[test] fn explicit_signed_subject_and_door_link() {
        let a=report(&policy());
        assert_eq!(a.subject_binding,"SIGNED_SUBJECT_REFERENCE_PRESENT_UNATTESTED");
        assert_eq!(a.access_rule,"MATCHING_24X7_RULE_UNTRUSTED_SOURCE");
        assert_eq!(a.channel,Some(1));
    }
    #[test] fn existing_v1_without_subject_does_not_invent_identity() {
        let mut p=policy();p["credentials"][0].as_object_mut().unwrap().remove("subject_id");
        let a=report(&p);
        assert_eq!(a.subject_binding,"MISSING_SIGNED_SUBJECT_REFERENCE");
        assert_eq!(a.access_rule,"MATCHING_24X7_RULE_UNTRUSTED_SOURCE");
    }
    #[test] fn nil_or_malformed_subject_is_rejected() {
        let mut p=policy();
        for value in [json!("00000000-0000-0000-0000-000000000000"),json!("not-a-uuid"),json!(23)] {
            p["credentials"][0]["subject_id"]=value;
            assert_eq!(report(&p).class,"MALFORMED_POLICY");
        }
    }
    #[test] fn unknown_card_is_not_mapped() {
        let a=assess(&policy(),2,&frame(5,22272),false);
        assert_eq!(a.class,"UNKNOWN_CREDENTIAL");
        assert_eq!(a.subject_binding,"NOT_RESOLVED");
    }
    #[test] fn reader_binding_missing_does_not_map() {
        assert_eq!(assess(&policy(),3,&frame(5,22271),false).class,"AMBIGUOUS_OR_UNKNOWN_READER");
    }
    #[test] fn access_on_another_door_does_not_match() {
        let mut p=policy();p["access_level_doors"][0]["channel"]=json!(3);
        assert_eq!(report(&p).access_rule,"NO_ACCESS_RULE_FOR_DOOR");
    }
    #[test] fn revoked_disabled_credential_does_not_match() {
        let mut p=policy();p["credentials"][0]["enabled"]=json!(false);
        assert_eq!(report(&p).class,"DISABLED_CREDENTIAL");
    }
    #[test] fn duplicate_credential_does_not_resolve() {
        let mut p=policy();let extra=p["credentials"][0].clone();
        p["credentials"].as_array_mut().unwrap().push(extra);
        assert_eq!(report(&p).class,"AMBIGUOUS_CREDENTIAL");
    }
    #[test] fn duplicate_rules_fail_closed() {
        let mut p=policy();let extra=p["access_level_doors"][0].clone();
        p["access_level_doors"].as_array_mut().unwrap().push(extra);
        assert_eq!(report(&p).access_rule,"AMBIGUOUS_ACCESS_RULE");
    }
    #[test] fn complex_schedule_does_not_become_always() {
        let mut p=policy();p["schedules"][0]["definition"]=json!({"always":true,"holidays":["2026-12-25"]});
        assert_eq!(report(&p).access_rule,"UNSUPPORTED_OR_AMBIGUOUS_SCHEDULE");
    }
    #[test] fn malformed_parity_or_overflow_is_refused() {
        let bits=frame(5,22271);
        assert_eq!(assess(&policy(),2,&bits,true).class,"INVALID_OR_UNSUPPORTED_WIEGAND");
        let mut b=bits.into_bytes();b[25]=if b[25]==b'0'{b'1'}else{b'0'};
        assert_eq!(assess(&policy(),2,std::str::from_utf8(&b).unwrap(),false).class,"INVALID_OR_UNSUPPORTED_WIEGAND");
    }
}
