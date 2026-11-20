//! HLAXS.Access 0.4 Stage A: cloud-signed bench shadow authorization INSIDE
//! the existing strict-diagnostic Rust controller process.
//!
//! No actuator, GPIO, local access engine, cloud command, or event-write APIs.
//! OFF by default; opt in with HLAXS040_UNIFIED_SHADOW=1 only when strict
//! diagnostic mode is also active. No production authorization is possible.
//! The worker intentionally drops buffered frames on invalid/expired policy.

#[path = "unified_shadow_040/sa08.rs"]
mod sa08;
#[path = "unified_shadow_040/sa10.rs"]
mod sa10;

use anyhow::{Result, anyhow, bail, ensure};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use crate::hal::credential_capture::CaptureFrame;

const ENDPOINT: &str = "https://gxwfuurzkdhxwxdbtdmt.supabase.co/functions/v1/hlaxs-shadow-policy-read/v1/snapshot";
const IDENTITY_PATH: &str = "/etc/hlaxs-access-auto-shadow-035/policy.env";
const PUBLIC_KEY_PATH: &str = "/opt/hlaxs/access-auto-shadow/0.3.5/cloud_bench_signing_public.pem";
const STATE_PATH: &str = "/var/lib/hlaxs/access-unified-shadow-040/state.json";
// Only the signed JSON response is cached: never policy identity headers or secrets.
// This is a diagnostic shadow cache, NOT a production offline access grant.
const SIGNED_CACHE_PATH: &str = "/var/lib/hlaxs/access-unified-shadow-040/signed-policy.json";
const PREVIOUS_STATE_PATH: &str = "/var/lib/hlaxs/access-auto-shadow-035/state.json";
const CONTROLLER: &str = "2722691f-f4db-4f42-b63d-dac94b06ec9e";
const ORGANIZATION: &str = "48409aab-ec9b-4faf-9eb2-204611d09d8b";
const SITE: &str = "a96cb5a6-75f2-4f07-8232-7c405257cfbd";
const MAX_HTTP: usize = 180_000;
const MAX_SIGNED: usize = 130_000;
const REFRESH: Duration = Duration::from_secs(15);

struct PolicyIdentity { id: String, secret: String }
struct SignedPolicy { document: Value, version: u64, checksum: String, expires: DateTime<Utc> }
#[derive(Debug, Clone)]
struct Anchor { version: u64, checksum: String }

fn hex_digest(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) { return None; }
    let mut dst = [0u8; 32];
    for (i, out) in dst.iter_mut().enumerate() {
        *out = u8::from_str_radix(&s[2*i..2*i+2], 16).ok()?;
    }
    if dst == [0; 32] { None } else { Some(dst) }
}

// Strict RFC4648 base64 decoder; avoids a new Cargo dependency / lockfile change.
fn decode_base64(src: &str, limit: usize) -> Result<Vec<u8>> {
    let b = src.as_bytes();
    ensure!(!b.is_empty() && b.len() % 4 == 0 && b.len() <= 8192, "invalid_base64");
    let mut result = Vec::new();
    for (i, quad) in b.chunks_exact(4).enumerate() {
        let last = i == b.len()/4-1;
        let digit = |v: u8| -> Result<u32> {
            Ok(match v { b'A'..=b'Z' => (v-b'A') as u32,
                b'a'..=b'z' => (v-b'a'+26) as u32,
                b'0'..=b'9' => (v-b'0'+52) as u32,
                b'+' => 62, b'/' => 63, _ => bail!("invalid_base64") })
        };
        ensure!(quad[0]!=b'=' && quad[1]!=b'=', "invalid_base64");
        let pad = if quad[2]==b'=' {2} else if quad[3]==b'=' {1} else {0};
        ensure!(last || pad==0, "invalid_base64");
        ensure!(pad!=2 || quad[3]==b'=', "invalid_base64");
        let a=digit(quad[0])?; let b1=digit(quad[1])?;
        let c=if pad==2 {0} else {digit(quad[2])?};
        let d=if pad!=0 {0} else {digit(quad[3])?};
        ensure!((pad!=2 || (b1 & 15)==0) && (pad!=1 || (c & 3)==0), "noncanonical_base64");
        result.push(((a<<2)|(b1>>4)) as u8);
        if pad<2 {result.push(((b1<<4)|(c>>2)) as u8);}
        if pad==0 {result.push(((c<<6)|d) as u8);}
        ensure!(result.len()<=limit, "base64_oversize");
    }
    Ok(result)
}

// No symlinks, non-root ownership, group/world-readable secrets, or giant files.
fn read_root_file(path: &str, max: u64, secret: bool) -> Result<String> {
    let mut f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let meta=f.metadata()?;
    ensure!(meta.is_file() && meta.uid()==0 && meta.len()<=max, "untrusted_file");
    if secret { ensure!(meta.mode() & 0o077 == 0, "untrusted_permissions"); }
    let mut b=String::new(); f.read_to_string(&mut b)?;
    ensure!(b.len() as u64<=max, "oversized_file");
    Ok(b)
}

fn identity() -> Result<PolicyIdentity> {
    let raw=read_root_file(IDENTITY_PATH, 2048, true)?;
    let mut id=None; let mut secret=None;
    for row in raw.lines().filter(|x|!x.is_empty() && !x.starts_with('#')) {
        let (k,v)=row.split_once('=').ok_or_else(||anyhow!("identity_format"))?;
        match k {
            "HLAXS035_POLICY_ID" if id.is_none()=>id=Some(v.to_string()),
            "HLAXS035_POLICY_SECRET" if secret.is_none()=>secret=Some(v.to_string()),
            _=>bail!("identity_format"),
        }
    }
    let id=id.ok_or_else(||anyhow!("identity_format"))?;
    let secret=secret.ok_or_else(||anyhow!("identity_format"))?;
    ensure!(id.len()==36 && id.bytes().all(|b|b.is_ascii_hexdigit()||b==b'-'), "identity_format");
    ensure!(secret.len()==71 && secret.starts_with("HLAXSP_") && secret[7..].bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),"identity_format");
    Ok(PolicyIdentity{id,secret})
}

fn public_key() -> Result<Vec<u8>> {
    let pem=read_root_file(PUBLIC_KEY_PATH,4096,false)?;
    let b64=pem.trim().strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|s|s.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or_else(||anyhow!("public_key_format"))?;
    let b64:String=b64.chars().filter(|c|!c.is_ascii_whitespace()).collect();
    let der=decode_base64(&b64, 64)?;
    let prefix:[u8;12]=[0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];
    ensure!(der.len()==44 && der.starts_with(&prefix),"public_key_der_invalid");
    Ok(der[12..].to_vec())
}

fn bool_is(v:&Value,key:&str,expected:bool)->bool {v.get(key).and_then(Value::as_bool)==Some(expected)}
fn timestamp(v: &Value) -> Result<DateTime<Utc>> {
    let s=v.as_str().ok_or_else(||anyhow!("time_format"))?;
    ensure!(s.ends_with('Z'), "time_format");
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}
fn required_array<'a>(obj: &'a Value, key: &str, cap: usize) -> Result<&'a Vec<Value>> {
    let a=obj.get(key).and_then(Value::as_array).ok_or_else(||anyhow!("policy_missing_list"))?;
    ensure!(a.len()<=cap,"policy_list_oversized"); Ok(a)
}

fn check_policy(p: &Value, now: DateTime<Utc>) -> Result<(u64, String, DateTime<Utc>)> {
    let scopes=[("schema","hlaxs-access-bench-policy-v1"),
        ("policy_origin","cloud_issued_bench_signed_not_production"),
        ("controller_id",CONTROLLER),("organization_id",ORGANIZATION),("site_id",SITE)];
    ensure!(scopes.iter().all(|(k,v)|p.get(*k).and_then(Value::as_str)==Some(*v)),"policy_scope");
    for k in ["outputs_enabled","cloud_commands_retrieved","cloud_events_uploaded",
              "production_signature_verified","physical_reader_verified"] {
        ensure!(bool_is(p,k,false),"policy_authority_invalid");
    }
    let version=p.get("config_version").and_then(Value::as_u64).ok_or_else(||anyhow!("policy_version"))?;
    ensure!((1..=1_000_000).contains(&version),"policy_version");
    let checksum=p.get("config_checksum").and_then(Value::as_str).ok_or_else(||anyhow!("policy_digest"))?;
    ensure!(hex_digest(checksum).is_some(),"policy_digest");
    let issued=timestamp(p.get("issued_at").ok_or_else(||anyhow!("missing_issued"))?)?;
    let expires=timestamp(p.get("expires_at").ok_or_else(||anyhow!("missing_expires"))?)?;
    ensure!(issued <= now+ChronoDuration::seconds(30) && now<expires &&
        expires-issued>=ChronoDuration::minutes(1) && expires-issued<=ChronoDuration::minutes(10),"policy_freshness");
    let readers=required_array(p,"readers",4)?;
    ensure!(readers.len()==4,"reader_count");
    let mut nums=HashSet::new(); let mut channels=HashSet::new(); let mut door_ids=HashSet::new();
    for r in readers {
        let n=r.get("number").and_then(Value::as_u64).ok_or_else(||anyhow!("reader_number"))?;
        let ch=r.get("door_channel").and_then(Value::as_u64).ok_or_else(||anyhow!("door_channel"))?;
        ensure!((1..=4).contains(&n)&&ch<=31&&nums.insert(n)&&channels.insert(ch),"reader_map");
        let reader_id=r.get("reader_id").and_then(Value::as_str).unwrap_or("");
        let door_id=r.get("door_id").and_then(Value::as_str).unwrap_or("");
        ensure!(reader_id.len()==36&&door_id.len()==36&&door_ids.insert(door_id),"reader_bindings");
    }
    ensure!(nums==HashSet::from([1,2,3,4]),"reader_map");
    let creds=required_array(p,"credentials",500)?;
    let mut cards=HashSet::new();
    for c in creds {
        let facility=c.get("facility_code").and_then(Value::as_u64).ok_or_else(||anyhow!("facility_format"))?;
        let card=c.get("card_code").and_then(Value::as_u64).ok_or_else(||anyhow!("card_format"))?;
        ensure!(facility<=255&&card<=65535&&c.get("enabled").and_then(Value::as_bool).is_some()&&cards.insert((facility,card)),"credential_format");
    }
    required_array(p,"access_levels",100)?;
    required_array(p,"credential_access_levels",1000)?;
    required_array(p,"access_level_doors",500)?;
    required_array(p,"schedules",100)?;
    Ok((version,checksum.to_string(),expires))
}

fn verify_envelope(raw:&[u8], key:&[u8],now:DateTime<Utc>)->Result<SignedPolicy> {
    ensure!(raw.len()<=MAX_HTTP,"cloud_payload_too_large");
    let response:Value=serde_json::from_slice(raw)?;
    ensure!(bool_is(&response,"success",true)&&bool_is(&response,"read_only",true)&&
        bool_is(&response,"commands_returned",false)&&bool_is(&response,"outputs_enabled",false)&&
        response.get("capability").and_then(Value::as_str)==Some("signed_shadow_policy_read_only"),"cloud_scope");
    let envelope=response.get("envelope").and_then(Value::as_object).ok_or_else(||anyhow!("missing_envelope"))?;
    ensure!(envelope.len()==3 && envelope.contains_key("signature_alg") && envelope.contains_key("payload_json") && envelope.contains_key("signature_b64"),"envelope_shape");
    ensure!(envelope.get("signature_alg").and_then(Value::as_str)==Some("Ed25519-HLAXS035-bench-cloud"),"signature_algorithm");
    let serialized=envelope.get("payload_json").and_then(Value::as_str).ok_or_else(||anyhow!("missing_signed_payload"))?;
    ensure!(serialized.len()<=MAX_SIGNED,"signed_payload_too_large");
    let signature=decode_base64(envelope.get("signature_b64").and_then(Value::as_str).ok_or_else(||anyhow!("signature_missing"))?,64)?;
    ensure!(signature.len()==64,"signature_size");
    UnparsedPublicKey::new(&ED25519,key).verify(serialized.as_bytes(),&signature).map_err(|_|anyhow!("signature_invalid"))?;
    let policy:Value=serde_json::from_str(serialized)?;
    let (version,checksum,expires)=check_policy(&policy,now)?;
    ensure!(response.get("config_version").and_then(Value::as_u64)==Some(version),"signed_version_mismatch");
    Ok(SignedPolicy{document:policy,version,checksum,expires})
}

fn read_anchor_file(path:&str) -> Result<Option<Anchor>> {
    if !Path::new(path).exists() {return Ok(None)}
    let data=read_root_file(path,1024,true)?;
    let v:Value=serde_json::from_str(&data)?;
    let version=v.get("version").and_then(Value::as_u64).ok_or_else(||anyhow!("anchor_version"))?;
    let digest=v.get("checksum").and_then(Value::as_str).ok_or_else(||anyhow!("anchor_checksum"))?;
    ensure!(version>0 && hex_digest(digest).is_some(), "anchor_format");
    Ok(Some(Anchor{version,checksum:digest.to_string()}))
}
fn merge_anchor(a:Option<Anchor>, b:Option<Anchor>)->Result<Option<Anchor>> {
    match (a,b){
        (None,x)|(x,None)=>Ok(x),
        (Some(a),Some(b)) if a.version==b.version => {
            ensure!(a.checksum==b.checksum,"anchor_conflict");Ok(Some(a))
        },
        (Some(a),Some(b)) =>Ok(Some(if a.version>b.version{a}else{b})),
    }
}
fn baseline()->Result<Option<Anchor>> {
    merge_anchor(read_anchor_file(PREVIOUS_STATE_PATH)?,read_anchor_file(STATE_PATH)?)
}
fn commit_anchor(anchor:&Anchor)->Result<()> {
    let path=Path::new(STATE_PATH);
    let parent=path.parent().ok_or_else(||anyhow!("anchor_path"))?;
    if parent.exists() {
        let meta=fs::symlink_metadata(parent)?;
        ensure!(meta.is_dir()&&!meta.file_type().is_symlink()&&meta.uid()==0&&meta.mode()&0o077==0,"anchor_dir_untrusted");
    } else {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent,fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {let _=read_anchor_file(STATE_PATH)?;}
    let tmp=parent.join(format!(".state-{}-{}.tmp",std::process::id(),anchor.version));
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    let data=json!({"version":anchor.version,"checksum":anchor.checksum}).to_string();
    let outcome=(||->Result<()>{
        f.write_all(data.as_bytes())?;f.sync_all()?;
        fs::rename(&tmp,path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if outcome.is_err(){let _=fs::remove_file(&tmp);}
    outcome
}

// Offline recovery is bound to the latest durable anti-rollback anchor. Even a
// correctly signed older policy is refused if a later version was seen online.
fn verify_recovered_cache(raw:&[u8],key:&[u8],now:DateTime<Utc>,anchor:Option<&Anchor>)->Result<SignedPolicy> {
    let anchor=anchor.ok_or_else(||anyhow!("offline_anchor_missing"))?;
    let p=verify_envelope(raw,key,now)?;
    ensure!(p.version==anchor.version && p.checksum==anchor.checksum,"offline_cache_anchor_mismatch");
    Ok(p)
}

// Root-owned private directory in the real service; current-user-owned private
// directory in unprivileged Rust tests. Atomic same-directory replace and fsync
// guarantee that a partial write is not considered a complete snapshot.
fn store_signed_cache_at(path:&Path,raw:&[u8])->Result<()> {
    ensure!(!raw.is_empty() && raw.len()<=MAX_HTTP,"cache_size_invalid");
    let parent=path.parent().ok_or_else(||anyhow!("cache_parent_missing"))?;
    let uid=unsafe{libc::geteuid()};
    let dir=fs::symlink_metadata(parent)?;
    ensure!(dir.file_type().is_dir() && dir.uid()==uid && dir.mode()&0o077==0,"cache_directory_untrusted");
    match fs::symlink_metadata(path) {
        Ok(m)=>ensure!(m.file_type().is_file() && m.uid()==uid && m.mode()&0o077==0,"cache_file_untrusted"),
        Err(e) if e.kind()==ErrorKind::NotFound=>{},
        Err(e)=>return Err(e.into()),
    }
    let tmp=parent.join(format!(".signed-policy-{}-{}.tmp",std::process::id(),
        Utc::now().timestamp_nanos_opt().ok_or_else(||anyhow!("cache_timestamp"))?));
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp)?;
    let result=(||->Result<()>{
        f.write_all(raw)?;
        f.sync_all()?;
        fs::rename(&tmp,path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err(){let _=fs::remove_file(&tmp);}
    result
}
fn load_signed_cache(key:&[u8],anchor:Option<&Anchor>,now:DateTime<Utc>)->Result<SignedPolicy> {
    // read_root_file rejects symlinks, oversized or non-root-owned cache, and
    // any group/world permission bits, before verifying the Ed25519 envelope.
    let raw=read_root_file(SIGNED_CACHE_PATH,MAX_HTTP as u64,true)?;
    verify_recovered_cache(raw.as_bytes(),key,now,anchor)
}

async fn fetch(client:&reqwest::Client,identity:&PolicyIdentity,key:&[u8])->Result<(SignedPolicy,Vec<u8>)> {
    let mut res=client.get(ENDPOINT)
        .header("x-hlaxs-policy-id",identity.id.as_str())
        .header("x-hlaxs-policy-secret",identity.secret.as_str())
        .header("accept","application/json")
        .send().await?;
    ensure!(res.status().as_u16()==200,"cloud_http_rejected");
    if let Some(len)=res.content_length(){ensure!(len<=MAX_HTTP as u64,"response_oversize");}
    let mut body=Vec::new();
    while let Some(chunk)=res.chunk().await? {
        ensure!(body.len()+chunk.len()<=MAX_HTTP,"response_oversize");
        body.extend_from_slice(&chunk);
    }
    let policy=verify_envelope(&body,key,Utc::now())?;
    Ok((policy,body))
}

// Intentionally redacted classifier from 0.3.5 Rust policy engine. No
// physical reader attestation; never returns an authorization grant.
fn candidate(policy:&Value,frame:&CaptureFrame)->(&'static str,Option<u64>) {
    if frame.overflow || frame.raw_bits.len()!=26 || !frame.raw_bits.bytes().all(|b|b==b'0'||b==b'1') {return ("INVALID_OR_UNSUPPORTED_WIEGAND",None)}
    let Some(readers)=policy.get("readers").and_then(Value::as_array) else{return ("MISSING_READER_MAP",None)};
    let matching:Vec<&Value>=readers.iter().filter(|r|r.get("number").and_then(Value::as_u64)==Some(frame.reader_number as u64)).collect();
    if matching.len()!=1{return ("AMBIGUOUS_OR_UNKNOWN_READER",None)}
    let channel=matching[0].get("door_channel").and_then(Value::as_u64);
    let Some(channel)=channel else{return ("DOOR_CHANNEL_UNBOUND",None)};
    let Some(raw)=u64::from_str_radix(&frame.raw_bits,2).ok() else{return ("INVALID_OR_UNSUPPORTED_WIEGAND",Some(channel))};
    let Ok(decoded)=sa10::decode_h10301(raw,26) else{return ("INVALID_OR_UNSUPPORTED_WIEGAND",Some(channel))};
    let Some(creds)=policy.get("credentials").and_then(Value::as_array) else{return ("MISSING_CREDENTIALS",Some(channel))};
    let same:Vec<&Value>=creds.iter().filter(|c|c.get("facility_code").and_then(Value::as_u64)==Some(decoded.facility as u64) && c.get("card_code").and_then(Value::as_u64)==Some(decoded.card as u64)).collect();
    if same.len()>1{return ("AMBIGUOUS_CREDENTIAL",Some(channel))}
    let Some(cred)=same.first() else{return ("UNKNOWN_CREDENTIAL",Some(channel))};
    if !bool_is(cred,"enabled",true) {return ("DISABLED_CREDENTIAL",Some(channel))}
    if cred.get("valid_from").is_some_and(|x|!x.is_null()) || cred.get("valid_until").is_some_and(|x|!x.is_null()) {return ("CREDENTIAL_VALIDITY_WINDOW_NOT_VERIFIED",Some(channel))}
    let Some(cid)=cred.get("id").and_then(Value::as_str) else{return ("MALFORMED_POLICY",Some(channel))};
    let Some(links)=policy.get("credential_access_levels").and_then(Value::as_array) else{return ("MALFORMED_POLICY",Some(channel))};
    let Some(levels)=policy.get("access_levels").and_then(Value::as_array) else{return ("MALFORMED_POLICY",Some(channel))};
    let Some(door_links)=policy.get("access_level_doors").and_then(Value::as_array) else{return ("MALFORMED_POLICY",Some(channel))};
    let Some(schedules)=policy.get("schedules").and_then(Value::as_array) else{return ("MALFORMED_POLICY",Some(channel))};
    let mut rules=0;let mut unsupported=false;
    for link in links.iter().filter(|v|v.get("credential_id").and_then(Value::as_str)==Some(cid)) {
        let Some(lid)=link.get("access_level_id").and_then(Value::as_str) else{continue};
        if levels.iter().filter(|v|v.get("id").and_then(Value::as_str)==Some(lid)&&bool_is(v,"enabled",true)).count()!=1{continue}
        for dl in door_links.iter().filter(|v|v.get("access_level_id").and_then(Value::as_str)==Some(lid)&&v.get("channel").and_then(Value::as_u64)==Some(channel)) {
            let sid=dl.get("schedule_id").and_then(Value::as_str);
            let eligible:Vec<&Value>=schedules.iter().filter(|v|v.get("id").and_then(Value::as_str)==sid).collect();
            if eligible.len()==1&&eligible[0].get("definition").and_then(|x|x.get("always")).and_then(Value::as_bool)==Some(true){rules+=1}else{unsupported=true}
        }
    }
    (if rules>1 {"AMBIGUOUS_ACCESS_RULE"} else if rules==1&&!unsupported {"MATCHING_24X7_RULE_UNTRUSTED_SOURCE"} else if unsupported {"UNSUPPORTED_OR_AMBIGUOUS_SCHEDULE"} else {"NO_ACCESS_RULE_FOR_DOOR"},Some(channel))
}

fn sa08_untrusted(policy:&SignedPolicy,reader:u64,channel:u64)->sa08::Decision {
    // No call path can set `verified=true` or submit a real actuator intent.
    let binding=sa08::ConfigBinding{epoch:1,version:policy.version,digest:hex_digest(&policy.checksum).unwrap_or([0;32])};
    let scope=sa08::Scope{tenant:1,site:1,controller:1,reader,door:channel+1};
    let clock=sa08::TrustedClock{unix_seconds:0,local:sa08::LocalTime{weekday:0,minute:0,utc_offset_minutes:0},verified:false,timezone_verified:false};
    let request=sa08::Request{subject:[0;32],scope,binding,clock,credential_mapping_verified:false};
    let snapshot=sa08::Snapshot{binding,scope,grants:vec![],verified:false,valid_until:0};
    sa08::evaluate(&request,&snapshot,None)
}

fn shadow_result(policy:&SignedPolicy,frame:&CaptureFrame,source:&str)->Value {
    let (class,door_channel)=candidate(&policy.document,frame);
    let reason=sa08_untrusted(policy,frame.reader_number as u64,door_channel.unwrap_or(0));
    json!({"event":"hlaxs040_unified_shadow_evaluation", "policy_version":policy.version,
        "policy_source":source,"offline_time_trusted":false,"offline_authorization_ready":false,
        "reader_number_claimed":frame.reader_number,"door_channel_claimed":door_channel,
        "policy_candidate":class,"sa08_result":format!("{:?}",reason),
        "shadow_access_decision":"DENY_UNTRUSTED_EVIDENCE","cloud_bench_signature_verified":true,
        "production_config_signature_verified":false,"physical_reader_verified":false,
        "trusted_time_verified":false,"actuator_authority":false,
        "cloud_writes_enabled":false,"outputs_enabled":false})
}

fn run(rx:mpsc::Receiver<CaptureFrame>)->Result<()> {
    let identity=identity()?; let key=public_key()?;
    let client=reqwest::Client::builder().timeout(Duration::from_secs(12)).build()?;
    let rt=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let mut anchor=baseline()?;
    let mut policy:Option<(SignedPolicy,&'static str)>=None;
    // Deliberate bench-only offline simulation without changing NIC or routes.
    // It can ONLY run inside the strict non-actuating diagnostic process.
    let offline_only=std::env::var("HLAXS040_OFFLINE_CACHE_ONLY").as_deref()==Ok("1");
    let mut next_refresh=Instant::now();
    info!(target:"hlaxs040_unified_shadow", "Rust bench shadow worker started (nonactuating)");
    loop {
        if Instant::now()>=next_refresh {
            // Never service reader events while fetching or validating policy.
            // A valid offline cache can support DENY-ONLY diagnostic evaluations
            // until the signed expiry under the (untrusted) device wall clock.
            // This is NOT a trusted time source or production offline access.
            let updated=if offline_only {Err(anyhow!("offline_cache_only_test_mode"))}
                else {rt.block_on(fetch(&client,&identity,&key))};
            policy=None;
            match updated {
                Ok((p,raw))=>{
                    let next=Anchor{version:p.version,checksum:p.checksum.clone()};
                    let status=(||->Result<()>{
                        let durable=baseline()?;
                        anchor=merge_anchor(anchor.take(),durable)?;
                        if let Some(prev)=&anchor {
                            ensure!(next.version>=prev.version,"policy_rollback");
                            ensure!(next.version!=prev.version||next.checksum==prev.checksum,"policy_same_version_drift");
                        }
                        if anchor.as_ref().is_none_or(|prev|next.version>prev.version) {
                            commit_anchor(&next)?;
                        }
                        // Persist exact server envelope bytes with the signature.
                        // No plaintext key, credential secret or request header.
                        store_signed_cache_at(Path::new(SIGNED_CACHE_PATH),&raw)?;
                        anchor=Some(next);
                        Ok(())
                    })();
                    if status.is_ok(){
                        info!(target:"hlaxs040_unified_shadow",config_version=p.version,credentials_loaded_in_memory=p.document["credentials"].as_array().map_or(0,Vec::len),"signed bench policy accepted and cached");
                        policy=Some((p,"cloud_live"));
                    } else {warn!(target:"hlaxs040_unified_shadow", "Policy persistence/rollback validation failed; shadow disabled");}
                }
                Err(_)=>{
                    // Cloud outages and restart recovery share this exact path.
                    // Corrupt, old, expired, conflicting or unanchored cache fails closed.
                    let recovered=(||->Result<SignedPolicy>{
                        anchor=merge_anchor(anchor.take(),baseline()?)?;
                        load_signed_cache(&key,anchor.as_ref(),Utc::now())
                    })();
                    match recovered {
                        Ok(p)=>{
                            info!(target:"hlaxs040_unified_shadow",config_version=p.version,
                                "signed bench policy recovered from offline cache; untrusted time; deny-only shadow");
                            policy=Some((p,"offline_signed_cache"));
                        }
                        Err(_)=>warn!(target:"hlaxs040_unified_shadow",
                            "Cloud policy unavailable; signed cache missing, expired or untrusted; shadow disabled"),
                    }
                }
            }
            // Discard all events collected while remote verification was in flight.
            while rx.try_recv().is_ok() {}
            next_refresh=Instant::now()+REFRESH;
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(frame)=>{
                if let Some((p,source))=&policy {
                    if Utc::now()>=p.expires {policy=None;continue}
                    let result=shadow_result(p,&frame,source);
                    info!(target:"hlaxs040_unified_shadow",result=%result,"NONACTUATING: in-process signed-policy shadow result");
                }
            }
            Err(RecvTimeoutError::Timeout)=>{},
            Err(RecvTimeoutError::Disconnected)=>break,
        }
    }
    Ok(())
}

pub fn start()->Option<SyncSender<CaptureFrame>> {
    if std::env::var("HLAXS040_UNIFIED_SHADOW").as_deref()!=Ok("1") ||
       std::env::var("HLAXS_WIEGAND_EDGE_DIAGNOSTIC").as_deref()!=Ok("1") ||
       unsafe{libc::geteuid()}!=0 {return None}
    let (tx,rx)=mpsc::sync_channel::<CaptureFrame>(128);
    std::thread::spawn(move|| {
        if run(rx).is_err(){warn!(target:"hlaxs040_unified_shadow","Rust shadow worker unavailable; fail closed");}
    });
    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame()->CaptureFrame {CaptureFrame{reader_number:2,raw_bits:"00000010101010110111111111".into(),overflow:false}}
    fn fixture()->Value {json!({"schema":"hlaxs-access-bench-policy-v1","policy_origin":"cloud_issued_bench_signed_not_production",
        "controller_id":CONTROLLER,"organization_id":ORGANIZATION,"site_id":SITE,
        "config_version":6,"config_checksum":"3bcbc91477d56419fe9b871964948d8d6b369a392b6e8ab1265e0df981528b2e",
        "issued_at":"2026-10-27T12:00:00Z","expires_at":"2026-10-27T12:10:00Z",
        "outputs_enabled":false,"cloud_commands_retrieved":false,"cloud_events_uploaded":false,
        "production_signature_verified":false,"physical_reader_verified":false,
        "readers":[{"number":1,"reader_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","door_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","door_channel":0},
                   {"number":2,"reader_id":"cccccccc-cccc-cccc-cccc-cccccccccccc","door_id":"dddddddd-dddd-dddd-dddd-dddddddddddd","door_channel":1},
                   {"number":3,"reader_id":"eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee","door_id":"ffffffff-ffff-ffff-ffff-ffffffffffff","door_channel":2},
                   {"number":4,"reader_id":"11111111-1111-1111-1111-111111111111","door_id":"22222222-2222-2222-2222-222222222222","door_channel":3}],
        "credentials":[],"access_levels":[],"credential_access_levels":[],"access_level_doors":[],"schedules":[]}) }
    #[test] fn base64_known(){assert_eq!(decode_base64("TWFu",64).unwrap(),b"Man");assert_eq!(decode_base64("TWE=",64).unwrap(),b"Ma");assert!(decode_base64("TW=F",64).is_err());}
    #[test] fn reader_2_unknown() {assert_eq!(candidate(&fixture(),&frame()),("UNKNOWN_CREDENTIAL",Some(1)));}
    #[test] fn overflow_denied(){let mut f=frame();f.overflow=true;assert_eq!(candidate(&fixture(),&f).0,"INVALID_OR_UNSUPPORTED_WIEGAND");}
    #[test] fn signed_freshness_gate(){let f=fixture();let now=timestamp(&f["issued_at"]).unwrap();assert!(check_policy(&f,now).is_ok());assert!(check_policy(&f,now+ChronoDuration::minutes(11)).is_err());}
    #[test] fn untrusted_time_deny(){let f=fixture();let now=timestamp(&f["issued_at"]).unwrap();let (version,checksum,expires)=check_policy(&f,now).unwrap();let policy=SignedPolicy{document:f,version,checksum,expires};assert_eq!(shadow_result(&policy,&frame(),"cloud_live")["sa08_result"],"Deny(UntrustedClock)");}
    #[test] fn no_authority_grant(){let f=fixture();let now=timestamp(&f["issued_at"]).unwrap();let (version,checksum,expires)=check_policy(&f,now).unwrap();let policy=SignedPolicy{document:f,version,checksum,expires};let out=shadow_result(&policy,&frame(),"cloud_live");assert_eq!(out["actuator_authority"],false);assert_eq!(out["cloud_writes_enabled"],false);}
    #[test] fn rollback(){let a=Anchor{version:7,checksum:"a".repeat(64)};let b=Anchor{version:6,checksum:"b".repeat(64)};let chosen=merge_anchor(Some(a),Some(b)).unwrap().unwrap();assert_eq!(chosen.version,7);}
    #[test] fn signature_verified_and_tamper_rejected() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let kp=Ed25519KeyPair::from_seed_unchecked(&[7u8;32]).unwrap();
        let document=fixture().to_string();
        let signature=kp.sign(document.as_bytes());
        fn encode(bytes:&[u8])->String {
            const ABC:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out=String::new();
            for c in bytes.chunks(3) {
                let a=c[0];let b=if c.len()>1{c[1]}else{0};let d=if c.len()>2{c[2]}else{0};
                out.push(ABC[(a>>2) as usize] as char);
                out.push(ABC[(((a&3)<<4)|(b>>4)) as usize] as char);
                out.push(if c.len()>1{ABC[(((b&15)<<2)|(d>>6)) as usize] as char}else{'='});
                out.push(if c.len()>2{ABC[(d&63) as usize] as char}else{'='});
            }
            out
        }
        let response=json!({"success":true,"read_only":true,"commands_returned":false,"outputs_enabled":false,
            "capability":"signed_shadow_policy_read_only","config_version":6,
            "envelope":{"signature_alg":"Ed25519-HLAXS035-bench-cloud","payload_json":document,
               "signature_b64":encode(signature.as_ref())}});
        let now=timestamp(&fixture()["issued_at"]).unwrap();
        let bytes=serde_json::to_vec(&response).unwrap();
        assert!(verify_envelope(&bytes,kp.public_key().as_ref(),now).is_ok());
        let mut tamper=response;
        tamper["envelope"]["payload_json"]=json!("{}");
        assert!(verify_envelope(&serde_json::to_vec(&tamper).unwrap(),kp.public_key().as_ref(),now).is_err());
    }
    fn signed_cache_fixture()->(Vec<u8>,Vec<u8>,DateTime<Utc>,Anchor) {
        use ring::signature::{Ed25519KeyPair,KeyPair};
        let kp=Ed25519KeyPair::from_seed_unchecked(&[9u8;32]).unwrap();
        let policy=fixture();
        let document=policy.to_string();
        let sig=kp.sign(document.as_bytes());
        const ABC:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded=String::new();
        for b in sig.as_ref().chunks(3) {
            let a=b[0];let c=if b.len()>1{b[1]}else{0};let d=if b.len()>2{b[2]}else{0};
            encoded.push(ABC[(a>>2) as usize] as char);
            encoded.push(ABC[(((a&3)<<4)|(c>>4)) as usize] as char);
            encoded.push(if b.len()>1{ABC[(((c&15)<<2)|(d>>6)) as usize] as char}else{'='});
            encoded.push(if b.len()>2{ABC[(d&63) as usize] as char}else{'='});
        }
        let raw=json!({"success":true,"read_only":true,"commands_returned":false,"outputs_enabled":false,
            "capability":"signed_shadow_policy_read_only","config_version":6,
            "envelope":{"signature_alg":"Ed25519-HLAXS035-bench-cloud",
                "payload_json":document,"signature_b64":encoded}}).to_string().into_bytes();
        let now=timestamp(&policy["issued_at"]).unwrap();
        let anchor=Anchor{version:6,checksum:policy["config_checksum"].as_str().unwrap().to_string()};
        (raw,kp.public_key().as_ref().to_vec(),now,anchor)
    }
    #[test] fn offline_cache_accepts_only_current_signed_anchor() {
        let (raw,key,now,anchor)=signed_cache_fixture();
        let p=verify_recovered_cache(&raw,&key,now,Some(&anchor)).unwrap();
        assert_eq!(p.version,6);
        assert!(verify_recovered_cache(&raw,&key,now,None).is_err());
        let newer=Anchor{version:7,checksum:anchor.checksum.clone()};
        assert!(verify_recovered_cache(&raw,&key,now,Some(&newer)).is_err());
        let drift=Anchor{version:6,checksum:"a".repeat(64)};
        assert!(verify_recovered_cache(&raw,&key,now,Some(&drift)).is_err());
    }
    #[test] fn offline_cache_rejects_tampering_and_expiry() {
        let (raw,key,now,anchor)=signed_cache_fixture();
        let mut tampered=raw.clone();
        let target=b"cloud_issued_bench_signed_not_production";
        let i=tampered.windows(target.len()).position(|p|p==target).unwrap();
        tampered[i]=b'X';
        assert!(verify_recovered_cache(&tampered,&key,now,Some(&anchor)).is_err());
        assert!(verify_recovered_cache(&raw,&key,now+ChronoDuration::minutes(11),Some(&anchor)).is_err());
    }
    #[test] fn offline_shadow_is_never_authorization() {
        let (raw,key,now,anchor)=signed_cache_fixture();
        let p=verify_recovered_cache(&raw,&key,now,Some(&anchor)).unwrap();
        let out=shadow_result(&p,&frame(),"offline_signed_cache");
        assert_eq!(out["policy_source"],"offline_signed_cache");
        assert_eq!(out["offline_time_trusted"],false);
        assert_eq!(out["offline_authorization_ready"],false);
        assert_eq!(out["shadow_access_decision"],"DENY_UNTRUSTED_EVIDENCE");
        assert_eq!(out["actuator_authority"],false);
        assert_eq!(out["outputs_enabled"],false);
        assert_eq!(out["cloud_writes_enabled"],false);
    }
    #[test] fn cache_atomic_save_preserves_bytes_and_private_permissions() {
        let (raw,_,_,_)=signed_cache_fixture();
        let path=std::env::temp_dir().join(format!("hlaxs040-cache-test-{}-{:?}",std::process::id(),std::thread::current().id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap();
        let file=path.join("signed-policy.json");
        store_signed_cache_at(&file,&raw).unwrap();
        assert_eq!(fs::read(&file).unwrap(),raw);
        assert_eq!(fs::metadata(&file).unwrap().mode()&0o777,0o600);
        // A symlink must never be replaced or followed.
        let link=path.join("link.json");
        std::os::unix::fs::symlink(&file,&link).unwrap();
        assert!(store_signed_cache_at(&link,&raw).is_err());
        fs::remove_dir_all(path).unwrap();
    }
    #[test] fn response_authority_flags_never_enable_actuation() {
        let f=fixture();
        let now=timestamp(&f["issued_at"]).unwrap();
        let mut modified=f.clone();
        modified["outputs_enabled"]=json!(true);
        assert!(check_policy(&modified,now).is_err());
        modified=f;
        modified["production_signature_verified"]=json!(true);
        assert!(check_policy(&modified,now).is_err());
    }
}
