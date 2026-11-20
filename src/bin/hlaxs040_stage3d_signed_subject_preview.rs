//! HLAXS.Access 0.4 Stage 3D — isolated BENCH signed-v7 subject preview.
//! Read-only device utility: never applies controller config, sends an ACK,
//! writes shadow policy/cache/state or drives any physical output.
#![allow(dead_code)]
#[path = "../cloud/unified_shadow_040/sa10.rs"]
mod sa10;
#[path = "../cloud/unified_shadow_040/mapping_3b.rs"]
mod mapping_3b;

use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ring::{digest::{Context as DigestContext, SHA256}, signature::{ED25519, UnparsedPublicKey}};
use serde_json::{Value, json};
use std::{collections::HashSet, fs::{self, File, OpenOptions}, io::Read, os::unix::fs::{MetadataExt, OpenOptionsExt}, process::Command, time::Duration};

const ENDPOINT: &str = "https://gxwfuurzkdhxwxdbtdmt.supabase.co/functions/v1/hlaxs-shadow-policy-preview-v7/v1/snapshot";
const IDENTITY: &str = "/etc/hlaxs-access-auto-shadow-035/policy.env";
const PUBLIC_KEY: &str = "/opt/hlaxs/access-auto-shadow/0.3.5/cloud_bench_signing_public.pem";
const STAGE3C_DB: &str = "/var/lib/hlaxs/access-stage3c-bench/v7-shadow.sqlite";
const UNIT: &str = "highline-nexus-controller.service";
const CONTROLLER: &str = "2722691f-f4db-4f42-b63d-dac94b06ec9e";
const ORG: &str = "48409aab-ec9b-4faf-9eb2-204611d09d8b";
const SITE: &str = "a96cb5a6-75f2-4f07-8232-7c405257cfbd";
const CURRENT_BINARY: &str = "c657b7df809da483a1b88812d6f19e974576fc185c6d72be388debb31595430f";
const CONFIG_SHA: &str = "7a89bb687b6eaa823c5d69c45b32529c4991d8e3e561cff6572d1a80e95320f6";
const TEST_SUBJECT: &str = "e0d7746e-8dd5-4a3d-abdd-ba1404a0fd8b";
const TEST_LEVEL: &str = "2fb75404-53b2-4d89-9d14-4733f90105fd";
const TEST_SCHEDULE: &str = "15009b2d-1b2a-44fb-8bb6-7f79be6d16cd";
const EXPECTED_CREDS: [(&str, u64, u64); 2] = [
    ("af809ce6-4d03-42c8-8392-bf98112280fe", 5, 22271),
    ("d6727897-eb21-47b6-bbda-da4a963b57de", 95, 10773),
];
const MAX_HTTP: usize = 180_000;
const MAX_SIGNED: usize = 130_000;

fn private_file(path: &str, max: u64, secret: bool) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path).with_context(|| format!("cannot_open_{path}"))?;
    let meta=f.metadata()?;
    ensure!(meta.is_file() && meta.uid()==0 && meta.len()>0 && meta.len()<=max, "untrusted_file");
    if secret { ensure!(meta.mode() & 0o077==0, "private_file_mode"); }
    let mut out=Vec::new(); f.take(max+1).read_to_end(&mut out)?;
    ensure!(!out.is_empty() && out.len() as u64<=max, "file_oversized");
    Ok(out)
}

fn b64decode(s: &str, max: usize) -> Result<Vec<u8>> {
    let b=s.as_bytes();
    ensure!(!b.is_empty() && b.len()%4==0 && b.len()<=8192,"base64_format");
    let mut out=Vec::new();
    for (i,chunk) in b.chunks_exact(4).enumerate() {
        let last=i==b.len()/4-1;
        let digit=|v:u8|->Result<u32>{Ok(match v{
            b'A'..=b'Z'=>(v-b'A') as u32,b'a'..=b'z'=>(v-b'a'+26) as u32,
            b'0'..=b'9'=>(v-b'0'+52) as u32,b'+'=>62,b'/'=>63,
            _=>bail!("base64_character")
        })};
        ensure!(chunk[0]!=b'=' && chunk[1]!=b'=',"base64_padding");
        let pad=if chunk[2]==b'=' {2} else if chunk[3]==b'=' {1} else {0};
        ensure!(last||pad==0,"base64_padding");
        ensure!(pad!=2 || chunk[3]==b'=',"base64_padding");
        let a=digit(chunk[0])?; let b=digit(chunk[1])?;
        let c=if pad==2 {0} else {digit(chunk[2])?};
        let d=if pad>0 {0} else {digit(chunk[3])?};
        ensure!((pad!=2 || (b&15)==0) && (pad!=1 || (c&3)==0),"base64_noncanonical");
        out.push(((a<<2)|(b>>4)) as u8);
        if pad<2 { out.push(((b<<4)|(c>>2)) as u8); }
        if pad==0 { out.push(((c<<6)|d) as u8); }
        ensure!(out.len()<=max,"base64_length");
    }
    Ok(out)
}

fn policy_key() -> Result<Vec<u8>> {
    let pem=String::from_utf8(private_file(PUBLIC_KEY,4096,false)?)?;
    let body=pem.trim().strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|s|s.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or_else(||anyhow!("unexpected_public_key_pem"))?;
    let der=b64decode(&body.chars().filter(|c|!c.is_ascii_whitespace()).collect::<String>(),64)?;
    let prefix=[0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];
    ensure!(der.len()==44 && der.starts_with(&prefix),"not_ed25519_public_key");
    Ok(der[12..].to_vec())
}

struct Identity { id: String, secret: String }
fn policy_identity() -> Result<Identity> {
    let raw=String::from_utf8(private_file(IDENTITY,2048,true)?)?;
    let mut id=None; let mut secret=None;
    for line in raw.lines().filter(|line|!line.is_empty()&&!line.starts_with('#')) {
        let (key,value)=line.split_once('=').ok_or_else(||anyhow!("invalid_identity"))?;
        match key {
            "HLAXS035_POLICY_ID" if id.is_none()=>id=Some(value.to_owned()),
            "HLAXS035_POLICY_SECRET" if secret.is_none()=>secret=Some(value.to_owned()),
            _=>bail!("invalid_identity"),
        }
    }
    let id=id.ok_or_else(||anyhow!("missing_policy_id"))?;
    let secret=secret.ok_or_else(||anyhow!("missing_policy_secret"))?;
    ensure!(mapping_3b::valid_reference(&id),"invalid_policy_id");
    ensure!(secret.len()==71 && secret.starts_with("HLAXSP_") &&
        secret[7..].bytes().all(|x|x.is_ascii_hexdigit()&&!x.is_ascii_uppercase()),"invalid_policy_secret");
    Ok(Identity{id,secret})
}

fn sha_reader(mut reader: File) -> Result<String> {
    let mut ctx=DigestContext::new(&SHA256); let mut buf=[0;32768];
    loop {let n=reader.read(&mut buf)?;if n==0{break;} ctx.update(&buf[..n]);}
    Ok(ctx.finish().as_ref().iter().map(|x|format!("{x:02x}")).collect())
}
fn command(name: &str, args: &[&str]) -> Result<String> {
    let out=Command::new(name).args(args).output()?;
    ensure!(out.status.success(),"preflight_command_failed");
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}
fn runtime_preflight() -> Result<()> {
    ensure!(unsafe{libc::geteuid()}==0,"root_required");
    ensure!(command("systemctl", &["is-active",UNIT])?=="active","controller_service_not_active");
    let pid: u32=command("systemctl", &["show","-p","MainPID","--value",UNIT])?.parse()?;
    ensure!(pid>1,"invalid_controller_pid");
    ensure!(sha_reader(File::open(format!("/proc/{pid}/exe"))?)?==CURRENT_BINARY,
        "running_controller_changed");
    let env=fs::read(format!("/proc/{pid}/environ"))?;
    let vars:Vec<&[u8]>=env.split(|b|*b==0).collect();
    for required in [b"HLAXS_WIEGAND_EDGE_DIAGNOSTIC=1".as_slice(),
        b"HLAXS_V23_CAPTURE_UPLOAD=1".as_slice(),
        b"HLAXS040_UNIFIED_SHADOW=1".as_slice()] {
        ensure!(vars.contains(&required),"strict_diagnostic_gate_missing");
    }
    ensure!(!vars.contains(&b"HLAXS040_OFFLINE_CACHE_ONLY=1".as_slice()),
        "offline_cache_simulation_unexpected");
    let meta=fs::symlink_metadata(STAGE3C_DB)?;
    ensure!(meta.file_type().is_file() && meta.uid()==0 && meta.mode() & 0o077==0,
        "stage3c_shadow_snapshot_untrusted");
    println!("RUNNING_STAGE3B=VERIFIED_NONACTUATING");
    println!("RUNNING_SHA256={CURRENT_BINARY}");
    println!("STAGE3C_SHADOW_DB=PRIVATE_PRESENT");
    Ok(())
}

fn required<'a>(v:&'a Value,k:&str,n:usize)->Result<&'a Vec<Value>> {
    let arr=v.get(k).and_then(Value::as_array).ok_or_else(||anyhow!("missing_{k}"))?;
    ensure!(arr.len()==n,"unexpected_{k}_length"); Ok(arr)
}
fn has_false(v:&Value,key:&str)->bool {v.get(key).and_then(Value::as_bool)==Some(false)}
fn has_true(v:&Value,key:&str)->bool {v.get(key).and_then(Value::as_bool)==Some(true)}
fn stamp(v:&Value)->Result<DateTime<Utc>> {
    let s=v.as_str().ok_or_else(||anyhow!("missing_timestamp"))?;
    ensure!(s.ends_with('Z'),"timestamp_not_utc");
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}

fn validate_policy(v:&Value,now:DateTime<Utc>)->Result<()> {
    for (key,want) in [
        ("schema","hlaxs-access-bench-policy-v1"),
        ("policy_origin","cloud_issued_bench_signed_not_production"),
        ("controller_id",CONTROLLER),("organization_id",ORG),("site_id",SITE),
        ("config_checksum",CONFIG_SHA),
        ("config_application_state","staged_not_applied"),
        ("subject_binding_origin","scoped_active_cardholder_credentials")
    ] {ensure!(v.get(key).and_then(Value::as_str)==Some(want),"signed_scope_mismatch_{key}");}
    ensure!(v.get("config_version").and_then(Value::as_u64)==Some(7),"signed_not_v7");
    for k in ["outputs_enabled","cloud_commands_retrieved","cloud_events_uploaded",
        "production_signature_verified","physical_reader_verified","device_acknowledged"] {
        ensure!(has_false(v,k),"signed_authority_flag_{k}");
    }
    ensure!(has_true(v,"preview_only"),"signed_preview_missing");
    let issued=stamp(v.get("issued_at").ok_or_else(||anyhow!("missing_issued"))?)?;
    let expires=stamp(v.get("expires_at").ok_or_else(||anyhow!("missing_expires"))?)?;
    ensure!(issued<=now+ChronoDuration::seconds(30) &&
        expires>now && expires-issued>=ChronoDuration::minutes(1)&&
        expires-issued<=ChronoDuration::minutes(10),"signed_preview_expired_or_clock_untrusted");

    let creds=required(v,"credentials",2)?;
    let seen:HashSet<_>=creds.iter().filter_map(|c|{
        Some((c.get("id")?.as_str()?,c.get("facility_code")?.as_u64()?,c.get("card_code")?.as_u64()?))
    }).collect();
    let expected:HashSet<_>=EXPECTED_CREDS.iter().map(|(id,fc,card)|(*id,*fc,*card)).collect();
    ensure!(seen==expected && creds.iter().all(|c|has_true(c,"enabled") &&
        c.get("subject_id").and_then(Value::as_str)==Some(TEST_SUBJECT) &&
        c.get("valid_from").is_none_or(Value::is_null) &&
        c.get("valid_until").is_none_or(Value::is_null)),"signed_subject_credential_mismatch");
    let readers=required(v,"readers",4)?;
    let mut reader_nums=HashSet::new(); let mut channels=HashSet::new();
    for r in readers {
        let num=r.get("number").and_then(Value::as_u64).ok_or_else(||anyhow!("reader_number_missing"))?;
        let channel=r.get("door_channel").and_then(Value::as_u64).ok_or_else(||anyhow!("channel_missing"))?;
        ensure!((1..=4).contains(&num)&&channel==num-1&&
            reader_nums.insert(num)&&channels.insert(channel)&&
            r.get("reader_id").and_then(Value::as_str).is_some_and(mapping_3b::valid_reference)&&
            r.get("door_id").and_then(Value::as_str).is_some_and(mapping_3b::valid_reference),
            "reader_door_map_mismatch");
    }
    ensure!(reader_nums==HashSet::from([1,2,3,4]),"reader_map_incomplete");
    let levels=required(v,"access_levels",1)?;
    ensure!(levels[0].get("id").and_then(Value::as_str)==Some(TEST_LEVEL) &&
        has_true(&levels[0],"enabled"),"access_level_mismatch");
    let links=required(v,"credential_access_levels",2)?;
    let mapped:HashSet<_>=links.iter().filter_map(|link|{
        Some((link.get("credential_id")?.as_str()?,link.get("access_level_id")?.as_str()?))
    }).collect();
    let wanted:HashSet<_>=EXPECTED_CREDS.iter().map(|(id,_,_)|(*id,TEST_LEVEL)).collect();
    ensure!(mapped==wanted,"credential_access_links_mismatch");
    let dl=required(v,"access_level_doors",4)?;
    let got:HashSet<_>=dl.iter().filter_map(|x|{
        Some((x.get("access_level_id")?.as_str()?,x.get("channel")?.as_u64()?,x.get("schedule_id")?.as_str()?))
    }).collect();
    let want:HashSet<_>=(0..4).map(|i|(TEST_LEVEL,i,TEST_SCHEDULE)).collect();
    ensure!(got==want,"door_access_links_mismatch");
    let schedules=required(v,"schedules",1)?;
    ensure!(schedules[0].get("id").and_then(Value::as_str)==Some(TEST_SCHEDULE) &&
        schedules[0].get("definition")==Some(&json!({"always":true})),"24x7_schedule_mismatch");
    Ok(())
}

fn verify_signed_response(bytes:&[u8],key:&[u8],now:DateTime<Utc>)->Result<Value> {
    ensure!(bytes.len()<=MAX_HTTP,"preview_response_too_large");
    let outer:Value=serde_json::from_slice(bytes)?;
    ensure!(has_true(&outer,"success") && has_true(&outer,"read_only") &&
        has_true(&outer,"preview_only") && has_false(&outer,"device_acknowledged") &&
        has_false(&outer,"commands_returned") && has_false(&outer,"outputs_enabled") &&
        outer.get("capability").and_then(Value::as_str)==Some("signed_shadow_policy_read_only") &&
        outer.get("config_version").and_then(Value::as_u64)==Some(7),"invalid_preview_response_contract");
    let envelope=outer.get("envelope").and_then(Value::as_object).ok_or_else(||anyhow!("missing_envelope"))?;
    ensure!(envelope.len()==3,"unexpected_envelope_fields");
    ensure!(envelope.get("signature_alg").and_then(Value::as_str)==Some("Ed25519-HLAXS035-bench-cloud"),"unknown_signer");
    let payload=envelope.get("payload_json").and_then(Value::as_str).ok_or_else(||anyhow!("missing_signed_payload"))?;
    ensure!(payload.len()<=MAX_SIGNED,"oversized_signed_payload");
    let signature=b64decode(envelope.get("signature_b64").and_then(Value::as_str).ok_or_else(||anyhow!("signature_missing"))?,64)?;
    ensure!(signature.len()==64,"signature_wrong_size");
    UnparsedPublicKey::new(&ED25519,key).verify(payload.as_bytes(),&signature).map_err(|_|anyhow!("ed25519_signature_invalid"))?;
    let policy:Value=serde_json::from_str(payload)?;
    validate_policy(&policy,now)?;
    Ok(policy)
}

fn wiegand(fc:u8,card:u16)->String {
    let data=((fc as u64)<<17)|((card as u64)<<1);
    let upper=(data>>13)&0xfff; let lower=(data>>1)&0xfff;
    let bits=data|((upper.count_ones() as u64 % 2)<<25)|((1-lower.count_ones() as u64 % 2));
    format!("{bits:026b}")
}
fn eval_preview(policy:&Value)->Result<()> {
    // This is a synthetic correctly-formed H10301 frame, NOT physical reader proof.
    let synthetic=wiegand(5,22271);
    for reader in 1..=4usize {
        let outcome=mapping_3b::assess(policy,reader,&synthetic,false);
        ensure!(outcome.channel==Some((reader-1) as u64) &&
            outcome.credential_binding=="SIGNED_CREDENTIAL_REFERENCE_PRESENT"&&
            outcome.subject_binding=="SIGNED_SUBJECT_REFERENCE_PRESENT_UNATTESTED"&&
            outcome.access_rule=="MATCHING_24X7_RULE_UNTRUSTED_SOURCE", "mapped_bench_preview_rule_invalid");
        println!("READER{reader}_SIGNED_V7_RULE=MATCHED_BENCH_PREVIEW_CHANNEL_{}",reader-1);
    }
    println!("SUBJECT_REFERENCE={TEST_SUBJECT}");
    println!("CREDENTIAL_REFERENCE=FC5_CARD22271");
    println!("SIGNED_SUBJECT_REFERENCE=VERIFIED_BENCH_PREVIEW_ONLY");
    println!("PHYSICAL_READER_EVENT=NOT_TESTED");
    println!("TRUSTED_TIME=NOT_ESTABLISHED");
    println!("SHADOW_DECISION=DENY_UNTRUSTED_EVIDENCE");
    println!("LIVE_POLICY_VERSION=UNCHANGED_V6");
    println!("CLOUD_ACK_SENT=NO");
    println!("LIVE_CONFIG_APPLIED=NO");
    println!("ACTUATOR_AUTHORITY=FALSE");
    Ok(())
}

async fn fetch_preview(id:&Identity,key:&[u8])->Result<Value>{
    let client=reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
    let mut response=client.get(ENDPOINT)
        .header("x-hlaxs-policy-id",id.id.as_str())
        .header("x-hlaxs-policy-secret",id.secret.as_str())
        .header("accept","application/json")
        .send().await?;
    ensure!(response.status().as_u16()==200,"preview_http_rejected");
    if let Some(n)=response.content_length(){ensure!(n<=MAX_HTTP as u64,"preview_http_oversized");}
    let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await? {
        ensure!(bytes.len()+chunk.len()<=MAX_HTTP,"preview_http_oversized");
        bytes.extend_from_slice(&chunk);
    }
    verify_signed_response(&bytes,key,Utc::now())
}

fn main()->Result<()> {
    let args:Vec<_>=std::env::args().collect();
    ensure!(args.len()==2 && ["--preflight","--verify-v7-preview"].contains(&args[1].as_str()),
        "usage: --preflight | --verify-v7-preview");
    runtime_preflight()?;
    let identity=policy_identity()?;
    let key=policy_key()?;
    ensure!(key.len()==32,"public_key_bad_length");
    println!("BENCH_SIGNING_KEY=VERIFIED_FORMAT");
    println!("DEVICE_POLICY_IDENTITY=PRIVATE_AND_IN_SCOPE");
    if args[1]=="--preflight" {
        println!("STAGE3D_PREFLIGHT=PASS");
        println!("DEVICE_WRITES=NONE");
        return Ok(());
    }
    let rt=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let policy=rt.block_on(fetch_preview(&identity,&key))?;
    println!("ED25519_SIGNATURE=VERIFIED");
    println!("CONFIG_VERSION=7");
    println!("CONFIG_SHA256={CONFIG_SHA}");
    eval_preview(&policy)?;
    println!("STAGE3D_SIGNED_V7_SUBJECT_PREVIEW=PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::{Ed25519KeyPair,KeyPair}};
    fn fixture(now:DateTime<Utc>)->Value {
        json!({"schema":"hlaxs-access-bench-policy-v1","policy_origin":"cloud_issued_bench_signed_not_production",
        "controller_id":CONTROLLER,"organization_id":ORG,"site_id":SITE,"config_version":7,
        "config_checksum":CONFIG_SHA,"issued_at":now.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
        "expires_at":(now+ChronoDuration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
        "outputs_enabled":false,"cloud_commands_retrieved":false,"cloud_events_uploaded":false,
        "production_signature_verified":false,"physical_reader_verified":false,"device_acknowledged":false,
        "preview_only":true,"config_application_state":"staged_not_applied",
        "subject_binding_origin":"scoped_active_cardholder_credentials",
        "readers":(1..=4).map(|n|json!({"number":n,"door_channel":n-1,
           "reader_id":"11111111-1111-1111-1111-111111111111",
           "door_id":"22222222-2222-2222-2222-222222222222"})).collect::<Vec<_>>(),
        "credentials":EXPECTED_CREDS.iter().map(|(id,fc,card)|json!({"id":id,"facility_code":fc,
           "card_code":card,"subject_id":TEST_SUBJECT,"enabled":true,"valid_from":null,"valid_until":null})).collect::<Vec<_>>(),
        "access_levels":[{"id":TEST_LEVEL,"enabled":true}],
        "credential_access_levels":EXPECTED_CREDS.iter().map(|(id,_,_)|json!({"credential_id":id,"access_level_id":TEST_LEVEL})).collect::<Vec<_>>(),
        "access_level_doors":(0..4).map(|c|json!({"access_level_id":TEST_LEVEL,"channel":c,"schedule_id":TEST_SCHEDULE})).collect::<Vec<_>>(),
        "schedules":[{"id":TEST_SCHEDULE,"timezone":"America/New_York","definition":{"always":true}}]})
    }
    fn b64encode(bytes:&[u8])->String {
        const CHARS:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out=String::new();
        for c in bytes.chunks(3) {
            let n=((c[0] as u32)<<16)|((c.get(1).copied().unwrap_or(0) as u32)<<8)|c.get(2).copied().unwrap_or(0) as u32;
            out.push(CHARS[((n>>18)&63) as usize] as char);
            out.push(CHARS[((n>>12)&63) as usize] as char);
            out.push(if c.len()>1{CHARS[((n>>6)&63) as usize] as char}else{'='});
            out.push(if c.len()>2{CHARS[(n&63) as usize] as char}else{'='});
        }
        out
    }
    fn signed_fixture()->(Vec<u8>,Vec<u8>) {
        let pair=Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key=Ed25519KeyPair::from_pkcs8(pair.as_ref()).unwrap();
        let doc=fixture(Utc::now()).to_string();
        let sig=key.sign(doc.as_bytes());
        let raw=json!({"success":true,"capability":"signed_shadow_policy_read_only",
            "read_only":true,"commands_returned":false,"outputs_enabled":false,
            "preview_only":true,"device_acknowledged":false,"config_version":7,
            "envelope":{"signature_alg":"Ed25519-HLAXS035-bench-cloud",
            "payload_json":doc,"signature_b64":b64encode(sig.as_ref())}}).to_string().into_bytes();
        (raw,key.public_key().as_ref().to_vec())
    }
    #[test] fn stage3d_signed_fixture_maps_four_doors(){
        let (bytes,key)=signed_fixture();
        let doc=verify_signed_response(&bytes,&key,Utc::now()).unwrap();
        assert!(eval_preview(&doc).is_ok());
    }
    #[test] fn tampered_envelope_signature_fails(){
        let (bytes,key)=signed_fixture();
        let mut v:Value=serde_json::from_slice(&bytes).unwrap();
        v["envelope"]["payload_json"]=json!("{}");
        assert!(verify_signed_response(&serde_json::to_vec(&v).unwrap(),&key,Utc::now()).is_err());
    }
    #[test] fn absent_subject_reference_denied(){
        let mut doc=fixture(Utc::now());
        doc["credentials"][0].as_object_mut().unwrap().remove("subject_id");
        assert!(validate_policy(&doc,Utc::now()).is_err());
    }
    #[test] fn unauthorized_output_flag_denied(){
        let mut doc=fixture(Utc::now()); doc["outputs_enabled"]=json!(true);
        assert!(validate_policy(&doc,Utc::now()).is_err());
    }
    #[test] fn access_scope_expansion_denied(){
        let mut doc=fixture(Utc::now()); doc["access_level_doors"][0]["channel"]=json!(9);
        assert!(validate_policy(&doc,Utc::now()).is_err());
    }
    #[test] fn wrong_version_denied(){
        let mut doc=fixture(Utc::now());doc["config_version"]=json!(6);
        assert!(validate_policy(&doc,Utc::now()).is_err());
    }
}
