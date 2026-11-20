//! Indagate Access Stage 3E — physical CAPTURE shadow classifier for signed v7 BENCH PREVIEW.
//! Strictly a diagnostic in-memory data path. Nothing here can apply configurations,
//! acknowledge a controller version, grant an unlock, operate GPIO/relay, or write a cache.
//! A frame observed by the capture worker is NOT cryptographic reader attestation.

use super::*;

const PREVIEW_ENDPOINT: &str =
    "https://gxwfuurzkdhxwxdbtdmt.supabase.co/functions/v1/hlaxs-shadow-policy-preview-v7/v1/snapshot";
const PREVIEW_CHECKSUM: &str = "7a89bb687b6eaa823c5d69c45b32529c4991d8e3e561cff6572d1a80e95320f6";
const PREVIEW_SUBJECT: &str = "e0d7746e-8dd5-4a3d-abdd-ba1404a0fd8b";
const PREVIEW_LEVEL: &str = "2fb75404-53b2-4d89-9d14-4733f90105fd";
const PREVIEW_SCHEDULE: &str = "15009b2d-1b2a-44fb-8bb6-7f79be6d16cd";
const PREVIEW_CARDS: [(&str, u64, u64); 2] = [
    ("af809ce6-4d03-42c8-8392-bf98112280fe",5,22271),
    ("d6727897-eb21-47b6-bbda-da4a963b57de",95,10773),
];
const PREVIEW_STAGE_DB: &str = "/var/lib/hlaxs/access-stage3c-bench/v7-shadow.sqlite";

fn field(v:&Value,k:&str,want:&str) -> bool {
    v.get(k).and_then(Value::as_str)==Some(want)
}

fn exact_array<'a>(p:&'a Value,k:&str,n:usize) -> Result<&'a Vec<Value>> {
    let items=required_array(p,k,n)?;
    ensure!(items.len()==n,"preview_list_count");
    Ok(items)
}

pub(super) fn stage_db_private() -> Result<()> {
    // This is a presence/ownership gate. Stage 3C CLI separately validates
    // recovery and checksum; the file is NEVER opened or modified here.
    let meta=fs::symlink_metadata(PREVIEW_STAGE_DB)?;
    ensure!(meta.file_type().is_file()&&meta.uid()==0&&meta.mode()&0o077==0,
        "stage3c_database_not_private");
    Ok(())
}

pub(super) fn validate_preview_document(p:&Value) -> Result<()> {
    ensure!(p.get("config_version").and_then(Value::as_u64)==Some(7) &&
        field(p,"config_checksum",PREVIEW_CHECKSUM) &&
        field(p,"config_application_state","staged_not_applied") &&
        field(p,"subject_binding_origin","scoped_active_cardholder_credentials") &&
        bool_is(p,"preview_only",true) && bool_is(p,"device_acknowledged",false),
        "preview_contract_or_version_invalid");
    for key in ["outputs_enabled","cloud_commands_retrieved","cloud_events_uploaded",
                "production_signature_verified","physical_reader_verified"] {
        ensure!(bool_is(p,key,false),"preview_authority_invalid");
    }
    let readers=exact_array(p,"readers",4)?;
    let mut found_readers=HashSet::new();
    let mut found_reader_ids=HashSet::new();
    let mut found_doors=HashSet::new();
    for r in readers {
        let number=r.get("number").and_then(Value::as_u64).ok_or_else(||anyhow!("preview_reader_number"))?;
        let channel=r.get("door_channel").and_then(Value::as_u64).ok_or_else(||anyhow!("preview_reader_channel"))?;
        let reader_id=r.get("reader_id").and_then(Value::as_str).unwrap_or("");
        let door_id=r.get("door_id").and_then(Value::as_str).unwrap_or("");
        ensure!((1..=4).contains(&number)&&channel==number-1&&found_readers.insert(number)&&
            mapping_3b::valid_reference(reader_id)&&found_reader_ids.insert(reader_id)&&
            mapping_3b::valid_reference(door_id)&&found_doors.insert(door_id),"preview_reader_map");
    }
    ensure!(found_readers==HashSet::from([1,2,3,4]),"preview_reader_map_incomplete");
    let credentials=exact_array(p,"credentials",2)?;
    let mut found=HashSet::new();
    for c in credentials {
        let id=c.get("id").and_then(Value::as_str).unwrap_or("");
        let fc=c.get("facility_code").and_then(Value::as_u64).ok_or_else(||anyhow!("preview_fc"))?;
        let card=c.get("card_code").and_then(Value::as_u64).ok_or_else(||anyhow!("preview_card"))?;
        ensure!(PREVIEW_CARDS.iter().any(|(i,f,n)|*i==id&&*f==fc&&*n==card)&&
            found.insert(id)&&bool_is(c,"enabled",true)&&
            field(c,"subject_id",PREVIEW_SUBJECT)&&
            c.get("valid_from").is_none_or(Value::is_null)&&
            c.get("valid_until").is_none_or(Value::is_null),"preview_credential_or_subject");
    }
    ensure!(found.len()==2,"preview_credential_duplicate");
    let levels=exact_array(p,"access_levels",1)?;
    ensure!(field(&levels[0],"id",PREVIEW_LEVEL)&&bool_is(&levels[0],"enabled",true),
        "preview_access_level");
    let links=exact_array(p,"credential_access_levels",2)?;
    let mut link_ids=HashSet::new();
    for l in links {
        let id=l.get("credential_id").and_then(Value::as_str).unwrap_or("");
        ensure!(PREVIEW_CARDS.iter().any(|(i,_,_)|*i==id)&&
            field(l,"access_level_id",PREVIEW_LEVEL)&&link_ids.insert(id),
            "preview_credential_access_level");
    }
    ensure!(link_ids.len()==2,"preview_credential_access_links");
    let doors=exact_array(p,"access_level_doors",4)?;
    let mut door_channels=HashSet::new();
    for d in doors {
        let channel=d.get("channel").and_then(Value::as_u64).ok_or_else(||anyhow!("preview_door_channel"))?;
        ensure!(channel<=3&&door_channels.insert(channel)&&
            field(d,"access_level_id",PREVIEW_LEVEL)&&
            field(d,"schedule_id",PREVIEW_SCHEDULE),"preview_door_access_level");
    }
    ensure!(door_channels==HashSet::from([0,1,2,3]),"preview_doors_incomplete");
    let schedules=exact_array(p,"schedules",1)?;
    ensure!(field(&schedules[0],"id",PREVIEW_SCHEDULE)&&
        field(&schedules[0],"timezone","America/New_York")&&
        schedules[0].get("definition")==Some(&json!({"always":true})),"preview_24x7_schedule");
    Ok(())
}

pub(super) fn verify_preview(raw:&[u8],key:&[u8],now:DateTime<Utc>) -> Result<SignedPolicy> {
    // The reusable 3B verifier verifies exact serialized Ed25519 bytes,
    // 10-minute freshness, controller/site/organization scope, and all
    // non-actuating flags BEFORE any Stage3E preview classification.
    let outer:Value=serde_json::from_slice(raw)?;
    ensure!(bool_is(&outer,"preview_only",true)&&bool_is(&outer,"device_acknowledged",false),
        "not_a_signed_preview_response");
    let p=verify_envelope(raw,key,now)?;
    validate_preview_document(&p.document)?;
    Ok(p)
}

pub(super) async fn fetch_preview(
    client:&reqwest::Client, identity:&PolicyIdentity, key:&[u8]
) -> Result<SignedPolicy> {
    // Only GET, with a separate endpoint. No ACK and no writes to Supabase.
    let mut res=client.get(PREVIEW_ENDPOINT)
        .header("x-hlaxs-policy-id",identity.id.as_str())
        .header("x-hlaxs-policy-secret",identity.secret.as_str())
        .header("accept","application/json")
        .send().await?;
    ensure!(res.status().as_u16()==200,"preview_http_unavailable");
    if let Some(len)=res.content_length() {ensure!(len<=MAX_HTTP as u64,"preview_response_oversize");}
    let mut body=Vec::new();
    while let Some(chunk)=res.chunk().await? {
        ensure!(body.len()+chunk.len()<=MAX_HTTP,"preview_response_oversize");
        body.extend_from_slice(&chunk);
    }
    verify_preview(&body,key,Utc::now())
}

pub(super) fn physical_result(policy:&SignedPolicy,frame:&CaptureFrame) -> Value {
    let assessment=mapping_3b::assess(&policy.document,frame.reader_number,&frame.raw_bits,frame.overflow);
    let reason=sa08_untrusted(policy,frame.reader_number as u64,assessment.channel.unwrap_or(0));
    // A signed reference is proven to be included in the authenticated preview;
    // neither real-world cardholder nor reader authenticity is attested.
    let matched=assessment.credential_binding=="SIGNED_CREDENTIAL_REFERENCE_PRESENT"&&
        assessment.subject_binding=="SIGNED_SUBJECT_REFERENCE_PRESENT_UNATTESTED"&&
        assessment.access_rule=="MATCHING_24X7_RULE_UNTRUSTED_SOURCE";
    json!({
        "event":"hlaxs040_stage3e_physical_preview_evaluation",
        "mapping_schema":"hlaxs040_stage3e_signed_preview_v7",
        "policy_source":"v7_signed_bench_preview_memory_only",
        "config_version":policy.version,
        "config_checksum":policy.checksum,
        "reader_number_claimed":frame.reader_number,
        "door_channel_claimed":assessment.channel,
        "physical_capture_observed":true,
        "physical_reader_verified":false,
        "credential_reference_state":assessment.credential_binding,
        "subject_binding_state":assessment.subject_binding,
        "access_rule_state":assessment.access_rule,
        "signed_subject_and_rule_match":matched,
        "policy_candidate":assessment.class,
        "sa08_result":format!("{:?}",reason),
        "shadow_access_decision":"DENY_UNTRUSTED_EVIDENCE",
        "trusted_time_verified":false,
        "production_config_signature_verified":false,
        "device_acknowledged":false,
        "live_config_applied":false,
        "actuator_authority":false,
        "cloud_writes_enabled":false,
        "outputs_enabled":false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair,KeyPair};

    fn fixture(now:DateTime<Utc>)->Value {
        json!({
            "schema":"hlaxs-access-bench-policy-v1", "policy_origin":"cloud_issued_bench_signed_not_production",
            "controller_id":CONTROLLER,"organization_id":ORGANIZATION,"site_id":SITE,
            "config_version":7,"config_checksum":PREVIEW_CHECKSUM,
            "issued_at":now.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
            "expires_at":(now+ChronoDuration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
            "outputs_enabled":false,"cloud_commands_retrieved":false,"cloud_events_uploaded":false,
            "production_signature_verified":false,"physical_reader_verified":false,
            "preview_only":true,"device_acknowledged":false,"config_application_state":"staged_not_applied",
            "subject_binding_origin":"scoped_active_cardholder_credentials",
            "readers":(1..=4).map(|n|json!({"number":n,"door_channel":n-1,
                "reader_id":format!("00000000-0000-0000-0000-{:012}",n),
                "door_id":format!("11111111-1111-1111-1111-{:012}",n)})).collect::<Vec<_>>(),
            "credentials":PREVIEW_CARDS.iter().map(|(id,fc,card)|json!({
                "id":id,"facility_code":fc,"card_code":card,"enabled":true,
                "subject_id":PREVIEW_SUBJECT,"valid_from":null,"valid_until":null
            })).collect::<Vec<_>>(),
            "access_levels":[{"id":PREVIEW_LEVEL,"enabled":true}],
            "credential_access_levels":PREVIEW_CARDS.iter().map(|(id,_,_)|json!({"credential_id":id,"access_level_id":PREVIEW_LEVEL})).collect::<Vec<_>>(),
            "access_level_doors":(0..4).map(|n|json!({"access_level_id":PREVIEW_LEVEL,
                "channel":n,"schedule_id":PREVIEW_SCHEDULE})).collect::<Vec<_>>(),
            "schedules":[{"id":PREVIEW_SCHEDULE,"timezone":"America/New_York",
                "definition":{"always":true}}]
        })
    }

    fn fake_frame(fc:u8,card:u16,reader:usize)->CaptureFrame {
        let data=((fc as u64)<<17)|((card as u64)<<1);
        let high=(data>>13)&0xfff;let low=(data>>1)&0xfff;
        let raw=data|(((high.count_ones()%2) as u64)<<25)|((1-(low.count_ones()%2) as u64));
        CaptureFrame{reader_number:reader,raw_bits:format!("{raw:026b}"),overflow:false}
    }

    fn signed_response(p:&Value, seed:[u8;32])->(Vec<u8>,Vec<u8>) {
        let kp=Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let serialized=p.to_string();let sig=kp.sign(serialized.as_bytes());
        const B64:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out=String::new();
        for t in sig.as_ref().chunks(3) {
            let a=t[0];let b=*t.get(1).unwrap_or(&0);let c=*t.get(2).unwrap_or(&0);
            out.push(B64[(a>>2) as usize] as char);
            out.push(B64[(((a&3)<<4)|(b>>4)) as usize] as char);
            out.push(if t.len()>1{B64[(((b&15)<<2)|(c>>6)) as usize] as char}else{'='});
            out.push(if t.len()>2{B64[(c&63) as usize] as char}else{'='});
        }
        let response=json!({"success":true,"read_only":true,"preview_only":true,
            "device_acknowledged":false,"commands_returned":false,"outputs_enabled":false,
            "capability":"signed_shadow_policy_read_only","config_version":7,
            "envelope":{"signature_alg":"Ed25519-HLAXS035-bench-cloud",
            "payload_json":serialized,"signature_b64":out}});
        (serde_json::to_vec(&response).unwrap(),kp.public_key().as_ref().to_vec())
    }

    #[test] fn valid_preview_and_physical_frame_classify_deny_only() {
        let now=Utc::now();let (body,key)=signed_response(&fixture(now),[12;32]);
        let policy=verify_preview(&body,&key,now).unwrap();
        let result=physical_result(&policy,&fake_frame(5,22271,2));
        assert_eq!(result["signed_subject_and_rule_match"],true);
        assert_eq!(result["door_channel_claimed"],1);
        assert_eq!(result["physical_reader_verified"],false);
        assert_eq!(result["actuator_authority"],false);
        assert_eq!(result["shadow_access_decision"],"DENY_UNTRUSTED_EVIDENCE");
        assert_eq!(result["sa08_result"],"Deny(UntrustedClock)");
    }
    #[test] fn unsigned_or_tampered_payload_is_denied() {
        let now=Utc::now();let (mut body,key)=signed_response(&fixture(now),[14;32]);
        let mut outer:Value=serde_json::from_slice(&body).unwrap();
        outer["envelope"]["payload_json"]=json!("{}");
        body=serde_json::to_vec(&outer).unwrap();
        assert!(verify_preview(&body,&key,now).is_err());
    }
    #[test] fn status_and_signature_correct_but_wrong_subject_is_denied() {
        let now=Utc::now();let mut p=fixture(now);
        p["credentials"][0]["subject_id"]=json!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let (body,key)=signed_response(&p,[15;32]);
        assert!(verify_preview(&body,&key,now).is_err());
    }
    #[test] fn preview_rejects_wrong_door_rule_even_if_signed() {
        let now=Utc::now();let mut p=fixture(now);
        p["access_level_doors"][0]["channel"]=json!(3);
        let (body,key)=signed_response(&p,[16;32]);
        assert!(verify_preview(&body,&key,now).is_err());
    }
    #[test] fn incorrect_version_and_preview_flags_are_denied() {
        let now=Utc::now();let mut p=fixture(now);p["config_version"]=json!(6);
        let (body,key)=signed_response(&p,[17;32]);
        assert!(verify_preview(&body,&key,now).is_err());
        let p=fixture(now);let (mut body,key)=signed_response(&p,[18;32]);
        let mut outer:Value=serde_json::from_slice(&body).unwrap();
        outer["preview_only"]=json!(false);
        body=serde_json::to_vec(&outer).unwrap();
        assert!(verify_preview(&body,&key,now).is_err());
    }
    #[test] fn expired_preview_cannot_classify() {
        let now=Utc::now();let (body,key)=signed_response(&fixture(now),[19;32]);
        assert!(verify_preview(&body,&key,now+ChronoDuration::minutes(12)).is_err());
    }
    #[test] fn unknown_or_invalid_reader_frames_never_match() {
        let now=Utc::now();let (body,key)=signed_response(&fixture(now),[20;32]);
        let p=verify_preview(&body,&key,now).unwrap();
        for f in [fake_frame(5,22272,2),fake_frame(5,22271,5)] {
            let r=physical_result(&p,&f);
            assert_eq!(r["signed_subject_and_rule_match"],false);
            assert_eq!(r["actuator_authority"],false);
        }
    }
}
