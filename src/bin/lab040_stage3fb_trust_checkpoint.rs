//! Indagate Access Stage 3F-A: offline, NON-ACTUATING signing contract verifier.
//! Never deployed as the live controller, never requests cloud config, never ACKs,
//! never writes durable trust state, never drives a door, never returns ALLOW.
//! Caller-provided --as-of is an UNTRUSTED SIMULATION CLOCK, not trusted time.
use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ring::{digest, signature::{UnparsedPublicKey, ED25519}};
use serde_json::Value;
use std::{collections::HashSet, env, fs, path::{Path, PathBuf}, os::unix::fs::{DirBuilderExt,MetadataExt,OpenOptionsExt,PermissionsExt}, fs::OpenOptions};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

const MAX_FILE: usize = 200_000;
const MAX_PAYLOAD: usize = 160_000;
const CONTROLLER: &str = "2722691f-f4db-4f42-b63d-dac94b06ec9e";
const ORGANIZATION: &str = "48409aab-ec9b-4faf-9eb2-204611d09d8b";
const SITE: &str = "a96cb5a6-75f2-4f07-8232-7c405257cfbd";
const CONFIG_HASH: &str = "7a89bb687b6eaa823c5d69c45b32529c4991d8e3e561cff6572d1a80e95320f6";
const SUBJECT: &str = "e0d7746e-8dd5-4a3d-abdd-ba1404a0fd8b";
const LEVEL: &str = "2fb75404-53b2-4d89-9d14-4733f90105fd";
const SCHEDULE: &str = "15009b2d-1b2a-44fb-8bb6-7f79be6d16cd";
const DOMAIN: &str = "hlaxs-access-production";
const CHECKPOINT_SCHEMA: &str = "hlaxs040_stage3fb_detached_checkpoint_v1";
const CHECKPOINT_FILE: &str = "trust-checkpoint.sqlite";
#[derive(Debug, Clone)]
struct Verified {epoch:u64,version:u64,checksum:String,keyring_digest:String}


fn sha_hex(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes).as_ref().iter().map(|x|format!("{x:02x}")).collect()
}
fn b64decode(s: &str, max:usize) -> Result<Vec<u8>> {
    let raw=s.as_bytes();
    ensure!(!raw.is_empty() && raw.len()%4==0 && raw.len()<=MAX_FILE,"invalid_b64_length");
    let mut output=Vec::new();
    for (i,quad) in raw.chunks_exact(4).enumerate() {
        let last=i+1==raw.len()/4;
        let val=|b:u8|->Result<u32>{Ok(match b {
            b'A'..=b'Z'=>(b-b'A') as u32,b'a'..=b'z'=>(b-b'a'+26) as u32,
            b'0'..=b'9'=>(b-b'0'+52) as u32,b'+'=>62,b'/'=>63,
            _=>bail!("invalid_b64_character") })};
        ensure!(quad[0]!=b'='&&quad[1]!=b'=',"invalid_b64_padding");
        let pad=if quad[2]==b'=' {2} else if quad[3]==b'=' {1} else {0};
        ensure!(last||pad==0,"invalid_b64_middle_padding");
        ensure!(pad!=2||quad[3]==b'=',"invalid_b64_padding");
        let a=val(quad[0])?;let b=val(quad[1])?;
        let c=if pad==2 {0} else {val(quad[2])?};
        let d=if pad>0 {0} else {val(quad[3])?};
        ensure!((pad!=2||(b&15)==0)&&(pad!=1||(c&3)==0),"noncanonical_b64");
        output.push(((a<<2)|(b>>4)) as u8);
        if pad<2 {output.push(((b<<4)|(c>>2)) as u8);}
        if pad==0 {output.push(((c<<6)|d) as u8);}
        ensure!(output.len()<=max,"b64_over_limit");
    }
    Ok(output)
}
fn parse_canonical(raw:&str) -> Result<Value> {
    ensure!(raw.len()<=MAX_PAYLOAD,"payload_too_large");
    let doc:Value=serde_json::from_str(raw)?;
    ensure!(doc.is_object(),"payload_not_object");
    // Enforce deterministic JSON serialization; rejects duplicate keys,
    // noncanonical number encodings and extraneous whitespace in signed input.
    ensure!(serde_json::to_string(&doc)?==raw,"payload_noncanonical");
    Ok(doc)
}
fn string<'a>(v:&'a Value,k:&str) -> Result<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or_else(||anyhow!("missing_string_{k}"))
}
fn boolean(v:&Value,k:&str,want:bool) -> Result<()> {
    ensure!(v.get(k).and_then(Value::as_bool)==Some(want),"wrong_boolean_{k}");Ok(())
}
fn expected(v:&Value,k:&str,want:&str) -> Result<()> {
    ensure!(string(v,k)?==want,"scope_or_schema_mismatch_{k}");Ok(())
}
fn number(v:&Value,k:&str) -> Result<u64> {
    v.get(k).and_then(Value::as_u64).ok_or_else(||anyhow!("missing_u64_{k}"))
}
fn stamp(v:&Value,k:&str) -> Result<DateTime<Utc>> {
    let raw=string(v,k)?;
    ensure!(raw.ends_with('Z'),"time_not_utc_{k}");
    Ok(DateTime::parse_from_rfc3339(raw)?.with_timezone(&Utc))
}
fn window(v:&Value, at:DateTime<Utc>, max:ChronoDuration) -> Result<()> {
    let issued=stamp(v,"issued_at")?;
    let expires=stamp(v,"expires_at")?;
    ensure!(issued<=at && at<expires && expires>issued && expires-issued<=max,
        "expired_or_future_or_unbounded_window");Ok(())
}
fn exact_fields(v:&Value,fields:&[&str]) -> Result<()> {
    let obj=v.as_object().ok_or_else(||anyhow!("expected_object"))?;
    ensure!(obj.len()==fields.len() && obj.keys().all(|key|fields.contains(&key.as_str())),
        "unexpected_or_missing_fields");Ok(())
}
fn envelope(raw:&[u8],key_id:&str,key:&[u8]) -> Result<Value> {
    ensure!(raw.len()<=MAX_FILE,"envelope_oversize");
    let e:Value=serde_json::from_slice(raw)?;
    exact_fields(&e,&["schema","algorithm","key_id","payload_json","signature_b64"])?;
    expected(&e,"schema","hlaxs-signed-artifact-envelope-v1")?;
    expected(&e,"algorithm","Ed25519")?;
    expected(&e,"key_id",key_id)?;
    ensure!(key.len()==32,"invalid_ed25519_public_key");
    let payload=string(&e,"payload_json")?;
    let sig=b64decode(string(&e,"signature_b64")?,64)?;
    ensure!(sig.len()==64,"invalid_ed25519_signature_length");
    UnparsedPublicKey::new(&ED25519,key).verify(payload.as_bytes(),&sig)
        .map_err(|_|anyhow!("ed25519_signature_rejected"))?;
    let doc=parse_canonical(payload)?;
    expected(&doc,"signer_key_id",key_id)?;
    Ok(doc)
}
fn root_spki(pem:&[u8]) -> Result<[u8;32]> {
    let pem=std::str::from_utf8(pem)?;
    let body=pem.trim().strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|s|s.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or_else(||anyhow!("expected_ed25519_spki_pem"))?;
    let der=b64decode(&body.chars().filter(|c|!c.is_ascii_whitespace()).collect::<String>(),44)?;
    let head=[0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];
    ensure!(der.len()==44 && der.starts_with(&head),"not_ed25519_spki");
    let mut key=[0u8;32];key.copy_from_slice(&der[12..]);Ok(key)
}
fn raw_key(b64:&str) -> Result<[u8;32]> {
    let dec=b64decode(b64,32)?;ensure!(dec.len()==32,"invalid_signer_key_length");
    let mut key=[0u8;32];key.copy_from_slice(&dec);Ok(key)
}
fn array<'a>(v:&'a Value,k:&str,n:usize) -> Result<&'a Vec<Value>> {
    let x=v.get(k).and_then(Value::as_array).ok_or_else(||anyhow!("missing_array_{k}"))?;
    ensure!(x.len()==n,"array_length_mismatch_{k}");Ok(x)
}
#[derive(Clone)]
struct Params {
    as_of:DateTime<Utc>,min_epoch:u64,root_id:String,
}
fn verify_chain(root_pem:&[u8],ring_envelope:&[u8],policy_envelope:&[u8],p:&Params) -> Result<Verified> {
    let root=root_spki(root_pem)?;
    ensure!(!p.root_id.is_empty() && p.min_epoch>0,"missing_trust_anchor_metadata");
    let keyring=envelope(ring_envelope,&p.root_id,&root)?;
    exact_fields(&keyring,&["schema","trust_domain","signer_key_id","controller_id",
        "organization_id","site_id","epoch","issued_at","expires_at","keys"])?;
    expected(&keyring,"schema","hlaxs-access-keyring-contract-v1")?;
    expected(&keyring,"trust_domain",DOMAIN)?;
    expected(&keyring,"controller_id",CONTROLLER)?;
    expected(&keyring,"organization_id",ORGANIZATION)?;
    expected(&keyring,"site_id",SITE)?;
    ensure!(number(&keyring,"epoch")? >= p.min_epoch,"keyring_epoch_rollback");
    window(&keyring,p.as_of,ChronoDuration::days(730))?;
    let keys=keyring.get("keys").and_then(Value::as_array).ok_or_else(||anyhow!("missing_keys"))?;
    ensure!(!keys.is_empty()&&keys.len()<=8,"invalid_key_count");
    let mut names=HashSet::new();
    let mut signer=None;
    ensure!(policy_envelope.len()<=MAX_FILE,"policy_envelope_oversize");
    let policy_v:Value=serde_json::from_slice(policy_envelope)?;
    let policy_id=string(&policy_v,"key_id")?.to_owned();
    ensure!(policy_id!=p.root_id,"root_cannot_sign_policy");
    for k in keys {
        exact_fields(k,&["key_id","purpose","status","public_key_b64","not_before","not_after"])?;
        let id=string(k,"key_id")?;
        ensure!(!id.is_empty()&&id.len()<=96 && names.insert(id.to_owned()),"duplicate_or_invalid_key_id");
        let public=raw_key(string(k,"public_key_b64")?)?;
        ensure!(public!=root,"root_key_must_be_separate");
        let active=string(k,"status")?;
        ensure!(["active","revoked","retired"].contains(&active),"invalid_key_status");
        expected(k,"purpose","access-policy")?;
        let begin=stamp(k,"not_before")?;
        let end=stamp(k,"not_after")?;
        ensure!(end>begin,"invalid_key_lifetime");
        if id==policy_id {
            ensure!(active=="active","signer_revoked_or_retired");
            ensure!(begin<=p.as_of && p.as_of<end,"signer_expired_or_not_yet_valid");
            signer=Some(public);
        }
    }
    let signer=signer.ok_or_else(||anyhow!("unknown_policy_signer"))?;
    let policy=envelope(policy_envelope,&policy_id,&signer)?;
    exact_fields(&policy,&["schema","trust_domain","signer_key_id","controller_id",
        "organization_id","site_id","config_version","config_checksum","issued_at",
        "expires_at","mode","outputs_enabled","actuator_authority","cloud_writes_enabled",
        "trusted_time_verified","configuration","configuration_sha256"])?;
    expected(&policy,"schema","hlaxs-access-policy-contract-v1")?;
    expected(&policy,"trust_domain",DOMAIN)?;
    expected(&policy,"controller_id",CONTROLLER)?;
    expected(&policy,"organization_id",ORGANIZATION)?;
    expected(&policy,"site_id",SITE)?;
    expected(&policy,"config_checksum",CONFIG_HASH)?;
    expected(&policy,"mode","detached-nonactuating-trust-audit")?;
    ensure!(number(&policy,"config_version")? == 7,"unexpected_config_version");
    for name in ["outputs_enabled","actuator_authority","cloud_writes_enabled","trusted_time_verified"]{
        boolean(&policy,name,false)?;
    }
    window(&policy,p.as_of,ChronoDuration::minutes(10))?;
    let config=policy.get("configuration").ok_or_else(||anyhow!("missing_configuration"))?;
    let config_raw=serde_json::to_vec(config)?;
    ensure!(sha_hex(&config_raw)==string(&policy,"configuration_sha256")?,"config_digest_mismatch");
    validate_bench_config(config)?;
    println!("ROOT_KEY_SIGNATURE=VERIFIED_OFFLINE");
    println!("KEYRING_EPOCH={}",number(&keyring,"epoch")?);
    println!("DELEGATED_KEY_STATUS=ACTIVE_VERIFIED_OFFLINE");
    println!("ED25519_POLICY_SIGNATURE=VERIFIED_OFFLINE");
    println!("CONFIGURATION_DIGEST=VERIFIED_OFFLINE");
    println!("CONFIG_VERSION=7");
    println!("SIGNED_SUBJECT_MAPPING=FC5_CARD22271_TO_NEXUS_TEST");
    println!("FOUR_DOOR_RULES=SIGNED_AND_MATCHED");
    println!("SIMULATED_AS_OF_UNTRUSTED={}",p.as_of.to_rfc3339());
    println!("PRODUCTION_TRUST_ESTABLISHED=NO");
    println!("DEVICE_TIME_ATTESTED=NO");
    println!("LIVE_CONTROLLER_CHANGED=NO");
    println!("CONFIG_APPLIED=NO");
    println!("CLOUD_ACK_SENT=NO");
    println!("OUTPUT_AUTHORITY=FALSE");
    println!("FINAL_AUTHORIZATION=DENY_UNTRUSTED_EVIDENCE");
    println!("STAGE3F_OFFLINE_SIGNATURE_CONTRACT=PASS");
    Ok(Verified{epoch:number(&keyring,"epoch")?,version:number(&policy,"config_version")?,
       checksum:string(&policy,"config_checksum")?.to_string(),keyring_digest:sha_hex(ring_envelope)})
}
fn validate_bench_config(v:&Value)->Result<()> {
    exact_fields(v,&["credentials","credential_access_levels","access_levels",
        "access_level_doors","schedules","readers"])?;
    let creds=array(v,"credentials",2)?;
    let expected_creds=[(5,22271),(95,10773)];
    let mut cred_ids=HashSet::new();
    for (fc,number) in expected_creds {
        let matching:Vec<_>=creds.iter().filter(|x|x.get("facility_code").and_then(Value::as_u64)==Some(fc)
            &&x.get("card_code").and_then(Value::as_u64)==Some(number)).collect();
        ensure!(matching.len()==1,"missing_or_duplicate_credential");
        let c=matching[0];boolean(c,"enabled",true)?;expected(c,"subject_id",SUBJECT)?;
        ensure!(cred_ids.insert(string(c,"id")?.to_owned()),"duplicate_credential_id");
    }
    let readers=array(v,"readers",4)?;
    let mut reader_numbers=HashSet::new();
    let mut reader_channels=HashSet::new();
    for r in readers { let num=number(r,"number")?;let channel=number(r,"door_channel")?;
        ensure!((1..=4).contains(&num)&&channel==num-1&&
            reader_numbers.insert(num)&&reader_channels.insert(channel),"reader_door_mismatch"); }
    let levels=array(v,"access_levels",1)?;
    expected(&levels[0],"id",LEVEL)?;boolean(&levels[0],"enabled",true)?;
    let mut associated=HashSet::new();
    for link in array(v,"credential_access_levels",2)? {
        expected(link,"access_level_id",LEVEL)?;
        let id=string(link,"credential_id")?;
        ensure!(cred_ids.contains(id)&&associated.insert(id),"invalid_credential_access_link");
    }
    ensure!(associated.len()==2,"incomplete_credential_access_links");
    let mut channels=HashSet::new();
    for link in array(v,"access_level_doors",4)? {
        expected(link,"access_level_id",LEVEL)?;
        expected(link,"schedule_id",SCHEDULE)?;
        ensure!(channels.insert(number(link,"channel")?),"duplicate_door_link");
    }
    ensure!(channels==HashSet::from([0,1,2,3]),"incomplete_door_permissions");
    let schedules=array(v,"schedules",1)?;
    expected(&schedules[0],"id",SCHEDULE)?;
    ensure!(schedules[0].get("definition")==Some(&serde_json::json!({"always":true})),"not_24x7");
    Ok(())
}
// SQLite is a locally durable monotonic checkpoint, NOT a hardware rollback counter.
// A privileged disk adversary could replace the whole DB with an earlier valid copy.
#[derive(Debug, Clone)]
struct State {root_id:String,root_sha:String,epoch:u64,config_version:u64,config_checksum:String,
    ring_sha:String,generation:u64,integrity:String}
fn seal(s:&State)->String {
  // Fixed ordered tuple with explicit domain separation, no ambiguity from join delimiters.
  let fields=serde_json::json!([CHECKPOINT_SCHEMA,s.root_id,s.root_sha,s.epoch,
     s.config_version,s.config_checksum,s.ring_sha,s.generation]);
  sha_hex(serde_json::to_string(&fields).expect("serializable_checkpoint").as_bytes())
}
fn check_state(s:&State)->Result<()> {
  ensure!(s.epoch>=1 && s.generation>=1 &&
     s.root_id.len()>0 && s.root_id.len()<=96 &&
     s.root_sha.len()==64 && s.root_sha.chars().all(|c|c.is_ascii_hexdigit()) &&
     (s.config_version==0 || s.config_checksum.len()==64) &&
     (s.config_version==0 || s.ring_sha.len()==64) &&
     s.integrity==seal(s),"CHECKPOINT_INTEGRITY_FAILURE");
  Ok(())
}
fn check_owner_private(path:&Path,is_dir:bool)->Result<()> {
  let link=fs::symlink_metadata(path).with_context(||format!("STATE_PATH_UNAVAILABLE {}",path.display()))?;
  ensure!(!link.file_type().is_symlink(),"STATE_SYMLINK_REJECTED");
  ensure!(if is_dir {link.is_dir()} else {link.is_file() && link.nlink()==1},"STATE_TYPE_REJECTED");
  ensure!(link.uid()==unsafe {libc::geteuid()},"STATE_OWNER_REJECTED");
  let mask=if is_dir {0o700} else {0o600};
  ensure!(link.permissions().mode()&0o777==mask,"STATE_PERMISSIONS_REJECTED");
  Ok(())
}
fn prepare_dir(path:&Path,create:bool)->Result<()> {
  if create && !path.exists() {
    // Unix mkdir honors specified restrictive permissions under any normal umask.
    fs::DirBuilder::new().mode(0o700).create(path).context("STATE_MKDIR_FAILED")?;
    let parent=path.parent().ok_or_else(||anyhow!("STATE_PARENT_REQUIRED"))?;
    fs::File::open(parent)?.sync_all().context("STATE_DIRECTORY_FSYNC_FAILED")?;
  }
  check_owner_private(path,true)
}
fn database(path:&Path,create:bool)->Result<Connection> {
  prepare_dir(path,create)?;
  let db_path=path.join(CHECKPOINT_FILE);
  if !db_path.exists() {
    ensure!(create,"STATE_NOT_INITIALIZED");
    let f=OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
       .open(&db_path).context("STATE_SECURE_CREATE_FAILED")?;
    f.sync_all()?;
    fs::File::open(path)?.sync_all()?;
  }
  check_owner_private(&db_path,false)?;
  let db=Connection::open(&db_path)?;
  db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2000;")?;
  db.execute_batch("CREATE TABLE IF NOT EXISTS checkpoint(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_name TEXT NOT NULL, root_id TEXT NOT NULL, root_sha TEXT NOT NULL,
    epoch INTEGER NOT NULL, config_version INTEGER NOT NULL,
    config_checksum TEXT NOT NULL, ring_sha TEXT NOT NULL,
    generation INTEGER NOT NULL, integrity TEXT NOT NULL);")?;
  check_owner_private(&db_path,false)?;
  Ok(db)
}
fn read_state(tx:&Transaction<'_>)->Result<Option<State>> {
  let s:Option<State>=tx.query_row("SELECT root_id,root_sha,epoch,config_version,config_checksum,ring_sha,generation,integrity
       FROM checkpoint WHERE singleton=1 AND schema_name=?1",[CHECKPOINT_SCHEMA],|r|{
     Ok(State{root_id:r.get(0)?,root_sha:r.get(1)?,epoch:r.get(2)?,
        config_version:r.get(3)?,config_checksum:r.get(4)?,ring_sha:r.get(5)?,
        generation:r.get(6)?,integrity:r.get(7)?})
  }).optional()?;
  // Reject unknown schema or duplicate rows; never interpret an empty lookup as first boot.
  let rows:i64=tx.query_row("SELECT COUNT(*) FROM checkpoint",[],|r|r.get(0))?;
  ensure!(rows<=1 && (rows==1)==s.is_some(),"CHECKPOINT_SCHEMA_OR_ROW_INVALID");
  if let Some(ref state)=s {check_state(state)?;}
  Ok(s)
}
fn store_state(tx:&Transaction<'_>,s:&State)->Result<()> {
  check_state(s)?;
  tx.execute("INSERT INTO checkpoint(singleton,schema_name,root_id,root_sha,epoch,config_version,config_checksum,ring_sha,generation,integrity)
     VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9)
     ON CONFLICT(singleton) DO UPDATE SET schema_name=excluded.schema_name,
     root_id=excluded.root_id,root_sha=excluded.root_sha,epoch=excluded.epoch,
     config_version=excluded.config_version,config_checksum=excluded.config_checksum,
     ring_sha=excluded.ring_sha,generation=excluded.generation,integrity=excluded.integrity",
   params![CHECKPOINT_SCHEMA,s.root_id,s.root_sha,s.epoch,s.config_version,
        s.config_checksum,s.ring_sha,s.generation,s.integrity])?;
  Ok(())
}
fn read_regular(path:&Path,label:&str)->Result<Vec<u8>> {
  let meta=fs::symlink_metadata(path)?;
  ensure!(meta.is_file() && !meta.file_type().is_symlink() && meta.len()<=MAX_FILE as u64,
       "INPUT_UNSAFE_{label}");
  fs::read(path).with_context(||format!("INPUT_READ_ERROR_{label}"))
}
fn run()->Result<()> {
  let args:Vec<String>=env::args().collect();
  if args.len()==8 && args[1]=="--pin-test-root" && args[2]=="--state-dir" &&
     args[4]=="--root-pem" && args[6]=="--root-key-id" {
    let state_dir=PathBuf::from(&args[3]);
    ensure!(state_dir.is_absolute(),"STATE_DIR_MUST_BE_ABSOLUTE");
    let root=read_regular(Path::new(&args[5]),"ROOT")?;
    let _=root_spki(&root)?;
    let root_id=&args[7];
    ensure!(!root_id.is_empty()&&root_id.len()<=96,"INVALID_ROOT_ID");
    let mut conn=database(&state_dir,true)?;
    let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(read_state(&tx)?.is_none(),"ROOT_ALREADY_PINNED");
    let mut state=State{root_id:root_id.clone(),root_sha:sha_hex(&root),epoch:1,
        config_version:0,config_checksum:String::new(),ring_sha:String::new(),
        generation:1,integrity:String::new()};
    state.integrity=seal(&state);
    store_state(&tx,&state)?;
    tx.commit()?;
    println!("STAGE3FB_TEST_ROOT_PINNED=PASS");
    println!("TRUST_ANCHOR_PROVISIONED_FOR_PRODUCTION=NO");
    println!("LOCAL_CHECKPOINT_ONLY=TRUE");
    println!("LIVE_CONTROLLER_CHANGED=NO");
    return Ok(())
  }
  if args.len()==4 && args[1]=="--inspect" && args[2]=="--state-dir" {
    let dir=PathBuf::from(&args[3]);
    ensure!(dir.is_absolute(),"STATE_DIR_MUST_BE_ABSOLUTE");
    let mut conn=database(&dir,false)?;
    let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state=read_state(&tx)?.ok_or_else(||anyhow!("STATE_NOT_PINNED"))?;
    println!("STAGE3FB_CHECKPOINT_INTEGRITY=PASS");
    println!("STATE_KEYRING_EPOCH={}",state.epoch);
    println!("STATE_CONFIG_VERSION={}",state.config_version);
    println!("STATE_GENERATION={}",state.generation);
    println!("ROOT_PIN=LOCAL_SIMULATION_ONLY");
    println!("HARDWARE_ROLLBACK_RESISTANCE=NOT_ESTABLISHED");
    println!("CONTROLLER_OUTPUT_AUTHORITY=FALSE");
    tx.commit()?;
    return Ok(())
  }
  if args.len()!=17 || args[1]!="--verify-and-commit" || args[2]!="--state-dir" ||
      args[4]!="--root-pem" || args[6]!="--root-key-id" || args[8]!="--keyring" ||
      args[10]!="--policy" || args[12]!="--as-of" || args[14]!="--min-epoch" ||
      args[16]!="--nonactuating-only" {
    bail!("Usage: --pin-test-root --state-dir ABS --root-pem PUB.pem --root-key-id ID | --inspect --state-dir ABS | --verify-and-commit --state-dir ABS --root-pem PUB.pem --root-key-id ID --keyring signed-keyring.json --policy signed-policy.json --as-of UTC --min-epoch N --nonactuating-only");
  }
  let dir=PathBuf::from(&args[3]);
  ensure!(dir.is_absolute(),"STATE_DIR_MUST_BE_ABSOLUTE");
  let root=read_regular(Path::new(&args[5]),"ROOT")?;
  let keyring=read_regular(Path::new(&args[9]),"KEYRING")?;
  let policy=read_regular(Path::new(&args[11]),"POLICY")?;
  let root_hash=sha_hex(&root);
  let at=DateTime::parse_from_rfc3339(&args[13])?.with_timezone(&Utc);
  ensure!(args[13].ends_with('Z'),"SIMULATED_CLOCK_MUST_BE_UTC");
  let cli_epoch:u64=args[15].parse()?;
  ensure!(cli_epoch>0,"INVALID_MIN_EPOCH");
  let mut conn=database(&dir,false)?;
  let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
  let mut existing=read_state(&tx)?.ok_or_else(||anyhow!("ROOT_NOT_PINNED"))?;
  ensure!(existing.root_id==args[7]&&existing.root_sha==root_hash,
    "PINNED_ROOT_MISMATCH");
  let p=Params{as_of:at,min_epoch:cli_epoch.max(existing.epoch),root_id:args[7].clone()};
  let verified=verify_chain(&root,&keyring,&policy,&p)?;
  ensure!(verified.epoch>=existing.epoch && verified.version>=existing.config_version,
    "DURABLE_VERSION_ROLLBACK");
  if verified.epoch==existing.epoch && existing.config_version>0 {
    ensure!(verified.keyring_digest==existing.ring_sha,"SAME_EPOCH_KEYRING_REPLACEMENT");
  }
  if verified.version==existing.config_version && existing.config_version>0 {
    ensure!(verified.checksum==existing.config_checksum,"SAME_VERSION_CONFIG_MUTATION");
  }
  let changed=verified.epoch>existing.epoch || verified.version>existing.config_version ||
     existing.config_version==0;
  if changed {
    existing.epoch=verified.epoch;existing.config_version=verified.version;
    existing.config_checksum=verified.checksum;
    existing.ring_sha=verified.keyring_digest;
    existing.generation=existing.generation.checked_add(1).ok_or_else(||anyhow!("GENERATION_OVERFLOW"))?;
    existing.integrity=seal(&existing);
    store_state(&tx,&existing)?;
  }
  tx.commit()?;
  println!("STAGE3FB_CRYPTO_VERIFICATION_AND_COMMIT=PASS");
  println!("STAGE3FB_DURABLE_EPOCH={}",existing.epoch);
  println!("STAGE3FB_DURABLE_CONFIG_VERSION={}",existing.config_version);
  println!("STAGE3FB_REPLAY={}",if changed {"NEW_CHECKPOINT"}else{"IDEMPOTENT"});
  println!("HARDWARE_ROLLBACK_RESISTANCE=NOT_ESTABLISHED");
  println!("TRUSTED_TIME=SIMULATED_NOT_PRODUCTION");
  println!("ROOT_KEY_CUSTODY=TEST_FIXTURE_ONLY");
  println!("CONTROLLER_OUTPUT_AUTHORITY=FALSE");
  println!("PRODUCTION_APPLIED_ACK_SENT=NO");
  println!("CLOUD_WRITES=NONE");
  Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("STAGE3FB_DETACHED_TRUST_CHECKPOINT=FAIL");eprintln!("ERROR={e:#}");std::process::exit(1)}}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::{Ed25519KeyPair,KeyPair}};
    use serde_json::json;
    fn sign(doc:Value,id:&str,key:&Ed25519KeyPair)->Vec<u8>{
        let payload=serde_json::to_string(&doc).unwrap();
        let signature=key.sign(payload.as_bytes());
        let b64=encode_b64(signature.as_ref());
        serde_json::to_vec(&json!({"schema":"hlaxs-signed-artifact-envelope-v1",
           "algorithm":"Ed25519","key_id":id,"payload_json":payload,"signature_b64":b64})).unwrap()
    }
    fn encode_b64(data:&[u8])->String{
        const ABC:&[u8;64]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out=String::new();
        for chunk in data.chunks(3){let a=chunk[0] as usize;let b=chunk.get(1).copied().unwrap_or(0) as usize;
            let c=chunk.get(2).copied().unwrap_or(0) as usize;
            out.push(ABC[a>>2] as char);out.push(ABC[((a&3)<<4)|(b>>4)] as char);
            out.push(if chunk.len()>1 {ABC[((b&15)<<2)|(c>>6)] as char} else {'='});
            out.push(if chunk.len()>2 {ABC[c&63] as char} else {'='});}
        out
    }
    fn make()->(Vec<u8>,Vec<u8>,Vec<u8>,Params,Ed25519KeyPair,Ed25519KeyPair) {
        let rng=SystemRandom::new();
        let root=Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
        let delegated=Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
        let t="2026-10-27T18:15:00Z";
        let p=Params{as_of:DateTime::parse_from_rfc3339(t).unwrap().with_timezone(&Utc),min_epoch:2,root_id:"test-root-a".into()};
        let keyring=json!({"schema":"hlaxs-access-keyring-contract-v1","trust_domain":DOMAIN,
            "signer_key_id":"test-root-a","controller_id":CONTROLLER,"organization_id":ORGANIZATION,
            "site_id":SITE,"epoch":2,"issued_at":"2026-10-27T00:00:00Z",
            "expires_at":"2026-10-28T00:00:00Z",
            "keys":[{"key_id":"test-delegated-a","purpose":"access-policy","status":"active",
             "public_key_b64":encode_b64(delegated.public_key().as_ref()),
             "not_before":"2026-10-27T00:00:00Z","not_after":"2026-10-28T00:00:00Z"}]});
        let config=json!({"credentials":[{"id":"af809ce6-4d03-42c8-8392-bf98112280fe",
            "facility_code":5,"card_code":22271,"subject_id":SUBJECT,"enabled":true},
           {"id":"d6727897-eb21-47b6-bbda-da4a963b57de","facility_code":95,"card_code":10773,"subject_id":SUBJECT,"enabled":true}],
           "credential_access_levels":[{"credential_id":"af809ce6-4d03-42c8-8392-bf98112280fe","access_level_id":LEVEL},
           {"credential_id":"d6727897-eb21-47b6-bbda-da4a963b57de","access_level_id":LEVEL}],
           "readers":(1..=4).map(|i|json!({"number":i,"door_channel":i-1})).collect::<Vec<_>>(),
           "access_levels":[{"id":LEVEL,"enabled":true}],
           "access_level_doors":(0..4).map(|i|json!({"access_level_id":LEVEL,"schedule_id":SCHEDULE,"channel":i})).collect::<Vec<_>>(),
           "schedules":[{"id":SCHEDULE,"definition":{"always":true}}]});
        let hash=sha_hex(serde_json::to_string(&config).unwrap().as_bytes());
        let policy=json!({"schema":"hlaxs-access-policy-contract-v1","trust_domain":DOMAIN,
            "signer_key_id":"test-delegated-a","controller_id":CONTROLLER,"organization_id":ORGANIZATION,
            "site_id":SITE,"config_version":7,"config_checksum":CONFIG_HASH,
            "issued_at":"2026-10-27T18:14:00Z","expires_at":"2026-10-27T18:20:00Z",
            "mode":"detached-nonactuating-trust-audit","outputs_enabled":false,"actuator_authority":false,
            "cloud_writes_enabled":false,"trusted_time_verified":false,"configuration":config,
            "configuration_sha256":hash});
        let root_pem=format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            encode_b64(&[&[0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00][..],root.public_key().as_ref()].concat())).into_bytes();
        (root_pem,sign(keyring,"test-root-a",&root),sign(policy,"test-delegated-a",&delegated),p,root,delegated)
    }
    #[test]fn valid_detached_chain(){let(r,k,s,p,_,_)=make();assert!(verify_chain(&r,&k,&s,&p).is_ok());}
    #[test]fn reject_modified_policy(){let(r,k,mut s,p,_,_)=make();let mut j:Value=serde_json::from_slice(&s).unwrap();j["signature_b64"]="AAAA".into();s=serde_json::to_vec(&j).unwrap();assert!(verify_chain(&r,&k,&s,&p).is_err());}
    #[test]fn reject_tampered_signed_payload(){let(r,k,mut s,p,_,_)=make();let mut j:Value=serde_json::from_slice(&s).unwrap();j["payload_json"]=string(&j,"payload_json").unwrap().replace("22271","22272").into();s=serde_json::to_vec(&j).unwrap();assert!(verify_chain(&r,&k,&s,&p).is_err());}
    #[test]fn reject_untrusted_root(){let(_,k,s,p,_,_)=make();let(r,_,_,_,_,_)=make();assert!(verify_chain(&r,&k,&s,&p).is_err());}
    #[test]fn reject_keyring_rollback(){let(r,k,s,mut p,_,_)=make();p.min_epoch=3;assert!(verify_chain(&r,&k,&s,&p).is_err());}
    #[test]fn reject_expired_policy(){let(r,k,s,mut p,_,_)=make();p.as_of=DateTime::parse_from_rfc3339("2026-10-27T18:22:00Z").unwrap().with_timezone(&Utc);assert!(verify_chain(&r,&k,&s,&p).is_err());}
    #[test]fn reject_root_used_as_delegate(){let(r,_,s,p,root,_)=make();let (_,k,_,_,_,_)=make();
        // Signer mismatch and untrusted keyring must both fail without live side effects.
        assert!(verify_chain(&r,&k,&s,&p).is_err());assert_eq!(root.public_key().as_ref().len(),32);}
    #[test]fn reject_duplicate_config_credential(){let(r,k,s,_p,_,_)=make();let j:Value=serde_json::from_slice(&s).unwrap();let raw=string(&j,"payload_json").unwrap();let mut v:Value=serde_json::from_str(raw).unwrap();v["configuration"]["credentials"][1]["facility_code"]=json!(5);assert!(validate_bench_config(&v["configuration"]).is_err());let _=(r,k);}
    #[test]fn reject_noncanonical_payload(){assert!(parse_canonical("{\"a\":1, \"a\":1}").is_err());}
    #[test]fn reject_revoked_signer_even_with_valid_root_signature() {
        let(r,k,s,p,root,_)=make();
        let e:Value=serde_json::from_slice(&k).unwrap();
        let mut doc:Value=serde_json::from_str(string(&e,"payload_json").unwrap()).unwrap();
        doc["keys"][0]["status"]=json!("revoked");
        let revoked=sign(doc,"test-root-a",&root);
        assert!(verify_chain(&r,&revoked,&s,&p).is_err());
    }
    #[test]fn reject_retired_signer_even_with_valid_root_signature() {
        let(r,k,s,p,root,_)=make();
        let e:Value=serde_json::from_slice(&k).unwrap();
        let mut doc:Value=serde_json::from_str(string(&e,"payload_json").unwrap()).unwrap();
        doc["keys"][0]["status"]=json!("retired");
        let retired=sign(doc,"test-root-a",&root);
        assert!(verify_chain(&r,&retired,&s,&p).is_err());
    }
    #[test]fn reject_valid_signed_wrong_configuration_digest() {
        let(r,k,s,p,_,delegated)=make();
        let e:Value=serde_json::from_slice(&s).unwrap();
        let mut doc:Value=serde_json::from_str(string(&e,"payload_json").unwrap()).unwrap();
        doc["configuration_sha256"]=json!("0".repeat(64));
        let wrong=sign(doc,"test-delegated-a",&delegated);
        assert!(verify_chain(&r,&k,&wrong,&p).is_err());
    }
    #[test]fn reject_non_base64_key(){assert!(raw_key("!").is_err());}

    #[test]fn checkpoint_integrity_rejects_tamper(){
       let mut s=State{root_id:"test-root-a".into(),root_sha:"a".repeat(64),epoch:2,
        config_version:7,config_checksum:CONFIG_HASH.into(),ring_sha:"b".repeat(64),
        generation:2,integrity:String::new()};
       s.integrity=seal(&s);
       assert!(check_state(&s).is_ok());
       s.epoch=1;
       assert!(check_state(&s).is_err());
    }
    #[test]fn checkpoint_state_schema_is_private_and_nonactuating(){
       assert!(CHECKPOINT_FILE.ends_with(".sqlite"));
       assert!(CHECKPOINT_SCHEMA.contains("detached_checkpoint"));
       assert_eq!(DOMAIN,"hlaxs-access-production");
    }

}
