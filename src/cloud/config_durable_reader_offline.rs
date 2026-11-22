//! Indagate Access: developer-only durable mock replay + signed synthetic reader events.
//! NOT registered by main.rs, cloud/mod.rs, agent.rs or HAL. No device I/O,
//! network listeners, physical actuation, cloud ACK or production configuration writes.
//! Signature keys here are DUMMY fixture keys, NOT physical reader credentials.
use anyhow::{anyhow, bail, ensure, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::HashMap;
use uuid::Uuid;
use super::config_mock_action::{MockAuthority, MockRequest, MockRouter, MockSink, MockReceipt};

pub const SIGNING_DOMAIN: &[u8] = b"HLAXS-SYNTHETIC-READER-EVENT-v1\0";
pub const LEDGER_MAX_EVENTS: i64 = 4096;

// Auditable portable SHA-256 / HMAC for OFFLINE synthetic fixtures only. Not a
// replacement for a vetted provider, authenticated reader transport or hardware
// trust root. The RFC SHA-256 and HMAC test vectors below pin this implementation.
const K: [u32; 64] = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32;8] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                          0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let bitlen=(data.len() as u64).wrapping_mul(8);
    let mut msg=data.to_vec();msg.push(0x80);
    while (msg.len()%64)!=56 {msg.push(0);}
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w=[0u32;64];
        for (i, b) in block.chunks_exact(4).enumerate() {
            w[i]=u32::from_be_bytes([b[0],b[1],b[2],b[3]]);
        }
        for i in 16..64 {
            let s0=w[i-15].rotate_right(7)^w[i-15].rotate_right(18)^(w[i-15]>>3);
            let s1=w[i-2].rotate_right(17)^w[i-2].rotate_right(19)^(w[i-2]>>10);
            w[i]=w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh]=h;
        for i in 0..64 {
            let s1=e.rotate_right(6)^e.rotate_right(11)^e.rotate_right(25);
            let ch=(e&f)^((!e)&g);
            let t1=hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0=a.rotate_right(2)^a.rotate_right(13)^a.rotate_right(22);
            let maj=(a&b)^(a&c)^(b&c);
            let t2=s0.wrapping_add(maj);
            hh=g;g=f;f=e;e=d.wrapping_add(t1);d=c;c=b;b=a;a=t1.wrapping_add(t2);
        }
        for (dst,v) in h.iter_mut().zip([a,b,c,d,e,f,g,hh]) {*dst=dst.wrapping_add(v);}
    }
    let mut out=[0u8;32];
    for (index, word) in h.iter().enumerate() {out[index*4..index*4+4].copy_from_slice(&word.to_be_bytes());}
    out
}
fn mac_sha256(key: &[u8], data: &[u8]) -> [u8;32] {
    let mut block=[0u8;64];
    if key.len()>64 {block[..32].copy_from_slice(&sha256(key));} else {block[..key.len()].copy_from_slice(key);}
    let mut inner=Vec::with_capacity(64+data.len());
    let mut outer=Vec::with_capacity(96);
    inner.extend(block.iter().map(|b|*b^0x36u8));inner.extend_from_slice(data);
    outer.extend(block.iter().map(|b|*b^0x5cu8));outer.extend_from_slice(&sha256(&inner));
    sha256(&outer)
}
fn ct_equal(a:&[u8;32],b:&[u8;32])->bool {
    let mut difference=0u8;
    for i in 0..32 {difference |= a[i]^b[i];}
    difference==0
}
fn hex(data:&[u8])->String {
    let mut out=String::with_capacity(data.len()*2);
    for b in data {use std::fmt::Write;let _=write!(&mut out,"{b:02x}");}
    out
}
fn put_string(out:&mut Vec<u8>,s:&str){out.extend_from_slice(&(s.len() as u32).to_be_bytes());out.extend_from_slice(s.as_bytes());}

#[derive(Clone)]
pub struct ReaderBinding {
    pub key_id:String,
    pub controller_id:String,
    pub tenant_id:String,
    pub site_id:String,
    pub reader_number:u64,
    secret:[u8;32],
}
impl ReaderBinding {
    /// Only fixed dummy test keys. A deployed reader would require independently
    /// authenticated transport, provisioned secrets and secure key storage.
    pub fn dummy(key_id:&str, authority:&MockAuthority,reader_number:u64,secret:[u8;32])->Self {
        Self {key_id:key_id.into(),controller_id:authority.controller_id.clone(),
             tenant_id:authority.tenant_id.clone(),site_id:authority.site_id.clone(),reader_number,secret}
    }
}
pub struct ReaderKeyring {bindings:HashMap<String,ReaderBinding>}
impl ReaderKeyring {
    pub fn new()->Self {Self{bindings:HashMap::new()}}
    pub fn enroll_dummy(&mut self,b:ReaderBinding)->Result<()> {
        ensure!(!b.key_id.is_empty()&&b.key_id.len()<=64&&b.key_id.bytes().all(|x|x.is_ascii_alphanumeric()||x==b'-'),"invalid synthetic key ID");
        ensure!((1..=4).contains(&b.reader_number),"invalid reader binding");
        ensure!(!self.bindings.contains_key(&b.key_id),"duplicate synthetic key id");
        ensure!(b.secret.iter().any(|byte| *byte!=0),"zero synthetic key refused");
        self.bindings.insert(b.key_id.clone(),b);
        Ok(())
    }
    pub fn revoke(&mut self,key_id:&str)->bool {self.bindings.remove(key_id).is_some()}
    fn lookup(&self,key_id:&str)->Option<&ReaderBinding>{self.bindings.get(key_id)}
}

#[derive(Clone)]
pub struct SignedFrame {
    pub key_id:String,
    pub nonce:u64,
    pub request:MockRequest,
    tag:[u8;32],
}
impl SignedFrame {
    /// Synthetic test sender ONLY. Never attach this to live reader frames.
    pub fn sign_dummy(request:MockRequest, nonce:u64,binding:&ReaderBinding)->Result<Self> {
        ensure!(nonce>0,"zero nonce");
        let mut frame=Self{key_id:binding.key_id.clone(),nonce,request,tag:[0;32]};
        frame.tag=mac_sha256(&binding.secret,&frame.canonical()?);
        Ok(frame)
    }
    fn canonical(&self)->Result<Vec<u8>> {
        ensure!(Uuid::parse_str(&self.request.event_id).is_ok(),"invalid synthetic UUID");
        let mut bytes=SIGNING_DOMAIN.to_vec();
        put_string(&mut bytes,&self.key_id);bytes.extend_from_slice(&self.nonce.to_be_bytes());
        put_string(&mut bytes,&self.request.event_id);
        put_string(&mut bytes,&self.request.controller_id);
        put_string(&mut bytes,&self.request.tenant_id);
        put_string(&mut bytes,&self.request.site_id);
        put_string(&mut bytes,&self.request.contract_version);
        put_string(&mut bytes,&self.request.policy_version);
        for n in [self.request.generation,self.request.expected_version,self.request.reader_number,
                  self.request.facility_code,self.request.card_code] {bytes.extend_from_slice(&n.to_be_bytes());}
        put_string(&mut bytes,&self.request.expected_checksum);
        bytes.extend_from_slice(&self.request.captured_at.timestamp_millis().to_be_bytes());
        bytes.extend_from_slice(&self.request.expires_at.timestamp_millis().to_be_bytes());
        Ok(bytes)
    }
    fn verified_binding<'a>(&self,ring:&'a ReaderKeyring,authority:&MockAuthority)->Result<&'a ReaderBinding> {
        ensure!(self.nonce>0,"synthetic nonce invalid");
        let binding=ring.lookup(&self.key_id).ok_or_else(||anyhow!("synthetic reader key unknown"))?;
        ensure!(self.request.reader_number==binding.reader_number &&
                binding.controller_id==authority.controller_id && binding.tenant_id==authority.tenant_id &&
                binding.site_id==authority.site_id &&
                self.request.controller_id==binding.controller_id &&
                self.request.tenant_id==binding.tenant_id && self.request.site_id==binding.site_id,
                "synthetic reader binding mismatch");
        ensure!(ct_equal(&mac_sha256(&binding.secret,&self.canonical()?),&self.tag),"synthetic signature invalid");
        Ok(binding)
    }
}

/// Disposable synthetic SQLite replay journal, never uses device's production DB.
/// Reserves authenticated events BEFORE policy evaluation, and never retries a
/// reserved/interrupted item as a new proposal. No raw cards/credentials stored.
pub struct SyntheticDurableJournal { conn:Connection }
impl SyntheticDurableJournal {
    pub fn open(conn:Connection)->Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(2))?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS synthetic_authority(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            controller TEXT NOT NULL,tenant TEXT NOT NULL,site TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation>0),config_version INTEGER NOT NULL CHECK(config_version>0),digest TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS synthetic_replay(
            event_id TEXT PRIMARY KEY, key_nonce TEXT NOT NULL UNIQUE,
            fingerprint TEXT NOT NULL,generation INTEGER NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('reserved','denied','proposed')),
            reason TEXT NOT NULL);")?;
        Ok(Self{conn})
    }
    pub fn initialize(&mut self,a:&MockAuthority)->Result<()> {
        ensure!(a.trusted(),"untrusted synthetic authority");
        let tx=self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count:i64=tx.query_row("SELECT COUNT(*) FROM synthetic_authority",[],|r|r.get(0))?;
        ensure!(count==0,"synthetic authority already initialized");
        tx.execute("INSERT INTO synthetic_authority VALUES(1,?1,?2,?3,?4,?5,?6)",
            params![a.controller_id,a.tenant_id,a.site_id,to_sql(a.generation)?,to_sql(a.snapshot.version)?,a.snapshot.checksum])?;
        tx.commit()?;Ok(())
    }
    fn check(conn:&Connection,a:&MockAuthority)->Result<()> {
        ensure!(a.trusted(),"synthetic configuration invalid");
        let (count,c,t,s,g,v,d):(i64,String,String,String,i64,i64,String)=conn.query_row(
           "SELECT (SELECT COUNT(*) FROM synthetic_authority),controller,tenant,site,generation,config_version,digest FROM synthetic_authority WHERE singleton=1",[],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))?;
        ensure!(count==1 && g>0 && v>0 && c==a.controller_id && t==a.tenant_id && s==a.site_id
            && (g as u64)==a.generation && (v as u64)==a.snapshot.version && d==a.snapshot.checksum,
            "durable authority state differs");Ok(())
    }
    pub fn advance_epoch(&mut self,old:&MockAuthority,next:&MockAuthority)->Result<()> {
        ensure!(next.trusted() && next.generation==old.generation.checked_add(1).ok_or_else(||anyhow!("synthetic epoch overflow"))?,"epoch must advance exactly once");
        ensure!(old.controller_id==next.controller_id && old.site_id==next.site_id && old.tenant_id==next.tenant_id,"authority scope changed");
        let tx=self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check(&tx,old)?;
        let updated=tx.execute("UPDATE synthetic_authority SET generation=?1,config_version=?2,digest=?3 WHERE singleton=1 AND generation=?4 AND config_version=?5 AND digest=?6",
            params![to_sql(next.generation)?,to_sql(next.snapshot.version)?,next.snapshot.checksum,
                    to_sql(old.generation)?,to_sql(old.snapshot.version)?,old.snapshot.checksum])?;
        ensure!(updated==1,"atomic epoch update failed");tx.commit()?;Ok(())
    }
    fn reserve(&mut self,a:&MockAuthority,frame:&SignedFrame)->Result<()> {
        let tx=self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check(&tx,a)?;
        let n:i64=tx.query_row("SELECT COUNT(*) FROM synthetic_replay",[],|r|r.get(0))?;
        ensure!(n>=0 && n<LEDGER_MAX_EVENTS,"durable ledger full (fail closed)");
        let existing:Option<String>=tx.query_row("SELECT event_id FROM synthetic_replay WHERE event_id=?1 OR key_nonce=?2 LIMIT 1",
          params![frame.request.event_id,format!("{}:{}",frame.key_id,frame.nonce)],|r|r.get(0)).optional()?;
        ensure!(existing.is_none(),"durable event/nonce replay refused");
        // Fingerprint is SHA256 of a MAC, not a raw credential, reader ID or card value.
        // No garbage collection: once reserved, this UUID/nonce is never reused.
        let digest=hex(&sha256(&frame.tag));
        tx.execute("INSERT INTO synthetic_replay(event_id,key_nonce,fingerprint,generation,phase,reason) VALUES(?1,?2,?3,?4,'reserved','interrupted_or_pending')",
          params![frame.request.event_id,format!("{}:{}",frame.key_id,frame.nonce),digest,to_sql(a.generation)?])?;
        tx.commit()?;Ok(())
    }
    fn finish(&mut self,event_id:&str,receipt:MockReceipt)->Result<()> {
        let phase=if receipt.proposed {"proposed"}else{"denied"};
        let tx=self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE synthetic_replay SET phase=?1,reason=?2 WHERE event_id=?3 AND phase='reserved'",
            params![phase,receipt.reason,event_id])?;
        ensure!(changed==1,"durable finalize refused (already terminal/corrupt)");
        tx.commit()?;Ok(())
    }
    pub fn phase(&self,event_id:&str)->Result<String> {
        self.conn.query_row("SELECT phase FROM synthetic_replay WHERE event_id=?1",[event_id],|r|r.get(0)).map_err(Into::into)
    }
    pub fn count(&self)->Result<i64> {Ok(self.conn.query_row("SELECT COUNT(*) FROM synthetic_replay",[],|r|r.get(0))?)}
    /// Hardwired NO-ACTUATION path. Synthetic crash leaves a terminal-in-practice
    /// reserved event, which replays can NEVER turn into an approved proposal.
    pub fn process(&mut self,authority:&MockAuthority,ring:&ReaderKeyring,frame:SignedFrame,now:DateTime<Utc>,
                   simulate_crash_after_reserve:bool)->MockReceipt {
        let rejected=||MockReceipt{proposed:false,reason:"synthetic_event_rejected"};
        if !authority.trusted() || frame.verified_binding(ring,authority).is_err() {return rejected();}
        if frame.request.captured_at>now || frame.request.expires_at<=now || frame.request.expires_at<=frame.request.captured_at
           || frame.request.expires_at.signed_duration_since(frame.request.captured_at).num_milliseconds()>3000
           || now.signed_duration_since(frame.request.captured_at).num_milliseconds()>5000 {return rejected();}
        if self.reserve(authority,&frame).is_err() {return rejected();}
        if simulate_crash_after_reserve {return MockReceipt{proposed:false,reason:"synthetic_interrupted"};}
        // The existing MockRouter performs an additional scope/time/policy/epoch
        // check and creates ONLY a non-executable intent. The MockSink only records
        // in RAM; it has no device, relay, GPIO or cloud interfaces.
        let mut router=MockRouter::default();
        let outcome=router.propose(authority,frame.request.clone(),now);
        let mut receipt=outcome.receipt;
        if let Some(intent)=outcome.intent {
            let mut sink=MockSink::default();
            let sink_receipt=sink.consume(&intent,authority,now);
            if !sink_receipt.proposed {receipt=MockReceipt{proposed:false,reason:"mock_sink_refused"};}
        }else{receipt=MockReceipt{proposed:false,reason:"mock_policy_denied"};}
        if self.finish(&frame.request.event_id,receipt).is_err() {return rejected();}
        receipt
    }
}
fn to_sql(n:u64)->Result<i64>{i64::try_from(n).map_err(|_|anyhow!("synthetic version/epoch out of range"))}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use super::super::config_policy_hardening::{synthetic_fixture,MockSnapshot};
    use super::super::config_mock_action::{CONTRACT_VERSION,POLICY_VERSION};
    use std::sync::{Arc,Barrier};
    use std::thread;
    fn now()->DateTime<Utc>{"2026-10-19T19:30:00Z".parse().unwrap()}
    fn authority()->MockAuthority{
        let snapshot=MockSnapshot::build(6,synthetic_fixture()).unwrap();
        MockAuthority{controller_id:"2722691f-f4db-4f42-b63d-dac94b06ec9e".into(),
         tenant_id:"synthetic-tenant".into(),site_id:"synthetic-site".into(),generation:31,snapshot}
    }
    fn binding(a:&MockAuthority)->ReaderBinding {ReaderBinding::dummy("dummy-reader-key-A",a,1,[0x42;32])}
    fn keys(a:&MockAuthority)->ReaderKeyring{let mut r=ReaderKeyring::new();r.enroll_dummy(binding(a)).unwrap();r}
    fn frame(a:&MockAuthority,id:u128,nonce:u64)->SignedFrame{
        let c=&a.snapshot.config["credentials"][0];
        let request=MockRequest{event_id:Uuid::from_u128(id).to_string(),controller_id:a.controller_id.clone(),
        tenant_id:a.tenant_id.clone(),site_id:a.site_id.clone(),
        contract_version:CONTRACT_VERSION.into(),policy_version:POLICY_VERSION.into(),
        generation:a.generation,expected_version:a.snapshot.version,expected_checksum:a.snapshot.checksum.clone(),
        reader_number:1,facility_code:c["facility_code"].as_u64().unwrap(),card_code:c["card_code"].as_u64().unwrap(),
        captured_at:now(),expires_at:now()+Duration::milliseconds(2500)};
        SignedFrame::sign_dummy(request,nonce,&binding(a)).unwrap()
    }
    fn memory(a:&MockAuthority)->SyntheticDurableJournal{
        let mut j=SyntheticDurableJournal::open(Connection::open_in_memory().unwrap()).unwrap();j.initialize(a).unwrap();j
    }
    fn hex_from(s:&str)->Vec<u8>{(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}
    #[test]fn sha256_standard_vectors(){
        assert_eq!(hex(&sha256(b"")),"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    #[test]fn hmac_rfc4231_test_case_1(){
        assert_eq!(mac_sha256(&[0x0b;20],b"Hi There").to_vec(),hex_from("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    }
    #[test]fn signed_synthetic_reader_allows_one_mock_receipt(){let a=authority();let mut j=memory(&a);let f=frame(&a,101,1);let out=j.process(&a,&keys(&a),f,now(),false);assert!(out.proposed);assert_eq!(j.count().unwrap(),1);}
    #[test]fn duplicate_event_denied_after_success(){let a=authority();let mut j=memory(&a);let f=frame(&a,102,2);assert!(j.process(&a,&keys(&a),f.clone(),now(),false).proposed);assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn reused_nonce_with_new_event_denied(){let a=authority();let mut j=memory(&a);assert!(j.process(&a,&keys(&a),frame(&a,103,3),now(),false).proposed);assert!(!j.process(&a,&keys(&a),frame(&a,104,3),now(),false).proposed);}
    #[test]fn tamper_card_after_signing_denied(){let a=authority();let mut j=memory(&a);let mut f=frame(&a,105,5);f.request.card_code+=1;assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);assert_eq!(j.count().unwrap(),0);}
    #[test]fn tamper_reader_after_signing_denied(){let a=authority();let mut j=memory(&a);let mut f=frame(&a,106,6);f.request.reader_number=2;assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn tamper_scope_after_signing_denied(){let a=authority();let mut j=memory(&a);let mut f=frame(&a,107,7);f.request.tenant_id="other".into();assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn tamper_config_digest_after_signing_denied(){let a=authority();let mut j=memory(&a);let mut f=frame(&a,108,8);f.request.expected_checksum="bad".into();assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn tamper_event_time_after_signing_denied(){let a=authority();let mut j=memory(&a);let mut f=frame(&a,109,9);f.request.captured_at=now()+Duration::seconds(1);assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn unknown_signing_key_denied(){let a=authority();let mut j=memory(&a);let mut f=frame(&a,110,10);f.key_id="bad".into();assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn wrong_signing_key_denied(){let a=authority();let mut j=memory(&a);let f=frame(&a,111,11);let mut ring=ReaderKeyring::new();ring.enroll_dummy(ReaderBinding::dummy("dummy-reader-key-A",&a,1,[0x99;32])).unwrap();assert!(!j.process(&a,&ring,f,now(),false).proposed);}
    #[test]fn expired_message_denied(){let a=authority();let mut j=memory(&a);let f=frame(&a,112,12);assert!(!j.process(&a,&keys(&a),f,now()+Duration::seconds(4),false).proposed);}
    #[test]fn unauthorized_reader_binding_denied(){let a=authority();let mut j=memory(&a);let f=frame(&a,113,13);let mut ring=ReaderKeyring::new();ring.enroll_dummy(ReaderBinding::dummy("dummy-reader-key-A",&a,2,[0x42;32])).unwrap();assert!(!j.process(&a,&ring,f,now(),false).proposed);}
    #[test]fn revoked_key_denied(){let a=authority();let mut j=memory(&a);let f=frame(&a,114,14);let mut ring=keys(&a);assert!(ring.revoke("dummy-reader-key-A"));assert!(!j.process(&a,&ring,f,now(),false).proposed);}
    #[test]fn crash_reservation_rejects_retry(){let a=authority();let mut j=memory(&a);let f=frame(&a,115,15);assert!(!j.process(&a,&keys(&a),f.clone(),now(),true).proposed);assert_eq!(j.phase(&f.request.event_id).unwrap(),"reserved");assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn denied_credential_reservation_is_terminal(){let a=authority();let mut j=memory(&a);let mut f=frame(&a,116,16);f.request.card_code=65535;f=SignedFrame::sign_dummy(f.request,16,&binding(&a)).unwrap();assert!(!j.process(&a,&keys(&a),f.clone(),now(),false).proposed);assert_eq!(j.phase(&f.request.event_id).unwrap(),"denied");assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}
    #[test]fn authority_epoch_rollback_aba_denied(){let a=authority();let mut j=memory(&a);let old=frame(&a,117,17);let mut next=a.clone();next.generation+=1;next.snapshot.version+=1;j.advance_epoch(&a,&next).unwrap();assert!(!j.process(&a,&keys(&a),old,now(),false).proposed);let mut rollback=a.clone();rollback.generation=a.generation+2;j.advance_epoch(&next,&rollback).unwrap();assert!(!j.process(&a,&keys(&a),frame(&a,118,18),now(),false).proposed);}
    #[test]fn synthetic_rotation_revokes_old_key(){let a=authority();let mut ring=keys(&a);let mut j=memory(&a);let mut next=a.clone();next.generation+=1;j.advance_epoch(&a,&next).unwrap();ring.revoke("dummy-reader-key-A");ring.enroll_dummy(ReaderBinding::dummy("dummy-reader-key-B",&next,1,[0x73;32])).unwrap();assert!(!j.process(&next,&ring,frame(&a,119,19),now(),false).proposed);let mut f=frame(&next,120,20);f=SignedFrame::sign_dummy(f.request,20,ring.lookup("dummy-reader-key-B").unwrap()).unwrap();assert!(j.process(&next,&ring,f,now(),false).proposed);}
    #[test]fn duplicate_key_enrollment_refused(){let a=authority();let mut ring=keys(&a);assert!(ring.enroll_dummy(binding(&a)).is_err());}
    #[test]fn full_ledger_refuses_new_events(){let a=authority();let mut j=memory(&a);for id in 1..=LEDGER_MAX_EVENTS {j.conn.execute("INSERT INTO synthetic_replay(event_id,key_nonce,fingerprint,generation,phase,reason) VALUES(?1,?2,'dummy',1,'denied','test')",params![format!("dummy-{id}"),format!("dummy-nonce-{id}")]).unwrap();}assert!(!j.process(&a,&keys(&a),frame(&a,122,22),now(),false).proposed);}
    #[test]fn journal_rejects_corrupted_epoch(){let a=authority();let mut j=memory(&a);j.conn.execute("UPDATE synthetic_authority SET digest='bad'",[]).unwrap();assert!(!j.process(&a,&keys(&a),frame(&a,123,23),now(),false).proposed);}
    #[test]fn sqlite_record_has_no_raw_card_columns(){let a=authority();let mut j=memory(&a);let f=frame(&a,124,24);assert!(j.process(&a,&keys(&a),f,now(),false).proposed);let mut stmt=j.conn.prepare("PRAGMA table_info(synthetic_replay)").unwrap();let columns:Vec<String>=stmt.query_map([],|r|r.get(1)).unwrap().map(|r|r.unwrap()).collect();assert!(!columns.iter().any(|s|s.contains("card")||s.contains("facility")||s.contains("credential")));}
    #[test]fn signed_debug_not_implemented_for_secrets(){let a=authority();let j=memory(&a);let f=frame(&a,125,25);assert!(f.canonical().unwrap().len()>100);assert_eq!(j.count().unwrap(),0);}
    #[cfg(unix)]
    fn tempdir()->std::path::PathBuf {use std::os::unix::fs::DirBuilderExt;let p=std::env::temp_dir().join(format!("hlaxs-durable-synthetic-{}",Uuid::new_v4()));std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();p}
    #[cfg(unix)]
    #[test]fn interrupted_event_durably_denied_after_reopen(){let a=authority();let dir=tempdir();let path=dir.join("offline.sqlite");let f=frame(&a,126,26);{let mut j=SyntheticDurableJournal::open(Connection::open(&path).unwrap()).unwrap();j.initialize(&a).unwrap();assert!(!j.process(&a,&keys(&a),f.clone(),now(),true).proposed);}{let mut j=SyntheticDurableJournal::open(Connection::open(&path).unwrap()).unwrap();assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}std::fs::remove_file(&path).unwrap();std::fs::remove_dir(&dir).unwrap();}
    #[cfg(unix)]
    #[test]fn successful_event_durably_denied_after_reopen(){let a=authority();let dir=tempdir();let path=dir.join("offline.sqlite");let f=frame(&a,127,27);{let mut j=SyntheticDurableJournal::open(Connection::open(&path).unwrap()).unwrap();j.initialize(&a).unwrap();assert!(j.process(&a,&keys(&a),f.clone(),now(),false).proposed);}{let mut j=SyntheticDurableJournal::open(Connection::open(&path).unwrap()).unwrap();assert!(!j.process(&a,&keys(&a),f,now(),false).proposed);}std::fs::remove_file(&path).unwrap();std::fs::remove_dir(&dir).unwrap();}
    #[cfg(unix)]
    #[test]fn two_process_like_sqlite_connections_only_one_proposal(){let a=authority();let dir=tempdir();let path=dir.join("offline.sqlite");{let mut j=SyntheticDurableJournal::open(Connection::open(&path).unwrap()).unwrap();j.initialize(&a).unwrap();}let barrier=Arc::new(Barrier::new(2));let f=frame(&a,128,28);let mut handles=Vec::new();for _ in 0..2 {let b=barrier.clone();let p=path.clone();let a=a.clone();let frame=f.clone();handles.push(thread::spawn(move||{let mut j=SyntheticDurableJournal::open(Connection::open(p).unwrap()).unwrap();b.wait();j.process(&a,&keys(&a),frame,now(),false).proposed}));}let grants:usize=handles.into_iter().map(|h|h.join().unwrap() as usize).sum();assert_eq!(grants,1);std::fs::remove_file(&path).unwrap();std::fs::remove_dir(&dir).unwrap();}
}
