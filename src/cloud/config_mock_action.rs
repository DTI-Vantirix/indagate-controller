//! Indagate Access pure MOCK-only decision-to-action proposals.
//! STANDALONE TEST CODE ONLY. Never register under cloud/mod.rs or main.rs.
//! There are NO GPIO/HAL/relay/OS-command/network/cloud interfaces here.
//! MockIntent is NOT a device command; MockSink only retains redacted memory.
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use super::{config_decision_offline, config_policy_hardening};

pub const CONTRACT_VERSION: &str = "hlaxs-mock-intent-v1";
pub const POLICY_VERSION: &str = "hlaxs-deny-only-2026-10-v1";
pub const MAX_REQUEST_TTL_MS: i64 = 3000;
pub const MAX_CLOCK_AGE_MS: i64 = 5000;
pub const MAX_SEEN_IDS: usize = 4096;

/// A mock-only authority and snapshot. Tenant/site fields are TEST ASSERTIONS,
/// not claims of authenticated real tenant/site registration.
#[derive(Clone)]
pub struct MockAuthority {
    pub controller_id: String,
    pub tenant_id: String,
    pub site_id: String,
    pub generation: u64, // monotonic synthetic epoch; changes after rollback/rebase
    pub snapshot: config_policy_hardening::MockSnapshot,
}

impl MockAuthority {
    pub fn trusted(&self) -> bool {
        self.generation > 0
            && Uuid::parse_str(&self.controller_id).is_ok()
            && !self.tenant_id.trim().is_empty() && !self.site_id.trim().is_empty()
            && self.snapshot.verify()
    }
}

/// No authenticated transport is modeled. An untrusted external sender could
/// spoof these fields: do not connect this to a real reader or cloud stream.
#[derive(Clone, PartialEq, Eq)]
pub struct MockRequest {
    pub event_id: String,
    pub controller_id: String,
    pub tenant_id: String,
    pub site_id: String,
    pub contract_version: String,
    pub policy_version: String,
    pub generation: u64,
    pub expected_version: u64,
    pub expected_checksum: String,
    pub reader_number: u64,
    pub facility_code: u64,  // never printed, logged or persisted by this module
    pub card_code: u64,      // never printed, logged or persisted by this module
    pub captured_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Private fields and no executor methods: cannot be interpreted as a HAL command.
#[derive(Clone)]
pub struct MockIntent {
    event_id: String,
    controller_id: String,
    tenant_id: String,
    site_id: String,
    expected_version: u64,
    expected_checksum: String,
    generation: u64,
    reader_number: u64,
    door_channel: u64,
    planned_unlock_ms: u64,
    expires_at: DateTime<Utc>,
}
impl std::fmt::Debug for MockIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockIntent").field("non_executable", &true)
            .field("configuration_version", &self.expected_version)
            .field("reader_number", &self.reader_number)
            .field("door_channel", &self.door_channel).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MockReceipt {
    pub proposed: bool,
    pub reason: &'static str, // fixed/redacted reasons; no card/holder or IDs
}
impl MockReceipt {
    fn deny(reason: &'static str) -> Self { Self { proposed: false, reason } }
    fn allow() -> Self { Self { proposed: true, reason: "mock_intent_proposed" } }
}

/// An authorization outcome never *executes* anything. Even a grant only returns
/// an opaque non-executable mock plan; a separate memory-only sink can inspect it.
pub struct ProposalOutcome {
    pub receipt: MockReceipt,
    pub intent: Option<MockIntent>,
}
impl ProposalOutcome {
    fn deny(reason: &'static str) -> Self { Self {receipt: MockReceipt::deny(reason),intent:None} }
}

/// Kept entirely in process memory; event IDs are bounded. No eviction: full
/// registry fails closed rather than permitting an old event to be replayed.
pub struct MockRouter {
    seen: HashMap<String, MockRequest>,
    pub receipts: Vec<MockReceipt>,
    limit: usize,
}
impl Default for MockRouter {
    fn default() -> Self { Self {seen:HashMap::new(),receipts:Vec::new(),limit:MAX_SEEN_IDS} }
}
impl MockRouter {
    pub fn with_limit(limit:usize)->Self { Self {limit, ..Self::default()} }
    pub fn seen_count(&self)->usize { self.seen.len() }
    fn record(&mut self,outcome:ProposalOutcome)->ProposalOutcome {
        // No request/card/credential/tenant/source identifiers are added to receipts.
        self.receipts.push(outcome.receipt);
        outcome
    }
    pub fn propose(&mut self, authority:&MockAuthority, request:MockRequest, now:DateTime<Utc>)->ProposalOutcome {
        if Uuid::parse_str(&request.event_id).is_err() {
            return self.record(ProposalOutcome::deny("event_id_invalid"));
        }
        if let Some(previous)=self.seen.get(&request.event_id) {
            return self.record(ProposalOutcome::deny(if previous==&request { "duplicate_event" } else { "conflicting_event_id" }));
        }
        if self.seen.len()>=self.limit { return self.record(ProposalOutcome::deny("replay_ledger_full")); }
        // Reserve event ID BEFORE attempting a simulated authorization. A local
        // failure cannot turn the same ID into a grant on retry.
        self.seen.insert(request.event_id.clone(), request.clone());

        if !authority.trusted() { return self.record(ProposalOutcome::deny("authority_invalid")); }
        if request.contract_version!=CONTRACT_VERSION || request.policy_version!=POLICY_VERSION {
            return self.record(ProposalOutcome::deny("contract_version_unsupported"));
        }
        if request.controller_id!=authority.controller_id || request.tenant_id!=authority.tenant_id
           || request.site_id!=authority.site_id {
            return self.record(ProposalOutcome::deny("scope_mismatch"));
        }
        if request.generation!=authority.generation
           || request.expected_version!=authority.snapshot.version
           || request.expected_checksum!=authority.snapshot.checksum {
            return self.record(ProposalOutcome::deny("configuration_binding_stale"));
        }
        if request.captured_at>now || request.expires_at<=now
           || request.expires_at<=request.captured_at
           || request.expires_at.signed_duration_since(request.captured_at)>Duration::milliseconds(MAX_REQUEST_TTL_MS)
           || now.signed_duration_since(request.captured_at)>Duration::milliseconds(MAX_CLOCK_AGE_MS) {
            return self.record(ProposalOutcome::deny("event_time_invalid"));
        }
        let probe=config_decision_offline::Probe {
            reader_number:request.reader_number, facility_code:request.facility_code,
            card_code:request.card_code, at_utc:now,
        };
        let decision=config_decision_offline::evaluate(&authority.snapshot.config,&probe);
        if !decision.allowed { return self.record(ProposalOutcome::deny(decision.reason)); }
        let Some(channel)=request.reader_number.checked_sub(1) else {
            return self.record(ProposalOutcome::deny("reader_invalid"));
        };
        // The only output-like data is a bounded *mock intent* duration taken
        // from the already-verified configuration. There is no actuation API.
        let Some(door)=authority.snapshot.config.get("doors").and_then(Value::as_array)
            .and_then(|d|d.iter().find(|d| d.get("channel").and_then(Value::as_u64)==Some(channel))) else {
            return self.record(ProposalOutcome::deny("door_missing"));
        };
        let Some(ms)=door.get("unlock_ms").and_then(Value::as_u64) else {
            return self.record(ProposalOutcome::deny("duration_invalid"));
        };
        if !(100..=600000).contains(&ms) { return self.record(ProposalOutcome::deny("duration_invalid")); }
        let intent=MockIntent {
            event_id:request.event_id,controller_id:authority.controller_id.clone(),
            tenant_id:authority.tenant_id.clone(),site_id:authority.site_id.clone(),
            generation:authority.generation,expected_version:authority.snapshot.version,
            expected_checksum:authority.snapshot.checksum.clone(),reader_number:request.reader_number,
            door_channel:channel,planned_unlock_ms:ms,expires_at:request.expires_at,
        };
        self.record(ProposalOutcome {receipt:MockReceipt::allow(),intent:Some(intent)})
    }
}

/// Strictly in-memory. This is NOT an actuator backend, cannot call the HAL,
/// and accepts only a bound opaque mock proposal, never a direct pulse command.
#[derive(Default)]
pub struct MockSink {
    consumed:HashSet<String>,
    pub recorded:Vec<MockReceipt>,
}
impl MockSink {
    pub fn count(&self)->usize {self.recorded.len()}
    pub fn consume(&mut self,intent:&MockIntent,authority:&MockAuthority,now:DateTime<Utc>)->MockReceipt {
        let result=if !self.consumed.insert(intent.event_id.clone()) { MockReceipt::deny("mock_proposal_duplicate") }
        else if !authority.trusted() { MockReceipt::deny("authority_invalid") }
        else if intent.expires_at<=now { MockReceipt::deny("mock_proposal_expired") }
        else if intent.controller_id!=authority.controller_id || intent.tenant_id!=authority.tenant_id
           || intent.site_id!=authority.site_id || intent.generation!=authority.generation
           || intent.expected_version!=authority.snapshot.version
           || intent.expected_checksum!=authority.snapshot.checksum {
            MockReceipt::deny("mock_proposal_stale")
        } else if !(1..=4).contains(&intent.reader_number)
           || intent.door_channel!=intent.reader_number-1 || !(100..=600000).contains(&intent.planned_unlock_ms)
           || !authority.snapshot.config.get("doors").and_then(Value::as_array).is_some_and(|doors| doors.iter().any(|door| {
               door.get("channel").and_then(Value::as_u64)==Some(intent.door_channel)
                   && door.get("enabled").and_then(Value::as_bool)==Some(true)
                   && door.get("unlock_ms").and_then(Value::as_u64)==Some(intent.planned_unlock_ms)
           })) {
            MockReceipt::deny("mock_proposal_invalid")
        } else {
            // A consumed proposal cannot be consumed twice even after an
            // authority changes. NO hardware command is emitted here.
            MockReceipt {proposed:true,reason:"mock_sink_recorded_only"}
        };
        self.recorded.push(result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc,Mutex};
    use std::thread;
    use rusqlite::{params, Connection, TransactionBehavior};

    fn at()->DateTime<Utc> { "2026-10-19T19:30:00Z".parse().unwrap() }
    fn authority()->MockAuthority {
        let config=config_policy_hardening::synthetic_fixture();
        let snap=config_policy_hardening::MockSnapshot::build(6,config).unwrap();
        MockAuthority { controller_id:"2722691f-f4db-4f42-b63d-dac94b06ec9e".into(),
            tenant_id:"test-tenant".into(),site_id:"test-site".into(),generation:11,snapshot:snap }
    }
    fn event(a:&MockAuthority,seq:u128)->MockRequest {
        MockRequest {event_id:Uuid::from_u128(seq).to_string(),
            controller_id:a.controller_id.clone(),tenant_id:a.tenant_id.clone(),site_id:a.site_id.clone(),
            contract_version:CONTRACT_VERSION.into(),policy_version:POLICY_VERSION.into(),
            generation:a.generation,expected_version:a.snapshot.version,expected_checksum:a.snapshot.checksum.clone(),
            reader_number:1,facility_code:41,card_code:1001,captured_at:at(),expires_at:at()+Duration::milliseconds(2500)}
    }
    fn propose(a:&MockAuthority,seq:u128)->ProposalOutcome {MockRouter::default().propose(a,event(a,seq),at())}
    #[test] fn grant_produces_one_non_executable_mock_intent() {
        let a=authority();let o=propose(&a,1);assert!(o.receipt.proposed);let intent=o.intent.unwrap();
        assert_eq!(intent.reader_number,1);assert_eq!(intent.door_channel,0);
        assert_eq!(intent.planned_unlock_ms,5000);
    }
    #[test] fn deny_never_returns_a_mock_intent() {
        let a=authority();let mut r=event(&a,2);r.card_code=9999;
        let o=MockRouter::default().propose(&a,r,at());assert!(!o.receipt.proposed);assert!(o.intent.is_none());
    }
    #[test] fn same_request_id_cannot_propose_twice(){
        let a=authority();let e=event(&a,3);let mut r=MockRouter::default();
        assert!(r.propose(&a,e.clone(),at()).receipt.proposed);
        let second=r.propose(&a,e,at());assert_eq!(second.receipt.reason,"duplicate_event");assert!(second.intent.is_none());
    }
    #[test] fn changed_payload_with_reused_id_denied(){
        let a=authority();let mut r=MockRouter::default();let e=event(&a,4);
        assert!(r.propose(&a,e.clone(),at()).receipt.proposed);
        let mut forged=e;forged.card_code=1002;
        assert_eq!(r.propose(&a,forged,at()).receipt.reason,"conflicting_event_id");
    }
    #[test] fn unsupported_contract_version_denied(){
        let a=authority();let mut e=event(&a,30);e.contract_version="unknown".into();
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"contract_version_unsupported");
    }
    #[test] fn unsupported_policy_version_denied(){
        let a=authority();let mut e=event(&a,31);e.policy_version="legacy".into();
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"contract_version_unsupported");
    }
    #[test] fn expired_request_is_denied(){
        let a=authority();let mut e=event(&a,5);e.expires_at=at();
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"event_time_invalid");
    }
    #[test] fn future_timestamp_is_denied(){
        let a=authority();let mut e=event(&a,6);e.captured_at=at()+Duration::seconds(1);
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"event_time_invalid");
    }
    #[test] fn oversized_ttl_is_denied(){
        let a=authority();let mut e=event(&a,7);e.expires_at=at()+Duration::milliseconds(MAX_REQUEST_TTL_MS+1);
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"event_time_invalid");
    }
    #[test] fn old_arrival_is_denied_even_with_future_expiry(){
        let a=authority();let mut e=event(&a,8);e.captured_at=at()-Duration::seconds(6);e.expires_at=at()+Duration::seconds(1);
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"event_time_invalid");
    }
    #[test] fn stale_version_is_denied(){
        let a=authority();let mut e=event(&a,9);e.expected_version=7;
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"configuration_binding_stale");
    }
    #[test] fn altered_digest_is_denied(){
        let a=authority();let mut e=event(&a,10);e.expected_checksum="bad".into();
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"configuration_binding_stale");
    }
    #[test] fn rollback_aba_requires_new_epoch(){
        let mut a=authority();let e=event(&a,11);a.generation+=1;
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"configuration_binding_stale");
    }
    #[test] fn controller_scope_mismatch_denied(){
        let a=authority();let mut e=event(&a,12);e.controller_id=Uuid::from_u128(999).to_string();
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"scope_mismatch");
    }
    #[test] fn tenant_scope_mismatch_denied(){
        let a=authority();let mut e=event(&a,13);e.tenant_id="other-tenant".into();
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"scope_mismatch");
    }
    #[test] fn site_scope_mismatch_denied(){
        let a=authority();let mut e=event(&a,14);e.site_id="other-site".into();
        assert_eq!(MockRouter::default().propose(&a,e,at()).receipt.reason,"scope_mismatch");
    }
    #[test] fn missing_reader_denied(){
        let a=authority();let mut e=event(&a,15);e.reader_number=99;
        assert!(!MockRouter::default().propose(&a,e,at()).receipt.proposed);
    }
    #[test] fn disabled_reader_denied(){
        let mut a=authority();a.snapshot.config["readers"][0]["enabled"]=json!(false);
        a.snapshot=config_policy_hardening::MockSnapshot::build(6,a.snapshot.config).unwrap();
        let e=event(&a,16);
        assert!(!MockRouter::default().propose(&a,e,at()).receipt.proposed);
    }
    #[test] fn invalid_wiegand_pair_denied(){
        let a=authority();let mut e=event(&a,17);e.card_code=65536;
        assert!(!MockRouter::default().propose(&a,e,at()).receipt.proposed);
    }
    #[test] fn malformed_event_id_denied_without_receipt_of_id(){
        let a=authority();let mut e=event(&a,18);e.event_id="secret-card-1234".into();
        let result=MockRouter::default().propose(&a,e,at());
        assert_eq!(result.receipt.reason,"event_id_invalid");assert!(!format!("{:?}",result.receipt).contains("1234"));
    }
    #[test] fn ledger_capacity_fails_closed(){
        let a=authority();let mut r=MockRouter::with_limit(1);
        assert!(r.propose(&a,event(&a,19),at()).receipt.proposed);
        assert_eq!(r.propose(&a,event(&a,20),at()).receipt.reason,"replay_ledger_full");
    }
    #[test] fn sink_records_once_in_memory(){
        let a=authority();let outcome=propose(&a,21);let intent=outcome.intent.unwrap();let mut sink=MockSink::default();
        assert!(sink.consume(&intent,&a,at()).proposed);
        assert_eq!(sink.consume(&intent,&a,at()).reason,"mock_proposal_duplicate");
        assert_eq!(sink.count(),2);
    }
    #[test] fn sink_rejects_expired_intent(){
        let a=authority();let intent=propose(&a,22).intent.unwrap();let mut sink=MockSink::default();
        assert_eq!(sink.consume(&intent,&a,at()+Duration::seconds(3)).reason,"mock_proposal_expired");
    }
    #[test] fn sink_rejection_is_terminal_even_if_clock_goes_backwards(){
        let a=authority();let intent=propose(&a,32).intent.unwrap();let mut sink=MockSink::default();
        assert_eq!(sink.consume(&intent,&a,at()+Duration::seconds(3)).reason,"mock_proposal_expired");
        assert_eq!(sink.consume(&intent,&a,at()).reason,"mock_proposal_duplicate");
    }
    #[test] fn sink_rejects_authority_epoch_changed(){
        let mut a=authority();let intent=propose(&a,23).intent.unwrap();a.generation+=1;
        assert_eq!(MockSink::default().consume(&intent,&a,at()).reason,"mock_proposal_stale");
    }
    #[test] fn sink_rejects_authority_checksum_changed(){
        let mut a=authority();let intent=propose(&a,24).intent.unwrap();
        a.snapshot.config["doors"][0]["unlock_ms"]=json!(7000);
        a.snapshot=config_policy_hardening::MockSnapshot::build(6,a.snapshot.config).unwrap();
        assert_eq!(MockSink::default().consume(&intent,&a,at()).reason,"mock_proposal_stale");
    }
    #[test] fn debug_does_not_expose_ids_or_card_values(){
        let a=authority();let intent=propose(&a,25).intent.unwrap();let repr=format!("{:?}",intent);
        assert!(!repr.contains("2722691f"));assert!(!repr.contains("test-tenant"));
        assert!(!repr.contains("1001"));assert!(!repr.contains(&intent.event_id));
    }
    #[test] fn concurrency_same_event_records_only_one_proposal(){
        let a=Arc::new(authority());let r=Arc::new(Mutex::new(MockRouter::default()));
        let mut jobs=Vec::new();for _ in 0..8 {
            let aa=a.clone();let rr=r.clone();jobs.push(thread::spawn(move ||{
                rr.lock().unwrap().propose(&aa,event(&aa,26),at()).receipt.proposed
            }));
        }
        let results:Vec<bool>=jobs.into_iter().map(|h|h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|&&b|b).count(),1);
        assert_eq!(r.lock().unwrap().seen_count(),1);
    }
    #[test] fn corruption_never_results_in_mock_grant(){
        let mut a=authority();a.snapshot.config["credentials"][0]["enabled"]=json!(false);
        let o=MockRouter::default().propose(&a,event(&a,27),at());
        assert_eq!(o.receipt.reason,"authority_invalid");assert!(o.intent.is_none());
    }
    #[test] fn explicitly_denied_access_level_never_proposes(){
        let mut a=authority();a.snapshot.config["access_levels"][0]["enabled"]=json!(false);
        a.snapshot=config_policy_hardening::MockSnapshot::build(6,a.snapshot.config).unwrap();
        let o=MockRouter::default().propose(&a,event(&a,28),at());assert!(!o.receipt.proposed);
    }
    #[test] fn mock_receipts_redacted_and_fixed(){
        let a=authority();let e=event(&a,29);let mut router=MockRouter::default();
        let _=router.propose(&a,e,at());let output=format!("{:?}",router.receipts);
        assert!(!output.contains("1001"));assert!(!output.contains("test-site"));
    }
    /// Separate-process durable *synthetic-only* replay ledger fixture.
    /// Holds NO real credential, config, card or holder values.
    fn reserve_dummy(conn:&mut Connection,event_id:&str,fingerprint:&str)->Result<&'static str,rusqlite::Error>{
        conn.execute_batch("PRAGMA synchronous=FULL;CREATE TABLE IF NOT EXISTS dummy_seen(event TEXT PRIMARY KEY,fingerprint TEXT NOT NULL)")?;
        let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:Result<String,_>=tx.query_row("SELECT fingerprint FROM dummy_seen WHERE event=?1",[event_id],|r|r.get(0));
        let code=match existing {
            Ok(v) if v==fingerprint => "duplicate",
            Ok(_) => "conflict",
            Err(rusqlite::Error::QueryReturnedNoRows)=> {
                tx.execute("INSERT INTO dummy_seen(event,fingerprint) VALUES(?1,?2)",params![event_id,fingerprint])?;
                "reserved"
            }
            Err(e)=>return Err(e),
        };
        tx.commit()?;Ok(code)
    }
    #[test] fn synthetic_durable_replay_survives_reopen(){
        let directory=std::env::temp_dir().join(format!("hlaxs-dummy-ledger-{}",Uuid::new_v4()));
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        }
        #[cfg(not(unix))] std::fs::create_dir(&directory).unwrap();
        let path=directory.join("dummy.sqlite");
        {
            let mut conn=Connection::open(&path).unwrap();
            assert_eq!(reserve_dummy(&mut conn,"dummy-id","synthetic-only-payload").unwrap(),"reserved");
        }
        {
            let mut conn=Connection::open(&path).unwrap();
            assert_eq!(reserve_dummy(&mut conn,"dummy-id","synthetic-only-payload").unwrap(),"duplicate");
            assert_eq!(reserve_dummy(&mut conn,"dummy-id","different-dummy").unwrap(),"conflict");
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
