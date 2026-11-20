//! SA-08: detached deterministic policy evaluator. No I/O, hardware, cryptography, or raw credentials.
//! Caller MUST validate signed configuration, credential mapping, and trusted timezone conversion.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Scope { pub tenant: u64, pub site: u64, pub controller: u64, pub reader: u64, pub door: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigBinding { pub epoch: u64, pub version: u64, pub digest: [u8; 32] }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime { pub weekday: u8, pub minute: u16, pub utc_offset_minutes: i16 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedClock { pub unix_seconds: i64, pub local: LocalTime, pub verified: bool, pub timezone_verified: bool }
#[derive(Clone, Debug)]
pub struct Schedule { pub weekdays_mask: u8, pub start_minute: u16, pub end_minute: u16, pub timezone_offset_minutes: i16, pub holiday_dates: Vec<i64> }
#[derive(Clone, Debug)]
pub struct Grant { pub subject: [u8; 32], pub scope: Scope, pub valid_from: i64, pub valid_until: i64, pub schedule: Schedule, pub revoked: bool }
#[derive(Clone, Debug)]
pub struct Snapshot { pub binding: ConfigBinding, pub scope: Scope, pub grants: Vec<Grant>, pub verified: bool, pub valid_until: i64 }
#[derive(Clone, Copy, Debug)]
pub struct Request { pub subject: [u8; 32], pub scope: Scope, pub binding: ConfigBinding, pub clock: TrustedClock, pub credential_mapping_verified: bool }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason { Allowed, UntrustedClock, InvalidLocalTime, UnverifiedConfig, StaleConfig, BindingMismatch, ScopeMismatch, CredentialUnverified, NoGrant, Revoked, ExpiredGrant, OutsideSchedule, Holiday, AmbiguousGrant }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision { Allow, Deny(Reason) }

fn valid_schedule(s: &Schedule) -> bool {
    s.weekdays_mask != 0 && (s.weekdays_mask & !0x7f) == 0 && s.start_minute < 1440 && s.end_minute <= 1440 && s.start_minute < s.end_minute && (-840..=840).contains(&s.timezone_offset_minutes)
}
/// `day_number` is a verified local calendar-day ordinal from the trusted time adapter.
/// For safety, `day_number` is supplied separately; no timezone or calendar computations are attempted here.
pub fn evaluate(request: &Request, snapshot: &Snapshot, day_number: Option<i64>) -> Decision {
    let t = request.clock;
    if !t.verified || !t.timezone_verified || day_number.is_none() { return Decision::Deny(Reason::UntrustedClock); }
    if t.local.weekday > 6 || t.local.minute >= 1440 || !(-840..=840).contains(&t.local.utc_offset_minutes) {
        return Decision::Deny(Reason::InvalidLocalTime);
    }
    if !snapshot.verified || snapshot.binding.epoch == 0 || snapshot.binding.version == 0 || snapshot.binding.digest == [0;32] { return Decision::Deny(Reason::UnverifiedConfig); }
    if t.unix_seconds >= snapshot.valid_until { return Decision::Deny(Reason::StaleConfig); }
    if request.binding != snapshot.binding { return Decision::Deny(Reason::BindingMismatch); }
    if request.scope != snapshot.scope { return Decision::Deny(Reason::ScopeMismatch); }
    if !request.credential_mapping_verified || request.subject == [0;32] { return Decision::Deny(Reason::CredentialUnverified); }
    let matching: Vec<&Grant> = snapshot.grants.iter().filter(|g| g.subject == request.subject && g.scope == request.scope).collect();
    if matching.is_empty() { return Decision::Deny(Reason::NoGrant); }
    // Avoid grant-order dependencies or authorization bypass when duplicate grant rows conflict.
    if matching.len() != 1 { return Decision::Deny(Reason::AmbiguousGrant); }
    let grant = matching[0];
    if grant.revoked { return Decision::Deny(Reason::Revoked); }
    if grant.valid_from >= grant.valid_until || t.unix_seconds < grant.valid_from || t.unix_seconds >= grant.valid_until { return Decision::Deny(Reason::ExpiredGrant); }
    if !valid_schedule(&grant.schedule) || t.local.utc_offset_minutes != grant.schedule.timezone_offset_minutes { return Decision::Deny(Reason::OutsideSchedule); }
    if grant.schedule.holiday_dates.contains(&day_number.unwrap()) { return Decision::Deny(Reason::Holiday); }
    if (grant.schedule.weekdays_mask & (1 << t.local.weekday)) == 0 || t.local.minute < grant.schedule.start_minute || t.local.minute >= grant.schedule.end_minute { return Decision::Deny(Reason::OutsideSchedule); }
    Decision::Allow
}

#[cfg(test)]
mod tests {
 use super::*;
 const S: Scope = Scope {tenant:1,site:2,controller:3,reader:4,door:5};
 fn fixture() -> (Request, Snapshot) {
  let binding = ConfigBinding {epoch:2,version:3,digest:[7;32]};
  let req = Request {subject:[4;32],scope:S,binding,credential_mapping_verified:true,clock:TrustedClock {unix_seconds:1_000,local:LocalTime {weekday:1,minute:600,utc_offset_minutes:-300},verified:true,timezone_verified:true}};
  let snap = Snapshot {binding,scope:S,verified:true,valid_until:2_000,grants:vec![Grant {subject:[4;32],scope:S,valid_from:900,valid_until:1_100,revoked:false,schedule:Schedule {weekdays_mask:0b0111110,start_minute:540,end_minute:1020,timezone_offset_minutes:-300,holiday_dates:vec![]}}]};
  (req,snap)
 }
 fn deny(f: impl FnOnce(&mut Request,&mut Snapshot), expected: Reason) {let (mut r,mut s)=fixture();f(&mut r,&mut s);assert_eq!(evaluate(&r,&s,Some(200)),Decision::Deny(expected));}
 #[test] fn authorized_in_window() {let (r,s)=fixture();assert_eq!(evaluate(&r,&s,Some(200)),Decision::Allow)}
 #[test] fn unknown_subject() {deny(|r,_|r.subject=[8;32],Reason::NoGrant)}
 #[test] fn unverified_mapping() {deny(|r,_|r.credential_mapping_verified=false,Reason::CredentialUnverified)}
 #[test] fn zero_subject() {deny(|r,_|r.subject=[0;32],Reason::CredentialUnverified)}
 #[test] fn cross_tenant_denied() {deny(|r,_|r.scope.tenant=2,Reason::ScopeMismatch)}
 #[test] fn cross_reader_denied() {deny(|r,_|r.scope.reader=9,Reason::ScopeMismatch)}
 #[test] fn cross_door_denied() {deny(|r,_|r.scope.door=9,Reason::ScopeMismatch)}
 #[test] fn mismatched_digest() {deny(|r,_|r.binding.digest=[8;32],Reason::BindingMismatch)}
 #[test] fn mismatched_epoch() {deny(|r,_|r.binding.epoch=3,Reason::BindingMismatch)}
 #[test] fn unverified_config() {deny(|_,s|s.verified=false,Reason::UnverifiedConfig)}
 #[test] fn zero_digest_rejected() {deny(|r,s|{r.binding.digest=[0;32];s.binding.digest=[0;32]},Reason::UnverifiedConfig)}
 #[test] fn stale_config() {deny(|r,_|r.clock.unix_seconds=2_000,Reason::StaleConfig)}
 #[test] fn untrusted_clock() {deny(|r,_|r.clock.verified=false,Reason::UntrustedClock)}
 #[test] fn unverifiable_timezone() {deny(|r,_|r.clock.timezone_verified=false,Reason::UntrustedClock)}
 #[test] fn missing_day() {let (r,s)=fixture();assert_eq!(evaluate(&r,&s,None),Decision::Deny(Reason::UntrustedClock))}
 #[test] fn invalid_weekday() {deny(|r,_|r.clock.local.weekday=7,Reason::InvalidLocalTime)}
 #[test] fn revoked() {deny(|_,s|s.grants[0].revoked=true,Reason::Revoked)}
 #[test] fn expired_grant() {deny(|r,_|r.clock.unix_seconds=1_100,Reason::ExpiredGrant)}
 #[test] fn before_grant() {deny(|r,_|r.clock.unix_seconds=899,Reason::ExpiredGrant)}
 #[test] fn after_hours() {deny(|r,_|r.clock.local.minute=1020,Reason::OutsideSchedule)}
 #[test] fn before_hours() {deny(|r,_|r.clock.local.minute=539,Reason::OutsideSchedule)}
 #[test] fn weekend() {deny(|r,_|r.clock.local.weekday=0,Reason::OutsideSchedule)}
 #[test] fn holiday() {deny(|_,s|s.grants[0].schedule.holiday_dates.push(200),Reason::Holiday)}
 #[test] fn timezone_mismatch() {deny(|r,_|r.clock.local.utc_offset_minutes=-240,Reason::OutsideSchedule)}
 #[test] fn invalid_schedule() {deny(|_,s|s.grants[0].schedule.start_minute=1400,Reason::OutsideSchedule)}
 #[test] fn duplicate_conflicting_grants() {deny(|_,s|s.grants.push(s.grants[0].clone()),Reason::AmbiguousGrant)}
 #[test] fn no_matching_grant() {deny(|_,s|s.grants.clear(),Reason::NoGrant)}
 #[test] fn adjacent_scope_does_not_grant() {deny(|_,s|s.grants[0].scope.site=3,Reason::NoGrant)}
 #[test] fn invalid_interval() {deny(|_,s|s.grants[0].valid_from=s.grants[0].valid_until,Reason::ExpiredGrant)}
}
