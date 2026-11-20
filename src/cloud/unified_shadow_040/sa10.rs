//! SA-10: detached credential-to-subject resolver; no I/O, secrets, actuator, crypto or network.
//! Caller must independently authenticate snapshot provenance and bind reader identity;
//! a Wiegand frame is NOT cryptographic proof that the physical credential is genuine.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope { pub tenant:u64, pub site:u64, pub controller:u64, pub reader:u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding { pub epoch:u64, pub version:u64, pub digest:[u8;32] }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format { H10301_26 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded { pub facility:u8, pub card:u16 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation { pub scope:Scope, pub binding:Binding, pub raw_frame:u64, pub bit_len:u8, pub reader_identity_verified:bool }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
 pub scope:Scope, pub format:Format, pub facility:u8, pub card:u16,
 pub subject:[u8;32], pub revoked:bool,
 // Printed/vendor identifiers are display-only metadata, never keys for authorization.
 pub printed_facility:Option<u32>, pub printed_card:Option<u32>,
}
#[derive(Debug, Clone)]
pub struct Snapshot {pub scope:Scope, pub binding:Binding, pub verified_provenance:bool, pub format:Format, pub mappings:Vec<Mapping> }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {UntrustedReader, UntrustedSnapshot, InvalidBinding, ScopeMismatch, FormatMismatch, MalformedFrame, Parity, Unknown, Ambiguous, Revoked, InvalidSubject}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Result { Resolved{subject:[u8;32], decoded:Decoded}, Denied(Denial) }

/// H10301: bit 25 even parity over bits 24..13; bit 0 odd parity over bits 12..1.
/// Frame is an unsigned 26-bit integer, MSB at bit 25.
pub fn decode_h10301(frame:u64, bit_len:u8)->std::result::Result<Decoded,Denial> {
 if bit_len!=26 || (frame >> 26)!=0 {return Err(Denial::MalformedFrame)}
 let high=((frame>>13)&0xfff) as u32;
 let low=((frame>>1)&0xfff) as u32;
 let even=((frame>>25)&1) as u32;
 let odd=(frame&1) as u32;
 if (high.count_ones()+even)%2 !=0 || (low.count_ones()+odd)%2 !=1 {return Err(Denial::Parity)}
 Ok(Decoded{facility:((frame>>17)&0xff) as u8,card:((frame>>1)&0xffff) as u16})
}

pub fn resolve(obs:&Observation, snapshot:&Snapshot)->Result {
 if !obs.reader_identity_verified {return Result::Denied(Denial::UntrustedReader)}
 if !snapshot.verified_provenance {return Result::Denied(Denial::UntrustedSnapshot)}
 if snapshot.binding.epoch==0 || snapshot.binding.version==0 || snapshot.binding.digest==[0;32] || obs.binding!=snapshot.binding {return Result::Denied(Denial::InvalidBinding)}
 if obs.scope!=snapshot.scope || obs.scope.tenant==0 || obs.scope.site==0 || obs.scope.controller==0 || obs.scope.reader==0 {return Result::Denied(Denial::ScopeMismatch)}
 let decoded=match snapshot.format {Format::H10301_26=>match decode_h10301(obs.raw_frame,obs.bit_len){Ok(v)=>v,Err(e)=>return Result::Denied(e)}};
 // Never resolve a duplicated matching identifier by row order. Contradictory/revoked rows deny.
 let mut matches=snapshot.mappings.iter().filter(|m|m.scope==obs.scope && m.format==snapshot.format && m.facility==decoded.facility && m.card==decoded.card);
 let mapping=match matches.next() {None=>return Result::Denied(Denial::Unknown),Some(m)=>m};
 if matches.next().is_some(){return Result::Denied(Denial::Ambiguous)}
 if mapping.revoked {return Result::Denied(Denial::Revoked)}
 if mapping.subject==[0;32] {return Result::Denied(Denial::InvalidSubject)}
 Result::Resolved{subject:mapping.subject,decoded}
}

#[cfg(test)]
mod tests {
use super::*;
const S:Scope=Scope{tenant:1,site:2,controller:3,reader:4};
fn encode(fc:u8,card:u16)->u64 {
 let data=((fc as u64)<<17)|((card as u64)<<1);
 let hi=(data>>13)&0xfff; let lo=(data>>1)&0xfff;
 let p_hi=(hi.count_ones()%2) as u64;
 let p_lo=(1-(lo.count_ones()%2)) as u64;
 data|(p_hi<<25)|p_lo
}
fn fixture()->(Observation,Snapshot){
 let binding=Binding{epoch:1,version:3,digest:[9;32]};
 let obs=Observation{scope:S,binding,raw_frame:encode(37,25397),bit_len:26,reader_identity_verified:true};
 let snap=Snapshot{scope:S,binding,verified_provenance:true,format:Format::H10301_26,mappings:vec![Mapping{scope:S,format:Format::H10301_26,facility:37,card:25397,subject:[8;32],revoked:false,printed_facility:Some(8025),printed_card:Some(25397)}]};
 (obs,snap)
}
fn denied(f:impl FnOnce(&mut Observation,&mut Snapshot), expected:Denial){let (mut o,mut s)=fixture();f(&mut o,&mut s);assert_eq!(resolve(&o,&s),Result::Denied(expected));}
#[test] fn accepted_decoded_identity(){let(o,s)=fixture();assert_eq!(resolve(&o,&s),Result::Resolved{subject:[8;32],decoded:Decoded{facility:37,card:25397}})}
#[test] fn ssf_printed_fc_is_not_wiegand_fc(){let (o,mut s)=fixture();s.mappings[0].facility=8025u32 as u8;assert_eq!(resolve(&o,&s),Result::Denied(Denial::Unknown));}
#[test] fn printed_values_do_not_affect_mapping(){let(o,mut s)=fixture();s.mappings[0].printed_facility=Some(9999);s.mappings[0].printed_card=Some(1);assert!(matches!(resolve(&o,&s),Result::Resolved{..}));}
#[test] fn bad_parity(){denied(|o,_|o.raw_frame^=1,Denial::Parity)}
#[test] fn wrong_length(){denied(|o,_|o.bit_len=34,Denial::MalformedFrame)}
#[test] fn extra_high_bits(){denied(|o,_|o.raw_frame|=1<<30,Denial::MalformedFrame)}
#[test] fn raw_unknown_card(){denied(|o,_|o.raw_frame=encode(37,25398),Denial::Unknown)}
#[test] fn wrong_facility(){denied(|o,_|o.raw_frame=encode(38,25397),Denial::Unknown)}
#[test] fn unverified_reader(){denied(|o,_|o.reader_identity_verified=false,Denial::UntrustedReader)}
#[test] fn unsigned_snapshot(){denied(|_,s|s.verified_provenance=false,Denial::UntrustedSnapshot)}
#[test] fn wrong_digest(){denied(|o,_|o.binding.digest=[8;32],Denial::InvalidBinding)}
#[test] fn wrong_epoch(){denied(|o,_|o.binding.epoch=2,Denial::InvalidBinding)}
#[test] fn zero_digest(){denied(|o,s|{o.binding.digest=[0;32];s.binding.digest=[0;32]},Denial::InvalidBinding)}
#[test] fn zero_version(){denied(|o,s|{o.binding.version=0;s.binding.version=0},Denial::InvalidBinding)}
#[test] fn cross_tenant(){denied(|o,_|o.scope.tenant=9,Denial::ScopeMismatch)}
#[test] fn cross_site(){denied(|o,_|o.scope.site=9,Denial::ScopeMismatch)}
#[test] fn cross_controller(){denied(|o,_|o.scope.controller=9,Denial::ScopeMismatch)}
#[test] fn cross_reader(){denied(|o,_|o.scope.reader=9,Denial::ScopeMismatch)}
#[test] fn zero_tenant(){denied(|o,s|{o.scope.tenant=0;s.scope.tenant=0;s.mappings[0].scope.tenant=0},Denial::ScopeMismatch)}
#[test] fn matching_row_in_other_scope_does_not_grant(){denied(|_,s|s.mappings[0].scope.reader=5,Denial::Unknown)}
#[test] fn revoked(){denied(|_,s|s.mappings[0].revoked=true,Denial::Revoked)}
#[test] fn zero_subject(){denied(|_,s|s.mappings[0].subject=[0;32],Denial::InvalidSubject)}
#[test] fn duplicate_identical_row_denied(){denied(|_,s|s.mappings.push(s.mappings[0].clone()),Denial::Ambiguous)}
#[test] fn duplicate_conflicting_subject_denied(){denied(|_,s|{let mut m=s.mappings[0].clone();m.subject=[4;32];s.mappings.push(m)},Denial::Ambiguous)}
#[test] fn conflicting_revocation_denied(){denied(|_,s|{let mut m=s.mappings[0].clone();m.revoked=true;s.mappings.push(m)},Denial::Ambiguous)}
#[test] fn unmapped(){denied(|_,s|s.mappings.clear(),Denial::Unknown)}
#[test] fn parity_exhaustive_small_sample(){for fc in [0,1,37,255]{for card in [0,1,25397,65535]{assert_eq!(decode_h10301(encode(fc,card),26),Ok(Decoded{facility:fc,card}));}}}
}
