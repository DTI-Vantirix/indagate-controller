//! Credential format identification. Candidate interpretations are NOT permissions.
//! Only H10301 with valid parity is authorization eligible in v2.2.
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Candidate {
    pub format_id: &'static str,
    pub frame_bits: usize,
    pub facility_code: Option<u32>,
    pub card_code: Option<u64>,
    pub parity: &'static str,
    pub authorization_eligible: bool,
    pub verified_definition: bool,
}

fn field(bits: &[u8]) -> u64 {
    bits.iter().fold(0u64, |v, bit| (v << 1) | u64::from(*bit))
}

pub fn identify(bits: &[u8], overflow: bool) -> Vec<Candidate> {
    if overflow || bits.is_empty() || bits.iter().any(|&b| b > 1) {
        return vec![];
    }
    // Only documented H10301 layout is treated as a verified decoding definition.
    if bits.len() == 26 {
        let even = bits[..13].iter().filter(|&&b| b == 1).count() % 2 == 0;
        let odd = bits[13..].iter().filter(|&&b| b == 1).count() % 2 == 1;
        let valid = even && odd;
        return vec![Candidate {
            format_id: "H10301-26",
            frame_bits: 26,
            facility_code: Some(field(&bits[1..9]) as u32),
            card_code: Some(field(&bits[9..25])),
            parity: if valid { "valid" } else { "invalid" },
            authorization_eligible: valid,
            verified_definition: true,
        }];
    }
    // 32/34-bit layouts vary. Explicitly reject until separately defined and verified.
    vec![Candidate {
        format_id: "UNIDENTIFIED",
        frame_bits: bits.len(),
        facility_code: None,
        card_code: None,
        parity: "not_evaluated",
        authorization_eligible: false,
        verified_definition: false,
    }]
}

pub fn printed_match(candidate: &Candidate, facility: u32, card: u64) -> bool {
    candidate.verified_definition
        && candidate.parity == "valid"
        && candidate.facility_code == Some(facility)
        && candidate.card_code == Some(card)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h10301(fc: u8, card: u16) -> Vec<u8> {
        let mut bits = vec![0];
        for i in (0..8).rev() {
            bits.push((fc >> i) & 1);
        }
        for i in (0..16).rev() {
            bits.push(((card >> i) & 1) as u8);
        }
        bits[0] = (bits[1..13].iter().filter(|&&b| b == 1).count() % 2) as u8;
        bits.push(
            if bits[13..25].iter().filter(|&&b| b == 1).count() % 2 == 0 {
                1
            } else {
                0
            },
        );
        bits
    }
    #[test]
    fn identifies_known_prox() {
        let cs = identify(&h10301(5, 22271), false);
        assert!(cs[0].authorization_eligible);
        assert!(printed_match(&cs[0], 5, 22271));
    }
    #[test]
    fn identifies_known_iclass() {
        let cs = identify(&h10301(101, 2083), false);
        assert!(printed_match(&cs[0], 101, 2083));
    }
    #[test]
    fn parity_error_never_authorizes() {
        let mut bits = h10301(5, 22271);
        bits[0] ^= 1;
        assert!(!identify(&bits, false)[0].authorization_eligible);
    }
    #[test]
    fn overflow_never_authorizes() {
        assert!(identify(&h10301(5, 22271), true).is_empty());
    }
    #[test]
    fn unsupported_lengths_have_no_invented_layout() {
        for n in [4, 24, 25, 32, 34, 37] {
            let cs = identify(&vec![0; n], false);
            assert_eq!(cs[0].format_id, "UNIDENTIFIED");
            assert!(!cs[0].authorization_eligible);
            assert!(cs[0].facility_code.is_none());
        }
    }
    #[test]
    fn printed_match_cannot_override_mismatch() {
        let cs = identify(&h10301(5, 22271), false);
        assert!(!printed_match(&cs[0], 8025, 25397));
    }
}
