//! The card layouts this controller can decide on.
//!
//! A reader delivers a run of bits. Their count says which layouts they could be, and each
//! layout says where the facility code and card number sit and how the card's own check
//! bits are worked out. Only layouts whose check bits are verified here are offered: a
//! card is never matched on bits that have not been checked.
//!
//! The same table tells the configuration what numbers a credential of each layout may
//! hold, so the two can never disagree about what a layout is.

/// One layout's reading of a card's bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// Layout identifier, shared with the server (`h10301-26`, ...).
    pub format: &'static str,
    /// Absent for layouts that have no facility code.
    pub facility_code: Option<u64>,
    pub card_code: u64,
    /// The card's check bits agree with this layout.
    pub parity_valid: bool,
}

/// What a credential of one layout may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest facility code, or `None` for a layout that has none.
    pub max_facility_code: Option<u64>,
    pub max_card_code: u64,
}

/// The limits for a layout, or `None` if this controller does not know it.
pub fn limits(format: &str) -> Option<Limits> {
    let (facility_bits, card_bits) = match format {
        "h10301-26" => (Some(8), 16),
        "h10306-34" => (Some(16), 16),
        "h10304-37" => (Some(16), 19),
        "h10302-37" => (None, 35),
        _ => return None,
    };
    Some(Limits { max_facility_code: facility_bits.map(|bits: u32| (1u64 << bits) - 1), max_card_code: (1u64 << card_bits) - 1 })
}

/// The number held in `bits[start..start + length]`, first bit most significant.
fn number(bits: &[u8], start: usize, length: usize) -> u64 {
    bits[start..start + length].iter().fold(0, |value, &bit| (value << 1) | u64::from(bit & 1))
}

fn ones(bits: &[u8]) -> usize {
    bits.iter().filter(|&&bit| bit & 1 == 1).count()
}

/// Even parity: the span, including its check bit, holds an even number of ones.
fn even(bits: &[u8]) -> bool {
    ones(bits) % 2 == 0
}

/// Odd parity: the span, including its check bit, holds an odd number of ones.
fn odd(bits: &[u8]) -> bool {
    ones(bits) % 2 == 1
}

/// Every reading this controller knows for these bits. Empty when their count matches no
/// known layout.
pub fn readings(bits: &[u8]) -> Vec<Reading> {
    match bits.len() {
        // H10301: P | 8-bit facility | 16-bit card | P. Even over the first 13 bits, odd
        // over the last 13.
        26 => vec![Reading {
            format: "h10301-26",
            facility_code: Some(number(bits, 1, 8)),
            card_code: number(bits, 9, 16),
            parity_valid: even(&bits[0..13]) && odd(&bits[13..26]),
        }],
        // H10306: P | 16-bit facility | 16-bit card | P. Even over the first 17 bits, odd
        // over the last 17.
        34 => vec![Reading {
            format: "h10306-34",
            facility_code: Some(number(bits, 1, 16)),
            card_code: number(bits, 17, 16),
            parity_valid: even(&bits[0..17]) && odd(&bits[17..34]),
        }],
        // Two layouts share 37 bits and the same check bits: even over the first 19 bits,
        // odd over the last 19 (the middle bit is counted by both). Which one a card is
        // cannot be told from the card; the credential says.
        37 => {
            let parity_valid = even(&bits[0..19]) && odd(&bits[18..37]);
            vec![
                // H10304: P | 16-bit facility | 19-bit card | P.
                Reading {
                    format: "h10304-37",
                    facility_code: Some(number(bits, 1, 16)),
                    card_code: number(bits, 17, 19),
                    parity_valid,
                },
                // H10302: P | 35-bit card | P.
                Reading { format: "h10302-37", facility_code: None, card_code: number(bits, 1, 35), parity_valid },
            ]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a card: the fields most significant bit first between two check bits worked
    /// out the way the layout says.
    pub(crate) fn card(fields: &[(u64, usize)], even_span: usize, odd_span: usize) -> Vec<u8> {
        let mut out = vec![0u8];
        for &(value, width) in fields {
            for i in (0..width).rev() {
                out.push(((value >> i) & 1) as u8);
            }
        }
        out.push(0);
        let total = out.len();
        out[0] = (ones(&out[0..even_span]) % 2) as u8;
        out[total - 1] = ((ones(&out[total - odd_span..total]) + 1) % 2) as u8;
        out
    }

    #[test]
    fn a_26_bit_card_reads_as_it_always_did() {
        // The bench's real card: facility 5, card 22271.
        let bits: Vec<u8> = "00000010101010110111111111".bytes().map(|b| b - b'0').collect();
        assert_eq!(
            readings(&bits),
            vec![Reading { format: "h10301-26", facility_code: Some(5), card_code: 22271, parity_valid: true }]
        );
        assert_eq!(readings(&card(&[(255, 8), (65535, 16)], 13, 13))[0].card_code, 65535);
    }

    #[test]
    fn a_34_bit_card_has_a_16_bit_facility_code() {
        let bits = card(&[(40000, 16), (51234, 16)], 17, 17);
        assert_eq!(bits.len(), 34);
        assert_eq!(
            readings(&bits),
            vec![Reading { format: "h10306-34", facility_code: Some(40000), card_code: 51234, parity_valid: true }]
        );
    }

    #[test]
    fn a_37_bit_card_has_two_readings_and_the_credential_chooses() {
        let bits = card(&[(1234, 16), (500_000, 19)], 19, 19);
        assert_eq!(bits.len(), 37);
        let both = readings(&bits);
        assert_eq!(both[0], Reading { format: "h10304-37", facility_code: Some(1234), card_code: 500_000, parity_valid: true });
        assert_eq!(both[1].format, "h10302-37");
        assert_eq!(both[1].facility_code, None);
        assert_eq!(both[1].card_code, (1234u64 << 19) | 500_000);
        assert!(both[1].parity_valid);

        let no_facility = card(&[(30_000_000_000, 35)], 19, 19);
        assert_eq!(readings(&no_facility)[1].card_code, 30_000_000_000);
    }

    #[test]
    fn one_flipped_bit_fails_the_check_in_every_layout() {
        for good in [
            card(&[(5, 8), (22271, 16)], 13, 13),
            card(&[(40000, 16), (51234, 16)], 17, 17),
            card(&[(1234, 16), (500_000, 19)], 19, 19),
        ] {
            assert!(readings(&good).iter().all(|r| r.parity_valid));
            for i in 0..good.len() {
                let mut bad = good.clone();
                bad[i] ^= 1;
                assert!(readings(&bad).iter().all(|r| !r.parity_valid), "bit {i} of a {}-bit card", good.len());
            }
        }
    }

    #[test]
    fn other_lengths_are_not_cards_this_controller_decides_on() {
        // 35 bits (Corporate 1000) is left out on purpose: its check bits are not verified here.
        for length in [0, 1, 25, 27, 33, 35, 36, 38, 48, 64] {
            assert!(readings(&vec![1; length]).is_empty(), "{length} bits");
        }
    }

    #[test]
    fn limits_follow_the_field_widths() {
        assert_eq!(limits("h10301-26"), Some(Limits { max_facility_code: Some(255), max_card_code: 65535 }));
        assert_eq!(limits("h10306-34"), Some(Limits { max_facility_code: Some(65535), max_card_code: 65535 }));
        assert_eq!(limits("h10304-37"), Some(Limits { max_facility_code: Some(65535), max_card_code: 524_287 }));
        assert_eq!(limits("h10302-37"), Some(Limits { max_facility_code: None, max_card_code: (1 << 35) - 1 }));
        assert_eq!(limits("corporate-1000-35"), None);
        assert_eq!(limits(""), None);
    }
}
