//! One path from "a reader delivered card bits" to an access decision.
//!
//! Every reader technology ends here: it hands over the bits it read and the reader port
//! they came from. This module decodes them, asks the access engine, pulses the door relay
//! on a grant and queues the event for upload. Wiegand feeds it today; OSDP readers feed it
//! the same way.
//!
//! Only 26-bit cards (H10301: 8-bit facility code, 16-bit card number) are understood.

use chrono::Utc;
use rusqlite::params;
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::access::engine::{self, AccessDecision};
use crate::storage::ControllerDatabase;

use super::relay_worker::RelayCommand;

/// Which reader technology delivered the bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSource {
    Wiegand,
    Osdp,
}

impl ReadSource {
    fn name(self) -> &'static str {
        match self {
            ReadSource::Wiegand => "wiegand",
            ReadSource::Osdp => "osdp",
        }
    }
}

/// Card bits from one reader port (`channel` is the port number minus one).
#[derive(Debug, Clone)]
pub struct CardRead {
    pub channel: u8,
    pub bits: Vec<u8>,
    pub source: ReadSource,
}

/// What became of a card read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// Not a 26-bit frame.
    InvalidFrame,
    /// 26 bits, but the parity bits are wrong.
    InvalidParity,
    Granted { relay_command_queued: bool },
    Denied,
    /// The access engine could not decide (database error).
    EngineError,
}

/// Event payloads from Wiegand readers stay exactly as they always were; other sources
/// say which they are.
fn with_source(mut payload: serde_json::Value, source: ReadSource) -> serde_json::Value {
    if source != ReadSource::Wiegand {
        if let Some(map) = payload.as_object_mut() {
            map.insert("source".into(), json!(source.name()));
        }
    }
    payload
}

fn validate_26(bits: &[u8]) -> bool {
    if bits.len() != 26 {
        return false;
    }

    let first_12_ones = bits[1..13].iter().filter(|&&b| b == 1).count();

    let second_12_ones = bits[13..25].iter().filter(|&&b| b == 1).count();

    let leading_parity = bits[0] as usize;
    let trailing_parity = bits[25] as usize;

    let first_even = (first_12_ones + leading_parity) % 2 == 0;

    let second_odd = (second_12_ones + trailing_parity) % 2 == 1;

    first_even && second_odd
}

fn decode_26(bits: &[u8]) -> Option<(u8, u16, u32, bool)> {
    if bits.len() != 26 {
        return None;
    }

    let mut facility: u8 = 0;

    for &bit in &bits[1..9] {
        facility = (facility << 1) | bit;
    }

    let mut card: u16 = 0;

    for &bit in &bits[9..25] {
        card = (card << 1) | bit as u16;
    }

    let mut full: u32 = 0;

    for &bit in bits {
        full = (full << 1) | bit as u32;
    }

    Some((facility, card, full, validate_26(bits)))
}

fn bit_string(bits: &[u8]) -> String {
    bits.iter()
        .map(|b| if *b == 0 { '0' } else { '1' })
        .collect()
}

pub(crate) fn queue_event(db: &ControllerDatabase, event_type: &str, channel: u8, payload: serde_json::Value) {
    let result = db.connection().execute(
        r#"
        INSERT INTO event_queue
        (
            id,
            event_type,
            channel,
            payload_json,
            occurred_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            Uuid::new_v4().to_string(),
            event_type,
            channel,
            payload.to_string(),
            Utc::now().to_rfc3339(),
        ],
    );

    if let Err(e) = result {
        warn!(
            event_type = event_type,
            channel = channel,
            error = %e,
            "Unable to queue Indagate event"
        );
    }
}

/// Decide one card read: decode, evaluate, actuate on a grant, and queue the event.
pub async fn handle(
    read: CardRead,
    db: &ControllerDatabase,
    relay_tx: &mpsc::Sender<RelayCommand>,
) -> ReadOutcome {
    let CardRead { channel, bits, source } = read;
    let raw_bits = bit_string(&bits);

    // A port answers only to the protocol it is configured for. A Wiegand reader left
    // wired to a port that has been set to OSDP (or the reverse) must not open the door.
    // A port with no configuration falls through to the engine, which denies it.
    if let Ok(Some(configured)) = db.reader_protocol(channel) {
        if configured != source.name() {
            warn!(
                target: "indagate_access",
                reader = channel + 1,
                channel = channel,
                configured = %configured,
                received = source.name(),
                "Card read ignored: reader port is configured for another protocol"
            );
            queue_event(
                db,
                "access_deny",
                channel,
                json!({
                    "reader": channel + 1,
                    "bits": bits.len(),
                    "raw_bits": raw_bits,
                    "decision": "Deny",
                    "reason": "reader_protocol_mismatch",
                    "configured_protocol": configured,
                    "source": source.name()
                }),
            );
            return ReadOutcome::Denied;
        }
    }

    let Some((facility, card, full, parity_valid)) = decode_26(&bits) else {
        warn!(
            target: "indagate_wiegand",
            reader = channel + 1,
            channel = channel,
            source = source.name(),
            bits = bits.len(),
            raw_bits = %raw_bits,
            "Invalid Wiegand frame length"
        );

        queue_event(
            db,
            "wiegand_invalid_frame",
            channel,
            with_source(
                json!({
                    "reader": channel + 1,
                    "bits": bits.len(),
                    "raw_bits": raw_bits,
                    "reason": "invalid_frame_length"
                }),
                source,
            ),
        );
        return ReadOutcome::InvalidFrame;
    };

    if !parity_valid {
        warn!(
            target: "indagate_wiegand",
            reader = channel + 1,
            channel = channel,
            source = source.name(),
            facility_code = facility,
            card_code = card,
            raw_bits = %raw_bits,
            "Credential rejected: invalid Wiegand parity"
        );

        queue_event(
            db,
            "access_deny",
            channel,
            with_source(
                json!({
                    "reader": channel + 1,
                    "facility_code": facility,
                    "card_code": card,
                    "full_code": full,
                    "raw_bits": raw_bits,
                    "parity_valid": false,
                    "decision": "Deny",
                    "reason": "invalid_parity"
                }),
                source,
            ),
        );
        return ReadOutcome::InvalidParity;
    }

    match engine::evaluate(db.connection(), facility, card, channel) {
        Ok(result) => {
            let granted = matches!(result.decision, AccessDecision::Grant);
            let event_type = if granted { "access_grant" } else { "access_deny" };

            let mut relay_command_queued = false;
            let mut unlock_ms: Option<u64> = None;

            if granted {
                match db.door_unlock_ms(channel) {
                    Ok(Some(duration)) => {
                        unlock_ms = Some(duration);

                        match relay_tx
                            .send(RelayCommand::Pulse {
                                channel,
                                duration_ms: duration,
                                response: None,
                            })
                            .await
                        {
                            Ok(()) => {
                                relay_command_queued = true;
                            }

                            Err(e) => {
                                error!(
                                    target: "indagate_access",
                                    channel = channel,
                                    error = %e,
                                    "Access GRANT could not be sent to relay worker"
                                );
                            }
                        }
                    }

                    Ok(None) => {
                        error!(
                            target: "indagate_access",
                            channel = channel,
                            "Access GRANT has no enabled door configuration"
                        );
                    }

                    Err(e) => {
                        error!(
                            target: "indagate_access",
                            channel = channel,
                            error = %e,
                            "Unable to load door unlock duration"
                        );
                    }
                }
            }

            info!(
                target: "indagate_access",
                reader = channel + 1,
                channel = channel,
                source = source.name(),
                facility_code = facility,
                card_code = card,
                decision = ?result.decision,
                reason = %result.reason,
                holder = ?result.holder_name,
                unlock_ms = ?unlock_ms,
                relay_command_queued = relay_command_queued,
                "ACCESS DECISION"
            );

            queue_event(
                db,
                event_type,
                channel,
                with_source(
                    json!({
                        "reader": channel + 1,
                        "facility_code": facility,
                        "card_code": card,
                        "full_code": full,
                        "raw_bits": raw_bits,
                        "parity_valid": true,
                        "decision": result.decision,
                        "reason": result.reason,
                        "credential_id": result.credential_id,
                        "holder_name": result.holder_name,
                        "unlock_ms": unlock_ms,
                        "relay_command_queued": relay_command_queued
                    }),
                    source,
                ),
            );

            if granted {
                ReadOutcome::Granted { relay_command_queued }
            } else {
                ReadOutcome::Denied
            }
        }

        Err(e) => {
            warn!(
                target: "indagate_access",
                reader = channel + 1,
                channel = channel,
                facility_code = facility,
                card_code = card,
                error = %e,
                "Access engine failure"
            );

            queue_event(
                db,
                "access_error",
                channel,
                with_source(
                    json!({
                        "reader": channel + 1,
                        "facility_code": facility,
                        "card_code": card,
                        "reason": "access_engine_error"
                    }),
                    source,
                ),
            );
            ReadOutcome::EngineError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 26-bit frame for a facility code and card number.
    fn frame_26(facility: u8, card: u16) -> Vec<u8> {
        let mut bits = vec![0u8; 26];
        for i in 0..8 {
            bits[1 + i] = (facility >> (7 - i)) & 1;
        }
        for i in 0..16 {
            bits[9 + i] = ((card >> (15 - i)) & 1) as u8;
        }
        let first: usize = bits[1..13].iter().map(|b| *b as usize).sum();
        let second: usize = bits[13..25].iter().map(|b| *b as usize).sum();
        bits[0] = (first % 2) as u8; // even parity over the first half
        bits[25] = ((second + 1) % 2) as u8; // odd parity over the second half
        bits
    }

    fn database() -> ControllerDatabase {
        ControllerDatabase::open(":memory:").expect("in-memory database")
    }

    /// Reader 1 enabled on door 1, door 1 enabled with a 3 second unlock, and one active
    /// card (facility 5, card 22271) allowed through that door at all times.
    fn database_with_one_card() -> ControllerDatabase {
        let db = database();
        db.connection()
            .execute_batch(
                r#"
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel)
                    VALUES (1, 'reader1', 1, 0);
                UPDATE door_config SET unlock_ms = 3000 WHERE channel = 0;
                INSERT INTO credentials (id, facility_code, card_code, enabled, holder_name)
                    VALUES ('card', 5, 22271, 1, 'Test');
                INSERT INTO access_levels (id, name, enabled) VALUES ('level1', 'Level', 1);
                INSERT INTO credential_access_levels VALUES ('card', 'level1');
                INSERT INTO access_level_doors VALUES ('level1', 0, 'always');
                INSERT INTO schedules (id, name, timezone, definition_json)
                    VALUES ('always', 'Always', 'America/New_York', '{"always":true}');
                "#,
            )
            .expect("seed");
        db
    }

    fn events(db: &ControllerDatabase) -> Vec<(String, serde_json::Value)> {
        let mut statement = db
            .connection()
            .prepare("SELECT event_type, payload_json FROM event_queue ORDER BY rowid")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap()
            .map(|row| {
                let (kind, payload) = row.unwrap();
                (kind, serde_json::from_str(&payload).unwrap())
            })
            .collect()
    }

    fn read(bits: Vec<u8>, source: ReadSource) -> CardRead {
        CardRead { channel: 0, bits, source }
    }

    #[test]
    fn frame_26_helper_builds_valid_frames() {
        let bits = frame_26(5, 22271);
        assert_eq!(decode_26(&bits), Some((5, 22271, decode_26(&bits).unwrap().2, true)));
    }

    #[tokio::test]
    async fn wrong_length_is_rejected_and_recorded() {
        let db = database();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = handle(read(vec![1; 34], ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::InvalidFrame);
        assert!(rx.try_recv().is_err(), "no relay command");
        let events = events(&db);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "wiegand_invalid_frame");
        assert_eq!(events[0].1["reason"], "invalid_frame_length");
        assert_eq!(events[0].1["bits"], 34);
    }

    #[tokio::test]
    async fn bad_parity_is_denied_without_asking_the_engine() {
        let db = database_with_one_card();
        let (tx, mut rx) = mpsc::channel(4);
        let mut bits = frame_26(5, 22271);
        bits[0] ^= 1;
        let outcome = handle(read(bits, ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::InvalidParity);
        assert!(rx.try_recv().is_err(), "no relay command");
        let events = events(&db);
        assert_eq!(events[0].0, "access_deny");
        assert_eq!(events[0].1["reason"], "invalid_parity");
    }

    #[tokio::test]
    async fn unknown_card_is_denied() {
        let db = database_with_one_card();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = handle(read(frame_26(5, 1), ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Denied);
        assert!(rx.try_recv().is_err(), "no relay command");
        assert_eq!(events(&db)[0].0, "access_deny");
    }

    #[tokio::test]
    async fn known_card_is_granted_and_pulses_its_door() {
        let db = database_with_one_card();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = handle(read(frame_26(5, 22271), ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Granted { relay_command_queued: true });
        match rx.try_recv().expect("a relay command") {
            RelayCommand::Pulse { channel, duration_ms, .. } => {
                assert_eq!((channel, duration_ms), (0, 3000));
            }
            _ => panic!("expected a pulse"),
        }
        let events = events(&db);
        assert_eq!(events[0].0, "access_grant");
        assert_eq!(events[0].1["facility_code"], 5);
        assert_eq!(events[0].1["card_code"], 22271);
        assert_eq!(events[0].1["unlock_ms"], 3000);
        // A Wiegand event carries exactly the fields it always has.
        assert!(events[0].1.get("source").is_none());
    }

    #[tokio::test]
    async fn an_osdp_read_decides_the_same_and_says_where_it_came_from() {
        let db = database_with_one_card();
        db.connection()
            .execute("UPDATE reader_config SET protocol = 'osdp', osdp_address = 7 WHERE reader_number = 1", [])
            .unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = handle(read(frame_26(5, 22271), ReadSource::Osdp), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Granted { relay_command_queued: true });
        assert!(rx.try_recv().is_ok());
        assert_eq!(events(&db)[0].1["source"], "osdp");
    }

    #[tokio::test]
    async fn a_wiegand_card_at_a_port_set_to_osdp_does_not_open_the_door() {
        let db = database_with_one_card();
        db.connection()
            .execute("UPDATE reader_config SET protocol = 'osdp', osdp_address = 7 WHERE reader_number = 1", [])
            .unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = handle(read(frame_26(5, 22271), ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Denied);
        assert!(rx.try_recv().is_err(), "no relay command");
        let events = events(&db);
        assert_eq!(events[0].0, "access_deny");
        assert_eq!(events[0].1["reason"], "reader_protocol_mismatch");
        assert_eq!(events[0].1["configured_protocol"], "osdp");
        assert_eq!(events[0].1["source"], "wiegand");
    }

    #[tokio::test]
    async fn an_osdp_card_at_a_port_set_to_wiegand_does_not_open_the_door() {
        let db = database_with_one_card();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = handle(read(frame_26(5, 22271), ReadSource::Osdp), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Denied);
        assert!(rx.try_recv().is_err(), "no relay command");
        assert_eq!(events(&db)[0].1["reason"], "reader_protocol_mismatch");
    }

    #[test]
    fn an_older_database_gains_the_protocol_columns_and_stays_wiegand() {
        let path = std::env::temp_dir().join(format!("indagate-reader-columns-{}.db", Uuid::new_v4()));
        {
            // The reader table as it was before ports had a protocol.
            let old = rusqlite::Connection::open(&path).unwrap();
            old.execute_batch(
                r#"
                CREATE TABLE reader_config (
                    reader_number INTEGER PRIMARY KEY CHECK(reader_number BETWEEN 1 AND 4),
                    reader_id TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    door_channel INTEGER NOT NULL CHECK(door_channel BETWEEN 0 AND 3),
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel) VALUES (2, 'reader2', 1, 1);
                "#,
            )
            .unwrap();
        }
        let db = ControllerDatabase::open(path.to_str().unwrap()).unwrap();
        assert_eq!(db.reader_protocol(1).unwrap().as_deref(), Some("wiegand"));
        assert_eq!(db.reader_protocol(0).unwrap(), None);
        assert!(db.osdp_readers().unwrap().is_empty());
        db.connection()
            .execute("UPDATE reader_config SET protocol = 'osdp', osdp_address = 12, osdp_baud_rate = 38400", [])
            .unwrap();
        assert_eq!(db.osdp_readers().unwrap(), vec![(1, 12, 38400)]);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
