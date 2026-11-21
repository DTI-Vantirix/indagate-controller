//! One path from "a reader delivered card bits" to an access decision.
//!
//! Every reader technology ends here: it hands over the bits it read and the reader port
//! they came from. This module decodes them, asks the access engine, pulses the door relay
//! on a grant and queues the event for upload. Wiegand feeds it today; OSDP readers feed it
//! the same way.
//!
//! Which card layouts are understood, and how each is checked, is `access::card_formats`.

use chrono::Utc;
use rusqlite::params;
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::access::card_formats;
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

/// Every bit of the card as one number, as events have always carried it.
fn full_code(bits: &[u8]) -> u64 {
    bits.iter().take(64).fold(0, |value, &bit| (value << 1) | u64::from(bit & 1))
}

/// Events for the 26-bit layout stay exactly as they always were; other layouts say which
/// they are.
fn with_format(mut payload: serde_json::Value, format: &str) -> serde_json::Value {
    if format != engine::DEFAULT_CARD_FORMAT {
        if let Some(map) = payload.as_object_mut() {
            map.insert("format".into(), json!(format));
        }
    }
    payload
}

fn as_card(reading: &card_formats::Reading) -> engine::Card<'static> {
    engine::Card { format: reading.format, facility_code: reading.facility_code, card_code: reading.card_code }
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

    let readings = card_formats::readings(&bits);
    let Some(first) = readings.first().copied() else {
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

    // A 37-bit card has two readings and the card cannot say which it is: take the one
    // this controller holds a credential for. Otherwise the first whose check bits agree.
    let reading = readings
        .iter()
        .copied()
        .find(|r| r.parity_valid && engine::card_is_known(db.connection(), &as_card(r)).unwrap_or(false))
        .or_else(|| readings.iter().copied().find(|r| r.parity_valid))
        .unwrap_or(first);
    let (format, facility, card, parity_valid) = (reading.format, reading.facility_code, reading.card_code, reading.parity_valid);
    let full = full_code(&bits);
    // From here on every event also says the layout, when it is not the 26-bit one.
    let with_source = |payload: serde_json::Value, source: ReadSource| with_format(with_source(payload, source), format);

    if !parity_valid {
        warn!(
            target: "indagate_wiegand",
            reader = channel + 1,
            channel = channel,
            source = source.name(),
            facility_code = ?facility,
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

    match engine::evaluate_card(db.connection(), &as_card(&reading), channel) {
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
                facility_code = ?facility,
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
                facility_code = ?facility,
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
        let reading = card_formats::readings(&bits);
        assert_eq!((reading[0].format, reading[0].facility_code, reading[0].card_code, reading[0].parity_valid), ("h10301-26", Some(5), 22271, true));
    }

    #[tokio::test]
    async fn wrong_length_is_rejected_and_recorded() {
        let db = database();
        let (tx, mut rx) = mpsc::channel(4);
        // 35 bits is a real card length, but not one this controller decides on.
        let outcome = handle(read(vec![1; 35], ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::InvalidFrame);
        assert!(rx.try_recv().is_err(), "no relay command");
        let events = events(&db);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "wiegand_invalid_frame");
        assert_eq!(events[0].1["reason"], "invalid_frame_length");
        assert_eq!(events[0].1["bits"], 35);
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
        assert_eq!(db.osdp_readers().unwrap(), vec![(1, 12, 38400, false)]);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    // ---------- longer card layouts ----------

    use crate::access::card_formats::tests::card as build_card;

    /// As `database_with_one_card`, plus a card of another layout allowed through door 1.
    fn database_with_card(id: &str, format: &str, facility: i64, card: i64) -> ControllerDatabase {
        let db = database_with_one_card();
        db.connection()
            .execute(
                "INSERT INTO credentials (id, format, facility_code, card_code, enabled, holder_name) VALUES (?1, ?2, ?3, ?4, 1, 'Long')",
                rusqlite::params![id, format, facility, card],
            )
            .unwrap();
        db.connection().execute("INSERT INTO credential_access_levels VALUES (?1, 'level1')", [id]).unwrap();
        db
    }

    #[tokio::test]
    async fn a_34_bit_card_opens_its_door_and_the_event_says_its_layout() {
        let db = database_with_card("long", "h10306-34", 40000, 51234);
        let (tx, mut rx) = mpsc::channel(4);
        let bits = build_card(&[(40000, 16), (51234, 16)], 17, 17);
        let outcome = handle(read(bits, ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Granted { relay_command_queued: true });
        assert!(rx.try_recv().is_ok(), "a relay command");
        let events = events(&db);
        assert_eq!(events[0].0, "access_grant");
        assert_eq!(events[0].1["format"], "h10306-34");
        assert_eq!(events[0].1["facility_code"], 40000);
        assert_eq!(events[0].1["card_code"], 51234);
        assert_eq!(events[0].1["credential_id"], "long");
        assert_eq!(events[0].1["bits"].as_u64().or(Some(34)), Some(34));
    }

    #[tokio::test]
    async fn events_for_26_bit_cards_are_unchanged() {
        let db = database_with_one_card();
        let (tx, _rx) = mpsc::channel(4);
        handle(read(frame_26(5, 22271), ReadSource::Wiegand), &db, &tx).await;
        let event = &events(&db)[0].1;
        assert!(event.get("format").is_none(), "no layout field for the 26-bit layout: {event}");
        assert_eq!(event["full_code"], 0b00000010101010110111111111u64);
    }

    #[tokio::test]
    async fn the_same_numbers_under_another_layout_are_a_different_card() {
        // The database knows facility 5, card 22271 as a 26-bit card only.
        let db = database_with_one_card();
        let (tx, mut rx) = mpsc::channel(4);
        let same_numbers_34_bit = build_card(&[(5, 16), (22271, 16)], 17, 17);
        let outcome = handle(read(same_numbers_34_bit, ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Denied);
        assert!(rx.try_recv().is_err(), "no relay command");
        let events = events(&db);
        assert_eq!(events[0].1["reason"], "credential_not_found");
        assert_eq!(events[0].1["format"], "h10306-34");

        // And the reverse: a 34-bit credential is not opened by a 26-bit card with its numbers.
        let db = database();
        db.connection()
            .execute_batch(
                r#"
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel) VALUES (1, 'reader1', 1, 0);
                INSERT INTO credentials (id, format, facility_code, card_code, enabled) VALUES ('long', 'h10306-34', 5, 22271, 1);
                INSERT INTO access_levels (id, name, enabled) VALUES ('level1', 'Level', 1);
                INSERT INTO credential_access_levels VALUES ('long', 'level1');
                INSERT INTO access_level_doors VALUES ('level1', 0, 'always');
                INSERT INTO schedules (id, name, timezone, definition_json) VALUES ('always', 'Always', 'America/New_York', '{"always":true}');
                "#,
            )
            .unwrap();
        let outcome = handle(read(frame_26(5, 22271), ReadSource::Wiegand), &db, &tx).await;
        assert_eq!(outcome, ReadOutcome::Denied);
        assert!(rx.try_recv().is_err(), "no relay command");
    }

    #[tokio::test]
    async fn a_37_bit_card_is_read_the_way_its_credential_says() {
        let bits = build_card(&[(1234, 16), (500_000, 19)], 19, 19);
        let as_one_number = (1234i64 << 19) | 500_000;

        // Held as the layout with a facility code.
        let db = database_with_card("with-facility", "h10304-37", 1234, 500_000);
        let (tx, mut rx) = mpsc::channel(4);
        assert_eq!(handle(read(bits.clone(), ReadSource::Wiegand), &db, &tx).await, ReadOutcome::Granted { relay_command_queued: true });
        assert!(rx.try_recv().is_ok());
        assert_eq!(events(&db)[0].1["format"], "h10304-37");

        // Held as the layout without one: the same bits, the other reading.
        let db = database_with_card("no-facility", "h10302-37", 0, as_one_number);
        assert_eq!(handle(read(bits.clone(), ReadSource::Wiegand), &db, &tx).await, ReadOutcome::Granted { relay_command_queued: true });
        assert!(rx.try_recv().is_ok());
        let event = &events(&db)[0].1;
        assert_eq!(event["format"], "h10302-37");
        assert!(event["facility_code"].is_null());
        assert_eq!(event["card_code"], as_one_number);

        // Held as neither: refused.
        let db = database_with_one_card();
        assert_eq!(handle(read(bits, ReadSource::Wiegand), &db, &tx).await, ReadOutcome::Denied);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_damaged_long_card_is_refused_before_any_lookup() {
        let db = database_with_card("long", "h10306-34", 40000, 51234);
        let (tx, mut rx) = mpsc::channel(4);
        let mut bits = build_card(&[(40000, 16), (51234, 16)], 17, 17);
        bits[20] ^= 1;
        assert_eq!(handle(read(bits, ReadSource::Wiegand), &db, &tx).await, ReadOutcome::InvalidParity);
        assert!(rx.try_recv().is_err(), "no relay command");
        assert_eq!(events(&db)[0].1["reason"], "invalid_parity");
    }

    #[test]
    fn an_older_database_keeps_its_cards_as_26_bit_ones() {
        let path = std::env::temp_dir().join(format!("indagate-card-layout-{}.db", Uuid::new_v4()));
        {
            // The credentials table as it was before cards had a layout.
            let old = rusqlite::Connection::open(&path).unwrap();
            old.execute_batch(
                r#"
                CREATE TABLE credentials (
                    id TEXT PRIMARY KEY,
                    facility_code INTEGER NOT NULL,
                    card_code INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    valid_from TEXT,
                    valid_until TEXT,
                    holder_name TEXT,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(facility_code, card_code)
                );
                INSERT INTO credentials (id, facility_code, card_code, enabled, holder_name) VALUES ('old', 5, 22271, 1, 'Kept');
                "#,
            )
            .unwrap();
        }
        let db = ControllerDatabase::open(path.to_str().unwrap()).unwrap();
        let kept: (String, i64, i64, String) = db
            .connection()
            .query_row("SELECT format, facility_code, card_code, holder_name FROM credentials WHERE id = 'old'", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!(kept, ("h10301-26".to_string(), 5, 22271, "Kept".to_string()));
        // The same numbers may now exist once per layout, and still only once within one.
        db.connection()
            .execute("INSERT INTO credentials (id, format, facility_code, card_code) VALUES ('long', 'h10306-34', 5, 22271)", [])
            .unwrap();
        assert!(db
            .connection()
            .execute("INSERT INTO credentials (id, format, facility_code, card_code) VALUES ('dup', 'h10301-26', 5, 22271)", [])
            .is_err());
        drop(db);
        // Opening it again changes nothing.
        let db = ControllerDatabase::open(path.to_str().unwrap()).unwrap();
        let count: i64 = db.connection().query_row("SELECT count(*) FROM credentials", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 2);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
