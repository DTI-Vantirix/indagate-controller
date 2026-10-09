use chrono::Utc;
use rusqlite::params;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::access::engine::{self, AccessDecision};
use crate::storage::NexusDatabase;

use super::profile::{BoardProfile, GpioLine};
use super::relay_worker::RelayCommand;

#[derive(Debug)]
struct ReaderState {
    channel: u8,
    d0_gpio: u32,
    d1_gpio: u32,
    last_d0: u8,
    last_d1: u8,
    bits: Vec<u8>,
    last_bit_at: Option<Instant>,
}

fn chip_index(chip: &str) -> Option<u32> {
    chip.strip_prefix("gpiochip")?.parse::<u32>().ok()
}

fn legacy_gpio(line: &GpioLine) -> Option<u32> {
    chip_index(line.chip).map(|index| (index * 32) + line.line)
}

fn read_gpio(gpio: u32) -> Result<u8, String> {
    let path = format!("/sys/class/gpio/gpio{}/value", gpio);

    let value = fs::read_to_string(&path).map_err(|e| format!("{}: {}", path, e))?;

    match value.trim() {
        "0" => Ok(0),
        "1" => Ok(1),
        other => Err(format!("unexpected value '{}'", other)),
    }
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

fn queue_event(db: &NexusDatabase, event_type: &str, channel: u8, payload: serde_json::Value) {
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
            "Unable to queue Nexus event"
        );
    }
}

async fn finish_frame(
    reader: &mut ReaderState,
    db: &NexusDatabase,
    relay_tx: &mpsc::Sender<RelayCommand>,
) {
    if reader.bits.is_empty() {
        return;
    }

    let bits = std::mem::take(&mut reader.bits);
    let raw_bits = bit_string(&bits);

    let Some((facility, card, full, parity_valid)) = decode_26(&bits) else {
        warn!(
            target: "nexus_wiegand",
            reader = reader.channel + 1,
            channel = reader.channel,
            bits = bits.len(),
            raw_bits = %raw_bits,
            "Invalid Wiegand frame length"
        );

        queue_event(
            db,
            "wiegand_invalid_frame",
            reader.channel,
            json!({
                "reader": reader.channel + 1,
                "bits": bits.len(),
                "raw_bits": raw_bits,
                "reason": "invalid_frame_length"
            }),
        );

        reader.last_bit_at = None;
        return;
    };

    if !parity_valid {
        warn!(
            target: "nexus_wiegand",
            reader = reader.channel + 1,
            channel = reader.channel,
            facility_code = facility,
            card_code = card,
            raw_bits = %raw_bits,
            "Credential rejected: invalid Wiegand parity"
        );

        queue_event(
            db,
            "access_deny",
            reader.channel,
            json!({
                "reader": reader.channel + 1,
                "facility_code": facility,
                "card_code": card,
                "full_code": full,
                "raw_bits": raw_bits,
                "parity_valid": false,
                "decision": "Deny",
                "reason": "invalid_parity"
            }),
        );

        reader.last_bit_at = None;
        return;
    }

    match engine::evaluate(db.connection(), facility, card, reader.channel) {
        Ok(result) => {
            let event_type = match result.decision {
                AccessDecision::Grant => "access_grant",
                AccessDecision::Deny => "access_deny",
            };

            let mut relay_command_queued = false;
            let mut unlock_ms: Option<u64> = None;

            if matches!(result.decision, AccessDecision::Grant) {
                match db.door_unlock_ms(reader.channel) {
                    Ok(Some(duration)) => {
                        unlock_ms = Some(duration);

                        match relay_tx
                            .send(RelayCommand::Pulse {
                                channel: reader.channel,
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
                                    target: "nexus_access",
                                    channel = reader.channel,
                                    error = %e,
                                    "Access GRANT could not be sent to relay worker"
                                );
                            }
                        }
                    }

                    Ok(None) => {
                        error!(
                            target: "nexus_access",
                            channel = reader.channel,
                            "Access GRANT has no enabled door configuration"
                        );
                    }

                    Err(e) => {
                        error!(
                            target: "nexus_access",
                            channel = reader.channel,
                            error = %e,
                            "Unable to load door unlock duration"
                        );
                    }
                }
            }

            info!(
                target: "nexus_access",
                reader = reader.channel + 1,
                channel = reader.channel,
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
                reader.channel,
                json!({
                    "reader": reader.channel + 1,
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
            );
        }

        Err(e) => {
            warn!(
                target: "nexus_access",
                reader = reader.channel + 1,
                channel = reader.channel,
                facility_code = facility,
                card_code = card,
                error = %e,
                "Access engine failure"
            );

            queue_event(
                db,
                "access_error",
                reader.channel,
                json!({
                    "reader": reader.channel + 1,
                    "facility_code": facility,
                    "card_code": card,
                    "reason": "access_engine_error"
                }),
            );
        }
    }

    reader.last_bit_at = None;
}

pub async fn run(profile: &BoardProfile, db_path: &str, relay_tx: mpsc::Sender<RelayCommand>) {
    const POLL_US: u64 = 250;
    const FRAME_GAP_MS: u64 = 30;

    let db = match NexusDatabase::open(db_path) {
        Ok(db) => db,

        Err(e) => {
            warn!(
                error = %e,
                "Unable to open Nexus database for Wiegand engine"
            );

            return;
        }
    };

    let mut readers = Vec::new();

    for profile_reader in &profile.readers {
        let Some(d0_gpio) = legacy_gpio(&profile_reader.d0) else {
            continue;
        };

        let Some(d1_gpio) = legacy_gpio(&profile_reader.d1) else {
            continue;
        };

        readers.push(ReaderState {
            channel: profile_reader.channel,
            d0_gpio,
            d1_gpio,
            last_d0: read_gpio(d0_gpio).unwrap_or(1),
            last_d1: read_gpio(d1_gpio).unwrap_or(1),
            bits: Vec::with_capacity(64),
            last_bit_at: None,
        });
    }

    info!(
        "Wiegand/access engine started for {} readers",
        readers.len()
    );

    let mut error_times: HashMap<u32, Instant> = HashMap::new();

    loop {
        let now = Instant::now();

        for reader in &mut readers {
            let d0 = match read_gpio(reader.d0_gpio) {
                Ok(v) => v,

                Err(e) => {
                    let log = error_times
                        .get(&reader.d0_gpio)
                        .map(|t| now.duration_since(*t) > Duration::from_secs(10))
                        .unwrap_or(true);

                    if log {
                        warn!(
                            gpio = reader.d0_gpio,
                            error = %e,
                            "Wiegand D0 read error"
                        );

                        error_times.insert(reader.d0_gpio, now);
                    }

                    continue;
                }
            };

            let d1 = match read_gpio(reader.d1_gpio) {
                Ok(v) => v,

                Err(e) => {
                    let log = error_times
                        .get(&reader.d1_gpio)
                        .map(|t| now.duration_since(*t) > Duration::from_secs(10))
                        .unwrap_or(true);

                    if log {
                        warn!(
                            gpio = reader.d1_gpio,
                            error = %e,
                            "Wiegand D1 read error"
                        );

                        error_times.insert(reader.d1_gpio, now);
                    }

                    continue;
                }
            };

            if reader.last_d0 == 1 && d0 == 0 {
                reader.bits.push(0);
                reader.last_bit_at = Some(now);
            }

            if reader.last_d1 == 1 && d1 == 0 {
                reader.bits.push(1);
                reader.last_bit_at = Some(now);
            }

            reader.last_d0 = d0;
            reader.last_d1 = d1;

            if let Some(last_bit) = reader.last_bit_at {
                if now.duration_since(last_bit) >= Duration::from_millis(FRAME_GAP_MS) {
                    finish_frame(reader, &db, &relay_tx).await;
                }
            }
        }

        sleep(Duration::from_micros(POLL_US)).await;
    }
}
