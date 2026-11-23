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

use crate::storage::ControllerDatabase;

use super::profile::{BoardProfile, GpioLine};
use super::relay_worker::{RelayCommand, Relock};

#[derive(Debug, Clone, Copy)]
enum InputKind {
    Door,
    Rex,
    Fire,
}

#[derive(Debug, Clone)]
struct WatchedInput {
    name: String,
    kind: InputKind,
    channel: Option<u8>,
    legacy_gpio: u32,

    last_raw: Option<u8>,

    candidate_raw: Option<u8>,
    candidate_since: Option<Instant>,
}

fn chip_index(chip: &str) -> Option<u32> {
    chip.strip_prefix("gpiochip")?.parse::<u32>().ok()
}

fn legacy_gpio(line: &GpioLine) -> Option<u32> {
    chip_index(line.chip).map(|index| index * 32 + line.line)
}

fn read_sysfs_gpio(gpio: u32) -> Result<u8, String> {
    let path = format!("/sys/class/gpio/gpio{}/value", gpio);

    let value = fs::read_to_string(&path).map_err(|e| format!("{}: {}", path, e))?;

    match value.trim() {
        "0" => Ok(0),
        "1" => Ok(1),

        other => Err(format!("unexpected GPIO value '{}'", other)),
    }
}

fn electrical_state(raw: u8) -> &'static str {
    match raw {
        0 => "circuit_closed",
        1 => "circuit_open",
        _ => "unknown",
    }
}

fn queue_event(
    db: &ControllerDatabase,
    event_type: &str,
    channel: Option<u8>,
    payload: serde_json::Value,
) {
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
            channel = ?channel,
            error = %e,
            "Unable to queue Indagate input event"
        );
    }
}

fn build_watch_list(profile: &BoardProfile) -> Vec<WatchedInput> {
    let mut inputs = Vec::new();

    for door in &profile.doors {
        if let Some(gpio) = legacy_gpio(&door.contact) {
            inputs.push(WatchedInput {
                name: format!("door{}_contact", door.channel + 1),
                kind: InputKind::Door,
                channel: Some(door.channel),
                legacy_gpio: gpio,
                last_raw: None,
                candidate_raw: None,
                candidate_since: None,
            });
        }

        if let Some(gpio) = legacy_gpio(&door.rex) {
            inputs.push(WatchedInput {
                name: format!("rex{}", door.channel + 1),
                kind: InputKind::Rex,
                channel: Some(door.channel),
                legacy_gpio: gpio,
                last_raw: None,
                candidate_raw: None,
                candidate_since: None,
            });
        }
    }

    if let Some(gpio) = legacy_gpio(&profile.fire) {
        inputs.push(WatchedInput {
            name: "fire".to_string(),
            kind: InputKind::Fire,
            channel: None,
            legacy_gpio: gpio,
            last_raw: None,
            candidate_raw: None,
            candidate_since: None,
        });
    }

    inputs
}

async fn process_initial_state(
    input: &WatchedInput,
    raw: u8,
    db: &ControllerDatabase,
    relay_tx: &mpsc::Sender<RelayCommand>,
) {
    match input.kind {
        InputKind::Door => {
            let Some(channel) = input.channel else {
                return;
            };

            let event_type = if raw == 1 { "door_open" } else { "door_closed" };

            // The relay worker follows the door for releases that relock with it.
            let _ = relay_tx.send(RelayCommand::DoorContact { channel, open: raw == 1 }).await;

            queue_event(
                db,
                event_type,
                Some(channel),
                json!({
                    "channel": channel,
                    "door": channel + 1,
                    "raw": raw,
                    "state": event_type,
                    "initial": true
                }),
            );

            info!(
                target: "indagate_door",
                channel = channel,
                door = channel + 1,
                state = event_type,
                "Door supervision initialized"
            );
        }

        InputKind::Rex => {
            //
            // Do not create an unlock merely because REX
            // happens to be held when Indagate starts.
            //
        }

        InputKind::Fire => {
            //
            // Fire is safety-critical enough that an
            // already-active fire input must be honored
            // immediately at startup.
            //
            let active = raw == 0;

            if active {
                if let Err(e) = relay_tx
                    .send(RelayCommand::FireOverride { active: true })
                    .await
                {
                    error!(
                        error = %e,
                        "Unable to activate startup fire override"
                    );
                }
            }

            queue_event(
                db,
                if active { "fire_active" } else { "fire_normal" },
                None,
                json!({
                    "raw": raw,
                    "fire_active": active,
                    "initial": true
                }),
            );
        }
    }
}

async fn process_change(
    input: &WatchedInput,
    previous_raw: Option<u8>,
    raw: u8,
    db: &ControllerDatabase,
    relay_tx: &mpsc::Sender<RelayCommand>,
) {
    match input.kind {
        InputKind::Door => {
            let Some(channel) = input.channel else {
                return;
            };

            //
            // Confirmed electrical behavior:
            //
            // raw 1 = circuit open
            // raw 0 = circuit closed
            //
            let event_type = if raw == 1 { "door_open" } else { "door_closed" };

            if let Err(e) = relay_tx.send(RelayCommand::DoorContact { channel, open: raw == 1 }).await {
                error!(target: "indagate_door", channel = channel, error = %e, "Unable to tell the relay worker about the door");
            }

            info!(
                target: "indagate_door",
                event = event_type,
                channel = channel,
                door = channel + 1,
                previous_raw = ?previous_raw,
                raw = raw,
                "DOOR STATE"
            );

            queue_event(
                db,
                event_type,
                Some(channel),
                json!({
                    "channel": channel,
                    "door": channel + 1,
                    "previous_raw": previous_raw,
                    "raw": raw,
                    "state": event_type
                }),
            );
        }

        InputKind::Rex => {
            let Some(channel) = input.channel else {
                return;
            };

            //
            // REX activates when circuit closes.
            //
            let rex_active = raw == 0;

            if rex_active {
                match db.door_unlock_ms(channel) {
                    Ok(Some(duration_ms)) => {
                        let relock = Relock::from_setting(db.door_rex_relock(channel).ok().flatten().as_deref());

                        match relay_tx
                            .send(RelayCommand::Release {
                                channel,
                                duration_ms,
                                relock,
                            })
                            .await
                        {
                            Ok(()) => {
                                info!(
                                    target: "indagate_rex",
                                    channel = channel,
                                    door = channel + 1,
                                    duration_ms = duration_ms,
                                    "REX GRANTED"
                                );

                                queue_event(
                                    db,
                                    "rex_grant",
                                    Some(channel),
                                    json!({
                                        "channel": channel,
                                        "door": channel + 1,
                                        "raw": raw,
                                        "unlock_ms": duration_ms,
                                        "relock": relock.name()
                                    }),
                                );
                            }

                            Err(e) => {
                                error!(
                                    target: "indagate_rex",
                                    channel = channel,
                                    error = %e,
                                    "Unable to send REX relay command"
                                );

                                queue_event(
                                    db,
                                    "rex_error",
                                    Some(channel),
                                    json!({
                                        "channel": channel,
                                        "door": channel + 1,
                                        "reason":
                                            "relay_command_failed"
                                    }),
                                );
                            }
                        }
                    }

                    Ok(None) => {
                        warn!(
                            target: "indagate_rex",
                            channel = channel,
                            "REX ignored because door is disabled or unconfigured"
                        );

                        queue_event(
                            db,
                            "rex_ignored",
                            Some(channel),
                            json!({
                                "channel": channel,
                                "door": channel + 1,
                                "reason":
                                    "door_disabled_or_unconfigured"
                            }),
                        );
                    }

                    Err(e) => {
                        error!(
                            target: "indagate_rex",
                            channel = channel,
                            error = %e,
                            "Unable to load REX unlock duration"
                        );
                    }
                }
            } else {
                info!(
                    target: "indagate_rex",
                    channel = channel,
                    door = channel + 1,
                    "REX RELEASED"
                );

                queue_event(
                    db,
                    "rex_released",
                    Some(channel),
                    json!({
                        "channel": channel,
                        "door": channel + 1,
                        "raw": raw
                    }),
                );
            }
        }

        InputKind::Fire => {
            let active = raw == 0;

            info!(
                target: "indagate_fire",
                fire_active = active,
                previous_raw = ?previous_raw,
                raw = raw,
                "FIRE INPUT CHANGE"
            );

            match relay_tx.send(RelayCommand::FireOverride { active }).await {
                Ok(()) => {
                    queue_event(
                        db,
                        if active {
                            "fire_active"
                        } else {
                            "fire_cleared"
                        },
                        None,
                        json!({
                            "previous_raw":
                                previous_raw,
                            "raw": raw,
                            "fire_active": active
                        }),
                    );
                }

                Err(e) => {
                    error!(
                        target: "indagate_fire",
                        error = %e,
                        "Unable to send fire override command"
                    );
                }
            }
        }
    }
}

pub async fn run(profile: &BoardProfile, db_path: &str, relay_tx: mpsc::Sender<RelayCommand>) {
    const POLL_INTERVAL_MS: u64 = 20;
    const DEBOUNCE_MS: u64 = 75;

    let db = match ControllerDatabase::open(db_path) {
        Ok(db) => db,

        Err(e) => {
            error!(
                error = %e,
                "Unable to open Indagate database for input monitor"
            );

            return;
        }
    };

    let mut inputs = build_watch_list(profile);

    let mut read_errors: HashMap<u32, Instant> = HashMap::new();

    info!(
        "Input monitor started: {} inputs, {} ms polling, {} ms debounce",
        inputs.len(),
        POLL_INTERVAL_MS,
        DEBOUNCE_MS
    );

    //
    // Initialize current states.
    //
    for input in &mut inputs {
        match read_sysfs_gpio(input.legacy_gpio) {
            Ok(raw) => {
                input.last_raw = Some(raw);

                info!(
                    target: "indagate_input",
                    event = "initial_state",
                    name = %input.name,
                    channel = ?input.channel,
                    gpio = input.legacy_gpio,
                    raw = raw,
                    state =
                        electrical_state(raw),
                    "Input initialized"
                );

                process_initial_state(input, raw, &db, &relay_tx).await;
            }

            Err(e) => {
                warn!(
                    name = %input.name,
                    gpio = input.legacy_gpio,
                    error = %e,
                    "Unable to initialize input"
                );
            }
        }
    }

    loop {
        let now = Instant::now();

        for input in &mut inputs {
            let raw = match read_sysfs_gpio(input.legacy_gpio) {
                Ok(value) => value,

                Err(e) => {
                    let should_log = read_errors
                        .get(&input.legacy_gpio)
                        .map(|last| now.duration_since(*last) >= Duration::from_secs(10))
                        .unwrap_or(true);

                    if should_log {
                        warn!(
                            name = %input.name,
                            gpio =
                                input.legacy_gpio,
                            error = %e,
                            "GPIO read failed"
                        );

                        read_errors.insert(input.legacy_gpio, now);
                    }

                    continue;
                }
            };

            if input.last_raw == Some(raw) {
                input.candidate_raw = None;
                input.candidate_since = None;
                continue;
            }

            if input.candidate_raw != Some(raw) {
                input.candidate_raw = Some(raw);
                input.candidate_since = Some(now);
                continue;
            }

            let stable_for = input
                .candidate_since
                .map(|start| now.duration_since(start))
                .unwrap_or_default();

            if stable_for < Duration::from_millis(DEBOUNCE_MS) {
                continue;
            }

            let previous = input.last_raw;

            input.last_raw = Some(raw);
            input.candidate_raw = None;
            input.candidate_since = None;

            info!(
                target: "indagate_input",
                event = "state_change",
                name = %input.name,
                channel = ?input.channel,
                gpio = input.legacy_gpio,
                previous_raw = ?previous,
                raw = raw,
                state = electrical_state(raw),
                "INPUT CHANGE"
            );

            process_change(input, previous, raw, &db, &relay_tx).await;
        }

        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}
