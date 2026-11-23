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
use super::door_alarm::{AlarmSettings, DoorWatch};
use super::relay_worker::{RelayCommand, Relock, door_state};

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
        // The request to exit is listed before the door's contact, so when both change
        // in the same round the release is known before the door is seen to open.
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

/// How long after a request to exit a door that opens counts as released by it, to cover
/// the moment the relay takes to follow.
const REX_RELEASE_GRACE: Duration = Duration::from_secs(1);

/// The door's state for judging whether it was forced. A locked door whose request to
/// exit went active a moment ago is being released. A door that is locked down is not:
/// its request to exit is refused.
fn released_by_rex(state: super::relay_worker::DoorState, rex_at: Option<Instant>, now: Instant) -> super::relay_worker::DoorState {
    use super::relay_worker::DoorState;
    let recent = rex_at.is_some_and(|at| now.saturating_duration_since(at) <= REX_RELEASE_GRACE);
    if state == DoorState::Locked && recent { DoorState::Unlocking } else { state }
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

    // Door alarms: one watch per door, and each door's settings, read again every few
    // seconds so a change takes effect without a restart.
    let mut door_watches: [DoorWatch; 4] = Default::default();
    let mut alarm_settings: [AlarmSettings; 4] = db.door_alarm_settings().unwrap_or_default();
    let mut alarm_settings_read = Instant::now();
    // When each door's request to exit last went active. The relay follows a moment
    // later, so a door that opens straight after is counted as released.
    let mut rex_at: [Option<Instant>; 4] = [None; 4];
    // How each door relocks after a momentary release. The relay worker is told at the
    // start and whenever the setting changes, so cards and remote unlocks follow it too.
    let mut relocks: [Option<Relock>; 4] = [None; 4];
    for channel in 0u8..4 {
        let relock = Relock::from_setting(db.door_rex_relock(channel).ok().flatten().as_deref());
        relocks[usize::from(channel)] = Some(relock);
        let _ = relay_tx.send(RelayCommand::DoorRelock { channel, relock }).await;
    }
    let alarm_event = |db: &ControllerDatabase, name: &str, channel: u8| {
        warn!(target: "indagate_door", event = name, channel = channel, door = channel + 1, "DOOR ALARM");
        queue_event(db, name, Some(channel), json!({ "channel": channel, "door": channel + 1 }));
    };

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

                if let (InputKind::Door, Some(channel)) = (input.kind, input.channel) {
                    if let Some(watch) = door_watches.get_mut(usize::from(channel)) {
                        watch.start(raw == 1, Instant::now());
                        watch.publish(channel);
                    }
                }

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

        if now.duration_since(alarm_settings_read) >= Duration::from_secs(3) {
            alarm_settings_read = now;
            if let Ok(settings) = db.door_alarm_settings() {
                alarm_settings = settings;
            }
            for channel in 0u8..4 {
                let relock = Relock::from_setting(db.door_rex_relock(channel).ok().flatten().as_deref());
                if relocks[usize::from(channel)] != Some(relock) {
                    relocks[usize::from(channel)] = Some(relock);
                    let _ = relay_tx.send(RelayCommand::DoorRelock { channel, relock }).await;
                }
            }
        }
        // A door that has stood open too long.
        for channel in 0u8..4 {
            let index = usize::from(channel);
            if let Some(name) = door_watches[index].tick(door_state(channel), alarm_settings[index], now) {
                door_watches[index].publish(channel);
                alarm_event(&db, name, channel);
            }
        }

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

            // Judged before the relay worker hears of the change: what matters is what
            // the door was doing at the moment it opened.
            if let (InputKind::Rex, Some(channel), 0) = (input.kind, input.channel, raw) {
                if let Some(slot) = rex_at.get_mut(usize::from(channel)) {
                    *slot = Some(now);
                }
            }
            if let (InputKind::Door, Some(channel)) = (input.kind, input.channel) {
                let index = usize::from(channel);
                if let Some(watch) = door_watches.get_mut(index) {
                    let state = released_by_rex(door_state(channel), rex_at[index], now);
                    let event = watch.contact(raw == 1, state, alarm_settings[index], now);
                    watch.publish(channel);
                    if let Some(name) = event {
                        alarm_event(&db, name, channel);
                    }
                }
            }

            process_change(input, previous, raw, &db, &relay_tx).await;
        }

        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::relay_worker::DoorState;

    #[test]
    fn a_door_opened_straight_after_its_request_to_exit_is_released() {
        let now = Instant::now();
        let just_now = Some(now - Duration::from_millis(200));
        let a_while_ago = Some(now - Duration::from_secs(5));
        assert_eq!(released_by_rex(DoorState::Locked, just_now, now), DoorState::Unlocking);
        assert_eq!(released_by_rex(DoorState::Locked, a_while_ago, now), DoorState::Locked);
        assert_eq!(released_by_rex(DoorState::Locked, None, now), DoorState::Locked);
        // A locked-down door refuses its request to exit, so it is still locked down.
        assert_eq!(released_by_rex(DoorState::ForcedLocked, just_now, now), DoorState::ForcedLocked);
    }

    #[test]
    fn a_request_to_exit_is_watched_before_its_doors_contact() {
        let profile = crate::hal::profile::acp4wr6_r1();
        let inputs = build_watch_list(&profile);
        for channel in 0u8..4 {
            let position = |kind: fn(&InputKind) -> bool| {
                inputs.iter().position(|input| input.channel == Some(channel) && kind(&input.kind))
            };
            let rex = position(|kind| matches!(kind, InputKind::Rex));
            let contact = position(|kind| matches!(kind, InputKind::Door));
            if let (Some(rex), Some(contact)) = (rex, contact) {
                assert!(rex < contact, "door {}", channel + 1);
            }
        }
    }
}
