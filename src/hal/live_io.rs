//! What the board's relays and inputs are doing right now, for the check-in.
//!
//! The server shows the present state of every output and input. The parts of the firmware
//! that own them say what they last saw here, and the check-in reports it:
//!
//! * the relay driver records each relay it switches, and whether the switch worked;
//! * the input monitor records each input's level once it has settled.
//!
//! Nothing here touches the hardware. In particular the relay chip is never read for the
//! check-in: a second reader on its bus could come between the relay worker's read and
//! write of the output register.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use super::door_alarm::{door_alarm, DoorAlarm};
use super::relay::RelayBackend;
use super::relay_worker::{door_state, DoorState};

#[derive(Default)]
struct Relays {
    /// Each relay as it was last switched: channel -> energised.
    energised: BTreeMap<u8, bool>,
    /// How the relay chip was last reached.
    backend: Option<RelayBackend>,
    /// Whether the last switch worked, and why not when it did not.
    last_error: Option<String>,
    switched: bool,
}

static RELAYS: Mutex<Option<Relays>> = Mutex::new(None);
/// Each input's settled level: name -> raw (0 = circuit closed, 1 = circuit open).
static INPUTS: Mutex<BTreeMap<String, u8>> = Mutex::new(BTreeMap::new());

/// The relay driver switched `channel`, and it worked.
pub fn relay_switched(channel: u8, energised: bool, backend: RelayBackend) {
    if let Ok(mut relays) = RELAYS.lock() {
        let relays = relays.get_or_insert_with(Relays::default);
        relays.energised.insert(channel, energised);
        relays.backend = Some(backend);
        relays.last_error = None;
        relays.switched = true;
    }
}

/// The relay driver could not switch a relay.
pub fn relay_failed(error: &str) {
    if let Ok(mut relays) = RELAYS.lock() {
        let relays = relays.get_or_insert_with(Relays::default);
        relays.last_error = Some(error.chars().take(200).collect());
        relays.switched = true;
    }
}

/// The input monitor saw `name` settle at `raw`.
pub fn input_settled(name: &str, raw: u8) {
    if let Ok(mut inputs) = INPUTS.lock() {
        inputs.insert(name.to_string(), raw);
    }
}

fn lock_word(state: DoorState) -> &'static str {
    match state {
        DoorState::Locked => "locked",
        DoorState::Unlocking => "unlocking",
        DoorState::HeldUnlocked => "held_unlocked",
        DoorState::ForcedLocked => "forced_locked",
    }
}

fn alarm_word(alarm: DoorAlarm) -> Option<&'static str> {
    match alarm {
        DoorAlarm::None => None,
        DoorAlarm::Forced => Some("forced"),
        DoorAlarm::Held => Some("held"),
    }
}

/// What an input's level means. A door contact and the fire input are closed circuits
/// when all is well; a request to exit closes its circuit when pressed.
fn input_meaning(name: &str, raw: u8) -> &'static str {
    let closed = raw == 0;
    if name.starts_with("rex") {
        if closed { "active" } else { "idle" }
    } else if name == "fire" {
        if closed { "active" } else { "normal" }
    } else if closed {
        "closed"
    } else {
        "open"
    }
}

/// The relay part of the check-in: how the chip is reached, whether the last switch
/// worked, and each relay's state. Before any relay has been switched nothing is known,
/// and nothing is claimed.
pub fn relay_report() -> Value {
    let Ok(relays) = RELAYS.lock() else { return Value::Null };
    let Some(relays) = relays.as_ref().filter(|relays| relays.switched) else {
        return json!({ "backend": null, "available": null, "outputs": [] });
    };
    json!({
        "backend": relays.backend,
        "available": relays.last_error.is_none(),
        "last_error": relays.last_error,
        "outputs": relays.energised.iter().map(|(channel, energised)| json!({
            "output": channel + 1,
            "energised": energised,
        })).collect::<Vec<_>>(),
    })
}

/// The door and input part of the check-in, for `doors` doors (channels 0 upward).
pub fn io_report(doors: u8) -> Value {
    let inputs = INPUTS.lock().map(|inputs| inputs.clone()).unwrap_or_default();
    let input = |name: &str| inputs.get(name).map(|raw| input_meaning(name, *raw));
    json!({
        "doors": (0..doors).map(|channel| json!({
            "door": channel + 1,
            "lock": lock_word(door_state(channel)),
            "alarm": alarm_word(door_alarm(channel)),
            "contact": input(&format!("door{}_contact", channel + 1)),
            "rex": input(&format!("rex{}", channel + 1)),
        })).collect::<Vec<_>>(),
        "inputs": inputs.iter().map(|(name, raw)| json!({
            "name": name,
            "raw": raw,
            "state": input_meaning(name, *raw),
        })).collect::<Vec<_>>(),
        "fire": input("fire"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_input_level_is_read_for_what_it_is() {
        // A door contact is a closed circuit while the door is shut.
        assert_eq!(input_meaning("door1_contact", 0), "closed");
        assert_eq!(input_meaning("door1_contact", 1), "open");
        // A request to exit closes its circuit when pressed.
        assert_eq!(input_meaning("rex3", 0), "active");
        assert_eq!(input_meaning("rex3", 1), "idle");
        // The fire input is active when its circuit closes, as the input monitor reads it.
        assert_eq!(input_meaning("fire", 0), "active");
        assert_eq!(input_meaning("fire", 1), "normal");
    }

    #[test]
    fn every_door_state_has_a_word() {
        assert_eq!(lock_word(DoorState::Locked), "locked");
        assert_eq!(lock_word(DoorState::Unlocking), "unlocking");
        assert_eq!(lock_word(DoorState::HeldUnlocked), "held_unlocked");
        assert_eq!(lock_word(DoorState::ForcedLocked), "forced_locked");
        assert_eq!(alarm_word(DoorAlarm::None), None);
        assert_eq!(alarm_word(DoorAlarm::Forced), Some("forced"));
        assert_eq!(alarm_word(DoorAlarm::Held), Some("held"));
    }

    #[test]
    fn the_io_report_lists_every_door_and_only_inputs_that_have_settled() {
        input_settled("door2_contact", 1);
        input_settled("rex2", 1);
        let report = io_report(4);
        assert_eq!(report["doors"].as_array().unwrap().len(), 4);
        assert_eq!(report["doors"][1]["door"], 2);
        assert_eq!(report["doors"][1]["contact"], "open");
        assert_eq!(report["doors"][1]["rex"], "idle");
        assert_eq!(report["doors"][1]["lock"], "locked");
        // An input that has not been read yet is not guessed at.
        assert!(report["doors"][3]["contact"].is_null());
    }
}
