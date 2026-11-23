//! What a reader's light and buzzer are told to do.
//!
//! A reader with light settings shows the state of its door at rest (locked, unlocked,
//! locked down) and the result of each card. A reader without them is left to show
//! whatever it shows on its own between cards, as before these settings existed.
//!
//! The settings arrive in the reader's `configuration` under `lights` and are kept, as
//! sent, in the controller database.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::door_alarm::DoorAlarm;
use super::relay_worker::DoorState;

/// A colour every OSDP reader with a light can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightColor {
    Off,
    Red,
    Green,
    Amber,
    Blue,
}

/// How a resting light is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blink {
    Steady,
    /// A slow flash: the door is locked down.
    Slow,
    /// A quick flash: the door is forced or held open.
    Fast,
}

fn red() -> LightColor {
    LightColor::Red
}
fn green() -> LightColor {
    LightColor::Green
}
fn yes() -> bool {
    true
}

/// One reader's light and buzzer settings. A setting the server leaves out takes the
/// usual value: red while locked, green while unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderLights {
    /// Steady colour while the door is locked.
    #[serde(default = "red")]
    pub locked: LightColor,
    /// Steady colour while the door is held unlocked by a schedule or an operator.
    #[serde(default = "green")]
    pub unlocked: LightColor,
    /// Colour for a granted card, shown for as long as the door stays released.
    #[serde(default = "green")]
    pub granted: LightColor,
    /// Colour flashed for a refused card.
    #[serde(default = "red")]
    pub denied: LightColor,
    /// Colour flashed slowly while the door is locked down (forced locked).
    #[serde(default = "red")]
    pub lockdown: LightColor,
    /// Colour flashed quickly while the door is forced or held open.
    #[serde(default = "red")]
    pub alarm: LightColor,
    #[serde(default = "yes")]
    pub beep_granted: bool,
    #[serde(default = "yes")]
    pub beep_denied: bool,
    /// Whether the buzzer sounds while the door is forced or held open.
    #[serde(default = "yes")]
    pub beep_alarm: bool,
}

impl ReaderLights {
    /// The light settings in a reader's `configuration`, if it has any.
    pub fn from_configuration(configuration: &Value) -> anyhow::Result<Option<Self>> {
        match configuration.get("lights") {
            None | Some(Value::Null) => Ok(None),
            Some(lights) if lights.is_object() => serde_json::from_value(lights.clone())
                .map(Some)
                .map_err(|err| anyhow::anyhow!("reader light settings are not valid: {err}")),
            Some(_) => Err(anyhow::anyhow!("reader light settings are not valid")),
        }
    }

    /// The light a reader rests on: a colour and how it is shown. A door alarm comes
    /// before anything the door is otherwise doing.
    pub fn resting(&self, door: DoorState, alarm: DoorAlarm) -> (LightColor, Blink) {
        if alarm != DoorAlarm::None {
            return (self.alarm, Blink::Fast);
        }
        match door {
            DoorState::Locked => (self.locked, Blink::Steady),
            DoorState::Unlocking => (self.granted, Blink::Steady),
            DoorState::HeldUnlocked => (self.unlocked, Blink::Steady),
            DoorState::ForcedLocked => (self.lockdown, Blink::Slow),
        }
    }

    /// Whether the reader's buzzer sounds for this alarm.
    pub fn sounds(&self, alarm: DoorAlarm) -> bool {
        self.beep_alarm && alarm != DoorAlarm::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_reader_without_light_settings_has_none() {
        assert_eq!(ReaderLights::from_configuration(&json!({ "transport": "rs485" })).unwrap(), None);
        assert_eq!(ReaderLights::from_configuration(&json!({ "lights": null })).unwrap(), None);
    }

    #[test]
    fn settings_left_out_take_the_usual_values() {
        let lights = ReaderLights::from_configuration(&json!({ "lights": {} })).unwrap().unwrap();
        assert_eq!(lights.locked, LightColor::Red);
        assert_eq!(lights.unlocked, LightColor::Green);
        assert_eq!(lights.granted, LightColor::Green);
        assert_eq!(lights.denied, LightColor::Red);
        assert!(lights.beep_granted && lights.beep_denied);
    }

    #[test]
    fn settings_are_read_as_sent_and_bad_ones_refused() {
        let lights = ReaderLights::from_configuration(&json!({ "lights": {
            "locked": "off", "unlocked": "blue", "granted": "amber", "denied": "red", "lockdown": "amber",
            "beep_granted": false, "beep_denied": true, "added_later": 1
        } }))
        .unwrap()
        .unwrap();
        assert_eq!(lights.locked, LightColor::Off);
        assert_eq!(lights.unlocked, LightColor::Blue);
        assert_eq!(lights.granted, LightColor::Amber);
        assert!(!lights.beep_granted);
        assert!(ReaderLights::from_configuration(&json!({ "lights": { "locked": "purple" } })).is_err());
        assert!(ReaderLights::from_configuration(&json!({ "lights": "red" })).is_err());
    }

    #[test]
    fn the_resting_light_follows_the_door() {
        let lights = ReaderLights::from_configuration(&json!({ "lights": { "granted": "blue", "lockdown": "amber" } })).unwrap().unwrap();
        let quiet = DoorAlarm::None;
        assert_eq!(lights.resting(DoorState::Locked, quiet), (LightColor::Red, Blink::Steady));
        assert_eq!(lights.resting(DoorState::Unlocking, quiet), (LightColor::Blue, Blink::Steady));
        assert_eq!(lights.resting(DoorState::HeldUnlocked, quiet), (LightColor::Green, Blink::Steady));
        assert_eq!(lights.resting(DoorState::ForcedLocked, quiet), (LightColor::Amber, Blink::Slow));
    }

    #[test]
    fn a_door_alarm_comes_before_the_doors_state() {
        let lights = ReaderLights::from_configuration(&json!({ "lights": { "alarm": "amber" } })).unwrap().unwrap();
        for alarm in [DoorAlarm::Forced, DoorAlarm::Held] {
            assert_eq!(lights.resting(DoorState::Locked, alarm), (LightColor::Amber, Blink::Fast));
            assert_eq!(lights.resting(DoorState::Unlocking, alarm), (LightColor::Amber, Blink::Fast));
            assert!(lights.sounds(alarm));
        }
        assert!(!lights.sounds(DoorAlarm::None));
        let silent = ReaderLights::from_configuration(&json!({ "lights": { "beep_alarm": false } })).unwrap().unwrap();
        assert!(!silent.sounds(DoorAlarm::Forced));
        // Settings from before alarms existed take the usual values.
        assert_eq!(silent.alarm, LightColor::Red);
    }
}
