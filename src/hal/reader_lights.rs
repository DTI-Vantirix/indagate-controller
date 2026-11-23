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
    #[serde(default = "yes")]
    pub beep_granted: bool,
    #[serde(default = "yes")]
    pub beep_denied: bool,
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

    /// The light a reader rests on for its door's state: a colour, and whether it flashes.
    pub fn resting(&self, door: DoorState) -> (LightColor, bool) {
        match door {
            DoorState::Locked => (self.locked, false),
            DoorState::Unlocking => (self.granted, false),
            DoorState::HeldUnlocked => (self.unlocked, false),
            DoorState::ForcedLocked => (self.lockdown, true),
        }
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
        assert_eq!(lights.resting(DoorState::Locked), (LightColor::Red, false));
        assert_eq!(lights.resting(DoorState::Unlocking), (LightColor::Blue, false));
        assert_eq!(lights.resting(DoorState::HeldUnlocked), (LightColor::Green, false));
        assert_eq!(lights.resting(DoorState::ForcedLocked), (LightColor::Amber, true));
    }
}
