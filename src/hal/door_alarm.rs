//! Door alarms: a door forced open, and a door held open too long.
//!
//! * **Forced**: the door contact opens while the door is locked and nothing has released
//!   it: no card, no request to exit, no remote unlock, no schedule.
//! * **Held**: the door has stayed open longer than its allowed time. A door held unlocked
//!   by a schedule or an operator is expected to stand open and does not count.
//!
//! Both are off unless the door's settings turn them on, so a door with no contact fitted
//! raises nothing. An alarm ends when the door closes.
//!
//! The input monitor feeds a `DoorWatch` per door and records the events; the alarm each
//! door is in is published here for anything that shows it (a reader's light and buzzer).

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use super::relay_worker::DoorState;

/// The alarm a door is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DoorAlarm {
    #[default]
    None,
    Forced,
    Held,
}

/// What a door's settings ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AlarmSettings {
    /// Raise an alarm when the door opens while locked.
    pub forced_open: bool,
    /// Raise an alarm when the door has been open this long. Zero: never.
    pub held_open_seconds: u32,
}

/// The alarm each door is in, as the input monitor last left it.
static ALARMS: [AtomicU8; 4] = [const { AtomicU8::new(0) }; 4];

/// The alarm door `channel` is in right now.
pub fn door_alarm(channel: u8) -> DoorAlarm {
    match ALARMS.get(usize::from(channel)).map(|alarm| alarm.load(Ordering::Relaxed)) {
        Some(1) => DoorAlarm::Forced,
        Some(2) => DoorAlarm::Held,
        _ => DoorAlarm::None,
    }
}

fn publish(channel: u8, alarm: DoorAlarm) {
    if let Some(slot) = ALARMS.get(usize::from(channel)) {
        slot.store(
            match alarm {
                DoorAlarm::None => 0,
                DoorAlarm::Forced => 1,
                DoorAlarm::Held => 2,
            },
            Ordering::Relaxed,
        );
    }
}

/// One door being watched. Each method returns the event to record, if there is one:
/// `door_forced`, `door_held`, or `door_alarm_cleared`.
#[derive(Debug, Default)]
pub struct DoorWatch {
    open_since: Option<Instant>,
    alarm: DoorAlarm,
}

impl DoorWatch {
    /// The door as it is found when the controller starts. A door that is already open is
    /// not counted as forced: nobody saw it open.
    pub fn start(&mut self, open: bool, now: Instant) {
        self.open_since = open.then_some(now);
        self.alarm = DoorAlarm::None;
    }

    /// The door contact changed. `state` is what the door was doing just before.
    pub fn contact(&mut self, open: bool, state: DoorState, settings: AlarmSettings, now: Instant) -> Option<&'static str> {
        if !open {
            self.open_since = None;
            if self.alarm == DoorAlarm::None {
                return None;
            }
            self.alarm = DoorAlarm::None;
            return Some("door_alarm_cleared");
        }
        self.open_since = Some(now);
        let locked = matches!(state, DoorState::Locked | DoorState::ForcedLocked);
        if settings.forced_open && locked && self.alarm == DoorAlarm::None {
            self.alarm = DoorAlarm::Forced;
            return Some("door_forced");
        }
        None
    }

    /// Time has passed. `state` is what the door is doing now.
    pub fn tick(&mut self, state: DoorState, settings: AlarmSettings, now: Instant) -> Option<&'static str> {
        let since = self.open_since?;
        if self.alarm == DoorAlarm::Held || settings.held_open_seconds == 0 || state == DoorState::HeldUnlocked {
            return None;
        }
        if now.saturating_duration_since(since) < Duration::from_secs(u64::from(settings.held_open_seconds)) {
            return None;
        }
        self.alarm = DoorAlarm::Held;
        Some("door_held")
    }

    /// Make the door's alarm known to whatever shows it.
    pub fn publish(&self, channel: u8) {
        publish(channel, self.alarm);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: AlarmSettings = AlarmSettings { forced_open: true, held_open_seconds: 30 };

    fn at(start: Instant, seconds: u64) -> Instant {
        start + Duration::from_secs(seconds)
    }

    #[test]
    fn a_door_opened_while_locked_is_forced_until_it_closes() {
        let start = Instant::now();
        let mut door = DoorWatch::default();
        assert_eq!(door.contact(true, DoorState::Locked, BOTH, start), Some("door_forced"));
        assert_eq!(door.alarm, DoorAlarm::Forced);
        assert_eq!(door.contact(false, DoorState::Locked, BOTH, at(start, 5)), Some("door_alarm_cleared"));
        assert_eq!(door.alarm, DoorAlarm::None);
        // A locked-down door that opens is forced as well.
        assert_eq!(door.contact(true, DoorState::ForcedLocked, BOTH, at(start, 6)), Some("door_forced"));
    }

    #[test]
    fn a_door_opened_after_being_released_is_not_forced() {
        let start = Instant::now();
        for released in [DoorState::Unlocking, DoorState::HeldUnlocked] {
            let mut door = DoorWatch::default();
            assert_eq!(door.contact(true, released, BOTH, start), None);
            assert_eq!(door.contact(false, DoorState::Locked, BOTH, at(start, 5)), None, "nothing to clear");
        }
    }

    #[test]
    fn a_door_left_open_is_held_once_its_time_is_up() {
        let start = Instant::now();
        let mut door = DoorWatch::default();
        assert_eq!(door.contact(true, DoorState::Unlocking, BOTH, start), None);
        assert_eq!(door.tick(DoorState::Locked, BOTH, at(start, 29)), None);
        assert_eq!(door.tick(DoorState::Locked, BOTH, at(start, 30)), Some("door_held"));
        assert_eq!(door.tick(DoorState::Locked, BOTH, at(start, 90)), None, "recorded once");
        assert_eq!(door.contact(false, DoorState::Locked, BOTH, at(start, 95)), Some("door_alarm_cleared"));
        assert_eq!(door.tick(DoorState::Locked, BOTH, at(start, 200)), None, "a closed door is not held");
    }

    #[test]
    fn a_door_held_unlocked_may_stand_open() {
        let start = Instant::now();
        let mut door = DoorWatch::default();
        assert_eq!(door.contact(true, DoorState::HeldUnlocked, BOTH, start), None);
        assert_eq!(door.tick(DoorState::HeldUnlocked, BOTH, at(start, 600)), None);
        // The schedule ends with the door still open: now it is held.
        assert_eq!(door.tick(DoorState::Locked, BOTH, at(start, 601)), Some("door_held"));
    }

    #[test]
    fn alarms_are_off_unless_the_door_asks_for_them() {
        let start = Instant::now();
        let off = AlarmSettings::default();
        let mut door = DoorWatch::default();
        assert_eq!(door.contact(true, DoorState::Locked, off, start), None);
        assert_eq!(door.tick(DoorState::Locked, off, at(start, 3600)), None);
        assert_eq!(door.contact(false, DoorState::Locked, off, at(start, 3601)), None);
    }

    #[test]
    fn a_door_found_open_at_start_is_not_forced_but_can_be_held() {
        let start = Instant::now();
        let mut door = DoorWatch::default();
        door.start(true, start);
        assert_eq!(door.alarm, DoorAlarm::None);
        assert_eq!(door.tick(DoorState::Locked, BOTH, at(start, 30)), Some("door_held"));
    }

    #[test]
    fn a_forced_door_left_open_becomes_held() {
        let start = Instant::now();
        let mut door = DoorWatch::default();
        assert_eq!(door.contact(true, DoorState::Locked, BOTH, start), Some("door_forced"));
        assert_eq!(door.tick(DoorState::Locked, BOTH, at(start, 30)), Some("door_held"));
        assert_eq!(door.contact(false, DoorState::Locked, BOTH, at(start, 31)), Some("door_alarm_cleared"));
    }
}
