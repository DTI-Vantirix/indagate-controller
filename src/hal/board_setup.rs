//! Getting the board's lines ready before anything uses them.
//!
//! The controller reads its inputs (door contacts, requests to exit, the fire input and the
//! Wiegand data lines) through the kernel's sysfs GPIO files, and reaches its relay chip
//! over an I2C bus that only works once the board's I/O enable line is driven high. None
//! of that is in place after a power-up. The board maker's own application used to do it
//! as it started, and for a long time this controller ran on what that application had
//! left behind from the last boot: after a reboot without it, no input could be read and
//! no relay could be switched.
//!
//! So the controller now does it itself, every time it starts, and depends on nothing
//! else having run first:
//!
//! 1. the I/O enable line is made an output and driven high, and the bus is given a
//!    moment to come up;
//! 2. the Wiegand reader light lines are made outputs and driven high, the state they
//!    rest in;
//! 3. every input line is exported and made an input.
//!
//! A line that is already as it should be is left alone. A line that cannot be prepared
//! is reported and the rest carry on: the parts of the controller that use it report it
//! again in their own terms.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use super::profile::{BoardProfile, GpioLine};

const SYSFS_GPIO: &str = "/sys/class/gpio";
/// How long a line may take to appear after it is asked for.
const EXPORT_WAIT: Duration = Duration::from_millis(500);
/// How long the I/O bus is given to come up after its enable line goes high.
const BUS_SETTLE: Duration = Duration::from_millis(300);

/// The number the sysfs files know a line by: 32 lines to a chip.
fn sysfs_number(line: &GpioLine) -> Option<u32> {
    let chip = line.chip.strip_prefix("gpiochip")?.parse::<u32>().ok()?;
    Some(chip * 32 + line.line)
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|text| text.trim().to_string())
}

/// Make sure the line has its sysfs folder, asking the kernel for it if it has not.
fn export(root: &Path, gpio: u32, wait: Duration) -> Result<(), String> {
    let folder = root.join(format!("gpio{gpio}"));
    if folder.exists() {
        return Ok(());
    }
    fs::write(root.join("export"), gpio.to_string()).map_err(|e| format!("GPIO {gpio}: export refused: {e}"))?;
    let asked = Instant::now();
    while !folder.join("direction").exists() {
        if asked.elapsed() >= wait {
            return Err(format!("GPIO {gpio}: did not appear after being exported"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn make_input(root: &Path, gpio: u32, wait: Duration) -> Result<(), String> {
    export(root, gpio, wait)?;
    let direction = root.join(format!("gpio{gpio}/direction"));
    if read_trimmed(&direction).as_deref() != Some("in") {
        fs::write(&direction, "in").map_err(|e| format!("GPIO {gpio}: cannot be made an input: {e}"))?;
    }
    Ok(())
}

fn drive_high(root: &Path, gpio: u32, wait: Duration) -> Result<(), String> {
    export(root, gpio, wait)?;
    let folder = root.join(format!("gpio{gpio}"));
    if read_trimmed(&folder.join("direction")).as_deref() != Some("out") {
        // "high" makes the line an output that starts high, with no low moment between.
        return fs::write(folder.join("direction"), "high").map_err(|e| format!("GPIO {gpio}: cannot be driven high: {e}"));
    }
    if read_trimmed(&folder.join("value")).as_deref() != Some("1") {
        fs::write(folder.join("value"), "1").map_err(|e| format!("GPIO {gpio}: cannot be driven high: {e}"))?;
    }
    Ok(())
}

/// The lines to drive high first (the I/O enable), the other lines to drive high (the
/// reader lights), and the lines to read, as sysfs numbers.
fn plan(profile: &BoardProfile) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let enable = profile.io_enable.iter().filter_map(sysfs_number).collect();
    let lights = profile.readers.iter().filter_map(|reader| sysfs_number(&reader.led)).collect();
    let mut inputs: Vec<u32> = Vec::new();
    for door in &profile.doors {
        inputs.extend(sysfs_number(&door.rex));
        inputs.extend(sysfs_number(&door.contact));
    }
    inputs.extend(sysfs_number(&profile.fire));
    for reader in &profile.readers {
        inputs.extend(sysfs_number(&reader.d0));
        inputs.extend(sysfs_number(&reader.d1));
    }
    (enable, lights, inputs)
}

fn prepare_at(root: &Path, profile: &BoardProfile, wait: Duration, settle: Duration) -> Vec<String> {
    let (enable, lights, inputs) = plan(profile);
    let mut problems = Vec::new();
    for gpio in &enable {
        problems.extend(drive_high(root, *gpio, wait).err());
    }
    if !enable.is_empty() {
        std::thread::sleep(settle);
    }
    for gpio in &lights {
        problems.extend(drive_high(root, *gpio, wait).err());
    }
    for gpio in &inputs {
        problems.extend(make_input(root, *gpio, wait).err());
    }
    problems
}

/// Prepare the board's lines. Call once, before the relays or inputs are used.
pub fn prepare(profile: &BoardProfile) {
    let problems = prepare_at(Path::new(SYSFS_GPIO), profile, EXPORT_WAIT, BUS_SETTLE);
    if problems.is_empty() {
        tracing::info!(target: "indagate_board", "Board lines prepared");
    }
    for problem in problems {
        tracing::error!(target: "indagate_board", problem = %problem, "A board line could not be prepared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the sysfs GPIO folder, with the given lines already present.
    fn sysfs_with(lines: &[(u32, &str, &str)]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("indagate-board-setup-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("export"), "").unwrap();
        for (gpio, direction, value) in lines {
            let folder = root.join(format!("gpio{gpio}"));
            fs::create_dir_all(&folder).unwrap();
            fs::write(folder.join("direction"), direction).unwrap();
            fs::write(folder.join("value"), value).unwrap();
        }
        root
    }

    const SHORT: Duration = Duration::from_millis(30);

    #[test]
    fn the_board_profile_names_every_line_the_board_needs() {
        let (enable, lights, inputs) = plan(&crate::hal::profile::acp4wr6_r1());
        assert_eq!(enable, vec![6], "the I/O enable line");
        assert_eq!(lights, vec![45, 49, 47, 48], "the four reader light lines");
        // Exit request then contact for each door, the fire input, then D0 and D1 of each reader.
        assert_eq!(inputs, vec![141, 140, 1, 8, 14, 156, 118, 157, 117, 119, 121, 122, 15, 138, 154, 155, 139]);
    }

    #[test]
    fn lines_already_present_are_set_the_right_way_round() {
        let root = sysfs_with(&[(6, "in", "0"), (140, "out", "0"), (141, "in", "1")]);
        assert_eq!(drive_high(&root, 6, SHORT), Ok(()));
        assert_eq!(fs::read_to_string(root.join("gpio6/direction")).unwrap(), "high");
        assert_eq!(make_input(&root, 140, SHORT), Ok(()));
        assert_eq!(fs::read_to_string(root.join("gpio140/direction")).unwrap(), "in");
        // Already an input: nothing is written.
        assert_eq!(make_input(&root, 141, SHORT), Ok(()));
        assert_eq!(fs::read_to_string(root.join("gpio141/direction")).unwrap(), "in");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_output_that_is_low_is_raised_without_changing_its_direction() {
        let root = sysfs_with(&[(6, "out", "0"), (45, "out", "1")]);
        assert_eq!(drive_high(&root, 6, SHORT), Ok(()));
        assert_eq!(fs::read_to_string(root.join("gpio6/direction")).unwrap(), "out");
        assert_eq!(fs::read_to_string(root.join("gpio6/value")).unwrap(), "1");
        assert_eq!(drive_high(&root, 45, SHORT), Ok(()));
        assert_eq!(fs::read_to_string(root.join("gpio45/value")).unwrap(), "1", "left as it was");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_line_is_asked_for_and_reported_if_it_never_appears() {
        let root = sysfs_with(&[]);
        let problem = make_input(&root, 117, SHORT).unwrap_err();
        assert!(problem.contains("117"), "{problem}");
        assert_eq!(fs::read_to_string(root.join("export")).unwrap(), "117", "the kernel was asked for it");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn one_line_that_cannot_be_prepared_does_not_stop_the_rest() {
        // Everything is present except the fire input.
        let present: Vec<(u32, &str, &str)> = [6, 45, 49, 47, 48, 141, 140, 1, 8, 14, 156, 118, 157, 119, 121, 122, 15, 138, 154, 155, 139]
            .iter()
            .map(|gpio| (*gpio, "in", "0"))
            .collect();
        let root = sysfs_with(&present);
        let problems = prepare_at(&root, &crate::hal::profile::acp4wr6_r1(), SHORT, Duration::ZERO);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("117"));
        assert_eq!(fs::read_to_string(root.join("gpio6/direction")).unwrap(), "high");
        assert_eq!(fs::read_to_string(root.join("gpio139/direction")).unwrap(), "in");
        let _ = fs::remove_dir_all(root);
    }
}
