use gpio_cdev::{Chip, LineRequestFlags};
use serde::Serialize;
use std::fs;

use super::profile::{BoardProfile, GpioLine};

#[derive(Debug, Serialize)]
pub struct InputSample {
    pub name: String,
    pub channel: Option<u8>,
    pub chip: String,
    pub line: u32,
    pub legacy_gpio: Option<u32>,
    pub raw_value: Option<u8>,
    pub circuit_state: String,
    pub access_method: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InputSnapshot {
    pub doors: Vec<InputSample>,
    pub rex: Vec<InputSample>,
    pub fire: InputSample,
}

fn chip_index(chip: &str) -> Option<u32> {
    chip.strip_prefix("gpiochip")?.parse::<u32>().ok()
}

fn legacy_gpio(line: &GpioLine) -> Option<u32> {
    chip_index(line.chip).map(|index| (index * 32) + line.line)
}

fn interpret_raw(raw: u8) -> String {
    match raw {
        0 => "circuit_closed".to_string(),
        1 => "circuit_open".to_string(),
        _ => "unknown".to_string(),
    }
}

fn read_via_cdev(line: &GpioLine) -> Result<u8, String> {
    let device = format!("/dev/{}", line.chip);

    let mut chip = Chip::new(&device).map_err(|e| format!("open {} failed: {}", device, e))?;

    let gpio_line = chip
        .get_line(line.line)
        .map_err(|e| format!("get line {} failed: {}", line.line, e))?;

    let handle = gpio_line
        .request(LineRequestFlags::INPUT, 0, "indagate-observe")
        .map_err(|e| format!("request input failed: {}", e))?;

    handle
        .get_value()
        .map_err(|e| format!("read failed: {}", e))
}

fn read_via_sysfs(line: &GpioLine) -> Result<u8, String> {
    let legacy = legacy_gpio(line).ok_or_else(|| "unable to derive legacy gpio".to_string())?;

    let path = format!("/sys/class/gpio/gpio{}/value", legacy);

    let value = fs::read_to_string(&path).map_err(|e| format!("read {} failed: {}", path, e))?;

    match value.trim() {
        "0" => Ok(0),
        "1" => Ok(1),
        other => Err(format!("unexpected GPIO value: {}", other)),
    }
}

fn sample(name: String, channel: Option<u8>, line: &GpioLine) -> InputSample {
    let legacy = legacy_gpio(line);

    match read_via_cdev(line) {
        Ok(raw) => InputSample {
            name,
            channel,
            chip: line.chip.to_string(),
            line: line.line,
            legacy_gpio: legacy,
            raw_value: Some(raw),
            circuit_state: interpret_raw(raw),
            access_method: "gpio-cdev".to_string(),
            error: None,
        },

        Err(cdev_error) => match read_via_sysfs(line) {
            Ok(raw) => InputSample {
                name,
                channel,
                chip: line.chip.to_string(),
                line: line.line,
                legacy_gpio: legacy,
                raw_value: Some(raw),
                circuit_state: interpret_raw(raw),
                access_method: "sysfs-readonly-fallback".to_string(),
                error: Some(format!(
                    "cdev unavailable while SightPAS may own line: {}",
                    cdev_error
                )),
            },

            Err(sysfs_error) => InputSample {
                name,
                channel,
                chip: line.chip.to_string(),
                line: line.line,
                legacy_gpio: legacy,
                raw_value: None,
                circuit_state: "unavailable".to_string(),
                access_method: "none".to_string(),
                error: Some(format!("cdev: {}; sysfs: {}", cdev_error, sysfs_error)),
            },
        },
    }
}

pub fn snapshot(profile: &BoardProfile) -> InputSnapshot {
    let doors = profile
        .doors
        .iter()
        .map(|door| {
            sample(
                format!("door{}_contact", door.channel + 1),
                Some(door.channel),
                &door.contact,
            )
        })
        .collect();

    let rex = profile
        .doors
        .iter()
        .map(|door| {
            sample(
                format!("rex{}", door.channel + 1),
                Some(door.channel),
                &door.rex,
            )
        })
        .collect();

    let fire = sample("fire".to_string(), None, &profile.fire);

    InputSnapshot { doors, rex, fire }
}
