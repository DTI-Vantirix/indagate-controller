use serde::Serialize;
use std::fs;
use std::path::Path;

use super::relay::RelayController;

#[derive(Debug, Serialize)]
pub struct GpioChipStatus {
    pub cdev_name: String,
    pub cdev_path: String,
    pub exists: bool,
    pub label: Option<String>,
    pub sysfs_base: Option<u32>,
    pub ngpio: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SerialStatus {
    pub device: &'static str,
    pub exists: bool,
}

#[derive(Debug, Serialize)]
pub struct HardwareHealth {
    pub gpiochips: Vec<GpioChipStatus>,
    pub relays: serde_json::Value,
    pub rs485: SerialStatus,
}

fn read_trimmed<P: AsRef<Path>>(path: P) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn expected_gpiochips() -> Vec<(&'static str, &'static str, u32)> {
    vec![
        ("gpiochip0", "30200000.gpio", 0),
        ("gpiochip1", "30210000.gpio", 32),
        ("gpiochip2", "30220000.gpio", 64),
        ("gpiochip3", "30230000.gpio", 96),
        ("gpiochip4", "30240000.gpio", 128),
    ]
}

fn inspect_gpiochip(cdev_name: &str, expected_label: &str, sysfs_base: u32) -> GpioChipStatus {
    let cdev_path = format!("/dev/{}", cdev_name);

    let sysfs_path = format!("/sys/class/gpio/gpiochip{}", sysfs_base);

    let cdev_exists = Path::new(&cdev_path).exists();

    let sysfs_exists = Path::new(&sysfs_path).exists();

    let label = if sysfs_exists {
        read_trimmed(format!("{}/label", sysfs_path))
    } else {
        None
    };

    let ngpio = if sysfs_exists {
        read_trimmed(format!("{}/ngpio", sysfs_path)).and_then(|v| v.parse::<u32>().ok())
    } else {
        None
    };

    let base = if sysfs_exists {
        read_trimmed(format!("{}/base", sysfs_path)).and_then(|v| v.parse::<u32>().ok())
    } else {
        None
    };

    let label_matches = label
        .as_deref()
        .map(|value| value == expected_label)
        .unwrap_or(false);

    GpioChipStatus {
        cdev_name: cdev_name.to_string(),

        cdev_path,

        exists: cdev_exists && sysfs_exists && label_matches,

        label,

        sysfs_base: base,

        ngpio,
    }
}

pub fn inspect() -> HardwareHealth {
    let gpiochips = expected_gpiochips()
        .into_iter()
        .map(|(name, label, base)| inspect_gpiochip(name, label, base))
        .collect::<Vec<_>>();

    let relay = RelayController::new();

    let relays = serde_json::to_value(relay.health()).unwrap_or_else(|_| {
        serde_json::json!({
            "available": false,
            "detail":
                "relay health serialization failed"
        })
    });

    let rs485_device = "/dev/ttymxc0";

    HardwareHealth {
        gpiochips,

        relays,

        rs485: SerialStatus {
            device: rs485_device,
            exists: Path::new(rs485_device).exists(),
        },
    }
}
