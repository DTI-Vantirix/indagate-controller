use anyhow::{Context, Result, anyhow};
use gpio_cdev::{Chip, LineRequestFlags};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::Duration;

const PCA9534_ADDRESS: i32 = 0x20;
const I2C_SLAVE: libc::c_ulong = 0x0703;

const REG_INPUT: u8 = 0x00;
const REG_OUTPUT: u8 = 0x01;
const REG_POLARITY: u8 = 0x02;
const REG_CONFIG: u8 = 0x03;

const RELAY_MASK: u8 = 0b1111_0000;

/// What to write before the relay lines can be driven directly: the output latch and the
/// configuration register (PCA9534: 1 = input, 0 = output), or `None` when all four relay
/// lines are outputs already and nothing may be touched.
///
/// Only the latches of lines that are still inputs are cleared. Bits 0-3 and the latches
/// of relay lines that are already outputs are preserved.
fn direct_output_setup(config: u8, output: u8) -> Option<(u8, u8)> {
    let still_inputs = config & RELAY_MASK;
    if still_inputs == 0 {
        return None;
    }
    Some((output & !still_inputs, config & !RELAY_MASK))
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum RelayBackend {
    GpioCdev,
    DirectI2c,
}

#[derive(Debug, Serialize)]
pub struct RelayHealth {
    pub available: bool,
    pub backend: Option<RelayBackend>,
    pub i2c_device: String,
    pub address: u8,
    pub gpiochip: Option<String>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct RelayState {
    pub channel: u8,
    pub line: u8,
    pub enabled: bool,
    pub backend: RelayBackend,
}

pub struct RelayController {
    i2c_device: String,
}

impl RelayController {
    pub fn new() -> Self {
        Self {
            i2c_device: "/dev/i2c-2".to_string(),
        }
    }

    fn relay_line(channel: u8) -> Result<u8> {
        match channel {
            0 => Ok(4),
            1 => Ok(5),
            2 => Ok(6),
            3 => Ok(7),
            _ => Err(anyhow!("invalid relay channel {}", channel)),
        }
    }

    fn discover_pca_gpiochip() -> Option<String> {
        let entries = fs::read_dir("/sys/class/gpio").ok()?;

        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().to_string();

            if !name.starts_with("gpiochip") {
                continue;
            }

            let label_path = entry.path().join("label");

            let Ok(label) = fs::read_to_string(label_path) else {
                continue;
            };

            let label = label.trim().to_lowercase();

            if label.contains("pca9534") || label.contains("2-0020") || label.contains("0020") {
                let dev_entries = fs::read_dir("/sys/class/gpio").ok()?;

                // Sysfs base names do not necessarily equal /dev gpiochip
                // numbering, so resolve by label below.
                drop(dev_entries);

                if let Ok(output) = std::process::Command::new("gpiodetect").output() {
                    let text = String::from_utf8_lossy(&output.stdout);

                    for line in text.lines() {
                        if line.to_lowercase().contains("pca9534")
                            || line.to_lowercase().contains("0020")
                        {
                            if let Some(first) = line.split_whitespace().next() {
                                return Some(first.to_string());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub fn health(&self) -> RelayHealth {
        if let Some(chip) = Self::discover_pca_gpiochip() {
            return RelayHealth {
                available: true,
                backend: Some(RelayBackend::GpioCdev),
                i2c_device: self.i2c_device.clone(),
                address: PCA9534_ADDRESS as u8,
                gpiochip: Some(chip),
                detail: "PCA9534 registered with Linux GPIO subsystem".to_string(),
            };
        }

        if Path::new(&self.i2c_device).exists() {
            match self.direct_read_register(REG_CONFIG) {
                Ok(_) => RelayHealth {
                    available: true,
                    backend: Some(RelayBackend::DirectI2c),
                    i2c_device: self.i2c_device.clone(),
                    address: PCA9534_ADDRESS as u8,
                    gpiochip: None,
                    detail: "PCA9534 reachable directly over I2C".to_string(),
                },

                Err(e) => RelayHealth {
                    available: false,
                    backend: None,
                    i2c_device: self.i2c_device.clone(),
                    address: PCA9534_ADDRESS as u8,
                    gpiochip: None,
                    detail: format!("PCA9534 not registered and direct I2C probe failed: {}", e),
                },
            }
        } else {
            RelayHealth {
                available: false,
                backend: None,
                i2c_device: self.i2c_device.clone(),
                address: PCA9534_ADDRESS as u8,
                gpiochip: None,
                detail: format!("{} does not exist", self.i2c_device),
            }
        }
    }

    fn open_i2c(&self) -> Result<std::fs::File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.i2c_device)
            .with_context(|| format!("open {}", self.i2c_device))?;

        let rc = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                I2C_SLAVE,
                PCA9534_ADDRESS as libc::c_ulong,
            )
        };

        if rc < 0 {
            return Err(anyhow!(
                "I2C_SLAVE ioctl failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(file)
    }

    fn direct_read_register(&self, register: u8) -> Result<u8> {
        let mut file = self.open_i2c()?;

        file.write_all(&[register])
            .with_context(|| format!("select PCA9534 register 0x{:02x}", register))?;

        let mut value = [0u8; 1];

        file.read_exact(&mut value)
            .with_context(|| format!("read PCA9534 register 0x{:02x}", register))?;

        Ok(value[0])
    }

    fn direct_write_register(&self, register: u8, value: u8) -> Result<()> {
        let mut file = self.open_i2c()?;

        file.write_all(&[register, value]).with_context(|| {
            format!(
                "write PCA9534 register 0x{:02x} value 0x{:02x}",
                register, value
            )
        })?;

        Ok(())
    }

    fn prepare_direct_outputs(&self) -> Result<()> {
        let config = self.direct_read_register(REG_CONFIG)?;
        let output = self.direct_read_register(REG_OUTPUT)?;

        // Relay lines that are already outputs are left exactly as they are: a relay
        // that is on for one door must not be touched because another door's relay is
        // being set.
        let Some((safe_output, new_config)) = direct_output_setup(config, output) else {
            return Ok(());
        };
        let becoming_outputs = config & RELAY_MASK;

        // SAFETY:
        // Set the output latch LOW for each relay line that is still an input, before
        // making it an output. This prevents a relay from switching on if the power-on
        // output latch is 0xFF.
        if safe_output != output {
            self.direct_write_register(REG_OUTPUT, safe_output)?;
        }

        self.direct_write_register(REG_CONFIG, new_config)?;

        // Verify the lines just made outputs are LOW.
        let verify_output = self.direct_read_register(REG_OUTPUT)?;

        if (verify_output & becoming_outputs) != 0 {
            return Err(anyhow!(
                "unsafe relay initialization: relay bits not low: output=0x{:02x}",
                verify_output
            ));
        }

        Ok(())
    }

    fn direct_set(&self, channel: u8, enabled: bool) -> Result<RelayState> {
        let line = Self::relay_line(channel)?;

        self.prepare_direct_outputs()?;

        let output = self.direct_read_register(REG_OUTPUT)?;

        let mask = 1u8 << line;

        let new_output = if enabled {
            output | mask
        } else {
            output & !mask
        };

        self.direct_write_register(REG_OUTPUT, new_output)?;

        let verify = self.direct_read_register(REG_OUTPUT)?;

        let actual = (verify & mask) != 0;

        if actual != enabled {
            return Err(anyhow!(
                "relay write verification failed: requested={} register=0x{:02x}",
                enabled,
                verify
            ));
        }

        Ok(RelayState {
            channel,
            line,
            enabled: actual,
            backend: RelayBackend::DirectI2c,
        })
    }

    fn cdev_set(&self, chip_name: &str, channel: u8, enabled: bool) -> Result<RelayState> {
        let line = Self::relay_line(channel)?;

        let path = format!("/dev/{}", chip_name);

        let mut chip = Chip::new(&path).with_context(|| format!("open {}", path))?;

        let gpio_line = chip
            .get_line(line as u32)
            .with_context(|| format!("get {} line {}", chip_name, line))?;

        let handle = gpio_line
            .request(
                LineRequestFlags::OUTPUT,
                if enabled { 1 } else { 0 },
                "indagate-relay",
            )
            .context("request relay output")?;

        handle
            .set_value(if enabled { 1 } else { 0 })
            .context("set relay value")?;

        Ok(RelayState {
            channel,
            line,
            enabled,
            backend: RelayBackend::GpioCdev,
        })
    }

    pub fn set(&self, channel: u8, enabled: bool) -> Result<RelayState> {
        let result = match Self::discover_pca_gpiochip() {
            Some(chip) => self.cdev_set(&chip, channel, enabled),
            None => self.direct_set(channel, enabled),
        };
        // What the relays are doing, and whether the chip answered, goes in the check-in.
        match &result {
            Ok(state) => super::live_io::relay_switched(state.channel, state.enabled, state.backend),
            Err(e) => super::live_io::relay_failed(&format!("{e:#}")),
        }
        result
    }

    pub fn pulse(&self, channel: u8, duration_ms: u64) -> Result<()> {
        self.set(channel, true)?;

        thread::sleep(Duration::from_millis(duration_ms));

        self.set(channel, false)?;

        Ok(())
    }

    pub fn dump_registers(&self) -> Result<(u8, u8, u8, u8)> {
        Ok((
            self.direct_read_register(REG_INPUT)?,
            self.direct_read_register(REG_OUTPUT)?,
            self.direct_read_register(REG_POLARITY)?,
            self.direct_read_register(REG_CONFIG)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relays_that_are_already_on_are_left_alone() {
        // All four relay lines are outputs, relay 1 is on: setting another relay must
        // not clear it.
        assert_eq!(direct_output_setup(0b0000_1111, 0b0001_0000), None);
        assert_eq!(direct_output_setup(0b0000_0000, 0b1111_0000), None);
    }

    #[test]
    fn lines_still_inputs_are_made_outputs_with_their_latch_low() {
        // Power-on: everything an input, latches high.
        assert_eq!(direct_output_setup(0xFF, 0xFF), Some((0b0000_1111, 0b0000_1111)));
        // Only relay 4's line is still an input; relay 1 is on and stays on.
        assert_eq!(direct_output_setup(0b1000_0011, 0b1001_0101), Some((0b0001_0101, 0b0000_0011)));
    }
}
