use anyhow::{Context, Result, anyhow};
use std::process::Command;

const NM_SERVICE: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const WIFI_IFACE: &str = "wlan0";

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {}", program))?;

    if !output.status.success() {
        return Err(anyhow!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn validate_object_path(path: &str) -> Result<()> {
    if !path.starts_with('/') || path == "/" {
        return Err(anyhow!("invalid D-Bus object path"));
    }

    if path
        .split('/')
        .skip(1)
        .any(|part| part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return Err(anyhow!("invalid D-Bus object path"));
    }

    Ok(())
}

fn parse_object_path(output: &str) -> Result<String> {
    let path = output
        .strip_prefix("o ")
        .ok_or_else(|| anyhow!("unexpected D-Bus response"))?
        .trim()
        .trim_matches('"');

    validate_object_path(path)?;

    Ok(path.to_string())
}

fn busctl_call(method: &str, signature: &str, args: &[&str]) -> Result<String> {
    let mut command_args = vec![
        "--system", "call", NM_SERVICE, NM_PATH, NM_SERVICE, method, signature,
    ];

    command_args.extend_from_slice(args);

    run("busctl", &command_args)
}

fn wifi_device_path() -> Result<String> {
    let output = run(
        "nmcli",
        &["-g", "GENERAL.DBUS-PATH", "device", "show", WIFI_IFACE],
    )?;

    validate_object_path(&output)?;

    if !output.starts_with("/org/freedesktop/NetworkManager/Devices/") {
        return Err(anyhow!("unexpected Wi-Fi device object path"));
    }

    Ok(output)
}

fn validate_checkpoint_path(path: &str) -> Result<()> {
    validate_object_path(path)?;

    let prefix = "/org/freedesktop/NetworkManager/Checkpoint/";

    let id = path
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow!("invalid checkpoint path"))?;

    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("invalid checkpoint identifier"));
    }

    Ok(())
}

fn validate_rollback_response(response: &str) -> Result<()> {
    let fields: Vec<&str> = response.split_whitespace().collect();

    if fields.len() < 2 || fields[0] != "a{su}" {
        return Err(anyhow!("invalid rollback response"));
    }

    let count: usize = fields[1].parse()?;

    if count == 0 {
        return Err(anyhow!("rollback returned no device results"));
    }

    if fields.len() != 2 + count * 2 {
        return Err(anyhow!("unexpected rollback result count"));
    }

    for entry in fields[2..].chunks_exact(2) {
        let device = entry[0].trim_matches('"');
        let status: u32 = entry[1].parse()?;

        // NetworkManager may return the interface name as the dictionary key.
        // Accept only the target Wi-Fi device or a validated device object path.
        if device != "wlan0" {
            validate_object_path(device)?;
            if !device.starts_with("/org/freedesktop/NetworkManager/Devices/") {
                return Err(anyhow!("rollback response contains unexpected device"));
            }
        }

        if status != 0 {
            return Err(anyhow!(
                "network rollback failed for {} with status {}",
                device,
                status
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct NetworkCheckpoint {
    pub path: String,
}

impl NetworkCheckpoint {
    pub fn create(timeout_seconds: u32) -> Result<Self> {
        if !(30..=600).contains(&timeout_seconds) {
            return Err(anyhow!(
                "checkpoint timeout must be between 30 and 600 seconds"
            ));
        }

        let device = wifi_device_path()?;
        let timeout = timeout_seconds.to_string();

        let response = busctl_call("CheckpointCreate", "aouu", &["1", &device, &timeout, "0"])?;

        let path = parse_object_path(&response)?;

        if !path.starts_with("/org/freedesktop/NetworkManager/Checkpoint/") {
            return Err(anyhow!("unexpected checkpoint object path"));
        }

        Ok(Self { path })
    }

    pub fn confirm(&self) -> Result<()> {
        validate_checkpoint_path(&self.path)?;

        busctl_call("CheckpointDestroy", "o", &[&self.path])?;

        Ok(())
    }

    pub fn rollback(&self) -> Result<()> {
        validate_checkpoint_path(&self.path)?;

        let response = busctl_call("CheckpointRollback", "o", &[&self.path])?;

        validate_rollback_response(&response)?;

        Ok(())
    }

    pub fn extend_timeout(&self, timeout_seconds: u32) -> Result<()> {
        validate_checkpoint_path(&self.path)?;

        if !(30..=600).contains(&timeout_seconds) {
            return Err(anyhow!("invalid rollback timeout"));
        }

        let timeout = timeout_seconds.to_string();

        busctl_call(
            "CheckpointAdjustRollbackTimeout",
            "ou",
            &[&self.path, &timeout],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_successful_rollback() {
        assert!(
            validate_rollback_response(r#"a{su} 1 "/org/freedesktop/NetworkManager/Devices/4" 0"#)
                .is_ok()
        );
    }

    #[test]
    fn accepts_interface_name_rollback_response() {
        assert!(validate_rollback_response(r#"a{su} 1 "wlan0" 0"#).is_ok());
    }

    #[test]
    fn rejects_other_interface_rollback_response() {
        assert!(validate_rollback_response(r#"a{su} 1 "eth0" 0"#).is_err());
    }

    #[test]
    fn rejects_failed_rollback() {
        assert!(
            validate_rollback_response(r#"a{su} 1 "/org/freedesktop/NetworkManager/Devices/4" 1"#)
                .is_err()
        );
    }

    #[test]
    fn rejects_disconnected_device_rollback() {
        assert!(
            validate_rollback_response(r#"a{su} 1 "/org/freedesktop/NetworkManager/Devices/4" 2"#)
                .is_err()
        );
    }

    #[test]
    fn rejects_rollback_result_for_unexpected_object() {
        assert!(
            validate_rollback_response(
                r#"a{su} 1 "/org/freedesktop/NetworkManager/Checkpoint/1" 0"#
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_empty_rollback_results() {
        assert!(validate_rollback_response("a{su} 0").is_err());
    }

    #[test]
    fn rejects_malformed_rollback_results() {
        assert!(
            validate_rollback_response(r#"a{su} 2 "/org/freedesktop/NetworkManager/Devices/4" 0"#)
                .is_err()
        );

        assert!(validate_rollback_response("unexpected response").is_err());
    }

    #[test]
    fn validates_checkpoint_object_paths() {
        assert!(validate_checkpoint_path("/org/freedesktop/NetworkManager/Checkpoint/1").is_ok());

        assert!(validate_checkpoint_path("/org/freedesktop/NetworkManager/Devices/4").is_err());

        assert!(
            validate_checkpoint_path("/org/freedesktop/NetworkManager/Checkpoint/abc").is_err()
        );
    }

    #[test]
    fn parses_checkpoint_response() {
        let path =
            parse_object_path(r#"o "/org/freedesktop/NetworkManager/Checkpoint/1""#).unwrap();

        assert_eq!(path, "/org/freedesktop/NetworkManager/Checkpoint/1");
    }

    #[test]
    fn rejects_invalid_checkpoint_response() {
        assert!(parse_object_path("invalid response").is_err());
    }

    #[test]
    fn rejects_invalid_object_path() {
        assert!(validate_object_path("not/a/path").is_err());
        assert!(validate_object_path("/bad//path").is_err());
        assert!(validate_object_path("/bad/path;command").is_err());
    }

    #[test]
    fn accepts_valid_object_path() {
        assert!(validate_object_path("/org/freedesktop/NetworkManager/Devices/4").is_ok());
    }
}
