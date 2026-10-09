use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::process::Command;

const WIFI_IFACE: &str = "wlan0";

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {}", program))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

        return Err(anyhow!(
            "{} failed: {}",
            program,
            if !stderr.is_empty() { stderr } else { stdout }
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn nmcli(args: &[&str]) -> Result<String> {
    run("nmcli", args)
}

fn split_nmcli_terse(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            ':' => {
                fields.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if escaped {
        current.push('\\');
    }

    fields.push(current);
    fields
}

fn wifi_device_row() -> Result<Option<Value>> {
    let output = nmcli(&[
        "-t",
        "-f",
        "DEVICE,TYPE,STATE,CONNECTION",
        "device",
        "status",
    ])?;

    for line in output.lines() {
        let parts = split_nmcli_terse(line);

        if parts.len() < 4 {
            continue;
        }

        let device = &parts[0];
        let device_type = &parts[1];
        let state = &parts[2];
        let connection = &parts[3];

        if device == WIFI_IFACE {
            return Ok(Some(json!({
                "interface": device,
                "type": device_type,
                "state": state,
                "connection": if connection.is_empty() { Value::Null } else { json!(connection) }
            })));
        }
    }

    Ok(None)
}

fn current_wifi_details() -> Value {
    let mut ssid: Option<String> = None;
    let mut signal_dbm: Option<i64> = None;

    if let Ok(output) = run("iw", &["dev", WIFI_IFACE, "link"]) {
        for line in output.lines() {
            let trimmed = line.trim();

            if let Some(value) = trimmed.strip_prefix("SSID:") {
                ssid = Some(value.trim().to_string());
            }

            if let Some(value) = trimmed.strip_prefix("signal:") {
                signal_dbm = value
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<i64>().ok());
            }
        }
    }

    json!({
        "ssid": ssid,
        "signal_dbm": signal_dbm
    })
}

pub fn wifi_status() -> Result<Value> {
    let radio = nmcli(&["radio", "wifi"])?;
    let device = wifi_device_row()?;
    let details = current_wifi_details();

    Ok(json!({
        "interface": WIFI_IFACE,
        "radio": radio,
        "device": device,
        "ssid": details["ssid"],
        "signal_dbm": details["signal_dbm"]
    }))
}

pub fn wifi_radio_enable() -> Result<Value> {
    nmcli(&["radio", "wifi", "on"])?;

    Ok(json!({
        "interface": WIFI_IFACE,
        "radio": "enabled"
    }))
}

pub fn wifi_scan() -> Result<Value> {
    let _ = nmcli(&["device", "wifi", "rescan", "ifname", WIFI_IFACE]);

    let output = nmcli(&[
        "-t",
        "-f",
        "BSSID,SSID,CHAN,SIGNAL,SECURITY",
        "device",
        "wifi",
        "list",
        "ifname",
        WIFI_IFACE,
    ])?;

    let mut networks = Vec::new();

    for line in output.lines() {
        let parts = split_nmcli_terse(line);

        if parts.len() < 5 {
            continue;
        }

        let channel = parts[2].parse::<u64>().ok();
        let signal = parts[3].parse::<u64>().ok();

        networks.push(json!({
            "bssid": parts[0],
            "ssid": if parts[1].is_empty() { Value::Null } else { json!(parts[1]) },
            "channel": channel,
            "signal": signal,
            "security": parts[4]
        }));
    }

    Ok(json!({
        "interface": WIFI_IFACE,
        "networks": networks
    }))
}

pub fn wifi_disconnect() -> Result<Value> {
    nmcli(&["device", "disconnect", WIFI_IFACE])?;

    Ok(json!({
        "interface": WIFI_IFACE,
        "state": "disconnected"
    }))
}

fn validate_profile_name(profile_name: &str) -> Result<&str> {
    let name = profile_name.trim();

    if name.is_empty() {
        return Err(anyhow!("Wi-Fi profile name is required"));
    }

    if name.len() > 128 {
        return Err(anyhow!("Wi-Fi profile name exceeds 128 bytes"));
    }

    if name.chars().any(|c| c.is_control()) {
        return Err(anyhow!("Wi-Fi profile name contains control characters"));
    }

    Ok(name)
}

fn validate_wifi_connection_type(connection_type: &str) -> Result<()> {
    if connection_type.trim() != "802-11-wireless" {
        return Err(anyhow!("saved connection is not a Wi-Fi profile"));
    }

    Ok(())
}

pub fn wifi_profile_preflight(profile_name: &str) -> Result<Value> {
    let name = validate_profile_name(profile_name)?;

    let connection_type = nmcli(&["-g", "connection.type", "connection", "show", name])?;

    validate_wifi_connection_type(&connection_type)?;

    let uuid = nmcli(&["-g", "connection.uuid", "connection", "show", name])?;

    let uuid = uuid::Uuid::parse_str(uuid.trim())
        .map_err(|_| anyhow!("saved Wi-Fi profile has invalid UUID"))?;

    let bound_iface = nmcli(&[
        "-g",
        "connection.interface-name",
        "connection",
        "show",
        name,
    ])?;

    if !bound_iface.is_empty() && bound_iface != WIFI_IFACE {
        return Err(anyhow!("saved Wi-Fi profile is bound to another interface"));
    }

    Ok(json!({
        "profile_name": name,
        "profile_uuid": uuid.to_string(),
        "interface": WIFI_IFACE,
        "connection_type": connection_type.trim(),
        "valid": true
    }))
}

pub fn wifi_activate_saved(profile_name: &str) -> Result<Value> {
    let profile_name = profile_name.trim();

    if profile_name.is_empty() {
        return Err(anyhow!("wifi_activate_saved requires profile_name"));
    }

    if profile_name.len() > 128 {
        return Err(anyhow!("wifi profile name is too long"));
    }

    if profile_name.chars().any(|c| c.is_control()) {
        return Err(anyhow!("wifi profile name contains invalid characters"));
    }

    let connection_type = nmcli(&["-g", "connection.type", "connection", "show", profile_name])?;

    if !connection_type.contains("wireless")
        && !connection_type.contains("wifi")
        && connection_type != "802-11-wireless"
    {
        return Err(anyhow!("saved connection is not a Wi-Fi profile"));
    }

    let bound_iface = nmcli(&[
        "-g",
        "connection.interface-name",
        "connection",
        "show",
        profile_name,
    ])
    .unwrap_or_default();

    if !bound_iface.is_empty() && bound_iface != WIFI_IFACE {
        return Err(anyhow!("saved Wi-Fi profile is bound to another interface"));
    }

    nmcli(&[
        "--wait",
        "15",
        "connection",
        "up",
        "id",
        profile_name,
        "ifname",
        WIFI_IFACE,
    ])?;

    Ok(json!({
        "interface": WIFI_IFACE,
        "profile_name": profile_name,
        "state": "activated"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_profile_name() {
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("   ").is_err());
    }

    #[test]
    fn rejects_profile_name_control_characters() {
        assert!(validate_profile_name("Office\nWiFi").is_err());
        assert!(validate_profile_name("Office\0WiFi").is_err());
    }

    #[test]
    fn rejects_oversized_profile_name() {
        let name = "A".repeat(129);
        assert!(validate_profile_name(&name).is_err());
    }

    #[test]
    fn accepts_valid_profile_name() {
        assert_eq!(
            validate_profile_name(" Office WiFi ").unwrap(),
            "Office WiFi"
        );
    }

    #[test]
    fn accepts_wireless_connection_type() {
        assert!(validate_wifi_connection_type("802-11-wireless").is_ok());
    }

    #[test]
    fn rejects_non_wireless_connection_type() {
        assert!(validate_wifi_connection_type("802-3-ethernet").is_err());

        assert!(validate_wifi_connection_type("vpn").is_err());
    }

    #[test]
    fn parses_standard_nmcli_fields() {
        let result = split_nmcli_terse("wlan0:wifi:connected:Office WiFi");

        assert_eq!(result, vec!["wlan0", "wifi", "connected", "Office WiFi"]);
    }

    #[test]
    fn parses_escaped_colons() {
        let result = split_nmcli_terse(r"AA\:BB\:CC\:DD\:EE\:FF:Office WiFi:6:85:WPA2");

        assert_eq!(
            result,
            vec!["AA:BB:CC:DD:EE:FF", "Office WiFi", "6", "85", "WPA2"]
        );
    }

    #[test]
    fn parses_empty_fields() {
        let result = split_nmcli_terse("wlan0:wifi:disconnected:");

        assert_eq!(result, vec!["wlan0", "wifi", "disconnected", ""]);
    }

    #[test]
    fn parses_escaped_backslashes() {
        let result = split_nmcli_terse(r"Office\\Network:wifi:connected:Office");

        assert_eq!(
            result,
            vec!["Office\\Network", "wifi", "connected", "Office"]
        );
    }

    #[test]
    fn preserves_trailing_escape() {
        let result = split_nmcli_terse("Office\\");

        assert_eq!(result, vec!["Office\\"]);
    }
}
