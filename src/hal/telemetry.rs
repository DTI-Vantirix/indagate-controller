use serde_json::{Map, Value, json};
use std::{fs, path::Path, process::Command, thread, time::Duration};

fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|v| v.trim().to_string())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn uptime_seconds() -> Option<u64> {
    read_trim("/proc/uptime")?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|v| v as u64)
}

fn boot_id() -> Option<String> {
    read_trim("/proc/sys/kernel/random/boot_id")
}

fn os_version() -> Option<String> {
    let raw = fs::read_to_string("/etc/os-release").ok()?;

    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return Some(value.trim_matches('"').to_string());
        }
    }

    None
}

fn kernel_version() -> Option<String> {
    command_output("uname", &["-r"])
}

/// The systemd unit a process belongs to, from the text of its `/proc/<pid>/cgroup`:
/// the last part of the path, when it is a service.
fn unit_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .filter_map(|line| line.rsplit('/').next())
        .map(str::trim)
        .find(|part| part.ends_with(".service") && part.len() > ".service".len())
        .map(str::to_string)
}

/// How many times systemd has restarted this controller's own service. The service is
/// whichever one this process runs in, so it needs no name built in.
fn service_restart_count() -> Option<u64> {
    let unit = unit_from_cgroup(&std::fs::read_to_string("/proc/self/cgroup").ok()?)?;
    command_output("systemctl", &["show", &unit, "--property=NRestarts", "--value"])?
    .parse::<u64>()
    .ok()
}

fn cpu_times() -> Option<(u64, u64)> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;

    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse::<u64>().ok())
        .collect();

    if values.len() < 4 {
        return None;
    }

    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    let total = values.iter().sum();

    Some((idle, total))
}

fn cpu_usage_percent() -> Option<f64> {
    let (idle_a, total_a) = cpu_times()?;

    thread::sleep(Duration::from_millis(120));

    let (idle_b, total_b) = cpu_times()?;

    let total_delta = total_b.checked_sub(total_a)?;
    let idle_delta = idle_b.checked_sub(idle_a)?;

    if total_delta == 0 {
        return None;
    }

    let busy = total_delta.saturating_sub(idle_delta);

    Some(((busy as f64 / total_delta as f64) * 1000.0).round() / 10.0)
}

fn cpu_snapshot() -> Value {
    let usage = cpu_usage_percent();

    let load = read_trim("/proc/loadavg")
        .map(|v| {
            v.split_whitespace()
                .take(3)
                .filter_map(|x| x.parse::<f64>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let load_1 = load.first().copied();
    let load_5 = load.get(1).copied();
    let load_15 = load.get(2).copied();

    let status = match usage {
        Some(v) if v >= 95.0 => "critical",
        Some(v) if v >= 85.0 => "warning",
        Some(_) => "ok",
        None => "unknown",
    };

    json!({
        "status": status,
        "usage_percent": usage,
        "load_1": load_1,
        "load_5": load_5,
        "load_15": load_15
    })
}

fn memory_snapshot() -> Value {
    let raw = fs::read_to_string("/proc/meminfo").unwrap_or_default();

    let mut total = None;
    let mut available = None;

    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let value = parts.next().and_then(|v| v.parse::<u64>().ok());

        match key {
            "MemTotal:" => total = value.map(|v| v * 1024),
            "MemAvailable:" => available = value.map(|v| v * 1024),
            _ => {}
        }
    }

    let used = match (total, available) {
        (Some(t), Some(a)) => Some(t.saturating_sub(a)),
        _ => None,
    };

    json!({
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": available
    })
}

fn storage_snapshot() -> Value {
    let output = command_output("df", &["-B1", "--output=size,used,avail", "/"]);

    let parsed = output.and_then(|text| {
        let line = text.lines().last()?;
        let values: Vec<u64> = line
            .split_whitespace()
            .filter_map(|v| v.parse::<u64>().ok())
            .collect();

        if values.len() < 3 {
            return None;
        }

        Some((values[0], values[1], values[2]))
    });

    match parsed {
        Some((total, used, available)) => {
            let available_pct = if total > 0 {
                available as f64 / total as f64 * 100.0
            } else {
                0.0
            };

            let status = if available_pct < 5.0 {
                "critical"
            } else if available_pct < 10.0 {
                "warning"
            } else {
                "ok"
            };

            json!({
                "status": status,
                "total_bytes": total,
                "used_bytes": used,
                "available_bytes": available
            })
        }

        None => json!({
            "status": "unknown"
        }),
    }
}

fn temperature_snapshot() -> Value {
    let mut zones = Map::new();
    let mut cpu_c = None;
    let mut soc_c = None;

    if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
        for entry in entries.flatten() {
            let path = entry.path();

            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("thermal_zone")
            {
                continue;
            }

            let zone_type = read_trim(path.join("type"))
                .unwrap_or_else(|| entry.file_name().to_string_lossy().to_string());

            let Some(raw_temp) = read_trim(path.join("temp")).and_then(|v| v.parse::<f64>().ok())
            else {
                continue;
            };

            let temp_c = if raw_temp > 1000.0 {
                raw_temp / 1000.0
            } else {
                raw_temp
            };

            let rounded = (temp_c * 10.0).round() / 10.0;

            zones.insert(zone_type.clone(), json!(rounded));

            let lower = zone_type.to_lowercase();

            if cpu_c.is_none() && lower.contains("cpu") {
                cpu_c = Some(rounded);
            }

            if soc_c.is_none() && lower.contains("soc") {
                soc_c = Some(rounded);
            }

            if cpu_c.is_none() {
                cpu_c = Some(rounded);
            }
        }
    }

    json!({
        "cpu_c": cpu_c,
        "soc_c": soc_c,
        "zones": zones
    })
}

fn sysfs_u64(path: &Path) -> Option<u64> {
    read_trim(path)?.parse::<u64>().ok()
}

fn interface_ipv4(name: &str) -> Option<String> {
    let out = command_output("ip", &["-o", "-4", "addr", "show", "dev", name])?;

    let values: Vec<&str> = out.split_whitespace().collect();

    for pair in values.windows(2) {
        if pair[0] == "inet" {
            return Some(pair[1].split('/').next()?.to_string());
        }
    }

    None
}

fn interface_gateway(name: &str) -> Option<String> {
    let out = command_output("ip", &["route", "show", "default", "dev", name])?;
    let parts: Vec<&str> = out.split_whitespace().collect();

    for pair in parts.windows(2) {
        if pair[0] == "via" {
            return Some(pair[1].to_string());
        }
    }

    None
}

fn default_interface() -> Option<String> {
    let out = command_output("ip", &["route", "show", "default"])?;
    let parts: Vec<&str> = out.split_whitespace().collect();

    for pair in parts.windows(2) {
        if pair[0] == "dev" {
            return Some(pair[1].to_string());
        }
    }

    None
}

fn wifi_info(name: &str) -> (Option<String>, Option<f64>) {
    let Some(out) = command_output("iw", &["dev", name, "link"]) else {
        return (None, None);
    };

    let mut ssid = None;
    let mut signal_dbm = None;

    for line in out.lines() {
        let line = line.trim();

        if let Some(value) = line.strip_prefix("SSID:") {
            ssid = Some(value.trim().to_string());
        }

        if let Some(value) = line.strip_prefix("signal:") {
            signal_dbm = value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok());
        }
    }

    (ssid, signal_dbm)
}

fn interface_snapshot(name: &str) -> Value {
    let base = Path::new("/sys/class/net").join(name);

    let iface_type = if base.join("wireless").exists() {
        "wifi"
    } else if name.starts_with("wwan") || name.starts_with("ppp") || name.starts_with("usb") {
        "cellular"
    } else {
        "ethernet"
    };

    let operstate = read_trim(base.join("operstate"));
    let link = operstate.as_deref() == Some("up");

    let speed_mbps = read_trim(base.join("speed"))
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0);

    let mac_address = read_trim(base.join("address"));
    let duplex = read_trim(base.join("duplex"));

    let stats = base.join("statistics");

    let (ssid, signal_dbm) = if iface_type == "wifi" {
        wifi_info(name)
    } else {
        (None, None)
    };

    json!({
        "name": name,
        "type": iface_type,
        "status": operstate,
        "link": link,
        "speed_mbps": speed_mbps,
        "duplex": duplex,
        "mac_address": mac_address,
        "ip_address": interface_ipv4(name),
        "gateway": interface_gateway(name),
        "rx_bytes": sysfs_u64(&stats.join("rx_bytes")),
        "tx_bytes": sysfs_u64(&stats.join("tx_bytes")),
        "rx_errors": sysfs_u64(&stats.join("rx_errors")),
        "tx_errors": sysfs_u64(&stats.join("tx_errors")),
        "rx_dropped": sysfs_u64(&stats.join("rx_dropped")),
        "tx_dropped": sysfs_u64(&stats.join("tx_dropped")),
        "ssid": ssid,
        "signal_dbm": signal_dbm
    })
}

fn dns_servers() -> Vec<String> {
    fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let line = line.trim();

            if !line.starts_with("nameserver ") {
                return None;
            }

            line.split_whitespace().nth(1).map(str::to_string)
        })
        .collect()
}

/// A value from ModemManager's output, which writes "--" where it has nothing.
fn modem_text(value: &Value, path: &[&str]) -> Option<String> {
    let mut at = value;
    for key in path {
        at = at.get(key)?;
    }
    let text = at.as_str()?.trim();
    (!text.is_empty() && text != "--").then(|| text.to_string())
}

/// The cellular modem's details as the check-in carries them, from what ModemManager
/// says about the modem (`mmcli -m ... -J`) and its SIM (`mmcli -i ... -J`). Only what
/// the modem reports is included; a board with no SIM fitted says so by its state.
fn cellular_report(modem: &Value, sim: Option<&Value>) -> Value {
    let generic = &modem["modem"]["generic"];
    let signal_percent = modem_text(generic, &["signal-quality", "value"]).and_then(|v| v.parse::<u8>().ok());
    let technology = generic["access-technologies"]
        .as_array()
        .map(|list| list.iter().filter_map(Value::as_str).filter(|t| *t != "--").collect::<Vec<_>>().join(", "))
        .filter(|joined| !joined.is_empty());
    let state = modem_text(generic, &["state"]);
    let failed = modem_text(generic, &["state-failed-reason"]);
    json!({
        "manufacturer": modem_text(generic, &["manufacturer"]),
        "modem_model": modem_text(generic, &["model"]),
        "modem_firmware": modem_text(generic, &["revision"]),
        "imei": modem_text(&modem["modem"]["3gpp"], &["imei"]).or_else(|| modem_text(generic, &["equipment-identifier"])),
        "iccid": sim.and_then(|sim| modem_text(sim, &["sim", "properties", "iccid"])),
        "carrier": modem_text(&modem["modem"]["3gpp"], &["operator-name"])
            .or_else(|| sim.and_then(|sim| modem_text(sim, &["sim", "properties", "operator-name"]))),
        "connection_state": match (&state, &failed) {
            (Some(state), Some(reason)) if state == "failed" => Some(format!("failed ({reason})")),
            _ => state.clone(),
        },
        "registration": modem_text(&modem["modem"]["3gpp"], &["registration-state"]),
        "technology": technology,
        "signal_percent": signal_percent,
        "signal_level": signal_percent.map(|percent| format!("{percent}%")),
        "sim_present": sim.is_some(),
    })
}

/// How long the modem's details are reused before ModemManager is asked again. A check-in
/// goes out every few seconds; the modem's state does not change that fast.
const CELLULAR_EVERY: Duration = Duration::from_secs(30);

/// The cellular modem's details, or nothing when the board has no modem or no
/// ModemManager. Asked for at most every `CELLULAR_EVERY`.
fn cellular_snapshot() -> Value {
    static LAST: std::sync::Mutex<Option<(std::time::Instant, Value)>> = std::sync::Mutex::new(None);
    if let Ok(last) = LAST.lock() {
        if let Some((at, value)) = last.as_ref() {
            if at.elapsed() < CELLULAR_EVERY {
                return value.clone();
            }
        }
    }
    let ask = |args: &[&str]| -> Option<Value> {
        let mut all = vec!["--timeout=5"];
        all.extend_from_slice(args);
        serde_json::from_str(&command_output("mmcli", &all)?).ok()
    };
    let report = (|| {
        let list = ask(&["-L", "-J"])?;
        let modem_path = list["modem-list"].as_array()?.first()?.as_str()?.to_string();
        let modem = ask(&["-m", &modem_path, "-J"])?;
        let sim = modem_text(&modem["modem"]["generic"], &["sim"]).and_then(|path| ask(&["-i", &path, "-J"]));
        Some(cellular_report(&modem, sim.as_ref()))
    })()
    .unwrap_or(Value::Null);
    if let Ok(mut last) = LAST.lock() {
        *last = Some((std::time::Instant::now(), report.clone()));
    }
    report
}

fn network_snapshot() -> Value {
    let primary = default_interface();

    let mut names = fs::read_dir("/sys/class/net")
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .filter(|name| name != "lo")
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    names.sort();

    let interfaces = names
        .iter()
        .map(|name| interface_snapshot(name))
        .collect::<Vec<_>>();

    json!({
        "primary": primary,
        "dns": dns_servers(),
        "interfaces": interfaces,
        "cellular": cellular_snapshot()
    })
}

/// The firmware's version: the package version and the build it came from. A build made
/// without naming itself (a developer's own) says so instead of passing for a release.
pub fn firmware_version() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), option_env!("INDAGATE_BUILD").unwrap_or("dev"))
}

pub fn checkin_payload(event_count: i64, applied_version: u64) -> Value {
    let network = network_snapshot();
    let restarts = service_restart_count();

    let cpu = cpu_snapshot();
    let memory = memory_snapshot();
    let storage = storage_snapshot();
    let temperature = temperature_snapshot();

    json!({
        "software": {
            "agent_version": env!("CARGO_PKG_VERSION"),
            "firmware_version": firmware_version(),
            "os_version": os_version(),
            "kernel_version": kernel_version()
        },
        "runtime": {
            "uptime_seconds": uptime_seconds(),
            "boot_id": boot_id(),
            "service_restart_count": restarts
        },
        "configuration": {
            "applied_version": applied_version
        },
        "network": network,
        // What every door, input and the fire input is doing right now.
        "io": super::live_io::io_report(super::profile::acp4wr6_r1().doors.len() as u8),
        "health": {
            "cpu_health": cpu["status"],
            "cpu": cpu,
            "memory": memory,
            "storage_health": storage["status"],
            "storage": storage,
            "temperature": temperature,
            "service_restart_count": restarts,
            "network": network["primary"],
            "event_queue": {
                "pending": event_count
            },
            // As the relay driver last found it: how the chip is reached and whether the
            // last switch worked. Nothing is claimed before a relay has been switched.
            "relay": super::live_io::relay_report(),
            "system": {
                "kernel_version": kernel_version()
            }
        }
    })
}

#[cfg(test)]
mod cellular_tests {
    use super::cellular_report;
    use serde_json::json;

    #[test]
    fn a_registered_modem_is_reported_in_full() {
        let modem = json!({ "modem": {
            "3gpp": { "imei": "860000000000001", "operator-name": "Example Mobile", "registration-state": "home" },
            "generic": {
                "manufacturer": "QUALCOMM INCORPORATED", "model": "QUECTEL Mobile Broadband Module",
                "revision": "EC25AFAR05A04M4G", "state": "connected", "state-failed-reason": "--",
                "access-technologies": ["lte"], "signal-quality": { "recent": "yes", "value": "72" },
                "sim": "/org/freedesktop/ModemManager1/SIM/0"
            }
        }});
        let sim = json!({ "sim": { "properties": { "iccid": "8900000000000000001", "operator-name": "Example" } } });
        let report = cellular_report(&modem, Some(&sim));
        assert_eq!(report["modem_model"], "QUECTEL Mobile Broadband Module");
        assert_eq!(report["imei"], "860000000000001");
        assert_eq!(report["iccid"], "8900000000000000001");
        assert_eq!(report["carrier"], "Example Mobile");
        assert_eq!(report["connection_state"], "connected");
        assert_eq!(report["registration"], "home");
        assert_eq!(report["technology"], "lte");
        assert_eq!(report["signal_percent"], 72);
        assert_eq!(report["signal_level"], "72%");
        assert_eq!(report["sim_present"], true);
    }

    #[test]
    fn a_modem_with_no_sim_says_so_and_claims_nothing_else() {
        let modem = json!({ "modem": {
            "3gpp": { "imei": "860000000000001", "operator-name": "--", "registration-state": "--" },
            "generic": {
                "manufacturer": "QUALCOMM INCORPORATED", "model": "QUECTEL Mobile Broadband Module",
                "state": "failed", "state-failed-reason": "sim-missing",
                "access-technologies": [], "signal-quality": { "recent": "no", "value": "0" }, "sim": "--"
            }
        }});
        let report = cellular_report(&modem, None);
        assert_eq!(report["connection_state"], "failed (sim-missing)");
        assert_eq!(report["sim_present"], false);
        assert!(report["iccid"].is_null());
        assert!(report["carrier"].is_null());
        assert!(report["registration"].is_null());
        assert!(report["technology"].is_null());
        assert_eq!(report["imei"], "860000000000001");
    }
}

#[cfg(test)]
mod version_tests {
    #[test]
    fn the_firmware_version_names_its_build() {
        let version = super::firmware_version();
        assert!(version.starts_with(concat!(env!("CARGO_PKG_VERSION"), "+")), "{version}");
        assert!(version.len() > env!("CARGO_PKG_VERSION").len() + 1);
    }
}

#[cfg(test)]
mod unit_name_tests {
    use super::unit_from_cgroup;

    #[test]
    fn the_service_is_read_from_the_process_own_cgroup() {
        assert_eq!(unit_from_cgroup("0::/system.slice/indagate-controller.service\n").as_deref(), Some("indagate-controller.service"));
        assert_eq!(unit_from_cgroup("0::/system.slice/hlaxs-access.service").as_deref(), Some("hlaxs-access.service"));
        // Run by hand in a login session: not a service.
        assert_eq!(unit_from_cgroup("0::/user.slice/user-0.slice/session-3.scope"), None);
        assert_eq!(unit_from_cgroup(""), None);
        assert_eq!(unit_from_cgroup("0::/.service"), None);
    }
}
