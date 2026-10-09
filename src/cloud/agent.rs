use crate::hal::network_manager;
use crate::hal::telemetry;
use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Response};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{error, info, warn};

use crate::hal::relay_worker::{DoorOverrideMode, RelayCommand};
use crate::storage::NexusDatabase;

pub const DEFAULT_BASE_URL: &str =
    "https://gxwfuurzkdhxwxdbtdmt.supabase.co/functions/v1/nexus-device";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub controller_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub device_secret: String,
    pub hardware_profile: String,

    #[serde(default)]
    pub pending_certificate_id: Option<String>,

    #[serde(default)]
    pub pending_rotation_command_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope {
    success: bool,
    #[serde(default)]
    data: Value,
    #[serde(default)]
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentData {
    device_id: String,
    controller_id: String,
    organization_id: String,
    site_id: String,
    device_secret: String,
    hardware_profile: String,
}

#[derive(Debug, Deserialize)]
struct CommandList {
    commands: Vec<DeviceCommand>,
}

#[derive(Debug, Deserialize)]
struct DeviceCommand {
    id: String,
    #[serde(rename = "type")]
    command_type: String,
    #[serde(default)]
    payload: Value,
    #[serde(default)]
    door_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudConfiguration {
    #[serde(default)]
    doors: Vec<CloudDoor>,

    #[serde(default)]
    credentials: Vec<CloudCredential>,

    #[serde(default)]
    access_levels: Vec<CloudAccessLevel>,

    #[serde(default)]
    credential_access_levels: Vec<CloudCredentialAccessLevel>,

    #[serde(default)]
    access_level_doors: Vec<CloudAccessLevelDoor>,

    #[serde(default)]
    schedules: Vec<CloudSchedule>,

    #[serde(default)]
    holidays: Vec<CloudHoliday>,
}

#[derive(Debug, Deserialize)]
struct CloudDoor {
    channel: u8,
    name: String,

    #[serde(default = "default_true")]
    enabled: bool,

    #[serde(default = "default_unlock_ms")]
    unlock_ms: u64,

    #[serde(default)]
    unlock_schedule_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudCredential {
    id: String,
    facility_code: u64,
    card_code: u64,

    #[serde(default = "default_true")]
    enabled: bool,

    #[serde(default)]
    valid_from: Option<String>,

    #[serde(default)]
    valid_until: Option<String>,

    #[serde(default)]
    holder_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudAccessLevel {
    id: String,
    name: String,

    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct CloudCredentialAccessLevel {
    credential_id: String,
    access_level_id: String,
}

#[derive(Debug, Deserialize)]
struct CloudAccessLevelDoor {
    access_level_id: String,
    channel: u8,

    #[serde(default)]
    schedule_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudSchedule {
    id: String,
    name: String,

    #[serde(default = "default_timezone")]
    timezone: String,

    definition: Value,
}

#[derive(Debug, Deserialize)]
struct CloudHoliday {
    id: String,
    name: String,
    holiday_date: String,

    #[serde(default)]
    schedule_id: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_unlock_ms() -> u64 {
    5000
}

fn default_timezone() -> String {
    "America/New_York".to_string()
}

fn config_dir() -> &'static str {
    "/var/lib/highline-nexus"
}

fn identity_path() -> &'static str {
    "/var/lib/highline-nexus/device.json"
}

fn save_identity_atomic(identity: &DeviceIdentity) -> Result<()> {
    fs::create_dir_all(config_dir())?;

    let target = Path::new(identity_path());
    let temp = Path::new("/var/lib/highline-nexus/device.json.next");

    let encoded = serde_json::to_vec_pretty(identity)?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(temp)?;

    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);

    fs::rename(temp, target)?;

    if let Some(parent) = target.parent() {
        let directory = fs::File::open(parent)?;
        directory.sync_all()?;
    }

    Ok(())
}

fn api_error(envelope: &ApiEnvelope) -> anyhow::Error {
    if let Some(error) = &envelope.error {
        anyhow!("{}: {}", error.code, error.message)
    } else {
        anyhow!("Nexus API request failed")
    }
}

async fn parse_response(response: Response) -> Result<ApiEnvelope> {
    let status = response.status();
    let body = response
        .json::<ApiEnvelope>()
        .await
        .context("decode Nexus API response")?;

    if !status.is_success() || !body.success {
        return Err(api_error(&body));
    }

    Ok(body)
}

pub fn load_identity() -> Result<Option<DeviceIdentity>> {
    let path = Path::new(identity_path());

    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path).context("read Nexus device identity")?;

    let identity =
        serde_json::from_str::<DeviceIdentity>(&raw).context("decode Nexus device identity")?;

    Ok(Some(identity))
}

fn save_identity(identity: &DeviceIdentity) -> Result<()> {
    fs::create_dir_all(config_dir())?;

    let tmp = format!("{}.tmp", identity_path());

    fs::write(&tmp, serde_json::to_vec_pretty(identity)?)?;

    fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

    fs::rename(tmp, identity_path())?;

    Ok(())
}

fn client() -> Result<Client> {
    Ok(Client::builder().timeout(Duration::from_secs(15)).build()?)
}

pub async fn enroll(enrollment_token: &str, hardware_serial: &str) -> Result<DeviceIdentity> {
    let client = client()?;

    let body = json!({
        "name": "ACP4WR6 Lab Controller",
        "hardware": {
            "profile_code": "HNX-HW-SP-ACP4WR6-R1",
            "hardware_serial": hardware_serial,
            "hardware_revision": "R1.0"
        },
        "software": {
            "agent_version": env!("CARGO_PKG_VERSION"),
            "firmware_version": "nexus-agent-dev"
        }
    });

    let response = client
        .post(format!("{}/v1/enroll", DEFAULT_BASE_URL))
        .header("x-nexus-enrollment-token", enrollment_token)
        .json(&body)
        .send()
        .await
        .context("send Nexus enrollment")?;

    let envelope = parse_response(response).await?;

    let data: EnrollmentData =
        serde_json::from_value(envelope.data).context("decode enrollment data")?;

    let identity = DeviceIdentity {
        device_id: data.device_id,
        controller_id: data.controller_id,
        organization_id: data.organization_id,
        site_id: data.site_id,
        device_secret: data.device_secret,
        hardware_profile: data.hardware_profile,
        pending_certificate_id: None,
        pending_rotation_command_id: None,
    };

    save_identity(&identity)?;

    Ok(identity)
}

async fn authenticated_get(identity: &DeviceIdentity, path: &str) -> Result<ApiEnvelope> {
    let response = client()?
        .get(format!("{}{}", DEFAULT_BASE_URL, path))
        .header("x-nexus-device-id", &identity.device_id)
        .header("x-nexus-device-secret", &identity.device_secret)
        .send()
        .await?;

    parse_response(response).await
}

async fn authenticated_post(
    identity: &DeviceIdentity,
    path: &str,
    body: Value,
) -> Result<ApiEnvelope> {
    let response = client()?
        .post(format!("{}{}", DEFAULT_BASE_URL, path))
        .header("x-nexus-device-id", &identity.device_id)
        .header("x-nexus-device-secret", &identity.device_secret)
        .json(&body)
        .send()
        .await?;

    parse_response(response).await
}

async fn finalize_pending_credential_rotation(identity: &mut DeviceIdentity) -> Result<bool> {
    let Some(certificate_id) = identity.pending_certificate_id.clone() else {
        return Ok(false);
    };

    //
    // This request authenticates using the NEW secret already
    // stored in identity.
    //
    authenticated_post(
        identity,
        "/v1/credential/rotate/commit",
        json!({
            "certificate_id": certificate_id
        }),
    )
    .await
    .context("commit Nexus device credential rotation")?;

    //
    // If this rotation originated from a device command, complete
    // that command using the replacement credential as well.
    //
    if let Some(command_id) = identity.pending_rotation_command_id.clone() {
        acknowledge_command(
            identity,
            &command_id,
            "completed",
            json!({
                "message":
                    "device credential rotated successfully",
                "certificate_id": certificate_id
            }),
            None,
        )
        .await
        .context("acknowledge completed credential rotation")?;
    }

    //
    // Only clear pending state after BOTH server commit and
    // command completion have succeeded.
    //
    identity.pending_certificate_id = None;
    identity.pending_rotation_command_id = None;

    save_identity_atomic(identity)?;

    info!(
        target: "nexus_cloud",
        "Nexus device credential rotation committed"
    );

    Ok(true)
}

async fn rotate_device_credential(identity: &DeviceIdentity, command_id: &str) -> Result<()> {
    let prepared = authenticated_post(identity, "/v1/credential/rotate/prepare", json!({}))
        .await
        .context("prepare Nexus device credential rotation")?;

    let certificate_id = prepared.data["certificate_id"]
        .as_str()
        .ok_or_else(|| anyhow!("credential rotation response missing certificate_id"))?
        .to_string();

    let device_secret = prepared.data["device_secret"]
        .as_str()
        .ok_or_else(|| anyhow!("credential rotation response missing device_secret"))?
        .to_string();

    if device_secret.len() < 32 {
        return Err(anyhow!(
            "credential rotation returned invalid device secret"
        ));
    }

    //
    // The cloud has provisioned NEW before this local identity is
    // changed. OLD therefore remains valid if this write fails.
    //
    let mut candidate = identity.clone();

    candidate.device_secret = device_secret;
    candidate.pending_certificate_id = Some(certificate_id.clone());
    candidate.pending_rotation_command_id = Some(command_id.to_string());

    //
    // Durably persist NEW before permitting OLD to be revoked.
    //
    save_identity_atomic(&candidate)?;

    //
    // Try to finish immediately.
    //
    // If network/power fails after this point, NEW is already
    // durable and valid. The systemd restart/startup path retries
    // commit and command ACK.
    //
    match finalize_pending_credential_rotation(&mut candidate).await {
        Ok(_) => {
            info!(
                target: "nexus_cloud",
                certificate_id = %certificate_id,
                "Device credential rotation complete; restarting Nexus agent"
            );
        }

        Err(e) => {
            warn!(
                target: "nexus_cloud",
                error = %e,
                certificate_id = %certificate_id,
                "Replacement credential persisted; rotation completion will retry after restart"
            );
        }
    }

    //
    // Do not continue running with the old in-memory identity.
    // systemd Restart=always reloads device.json immediately.
    //
    std::process::exit(75);
}

async fn checkin(identity: &DeviceIdentity, db: &NexusDatabase) -> Result<Value> {
    let applied_version = db
        .connection()
        .query_row(
            r#"
            SELECT value
            FROM controller_config
            WHERE key = 'cloud_config_version'
            "#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let event_count: i64 = db.connection().query_row(
        r#"
        SELECT COUNT(*)
        FROM event_queue
        WHERE uploaded_at IS NULL
        "#,
        [],
        |row| row.get(0),
    )?;

    let body = tokio::task::spawn_blocking(move || {
        telemetry::checkin_payload(event_count, applied_version)
    })
    .await
    .context("collect SP4 telemetry")?;

    Ok(authenticated_post(identity, "/v1/checkin", body)
        .await?
        .data)
}

async fn upload_events(identity: &DeviceIdentity, db: &NexusDatabase) -> Result<()> {
    let mut stmt = db.connection().prepare(
        r#"
        SELECT
            id,
            event_type,
            channel,
            payload_json,
            occurred_at
        FROM event_queue
        WHERE uploaded_at IS NULL
        ORDER BY occurred_at ASC
        LIMIT 50
        "#,
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<u8>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;

    let mut events = Vec::new();
    let mut ids = Vec::new();

    for row in rows {
        let (id, event_type, channel, payload, occurred_at) = row?;

        let metadata: Value = serde_json::from_str(&payload).unwrap_or_else(|_| json!({}));

        let cloud_type = match event_type.as_str() {
            "access_grant" => "access_granted",
            "access_deny" => "access_denied",
            "rex_grant" | "rex_released" => "rex",
            "fire_active" => "input_active",
            "fire_cleared" | "fire_normal" => "input_restored",
            "scheduled_unlock_active"
            | "scheduled_unlock_inactive"
            | "wiegand_invalid_frame"
            | "access_error"
            | "rex_error"
            | "rex_ignored" => "system",
            other => other,
        };

        events.push(json!({
            "event_uuid": id,
            "type": cloud_type,
            "timestamp": occurred_at,
            "metadata": {
                "local_type": event_type,
                "channel": channel,
                "data": metadata
            }
        }));

        ids.push(id);
    }

    if events.is_empty() {
        return Ok(());
    }

    let submitted_count = events.len() as u64;

    let response = authenticated_post(identity, "/v1/events", json!({ "events": events })).await?;

    let accepted = response.data["accepted"].as_u64().unwrap_or(0);

    let duplicates = response.data["duplicates"].as_u64().unwrap_or(0);

    if accepted + duplicates != submitted_count {
        return Err(anyhow!(
            "cloud event batch incomplete: submitted={}, accepted={}, duplicates={}",
            submitted_count,
            accepted,
            duplicates
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();

    for id in ids {
        db.connection().execute(
            r#"
            UPDATE event_queue
            SET uploaded_at = ?2
            WHERE id = ?1
            "#,
            rusqlite::params![id, now],
        )?;
    }

    Ok(())
}

async fn acknowledge_command(
    identity: &DeviceIdentity,
    command_id: &str,
    state: &str,
    result: Value,
    failure_reason: Option<&str>,
) -> Result<()> {
    authenticated_post(
        identity,
        &format!("/v1/commands/{}/ack", urlencoding::encode(command_id)),
        json!({
            "state": state,
            "result": result,
            "failure_reason": failure_reason
        }),
    )
    .await?;

    Ok(())
}

fn network_command_requires_protection(command_type: &str) -> bool {
    matches!(command_type, "wifi_disconnect" | "wifi_activate_saved")
}

async fn handle_command(
    identity: &DeviceIdentity,
    command: DeviceCommand,
    relay_tx: &mpsc::Sender<RelayCommand>,
) -> Result<()> {
    acknowledge_command(identity, &command.id, "acknowledged", json!({}), None).await?;

    if command.command_type == "credential_rotate" {
        rotate_device_credential(identity, &command.id).await?;

        return Ok(());
    }

    let result: Result<Value> = async {
        if network_command_requires_protection(&command.command_type) {
            return Err(anyhow!(
                "network configuration command disabled until protected switching is implemented"
            ));
        }

        match command.command_type.as_str() {
            "diagnostic_request" => Ok(json!({
                "message": "diagnostic request acknowledged"
            })),

            "controller_sync" => Ok(json!({
                "message": "configuration synchronization requested"
            })),

            "wifi_status" => tokio::task::spawn_blocking(network_manager::wifi_status)
                .await
                .map_err(|e| anyhow!("wifi status task failed: {}", e))?,

            "wifi_radio_enable" => tokio::task::spawn_blocking(network_manager::wifi_radio_enable)
                .await
                .map_err(|e| anyhow!("wifi radio task failed: {}", e))?,

            "wifi_scan" => tokio::task::spawn_blocking(network_manager::wifi_scan)
                .await
                .map_err(|e| anyhow!("wifi scan task failed: {}", e))?,

            "wifi_disconnect" => tokio::task::spawn_blocking(network_manager::wifi_disconnect)
                .await
                .map_err(|e| anyhow!("wifi disconnect task failed: {}", e))?,

            "wifi_activate_saved" => {
                let profile_name = command.payload["profile_name"]
                    .as_str()
                    .ok_or_else(|| anyhow!("wifi_activate_saved missing profile_name"))?
                    .to_string();

                tokio::task::spawn_blocking(move || {
                    network_manager::wifi_activate_saved(&profile_name)
                })
                .await
                .map_err(|e| anyhow!("wifi activation task failed: {}", e))?
            }

            "controller_restart" => {
                // Deliberately do not reboot directly from a cloud message
                // during development. The command path is proven without
                // making a remote command capable of unexpectedly restarting
                // the lab controller.
                Ok(json!({
                    "message":
                        "restart command received; restart execution disabled in development"
                }))
            }

            "door_hold_open" => {
                let channel = command.payload["channel"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("door_hold_open missing channel"))?;

                if channel > 3 {
                    Err(anyhow!("invalid relay channel"))
                } else {
                    let expires_at =
                        match command.payload.get("expires_at").and_then(|v| v.as_str()) {
                            Some(value) => Some(
                                chrono::DateTime::parse_from_rfc3339(value)?
                                    .with_timezone(&chrono::Utc),
                            ),

                            None => None,
                        };

                    let (tx, rx) = oneshot::channel();

                    relay_tx
                        .send(RelayCommand::SetOverride {
                            channel: channel as u8,
                            mode: DoorOverrideMode::HoldUnlocked,
                            expires_at,
                            response: tx,
                        })
                        .await?;

                    rx.await
                        .map_err(|_| anyhow!("relay worker dropped override response"))?
                        .map_err(anyhow::Error::msg)?;

                    Ok(json!({
                        "channel": channel,
                        "mode": "hold_unlocked",
                        "expires_at":
                            expires_at.map(
                                |x| x.to_rfc3339()
                            )
                    }))
                }
            }

            "door_lock" => {
                let channel = command.payload["channel"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("door_lock missing channel"))?;

                if channel > 3 {
                    Err(anyhow!("invalid relay channel"))
                } else {
                    let expires_at =
                        match command.payload.get("expires_at").and_then(|v| v.as_str()) {
                            Some(value) => Some(
                                chrono::DateTime::parse_from_rfc3339(value)?
                                    .with_timezone(&chrono::Utc),
                            ),

                            None => None,
                        };

                    let (tx, rx) = oneshot::channel();

                    relay_tx
                        .send(RelayCommand::SetOverride {
                            channel: channel as u8,
                            mode: DoorOverrideMode::ForceLocked,
                            expires_at,
                            response: tx,
                        })
                        .await?;

                    rx.await
                        .map_err(|_| anyhow!("relay worker dropped override response"))?
                        .map_err(anyhow::Error::msg)?;

                    Ok(json!({
                        "channel": channel,
                        "mode": "force_locked",
                        "expires_at":
                            expires_at.map(
                                |x| x.to_rfc3339()
                            )
                    }))
                }
            }

            "door_return_to_schedule" => {
                let channel = command.payload["channel"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("door_return_to_schedule missing channel"))?;

                if channel > 3 {
                    Err(anyhow!("invalid relay channel"))
                } else {
                    let (tx, rx) = oneshot::channel();

                    relay_tx
                        .send(RelayCommand::ClearOverride {
                            channel: channel as u8,
                            response: tx,
                        })
                        .await?;

                    rx.await
                        .map_err(|_| anyhow!("relay worker dropped clear response"))?
                        .map_err(anyhow::Error::msg)?;

                    Ok(json!({
                        "channel": channel,
                        "mode": "normal_schedule"
                    }))
                }
            }

            "relay_pulse" => {
                let channel = command.payload["channel"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("relay_pulse missing channel"))?;

                let duration_ms = command.payload["duration_ms"]
                    .as_u64()
                    .unwrap_or(5000)
                    .clamp(100, 60000);

                if channel > 3 {
                    Err(anyhow!("invalid relay channel"))
                } else {
                    let (tx, rx) = oneshot::channel();

                    relay_tx
                        .send(RelayCommand::Pulse {
                            channel: channel as u8,
                            duration_ms,
                            response: Some(tx),
                        })
                        .await?;

                    match rx.await {
                        Ok(Ok(())) => Ok(json!({
                            "channel": channel,
                            "duration_ms": duration_ms
                        })),

                        Ok(Err(reason)) => Err(anyhow!(reason)),

                        Err(_) => Err(anyhow!("relay worker dropped pulse response")),
                    }
                }
            }

            _ => Err(anyhow!(
                "unsupported device command {}",
                command.command_type
            )),
        }
    }
    .await;

    match result {
        Ok(result) => {
            acknowledge_command(identity, &command.id, "completed", result, None).await?;
        }

        Err(e) => {
            acknowledge_command(
                identity,
                &command.id,
                "failed",
                json!({}),
                Some(&e.to_string()),
            )
            .await?;
        }
    }

    Ok(())
}

async fn poll_commands(
    identity: &DeviceIdentity,
    relay_tx: &mpsc::Sender<RelayCommand>,
) -> Result<()> {
    let envelope = authenticated_get(identity, "/v1/commands").await?;

    let list: CommandList = serde_json::from_value(envelope.data)?;

    for command in list.commands {
        if let Err(e) = handle_command(identity, command, relay_tx).await {
            warn!(
                error = %e,
                "Nexus command handling failed"
            );
        }
    }

    Ok(())
}

fn validate_timestamp(value: &Option<String>, field: &str) -> Result<()> {
    if let Some(value) = value {
        chrono::DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("{} is not a valid RFC3339 timestamp", field))?;
    }

    Ok(())
}

fn validate_cloud_configuration(config: &CloudConfiguration) -> Result<()> {
    //
    // ACP4WR6 R1 is a fixed four-door controller.
    // A full snapshot must explicitly contain every door.
    //
    if config.doors.len() != 4 {
        return Err(anyhow!("configuration must contain exactly 4 doors"));
    }

    let mut door_channels = HashSet::new();

    for door in &config.doors {
        if door.channel > 3 {
            return Err(anyhow!("invalid door channel {}", door.channel));
        }

        if !door_channels.insert(door.channel) {
            return Err(anyhow!("duplicate door channel {}", door.channel));
        }

        if door.name.trim().is_empty() {
            return Err(anyhow!("door {} has an empty name", door.channel));
        }

        if door.unlock_ms < 100 || door.unlock_ms > 600_000 {
            return Err(anyhow!(
                "door {} unlock_ms must be 100..600000",
                door.channel
            ));
        }
    }

    for expected in 0u8..4 {
        if !door_channels.contains(&expected) {
            return Err(anyhow!("door channel {} is missing", expected));
        }
    }

    let schedule_ids: HashSet<String> = config.schedules.iter().map(|s| s.id.clone()).collect();

    if schedule_ids.len() != config.schedules.len() {
        return Err(anyhow!("duplicate schedule id"));
    }

    for schedule in &config.schedules {
        if schedule.id.trim().is_empty() || schedule.name.trim().is_empty() {
            return Err(anyhow!("schedule id/name cannot be empty"));
        }

        schedule
            .timezone
            .parse::<chrono_tz::Tz>()
            .map_err(|_| anyhow!("invalid schedule timezone {}", schedule.timezone))?;

        if !schedule.definition.is_object() {
            return Err(anyhow!(
                "schedule {} definition must be an object",
                schedule.id
            ));
        }
    }

    for door in &config.doors {
        if let Some(schedule_id) = &door.unlock_schedule_id {
            if !schedule_ids.contains(schedule_id) {
                return Err(anyhow!(
                    "door {} references unknown unlock schedule {}",
                    door.channel,
                    schedule_id
                ));
            }
        }
    }

    let credential_ids: HashSet<String> = config.credentials.iter().map(|c| c.id.clone()).collect();

    if credential_ids.len() != config.credentials.len() {
        return Err(anyhow!("duplicate credential id"));
    }

    let mut credential_values = HashSet::new();

    for credential in &config.credentials {
        if credential.id.trim().is_empty() {
            return Err(anyhow!("credential id cannot be empty"));
        }

        if credential.facility_code > 255 {
            return Err(anyhow!(
                "credential {} facility code exceeds Wiegand-26 range",
                credential.id
            ));
        }

        if credential.card_code > 65535 {
            return Err(anyhow!(
                "credential {} card code exceeds Wiegand-26 range",
                credential.id
            ));
        }

        if !credential_values.insert((credential.facility_code, credential.card_code)) {
            return Err(anyhow!("duplicate facility/card credential"));
        }

        validate_timestamp(&credential.valid_from, "credential.valid_from")?;

        validate_timestamp(&credential.valid_until, "credential.valid_until")?;

        if let (Some(valid_from), Some(valid_until)) =
            (&credential.valid_from, &credential.valid_until)
        {
            let from = chrono::DateTime::parse_from_rfc3339(valid_from)?;

            let until = chrono::DateTime::parse_from_rfc3339(valid_until)?;

            if until < from {
                return Err(anyhow!(
                    "credential {} valid_until is before valid_from",
                    credential.id
                ));
            }
        }
    }

    let access_level_ids: HashSet<String> =
        config.access_levels.iter().map(|a| a.id.clone()).collect();

    if access_level_ids.len() != config.access_levels.len() {
        return Err(anyhow!("duplicate access level id"));
    }

    for access_level in &config.access_levels {
        if access_level.id.trim().is_empty() || access_level.name.trim().is_empty() {
            return Err(anyhow!("access level id/name cannot be empty"));
        }
    }

    for mapping in &config.credential_access_levels {
        if !credential_ids.contains(&mapping.credential_id) {
            return Err(anyhow!(
                "credential mapping references unknown credential {}",
                mapping.credential_id
            ));
        }

        if !access_level_ids.contains(&mapping.access_level_id) {
            return Err(anyhow!(
                "credential mapping references unknown access level {}",
                mapping.access_level_id
            ));
        }
    }

    for mapping in &config.access_level_doors {
        if !access_level_ids.contains(&mapping.access_level_id) {
            return Err(anyhow!(
                "door mapping references unknown access level {}",
                mapping.access_level_id
            ));
        }

        if mapping.channel > 3 {
            return Err(anyhow!(
                "access level door mapping has invalid channel {}",
                mapping.channel
            ));
        }

        if let Some(schedule_id) = &mapping.schedule_id {
            if !schedule_ids.contains(schedule_id) {
                return Err(anyhow!(
                    "access level door mapping references unknown schedule {}",
                    schedule_id
                ));
            }
        }
    }

    let mut holiday_ids = HashSet::new();

    for holiday in &config.holidays {
        if !holiday_ids.insert(holiday.id.clone()) {
            return Err(anyhow!("duplicate holiday id"));
        }

        chrono::NaiveDate::parse_from_str(&holiday.holiday_date, "%Y-%m-%d")
            .with_context(|| format!("invalid holiday date {}", holiday.holiday_date))?;

        if let Some(schedule_id) = &holiday.schedule_id {
            if !schedule_ids.contains(schedule_id) {
                return Err(anyhow!(
                    "holiday {} references unknown schedule {}",
                    holiday.id,
                    schedule_id
                ));
            }
        }
    }

    Ok(())
}

fn apply_cloud_configuration(
    db: &NexusDatabase,
    version: u64,
    checksum: Option<&str>,
    config: &CloudConfiguration,
) -> Result<()> {
    validate_cloud_configuration(config)?;

    //
    // unchecked_transaction() is intentional here:
    // NexusDatabase exposes &Connection and the cloud
    // agent owns this connection exclusively.
    //
    let tx = db
        .connection()
        .unchecked_transaction()
        .context("begin cloud configuration transaction")?;

    //
    // Remove relationship rows first.
    //
    tx.execute("DELETE FROM credential_access_levels", [])?;

    tx.execute("DELETE FROM access_level_doors", [])?;

    tx.execute("DELETE FROM holidays", [])?;

    tx.execute("DELETE FROM credentials", [])?;

    tx.execute("DELETE FROM access_levels", [])?;

    tx.execute("DELETE FROM schedules", [])?;

    //
    // Schedules.
    //
    for schedule in &config.schedules {
        let definition_json = serde_json::to_string(&schedule.definition)?;

        tx.execute(
            r#"
            INSERT INTO schedules
            (
                id,
                name,
                timezone,
                definition_json,
                updated_at
            )
            VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)
            "#,
            rusqlite::params![
                schedule.id,
                schedule.name,
                schedule.timezone,
                definition_json,
            ],
        )?;
    }

    //
    // Holidays.
    //
    for holiday in &config.holidays {
        tx.execute(
            r#"
            INSERT INTO holidays
            (
                id,
                name,
                holiday_date,
                schedule_id,
                updated_at
            )
            VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)
            "#,
            rusqlite::params![
                holiday.id,
                holiday.name,
                holiday.holiday_date,
                holiday.schedule_id,
            ],
        )?;
    }

    //
    // Access levels.
    //
    for access_level in &config.access_levels {
        tx.execute(
            r#"
            INSERT INTO access_levels
            (
                id,
                name,
                enabled,
                updated_at
            )
            VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)
            "#,
            rusqlite::params![
                access_level.id,
                access_level.name,
                if access_level.enabled { 1i64 } else { 0i64 },
            ],
        )?;
    }

    //
    // Credentials.
    //
    for credential in &config.credentials {
        tx.execute(
            r#"
            INSERT INTO credentials
            (
                id,
                facility_code,
                card_code,
                enabled,
                valid_from,
                valid_until,
                holder_name,
                updated_at
            )
            VALUES
            (
                ?1, ?2, ?3, ?4,
                ?5, ?6, ?7,
                CURRENT_TIMESTAMP
            )
            "#,
            rusqlite::params![
                credential.id,
                credential.facility_code as i64,
                credential.card_code as i64,
                if credential.enabled { 1i64 } else { 0i64 },
                credential.valid_from,
                credential.valid_until,
                credential.holder_name,
            ],
        )?;
    }

    //
    // Credential → access-level mapping.
    //
    for mapping in &config.credential_access_levels {
        tx.execute(
            r#"
            INSERT INTO credential_access_levels
            (
                credential_id,
                access_level_id
            )
            VALUES (?1, ?2)
            "#,
            rusqlite::params![mapping.credential_id, mapping.access_level_id,],
        )?;
    }

    //
    // Access-level → door/schedule mapping.
    //
    for mapping in &config.access_level_doors {
        tx.execute(
            r#"
            INSERT INTO access_level_doors
            (
                access_level_id,
                channel,
                schedule_id
            )
            VALUES (?1, ?2, ?3)
            "#,
            rusqlite::params![
                mapping.access_level_id,
                mapping.channel as i64,
                mapping.schedule_id,
            ],
        )?;
    }

    //
    // Door configuration.
    //
    // We UPDATE the fixed four rows rather than delete
    // them because these channels are physical hardware.
    //
    for door in &config.doors {
        let changed = tx.execute(
            r#"
            UPDATE door_config
            SET
                name = ?2,
                enabled = ?3,
                unlock_ms = ?4,
                unlock_schedule_id = ?5,
                updated_at = CURRENT_TIMESTAMP
            WHERE channel = ?1
            "#,
            rusqlite::params![
                door.channel as i64,
                door.name,
                if door.enabled { 1i64 } else { 0i64 },
                door.unlock_ms as i64,
                door.unlock_schedule_id,
            ],
        )?;

        if changed != 1 {
            return Err(anyhow!("door_config channel {} is missing", door.channel));
        }
    }

    //
    // Persist the cloud version inside the SAME
    // transaction as the access configuration.
    //
    tx.execute(
        r#"
        INSERT INTO controller_config
            (key, value, updated_at)
        VALUES
            ('cloud_config_version', ?1, CURRENT_TIMESTAMP)
        ON CONFLICT(key)
        DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        "#,
        [version.to_string()],
    )?;

    if let Some(checksum) = checksum {
        tx.execute(
            r#"
            INSERT INTO controller_config
                (key, value, updated_at)
            VALUES
                ('cloud_config_checksum', ?1, CURRENT_TIMESTAMP)
            ON CONFLICT(key)
            DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            "#,
            [checksum],
        )?;
    }

    tx.commit()
        .context("commit cloud configuration transaction")?;

    Ok(())
}

async fn sync_config_if_needed(
    identity: &DeviceIdentity,
    db: &NexusDatabase,
    checkin_data: &Value,
) -> Result<()> {
    let update_available = checkin_data["config_update_available"]
        .as_bool()
        .unwrap_or(false);

    if !update_available {
        return Ok(());
    }

    let envelope = authenticated_get(identity, "/v1/config").await?;

    let version = envelope.data["version"]
        .as_u64()
        .ok_or_else(|| anyhow!("configuration response missing version"))?;

    let checksum = envelope.data["checksum"].as_str().map(str::to_string);

    let configuration_value = envelope
        .data
        .get("configuration")
        .cloned()
        .ok_or_else(|| anyhow!("configuration response missing configuration"))?;

    let configuration: CloudConfiguration =
        serde_json::from_value(configuration_value).context("decode cloud configuration")?;

    info!(
        target: "nexus_cloud",
        version = version,
        "Cloud configuration downloaded"
    );

    match apply_cloud_configuration(db, version, checksum.as_deref(), &configuration) {
        Ok(()) => {
            authenticated_post(
                identity,
                "/v1/config/ack",
                json!({
                    "version": version,
                    "status": "applied",
                    "checksum": checksum,
                    "applied_at":
                        chrono::Utc::now()
                            .to_rfc3339()
                }),
            )
            .await
            .context("ack applied cloud configuration")?;

            info!(
                target: "nexus_cloud",
                version = version,
                "Cloud configuration applied and acknowledged"
            );

            Ok(())
        }

        Err(apply_error) => {
            let error_text = apply_error.to_string();

            //
            // Best effort failed ACK.
            //
            let ack_result = authenticated_post(
                identity,
                "/v1/config/ack",
                json!({
                    "version": version,
                    "status": "failed",
                    "checksum": checksum,
                    "error": {
                        "message": error_text
                    }
                }),
            )
            .await;

            if let Err(ack_error) = ack_result {
                warn!(
                    error = %ack_error,
                    version = version,
                    "Unable to acknowledge configuration failure"
                );
            }

            Err(apply_error)
        }
    }
}

pub async fn run(db_path: &str, relay_tx: mpsc::Sender<RelayCommand>) {
    let mut identity = match load_identity() {
        Ok(Some(identity)) => identity,

        Ok(None) => {
            warn!("Nexus cloud agent not enrolled; local access remains operational");
            return;
        }

        Err(e) => {
            error!(
                error = %e,
                "Unable to load Nexus device identity"
            );
            return;
        }
    };

    let db = match NexusDatabase::open(db_path) {
        Ok(db) => db,

        Err(e) => {
            error!(
                error = %e,
                "Unable to open database for Nexus cloud agent"
            );
            return;
        }
    };

    info!(
        controller_id = %identity.controller_id,
        "Nexus cloud agent started"
    );

    if identity.pending_certificate_id.is_some() {
        warn!(
            target: "nexus_cloud",
            "Pending device credential rotation detected"
        );

        loop {
            match finalize_pending_credential_rotation(&mut identity).await {
                Ok(_) => break,

                Err(e) => {
                    warn!(
                        target: "nexus_cloud",
                        error = %e,
                        "Unable to finish pending credential rotation; retrying"
                    );

                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    let mut checkin_timer = interval(Duration::from_secs(30));

    let mut command_timer = interval(Duration::from_secs(5));

    let mut event_timer = interval(Duration::from_secs(5));

    checkin_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    command_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    event_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = checkin_timer.tick() => {
                match checkin(&identity, &db).await {
                    Ok(data) => {
                        info!(
                            target: "nexus_cloud",
                            "Cloud check-in successful"
                        );

                        if let Err(e) =
                            sync_config_if_needed(
                                &identity,
                                &db,
                                &data,
                            )
                            .await
                        {
                            warn!(
                                error = %e,
                                "Configuration synchronization failed"
                            );
                        }
                    }

                    Err(e) => {
                        warn!(
                            error = %e,
                            "Cloud check-in failed; offline access remains active"
                        );
                    }
                }
            }

            _ = command_timer.tick() => {
                if let Err(e) =
                    poll_commands(
                        &identity,
                        &relay_tx,
                    )
                    .await
                {
                    warn!(
                        error = %e,
                        "Cloud command poll failed"
                    );
                }
            }

            _ = event_timer.tick() => {
                if let Err(e) =
                    upload_events(
                        &identity,
                        &db,
                    )
                    .await
                {
                    warn!(
                        error = %e,
                        "Cloud event upload failed"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod network_command_guard_tests {
    use super::*;

    #[test]
    fn blocks_unprotected_wifi_disconnect() {
        assert!(network_command_requires_protection("wifi_disconnect"));
    }

    #[test]
    fn blocks_unprotected_wifi_activation() {
        assert!(network_command_requires_protection("wifi_activate_saved"));
    }

    #[test]
    fn permits_wifi_status() {
        assert!(!network_command_requires_protection("wifi_status"));
    }

    #[test]
    fn permits_wifi_scan() {
        assert!(!network_command_requires_protection("wifi_scan"));
    }

    #[test]
    fn permits_wifi_radio_enable() {
        assert!(!network_command_requires_protection("wifi_radio_enable"));
    }
}
