use crate::hal::actuator_command_journal::{ActuatorCommandJournal, ReserveResult};
use crate::hal::credential_rotation_journal::{CredentialRotationJournal, RotationReservation};
use crate::hal::network_command_journal::NetworkCommandJournal;
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
use crate::storage::ControllerDatabase;


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
    readers: Vec<CloudReader>,

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

// SA16Q READER POLICY V1: all reader authorization fields must arrive
// explicitly from the validated server-side controller configuration.
#[derive(Debug, Deserialize)]
struct CloudReader {
    id: String,
    reader_number: u8,
    door_channel: Option<u8>,
    door_id: Option<String>,
    enabled: Option<bool>,
    protocol: String,
    configuration: Value,
    /// Bus address of an OSDP reader (0 to 126). Absent for Wiegand.
    #[serde(default)]
    osdp_address: Option<i64>,
    /// Whether an OSDP reader must use the encrypted secure channel.
    #[serde(default)]
    osdp_secure_channel: Option<bool>,
}

/// The D0 and D1 lines of each reader port's Wiegand input, port 1 first.
const READER_PINS: [((&str, u64), (&str, u64)); 4] = [
    (("gpiochip3", 23), ("gpiochip3", 25)),
    (("gpiochip3", 26), ("gpiochip0", 15)),
    (("gpiochip4", 10), ("gpiochip4", 26)),
    (("gpiochip4", 27), ("gpiochip4", 11)),
];

/// Line speeds an OSDP reader may be set to.
const OSDP_BAUD_RATES: [u32; 6] = [9600, 19200, 38400, 57600, 115200, 230400];
const OSDP_DEFAULT_BAUD_RATE: u32 = 9600;

/// What one reader port is told to be, once its settings have passed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReaderLink {
    Wiegand,
    Osdp { address: u8, baud_rate: u32 },
}

impl ReaderLink {
    fn protocol(self) -> &'static str {
        match self {
            ReaderLink::Wiegand => "wiegand",
            ReaderLink::Osdp { .. } => "osdp",
        }
    }
}

/// The protocol-specific part of a reader's settings. A Wiegand reader must sit on its
/// port's own pins and be commissioned for 26-bit cards, as before. An OSDP reader needs a
/// bus address and the RS-485 transport.
fn reader_link(r: &CloudReader, pins: ((&str, u64), (&str, u64))) -> Result<ReaderLink> {
    if r.protocol.eq_ignore_ascii_case("wiegand") {
        if r.configuration.get("validated").and_then(Value::as_bool) != Some(true)
            || r.configuration.get("format").and_then(Value::as_str) != Some("Wiegand-26")
        {
            return Err(anyhow!("SA16Q reader identity, commissioning or mapping invalid"));
        }
        for (field, (chip, line)) in [("d0", pins.0), ("d1", pins.1)] {
            let Some(actual) = r.configuration.get(field) else {
                return Err(anyhow!("SA16Q reader GPIO configuration missing"));
            };
            if actual.get("chip").and_then(Value::as_str) != Some(chip)
                || actual.get("line").and_then(Value::as_u64) != Some(line)
            {
                return Err(anyhow!("SA16Q reader GPIO profile mismatch"));
            }
        }
        return Ok(ReaderLink::Wiegand);
    }
    if r.protocol.eq_ignore_ascii_case("osdp") {
        let Some(address) = r.osdp_address.and_then(|a| u8::try_from(a).ok()).filter(|a| *a <= 126) else {
            return Err(anyhow!("OSDP reader needs a bus address from 0 to 126"));
        };
        if r.configuration.get("transport").and_then(Value::as_str) != Some("rs485") {
            return Err(anyhow!("OSDP reader must use the RS-485 transport"));
        }
        let baud_rate = match r.configuration.get("baud_rate") {
            None | Some(Value::Null) => OSDP_DEFAULT_BAUD_RATE,
            Some(value) => value
                .as_u64()
                .and_then(|b| u32::try_from(b).ok())
                .filter(|b| OSDP_BAUD_RATES.contains(b))
                .ok_or_else(|| anyhow!("OSDP reader line speed is not one this controller supports"))?,
        };
        if r.osdp_secure_channel == Some(true) {
            // Refused rather than run in the clear: there is no way yet to give the
            // controller the reader's key.
            return Err(anyhow!("OSDP secure channel is not supported by this firmware yet"));
        }
        return Ok(ReaderLink::Osdp { address, baud_rate });
    }
    Err(anyhow!("SA16Q reader identity, commissioning or mapping invalid"))
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
    // SA-15M live legacy identity guard: no sealed-storage activation.
    crate::cloud::sa15m_live_identity_gate::enforce_legacy_mode(Path::new(identity_path()))?;
    // SA-15K: same plaintext JSON format and legacy cloud protocol.
    // The new persistence adapter is NOT an encrypted-credential migration.
    crate::cloud::sa15x_startup_router::save_identity(Path::new(identity_path()), identity)
}

fn api_error(envelope: &ApiEnvelope) -> anyhow::Error {
    if let Some(error) = &envelope.error {
        anyhow!("{}: {}", error.code, error.message)
    } else {
        anyhow!("Indagate API request failed")
    }
}

async fn parse_response(response: Response) -> Result<ApiEnvelope> {
    let status = response.status();
    let body = response
        .json::<ApiEnvelope>()
        .await
        .context("decode Indagate API response")?;

    if !status.is_success() || !body.success {
        return Err(api_error(&body));
    }

    Ok(body)
}

pub fn load_identity() -> Result<Option<DeviceIdentity>> {
    // SA-15M live legacy identity guard: no plaintext fallback after marker.
    crate::cloud::sa15m_live_identity_gate::enforce_legacy_mode(Path::new(identity_path()))?;
    crate::cloud::sa15x_startup_router::load_identity(Path::new(identity_path()))
}

fn save_identity(identity: &DeviceIdentity) -> Result<()> {
    // Enrollment and rotation both use the identical fail-closed store.
    save_identity_atomic(identity)
}

/// The shared HTTP client (see `cloud::endpoint`): one connection reused for every call.
fn client() -> Result<Client> {
    super::endpoint::client()
}

pub async fn enroll(enrollment_token: &str, hardware_serial: &str) -> Result<DeviceIdentity> {
    // Refuse unsupported sealed mode BEFORE contacting cloud enrollment.
    crate::cloud::sa15m_live_identity_gate::enforce_legacy_mode(Path::new(identity_path()))?;
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
        .post(format!("{}/v1/enroll", super::endpoint::base_url()?))
        .header("x-indagate-enrollment-token", enrollment_token)
        .header("x-nexus-enrollment-token", enrollment_token)
        .json(&body)
        .send()
        .await
        .context("send Indagate enrollment")?;

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

    crate::cloud::sa16a_identity_lifecycle::persist_enrollment(
        Path::new(identity_path()), &identity,
    )?;

    Ok(identity)
}

async fn authenticated_get(identity: &DeviceIdentity, path: &str) -> Result<ApiEnvelope> {
    let response = client()?
        .get(format!("{}{}", super::endpoint::base_url()?, path))
        .header("x-indagate-device-id", &identity.device_id)
        .header("x-nexus-device-id", &identity.device_id)
        .header("x-indagate-device-secret", &identity.device_secret)
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
        .post(format!("{}{}", super::endpoint::base_url()?, path))
        .header("x-indagate-device-id", &identity.device_id)
        .header("x-nexus-device-id", &identity.device_id)
        .header("x-indagate-device-secret", &identity.device_secret)
        .header("x-nexus-device-secret", &identity.device_secret)
        .json(&body)
        .send()
        .await?;

    parse_response(response).await
}

async fn finalize_pending_credential_rotation(identity: &mut DeviceIdentity) -> Result<bool> {
    // Refuse plaintext credential use if a cutover marker is present.
    crate::cloud::sa15m_live_identity_gate::enforce_legacy_mode(Path::new(identity_path()))?;
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
    .context("commit Indagate device credential rotation")?;

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

    crate::cloud::sa16a_identity_lifecycle::persist_finalized(
        Path::new(identity_path()), identity,
    )?;

    info!(
        target: "indagate_cloud",
        "Indagate device credential rotation committed"
    );

    Ok(true)
}

/// Validate rotation preparation before any durable identity change.
/// Do not include a returned secret in error messages or logs.
fn validate_rotation_prepare(data: &Value) -> Result<(String, String)> {
    let certificate_id = data["certificate_id"]
        .as_str()
        .ok_or_else(|| anyhow!("credential rotation response missing certificate_id"))?;
    let secret = data["device_secret"]
        .as_str()
        .ok_or_else(|| anyhow!("credential rotation response missing device_secret"))?;
    if certificate_id.is_empty()
        || certificate_id.len() > 256
        || certificate_id.chars().any(char::is_control)
    {
        return Err(anyhow!(
            "credential rotation returned invalid certificate identifier"
        ));
    }
    if secret.len() < 32 || secret.len() > 4096 || secret.chars().any(char::is_control) {
        return Err(anyhow!(
            "credential rotation returned invalid device secret"
        ));
    }
    Ok((certificate_id.to_string(), secret.to_string()))
}

/// An unfinished rotation must complete through the existing startup recovery path.
/// In particular, never issue a second prepare with an old in-memory identity.
fn ensure_no_pending_rotation(identity: &DeviceIdentity) -> Result<()> {
    if identity.pending_certificate_id.is_some() || identity.pending_rotation_command_id.is_some() {
        return Err(anyhow!(
            "pending credential rotation requires startup reconciliation"
        ));
    }
    Ok(())
}

async fn rotate_device_credential(
    identity: &DeviceIdentity,
    command_id: &str,
    rotation_journal: &CredentialRotationJournal,
) -> Result<()> {
    // Refuse unsupported storage mode BEFORE requesting a replacement.
    crate::cloud::sa15m_live_identity_gate::enforce_legacy_mode(Path::new(identity_path()))?;
    ensure_no_pending_rotation(identity)?;
    let prepared = authenticated_post(identity, "/v1/credential/rotate/prepare", json!({}))
        .await
        .context("prepare Indagate device credential rotation")?;

    let (certificate_id, device_secret) = validate_rotation_prepare(&prepared.data)?;

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
    crate::cloud::sa16a_identity_lifecycle::persist_prepared(
        Path::new(identity_path()), identity, &candidate, command_id,
    )?;

    //
    // Try to finish immediately.
    //
    // If network/power fails after this point, NEW is already
    // durable and valid. The systemd restart/startup path retries
    // commit and command ACK.
    //
    match finalize_pending_credential_rotation(&mut candidate).await {
        Ok(_) => {
            // The rotation is finished on both sides, so its journal reservation is closed
            // here. Previously only the startup-recovery path did this: after a rotation that
            // completed on the first attempt the reservation stayed open and every later
            // rotation was refused with "another credential rotation requires reconciliation".
            if let Err(e) = rotation_journal.mark_completed(command_id) {
                warn!(error = %e, "Credential rotation finalized but journal reconciliation failed");
            }
            info!(
                target: "indagate_cloud",
                certificate_id = %certificate_id,
                "Device credential rotation complete; restarting Indagate agent"
            );
        }

        Err(e) => {
            warn!(
                target: "indagate_cloud",
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

async fn checkin(identity: &DeviceIdentity, db: &ControllerDatabase) -> Result<Value> {
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

async fn upload_events(identity: &DeviceIdentity, db: &ControllerDatabase) -> Result<()> {
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

fn is_actuator_command(command_type: &str) -> bool {
    matches!(
        command_type,
        "door_hold_open" | "door_lock" | "door_return_to_schedule" | "relay_pulse"
    )
}

fn network_command_requires_protection(command_type: &str) -> bool {
    matches!(command_type, "wifi_disconnect" | "wifi_activate_saved")
}

async fn handle_command(
    identity: &DeviceIdentity,
    command: DeviceCommand,
    relay_tx: &mpsc::Sender<RelayCommand>,
    journal: &NetworkCommandJournal,
    actuator_journal: &mut ActuatorCommandJournal,
    rotation_journal: &mut CredentialRotationJournal,
) -> Result<()> {
    // Guarded commands are never executed, even if journaling or cloud ACK fails.
    // Persist the failure first, then use the retryable outbox.
    if network_command_requires_protection(&command.command_type) {
        journal.record_guarded_rejection(&command.id)?;
        return Ok(());
    }

    let actuator = is_actuator_command(&command.command_type);
    if actuator {
        // The SQLite reservation commits before any actuator operation. A duplicate,
        // including a replay after a crash, never activates the relay again.
        match actuator_journal.reserve(&command.id, &command.command_type, &command.payload)? {
            ReserveResult::New => {}
            ReserveResult::AlreadyReserved => {
                warn!(command_id = %command.id, "Ambiguous actuator command requires reconciliation");
                return Ok(());
            }
            ReserveResult::AlreadyTerminal => return Ok(()),
        }
    }

    // Do not execute a newly reserved actuator command if initial ACK fails.
    // The reserved record remains ambiguous, requiring operator reconciliation.
    acknowledge_command(identity, &command.id, "acknowledged", json!({}), None).await?;

    if command.command_type == "credential_rotate" {
        // Persist this identifier before contacting rotate/prepare.
        // A lost reply or process crash must never trigger another prepare.
        match rotation_journal.reserve(&command.id)? {
            RotationReservation::New => {
                rotate_device_credential(identity, &command.id, rotation_journal).await?
            }
            RotationReservation::AlreadyReserved => {
                warn!(command_id = %command.id, "Credential rotation requires reconciliation; refusing duplicate prepare");
            }
            RotationReservation::AlreadyCompleted => {}
        }
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

            "wifi_profile_preflight" => {
                let profile_name = command.payload["profile_name"]
                    .as_str()
                    .ok_or_else(|| anyhow!("wifi_profile_preflight missing profile_name"))?
                    .to_string();
                tokio::task::spawn_blocking(move || {
                    network_manager::wifi_profile_preflight(&profile_name)
                })
                .await
                .map_err(|e| anyhow!("wifi profile preflight task failed: {}", e))?
            }

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

    if actuator {
        // Always persist the terminal outcome before delivery. ACK failure cannot
        // lead to a second physical actuation on retry.
        actuator_journal.finish(&command.id, &result)?;
        return Ok(());
    }

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

/// Deliver every pending result in the bounded batch, even if an earlier ACK fails.
/// A failure never marks its result delivered; the existing journal retries it.
/// No actuator or network command is executed during delivery.
async fn deliver_ack_batch<T, F, Fut>(items: Vec<T>, mut deliver: F) -> Result<()>
where
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut failed = 0usize;
    for item in items {
        if deliver(item).await.is_err() {
            failed += 1;
        }
    }
    if failed != 0 {
        return Err(anyhow!(
            "{} deferred acknowledgements could not be delivered",
            failed
        ));
    }
    Ok(())
}

async fn flush_actuator_acks(
    identity: &DeviceIdentity,
    journal: &ActuatorCommandJournal,
) -> Result<()> {
    deliver_ack_batch(journal.unreported(25)?, |report| async move {
        acknowledge_command(
            identity,
            &report.command_id,
            &report.state,
            report.result,
            report.failure_reason.as_deref(),
        )
        .await?;
        journal.mark_reported(&report.command_id)?;
        Ok(())
    })
    .await
}

const GUARDED_NETWORK_FAILURE: &str =
    "network configuration command disabled until protected switching is implemented";

async fn flush_guarded_network_acks(
    identity: &DeviceIdentity,
    journal: &NetworkCommandJournal,
) -> Result<()> {
    deliver_ack_batch(
        journal.pending_guarded_rejections(25)?,
        |command_id| async move {
            acknowledge_command(
                identity,
                &command_id,
                "failed",
                json!({}),
                Some(GUARDED_NETWORK_FAILURE),
            )
            .await?;
            journal.mark_guarded_rejection_reported(&command_id)?;
            Ok(())
        },
    )
    .await
}

async fn poll_commands(
    identity: &DeviceIdentity,
    relay_tx: &mpsc::Sender<RelayCommand>,
    journal: &NetworkCommandJournal,
    actuator_journal: &mut ActuatorCommandJournal,
    rotation_journal: &mut CredentialRotationJournal,
) -> Result<()> {
    let envelope = authenticated_get(identity, "/v1/commands").await?;

    let list: CommandList = serde_json::from_value(envelope.data)?;

    for command in list.commands {
        if let Err(e) = handle_command(
            identity,
            command,
            relay_tx,
            journal,
            actuator_journal,
            rotation_journal,
        )
        .await
        {
            warn!(
                error = %e,
                "Indagate command handling failed"
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

    // SA16Q READER POLICY V1: each of the four reader ports keeps its pinned door. A
    // Wiegand reader must be on its port's own pins; an OSDP reader needs its own bus
    // address. Uncommissioned or rewired pins and arbitrary reassignment are refused.
    if config.readers.len() != 4 {
        return Err(anyhow!("SA16Q expected exactly four explicit reader policies"));
    }
    let mut seen_reader_ports = HashSet::new();
    let mut seen_reader_ids = HashSet::new();
    let mut seen_osdp_addresses = HashSet::new();
    let pins = READER_PINS;
    for r in &config.readers {
        if !(1..=4).contains(&r.reader_number) ||
            !seen_reader_ports.insert(r.reader_number) ||
            !seen_reader_ids.insert(r.id.as_str()) ||
            uuid::Uuid::parse_str(&r.id).is_err() ||
            r.door_channel != Some(r.reader_number - 1) ||
            r.enabled.is_none() ||
            r.door_id.as_deref().is_none_or(|x| uuid::Uuid::parse_str(x).is_err())
        {
            return Err(anyhow!("SA16Q reader identity, commissioning or mapping invalid"));
        }
        if let ReaderLink::Osdp { address, .. } = reader_link(r, pins[(r.reader_number - 1) as usize])? {
            if !seen_osdp_addresses.insert(address) {
                return Err(anyhow!("two OSDP readers share a bus address"));
            }
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
    db: &ControllerDatabase,
    version: u64,
    checksum: Option<&str>,
    config: &CloudConfiguration,
) -> Result<()> {
    validate_cloud_configuration(config)?;

    //
    // unchecked_transaction() is intentional here:
    // ControllerDatabase exposes &Connection and the cloud
    // agent owns this connection exclusively.
    //
    let tx = db
        .connection()
        .unchecked_transaction()
        .context("begin cloud configuration transaction")?;

    //
    // Remove relationship rows first.
    //
    // SA16Q READER POLICY V1: replace identities atomically with credentials,
    // schedules and the cloud version. A failed transaction cannot partially
    // activate new or disabled reader policies.
    tx.execute("DELETE FROM reader_config", [])?;
    for reader in &config.readers {
        // Validation has already accepted these settings; working the link out again here
        // keeps what is stored tied to the same rules.
        let link = reader_link(reader, READER_PINS[usize::from(reader.reader_number - 1)])?;
        let (osdp_address, osdp_baud_rate) = match link {
            ReaderLink::Wiegand => (None, None),
            ReaderLink::Osdp { address, baud_rate } => (Some(i64::from(address)), Some(i64::from(baud_rate))),
        };
        tx.execute(
            "INSERT INTO reader_config(reader_number,reader_id,enabled,door_channel,protocol,osdp_address,osdp_baud_rate)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                i64::from(reader.reader_number), &reader.id,
                if reader.enabled == Some(true) { 1i64 } else { 0i64 },
                i64::from(reader.door_channel.ok_or_else(|| anyhow!("reader missing door channel"))?),
                link.protocol(), osdp_address, osdp_baud_rate,
            ],
        )?;
    }

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
    db: &ControllerDatabase,
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
        target: "indagate_cloud",
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
                target: "indagate_cloud",
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
    // SA-15X: fail-closed storage mode check before cloud agent startup.
    // The real runtime remains legacy-only; encrypted preview is lab-only.
    if let Err(e) = crate::cloud::sa15x_startup_router::startup_preflight(Path::new(identity_path())) {
        error!(error = %e, "SA-15X identity storage preflight denied cloud agent startup");
        return;
    }

    // A mis-set cloud address stops the cloud agent (never a silent fallback to another
    // server); local access control is unaffected.
    match super::endpoint::base_url() {
        Ok(url) => info!(target: "indagate_cloud", cloud_url = %url, "Indagate server address"),
        Err(e) => {
            error!(error = %e, "Cloud address is not usable; cloud agent disabled, local access remains operational");
            return;
        }
    }
    if let Err(e) = super::endpoint::client() {
        error!(error = %e, "Cloud connection settings are not usable; cloud agent disabled, local access remains operational");
        return;
    }

    let mut identity = match load_identity() {
        Ok(Some(identity)) => identity,

        Ok(None) => {
            warn!("Indagate cloud agent not enrolled; local access remains operational");
            return;
        }

        Err(e) => {
            error!(
                error = %e,
                "Unable to load Indagate device identity"
            );
            return;
        }
    };

    // SA-15I opt-in metadata-only diagnostic; never reads device_secret.
    // Exact opt-in value required. Default is completely inert.
    // Errors in this diagnostic do not alter existing cloud operation.
    if std::env::var("HLAXS_SA15I_READONLY_AUDIT").ok().as_deref() == Some("lab-only") {
        let view = super::sa15i_identity_bridge::LegacyMetadata {
            device_id: &identity.device_id,
            controller_id: &identity.controller_id,
            pending_certificate_id: identity.pending_certificate_id.as_deref(),
            pending_rotation_command_id: identity.pending_rotation_command_id.as_deref(),
        };
        match super::sa15i_identity_bridge::audit_metadata(view, None) {
            Ok(decision) => info!(
                target: "indagate_cloud",
                pending_recovery = matches!(decision.route, super::sa15i_identity_bridge::RecoveryRoute::PendingReplacementMustCommit),
                synthetic_snapshot_checked = decision.synthetic_snapshot_checked,
                live_migration_permitted = decision.live_migration_permitted,
                "SA-15I read-only identity lifecycle audit (no migration)"
            ),
            Err(_) => warn!(
                target: "indagate_cloud",
                "SA-15I read-only identity metadata validation unavailable; live cloud flow unchanged"
            ),
        }
    }

    // SA-16A: reject malformed durable pending rotation state before networking.
    // Existing startup commit/ACK replay is NOT replaced or bypassed.
    if let Err(e) = crate::cloud::sa16a_identity_lifecycle::validate_startup_state(&identity) {
        error!(error = %e, "SA-16A identity lifecycle validation failed");
        return;
    }

    let db = match ControllerDatabase::open(db_path) {
        Ok(db) => db,

        Err(e) => {
            error!(
                error = %e,
                "Unable to open database for Indagate cloud agent"
            );
            return;
        }
    };

    let journal_path = std::path::PathBuf::from(db_path).with_extension("network-commands.sqlite");
    let network_journal = match NetworkCommandJournal::open(&journal_path) {
        Ok(journal) => journal,
        Err(e) => {
            // Fail closed: never dispatch cloud commands with uncertain journal state.
            error!(error = %e, "Network command journal unavailable; cloud agent disabled");
            return;
        }
    };

    let mut actuator_journal = match ActuatorCommandJournal::open(&journal_path) {
        Ok(journal) => journal,
        Err(e) => {
            error!(error = %e, "Actuator journal unavailable; cloud agent disabled");
            return;
        }
    };
    match actuator_journal.unresolved() {
        Ok(ids) if !ids.is_empty() => {
            warn!(
                count = ids.len(),
                "Interrupted actuator commands require manual reconciliation"
            );
        }
        Err(e) => {
            error!(error = %e, "Actuator reconciliation unavailable; cloud agent disabled");
            return;
        }
        _ => {}
    }

    let mut rotation_journal = match CredentialRotationJournal::open(&journal_path) {
        Ok(journal) => journal,
        Err(e) => {
            error!(error = %e, "Credential rotation journal unavailable; cloud agent disabled");
            return;
        }
    };
    match rotation_journal.unresolved() {
        Ok(ids) if !ids.is_empty() => warn!(
            count = ids.len(),
            "Unresolved credential rotation reservations require reconciliation"
        ),
        Err(e) => {
            error!(error = %e, "Credential rotation reconciliation unavailable; cloud agent disabled");
            return;
        }
        _ => {}
    }

    info!(
        controller_id = %identity.controller_id,
        "Indagate cloud agent started"
    );

    if identity.pending_certificate_id.is_some() {
        warn!(
            target: "indagate_cloud",
            "Pending device credential rotation detected"
        );

        loop {
            // Only after authenticated commit and command ACK succeed may the
            // journal reservation become terminal. The pending identity is the
            // authoritative recovery record for the credential itself.
            let pending_command_id = identity.pending_rotation_command_id.clone();
            match finalize_pending_credential_rotation(&mut identity).await {
                Ok(_) => {
                    if let Some(id) = pending_command_id {
                        if let Err(e) = rotation_journal.mark_completed(&id) {
                            warn!(error = %e, "Credential rotation finalized but journal reconciliation failed");
                        }
                    }
                    break;
                }

                Err(e) => {
                    warn!(
                        target: "indagate_cloud",
                        error = %e,
                        "Unable to finish pending credential rotation; retrying"
                    );

                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    // SA-16N LAB FAST CLOUD POLL: SA-16N CHECKIN GATED SYNC R3; check-in 30s -> 3s (bench), commands/events remain 5s.
    let mut checkin_timer = interval(Duration::from_secs(3));

    let mut command_timer = interval(Duration::from_secs(5));

    let mut event_timer = interval(Duration::from_secs(5));

    checkin_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    command_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    event_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Push stream: the server can say "there is work" between timer ticks. It only chooses
    // which of the existing steps runs next; with no stream the timers below do everything.
    let (nudge_tx, mut nudge_rx) = mpsc::channel::<super::endpoint::Nudge>(8);
    let mut push_open = super::endpoint::push_enabled();
    if push_open {
        tokio::spawn(super::endpoint::run_stream(
            identity.device_id.clone(),
            identity.device_secret.clone(),
            nudge_tx,
        ));
    } else {
        info!(target: "indagate_cloud", "Push stream disabled by INDAGATE_SERVER_PUSH; using timed polling only");
    }

    enum Work {
        Checkin,
        Commands,
        Events,
    }

    loop {
        let work = tokio::select! {
            _ = checkin_timer.tick() => Work::Checkin,
            _ = command_timer.tick() => Work::Commands,
            _ = event_timer.tick() => Work::Events,
            nudge = nudge_rx.recv(), if push_open => match nudge {
                Some(super::endpoint::Nudge::Config) => Work::Checkin,
                Some(super::endpoint::Nudge::Commands) => Work::Commands,
                None => {
                    // The stream task has ended; carry on with the timers alone.
                    push_open = false;
                    continue;
                }
            },
        };

        match work {
            Work::Checkin => {
                match checkin(&identity, &db).await {
                    Ok(data) => {
                        info!(
                            target: "indagate_cloud",
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

            Work::Commands => {
                if let Err(e) = flush_actuator_acks(&identity, &actuator_journal).await {
                    warn!(error = %e, "Deferred actuator acknowledgement failed");
                }
                if let Err(e) = flush_guarded_network_acks(&identity, &network_journal).await {
                    warn!(error = %e, "Deferred network rejection acknowledgement failed");
                }

                if let Err(e) =
                    poll_commands(
                        &identity,
                        &relay_tx,
                        &network_journal,
                        &mut actuator_journal,
                        &mut rotation_journal,
                    )
                    .await
                {
                    warn!(
                        error = %e,
                        "Cloud command poll failed"
                    );
                }
            }

            Work::Events => {
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
mod reader_link_tests {
    use super::*;
    use serde_json::json;

    const PORT_ONE: ((&str, u64), (&str, u64)) = READER_PINS[0];

    fn reader(extra: Value) -> CloudReader {
        let mut base = json!({
            "id": "11111111-1111-4111-8111-111111111111",
            "reader_number": 1,
            "door_channel": 0,
            "door_id": "22222222-2222-4222-8222-222222222222",
            "enabled": true,
        });
        base.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    fn wiegand() -> Value {
        json!({
            "protocol": "wiegand",
            "configuration": {
                "validated": true, "format": "Wiegand-26",
                "d0": { "chip": "gpiochip3", "line": 23 }, "d1": { "chip": "gpiochip3", "line": 25 }
            }
        })
    }

    fn osdp(address: Value, configuration: Value) -> Value {
        json!({ "protocol": "osdp", "osdp_address": address, "osdp_secure_channel": false, "configuration": configuration })
    }

    #[test]
    fn a_wiegand_reader_on_its_own_pins_is_accepted_as_before() {
        assert_eq!(reader_link(&reader(wiegand()), PORT_ONE).unwrap(), ReaderLink::Wiegand);
        // The settings the server sends for a Wiegand reader carry no OSDP fields at all.
        let without_osdp_fields: CloudReader = serde_json::from_value(json!({
            "id": "11111111-1111-4111-8111-111111111111", "reader_number": 1, "door_channel": 0,
            "door_id": "22222222-2222-4222-8222-222222222222", "enabled": true,
            "protocol": "wiegand", "configuration": wiegand()["configuration"],
        }))
        .unwrap();
        assert_eq!(reader_link(&without_osdp_fields, PORT_ONE).unwrap(), ReaderLink::Wiegand);
    }

    #[test]
    fn a_wiegand_reader_on_the_wrong_pins_or_uncommissioned_is_refused() {
        let mut moved = wiegand();
        moved["configuration"]["d0"]["line"] = json!(24);
        assert!(reader_link(&reader(moved), PORT_ONE).is_err());
        let mut uncommissioned = wiegand();
        uncommissioned["configuration"]["validated"] = json!(false);
        assert!(reader_link(&reader(uncommissioned), PORT_ONE).is_err());
        let mut other_format = wiegand();
        other_format["configuration"]["format"] = json!("Wiegand-34");
        assert!(reader_link(&reader(other_format), PORT_ONE).is_err());
    }

    #[test]
    fn an_osdp_reader_needs_an_address_and_the_rs485_transport() {
        let rs485 = json!({ "transport": "rs485" });
        assert_eq!(
            reader_link(&reader(osdp(json!(7), rs485.clone())), PORT_ONE).unwrap(),
            ReaderLink::Osdp { address: 7, baud_rate: 9600 }
        );
        assert_eq!(
            reader_link(&reader(osdp(json!(126), json!({ "transport": "rs485", "baud_rate": 115200 }))), PORT_ONE).unwrap(),
            ReaderLink::Osdp { address: 126, baud_rate: 115200 }
        );
        for bad_address in [json!(null), json!(127), json!(-1), json!(300)] {
            assert!(reader_link(&reader(osdp(bad_address.clone(), rs485.clone())), PORT_ONE).is_err(), "{bad_address}");
        }
        assert!(reader_link(&reader(osdp(json!(7), json!({}))), PORT_ONE).is_err());
        assert!(reader_link(&reader(osdp(json!(7), json!({ "transport": "rs485", "baud_rate": 1200 }))), PORT_ONE).is_err());
        assert!(reader_link(&reader(osdp(json!(7), json!({ "transport": "rs485", "baud_rate": "fast" }))), PORT_ONE).is_err());
    }

    #[test]
    fn secure_channel_is_refused_rather_than_run_in_the_clear() {
        let mut secure = osdp(json!(7), json!({ "transport": "rs485" }));
        secure["osdp_secure_channel"] = json!(true);
        let error = reader_link(&reader(secure), PORT_ONE).unwrap_err().to_string();
        assert!(error.contains("secure channel"), "{error}");
    }

    #[test]
    fn an_unknown_protocol_is_refused() {
        let unknown = json!({ "protocol": "clock-and-data", "configuration": {} });
        assert!(reader_link(&reader(unknown), PORT_ONE).is_err());
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

#[cfg(test)]
mod deferred_ack_delivery_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn failed_first_ack_does_not_starve_later_results() {
        let delivered = Arc::new(Mutex::new(Vec::<u32>::new()));
        let seen = Arc::clone(&delivered);
        let result = deliver_ack_batch(vec![1u32, 2, 3], move |id| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock().unwrap().push(id);
                if id == 1 {
                    Err(anyhow!("mock HTTP failure"))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(*delivered.lock().unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn all_successful_acks_complete_batch() {
        let result = deliver_ack_batch(vec![1u32, 2, 3], |_id| async { Ok(()) }).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn all_failed_acks_return_batch_error() {
        let attempted = Arc::new(Mutex::new(0usize));
        let seen = Arc::clone(&attempted);
        let result = deliver_ack_batch(vec![1u32, 2], move |_id| {
            let seen = Arc::clone(&seen);
            async move {
                *seen.lock().unwrap() += 1;
                Err(anyhow!("mock delivery failure"))
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(*attempted.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn empty_ack_batch_is_successful() {
        let result = deliver_ack_batch(Vec::<u32>::new(), |_id| async { Ok(()) }).await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod credential_rotation_safety_tests {
    use super::*;

    fn example_identity() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "device_test".into(),
            controller_id: "controller_test".into(),
            organization_id: "organization_test".into(),
            site_id: "site_test".into(),
            device_secret: "old_secret_for_testing_only_000000000".into(),
            hardware_profile: "ACP4WR6-R1".into(),
            pending_certificate_id: None,
            pending_rotation_command_id: None,
        }
    }

    #[test]
    fn accepts_well_formed_rotation_prepare() {
        let data = json!({
            "certificate_id": "cert_123",
            "device_secret": "abcdefghijklmnopqrstuvwxyz012345"
        });
        let (cert, secret) = validate_rotation_prepare(&data).unwrap();
        assert_eq!(cert, "cert_123");
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn rejects_missing_prepare_fields() {
        assert!(validate_rotation_prepare(&json!({})).is_err());
        assert!(validate_rotation_prepare(&json!({"certificate_id":"cert"})).is_err());
    }

    #[test]
    fn rejects_invalid_certificate_id() {
        let secret = "a".repeat(32);
        for bad in ["".to_string(), "x".repeat(257), "cert\nnew".into()] {
            assert!(
                validate_rotation_prepare(&json!({"certificate_id":bad,"device_secret":secret}))
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_invalid_secret_without_leaking_it() {
        for bad in [
            "short".to_string(),
            "a".repeat(4097),
            format!("{}\n", "a".repeat(32)),
        ] {
            let error =
                validate_rotation_prepare(&json!({"certificate_id":"cert","device_secret":bad}))
                    .unwrap_err();
            assert_eq!(
                error.to_string(),
                "credential rotation returned invalid device secret"
            );
        }
    }

    #[test]
    fn rejects_pending_rotation_without_repreparing() {
        let mut identity = example_identity();
        identity.pending_certificate_id = Some("pending_cert".into());
        assert!(ensure_no_pending_rotation(&identity).is_err());
        identity.pending_certificate_id = None;
        identity.pending_rotation_command_id = Some("pending_command".into());
        assert!(ensure_no_pending_rotation(&identity).is_err());
    }

    #[test]
    fn permits_rotation_when_no_pending_state() {
        assert!(ensure_no_pending_rotation(&example_identity()).is_ok());
    }
}

#[cfg(test)]
mod live_server_tests {
    //! Exercises this agent's own request code against a running cloud server.
    //!
    //! Ignored in a normal test run. To run it, start a server and set
    //! `INDAGATE_SERVER_URL` (or `NEXUS_CLOUD_URL`), `NEXUS_TEST_DEVICE_ID` and `NEXUS_TEST_DEVICE_SECRET` for an enrolled
    //! controller that has at least one command waiting, then:
    //!
    //! ```text
    //! cargo test --bin highline-nexus-controller live_server -- --ignored --nocapture
    //! ```
    //!
    //! It touches no hardware, no identity file and no local database.
    use super::*;
    use crate::cloud::endpoint::{Nudge, run_stream};

    fn test_identity() -> DeviceIdentity {
        let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the live test"));
        DeviceIdentity {
            device_id: var("NEXUS_TEST_DEVICE_ID"),
            controller_id: "live-test".into(),
            organization_id: "live-test".into(),
            site_id: "live-test".into(),
            device_secret: var("NEXUS_TEST_DEVICE_SECRET"),
            hardware_profile: "HNX-HW-SP-ACP4WR6-R1".into(),
            pending_certificate_id: None,
            pending_rotation_command_id: None,
        }
    }

    #[tokio::test]
    #[ignore = "needs a running server; see the module comment"]
    async fn firmware_client_round_trip() {
        let identity = test_identity();
        println!("cloud address: {}", crate::cloud::endpoint::base_url().unwrap());

        // Push stream: work already waiting is announced as soon as the stream opens.
        let (tx, mut rx) = mpsc::channel(8);
        let stream = tokio::spawn(run_stream(identity.device_id.clone(), identity.device_secret.clone(), tx));
        let mut seen = Vec::new();
        while seen.len() < 2 {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(nudge)) => seen.push(nudge),
                _ => break,
            }
        }
        println!("nudges received on the push stream: {seen:?}");
        assert!(seen.contains(&Nudge::Commands), "expected a commands nudge, got {seen:?}");

        // Check-in, in the shape this agent sends.
        let checkin = authenticated_post(
            &identity,
            "/v1/checkin",
            json!({
                "software": { "agent_version": env!("CARGO_PKG_VERSION"), "firmware_version": "live-test" },
                "configuration": { "applied_version": 0 }
            }),
        )
        .await
        .expect("check-in");
        assert!(checkin.data["config_update_available"].is_boolean(), "check-in reply: {}", checkin.data);

        // Configuration: the reply must have the shape this agent deserializes.
        let config = authenticated_get(&identity, "/v1/config").await.expect("fetch configuration");
        assert!(config.data["version"].as_u64().is_some(), "version must be an unsigned integer");
        let parsed: CloudConfiguration =
            serde_json::from_value(config.data["configuration"].clone()).expect("configuration shape");
        println!(
            "configuration v{} has {} doors and {} readers; local validation: {}",
            config.data["version"],
            parsed.doors.len(),
            parsed.readers.len(),
            match validate_cloud_configuration(&parsed) {
                Ok(()) => "accepted".to_string(),
                Err(e) => format!("rejected ({e})"),
            }
        );

        // Commands: fetch, acknowledge, complete, exactly as the agent loop does.
        let list = authenticated_get(&identity, "/v1/commands").await.expect("fetch commands");
        let commands: CommandList = serde_json::from_value(list.data).expect("command list shape");
        assert!(!commands.commands.is_empty(), "the test needs a command waiting");
        for command in &commands.commands {
            println!("command {} of type {}", command.id, command.command_type);
            acknowledge_command(&identity, &command.id, "acknowledged", json!({}), None).await.expect("acknowledge");
            acknowledge_command(&identity, &command.id, "completed", json!({ "message": "live test" }), None)
                .await
                .expect("complete");
        }
        // A command is handed over once only.
        let again = authenticated_get(&identity, "/v1/commands").await.expect("fetch commands again");
        let again: CommandList = serde_json::from_value(again.data).expect("command list shape");
        assert!(again.commands.is_empty(), "commands were delivered twice");

        // A wrong secret is reported with the server's error code, as the agent logs it.
        let mut wrong = identity.clone();
        wrong.device_secret = format!("HNXD_{}", "0".repeat(64));
        let error = authenticated_get(&wrong, "/v1/commands").await.expect_err("wrong secret must fail");
        assert!(error.to_string().starts_with("DEVICE_UNAUTHORIZED"), "unexpected error: {error}");

        stream.abort();
    }
}
