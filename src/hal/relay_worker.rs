use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, MissedTickBehavior, interval};
use tracing::{error, info, warn};

use super::relay::RelayController;

const OVERRIDE_PATH: &str = "/var/lib/highline-nexus/door-overrides.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DoorOverrideMode {
    HoldUnlocked,
    ForceLocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDoorOverride {
    mode: DoorOverrideMode,

    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedOverrideFile {
    #[serde(default)]
    doors: [Option<PersistedDoorOverride>; 4],
}

impl Default for PersistedOverrideFile {
    fn default() -> Self {
        Self {
            doors: [None, None, None, None],
        }
    }
}

#[derive(Debug)]
pub enum RelayCommand {
    Pulse {
        channel: u8,
        duration_ms: u64,
        response: Option<oneshot::Sender<Result<(), String>>>,
    },

    //
    // Current state requested by the normal schedule engine.
    //
    On {
        channel: u8,
    },

    Off {
        channel: u8,
    },

    //
    // Persistent operator/admin modes.
    //
    SetOverride {
        channel: u8,
        mode: DoorOverrideMode,
        expires_at: Option<DateTime<Utc>>,
        response: oneshot::Sender<Result<(), String>>,
    },

    ClearOverride {
        channel: u8,
        response: oneshot::Sender<Result<(), String>>,
    },

    //
    // Global life-safety override.
    //
    FireOverride {
        active: bool,
    },
}

fn valid_channel(channel: u8) -> bool {
    channel < 4
}

fn load_overrides() -> PersistedOverrideFile {
    let path = Path::new(OVERRIDE_PATH);

    if !path.exists() {
        return PersistedOverrideFile::default();
    }

    match fs::read(path)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| {
            serde_json::from_slice::<PersistedOverrideFile>(&bytes).map_err(anyhow::Error::from)
        }) {
        Ok(mut file) => {
            let now = Utc::now();

            for item in &mut file.doors {
                let expired = item
                    .as_ref()
                    .and_then(|entry| entry.expires_at)
                    .map(|expiry| expiry <= now)
                    .unwrap_or(false);

                if expired {
                    *item = None;
                }
            }

            file
        }

        Err(e) => {
            error!(
                target: "indagate_relay",
                error = %e,
                "Unable to load door overrides; using normal schedule"
            );

            PersistedOverrideFile::default()
        }
    }
}

fn save_overrides(file: &PersistedOverrideFile) -> Result<()> {
    let target = Path::new(OVERRIDE_PATH);

    let temp = Path::new("/var/lib/highline-nexus/door-overrides.json.next");

    fs::create_dir_all(
        target
            .parent()
            .ok_or_else(|| anyhow!("door override path has no parent"))?,
    )?;

    let encoded = serde_json::to_vec_pretty(file)?;

    let mut output = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(temp)?;

    output.write_all(&encoded)?;
    output.sync_all()?;
    drop(output);

    fs::rename(temp, target)?;

    if let Some(parent) = target.parent() {
        fs::File::open(parent)?.sync_all()?;
    }

    Ok(())
}

fn effective_normal_state(
    channel: u8,
    schedule_state: &[bool; 4],
    overrides: &PersistedOverrideFile,
) -> bool {
    match overrides.doors[channel as usize].as_ref() {
        Some(entry) => match entry.mode {
            DoorOverrideMode::HoldUnlocked => true,
            DoorOverrideMode::ForceLocked => false,
        },

        None => schedule_state[channel as usize],
    }
}

fn desired_physical_state(
    channel: u8,
    fire_active: bool,
    schedule_state: &[bool; 4],
    overrides: &PersistedOverrideFile,
) -> bool {
    let normal = effective_normal_state(channel, schedule_state, overrides);

    //
    // Preserve the controller's already-proven fire behavior:
    // fire reverses the effective normal relay state.
    //
    if fire_active { !normal } else { normal }
}

fn override_expired(entry: &PersistedDoorOverride) -> bool {
    entry
        .expires_at
        .map(|expiry| expiry <= Utc::now())
        .unwrap_or(false)
}

pub async fn run(mut receiver: mpsc::Receiver<RelayCommand>) {
    let relay = RelayController::new();

    //
    // What the unlock schedule currently requests.
    //
    let mut schedule_state = [false; 4];

    //
    // Persistent hold-open / force-lock state.
    //
    let mut overrides = load_overrides();

    //
    // Active momentary unlock timers.
    //
    let mut deadlines: [Option<Instant>; 4] = [None, None, None, None];

    let mut fire_active = false;

    let mut ticker = interval(Duration::from_millis(50));

    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!("Indagate relay command worker started");

    //
    // Do NOT actuate persistent state here.
    //
    // main.rs queues an already-active fire condition before
    // the relay worker runs, and the schedule controller performs
    // an initial evaluation for every door. This prevents an
    // override from briefly actuating ahead of an active fire.
    //

    loop {
        tokio::select! {
            command = receiver.recv() => {
                let Some(command) = command else {
                    warn!(
                        "Relay command channel closed"
                    );

                    //
                    // Fail secure on worker shutdown.
                    //
                    for channel in 0u8..4 {
                        if let Err(e) =
                            relay.set(
                                channel,
                                false,
                            )
                        {
                            error!(
                                channel = channel,
                                error = %e,
                                "Unable to turn relay off during worker shutdown"
                            );
                        }
                    }

                    return;
                };

                match command {
                    RelayCommand::FireOverride {
                        active,
                    } => {
                        if active && !fire_active {
                            info!(
                                target: "indagate_fire",
                                "FIRE OVERRIDE ACTIVE"
                            );

                            //
                            // A life-safety event cancels any
                            // momentary pulse in progress.
                            //
                            deadlines =
                                [
                                    None,
                                    None,
                                    None,
                                    None,
                                ];

                            fire_active = true;

                            for channel in 0u8..4 {
                                let normal =
                                    effective_normal_state(
                                        channel,
                                        &schedule_state,
                                        &overrides,
                                    );

                                let desired =
                                    desired_physical_state(
                                        channel,
                                        true,
                                        &schedule_state,
                                        &overrides,
                                    );

                                match relay.set(
                                    channel,
                                    desired,
                                ) {
                                    Ok(state) => {
                                        info!(
                                            target: "indagate_fire",
                                            channel = channel,
                                            previous_normal_state =
                                                normal,
                                            fire_state =
                                                desired,
                                            backend =
                                                ?state.backend,
                                            "Relay reversed for fire alarm"
                                        );
                                    }

                                    Err(e) => {
                                        error!(
                                            target: "indagate_fire",
                                            channel = channel,
                                            error = %e,
                                            "Unable to apply fire relay state"
                                        );
                                    }
                                }
                            }
                        }

                        if !active && fire_active {
                            info!(
                                target: "indagate_fire",
                                "FIRE OVERRIDE CLEARED"
                            );

                            fire_active = false;

                            //
                            // Return to CURRENT effective state:
                            // persistent override if present,
                            // otherwise current schedule state.
                            //
                            for channel in 0u8..4 {
                                let desired =
                                    desired_physical_state(
                                        channel,
                                        false,
                                        &schedule_state,
                                        &overrides,
                                    );

                                match relay.set(
                                    channel,
                                    desired,
                                ) {
                                    Ok(state) => {
                                        info!(
                                            target: "indagate_fire",
                                            channel = channel,
                                            restored_state =
                                                desired,
                                            backend =
                                                ?state.backend,
                                            "Relay restored after fire alarm"
                                        );
                                    }

                                    Err(e) => {
                                        error!(
                                            target: "indagate_fire",
                                            channel = channel,
                                            error = %e,
                                            "Unable to restore relay after fire"
                                        );
                                    }
                                }
                            }
                        }
                    }

                    RelayCommand::Pulse {
                        channel,
                        duration_ms,
                        response,
                    } => {
                        if !valid_channel(
                            channel,
                        ) {
                            warn!(
                                channel = channel,
                                "Rejected invalid relay pulse channel"
                            );

                            if let Some(response) = response {
                                let _ = response.send(
                                    Err("invalid relay channel".to_string())
                                );
                            }

                            continue;
                        }

                        //
                        // Fire always wins.
                        //
                        if fire_active {
                            warn!(
                                target: "indagate_relay",
                                channel = channel,
                                "Relay pulse ignored during fire override"
                            );

                            if let Some(response) = response {
                                let _ = response.send(
                                    Err("relay pulse suppressed by active fire override".to_string())
                                );
                            }

                            continue;
                        }

                        //
                        // Persistent force-lock always wins over
                        // card, REX and remote momentary unlock.
                        //
                        if matches!(
                            overrides.doors[
                                channel as usize
                            ]
                            .as_ref()
                            .map(|entry| entry.mode),
                            Some(
                                DoorOverrideMode::
                                    ForceLocked
                            )
                        ) {
                            warn!(
                                target: "indagate_relay",
                                channel = channel,
                                "Relay pulse suppressed by force-lock override"
                            );

                            if let Some(response) = response {
                                let _ = response.send(
                                    Err("relay pulse suppressed by force-lock override".to_string())
                                );
                            }

                            continue;
                        }

                        //
                        // Already continuously unlocked.
                        //
                        if matches!(
                            overrides.doors[
                                channel as usize
                            ]
                            .as_ref()
                            .map(|entry| entry.mode),
                            Some(
                                DoorOverrideMode::
                                    HoldUnlocked
                            )
                        ) {
                            info!(
                                target: "indagate_relay",
                                channel = channel,
                                "Relay pulse unnecessary during hold-unlocked override"
                            );

                            if let Some(response) = response {
                                let _ = response.send(Ok(()));
                            }

                            continue;
                        }

                        match relay.set(
                            channel,
                            true,
                        ) {
                            Ok(state) => {
                                deadlines[
                                    channel as usize
                                ] = Some(
                                    Instant::now()
                                        + Duration::from_millis(
                                            duration_ms,
                                        ),
                                );

                                info!(
                                    target: "indagate_relay",
                                    event =
                                        "relay_on",
                                    channel =
                                        channel,
                                    duration_ms =
                                        duration_ms,
                                    backend =
                                        ?state.backend,
                                    "Timed relay activated"
                                );

                                if let Some(response) = response {
                                    let _ = response.send(Ok(()));
                                }
                            }

                            Err(e) => {
                                error!(
                                    target: "indagate_relay",
                                    channel =
                                        channel,
                                    error = %e,
                                    "Timed relay activation failed"
                                );

                                if let Some(response) = response {
                                    let _ = response.send(
                                        Err(e.to_string())
                                    );
                                }
                            }
                        }
                    }

                    RelayCommand::On {
                        channel,
                    } => {
                        if !valid_channel(
                            channel,
                        ) {
                            warn!(
                                channel = channel,
                                "Rejected invalid relay ON channel"
                            );

                            continue;
                        }

                        //
                        // Always update schedule truth, even when
                        // another mode currently has precedence.
                        //
                        schedule_state[
                            channel as usize
                        ] = true;

                        deadlines[
                            channel as usize
                        ] = None;

                        let desired =
                            desired_physical_state(
                                channel,
                                fire_active,
                                &schedule_state,
                                &overrides,
                            );

                        match relay.set(
                            channel,
                            desired,
                        ) {
                            Ok(state) => {
                                info!(
                                    target: "indagate_relay",
                                    event =
                                        "relay_schedule_reconciled",
                                    channel =
                                        channel,
                                    schedule_state =
                                        true,
                                    desired =
                                        desired,
                                    fire_active =
                                        fire_active,
                                    override_active =
                                        overrides.doors[
                                            channel as usize
                                        ].is_some(),
                                    backend =
                                        ?state.backend,
                                    "Relay state reconciled after schedule ON"
                                );
                            }

                            Err(e) => {
                                error!(
                                    target: "indagate_relay",
                                    channel =
                                        channel,
                                    error = %e,
                                    "Scheduled relay ON reconciliation failed"
                                );
                            }
                        }
                    }

                    RelayCommand::Off {
                        channel,
                    } => {
                        if !valid_channel(
                            channel,
                        ) {
                            warn!(
                                channel = channel,
                                "Rejected invalid relay OFF channel"
                            );

                            continue;
                        }

                        schedule_state[
                            channel as usize
                        ] = false;

                        deadlines[
                            channel as usize
                        ] = None;

                        let desired =
                            desired_physical_state(
                                channel,
                                fire_active,
                                &schedule_state,
                                &overrides,
                            );

                        match relay.set(
                            channel,
                            desired,
                        ) {
                            Ok(state) => {
                                info!(
                                    target: "indagate_relay",
                                    event =
                                        "relay_schedule_reconciled",
                                    channel =
                                        channel,
                                    schedule_state =
                                        false,
                                    desired =
                                        desired,
                                    fire_active =
                                        fire_active,
                                    override_active =
                                        overrides.doors[
                                            channel as usize
                                        ].is_some(),
                                    backend =
                                        ?state.backend,
                                    "Relay state reconciled after schedule OFF"
                                );
                            }

                            Err(e) => {
                                error!(
                                    target: "indagate_relay",
                                    channel =
                                        channel,
                                    error = %e,
                                    "Scheduled relay OFF reconciliation failed"
                                );
                            }
                        }
                    }

                    RelayCommand::SetOverride {
                        channel,
                        mode,
                        expires_at,
                        response,
                    } => {
                        let result = async {
                            if !valid_channel(
                                channel,
                            ) {
                                return Err(
                                    "invalid relay channel"
                                        .to_string(),
                                );
                            }

                            if expires_at
                                .map(
                                    |expiry| {
                                        expiry
                                            <= Utc::now()
                                    },
                                )
                                .unwrap_or(false)
                            {
                                return Err(
                                    "override expiry must be in the future"
                                        .to_string(),
                                );
                            }

                            let previous =
                                overrides.doors[
                                    channel as usize
                                ]
                                .clone();

                            overrides.doors[
                                channel as usize
                            ] = Some(
                                PersistedDoorOverride {
                                    mode,
                                    expires_at,
                                },
                            );

                            //
                            // Persist before hardware actuation.
                            //
                            if let Err(e) =
                                save_overrides(
                                    &overrides,
                                )
                            {
                                overrides.doors[
                                    channel as usize
                                ] = previous;

                                return Err(
                                    format!(
                                        "persist override: {e}"
                                    ),
                                );
                            }

                            deadlines[
                                channel as usize
                            ] = None;

                            let desired =
                                desired_physical_state(
                                    channel,
                                    fire_active,
                                    &schedule_state,
                                    &overrides,
                                );

                            //
                            // If physical application fails, roll
                            // the persisted override back too.
                            //
                            if let Err(e) =
                                relay.set(
                                    channel,
                                    desired,
                                )
                            {
                                overrides.doors[
                                    channel as usize
                                ] = previous;

                                if let Err(
                                    rollback_error,
                                ) =
                                    save_overrides(
                                        &overrides,
                                    )
                                {
                                    error!(
                                        target:
                                            "nexus_relay",
                                        channel =
                                            channel,
                                        error =
                                            %rollback_error,
                                        "Unable to persist override rollback"
                                    );
                                }

                                return Err(
                                    e.to_string(),
                                );
                            }

                            info!(
                                target: "indagate_relay",
                                event =
                                    "door_override_set",
                                channel =
                                    channel,
                                mode = ?mode,
                                desired =
                                    desired,
                                fire_active =
                                    fire_active,
                                expires_at =
                                    ?expires_at,
                                "Persistent door override applied"
                            );

                            Ok(())
                        }
                        .await;

                        let _ =
                            response.send(result);
                    }

                    RelayCommand::ClearOverride {
                        channel,
                        response,
                    } => {
                        let result = async {
                            if !valid_channel(
                                channel,
                            ) {
                                return Err(
                                    "invalid relay channel"
                                        .to_string(),
                                );
                            }

                            let previous =
                                overrides.doors[
                                    channel as usize
                                ]
                                .clone();

                            overrides.doors[
                                channel as usize
                            ] = None;

                            if let Err(e) =
                                save_overrides(
                                    &overrides,
                                )
                            {
                                overrides.doors[
                                    channel as usize
                                ] = previous;

                                return Err(
                                    format!(
                                        "persist override clear: {e}"
                                    ),
                                );
                            }

                            deadlines[
                                channel as usize
                            ] = None;

                            let desired =
                                desired_physical_state(
                                    channel,
                                    fire_active,
                                    &schedule_state,
                                    &overrides,
                                );

                            if let Err(e) =
                                relay.set(
                                    channel,
                                    desired,
                                )
                            {
                                overrides.doors[
                                    channel as usize
                                ] = previous;

                                if let Err(
                                    rollback_error,
                                ) =
                                    save_overrides(
                                        &overrides,
                                    )
                                {
                                    error!(
                                        target:
                                            "nexus_relay",
                                        channel =
                                            channel,
                                        error =
                                            %rollback_error,
                                        "Unable to persist override-clear rollback"
                                    );
                                }

                                return Err(
                                    e.to_string(),
                                );
                            }

                            info!(
                                target: "indagate_relay",
                                event =
                                    "door_override_cleared",
                                channel =
                                    channel,
                                restored_state =
                                    desired,
                                fire_active =
                                    fire_active,
                                "Door returned to schedule"
                            );

                            Ok(())
                        }
                        .await;

                        let _ =
                            response.send(result);
                    }
                }
            }

            _ = ticker.tick() => {
                //
                // First expire persistent overrides.
                //
                let mut persistence_changed =
                    false;

                for channel in 0u8..4 {
                    let expired =
                        overrides.doors[
                            channel as usize
                        ]
                        .as_ref()
                        .map(
                            override_expired,
                        )
                        .unwrap_or(false);

                    if !expired {
                        continue;
                    }

                    overrides.doors[
                        channel as usize
                    ] = None;

                    deadlines[
                        channel as usize
                    ] = None;

                    persistence_changed =
                        true;

                    let desired =
                        desired_physical_state(
                            channel,
                            fire_active,
                            &schedule_state,
                            &overrides,
                        );

                    match relay.set(
                        channel,
                        desired,
                    ) {
                        Ok(state) => {
                            info!(
                                target: "indagate_relay",
                                event =
                                    "door_override_expired",
                                channel =
                                    channel,
                                desired =
                                    desired,
                                fire_active =
                                    fire_active,
                                backend =
                                    ?state.backend,
                                "Persistent door override expired"
                            );
                        }

                        Err(e) => {
                            error!(
                                target: "indagate_relay",
                                channel =
                                    channel,
                                error = %e,
                                "Unable to reconcile relay after override expiry"
                            );
                        }
                    }
                }

                if persistence_changed {
                    if let Err(e) =
                        save_overrides(
                            &overrides,
                        )
                    {
                        error!(
                            target: "indagate_relay",
                            error = %e,
                            "Unable to persist expired override cleanup"
                        );
                    }
                }

                //
                // Fire cancels pulse deadlines when it activates,
                // so no timed completion should execute during fire.
                //
                if fire_active {
                    continue;
                }

                let now =
                    Instant::now();

                for channel in 0u8..4 {
                    let Some(deadline) =
                        deadlines[
                            channel as usize
                        ]
                    else {
                        continue;
                    };

                    if now < deadline {
                        continue;
                    }

                    let desired =
                        desired_physical_state(
                            channel,
                            false,
                            &schedule_state,
                            &overrides,
                        );

                    match relay.set(
                        channel,
                        desired,
                    ) {
                        Ok(state) => {
                            deadlines[
                                channel as usize
                            ] = None;

                            info!(
                                target: "indagate_relay",
                                event =
                                    "relay_pulse_complete",
                                channel =
                                    channel,
                                restored_state =
                                    desired,
                                backend =
                                    ?state.backend,
                                "Timed relay command completed"
                            );
                        }

                        Err(e) => {
                            error!(
                                target: "indagate_relay",
                                channel =
                                    channel,
                                error = %e,
                                "Timed relay completion failed; will retry"
                            );
                        }
                    }
                }
            }
        }
    }
}
