use chrono::Utc;
use rusqlite::params;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::hal::relay_worker::RelayCommand;
use crate::storage::NexusDatabase;

use super::schedule;

fn queue_event(db: &NexusDatabase, event_type: &str, channel: u8, payload: serde_json::Value) {
    let result = db.connection().execute(
        r#"
        INSERT INTO event_queue
        (
            id,
            event_type,
            channel,
            payload_json,
            occurred_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            Uuid::new_v4().to_string(),
            event_type,
            channel,
            payload.to_string(),
            Utc::now().to_rfc3339(),
        ],
    );

    if let Err(e) = result {
        warn!(
            channel = channel,
            error = %e,
            "Unable to queue scheduled-unlock event"
        );
    }
}

fn desired_state(db: &NexusDatabase, channel: u8) -> Result<bool, anyhow::Error> {
    use rusqlite::OptionalExtension;

    let schedule_id = db
        .connection()
        .query_row(
            r#"
            SELECT unlock_schedule_id
            FROM door_config
            WHERE channel = ?1
              AND enabled = 1
            "#,
            [channel],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();

    let Some(schedule_id) = schedule_id else {
        return Ok(false);
    };

    schedule::is_schedule_active(db.connection(), &schedule_id)
}

pub async fn run(db_path: &str, relay_tx: mpsc::Sender<RelayCommand>) {
    let db = match NexusDatabase::open(db_path) {
        Ok(db) => db,

        Err(e) => {
            error!(
                error = %e,
                "Unable to open database for scheduled unlock controller"
            );
            return;
        }
    };

    // None forces initial evaluation for every door.
    let mut last_desired: [Option<bool>; 4] = [None, None, None, None];

    let mut ticker = interval(Duration::from_secs(2));

    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!("Scheduled door-unlock controller started");

    loop {
        ticker.tick().await;

        for channel in 0u8..4 {
            let desired = match desired_state(&db, channel) {
                Ok(value) => value,

                Err(e) => {
                    error!(
                        channel = channel,
                        error = %e,
                        "Unable to evaluate door unlock schedule"
                    );

                    // Fail closed.
                    false
                }
            };

            if last_desired[channel as usize] == Some(desired) {
                continue;
            }

            let command = if desired {
                RelayCommand::On { channel }
            } else {
                RelayCommand::Off { channel }
            };

            match relay_tx.send(command).await {
                Ok(()) => {
                    last_desired[channel as usize] = Some(desired);

                    let event_type = if desired {
                        "scheduled_unlock_active"
                    } else {
                        "scheduled_unlock_inactive"
                    };

                    info!(
                        target: "nexus_schedule",
                        channel = channel,
                        door = channel + 1,
                        relay_held = desired,
                        "Scheduled door state changed"
                    );

                    queue_event(
                        &db,
                        event_type,
                        channel,
                        json!({
                            "channel": channel,
                            "door": channel + 1,
                            "relay_held": desired
                        }),
                    );
                }

                Err(e) => {
                    error!(
                        channel = channel,
                        error = %e,
                        "Unable to send scheduled relay command"
                    );
                }
            }
        }
    }
}
