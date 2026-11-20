use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use super::schedule;

#[derive(Debug, Clone, Serialize)]
pub enum AccessDecision {
    Grant,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionResult {
    pub decision: AccessDecision,
    pub reason: String,
    pub facility_code: u8,
    pub card_code: u16,
    pub channel: u8,
    pub credential_id: Option<String>,
    pub holder_name: Option<String>,
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

pub fn evaluate(
    conn: &Connection,
    facility_code: u8,
    card_code: u16,
    channel: u8,
) -> Result<DecisionResult> {
    evaluate_at(conn, facility_code, card_code, channel, Utc::now())
}

// Exposed only inside this crate for a deterministic bench test. The production
// entry point above always uses its actual UTC clock.
pub(crate) fn evaluate_at(
    conn: &Connection,
    facility_code: u8,
    card_code: u16,
    channel: u8,
    now: DateTime<Utc>,
) -> Result<DecisionResult> {
    // SA16Q READER POLICY V1: port is assigned by the pinned GPIO profile, not
    // by card data. No database reader mapping => deny, never legacy allow.
    let reader_policy = conn.query_row(
        "SELECT enabled, door_channel FROM reader_config WHERE reader_number = ?1",
        [i64::from(channel) + 1],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    ).optional()?;
    let reader_denial = match reader_policy {
        None => Some("reader_not_configured"),
        Some((0, _)) => Some("reader_disabled"),
        Some((1, target)) if target == i64::from(channel) => None,
        _ => Some("reader_door_mapping_invalid"),
    };
    if let Some(reason) = reader_denial {
        return Ok(DecisionResult {
            decision: AccessDecision::Deny, reason: reason.to_string(),
            facility_code, card_code, channel,
            credential_id: None, holder_name: None,
        });
    }

    let door_enabled = conn
        .query_row(
            r#"
            SELECT enabled
            FROM door_config
            WHERE channel = ?1
            "#,
            [channel],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;

    match door_enabled {
        Some(1) => {}
        Some(_) => {
            return Ok(DecisionResult {
                decision: AccessDecision::Deny,
                reason: "door_disabled".to_string(),
                facility_code,
                card_code,
                channel,
                credential_id: None,
                holder_name: None,
            });
        }
        None => {
            return Ok(DecisionResult {
                decision: AccessDecision::Deny,
                reason: "door_not_configured".to_string(),
                facility_code,
                card_code,
                channel,
                credential_id: None,
                holder_name: None,
            });
        }
    }
    let credential = conn
        .query_row(
            r#"
            SELECT
                id,
                enabled,
                holder_name,
                valid_from,
                valid_until
            FROM credentials
            WHERE facility_code = ?1
              AND card_code = ?2
            "#,
            params![facility_code, card_code],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;

    let Some((credential_id, enabled, holder_name, valid_from, valid_until)) = credential else {
        return Ok(DecisionResult {
            decision: AccessDecision::Deny,
            reason: "credential_not_found".to_string(),
            facility_code,
            card_code,
            channel,
            credential_id: None,
            holder_name: None,
        });
    };

    if enabled == 0 {
        return Ok(DecisionResult {
            decision: AccessDecision::Deny,
            reason: "credential_disabled".to_string(),
            facility_code,
            card_code,
            channel,
            credential_id: Some(credential_id),
            holder_name,
        });
    }

    if let Some(valid_from) = valid_from {
        if now < parse_datetime(&valid_from)? {
            return Ok(DecisionResult {
                decision: AccessDecision::Deny,
                reason: "credential_not_yet_valid".to_string(),
                facility_code,
                card_code,
                channel,
                credential_id: Some(credential_id),
                holder_name,
            });
        }
    }

    if let Some(valid_until) = valid_until {
        if now >= parse_datetime(&valid_until)? {
            return Ok(DecisionResult {
                decision: AccessDecision::Deny,
                reason: "credential_expired".to_string(),
                facility_code,
                card_code,
                channel,
                credential_id: Some(credential_id),
                holder_name,
            });
        }
    }

    let mut stmt = conn.prepare(
        r#"
        SELECT ald.schedule_id
        FROM credential_access_levels cal
        JOIN access_levels al
          ON al.id = cal.access_level_id
        JOIN access_level_doors ald
          ON ald.access_level_id = al.id
        WHERE cal.credential_id = ?1
          AND al.enabled = 1
          AND ald.channel = ?2
        "#,
    )?;

    let schedule_rows = stmt.query_map(params![credential_id, channel], |row| {
        row.get::<_, Option<String>>(0)
    })?;

    // SA-16P-HARDEN V1: conservative holiday precedence across all access paths.
    // Do not short-circuit on the first grant: a different path may explicitly
    // deny access for a holiday on this schedule's site-local date.
    let holidays_configured = schedule::has_configured_holidays(conn)?;
    let mut found_door_permission = false;
    let mut found_active_schedule = false;
    let mut found_holiday_denial = false;
    let mut unsafe_unscheduled_path = false;

    for row in schedule_rows {
        found_door_permission = true;
        match row? {
            None => {
                if holidays_configured {
                    // No schedule means no verified timezone for a holiday.
                    unsafe_unscheduled_path = true;
                } else {
                    // Preserve legacy no-schedule authorization when there are
                    // no holiday policies at all.
                    found_active_schedule = true;
                }
            }
            Some(schedule_id) => {
                if schedule::is_holiday_denied_at(conn, &schedule_id, &now)? {
                    found_holiday_denial = true;
                }
                if schedule::is_schedule_active_at(conn, &schedule_id, &now)? {
                    found_active_schedule = true;
                }
            }
        }
    }

    if !found_door_permission {
        return Ok(DecisionResult {
            decision: AccessDecision::Deny,
            reason: "door_not_allowed".to_string(),
            facility_code,
            card_code,
            channel,
            credential_id: Some(credential_id),
            holder_name,
        });
    }

    if unsafe_unscheduled_path || found_holiday_denial {
        return Ok(DecisionResult {
            decision: AccessDecision::Deny,
            reason: if unsafe_unscheduled_path {
                "schedule_missing_for_holiday"
            } else {
                "holiday_denied"
            }.to_string(),
            facility_code,
            card_code,
            channel,
            credential_id: Some(credential_id),
            holder_name,
        });
    }

    if !found_active_schedule {
        return Ok(DecisionResult {
            decision: AccessDecision::Deny,
            reason: "schedule_inactive".to_string(),
            facility_code,
            card_code,
            channel,
            credential_id: Some(credential_id),
            holder_name,
        });
    }

    Ok(DecisionResult {
        decision: AccessDecision::Grant,
        reason: "access_granted".to_string(),
        facility_code,
        card_code,
        channel,
        credential_id: Some(credential_id),
        holder_name,
    })
}
