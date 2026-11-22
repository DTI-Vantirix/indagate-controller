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
    let card = Card { format: DEFAULT_CARD_FORMAT, facility_code: Some(u64::from(facility_code)), card_code: u64::from(card_code) };
    let decided = evaluate_card_at(conn, &card, channel, now)?;
    Ok(DecisionResult {
        decision: decided.decision,
        reason: decided.reason,
        facility_code,
        card_code,
        channel,
        credential_id: decided.credential_id,
        holder_name: decided.holder_name,
    })
}

/// The layout every card had before layouts were recorded: 26 bits, an 8-bit facility
/// code and a 16-bit card number.
pub const DEFAULT_CARD_FORMAT: &str = "h10301-26";

/// A card as one layout reads it. The same bits can mean different cards under different
/// layouts, so a credential is matched on the layout as well as the numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Card<'a> {
    /// Layout identifier, e.g. `h10301-26`.
    pub format: &'a str,
    /// Absent for layouts that have no facility code.
    pub facility_code: Option<u64>,
    pub card_code: u64,
}

/// The decision for a card of any layout.
#[derive(Debug, Clone)]
pub struct CardDecision {
    pub decision: AccessDecision,
    pub reason: String,
    pub credential_id: Option<String>,
    pub holder_name: Option<String>,
}

impl CardDecision {
    fn deny(reason: &str, credential_id: Option<String>, holder_name: Option<String>) -> Self {
        Self { decision: AccessDecision::Deny, reason: reason.to_string(), credential_id, holder_name }
    }
}

/// Decide whether `card` may open the door on reader port `channel` now.
pub fn evaluate_card(conn: &Connection, card: &Card<'_>, channel: u8) -> Result<CardDecision> {
    evaluate_card_at(conn, card, channel, Utc::now())
}

/// Whether a credential exists for `card` at all, whatever its state.
pub fn card_is_known(conn: &Connection, card: &Card<'_>) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM credentials WHERE format = ?1 AND facility_code = ?2 AND card_code = ?3",
            params![card.format, stored_facility(card), i64::try_from(card.card_code)?],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// A layout with no facility code is stored with facility 0; the layout keeps it apart
/// from any card that really has facility 0.
fn stored_facility(card: &Card<'_>) -> i64 {
    card.facility_code.and_then(|f| i64::try_from(f).ok()).unwrap_or(0)
}

pub(crate) fn evaluate_card_at(
    conn: &Connection,
    card: &Card<'_>,
    channel: u8,
    now: DateTime<Utc>,
) -> Result<CardDecision> {
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
        return Ok(CardDecision::deny(reason, None, None));
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
        Some(_) => return Ok(CardDecision::deny("door_disabled", None, None)),
        None => return Ok(CardDecision::deny("door_not_configured", None, None)),
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
            WHERE format = ?1
              AND facility_code = ?2
              AND card_code = ?3
            "#,
            params![card.format, stored_facility(card), i64::try_from(card.card_code)?],
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
        return Ok(CardDecision::deny("credential_not_found", None, None));
    };

    if enabled == 0 {
        return Ok(CardDecision::deny("credential_disabled", Some(credential_id), holder_name));
    }

    if let Some(valid_from) = valid_from {
        if now < parse_datetime(&valid_from)? {
            return Ok(CardDecision::deny("credential_not_yet_valid", Some(credential_id), holder_name));
        }
    }

    if let Some(valid_until) = valid_until {
        if now >= parse_datetime(&valid_until)? {
            return Ok(CardDecision::deny("credential_expired", Some(credential_id), holder_name));
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
        return Ok(CardDecision::deny("door_not_allowed", Some(credential_id), holder_name));
    }

    if unsafe_unscheduled_path || found_holiday_denial {
        let reason = if unsafe_unscheduled_path { "schedule_missing_for_holiday" } else { "holiday_denied" };
        return Ok(CardDecision::deny(reason, Some(credential_id), holder_name));
    }

    if !found_active_schedule {
        return Ok(CardDecision::deny("schedule_inactive", Some(credential_id), holder_name));
    }

    Ok(CardDecision {
        decision: AccessDecision::Grant,
        reason: "access_granted".to_string(),
        credential_id: Some(credential_id),
        holder_name,
    })
}
