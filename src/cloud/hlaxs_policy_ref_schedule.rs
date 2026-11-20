use anyhow::{Context, Result};
use chrono::{Datelike, TimeZone, Timelike, Utc, Weekday};
use chrono_tz::Tz;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TimeRange {
    start: String,
    end: String,
}

#[derive(Debug, Deserialize, Default)]
struct WeeklySchedule {
    #[serde(default)]
    always: bool,

    #[serde(default)]
    monday: Vec<TimeRange>,
    #[serde(default)]
    tuesday: Vec<TimeRange>,
    #[serde(default)]
    wednesday: Vec<TimeRange>,
    #[serde(default)]
    thursday: Vec<TimeRange>,
    #[serde(default)]
    friday: Vec<TimeRange>,
    #[serde(default)]
    saturday: Vec<TimeRange>,
    #[serde(default)]
    sunday: Vec<TimeRange>,
}

enum HolidayAction {
    Deny,
    Allow,
    UseSchedule(String),
}

fn parse_minutes(value: &str) -> Option<u32> {
    if value == "24:00" {
        return Some(1440);
    }

    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;

    if hour > 23 || minute > 59 {
        return None;
    }

    Some(hour * 60 + minute)
}

fn ranges_for_weekday(definition: &WeeklySchedule, weekday: Weekday) -> &[TimeRange] {
    match weekday {
        Weekday::Mon => &definition.monday,
        Weekday::Tue => &definition.tuesday,
        Weekday::Wed => &definition.wednesday,
        Weekday::Thu => &definition.thursday,
        Weekday::Fri => &definition.friday,
        Weekday::Sat => &definition.saturday,
        Weekday::Sun => &definition.sunday,
    }
}

fn previous_weekday(weekday: Weekday) -> Weekday {
    match weekday {
        Weekday::Mon => Weekday::Sun,
        Weekday::Tue => Weekday::Mon,
        Weekday::Wed => Weekday::Tue,
        Weekday::Thu => Weekday::Wed,
        Weekday::Fri => Weekday::Thu,
        Weekday::Sat => Weekday::Fri,
        Weekday::Sun => Weekday::Sat,
    }
}

fn same_day_range_matches(range: &TimeRange, current: u32) -> bool {
    let Some(start) = parse_minutes(&range.start) else {
        return false;
    };

    let Some(end) = parse_minutes(&range.end) else {
        return false;
    };

    if start == 0 && end == 1440 {
        return true;
    }

    if start <= end {
        current >= start && current < end
    } else {
        // Overnight range begins today and carries into tomorrow.
        current >= start
    }
}

fn previous_day_carryover_matches(range: &TimeRange, current: u32) -> bool {
    let Some(start) = parse_minutes(&range.start) else {
        return false;
    };

    let Some(end) = parse_minutes(&range.end) else {
        return false;
    };

    start > end && current < end
}

fn weekly_matches(definition: &WeeklySchedule, weekday: Weekday, current_minutes: u32) -> bool {
    if definition.always {
        return true;
    }

    if ranges_for_weekday(definition, weekday)
        .iter()
        .any(|r| same_day_range_matches(r, current_minutes))
    {
        return true;
    }

    let previous = previous_weekday(weekday);

    ranges_for_weekday(definition, previous)
        .iter()
        .any(|r| previous_day_carryover_matches(r, current_minutes))
}

fn load_schedule(conn: &Connection, schedule_id: &str) -> Result<Option<(Tz, WeeklySchedule)>> {
    let schedule = conn
        .query_row(
            r#"
            SELECT timezone, definition_json
            FROM schedules
            WHERE id = ?1
            "#,
            [schedule_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;

    let Some((timezone, definition_json)) = schedule else {
        return Ok(None);
    };

    let definition: WeeklySchedule =
        serde_json::from_str(&definition_json).context("invalid schedule definition")?;

    let tz: Tz = timezone
        .parse()
        .with_context(|| format!("invalid timezone {}", timezone))?;

    Ok(Some((tz, definition)))
}

fn schedule_active_without_holiday(conn: &Connection, schedule_id: &str) -> Result<bool> {
    let Some((tz, definition)) = load_schedule(conn, schedule_id)? else {
        return Ok(false);
    };

    let local = tz.from_utc_datetime(&crate::test_clock::now().naive_utc());

    let current_minutes = local.hour() * 60 + local.minute();

    Ok(weekly_matches(
        &definition,
        local.weekday(),
        current_minutes,
    ))
}

fn holiday_action(conn: &Connection, local_date: &str) -> Result<Option<HolidayAction>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT behavior, schedule_id
        FROM holidays
        WHERE holiday_date = ?1
        ORDER BY id ASC
        "#,
    )?;

    let rows = stmt.query_map([local_date], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })?;

    let mut allow = false;
    let mut override_schedule: Option<String> = None;

    for row in rows {
        let (behavior, schedule_id) = row?;

        match behavior.as_str() {
            // Fail-safe precedence when multiple holiday rows exist.
            "deny" => return Ok(Some(HolidayAction::Deny)),

            "allow" => {
                allow = true;
            }

            "use_schedule" => {
                if override_schedule.is_none() {
                    override_schedule = schedule_id;
                }
            }

            // Unknown holiday behavior fails closed.
            _ => return Ok(Some(HolidayAction::Deny)),
        }
    }

    if let Some(schedule_id) = override_schedule {
        return Ok(Some(HolidayAction::UseSchedule(schedule_id)));
    }

    if allow {
        return Ok(Some(HolidayAction::Allow));
    }

    Ok(None)
}

pub fn is_schedule_active(conn: &Connection, schedule_id: &str) -> Result<bool> {
    let Some((tz, definition)) = load_schedule(conn, schedule_id)? else {
        return Ok(false);
    };

    let local = tz.from_utc_datetime(&crate::test_clock::now().naive_utc());

    let local_date = local.date_naive().format("%Y-%m-%d").to_string();

    match holiday_action(conn, &local_date)? {
        Some(HolidayAction::Deny) => {
            return Ok(false);
        }

        Some(HolidayAction::Allow) => {
            return Ok(true);
        }

        Some(HolidayAction::UseSchedule(override_schedule_id)) => {
            return schedule_active_without_holiday(conn, &override_schedule_id);
        }

        None => {}
    }

    let current_minutes = local.hour() * 60 + local.minute();

    Ok(weekly_matches(
        &definition,
        local.weekday(),
        current_minutes,
    ))
}
