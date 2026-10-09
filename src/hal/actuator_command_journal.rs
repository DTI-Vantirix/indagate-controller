//! Durable, at-most-once dispatch for security-sensitive actuator commands.
//! A reserved command after restart is ambiguous: never execute it again automatically.
use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveResult {
    New,
    AlreadyReserved,
    AlreadyTerminal,
}

#[derive(Debug, PartialEq)]
pub struct ActuatorReport {
    pub command_id: String,
    pub state: String,
    pub result: Value,
    pub failure_reason: Option<String>,
}

pub struct ActuatorCommandJournal {
    conn: Connection,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl ActuatorCommandJournal {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create actuator journal directory")?;
        }
        let conn = Connection::open(path).context("open actuator command journal")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS actuator_command_journal (
                command_id TEXT PRIMARY KEY,
                command_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('reserved','completed','failed')),
                result_json TEXT,
                failure_reason TEXT,
                reported INTEGER NOT NULL DEFAULT 0 CHECK(reported IN (0,1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE INDEX IF NOT EXISTS idx_actuator_unreported
                ON actuator_command_journal(reported,state);",
        )?;
        Ok(Self { conn })
    }

    /// Reserve before any actuator execution. Replays never grant execution rights.
    pub fn reserve(
        &mut self,
        id: &str,
        command_type: &str,
        payload: &Value,
    ) -> Result<ReserveResult> {
        if !valid_id(id) {
            return Err(anyhow!("invalid actuator command identifier"));
        }
        if !matches!(
            command_type,
            "door_hold_open" | "door_lock" | "door_return_to_schedule" | "relay_pulse"
        ) {
            return Err(anyhow!("not an actuator command"));
        }
        let serialized = serde_json::to_string(payload)?;
        if serialized.len() > 65536 {
            return Err(anyhow!("actuator payload exceeds limit"));
        }
        let tx = self.conn.transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO actuator_command_journal(command_id,command_type,payload_json,state)
             VALUES (?1,?2,?3,'reserved')",
            params![id, command_type, serialized],
        )?;
        let result = if inserted == 1 {
            ReserveResult::New
        } else {
            let (existing_type, existing_payload, state): (String, String, String) = tx.query_row(
                "SELECT command_type,payload_json,state FROM actuator_command_journal WHERE command_id=?1",
                [id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            )?;
            if existing_type != command_type || existing_payload != serialized {
                return Err(anyhow!(
                    "actuator command ID reused with different contents"
                ));
            }
            if state == "reserved" {
                ReserveResult::AlreadyReserved
            } else {
                ReserveResult::AlreadyTerminal
            }
        };
        tx.commit()?;
        Ok(result)
    }

    /// Persist the terminal outcome BEFORE any final cloud acknowledgement.
    pub fn finish(&self, id: &str, result: &Result<Value>) -> Result<bool> {
        if !valid_id(id) {
            return Err(anyhow!("invalid actuator command identifier"));
        }
        let (state, value, failure): (&str, Value, Option<&str>) = match result {
            Ok(value) => ("completed", value.clone(), None),
            Err(_) => (
                "failed",
                serde_json::json!({}),
                Some("controller actuator command failed"),
            ),
        };
        let result_json = serde_json::to_string(&value)?;
        if result_json.len() > 65536 {
            return Err(anyhow!("actuator result exceeds limit"));
        }
        let rows = self.conn.execute(
            "UPDATE actuator_command_journal
             SET state=?2,result_json=?3,failure_reason=?4,reported=0
             WHERE command_id=?1 AND state='reserved'",
            params![id, state, result_json, failure],
        )?;
        if rows == 0 {
            let count: i64 = self.conn.query_row(
                "SELECT count(*) FROM actuator_command_journal WHERE command_id=?1",
                [id],
                |r| r.get(0),
            )?;
            if count == 0 {
                return Err(anyhow!("actuator command was never reserved"));
            }
        }
        Ok(rows == 1)
    }

    pub fn unreported(&self, limit: usize) -> Result<Vec<ActuatorReport>> {
        if limit == 0 || limit > 100 {
            return Err(anyhow!("invalid actuator report batch size"));
        }
        let mut stmt = self.conn.prepare(
            "SELECT command_id,state,result_json,failure_reason
             FROM actuator_command_journal WHERE reported=0 AND state IN ('completed','failed')
             ORDER BY created_at,command_id LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut reports = Vec::new();
        for row in rows {
            let (command_id, state, result_json, failure_reason) = row?;
            reports.push(ActuatorReport {
                command_id,
                state,
                result: serde_json::from_str(&result_json)?,
                failure_reason,
            });
        }
        Ok(reports)
    }

    pub fn mark_reported(&self, id: &str) -> Result<bool> {
        if !valid_id(id) {
            return Err(anyhow!("invalid actuator command identifier"));
        }
        Ok(self.conn.execute(
            "UPDATE actuator_command_journal SET reported=1 WHERE command_id=?1
             AND reported=0 AND state IN ('completed','failed')",
            [id],
        )? == 1)
    }

    /// These commands may already have moved a relay; they require operator reconciliation.
    pub fn unresolved(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT command_id FROM actuator_command_journal WHERE state='reserved' ORDER BY created_at,command_id"
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hlaxs-actuator-{}.db", uuid::Uuid::new_v4()))
    }
    #[test]
    fn duplicate_pulse_never_reexecutes() {
        let p = path();
        let mut j = ActuatorCommandJournal::open(&p).unwrap();
        let payload = serde_json::json!({"channel":1,"duration_ms":5000});
        assert_eq!(
            j.reserve("command_1", "relay_pulse", &payload).unwrap(),
            ReserveResult::New
        );
        assert_eq!(
            j.reserve("command_1", "relay_pulse", &payload).unwrap(),
            ReserveResult::AlreadyReserved
        );
        assert!(
            j.reserve(
                "command_1",
                "relay_pulse",
                &serde_json::json!({"channel":2})
            )
            .is_err()
        );
        assert!(j.reserve("command_1", "door_lock", &payload).is_err());
        drop(j);
        let _ = std::fs::remove_file(p);
    }
    #[test]
    fn terminal_success_persists_and_ack_waits_for_delivery() {
        let p = path();
        let payload = serde_json::json!({"channel":0});
        {
            let mut j = ActuatorCommandJournal::open(&p).unwrap();
            j.reserve("command_2", "door_lock", &payload).unwrap();
            j.finish("command_2", &Ok(serde_json::json!({"mode":"force_locked"})))
                .unwrap();
        }
        {
            let mut j = ActuatorCommandJournal::open(&p).unwrap();
            assert_eq!(
                j.reserve("command_2", "door_lock", &payload).unwrap(),
                ReserveResult::AlreadyTerminal
            );
            let reports = j.unreported(10).unwrap();
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].state, "completed");
            assert_eq!(reports[0].result["mode"], "force_locked");
            assert!(j.mark_reported("command_2").unwrap());
            assert!(j.unreported(10).unwrap().is_empty());
        }
        let _ = std::fs::remove_file(p);
    }
    #[test]
    fn interrupted_command_is_not_replayed() {
        let p = path();
        let payload = serde_json::json!({"channel":2});
        {
            let mut j = ActuatorCommandJournal::open(&p).unwrap();
            j.reserve("command_3", "door_hold_open", &payload).unwrap();
        }
        {
            let mut j = ActuatorCommandJournal::open(&p).unwrap();
            assert_eq!(
                j.reserve("command_3", "door_hold_open", &payload).unwrap(),
                ReserveResult::AlreadyReserved
            );
            assert_eq!(j.unresolved().unwrap(), vec!["command_3"]);
            assert!(j.unreported(10).unwrap().is_empty());
        }
        let _ = std::fs::remove_file(p);
    }
    #[test]
    fn failures_have_fixed_non_secret_reason() {
        let p = path();
        let mut j = ActuatorCommandJournal::open(&p).unwrap();
        j.reserve(
            "command_4",
            "door_return_to_schedule",
            &serde_json::json!({"channel":0}),
        )
        .unwrap();
        j.finish("command_4", &Err(anyhow!("sensitive internal detail")))
            .unwrap();
        let reports = j.unreported(10).unwrap();
        assert_eq!(reports[0].state, "failed");
        assert_eq!(
            reports[0].failure_reason.as_deref(),
            Some("controller actuator command failed")
        );
        assert!(!format!("{:?}", reports).contains("sensitive internal detail"));
        let _ = std::fs::remove_file(p);
    }
    #[test]
    fn invalid_command_and_batch_are_rejected() {
        let p = path();
        let mut j = ActuatorCommandJournal::open(&p).unwrap();
        assert!(
            j.reserve("../bad", "relay_pulse", &serde_json::json!({}))
                .is_err()
        );
        assert!(
            j.reserve("ok", "credential_rotate", &serde_json::json!({}))
                .is_err()
        );
        assert!(j.unreported(0).is_err());
        assert!(j.unreported(101).is_err());
        let _ = std::fs::remove_file(p);
    }
}
