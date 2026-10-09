//! Durable, isolated journal for future protected network commands.
//! Not connected to cloud dispatch and does not execute network operations.
//! A reserved command is NEVER automatically re-executed after restart.
use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveOutcome {
    New,
    AlreadyReserved,
    AlreadyTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    Completed,
    Failed,
}

impl TerminalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PendingReport {
    pub command_id: String,
    pub outcome: TerminalOutcome,
    pub result_code: String,
}

pub struct NetworkCommandJournal {
    conn: Connection,
}

fn validate_command_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(anyhow!("invalid command identifier"));
    }
    Ok(())
}

fn validate_result_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        "ok",
        "invalid_request",
        "preflight_failed",
        "activation_failed",
        "verification_failed",
        "cloud_confirmation_failed",
        "rollback_failed",
        "interrupted",
        "internal_error",
    ];
    if !CODES.contains(&code) {
        return Err(anyhow!("unsupported result code"));
    }
    Ok(())
}

impl NetworkCommandJournal {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create journal directory")?;
        }
        let conn = Connection::open(path).context("open network command journal")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS network_command_journal (
                command_id TEXT PRIMARY KEY,
                profile_uuid TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('reserved','completed','failed')),
                result_code TEXT,
                reported INTEGER NOT NULL DEFAULT 0 CHECK(reported IN (0,1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE INDEX IF NOT EXISTS idx_network_command_report
                ON network_command_journal(reported, status);
             CREATE TABLE IF NOT EXISTS guarded_network_rejections (
                command_id TEXT PRIMARY KEY,
                reported INTEGER NOT NULL DEFAULT 0 CHECK(reported IN (0,1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );",
        )?;
        Ok(Self { conn })
    }

    /// Atomically claims a command. A matching replay never authorizes re-execution.
    /// The canonical UUID binds the command ID to the intended saved profile.
    pub fn reserve(&mut self, command_id: &str, profile_uuid: &str) -> Result<ReserveOutcome> {
        validate_command_id(command_id)?;
        let profile = uuid::Uuid::parse_str(profile_uuid)
            .context("invalid profile UUID")?
            .to_string();
        let tx = self.conn.transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO network_command_journal(command_id, profile_uuid, status)
             VALUES (?1, ?2, 'reserved')",
            params![command_id, profile],
        )?;
        let outcome = if inserted == 1 {
            ReserveOutcome::New
        } else {
            let (existing_profile, existing_state): (String, String) = tx.query_row(
                "SELECT profile_uuid, status FROM network_command_journal WHERE command_id=?1",
                [command_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if existing_profile != profile {
                return Err(anyhow!("command ID replay with different profile UUID"));
            }
            if existing_state == "reserved" {
                ReserveOutcome::AlreadyReserved
            } else {
                ReserveOutcome::AlreadyTerminal
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Record a terminal decision, but never overwrite one. Repeated delivery is safe.
    /// Only fixed, non-secret result codes are accepted.
    pub fn finish(
        &mut self,
        command_id: &str,
        outcome: TerminalOutcome,
        code: &str,
    ) -> Result<bool> {
        validate_command_id(command_id)?;
        validate_result_code(code)?;
        if (outcome == TerminalOutcome::Completed) != (code == "ok") {
            return Err(anyhow!("result code does not match terminal outcome"));
        }
        let updated = self.conn.execute(
            "UPDATE network_command_journal
             SET status=?2, result_code=?3, reported=0, updated_at=CURRENT_TIMESTAMP
             WHERE command_id=?1 AND status='reserved'",
            params![command_id, outcome.as_str(), code],
        )?;
        if updated == 0 && !self.exists(command_id)? {
            return Err(anyhow!("cannot finish an unknown command"));
        }
        Ok(updated == 1)
    }

    pub fn unreported(&self, limit: usize) -> Result<Vec<PendingReport>> {
        if limit == 0 || limit > 1000 {
            return Err(anyhow!("invalid report batch size"));
        }
        let mut stmt = self.conn.prepare(
            "SELECT command_id, status, result_code FROM network_command_journal
             WHERE status IN ('completed', 'failed') AND reported=0
             ORDER BY created_at, command_id LIMIT ?1",
        )?;
        let results = stmt.query_map([limit as i64], |row| {
            let state: String = row.get(1)?;
            Ok(PendingReport {
                command_id: row.get(0)?,
                outcome: if state == "completed" {
                    TerminalOutcome::Completed
                } else {
                    TerminalOutcome::Failed
                },
                result_code: row.get(2)?,
            })
        })?;
        results
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Call only after an authenticated cloud acknowledgement has succeeded.
    pub fn mark_reported(&self, command_id: &str) -> Result<bool> {
        validate_command_id(command_id)?;
        Ok(self.conn.execute(
            "UPDATE network_command_journal SET reported=1, updated_at=CURRENT_TIMESTAMP
             WHERE command_id=?1 AND status IN ('completed','failed') AND reported=0",
            [command_id],
        )? == 1)
    }

    /// Persist a safe, fixed rejection before attempting the authenticated cloud ACK.
    /// A duplicate command cannot cause the outcome to change or execute networking.
    pub fn record_guarded_rejection(&self, command_id: &str) -> Result<()> {
        validate_command_id(command_id)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO guarded_network_rejections(command_id) VALUES (?1)",
            [command_id],
        )?;
        Ok(())
    }

    pub fn pending_guarded_rejections(&self, limit: usize) -> Result<Vec<String>> {
        if limit == 0 || limit > 100 {
            return Err(anyhow!("invalid rejection batch size"));
        }
        let mut stmt = self.conn.prepare(
            "SELECT command_id FROM guarded_network_rejections WHERE reported=0
             ORDER BY created_at, command_id LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| row.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Mark delivered only after authenticated_post returns success.
    pub fn mark_guarded_rejection_reported(&self, command_id: &str) -> Result<bool> {
        validate_command_id(command_id)?;
        Ok(self.conn.execute(
            "UPDATE guarded_network_rejections SET reported=1 WHERE command_id=?1 AND reported=0",
            [command_id],
        )? == 1)
    }

    /// Reserved commands are ambiguous after interruption. They require explicit
    /// reconciliation, NOT automatic replay or assumed failure/success.
    pub fn unresolved(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT command_id FROM network_command_journal WHERE status='reserved' ORDER BY created_at, command_id",
        )?;
        let entries = stmt.query_map([], |row| row.get::<_, String>(0))?;
        entries
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn exists(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM network_command_journal WHERE command_id=?1",
                [id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hlaxs-network-journal-{}.sqlite",
            uuid::Uuid::new_v4()
        ))
    }
    const UUID_A: &str = "b5513ddd-ca75-498c-97d1-2e2b5c151ec0";
    const UUID_B: &str = "6f4fed01-a7e6-4e25-8d8a-161989c824ad";

    #[test]
    fn guarded_rejection_survives_restart_and_is_idempotent() {
        let path = temp_path();
        {
            let journal = NetworkCommandJournal::open(&path).unwrap();
            journal.record_guarded_rejection("guarded_1").unwrap();
            journal.record_guarded_rejection("guarded_1").unwrap();
            assert_eq!(
                journal.pending_guarded_rejections(10).unwrap(),
                vec!["guarded_1"]
            );
        }
        {
            let journal = NetworkCommandJournal::open(&path).unwrap();
            assert_eq!(
                journal.pending_guarded_rejections(10).unwrap(),
                vec!["guarded_1"]
            );
            assert!(
                journal
                    .mark_guarded_rejection_reported("guarded_1")
                    .unwrap()
            );
            assert!(
                !journal
                    .mark_guarded_rejection_reported("guarded_1")
                    .unwrap()
            );
            journal.record_guarded_rejection("guarded_1").unwrap();
            assert!(journal.pending_guarded_rejections(10).unwrap().is_empty());
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn guarded_rejections_validate_identifiers_and_limits() {
        let path = temp_path();
        let journal = NetworkCommandJournal::open(&path).unwrap();
        assert!(journal.record_guarded_rejection("../bad").is_err());
        assert!(journal.pending_guarded_rejections(0).is_err());
        assert!(journal.pending_guarded_rejections(101).is_err());
        assert!(!journal.mark_guarded_rejection_reported("unknown").unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn duplicate_command_cannot_execute_twice() {
        let path = temp_path();
        let mut journal = NetworkCommandJournal::open(&path).unwrap();
        assert_eq!(
            journal.reserve("cmd_1", UUID_A).unwrap(),
            ReserveOutcome::New
        );
        assert_eq!(
            journal.reserve("cmd_1", UUID_A).unwrap(),
            ReserveOutcome::AlreadyReserved
        );
        assert!(journal.reserve("cmd_1", UUID_B).is_err());
        assert_eq!(journal.unresolved().unwrap(), vec!["cmd_1"]);
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn terminal_state_survives_reopen_and_replay() {
        let path = temp_path();
        {
            let mut journal = NetworkCommandJournal::open(&path).unwrap();
            assert_eq!(
                journal.reserve("cmd_2", UUID_A).unwrap(),
                ReserveOutcome::New
            );
            assert!(
                journal
                    .finish("cmd_2", TerminalOutcome::Completed, "ok")
                    .unwrap()
            );
            assert!(
                !journal
                    .finish("cmd_2", TerminalOutcome::Failed, "internal_error")
                    .unwrap()
            );
        }
        {
            let mut journal = NetworkCommandJournal::open(&path).unwrap();
            assert_eq!(
                journal.reserve("cmd_2", UUID_A).unwrap(),
                ReserveOutcome::AlreadyTerminal
            );
            assert_eq!(
                journal.unreported(10).unwrap(),
                vec![PendingReport {
                    command_id: "cmd_2".into(),
                    outcome: TerminalOutcome::Completed,
                    result_code: "ok".into()
                }]
            );
            assert!(journal.mark_reported("cmd_2").unwrap());
            assert!(journal.unreported(10).unwrap().is_empty());
            assert!(!journal.mark_reported("cmd_2").unwrap());
        }
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn interrupted_command_is_not_replayed() {
        let path = temp_path();
        NetworkCommandJournal::open(&path)
            .unwrap()
            .reserve("cmd_3", UUID_A)
            .unwrap();
        let mut journal = NetworkCommandJournal::open(&path).unwrap();
        assert_eq!(
            journal.reserve("cmd_3", UUID_A).unwrap(),
            ReserveOutcome::AlreadyReserved
        );
        assert_eq!(journal.unresolved().unwrap(), vec!["cmd_3"]);
        assert!(journal.unreported(10).unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn rejects_invalid_identifiers_and_codes() {
        let path = temp_path();
        let mut journal = NetworkCommandJournal::open(&path).unwrap();
        assert!(journal.reserve("../unsafe", UUID_A).is_err());
        assert!(journal.reserve("cmd", "bad-uuid").is_err());
        assert!(
            journal
                .finish("not-found", TerminalOutcome::Failed, "internal_error")
                .is_err()
        );
        journal.reserve("cmd", UUID_A).unwrap();
        assert!(
            journal
                .finish("cmd", TerminalOutcome::Failed, "custom-secret-message")
                .is_err()
        );
        assert!(
            journal
                .finish("cmd", TerminalOutcome::Completed, "rollback_failed")
                .is_err()
        );
        assert!(!journal.mark_reported("cmd").unwrap());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn failed_outcome_retries_reporting() {
        let path = temp_path();
        let mut journal = NetworkCommandJournal::open(&path).unwrap();
        journal.reserve("cmd_4", UUID_B).unwrap();
        journal
            .finish("cmd_4", TerminalOutcome::Failed, "verification_failed")
            .unwrap();
        assert_eq!(
            journal.unreported(10).unwrap()[0].result_code,
            "verification_failed"
        );
        assert!(journal.mark_reported("cmd_4").unwrap());
        assert!(journal.unreported(10).unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }
}
