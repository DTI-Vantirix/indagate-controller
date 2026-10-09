//! Durable reservation of credential rotation commands.
//! Reserved rotation commands are ambiguous after interruption: never prepare twice.
use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, params};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReservation {
    New,
    AlreadyReserved,
    AlreadyCompleted,
}

pub struct CredentialRotationJournal {
    conn: Connection,
}

fn valid_command_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl CredentialRotationJournal {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create credential journal directory")?;
        }
        let conn = Connection::open(path).context("open credential rotation journal")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS credential_rotation_journal (
                command_id TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK(state IN ('reserved','completed')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );",
        )?;
        Ok(Self { conn })
    }

    /// Must commit before /credential/rotate/prepare is requested.
    pub fn reserve(&mut self, command_id: &str) -> Result<RotationReservation> {
        if !valid_command_id(command_id) {
            return Err(anyhow!("invalid credential rotation command identifier"));
        }
        let tx = self.conn.transaction()?;
        // Never initiate a different rotation while an earlier prepare may
        // have reached the server; require explicit reconciliation first.
        let existing: i64 = tx.query_row(
            "SELECT count(*) FROM credential_rotation_journal WHERE state='reserved' AND command_id<>?1",
            [command_id], |r| r.get(0),
        )?;
        if existing != 0 {
            return Err(anyhow!(
                "another credential rotation requires reconciliation"
            ));
        }
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO credential_rotation_journal(command_id,state) VALUES (?1,'reserved')",
            [command_id],
        )?;
        let outcome = if inserted == 1 {
            RotationReservation::New
        } else {
            let state: String = tx.query_row(
                "SELECT state FROM credential_rotation_journal WHERE command_id=?1",
                [command_id],
                |r| r.get(0),
            )?;
            match state.as_str() {
                "reserved" => RotationReservation::AlreadyReserved,
                "completed" => RotationReservation::AlreadyCompleted,
                _ => return Err(anyhow!("unexpected credential rotation journal state")),
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// Call only after the durable identity recovery flow has successfully
    /// committed rotation and acknowledged its command to the cloud.
    pub fn mark_completed(&self, command_id: &str) -> Result<bool> {
        if !valid_command_id(command_id) {
            return Err(anyhow!("invalid credential rotation command identifier"));
        }
        Ok(self.conn.execute(
            "UPDATE credential_rotation_journal SET state='completed' WHERE command_id=?1 AND state='reserved'",
            [command_id],
        )? == 1)
    }

    /// Reserved entries may represent a prepare call that reached the server.
    /// Never replay automatically; an operator must reconcile if identity has
    /// no matching pending rotation.
    pub fn unresolved(&self) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT command_id FROM credential_rotation_journal WHERE state='reserved' ORDER BY created_at,command_id",
        )?;
        let entries = statement.query_map([], |r| r.get::<_, String>(0))?;
        entries
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hlaxs-rotation-{}.sqlite", uuid::Uuid::new_v4()))
    }
    #[test]
    fn reserves_before_prepare_and_blocks_duplicate() {
        let path = temp_path();
        let mut journal = CredentialRotationJournal::open(&path).unwrap();
        assert_eq!(
            journal.reserve("rotation_1").unwrap(),
            RotationReservation::New
        );
        assert_eq!(
            journal.reserve("rotation_1").unwrap(),
            RotationReservation::AlreadyReserved
        );
        assert_eq!(journal.unresolved().unwrap(), vec!["rotation_1"]);
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn interrupted_reservation_survives_restart() {
        let path = temp_path();
        CredentialRotationJournal::open(&path)
            .unwrap()
            .reserve("rotation_2")
            .unwrap();
        let mut journal = CredentialRotationJournal::open(&path).unwrap();
        assert_eq!(
            journal.reserve("rotation_2").unwrap(),
            RotationReservation::AlreadyReserved
        );
        assert_eq!(journal.unresolved().unwrap(), vec!["rotation_2"]);
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn only_explicitly_reconciled_rotation_is_completed() {
        let path = temp_path();
        let mut journal = CredentialRotationJournal::open(&path).unwrap();
        journal.reserve("rotation_3").unwrap();
        assert!(journal.mark_completed("rotation_3").unwrap());
        assert!(!journal.mark_completed("rotation_3").unwrap());
        assert_eq!(
            journal.reserve("rotation_3").unwrap(),
            RotationReservation::AlreadyCompleted
        );
        assert!(journal.unresolved().unwrap().is_empty());
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn unresolved_rotation_blocks_different_rotation() {
        let path = temp_path();
        let mut journal = CredentialRotationJournal::open(&path).unwrap();
        journal.reserve("rotation_first").unwrap();
        assert!(journal.reserve("rotation_second").is_err());
        assert_eq!(
            journal.reserve("rotation_first").unwrap(),
            RotationReservation::AlreadyReserved
        );
        journal.mark_completed("rotation_first").unwrap();
        assert_eq!(
            journal.reserve("rotation_second").unwrap(),
            RotationReservation::New
        );
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn invalid_identifiers_do_not_reserve() {
        let path = temp_path();
        let mut journal = CredentialRotationJournal::open(&path).unwrap();
        for bad in ["", "../escape", "bad space", "line\nfeed"] {
            assert!(journal.reserve(bad).is_err());
        }
        assert!(journal.reserve(&"x".repeat(129)).is_err());
        assert!(journal.unresolved().unwrap().is_empty());
        drop(journal);
        let _ = std::fs::remove_file(path);
    }
}
