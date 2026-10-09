//! Read-only diagnostic view of the durable command journals.
//! Never alters journal state, sends cloud requests, or operates relays.
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use std::path::Path;

fn count(conn: &Connection, sql: &str) -> Result<i64> {
    Ok(conn.query_row(sql, [], |row| row.get(0))?)
}

fn ids(conn: &Connection, sql: &str) -> Result<Vec<String>> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Requires the already-existing durable SQLite database. Read-only means no
/// schema migration, no creation of missing files, and no command execution.
pub fn inspect(path: &Path) -> Result<Value> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open existing journal read-only: {}", path.display()))?;

    let ambiguous_actuator_ids = ids(
        &conn,
        "SELECT command_id FROM actuator_command_journal WHERE state='reserved' ORDER BY created_at, command_id",
    ).context("actuator journal not available")?;
    let actuator_ack_backlog = count(
        &conn,
        "SELECT COUNT(*) FROM actuator_command_journal WHERE reported=0 AND state IN ('completed','failed')",
    )?;
    let network_ack_backlog = count(
        &conn,
        "SELECT COUNT(*) FROM network_command_journal WHERE reported=0 AND status IN ('completed','failed')",
    )?;
    let pending_network_ids = ids(
        &conn,
        "SELECT command_id FROM network_command_journal WHERE status='reserved' ORDER BY created_at, command_id",
    )?;
    let guarded_wifi_rejections_pending = count(
        &conn,
        "SELECT COUNT(*) FROM guarded_network_rejections WHERE reported=0",
    )?;

    Ok(json!({
        "mode": "read_only",
        "ambiguous_actuator_command_ids": ambiguous_actuator_ids,
        "ambiguous_network_command_ids": pending_network_ids,
        "actuator_terminal_ack_backlog": actuator_ack_backlog,
        "network_terminal_ack_backlog": network_ack_backlog,
        "guarded_wifi_rejection_ack_backlog": guarded_wifi_rejections_pending,
        "action_required": "Investigate reserved commands; never automatically replay physical actuations"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn seeded_db() -> (std::path::PathBuf, Connection) {
        let path = std::env::temp_dir().join(format!(
            "hlaxs-command-reconciliation-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE actuator_command_journal (command_id TEXT, state TEXT, reported INTEGER, created_at TEXT);
             CREATE TABLE network_command_journal (command_id TEXT, status TEXT, reported INTEGER, created_at TEXT);
             CREATE TABLE guarded_network_rejections (reported INTEGER);"
        ).unwrap();
        (path, conn)
    }

    #[test]
    fn shows_ambiguous_and_pending_without_mutation() {
        let (path, conn) = seeded_db();
        conn.execute_batch(
            "INSERT INTO actuator_command_journal VALUES ('relay_123','reserved',0,'2026-01-01');
             INSERT INTO actuator_command_journal VALUES ('relay_124','completed',0,'2026-01-02');
             INSERT INTO network_command_journal VALUES ('wifi_123','reserved',0,'2026-01-01');
             INSERT INTO network_command_journal VALUES ('wifi_124','failed',0,'2026-01-02');
             INSERT INTO guarded_network_rejections VALUES (0);",
        )
        .unwrap();
        let result = inspect(&path).unwrap();
        assert_eq!(
            result["ambiguous_actuator_command_ids"],
            json!(["relay_123"])
        );
        assert_eq!(result["ambiguous_network_command_ids"], json!(["wifi_123"]));
        assert_eq!(result["actuator_terminal_ack_backlog"], 1);
        assert_eq!(result["network_terminal_ack_backlog"], 1);
        assert_eq!(result["guarded_wifi_rejection_ack_backlog"], 1);
        let persisted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM actuator_command_journal WHERE state='reserved'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(persisted, 1);
        drop(conn);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn empty_journals_report_no_actions() {
        let (path, conn) = seeded_db();
        let result = inspect(&path).unwrap();
        assert_eq!(result["ambiguous_actuator_command_ids"], json!([]));
        assert_eq!(result["ambiguous_network_command_ids"], json!([]));
        assert_eq!(result["actuator_terminal_ack_backlog"], 0);
        drop(conn);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn never_creates_a_missing_journal() {
        let path =
            std::env::temp_dir().join(format!("hlaxs-missing-{}.sqlite", uuid::Uuid::new_v4()));
        assert!(inspect(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn missing_schema_fails_explicitly() {
        let path = std::env::temp_dir().join(format!(
            "hlaxs-empty-schema-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let conn = Connection::open(&path).unwrap();
        drop(conn);
        assert!(inspect(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
