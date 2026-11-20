use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::fs;
use std::path::Path;

pub const DEFAULT_DB_PATH: &str = "/var/lib/highline-nexus/nexus.db";

pub struct ControllerDatabase {
    conn: Connection,
}

impl ControllerDatabase {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create database directory {:?}", parent))?;
        }

        let conn = Connection::open(path).with_context(|| format!("open database {}", path))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        let db = Self { conn };
        db.migrate()?;

        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS controller_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            -- SA16Q READER POLICY V1: no default rows. An uncommissioned port
            -- cannot grant access before an authenticated cloud snapshot installs
            -- the explicit policy into this same SQLite database.
            CREATE TABLE IF NOT EXISTS reader_config (
                reader_number INTEGER PRIMARY KEY CHECK(reader_number BETWEEN 1 AND 4),
                reader_id TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                door_channel INTEGER NOT NULL CHECK(door_channel BETWEEN 0 AND 3),
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                facility_code INTEGER NOT NULL,
                card_code INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                valid_from TEXT,
                valid_until TEXT,
                holder_name TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(facility_code, card_code)
            );

            CREATE TABLE IF NOT EXISTS access_levels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS credential_access_levels (
                credential_id TEXT NOT NULL,
                access_level_id TEXT NOT NULL,
                PRIMARY KEY(credential_id, access_level_id),
                FOREIGN KEY(credential_id)
                    REFERENCES credentials(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(access_level_id)
                    REFERENCES access_levels(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS access_level_doors (
                access_level_id TEXT NOT NULL,
                channel INTEGER NOT NULL,
                schedule_id TEXT,
                PRIMARY KEY(access_level_id, channel),
                FOREIGN KEY(access_level_id)
                    REFERENCES access_levels(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS schedules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                timezone TEXT NOT NULL DEFAULT 'America/New_York',
                definition_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS holidays (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                holiday_date TEXT NOT NULL,
                behavior TEXT NOT NULL DEFAULT 'deny',
                schedule_id TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS event_queue (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                channel INTEGER,
                payload_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                uploaded_at TEXT,
                upload_attempts INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_event_queue_pending
                ON event_queue(uploaded_at, occurred_at);

            CREATE INDEX IF NOT EXISTS idx_credentials_lookup
                ON credentials(facility_code, card_code);

            CREATE TABLE IF NOT EXISTS command_state (
                command_id TEXT PRIMARY KEY,
                command_type TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT,
                received_at TEXT NOT NULL,
                completed_at TEXT,
                result_json TEXT
            );
            "#,
        )?;

        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS door_config (
                channel INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                unlock_ms INTEGER NOT NULL DEFAULT 5000,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            INSERT OR IGNORE INTO door_config
                (channel, name, enabled, unlock_ms)
            VALUES
                (0, 'Door 1', 1, 5000),
                (1, 'Door 2', 1, 5000),
                (2, 'Door 3', 1, 5000),
                (3, 'Door 4', 1, 5000);
            "#,
        )?;

        let mut has_unlock_schedule_id = false;

        {
            let mut stmt = self.conn.prepare("PRAGMA table_info(door_config)")?;

            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;

            for column in columns {
                if column? == "unlock_schedule_id" {
                    has_unlock_schedule_id = true;
                    break;
                }
            }
        }

        if !has_unlock_schedule_id {
            self.conn.execute(
                "ALTER TABLE door_config ADD COLUMN unlock_schedule_id TEXT",
                [],
            )?;
        }

        let mut has_holiday_behavior = false;

        {
            let mut stmt = self.conn.prepare("PRAGMA table_info(holidays)")?;

            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;

            for column in columns {
                if column? == "behavior" {
                    has_holiday_behavior = true;
                    break;
                }
            }
        }

        if !has_holiday_behavior {
            self.conn.execute(
                "ALTER TABLE holidays ADD COLUMN behavior TEXT NOT NULL DEFAULT 'deny'",
                [],
            )?;
        }

        Ok(())
    }

    pub fn door_unlock_ms(&self, channel: u8) -> Result<Option<u64>> {
        use rusqlite::OptionalExtension;

        let value = self
            .conn
            .query_row(
                r#"
            SELECT unlock_ms
            FROM door_config
            WHERE channel = ?1
              AND enabled = 1
            "#,
                [channel],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        Ok(value.map(|v| v.max(0) as u64))
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO controller_config(key, value, updated_at)
            VALUES(?1, ?2, CURRENT_TIMESTAMP)
            ON CONFLICT(key)
            DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            "#,
            params![key, value],
        )?;

        Ok(())
    }

    pub fn count_credentials(&self) -> Result<i64> {
        let count = self
            .conn
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))?;

        Ok(count)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}
