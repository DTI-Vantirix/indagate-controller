use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::fs;
use std::path::Path;

pub const DEFAULT_DB_PATH: &str = "/var/lib/highline-nexus/nexus.db";

pub struct ControllerDatabase {
    conn: Connection,
}

/// A secure-channel key held for one OSDP reader.
#[derive(Clone, PartialEq, Eq)]
pub struct OsdpReaderKey {
    pub key: [u8; 16],
    /// The reader has taken the key. Otherwise it is still to be handed over.
    pub active: bool,
    /// For a key not yet taken: until when the controller may hand it over.
    pub enroll_until: Option<chrono::DateTime<chrono::Utc>>,
    /// A key change in progress: the key the reader is to change to.
    pub next_key: Option<[u8; 16]>,
    /// Until when the change may be started.
    pub rotate_until: Option<chrono::DateTime<chrono::Utc>>,
    /// The new key has been sent to the reader. From that moment the reader may hold
    /// either key, so neither is discarded until one of them is seen to work.
    pub rotate_sent: bool,
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

        // How a door released by its request to exit relocks. Absent means timed.
        let has_rex_relock = {
            let mut stmt = self.conn.prepare("PRAGMA table_info(door_config)")?;
            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
            columns.collect::<rusqlite::Result<Vec<String>>>()?.iter().any(|column| column == "rex_relock")
        };
        if !has_rex_relock {
            self.conn.execute("ALTER TABLE door_config ADD COLUMN rex_relock TEXT", [])?;
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

        // Reader ports learn which protocol they speak. Rows from before this are Wiegand.
        let reader_columns: Vec<String> = {
            let mut stmt = self.conn.prepare("PRAGMA table_info(reader_config)")?;
            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
            columns.collect::<rusqlite::Result<_>>()?
        };
        for (column, definition) in [
            ("protocol", "TEXT NOT NULL DEFAULT 'wiegand'"),
            ("osdp_address", "INTEGER"),
            ("osdp_baud_rate", "INTEGER"),
            ("osdp_secure", "INTEGER NOT NULL DEFAULT 0"),
            ("lights", "TEXT"),
        ] {
            if !reader_columns.iter().any(|existing| existing == column) {
                self.conn.execute(&format!("ALTER TABLE reader_config ADD COLUMN {column} {definition}"), [])?;
            }
        }

        // Cards are matched on their layout as well as their numbers. A database from
        // before that has no layout column, and a uniqueness rule on the numbers alone;
        // rebuild the table, keeping every card as the 26-bit layout it could only be.
        let has_format: bool = {
            let mut stmt = self.conn.prepare("PRAGMA table_info(credentials)")?;
            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
            columns.collect::<rusqlite::Result<Vec<String>>>()?.iter().any(|c| c == "format")
        };
        if !has_format {
            self.conn.pragma_update(None, "foreign_keys", "OFF")?;
            let rebuilt = self.conn.execute_batch(
                r#"
                BEGIN;
                CREATE TABLE credentials_new (
                    id TEXT PRIMARY KEY,
                    format TEXT NOT NULL DEFAULT 'h10301-26',
                    facility_code INTEGER NOT NULL,
                    card_code INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    valid_from TEXT,
                    valid_until TEXT,
                    holder_name TEXT,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(format, facility_code, card_code)
                );
                INSERT INTO credentials_new (id, format, facility_code, card_code, enabled, valid_from, valid_until, holder_name, updated_at)
                    SELECT id, 'h10301-26', facility_code, card_code, enabled, valid_from, valid_until, holder_name, updated_at FROM credentials;
                DROP TABLE credentials;
                ALTER TABLE credentials_new RENAME TO credentials;
                CREATE INDEX IF NOT EXISTS idx_credentials_lookup ON credentials(format, facility_code, card_code);
                COMMIT;
                "#,
            );
            self.conn.pragma_update(None, "foreign_keys", "ON")?;
            if let Err(err) = rebuilt {
                let _ = self.conn.execute_batch("ROLLBACK;");
                return Err(err).context("add the card layout to the credentials table");
            }
        }

        // Secure-channel keys for OSDP readers. They are made on this controller and never
        // leave it, so they are kept apart from the configuration, which the server
        // replaces wholesale.
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS osdp_reader_keys (
                reader_number INTEGER PRIMARY KEY,
                key BLOB NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending', 'active')),
                enroll_until TEXT,
                next_key BLOB,
                rotate_until TEXT,
                rotate_sent INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            "#,
        )?;

        Ok(())
    }

    /// The secure-channel key held for the reader on `channel`: the key, whether the reader
    /// has taken it (`active`) or is still to be given it (`pending`), and for a pending
    /// key the time until which the controller may hand it over.
    pub fn osdp_reader_key(&self, channel: u8) -> Result<Option<OsdpReaderKey>> {
        use rusqlite::OptionalExtension;

        let row = self
            .conn
            .query_row(
                "SELECT key, state, enroll_until, next_key, rotate_until, rotate_sent
                   FROM osdp_reader_keys WHERE reader_number = ?1",
                [i64::from(channel) + 1],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((key, state, enroll_until, next_key, rotate_until, rotate_sent)) = row else { return Ok(None) };
        let as_key = |bytes: Vec<u8>| -> Result<[u8; 16]> {
            bytes.try_into().map_err(|_| anyhow::anyhow!("stored OSDP key has the wrong length"))
        };
        let as_time = |text: Option<String>| {
            text.and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok()).map(|t| t.with_timezone(&chrono::Utc))
        };
        Ok(Some(OsdpReaderKey {
            key: as_key(key)?,
            active: state == "active",
            enroll_until: as_time(enroll_until),
            next_key: next_key.map(as_key).transpose()?,
            rotate_until: as_time(rotate_until),
            rotate_sent: rotate_sent != 0,
        }))
    }

    /// Start changing the key of the reader on `channel` to `next`, to be begun by `until`.
    /// Only a reader that has taken its key can have it changed, and a change already
    /// under way keeps its own new key (only the time is extended). Returns whether a
    /// change is now under way.
    pub fn osdp_begin_rotation(&self, channel: u8, next: [u8; 16], until: chrono::DateTime<chrono::Utc>) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE osdp_reader_keys
                SET next_key = coalesce(next_key, ?2), rotate_until = ?3, updated_at = ?4
              WHERE reader_number = ?1 AND state = 'active'",
            rusqlite::params![i64::from(channel) + 1, next.to_vec(), until.to_rfc3339(), chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(changed > 0)
    }

    /// Record whether the new key has been sent to the reader on `channel`.
    pub fn osdp_rotation_sent(&self, channel: u8, sent: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE osdp_reader_keys SET rotate_sent = ?2, updated_at = ?3 WHERE reader_number = ?1 AND next_key IS NOT NULL",
            rusqlite::params![i64::from(channel) + 1, i64::from(sent), chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// The reader on `channel` answers to its new key: that is now its key.
    pub fn osdp_commit_rotation(&self, channel: u8) -> Result<()> {
        self.conn.execute(
            "UPDATE osdp_reader_keys
                SET key = next_key, next_key = NULL, rotate_until = NULL, rotate_sent = 0, updated_at = ?2
              WHERE reader_number = ?1 AND next_key IS NOT NULL",
            rusqlite::params![i64::from(channel) + 1, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Give up a key change that was never sent to the reader on `channel`. One that was
    /// sent is never given up this way: the reader may hold the new key.
    pub fn osdp_cancel_rotation(&self, channel: u8) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE osdp_reader_keys SET next_key = NULL, rotate_until = NULL, updated_at = ?2
              WHERE reader_number = ?1 AND next_key IS NOT NULL AND rotate_sent = 0",
            rusqlite::params![i64::from(channel) + 1, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(changed > 0)
    }

    /// Hold `key` for the reader on `channel` as not yet taken, to be handed over until
    /// `until`. A key the reader has already taken is never overwritten here.
    pub fn osdp_begin_enrollment(&self, channel: u8, key: [u8; 16], until: chrono::DateTime<chrono::Utc>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO osdp_reader_keys (reader_number, key, state, enroll_until, updated_at)
             VALUES (?1, ?2, 'pending', ?3, ?4)
             ON CONFLICT(reader_number) DO UPDATE SET key = excluded.key, enroll_until = excluded.enroll_until,
                                                     updated_at = excluded.updated_at
              WHERE osdp_reader_keys.state = 'pending'",
            rusqlite::params![i64::from(channel) + 1, key.to_vec(), until.to_rfc3339(), chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Record that the reader on `channel` has taken its key.
    pub fn osdp_mark_enrolled(&self, channel: u8) -> Result<()> {
        self.conn.execute(
            "UPDATE osdp_reader_keys SET state = 'active', enroll_until = NULL, updated_at = ?2 WHERE reader_number = ?1",
            rusqlite::params![i64::from(channel) + 1, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Forget the key held for the reader on `channel`. Returns whether there was one.
    pub fn osdp_forget_key(&self, channel: u8) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM osdp_reader_keys WHERE reader_number = ?1", [i64::from(channel) + 1])? > 0)
    }

    /// The protocol a reader port is configured for (`wiegand` or `osdp`), or `None` when
    /// the port has no configuration at all. `channel` is the port number minus one.
    pub fn reader_protocol(&self, channel: u8) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;

        Ok(self
            .conn
            .query_row(
                "SELECT protocol FROM reader_config WHERE reader_number = ?1",
                [i64::from(channel) + 1],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    /// The enabled OSDP readers: (channel, bus address, line speed, secure channel required),
    /// lowest port first.
    pub fn osdp_readers(&self) -> Result<Vec<(u8, u8, u32, bool)>> {
        let mut stmt = self.conn.prepare(
            "SELECT reader_number, osdp_address, osdp_baud_rate, osdp_secure FROM reader_config
              WHERE protocol = 'osdp' AND enabled = 1 AND osdp_address IS NOT NULL
              ORDER BY reader_number",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, i64>(3)?))
        })?;
        let mut readers = Vec::new();
        for row in rows {
            let (number, address, baud_rate, secure) = row?;
            let (Ok(number), Ok(address)) = (u8::try_from(number), u8::try_from(address)) else { continue };
            if !(1..=4).contains(&number) {
                continue;
            }
            let baud_rate = baud_rate.and_then(|b| u32::try_from(b).ok()).unwrap_or(9600);
            readers.push((number - 1, address, baud_rate, secure != 0));
        }
        Ok(readers)
    }

    /// For each enabled OSDP reader port (channel): the door it stands at, and its light
    /// settings if it has any. Settings that cannot be read count as none.
    pub fn osdp_reader_lights(
        &self,
    ) -> Result<std::collections::HashMap<u8, (u8, Option<crate::hal::reader_lights::ReaderLights>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT reader_number, door_channel, lights FROM reader_config WHERE protocol = 'osdp' AND enabled = 1",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<String>>(2)?))
        })?;
        let mut readers = std::collections::HashMap::new();
        for row in rows {
            let (number, door, lights) = row?;
            let (Ok(number), Ok(door)) = (u8::try_from(number), u8::try_from(door)) else { continue };
            if !(1..=4).contains(&number) || door > 3 {
                continue;
            }
            let lights = lights.and_then(|text| serde_json::from_str(&text).ok());
            readers.insert(number - 1, (door, lights));
        }
        Ok(readers)
    }

    /// How a door released by its request to exit relocks (`timed`, `door_open`,
    /// `door_closed`); `None` when nothing is set.
    pub fn door_rex_relock(&self, channel: u8) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;

        Ok(self
            .conn
            .query_row("SELECT rex_relock FROM door_config WHERE channel = ?1", [channel], |row| {
                row.get::<_, Option<String>>(0)
            })
            .optional()?
            .flatten())
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
