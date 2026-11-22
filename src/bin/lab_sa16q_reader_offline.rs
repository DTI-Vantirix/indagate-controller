//! SA16Q reader-security gate: exact live access/engine.rs with in-memory SQLite.
//! NO GPIO, NO CLOUD NETWORK, NO RELAY, NO PHYSICAL DEVICE DATA.
mod access {
    pub mod schedule { include!("../access/schedule.rs"); }
    pub mod engine { include!("../access/engine.rs"); }
}
fn main() { println!("SA16Q_READER_GATE_TEST_BIN=NO_HARDWARE_IO"); }
#[cfg(test)]
mod tests {
    use super::access::engine::{self,AccessDecision};
    use anyhow::Result;
    use chrono::{DateTime,Utc};
    use rusqlite::Connection;
    fn at()->DateTime<Utc>{"2026-11-02T15:00:00Z".parse().unwrap()}
    fn baseline()->Result<Connection>{
        let db=Connection::open_in_memory()?;
        db.execute_batch(r#"
            CREATE TABLE reader_config(reader_number INTEGER PRIMARY KEY,reader_id TEXT NOT NULL,enabled INTEGER NOT NULL,door_channel INTEGER NOT NULL);
            CREATE TABLE door_config(channel INTEGER PRIMARY KEY,enabled INTEGER NOT NULL);
            CREATE TABLE credentials(id TEXT PRIMARY KEY,facility_code INTEGER NOT NULL,card_code INTEGER NOT NULL,enabled INTEGER NOT NULL,holder_name TEXT,valid_from TEXT,valid_until TEXT);
            CREATE TABLE access_levels(id TEXT PRIMARY KEY,enabled INTEGER NOT NULL);
            CREATE TABLE credential_access_levels(credential_id TEXT,access_level_id TEXT);
            CREATE TABLE access_level_doors(access_level_id TEXT,channel INTEGER,schedule_id TEXT);
            CREATE TABLE schedules(id TEXT PRIMARY KEY,timezone TEXT NOT NULL,definition_json TEXT NOT NULL);
            CREATE TABLE holidays(id TEXT PRIMARY KEY,holiday_date TEXT,behavior TEXT,schedule_id TEXT);
            INSERT INTO reader_config VALUES(1,'reader1',1,0);
            INSERT INTO reader_config VALUES(2,'reader2',1,1);
            INSERT INTO door_config VALUES(0,1);
            INSERT INTO door_config VALUES(1,1);
            INSERT INTO credentials VALUES('card',41,1234,1,'Lab',NULL,NULL);
            INSERT INTO access_levels VALUES('level1',1);
            INSERT INTO credential_access_levels VALUES('card','level1');
            INSERT INTO access_level_doors VALUES('level1',0,'always');
            INSERT INTO schedules VALUES('always','America/New_York','{"always":true}');
        "#)?;
        Ok(db)
    }
    fn assert_decision(db:&Connection,channel:u8,expect:&str)->Result<()> {
        let result=engine::evaluate_at(db,41,1234,channel,at())?;
        let ok=matches!(result.decision,AccessDecision::Grant);
        assert_eq!((ok,result.reason.as_str()),(expect=="access_granted",expect));
        Ok(())
    }
    #[test] fn valid_commissioned_port_grants()->Result<()> {let db=baseline()?;assert_decision(&db,0,"access_granted")}
    #[test] fn disabled_reader_denied()->Result<()> {let db=baseline()?;db.execute("UPDATE reader_config SET enabled=0 WHERE reader_number=1",[])?;assert_decision(&db,0,"reader_disabled")}
    #[test] fn missing_reader_denied()->Result<()> {let db=baseline()?;db.execute("DELETE FROM reader_config WHERE reader_number=1",[])?;assert_decision(&db,0,"reader_not_configured")}
    #[test] fn unmapped_reader_denied()->Result<()> {let db=baseline()?;db.execute("UPDATE reader_config SET door_channel=2 WHERE reader_number=1",[])?;assert_decision(&db,0,"reader_door_mapping_invalid")}
    #[test] fn out_of_range_reader_denied()->Result<()> {let db=baseline()?;assert_decision(&db,3,"reader_not_configured")}
    #[test] fn non_boolean_reader_state_denied()->Result<()> {let db=baseline()?;db.execute("UPDATE reader_config SET enabled=2 WHERE reader_number=1",[])?;assert_decision(&db,0,"reader_door_mapping_invalid")}
    #[test] fn correctly_configured_other_port_does_not_grant_other_door()->Result<()> {let db=baseline()?;assert_decision(&db,1,"door_not_allowed")}
    #[test] fn credential_not_found_denied()->Result<()> {let db=baseline()?;db.execute("DELETE FROM credentials",[])?;assert_decision(&db,0,"credential_not_found")}
    #[test] fn door_disabled_denied()->Result<()> {let db=baseline()?;db.execute("UPDATE door_config SET enabled=0 WHERE channel=0",[])?;assert_decision(&db,0,"door_disabled")}
    #[test] fn holiday_denial_still_wins()->Result<()> {let db=baseline()?;db.execute("INSERT INTO holidays VALUES('h','2026-11-02','deny',NULL)",[])?;assert_decision(&db,0,"holiday_denied")}
    #[test] fn reader_denial_precedes_credential_lookup()->Result<()> {let db=baseline()?;db.execute("UPDATE reader_config SET enabled=0 WHERE reader_number=1",[])?;db.execute("DELETE FROM credentials",[])?;assert_decision(&db,0,"reader_disabled")}
    #[test] fn end_of_credential_lifetime_remains_exclusive()->Result<()> {let db=baseline()?;db.execute("UPDATE credentials SET valid_until='2026-11-02T15:00:00Z'",[])?;assert_decision(&db,0,"credential_expired")}
    #[test] fn explicit_reader_enable_restores_grant()->Result<()> {let db=baseline()?;db.execute("UPDATE reader_config SET enabled=0 WHERE reader_number=1",[])?;assert_decision(&db,0,"reader_disabled")?;db.execute("UPDATE reader_config SET enabled=1 WHERE reader_number=1",[])?;assert_decision(&db,0,"access_granted")}
}
