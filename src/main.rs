mod access;
mod cloud;
mod hal;
mod paths;
mod storage;

use anyhow::{Result, anyhow};
use tracing::info;

fn run_access_self_test(db: &storage::ControllerDatabase) -> Result<()> {
    println!("=== INDAGATE ACCESS SELF TEST ===");

    let tests = [
        ("Known credential / Door 1", 95u8, 10773u16, 0u8),
        ("Known credential / Door 2", 95u8, 10773u16, 1u8),
        ("Unknown credential / Door 1", 99u8, 9999u16, 0u8),
    ];

    for (name, facility, card, channel) in tests {
        let result = access::engine::evaluate(db.connection(), facility, card, channel)?;

        println!();
        println!("{}", name);
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

fn relay_command(args: &[String]) -> Result<bool> {
    if args.len() < 2 || args[1] != "relay" {
        return Ok(false);
    }

    let relay = hal::relay::RelayController::new();

    if args.len() == 3 && args[2] == "status" {
        println!("{}", serde_json::to_string_pretty(&relay.health())?);

        if let Ok((input, output, polarity, config)) = relay.dump_registers() {
            println!(
                "PCA9534 registers: input=0x{:02X} output=0x{:02X} polarity=0x{:02X} config=0x{:02X}",
                input, output, polarity, config
            );
        }

        return Ok(true);
    }

    if args.len() < 4 {
        return Err(anyhow!(
            "usage: relay status | relay on <0-3> | relay off <0-3> | relay pulse <0-3> <ms>"
        ));
    }

    let action = args[2].as_str();

    let channel: u8 = args[3]
        .parse()
        .map_err(|_| anyhow!("invalid relay channel"))?;

    match action {
        "on" => {
            let state = relay.set(channel, true)?;

            println!("{}", serde_json::to_string_pretty(&state)?);
        }

        "off" => {
            let state = relay.set(channel, false)?;

            println!("{}", serde_json::to_string_pretty(&state)?);
        }

        "pulse" => {
            if args.len() < 5 {
                return Err(anyhow!("relay pulse requires duration in milliseconds"));
            }

            let duration_ms: u64 = args[4]
                .parse()
                .map_err(|_| anyhow!("invalid pulse duration"))?;

            relay.pulse(channel, duration_ms)?;

            println!("Relay {} pulsed for {} ms", channel, duration_ms);
        }

        _ => {
            return Err(anyhow!("unknown relay action {}", action));
        }
    }

    Ok(true)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 3 && args[1] == "enroll" {
        let token = &args[2];

        let serial = if args.len() >= 4 {
            args[3].clone()
        } else {
            "ACP4WR6-LAB-001".to_string()
        };

        let identity = cloud::agent::enroll(token, &serial).await?;

        println!("Indagate enrollment successful");
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "device_id":
                    identity.device_id,
                "controller_id":
                    identity.controller_id,
                "organization_id":
                    identity.organization_id,
                "site_id":
                    identity.site_id,
                "hardware_profile":
                    identity.hardware_profile
            }))?
        );

        return Ok(());
    }

    // The strict diagnostic mode this switch used to select no longer exists. A controller
    // still configured for it must not quietly come up as a normal, door-opening controller
    // instead, so it refuses to start until the setting is removed.
    if std::env::var("HLAXS_WIEGAND_EDGE_DIAGNOSTIC").as_deref() == Ok("1") {
        return Err(anyhow!(
            "HLAXS_WIEGAND_EDGE_DIAGNOSTIC=1 is set, but diagnostic mode has been removed; \
             remove that setting to run the controller normally"
        ));
    }

    if relay_command(&args)? {
        return Ok(());
    }

    let profile = hal::profile::acp4wr6_r1();

    let db_path =
        std::env::var("INDAGATE_DB_PATH").or_else(|_| std::env::var("NEXUS_DB_PATH")).unwrap_or_else(|_| paths::default_db_path());

    // Offline schema migration check for an EXPLICITLY SUPPLIED test DB only.
    // Must exit before hardware inspection, I/O workers, or cloud operations.
    if args.get(1).map(String::as_str) == Some("migrate-only") {
        let explicit_path = std::env::var("INDAGATE_DB_PATH").or_else(|_| std::env::var("NEXUS_DB_PATH"))
            .map_err(|_| anyhow!("migrate-only requires explicit INDAGATE_DB_PATH"))?;
        if paths::is_live_db(&explicit_path) {
            return Err(anyhow!("migrate-only refuses the default live database"));
        }
        let test_path = std::path::Path::new(&explicit_path);
        if !test_path.is_file() {
            return Err(anyhow!("migrate-only requires an existing database file"));
        }
        let _database = storage::ControllerDatabase::open(&explicit_path)?;
        println!("MIGRATION-ONLY PASSED — no hardware or cloud workers started");
        return Ok(());
    }

    // Local read-only inspection of persisted command outcomes. This must run
    // before opening hardware or launching any of the controller's tasks.
    if args.get(1).map(String::as_str) == Some("journal-status") {
        let journal_path =
            std::path::PathBuf::from(&db_path).with_extension("network-commands.sqlite");
        let report = hal::command_reconciliation::inspect(&journal_path)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let db = storage::ControllerDatabase::open(&db_path)?;

    db.set_config("hardware_model", profile.model)?;
    db.set_config("controller_mode", "observe")?;

    if args.iter().any(|arg| arg == "--self-test-access") {
        run_access_self_test(&db)?;
        return Ok(());
    }

    let health = hal::health::inspect();
    let inputs = hal::input::snapshot(&profile);

    info!("Indagate Controller starting");
    info!("Hardware profile: {}", profile.model);

    info!(
        database = %db_path,
        credentials = db.count_credentials()?,
        "Local database ready"
    );

    println!("=== HARDWARE HEALTH ===");
    println!("{}", serde_json::to_string_pretty(&health)?);

    println!();
    println!("=== INITIAL INPUT SNAPSHOT ===");
    println!("{}", serde_json::to_string_pretty(&inputs)?);

    println!();
    println!("=== INDAGATE ACTIVE ACCESS MODE ===");

    let (relay_tx, relay_rx) = tokio::sync::mpsc::channel(64);

    //
    // If fire is already active when Indagate starts,
    // queue the fire override before any schedule
    // controller can issue steady relay commands.
    //
    if inputs.fire.raw_value == Some(0) {
        relay_tx
            .send(hal::relay_worker::RelayCommand::FireOverride { active: true })
            .await?;
    }

    tokio::join!(
        hal::monitor::run(&profile, &db_path, relay_tx.clone(),),
        hal::wiegand::run(&profile, &db_path, relay_tx.clone(),),
        hal::osdp::run(profile.rs485_device, &db_path, relay_tx.clone(),),
        access::unlock_schedule::run(&db_path, relay_tx.clone(),),
        cloud::agent::run(&db_path, relay_tx,),
        hal::relay_worker::run(relay_rx),
    );

    Ok(())
}
