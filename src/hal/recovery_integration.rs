//! Non-hardware recovery scenarios using the same durable SQLite file.
//! These tests never execute relays, touch NetworkManager, or contact the cloud.
#![cfg(test)]

use crate::hal::actuator_command_journal::{ActuatorCommandJournal, ReserveResult};
use crate::hal::command_reconciliation;
use crate::hal::credential_rotation_journal::{CredentialRotationJournal, RotationReservation};
use crate::hal::network_command_journal::{NetworkCommandJournal, ReserveOutcome};
use serde_json::json;
use std::path::PathBuf;

const WIFI_UUID: &str = "b5513ddd-ca75-498c-97d1-2e2b5c151ec0";

struct TestDb(PathBuf);
impl TestDb {
    fn new() -> Self {
        let db = Self(std::env::temp_dir().join(format!(
            "hlaxs-recovery-integration-{}.sqlite",
            uuid::Uuid::new_v4()
        )));
        // The read-only reconciliation view queries all three journals.
        // Initializing every schema mirrors the controller's startup path
        // and prevents tests from depending on which journal ran first.
        CredentialRotationJournal::open(&db.0).expect("initialize rotation journal");
        ActuatorCommandJournal::open(&db.0).expect("initialize actuator journal");
        NetworkCommandJournal::open(&db.0).expect("initialize network journal");
        db
    }
}
impl Drop for TestDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", self.0.display(), suffix));
        }
    }
}

#[test]
fn interrupted_operations_remain_reserved_after_reopen() {
    let db = TestDb::new();
    {
        let mut rotation = CredentialRotationJournal::open(&db.0).unwrap();
        let mut actuator = ActuatorCommandJournal::open(&db.0).unwrap();
        let mut network = NetworkCommandJournal::open(&db.0).unwrap();
        assert_eq!(
            rotation.reserve("rotation_pending").unwrap(),
            RotationReservation::New
        );
        assert_eq!(
            actuator
                .reserve(
                    "relay_pending",
                    "relay_pulse",
                    &json!({"channel": 1, "duration_ms": 5000})
                )
                .unwrap(),
            ReserveResult::New
        );
        assert_eq!(
            network.reserve("wifi_pending", WIFI_UUID).unwrap(),
            ReserveOutcome::New
        );
    }
    {
        let mut rotation = CredentialRotationJournal::open(&db.0).unwrap();
        let mut actuator = ActuatorCommandJournal::open(&db.0).unwrap();
        let mut network = NetworkCommandJournal::open(&db.0).unwrap();
        assert_eq!(
            rotation.reserve("rotation_pending").unwrap(),
            RotationReservation::AlreadyReserved
        );
        assert_eq!(
            actuator
                .reserve(
                    "relay_pending",
                    "relay_pulse",
                    &json!({"channel": 1, "duration_ms": 5000})
                )
                .unwrap(),
            ReserveResult::AlreadyReserved
        );
        assert_eq!(
            network.reserve("wifi_pending", WIFI_UUID).unwrap(),
            ReserveOutcome::AlreadyReserved
        );
        assert!(actuator.unreported(10).unwrap().is_empty());
        assert!(network.unreported(10).unwrap().is_empty());
        let status = command_reconciliation::inspect(&db.0).unwrap();
        assert_eq!(
            status["ambiguous_credential_rotation_command_ids"],
            json!(["rotation_pending"])
        );
        assert_eq!(
            status["ambiguous_actuator_command_ids"],
            json!(["relay_pending"])
        );
        assert_eq!(
            status["ambiguous_network_command_ids"],
            json!(["wifi_pending"])
        );
    }
}

#[test]
fn terminal_actuation_survives_lost_ack_without_reexecution() {
    let db = TestDb::new();
    let payload = json!({"channel": 2});
    {
        let mut actuator = ActuatorCommandJournal::open(&db.0).unwrap();
        actuator
            .reserve("door_outcome", "door_lock", &payload)
            .unwrap();
        assert!(
            actuator
                .finish("door_outcome", &Ok(json!({"state": "locked"})))
                .unwrap()
        );
    }
    {
        let mut actuator = ActuatorCommandJournal::open(&db.0).unwrap();
        assert_eq!(
            actuator
                .reserve("door_outcome", "door_lock", &payload)
                .unwrap(),
            ReserveResult::AlreadyTerminal
        );
        let reports = actuator.unreported(10).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].state, "completed");
        assert_eq!(reports[0].result["state"], "locked");
        assert_eq!(
            command_reconciliation::inspect(&db.0).unwrap()["actuator_terminal_ack_backlog"],
            1
        );
        assert!(actuator.mark_reported("door_outcome").unwrap());
        assert!(actuator.unreported(10).unwrap().is_empty());
        assert_eq!(
            command_reconciliation::inspect(&db.0).unwrap()["actuator_terminal_ack_backlog"],
            0
        );
    }
}

#[test]
fn guarded_wifi_rejection_remains_pending_until_delivery() {
    let db = TestDb::new();
    {
        let network = NetworkCommandJournal::open(&db.0).unwrap();
        network.record_guarded_rejection("wifi_guarded").unwrap();
    }
    {
        let network = NetworkCommandJournal::open(&db.0).unwrap();
        assert_eq!(
            network.pending_guarded_rejections(10).unwrap(),
            vec!["wifi_guarded"]
        );
        network.record_guarded_rejection("wifi_guarded").unwrap();
        assert_eq!(
            command_reconciliation::inspect(&db.0).unwrap()["guarded_wifi_rejection_ack_backlog"],
            1
        );
        assert!(
            network
                .mark_guarded_rejection_reported("wifi_guarded")
                .unwrap()
        );
        assert!(
            !network
                .mark_guarded_rejection_reported("wifi_guarded")
                .unwrap()
        );
        assert!(network.pending_guarded_rejections(10).unwrap().is_empty());
    }
}

#[test]
fn completed_rotation_can_be_reconciled_without_repeating_prepare() {
    let db = TestDb::new();
    {
        let mut rotation = CredentialRotationJournal::open(&db.0).unwrap();
        rotation.reserve("rotation_final").unwrap();
        assert!(rotation.mark_completed("rotation_final").unwrap());
    }
    {
        let mut rotation = CredentialRotationJournal::open(&db.0).unwrap();
        assert_eq!(
            rotation.reserve("rotation_final").unwrap(),
            RotationReservation::AlreadyCompleted
        );
        assert!(!rotation.mark_completed("rotation_final").unwrap());
        assert!(rotation.unresolved().unwrap().is_empty());
        let status = command_reconciliation::inspect(&db.0).unwrap();
        assert_eq!(status["completed_credential_rotation_count"], 1);
    }
}
