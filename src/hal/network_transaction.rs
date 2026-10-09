use anyhow::{Result, anyhow};
use std::sync::{Mutex, MutexGuard};

static NETWORK_OPERATION_LOCK: Mutex<()> = Mutex::new(());

pub struct NetworkOperationGuard {
    _guard: MutexGuard<'static, ()>,
}

impl NetworkOperationGuard {
    pub fn acquire() -> Result<Self> {
        let guard = NETWORK_OPERATION_LOCK
            .try_lock()
            .map_err(|_| anyhow!("another network operation is already active"))?;

        Ok(Self { _guard: guard })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Validated,
    CheckpointCreated,
    ActivationRequested,
    ConnectivityVerified,
    CloudConfirmed,
    Completed,
    RolledBack,
}

pub fn valid_transition(current: TransactionState, next: TransactionState) -> bool {
    use TransactionState::*;

    matches!(
        (current, next),
        (Validated, CheckpointCreated)
            | (CheckpointCreated, ActivationRequested)
            | (ActivationRequested, ConnectivityVerified)
            | (ConnectivityVerified, CloudConfirmed)
            | (CloudConfirmed, Completed)
            | (CheckpointCreated, RolledBack)
            | (ActivationRequested, RolledBack)
            | (ConnectivityVerified, RolledBack)
            | (CloudConfirmed, RolledBack)
    )
}

/// A side-effect-free description of a proposed network transaction.
/// No checkpoint is created and no profile is activated by this function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionPlan {
    pub interface: &'static str,
    pub profile_uuid: String,
    pub rollback_timeout_seconds: u32,
}

pub fn validate_transaction_plan(
    profile_uuid: &str,
    timeout_seconds: u32,
) -> Result<TransactionPlan> {
    let parsed =
        uuid::Uuid::parse_str(profile_uuid).map_err(|_| anyhow!("invalid Wi-Fi profile UUID"))?;
    if !(60..=600).contains(&timeout_seconds) {
        return Err(anyhow!("rollback timeout must be 60..=600 seconds"));
    }
    Ok(TransactionPlan {
        interface: "wlan0",
        profile_uuid: parsed.to_string(),
        rollback_timeout_seconds: timeout_seconds,
    })
}

/// Abstracts external effects so the transaction can be tested without touching networking.
/// Production implementations must ensure the checkpoint rollback deadline stays armed
/// until the authenticated cloud confirmation succeeds.
pub trait NetworkTransactionBackend {
    fn preflight(&mut self, plan: &TransactionPlan) -> Result<()>;
    fn checkpoint(&mut self, plan: &TransactionPlan) -> Result<()>;
    fn activate(&mut self, plan: &TransactionPlan) -> Result<()>;
    fn verify_wifi(&mut self, plan: &TransactionPlan) -> Result<()>;
    fn confirm_cloud(&mut self, plan: &TransactionPlan) -> Result<()>;
    fn commit_checkpoint(&mut self) -> Result<()>;
    fn rollback_checkpoint(&mut self) -> Result<()>;
}

/// Transaction orchestration logic only. Not exposed to remote commands yet.
/// A failed operation after checkpoint creation always attempts rollback.
/// A failure to confirm the cloud never commits the checkpoint.
pub fn execute_transaction<B: NetworkTransactionBackend>(
    backend: &mut B,
    plan: &TransactionPlan,
) -> Result<TransactionState> {
    let _guard = NetworkOperationGuard::acquire()?;
    backend.preflight(plan)?;
    backend.checkpoint(plan)?;

    let operation = (|| -> Result<()> {
        backend.activate(plan)?;
        backend.verify_wifi(plan)?;
        backend.confirm_cloud(plan)?;
        backend.commit_checkpoint()?;
        Ok(())
    })();

    match operation {
        Ok(()) => Ok(TransactionState::Completed),
        Err(reason) => {
            if let Err(rollback_error) = backend.rollback_checkpoint() {
                Err(anyhow!(
                    "network transaction failed: {reason}; rollback also failed: {rollback_error}"
                ))
            } else {
                Err(reason)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct FakeBackend {
        events: Vec<&'static str>,
        fail_at: Option<&'static str>,
    }

    impl FakeBackend {
        fn new(fail_at: Option<&'static str>) -> Self {
            Self {
                events: Vec::new(),
                fail_at,
            }
        }

        fn step(&mut self, name: &'static str) -> Result<()> {
            self.events.push(name);
            if self.fail_at == Some(name) {
                Err(anyhow!("simulated {name} failure"))
            } else {
                Ok(())
            }
        }
    }

    impl NetworkTransactionBackend for FakeBackend {
        fn preflight(&mut self, _: &TransactionPlan) -> Result<()> {
            self.step("preflight")
        }
        fn checkpoint(&mut self, _: &TransactionPlan) -> Result<()> {
            self.step("checkpoint")
        }
        fn activate(&mut self, _: &TransactionPlan) -> Result<()> {
            self.step("activate")
        }
        fn verify_wifi(&mut self, _: &TransactionPlan) -> Result<()> {
            self.step("verify_wifi")
        }
        fn confirm_cloud(&mut self, _: &TransactionPlan) -> Result<()> {
            self.step("confirm_cloud")
        }
        fn commit_checkpoint(&mut self) -> Result<()> {
            self.step("commit")
        }
        fn rollback_checkpoint(&mut self) -> Result<()> {
            self.step("rollback")
        }
    }

    fn sample_plan() -> TransactionPlan {
        validate_transaction_plan("b5513ddd-ca75-498c-97d1-2e2b5c151ec0", 120).unwrap()
    }

    #[test]
    fn successful_transaction_commits_only_after_cloud_confirmation() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let mut backend = FakeBackend::new(None);
        assert_eq!(
            execute_transaction(&mut backend, &sample_plan()).unwrap(),
            TransactionState::Completed
        );
        assert_eq!(
            backend.events,
            vec![
                "preflight",
                "checkpoint",
                "activate",
                "verify_wifi",
                "confirm_cloud",
                "commit"
            ]
        );
    }

    #[test]
    fn preflight_failure_never_creates_checkpoint() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let mut backend = FakeBackend::new(Some("preflight"));
        assert!(execute_transaction(&mut backend, &sample_plan()).is_err());
        assert_eq!(backend.events, vec!["preflight"]);
    }

    #[test]
    fn activation_failure_rolls_back() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let mut backend = FakeBackend::new(Some("activate"));
        assert!(execute_transaction(&mut backend, &sample_plan()).is_err());
        assert_eq!(backend.events.last(), Some(&"rollback"));
    }

    #[test]
    fn wifi_verification_failure_rolls_back() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let mut backend = FakeBackend::new(Some("verify_wifi"));
        assert!(execute_transaction(&mut backend, &sample_plan()).is_err());
        assert!(!backend.events.contains(&"confirm_cloud"));
        assert_eq!(backend.events.last(), Some(&"rollback"));
    }

    #[test]
    fn cloud_confirmation_failure_does_not_commit() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let mut backend = FakeBackend::new(Some("confirm_cloud"));
        assert!(execute_transaction(&mut backend, &sample_plan()).is_err());
        assert!(!backend.events.contains(&"commit"));
        assert_eq!(backend.events.last(), Some(&"rollback"));
    }

    #[test]
    fn checkpoint_commit_failure_attempts_rollback() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let mut backend = FakeBackend::new(Some("commit"));
        assert!(execute_transaction(&mut backend, &sample_plan()).is_err());
        assert_eq!(backend.events.last(), Some(&"rollback"));
    }

    #[test]
    fn plan_accepts_valid_uuid_and_timeout() {
        let plan = validate_transaction_plan("b5513ddd-ca75-498c-97d1-2e2b5c151ec0", 120).unwrap();
        assert_eq!(plan.interface, "wlan0");
        assert_eq!(plan.rollback_timeout_seconds, 120);
    }

    #[test]
    fn plan_rejects_bad_uuid() {
        assert!(validate_transaction_plan("not-uuid", 120).is_err());
    }

    #[test]
    fn plan_rejects_unsafe_timeout() {
        let uuid = "b5513ddd-ca75-498c-97d1-2e2b5c151ec0";
        assert!(validate_transaction_plan(uuid, 0).is_err());
        assert!(validate_transaction_plan(uuid, 601).is_err());
    }

    #[test]
    fn acquires_network_lock() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let _guard = NetworkOperationGuard::acquire().unwrap();
    }

    #[test]
    fn blocks_overlapping_operations() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let first = NetworkOperationGuard::acquire().unwrap();

        assert!(NetworkOperationGuard::acquire().is_err());

        drop(first);

        assert!(NetworkOperationGuard::acquire().is_ok());
    }

    #[test]
    fn accepts_normal_transaction_sequence() {
        use TransactionState::*;

        assert!(valid_transition(Validated, CheckpointCreated));
        assert!(valid_transition(CheckpointCreated, ActivationRequested));
        assert!(valid_transition(ActivationRequested, ConnectivityVerified));
        assert!(valid_transition(ConnectivityVerified, CloudConfirmed));
        assert!(valid_transition(CloudConfirmed, Completed));
    }

    #[test]
    fn rejects_early_confirmation() {
        use TransactionState::*;

        assert!(!valid_transition(Validated, Completed));
        assert!(!valid_transition(ActivationRequested, Completed));
        assert!(!valid_transition(ConnectivityVerified, Completed));
    }

    #[test]
    fn allows_rollback_after_checkpoint() {
        use TransactionState::*;

        assert!(valid_transition(CheckpointCreated, RolledBack));
        assert!(valid_transition(ActivationRequested, RolledBack));
        assert!(valid_transition(ConnectivityVerified, RolledBack));
    }

    #[test]
    fn prohibits_changes_after_completion() {
        use TransactionState::*;

        assert!(!valid_transition(Completed, ActivationRequested));
        assert!(!valid_transition(RolledBack, ActivationRequested));
    }
}
