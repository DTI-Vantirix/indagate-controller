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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquires_network_lock() {
        let _guard = NetworkOperationGuard::acquire().unwrap();
    }

    #[test]
    fn blocks_overlapping_operations() {
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
