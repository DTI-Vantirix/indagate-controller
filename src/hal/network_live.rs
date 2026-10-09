//! NetworkManager-backed transaction operations.
//! Deliberately NOT registered with cloud command dispatch.
//! A future caller must supply a real authenticated cloud confirmation callback.
use crate::hal::network_checkpoint::NetworkCheckpoint;
use crate::hal::network_safety::{HostNetworkLock, bounded_command};
use crate::hal::network_transaction::{NetworkTransactionBackend, TransactionPlan};
use anyhow::{Context, Result, anyhow};
use std::path::Path;
use std::time::Duration;

const CLOUD_URL: &str = "https://gxwfuurzkdhxwxdbtdmt.supabase.co/functions/v1/nexus-device";

fn command(program: &str, args: &[&str]) -> Result<String> {
    bounded_command(program, args, Duration::from_secs(25))
}

fn active_uuid() -> Result<String> {
    command(
        "nmcli",
        &["-g", "GENERAL.CON-UUID", "device", "show", "wlan0"],
    )
}

fn verify_uuid(expected: &str, observed: &str) -> Result<()> {
    let expected = uuid::Uuid::parse_str(expected).context("invalid requested UUID")?;
    let observed = uuid::Uuid::parse_str(observed).context("wlan0 has no valid active UUID")?;
    if expected != observed {
        return Err(anyhow!("wlan0 is connected to a different saved profile"));
    }
    Ok(())
}

fn verify_wifi_https() -> Result<()> {
    // CURLOPT_INTERFACE equivalent pins outbound traffic to wlan0.
    // Do not use --insecure, and do not follow redirects.
    let status = command(
        "curl",
        &[
            "--interface",
            "wlan0",
            "--connect-timeout",
            "5",
            "--max-time",
            "12",
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            CLOUD_URL,
        ],
    )?;
    let status: u16 = status.parse().context("invalid HTTPS status response")?;
    // 401/403 are proof of TLS transport, NOT authentication.
    if !(200..500).contains(&status) {
        return Err(anyhow!("Wi-Fi HTTPS probe returned status {status}"));
    }
    Ok(())
}

/// Cloud confirmation MUST be authenticated, correlated with a unique command ID,
/// and durable/idempotent before production remote execution is enabled.
/// This module does not supply or invoke a production confirmation implementation.
pub trait CloudConfirmation {
    fn confirm_authenticated(&mut self, plan: &TransactionPlan) -> Result<()>;
}

/// Local backend; not reachable from cloud commands.
/// External operation locks and reboot-safe restoration are still outstanding.
pub struct LiveNetworkBackend<C: CloudConfirmation> {
    checkpoint: Option<NetworkCheckpoint>,
    confirmation: C,
    host_lock: Option<HostNetworkLock>,
}

impl<C: CloudConfirmation> LiveNetworkBackend<C> {
    pub fn new(confirmation: C) -> Self {
        Self {
            checkpoint: None,
            confirmation,
            host_lock: None,
        }
    }
}

impl<C: CloudConfirmation> NetworkTransactionBackend for LiveNetworkBackend<C> {
    fn preflight(&mut self, plan: &TransactionPlan) -> Result<()> {
        if self.host_lock.is_some() {
            return Err(anyhow!("network transaction lock already held"));
        }
        self.host_lock = Some(HostNetworkLock::acquire(Path::new(
            "/run/lock/hlaxs-network.lock",
        ))?);

        if plan.interface != "wlan0" {
            return Err(anyhow!("unsupported network interface"));
        }
        let type_name = command(
            "nmcli",
            &[
                "-g",
                "connection.type",
                "connection",
                "show",
                &plan.profile_uuid,
            ],
        )?;
        if type_name != "802-11-wireless" {
            return Err(anyhow!("target profile is not Wi-Fi"));
        }
        let bound = command(
            "nmcli",
            &[
                "-g",
                "connection.interface-name",
                "connection",
                "show",
                &plan.profile_uuid,
            ],
        )?;
        if !bound.is_empty() && bound != "wlan0" {
            return Err(anyhow!("target profile belongs to another interface"));
        }
        Ok(())
    }

    fn checkpoint(&mut self, plan: &TransactionPlan) -> Result<()> {
        if self.checkpoint.is_some() {
            return Err(anyhow!("checkpoint already exists"));
        }
        self.checkpoint = Some(NetworkCheckpoint::create(plan.rollback_timeout_seconds)?);
        Ok(())
    }

    fn activate(&mut self, plan: &TransactionPlan) -> Result<()> {
        if self.checkpoint.is_none() {
            return Err(anyhow!("checkpoint not armed"));
        }
        command(
            "nmcli",
            &[
                "--wait",
                "15",
                "connection",
                "up",
                "uuid",
                &plan.profile_uuid,
                "ifname",
                "wlan0",
            ],
        )?;
        Ok(())
    }

    fn verify_wifi(&mut self, plan: &TransactionPlan) -> Result<()> {
        verify_uuid(&plan.profile_uuid, &active_uuid()?)?;
        verify_wifi_https()
    }

    fn confirm_cloud(&mut self, plan: &TransactionPlan) -> Result<()> {
        self.confirmation.confirm_authenticated(plan)
    }

    fn commit_checkpoint(&mut self) -> Result<()> {
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| anyhow!("checkpoint missing"))?;
        checkpoint.confirm()?;
        self.checkpoint = None;
        Ok(())
    }

    fn rollback_checkpoint(&mut self) -> Result<()> {
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| anyhow!("checkpoint missing"))?;
        checkpoint.rollback()?;
        self.checkpoint = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_same_uuid_case_insensitively() {
        assert!(
            verify_uuid(
                "B5513DDD-CA75-498C-97D1-2E2B5C151EC0",
                "b5513ddd-ca75-498c-97d1-2e2b5c151ec0"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_different_uuid() {
        assert!(
            verify_uuid(
                "b5513ddd-ca75-498c-97d1-2e2b5c151ec0",
                "6f4fed01-a7e6-4e25-8d8a-161989c824ad"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_empty_uuid() {
        assert!(verify_uuid("b5513ddd-ca75-498c-97d1-2e2b5c151ec0", "").is_err());
    }
}
