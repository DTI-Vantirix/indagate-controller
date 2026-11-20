//! SA-15B interface for a future sealed controller credential.
//!
//! No active backend for sealing the legacy `device_secret` is implemented yet.
//! IMPORTANT: A CAAM black-key blob holds a symmetric key, NOT an arbitrary
//! cloud credential. Do not pass existing credentials to `caam-keygen -t`:
//! that puts secrets in process arguments. Never silently fall back to plaintext.

use anyhow::{Result, ensure, bail};
use serde::{Deserialize, Serialize};

pub const SEALED_SECRET_SCHEMA: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackend {
    Caam,
    Tpm2,
    Optee,
    SoftwareDevelopment,
}

/// Safe metadata; MUST NOT contain a secret, ciphertext or a filesystem path.
/// The referenced protected object is handled by the selected backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedSecretRef {
    pub schema_version: u8,
    pub backend: SecretBackend,
    pub controller_id: String,
    pub object_id: String,
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl SealedSecretRef {
    /// Validate binding BEFORE consulting a storage backend. No trust promotion.
    pub fn validate_for(&self, expected_controller_id: &str) -> Result<()> {
        ensure!(self.schema_version == SEALED_SECRET_SCHEMA, "unsupported sealed secret schema");
        ensure!(safe_identifier(&self.controller_id), "invalid controller identity");
        ensure!(self.controller_id == expected_controller_id, "credential controller binding mismatch");
        ensure!(safe_identifier(&self.object_id), "invalid protected object identifier");
        Ok(())
    }
}

/// A backend must either return the exact credential or fail closed.
/// It must never return a placeholder, bypass authentication, or downgrade.
pub trait DeviceSecretStore {
    fn backend(&self) -> SecretBackend;
    fn seal(&self, controller_id: &str, secret: &[u8]) -> Result<SealedSecretRef>;
    fn open(&self, controller_id: &str, reference: &SealedSecretRef) -> Result<Vec<u8>>;
}

/// Compile-time integration placeholder: deliberately refuses live secret use
/// until authenticated encryption with CAAM protected key is implemented and
/// verified on the actual device.
pub struct CaamSecretStorePending;

impl DeviceSecretStore for CaamSecretStorePending {
    fn backend(&self) -> SecretBackend { SecretBackend::Caam }

    fn seal(&self, _controller_id: &str, _secret: &[u8]) -> Result<SealedSecretRef> {
        bail!("CAAM secret encryption has not been validated; migration disabled")
    }

    fn open(&self, _controller_id: &str, _reference: &SealedSecretRef) -> Result<Vec<u8>> {
        bail!("CAAM secret decryption has not been validated; no plaintext fallback")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> SealedSecretRef {
        SealedSecretRef { schema_version: SEALED_SECRET_SCHEMA, backend: SecretBackend::Caam,
            controller_id: "test-controller".into(), object_id: "key1".into() }
    }

    #[test]
    fn reference_is_bound_to_controller() {
        assert!(valid().validate_for("test-controller").is_ok());
        assert!(valid().validate_for("different-controller").is_err());
    }

    #[test]
    fn rejects_bad_schema_and_path_like_ids() {
        let mut r = valid(); r.schema_version = 1;
        assert!(r.validate_for("test-controller").is_err());
        let mut r = valid(); r.object_id = "../../etc/shadow".into();
        assert!(r.validate_for("test-controller").is_err());
    }

    #[test]
    fn sealed_reference_rejects_embedded_plaintext_secret() {
        let raw = r#"{"schema_version":2,"backend":"caam","controller_id":"test-controller","object_id":"key1","device_secret":"DO-NOT-ACCEPT"}"#;
        assert!(serde_json::from_str::<SealedSecretRef>(raw).is_err());
    }

    #[test]
    fn caam_store_fails_closed_until_encryption_is_validated() {
        let backend = CaamSecretStorePending;
        assert_eq!(backend.backend(), SecretBackend::Caam);
        assert!(backend.seal("test-controller", b"fake-secret-for-test").is_err());
        assert!(backend.open("test-controller", &valid()).is_err());
    }
}
