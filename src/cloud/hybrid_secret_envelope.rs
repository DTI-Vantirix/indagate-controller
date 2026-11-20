//! SA-15E development-only hybrid credential envelope.
//!
//! A fresh random AES-256-GCM data-encryption key (DEK) protects each synthetic
//! credential using SA-15C's authenticated envelope. An external key-wrapper
//! encrypts just the 32-byte DEK using a 16-byte IV. On SightPas the backend
//! will be CAAM's `tk(cbc(aes))` protected-key transform.
//!
//! CAUTION: This Rust module provides the CONTRACT, not a live CAAM AF_ALG
//! implementation. The separate controller bench exercises real CAAM and GCM.
//! No existing device.json, enrollment, authorization, or rotation is modified.
//! Current HAB state is OPEN; no production device-bound assurance is claimed.
//!
//! The CBC-wrapped DEK is not independently authenticated: tampering is
//! rejected when the recovered DEK fails to authenticate the inner AEAD data.
//! Do NOT expose an API that returns the unwrapped DEK without verifying AEAD.

use anyhow::{Result, ensure};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use crate::cloud::secret_envelope::{DevelopmentAead, SecretEnvelope};

const SCHEMA: u8 = 1;
const WRAP_BYTES: usize = 32;
const WRAP_IV_BYTES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrappingAlgorithm { CaamTaggedAes256Cbc }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridSecretEnvelope {
    pub schema_version: u8,
    pub wrapping_algorithm: WrappingAlgorithm,
    pub wrapping_key_id: String,
    pub wrap_iv: [u8; WRAP_IV_BYTES],
    pub wrapped_dek: Vec<u8>,
    pub secret: SecretEnvelope,
}

/// This interface deliberately does not have a software production fallback.
/// A real CAAM implementation must be validated on target before it is used
/// with real device credentials. Test implementations belong under #[cfg(test)].
pub trait DataKeyWrapper {
    fn wrap_32(&self, dek: &[u8; WRAP_BYTES], iv: &[u8; WRAP_IV_BYTES]) -> Result<[u8; WRAP_BYTES]>;
    fn unwrap_32(&self, encrypted: &[u8; WRAP_BYTES], iv: &[u8; WRAP_IV_BYTES]) -> Result<[u8; WRAP_BYTES]>;
}

fn valid_key_id(id: &str) -> bool {
    id.starts_with("hlaxs-sa15e-") && id.len() <= 128 &&
        id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl HybridSecretEnvelope {
    pub fn validate_for(&self, controller_id: &str, object_id: &str) -> Result<()> {
        ensure!(self.schema_version == SCHEMA, "unsupported hybrid secret version");
        ensure!(self.wrapping_algorithm == WrappingAlgorithm::CaamTaggedAes256Cbc,
            "unsupported wrapping algorithm");
        ensure!(valid_key_id(&self.wrapping_key_id), "invalid CAAM key identifier");
        ensure!(self.wrapped_dek.len() == WRAP_BYTES, "invalid wrapped DEK length");
        self.secret.validate_for(controller_id, object_id)?;
        Ok(())
    }
}

/// Isolated development-only hybrid envelope. Never use for live enrollment,
/// credential migration or a controller with unverified hardware assurance.
pub fn seal_development_hybrid<W: DataKeyWrapper>(
    wrapper: &W, wrapping_key_id: &str, controller_id: &str, object_id: &str,
    synthetic_secret: &[u8],
) -> Result<HybridSecretEnvelope> {
    ensure!(valid_key_id(wrapping_key_id), "invalid CAAM development key id");
    let rng = SystemRandom::new();
    let mut dek = [0u8; WRAP_BYTES];
    let mut iv = [0u8; WRAP_IV_BYTES];
    rng.fill(&mut dek).map_err(|_| anyhow::anyhow!("random DEK creation failed"))?;
    rng.fill(&mut iv).map_err(|_| anyhow::anyhow!("random CAAM wrapping IV creation failed"))?;
    let secret = DevelopmentAead::from_test_key(&dek)?.seal(controller_id, object_id, synthetic_secret)?;
    let wrapped_dek = wrapper.wrap_32(&dek, &iv)?;
    dek.fill(0); // best-effort only; not guaranteed memory erasure
    Ok(HybridSecretEnvelope {
        schema_version: SCHEMA,
        wrapping_algorithm: WrappingAlgorithm::CaamTaggedAes256Cbc,
        wrapping_key_id: wrapping_key_id.to_owned(),
        wrap_iv: iv,
        wrapped_dek: wrapped_dek.to_vec(),
        secret,
    })
}

/// Returns ONLY authenticated secret plaintext; never exposes the unwrapped DEK.
pub fn open_development_hybrid<W: DataKeyWrapper>(
    wrapper: &W, expected_wrapping_key_id: &str, controller_id: &str,
    object_id: &str, envelope: &HybridSecretEnvelope,
) -> Result<Vec<u8>> {
    envelope.validate_for(controller_id, object_id)?;
    ensure!(valid_key_id(expected_wrapping_key_id), "invalid expected key id");
    ensure!(envelope.wrapping_key_id == expected_wrapping_key_id,
        "wrapping key binding mismatch");
    let encrypted: [u8; WRAP_BYTES] = envelope.wrapped_dek.as_slice()
        .try_into().map_err(|_| anyhow::anyhow!("invalid wrapped key"))?;
    let mut dek = wrapper.unwrap_32(&encrypted, &envelope.wrap_iv)?;
    let result = DevelopmentAead::from_test_key(&dek)?
        .open(controller_id, object_id, &envelope.secret);
    dek.fill(0); // best-effort only
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Purely structural fixture; NOT cryptographic and NOT available outside
    // #[cfg(test)]. Production integration must replace this with real CAAM.
    struct FakeWrapper;
    impl DataKeyWrapper for FakeWrapper {
        fn wrap_32(&self, d: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            let mut out = *d;
            for (i, b) in out.iter_mut().enumerate() { *b ^= iv[i % 16] ^ 0xC5; }
            Ok(out)
        }
        fn unwrap_32(&self, e: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
            self.wrap_32(e, iv)
        }
    }
    const KEY: &str = "hlaxs-sa15e-fixture";
    fn example() -> HybridSecretEnvelope {
        seal_development_hybrid(&FakeWrapper, KEY, "controller_A", "object_A", b"FAKE-SECRET")
            .unwrap()
    }
    fn open(e: &HybridSecretEnvelope) -> Result<Vec<u8>> {
        open_development_hybrid(&FakeWrapper, KEY, "controller_A", "object_A", e)
    }
    #[test]
    fn round_trip_fixture() { assert_eq!(open(&example()).unwrap(), b"FAKE-SECRET"); }
    #[test]
    fn modified_wrapped_key_fails() {
        let mut e = example(); e.wrapped_dek[0] ^= 1;
        assert!(open(&e).is_err());
    }
    #[test]
    fn modified_wrap_iv_fails() {
        let mut e = example(); e.wrap_iv[0] ^= 1;
        assert!(open(&e).is_err());
    }
    #[test]
    fn wrong_controller_object_and_key_id_fail() {
        let e = example();
        assert!(open_development_hybrid(&FakeWrapper, KEY, "controller_B", "object_A", &e).is_err());
        assert!(open_development_hybrid(&FakeWrapper, KEY, "controller_A", "object_B", &e).is_err());
        assert!(open_development_hybrid(&FakeWrapper, "hlaxs-sa15e-other", "controller_A", "object_A", &e).is_err());
    }
    #[test]
    fn no_plaintext_in_serialized_form_and_unknown_fields_rejected() {
        let e = example();
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("FAKE-SECRET"));
        assert!(!json.contains("device_secret"));
        let parsed: HybridSecretEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(open(&parsed).unwrap(), b"FAKE-SECRET");
        let injected = json.replacen("{", "{\"device_secret\":\"bad\",", 1);
        assert!(serde_json::from_str::<HybridSecretEnvelope>(&injected).is_err());
    }
    #[test]
    fn bad_names_and_structure_fail_closed() {
        assert!(seal_development_hybrid(&FakeWrapper, "../bad", "controller_A", "object_A", b"fake").is_err());
        let mut e = example(); e.schema_version += 1; assert!(open(&e).is_err());
        let mut e = example(); e.wrapped_dek.pop(); assert!(open(&e).is_err());
    }
}
