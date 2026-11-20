//! SA-15C: authenticated credential-envelope format and software crypto prototype.
//!
//! This module is *not* CAAM-backed and must NOT be wired into live controller
//! enrollment, rotation, or `device.json`. The `DevelopmentAead` key exists in
//! process memory. Real hardware CAAM protected-key encryption is a later step.
//!
//! AES-256-GCM provides ciphertext integrity and authenticates controller and
//! object identifiers as associated data. Only randomly generated 96-bit
//! nonces are used. Never reuse a nonce under the same key.

use anyhow::{Result, anyhow, ensure};
use ring::{aead, rand::{SecureRandom, SystemRandom}};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u8 = 1;
const MAX_SECRET_BYTES: usize = 4096;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const AAD_PREFIX: &[u8] = b"HLAXS.Access/device-secret-envelope/v1\0";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeAlgorithm {
    Aes256Gcm,
}

/// Serialized ciphertext + authenticated metadata. No plaintext or raw key.
/// Do not log the ciphertext or expose this object through untrusted APIs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEnvelope {
    pub schema_version: u8,
    pub algorithm: EnvelopeAlgorithm,
    pub controller_id: String,
    pub object_id: String,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext_and_tag: Vec<u8>,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn associated_data(controller_id: &str, object_id: &str) -> Result<Vec<u8>> {
    ensure!(valid_id(controller_id), "invalid controller identifier");
    ensure!(valid_id(object_id), "invalid credential object identifier");
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + controller_id.len() + object_id.len() + 2);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(controller_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(object_id.as_bytes());
    aad.push(0);
    Ok(aad)
}

impl SecretEnvelope {
    /// Check structural limits before any allocation or cryptographic attempt.
    pub fn validate_for(&self, controller_id: &str, object_id: &str) -> Result<()> {
        ensure!(self.schema_version == SCHEMA_VERSION, "unsupported envelope version");
        ensure!(self.algorithm == EnvelopeAlgorithm::Aes256Gcm, "unsupported encryption algorithm");
        ensure!(self.controller_id == controller_id, "controller binding mismatch");
        ensure!(self.object_id == object_id, "credential object binding mismatch");
        associated_data(&self.controller_id, &self.object_id)?;
        ensure!(
            self.ciphertext_and_tag.len() >= TAG_BYTES + 1
                && self.ciphertext_and_tag.len() <= MAX_SECRET_BYTES + TAG_BYTES,
            "invalid encrypted credential length"
        );
        Ok(())
    }
}

/// SOFTWARE ONLY. The caller supplies an ephemeral 256-bit test key.
/// Using this type with a key extracted from a CAAM black-key blob would
/// defeat the hardware-protected key model: never do that.
pub struct DevelopmentAead {
    cipher: aead::LessSafeKey,
}

impl DevelopmentAead {
    pub fn from_test_key(key_bytes: &[u8; 32]) -> Result<Self> {
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
            .map_err(|_| anyhow!("invalid development encryption key"))?;
        Ok(Self { cipher: aead::LessSafeKey::new(unbound) })
    }

    /// In-memory encryption only. Does not persist the result or use CAAM.
    pub fn seal(&self, controller_id: &str, object_id: &str, secret: &[u8]) -> Result<SecretEnvelope> {
        ensure!(!secret.is_empty() && secret.len() <= MAX_SECRET_BYTES, "invalid test credential length");
        let aad = associated_data(controller_id, object_id)?;
        let mut nonce = [0u8; NONCE_BYTES];
        SystemRandom::new().fill(&mut nonce).map_err(|_| anyhow!("secure random generation failed"))?;
        let mut ciphertext = secret.to_vec();
        self.cipher.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_slice()),
            &mut ciphertext,
        ).map_err(|_| anyhow!("development credential encryption failed"))?;
        Ok(SecretEnvelope {
            schema_version: SCHEMA_VERSION,
            algorithm: EnvelopeAlgorithm::Aes256Gcm,
            controller_id: controller_id.to_owned(),
            object_id: object_id.to_owned(),
            nonce,
            ciphertext_and_tag: ciphertext,
        })
    }

    /// Decrypt only after metadata binding + AEAD authentication succeeds.
    pub fn open(&self, controller_id: &str, object_id: &str, envelope: &SecretEnvelope) -> Result<Vec<u8>> {
        envelope.validate_for(controller_id, object_id)?;
        let aad = associated_data(controller_id, object_id)?;
        let mut data = envelope.ciphertext_and_tag.clone();
        let plaintext = self.cipher.open_in_place(
            aead::Nonce::assume_unique_for_key(envelope.nonce),
            aead::Aad::from(aad.as_slice()),
            &mut data,
        ).map_err(|_| anyhow!("credential authentication failed"))?;
        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> DevelopmentAead { DevelopmentAead::from_test_key(&[0x4A; 32]).unwrap() }
    const TEST_SECRET: &[u8] = b"fictional-cloud-credential-not-real";

    #[test]
    fn software_envelope_round_trip() {
        let cipher = cipher();
        let env = cipher.seal("test_controller", "test_object", TEST_SECRET).unwrap();
        assert_eq!(cipher.open("test_controller", "test_object", &env).unwrap(), TEST_SECRET);
        assert_ne!(&env.ciphertext_and_tag[..TEST_SECRET.len()], TEST_SECRET);
    }

    #[test]
    fn wrong_controller_and_object_fail_closed() {
        let cipher = cipher();
        let env = cipher.seal("controller_A", "object_A", TEST_SECRET).unwrap();
        assert!(cipher.open("controller_B", "object_A", &env).is_err());
        assert!(cipher.open("controller_A", "object_B", &env).is_err());
        let mut altered = env.clone(); altered.controller_id = "controller_B".into();
        assert!(cipher.open("controller_B", "object_A", &altered).is_err());
        let mut altered = env; altered.object_id = "object_B".into();
        assert!(cipher.open("controller_A", "object_B", &altered).is_err());
    }

    #[test]
    fn tampered_ciphertext_and_nonce_fail_closed() {
        let cipher = cipher();
        let env = cipher.seal("controller_A", "object_A", TEST_SECRET).unwrap();
        let mut altered = env.clone(); altered.ciphertext_and_tag[0] ^= 0x01;
        assert!(cipher.open("controller_A", "object_A", &altered).is_err());
        let mut altered = env; altered.nonce[0] ^= 0x01;
        assert!(cipher.open("controller_A", "object_A", &altered).is_err());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let encrypted = cipher().seal("controller_A", "object_A", TEST_SECRET).unwrap();
        let other = DevelopmentAead::from_test_key(&[0x5B; 32]).unwrap();
        assert!(other.open("controller_A", "object_A", &encrypted).is_err());
    }

    #[test]
    fn invalid_ids_and_lengths_fail_closed() {
        let cipher = cipher();
        assert!(cipher.seal("../controller", "obj", TEST_SECRET).is_err());
        assert!(cipher.seal("controller", "obj/../../etc", TEST_SECRET).is_err());
        assert!(cipher.seal("controller", "object", b"").is_err());
        assert!(cipher.seal("controller", "object", &vec![1; 4097]).is_err());
        let mut env = cipher.seal("controller", "object", TEST_SECRET).unwrap();
        env.schema_version = 99;
        assert!(cipher.open("controller", "object", &env).is_err());
    }

    #[test]
    fn serialization_never_includes_plaintext_field() {
        let cipher = cipher();
        let env = cipher.seal("controller", "object", TEST_SECRET).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("device_secret"));
        assert!(!json.contains("fictional-cloud-credential-not-real"));
        let decoded: SecretEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(cipher.open("controller", "object", &decoded).unwrap(), TEST_SECRET);
        let injected = json.replacen("{", "{\"device_secret\":\"unsafe\",", 1);
        assert!(serde_json::from_str::<SecretEnvelope>(&injected).is_err());
    }
}
