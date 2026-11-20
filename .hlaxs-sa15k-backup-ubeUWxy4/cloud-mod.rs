pub mod agent;
pub mod config_shadow;
pub mod unified_shadow_040;

// SA-15A: diagnostic only; not wired into live authorization or enrollment.
pub mod device_trust;

// SA-15B: additive; no live credential migration or startup calls.
pub mod device_secret_storage;
pub mod caam_key_blob;

// SA-15C: authenticated test envelope, not used for live credentials.
pub mod secret_envelope;

// SA-15E: isolated development hybrid; not used by live identity.
pub mod hybrid_secret_envelope;

// SA-15F: native AF_ALG adapter; NOT used by live agent.
pub mod caam_afalg_wrapper;

// SA-15H synthetic lab-only; no live cloud-agent integration.
pub mod sa15h_staged_store;

// SA-15I: disabled-by-default metadata-only cloud lifecycle bridge.
pub mod sa15i_identity_bridge;

// SA-15J: synthetic-only migration/recovery lab; no live agent hook.
pub mod sa15j_legacy_migration_lab;
