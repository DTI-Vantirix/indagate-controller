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
