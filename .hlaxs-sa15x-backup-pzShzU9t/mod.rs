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

// SA-15K: legacy JSON storage adapter only; no live encrypted cutover.
pub mod sa15k_legacy_identity_store;

// SA-15L: isolated synthetic full-identity encrypted cutover rehearsal only.
pub mod sa15l_sealed_identity_lab;

// SA-15M: fail-closed legacy-only mode guard; sealed migration disabled.
pub mod sa15m_live_identity_gate;

// SA-15N: synthetic-only cutover & local mock cloud rotation replay. No live hooks.
pub mod sa15n_transactional_rotation_lab;

// SA-15U: full DeviceIdentity lab adapter only, no runtime cutover.
pub mod sa15u_agent_sealed_store;

// SA-15V: common cloud-agent identity I/O seam; legacy-only, sealed mode blocked.
pub mod sa15v_identity_router;
