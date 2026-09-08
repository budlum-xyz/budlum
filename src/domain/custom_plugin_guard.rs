//! WIRING: unwired - E2's plugin-code-hash check waits for the Custom plugin loader.
//!
//! `ConsensusKind::Custom` has no production path that loads plugin BYTES
//! today: `main.rs` registers only the built-in plugins, and the domain
//! dispatch in `blockchain.rs` binds a registered plugin object without ever
//! seeing its code. Until a loader exists that hands over bytes, this guard
//! has no honest caller; it moves the day one lands, and this declaration
//! leaves with it. Deleting the guard instead would be worse: a Custom
//! domain's `plugin_code_hash` field would be a claim nothing checks.

use crate::domain::types::{ConsensusDomain, ConsensusKind};

/// E2: Validate that a Custom domain's plugin code hash matches the registered hash.
///
/// # Errors
///
/// A string finding when the domain is Custom but declares no hash, the
/// plugin bytes are empty, or the computed hash disagrees with the
/// registered one.
pub fn validate_custom_plugin_hash(
    domain: &ConsensusDomain,
    plugin_bytes: &[u8],
) -> Result<(), String> {
    use sha3::{Digest, Sha3_256};
    if let ConsensusKind::Custom(_) = &domain.kind {
        let expected = domain.plugin_code_hash.ok_or_else(|| {
            format!(
                "Custom domain {} must declare a plugin_code_hash",
                domain.id
            )
        })?;
        let computed: crate::domain::types::Hash32 = Sha3_256::digest(plugin_bytes).into();
        if expected != computed {
            return Err(format!(
                "Custom domain {} plugin code hash mismatch: expected {:?}, computed {:?}",
                domain.id, expected, computed
            ));
        }
    }
    Ok(())
}
