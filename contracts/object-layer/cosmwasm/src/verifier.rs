//! Budlum finality on a CosmWasm home chain (WP-62, part 2).
//!
//! The endpoint asks one question: is this Budlum checkpoint final. The
//! answer needs the succinct Budlum finality proof (WP-60). Until it lands
//! the verifier is fail-closed: no checkpoint is final, the endpoint's
//! silence clock never restarts, and no release passes.

use cosmwasm_std::StdError;

/// Record a checkpoint with its proof. Fail-closed until WP-60.
pub fn record(_height: u64, _header_hash: [u8; 32], _proof: &[u8]) -> Result<(), StdError> {
    Err(StdError::generic_err("budlum verifier: not open (WP-60)"))
}

/// Whether a Budlum checkpoint height is final. False until WP-60.
#[must_use]
pub fn height_final(_height: u64) -> bool {
    false
}
