//! Budlum finality on a CosmWasm home chain.
//!
//! The endpoint asks one question: is this Budlum checkpoint final. The
//! answer needs the succinct Budlum finality proof. Until it lands
//! the verifier is fail-closed: no checkpoint is final, the endpoint's
//! silence clock never restarts, and no release passes.

use cosmwasm_std::StdError;

/// Record a checkpoint with its proof. Fail-closed until the succinct finality proof lands.
pub fn record(_height: u64, _header_hash: [u8; 32], _proof: &[u8]) -> Result<(), StdError> {
    Err(StdError::generic_err("budlum verifier: not open"))
}

/// Whether a Budlum checkpoint height is final. False until the succinct finality proof lands.
#[must_use]
pub fn height_final(_height: u64) -> bool {
    false
}
