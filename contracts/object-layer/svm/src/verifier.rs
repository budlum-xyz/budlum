//! Budlum finality on an SVM home chain.
//!
//! The endpoint asks one question: is this Budlum checkpoint final. The
//! answer needs the succinct Budlum finality proof. Until it lands
//! the verifier is fail-closed: `height_final` is false for every height, so
//! the endpoint's silence clock never restarts and no release passes.

use solana_program::program_error::ProgramError;

/// Custom error code: the proof system is not open yet.
pub const NOT_OPEN: u32 = 0x4255_0001;

/// Record a checkpoint with its proof. Fail-closed until the succinct finality proof lands.
pub fn record(_height: u64, _header_hash: [u8; 32], _proof: &[u8]) -> Result<(), ProgramError> {
    Err(ProgramError::Custom(NOT_OPEN))
}

/// Whether a Budlum checkpoint height is final. False until the succinct finality proof lands.
#[must_use]
pub fn height_final(_height: u64) -> bool {
    false
}
