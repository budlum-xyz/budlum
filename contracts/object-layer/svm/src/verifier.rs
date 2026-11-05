//! Budlum finality on an SVM home chain (WP-63, part 2).
//!
//! The endpoint asks one question: is this Budlum checkpoint final. The
//! answer needs the succinct Budlum finality proof (WP-60). Until it lands
//! the verifier is fail-closed: `height_final` is false for every height, so
//! the endpoint's silence clock never restarts and no release passes.

use solana_program::program_error::ProgramError;

/// Custom error code: the proof system is not open yet (WP-60).
pub const NOT_OPEN: u32 = 0x4255_0001;

/// Record a checkpoint with its proof. Fail-closed until WP-60.
pub fn record(_height: u64, _header_hash: [u8; 32], _proof: &[u8]) -> Result<(), ProgramError> {
    Err(ProgramError::Custom(NOT_OPEN))
}

/// Whether a Budlum checkpoint height is final. False until WP-60.
#[must_use]
pub fn height_final(_height: u64) -> bool {
    false
}
