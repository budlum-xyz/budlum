//! Stateless Aptos Move `fungible_asset` / `coin` pointer descriptor (`WP-52`).
//!
//! Holds zero local balance or allowance resource; every transfer or approval
//! routes back to the asset's home EE over `0xB001` `UniversalCall`.

use budlum_uel_abi::EeId;
use sha3::{Digest, Sha3_256};

/// Magic prefix identifying a stateless Move pointer metadata object.
pub const MOVE_POINTER_META_MAGIC: &[u8; 8] = b"BDLMMVPT";

/// Derives the deterministic 32-byte Move `fungible_asset` pointer object address.
#[must_use]
pub fn derive_move_pointer_object(asset_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_UEL_POINTER_V1");
    h.update(asset_id);
    h.update([EeId::MOVE.0]);
    h.finalize().into()
}
