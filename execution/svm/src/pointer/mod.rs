//! Stateless SPL Token pointer descriptor for non-SVM UAR assets (`WP-52`).
//!
//! Holds zero local balance or allowance storage; every balance/allowance mutation
//! routes back to the asset's home EE over `0xB001` `UniversalCall`.

use budlum_uel_abi::EeId;
use sha2::{Digest, Sha256};

/// Magic prefix identifying a stateless SPL pointer mint account in `ee/svm/account`.
pub const SVM_POINTER_MINT_MAGIC: &[u8; 8] = b"BDLMSPLP";

/// Derives the deterministic 32-byte SPL pointer mint address for `asset_id`.
#[must_use]
pub fn derive_spl_pointer_mint(asset_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_UEL_POINTER_V1");
    h.update(asset_id);
    h.update([EeId::SVM.0]);
    h.finalize().into()
}
