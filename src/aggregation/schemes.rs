//! The scheme registry of the aggregation layer: which signature schemes may
//! be claimed, how large their objects are and how a node verifies one
//! natively.
//!
//! A signature object is the public key followed by the signature. Both have
//! a fixed length per scheme, so the object has exactly one length and its
//! two halves need no length prefix.
//!
//! WIRING: [`AGG_SCHEMES`] is read through [`agg_scheme`]; the parameter
//! commitment of the STARK backend lists it when the `verify_sig` programs
//! of Phase 2 exist.

use crate::core::address::Address;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::Hash32;

/// A signature scheme whose signatures may be claimed.
#[derive(Debug, Clone, Copy)]
pub struct AggScheme {
    /// The scheme id.
    pub id: SchemeId,
    /// The canonical name of the scheme.
    pub name: &'static str,
    /// Bytes of a public key.
    pub public_key_bytes: usize,
    /// Bytes of a signature.
    pub signature_bytes: usize,
    /// The account a public key controls, when the key is well formed.
    signer_of: fn(&[u8]) -> Option<Address>,
    /// Whether `signature` is a signature of `public_key` over the message
    /// hash, under the scheme statuses of the chain.
    verifies: fn(&SchemeStatusRegistry, &[u8], &Hash32, &[u8]) -> bool,
}

fn ml_dsa_87_signer(public_key: &[u8]) -> Option<Address> {
    crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(public_key).ok()
}

/// The signature a claimed transaction needs is the one an inline V5
/// transaction carries: ML-DSA-87 over the signing hash under the V5 context.
/// A wallet signs once and the same signature serves both paths.
fn ml_dsa_87_verifies(
    registry: &SchemeStatusRegistry,
    public_key: &[u8],
    msg_hash: &Hash32,
    signature: &[u8],
) -> bool {
    crate::crypto::primitives::verify_ml_dsa_87_signature_in(
        registry,
        crate::crypto::ctx::TX_V5,
        msg_hash,
        signature,
        public_key,
    )
    .is_ok()
}

/// Every scheme whose signatures may be claimed.
pub const AGG_SCHEMES: &[AggScheme] = &[AggScheme {
    id: SchemeId::ML_DSA_87,
    name: "ml-dsa-87-fips204-v1",
    public_key_bytes: 2592,
    signature_bytes: 4627,
    signer_of: ml_dsa_87_signer,
    verifies: ml_dsa_87_verifies,
}];

/// The registry entry of `id`, if its signatures may be claimed.
#[must_use]
pub fn agg_scheme(id: SchemeId) -> Option<&'static AggScheme> {
    AGG_SCHEMES.iter().find(|scheme| scheme.id == id)
}

impl AggScheme {
    /// The exact size of a signature object of this scheme: the public key
    /// and the signature.
    #[must_use]
    pub const fn max_object_bytes(&self) -> usize {
        self.public_key_bytes.saturating_add(self.signature_bytes)
    }

    /// Verify a signature object natively. Returns the account that signed
    /// `msg_hash`, or `None` when the object is not a valid signature of this
    /// scheme over that hash.
    #[must_use]
    pub fn verify_object(
        &self,
        registry: &SchemeStatusRegistry,
        payload: &[u8],
        msg_hash: &Hash32,
    ) -> Option<Address> {
        if payload.len() != self.max_object_bytes() {
            return None;
        }
        let (public_key, signature) = payload.split_at_checked(self.public_key_bytes)?;
        let signer = (self.signer_of)(public_key)?;
        (self.verifies)(registry, public_key, msg_hash, signature).then_some(signer)
    }
}
