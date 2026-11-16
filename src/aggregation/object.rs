//! Native verification of a heavy object and the claim it stands for.

use super::claim::Claim;
use super::envelope::{Envelope, ObjectKind};
use super::params::AggParams;
use super::schemes::agg_scheme;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};

/// Why an object was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectError {
    /// The scheme is not in the aggregation scheme registry.
    UnknownScheme(u16),
    /// The payload is longer than the limit of its kind.
    PayloadTooLarge(usize),
    /// Native verification failed.
    Invalid,
    /// The node does not aggregate objects of this kind yet.
    KindNotEnabled(ObjectKind),
}

impl std::fmt::Display for ObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownScheme(id) => write!(f, "scheme {id:#06x} cannot be claimed"),
            Self::PayloadTooLarge(len) => write!(f, "payload of {len} bytes is over the limit"),
            Self::Invalid => write!(f, "the object does not verify"),
            Self::KindNotEnabled(kind) => write!(f, "objects of kind {kind:?} are not aggregated"),
        }
    }
}

impl std::error::Error for ObjectError {}

/// The largest payload an object of this kind may carry (admission rule 1).
///
/// # Errors
///
/// [`ObjectError::UnknownScheme`] for a signature of a scheme outside the
/// registry (admission rule 2).
pub fn max_payload_bytes(
    params: &AggParams,
    kind: ObjectKind,
    scheme: SchemeId,
) -> Result<usize, ObjectError> {
    match kind {
        ObjectKind::Signature => agg_scheme(scheme)
            .map(super::schemes::AggScheme::max_object_bytes)
            .ok_or(ObjectError::UnknownScheme(scheme.0)),
        ObjectKind::StarkProof => Ok(params.max_stark_object_bytes),
        ObjectKind::PcsOpening => Ok(params.max_pcs_object_bytes),
    }
}

/// Verify the object of an envelope natively and derive its claim.
///
/// A signature object is checked against the hash of the transaction the
/// envelope names. The hash of a transaction is its signing hash, so the
/// claim is the one the account rule asks for:
/// `Claim::Sig { scheme, signer, msg_hash: tx.signing_hash() }`. The signer is
/// the account the public key controls, so a claim for an account cannot be
/// derived from another key.
///
/// # Errors
///
/// [`ObjectError`] when the scheme is unknown, the object does not verify or
/// its kind is not aggregated yet.
pub fn derive_claim(
    registry: &SchemeStatusRegistry,
    envelope: &Envelope,
) -> Result<Claim, ObjectError> {
    match envelope.kind {
        ObjectKind::Signature => {
            let scheme =
                agg_scheme(envelope.scheme).ok_or(ObjectError::UnknownScheme(envelope.scheme.0))?;
            let signer = scheme
                .verify_object(registry, &envelope.payload, &envelope.tx_hash)
                .ok_or(ObjectError::Invalid)?;
            Ok(Claim::Sig {
                scheme: scheme.id,
                signer,
                msg_hash: envelope.tx_hash,
            })
        }
        kind @ (ObjectKind::StarkProof | ObjectKind::PcsOpening) => {
            Err(ObjectError::KindNotEnabled(kind))
        }
    }
}
