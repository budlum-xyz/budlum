//! WIRING: unwired - verify_anchor_light is reached only from the anchor-ledger tests in this tree; the finality consumer that will call it is not in this tree yet.
//! Verification of the post-quantum anchors [`super::pq_anchor`] emits.
//!
//! WIRING: the node verifies the anchors it emits before it logs them
//! (`Blockchain::emit_anchor_for`), and the light client path
//! (`verify_anchor_light`) is the entry point for the remote-anchor consumer:
//! the light client verifies quorum-certificate checkpoints today, not anchor
//! records, so the light entry point is pinned by the `pq_anchor` test suite
//! until that consumer lands and stays public so it needs no API change.

use super::anchor_ledger::{AnchorKeyLedger, KeyFamily, ANCHOR_KEY_COUNT, ANCHOR_THRESHOLD};
use super::pq_anchor::{
    anchor_leaf_digest, AnchorError, AnchorInclusionProof, AnchorSignature,
    AnchorSignatureAlgorithm, PqAnchor,
};
use crate::consensus::merkle_tree::{combine_sha3, odd_promotion_sentinel, promote_sha3};
use crate::crypto::facts::QuantumClass;
use subtle::ConstantTimeEq;

/// Hard upper bound on Merkle sibling steps accepted by [`verify_anchor_leaf_light`]
/// (`2^32` leaves), preventing adversarial deep-path hashing `DoS`.
pub const MAX_ANCHOR_MERKLE_DEPTH: usize = 32;

/// Verify one anchor signature under the ledger key bytes (ML-DSA-87,
/// `BDLM/ANCHOR/V2`).
pub(crate) fn verify_one(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), AnchorError> {
    verify_in_context(
        AnchorSignatureAlgorithm::MlDsa87,
        public_key,
        payload,
        crate::crypto::ctx::ANCHOR_V2,
        signature,
    )
}

/// Verify one Root Seal signature under the ledger key bytes
/// (SLH-DSA-SHAKE-256s, `BDLM/SEAL/V1`).
pub(crate) fn verify_seal_signature(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), AnchorError> {
    verify_in_context(
        AnchorSignatureAlgorithm::SlhDsaShake256s,
        public_key,
        payload,
        crate::crypto::ctx::SEAL_V1,
        signature,
    )
}

/// Verify one signature of a supported algorithm under the named context,
/// through the verification facade (both ML-DSA libraries must accept).
pub(crate) fn verify_in_context(
    algorithm: AnchorSignatureAlgorithm,
    public_key: &[u8],
    payload: &[u8],
    ctx: &[u8],
    signature: &[u8],
) -> Result<(), AnchorError> {
    if !algorithm.is_supported() {
        return Err(AnchorError::UnsupportedAlgorithm { algorithm });
    }
    let Some(scheme) = algorithm.scheme_id() else {
        return Err(AnchorError::UnsupportedAlgorithm { algorithm });
    };
    crate::crypto::pq::verify(scheme, public_key, payload, ctx, signature)
        .map_err(|_| AnchorError::InvalidSignature)
}

/// How many signatures one anchor may carry: one per
/// ledger key. Each costs an ML-DSA-87 verification; an unbounded list is a
/// `DoS` multiplier.
pub const MAX_ANCHOR_SIGNATURES: usize = ANCHOR_KEY_COUNT;

/// Refuse oversized or self-duplicate signature lists before any
/// expensive verification runs. An empty list reaches no threshold.
pub(crate) fn check_signature_list(signatures: &[AnchorSignature]) -> Result<(), AnchorError> {
    if signatures.is_empty() {
        return Err(AnchorError::ThresholdNotReached {
            required: ANCHOR_THRESHOLD,
            valid: 0,
        });
    }
    if signatures.len() > MAX_ANCHOR_SIGNATURES {
        return Err(AnchorError::TooManySignatures {
            max: MAX_ANCHOR_SIGNATURES,
            presented: signatures.len(),
        });
    }
    for (i, sig) in signatures.iter().enumerate() {
        if signatures
            .iter()
            .take(i)
            .any(|prev| prev.key_index == sig.key_index)
        {
            return Err(AnchorError::DuplicateSignature);
        }
    }
    Ok(())
}

/// The checks both verification paths share, before any signature is
/// verified: bounded list, the chain, and the key epoch (an anchor
/// from a rotated-out epoch is dead on arrival).
fn precheck(anchor: &PqAnchor, ledger: &AnchorKeyLedger) -> Result<(), AnchorError> {
    check_signature_list(&anchor.signatures)?;
    if bool::from(anchor.aggregate_root.ct_eq(&[0u8; 32])) {
        return Err(AnchorError::ZeroDigest {
            field: "aggregate_root",
        });
    }
    if let Some(sr) = anchor.stark_root.as_ref() {
        if bool::from(sr.ct_eq(&[0u8; 32])) {
            return Err(AnchorError::ZeroDigest {
                field: "stark_root",
            });
        }
    }
    if let Some(cr) = anchor.crossdomain_root.as_ref() {
        if bool::from(cr.ct_eq(&[0u8; 32])) {
            return Err(AnchorError::ZeroDigest {
                field: "crossdomain_root",
            });
        }
    }
    if anchor.chain_id != ledger.chain_id {
        return Err(AnchorError::WrongChain {
            expected: ledger.chain_id,
            got: anchor.chain_id,
        });
    }
    if anchor.key_epoch != ledger.key_epoch {
        return Err(AnchorError::StaleAnchorEpoch {
            anchor_epoch: anchor.key_epoch,
            current_epoch: ledger.key_epoch,
        });
    }
    Ok(())
}

/// Full verification: every listed signature names a ledger key and verifies,
/// and at least two distinct keys that are not suspended did so.
///
/// A signature of a suspended key still has to verify (a forged one is a
/// fault), but it does not count toward the threshold.
///
/// # Errors
///
/// The first [`AnchorError`] that applies.
pub fn verify_anchor_full(anchor: &PqAnchor, ledger: &AnchorKeyLedger) -> Result<(), AnchorError> {
    precheck(anchor, ledger)?;
    let payload = anchor.payload();
    let mut live = 0usize;
    for sig in &anchor.signatures {
        let Some(public_key) = ledger.anchor_key(sig.key_index) else {
            return Err(AnchorError::UnknownKeyIndex {
                index: sig.key_index,
            });
        };
        verify_one(public_key, &payload, &sig.signature)?;
        if !ledger.is_suspended(KeyFamily::Anchor, sig.key_index, anchor.key_epoch) {
            live += 1;
        }
    }
    if live < ANCHOR_THRESHOLD {
        return Err(AnchorError::ThresholdNotReached {
            required: ANCHOR_THRESHOLD,
            valid: live,
        });
    }
    Ok(())
}

/// Light verification for wallets and mesh nodes. It asks for the same
/// threshold as [`verify_anchor_full`]: a light client does not get a lower
/// bar, only a cheaper walk. Signatures that do not verify are skipped and
/// the walk stops as soon as two distinct live keys have verified.
///
/// # Errors
///
/// [`AnchorError::ThresholdNotReached`] when fewer than two live keys verify,
/// or the precheck refusals (chain, epoch, list bounds).
pub fn verify_anchor_light(anchor: &PqAnchor, ledger: &AnchorKeyLedger) -> Result<(), AnchorError> {
    precheck(anchor, ledger)?;
    let payload = anchor.payload();
    let mut live = 0usize;
    for sig in &anchor.signatures {
        let Some(public_key) = ledger.anchor_key(sig.key_index) else {
            continue;
        };
        if ledger.is_suspended(KeyFamily::Anchor, sig.key_index, anchor.key_epoch) {
            continue;
        }
        if verify_one(public_key, &payload, &sig.signature).is_ok() {
            live += 1;
            if live >= ANCHOR_THRESHOLD {
                return Ok(());
            }
        }
    }
    Err(AnchorError::ThresholdNotReached {
        required: ANCHOR_THRESHOLD,
        valid: live,
    })
}

/// Verifies both the 2-of-3 ML-DSA-87 post-quantum anchor and a bounded
/// domain-leaf Merkle inclusion proof against [`PqAnchor::aggregate_root`],
/// returning the leaf's cryptographically bound [`QuantumClass`].
///
/// The cheap inclusion-proof checks (`finality_digest != 0`, path length
/// `<= MAX_ANCHOR_MERKLE_DEPTH`, odd-promotion parity, canonical leaf-index
/// exhaustion, and constant-time root equality) run before expensive ML-DSA-87
/// signature verification so forged paths burn zero lattice verification CPU.
///
/// Convenience: exposed for mobile wallets, light clients, and cross-domain
/// post-quantum settlement verification.
///
/// # Errors
///
/// Returns [`AnchorError::ZeroDigest`], [`AnchorError::InvalidInclusionProof`],
/// or any [`verify_anchor_light`] refusal when verification fails.
pub fn verify_anchor_leaf_light(
    anchor: &PqAnchor,
    ledger: &AnchorKeyLedger,
    proof: &AnchorInclusionProof,
) -> Result<QuantumClass, AnchorError> {
    precheck(anchor, ledger)?;
    if bool::from(proof.leaf.finality_digest.ct_eq(&[0u8; 32])) {
        return Err(AnchorError::ZeroDigest {
            field: "leaf finality_digest",
        });
    }
    if proof.leaf_count == 0 {
        return Err(AnchorError::EmptyAggregation);
    }
    if proof.leaf_count > (1u64 << MAX_ANCHOR_MERKLE_DEPTH) {
        return Err(AnchorError::InvalidInclusionProof(
            "leaf count exceeds maximum Merkle tree capacity",
        ));
    }
    if proof.leaf_index >= proof.leaf_count {
        return Err(AnchorError::InvalidInclusionProof(
            "leaf index out of range for declared leaf count",
        ));
    }
    if proof.siblings.len() > MAX_ANCHOR_MERKLE_DEPTH {
        return Err(AnchorError::InvalidInclusionProof(
            "inclusion path exceeds maximum Merkle depth",
        ));
    }
    let sentinel = odd_promotion_sentinel();
    let mut current = anchor_leaf_digest(&proof.leaf);
    let mut idx = proof.leaf_index;
    let mut layer_len = proof.leaf_count;
    for sibling in &proof.siblings {
        if layer_len <= 1 {
            return Err(AnchorError::InvalidInclusionProof(
                "inclusion path carries extra siblings past the Merkle root",
            ));
        }
        let is_odd = (idx & 1) == 1;
        let must_promote = !is_odd && idx.saturating_add(1) == layer_len;
        let is_sentinel = bool::from(sibling.ct_eq(&sentinel));
        if is_sentinel != must_promote {
            return Err(AnchorError::InvalidInclusionProof(
                "promotion sentinel disagrees with exact layer-tail geometry",
            ));
        }
        if must_promote {
            current = promote_sha3(&current);
        } else {
            if bool::from(sibling.ct_eq(&[0u8; 32])) {
                return Err(AnchorError::ZeroDigest {
                    field: "inclusion sibling",
                });
            }
            current = if is_odd {
                combine_sha3(sibling, &current)
            } else {
                combine_sha3(&current, sibling)
            };
        }
        idx >>= 1;
        layer_len = layer_len.div_ceil(2);
    }
    if layer_len != 1 || idx != 0 {
        return Err(AnchorError::InvalidInclusionProof(
            "inclusion path truncated before reaching the single Merkle root",
        ));
    }
    if !bool::from(current.ct_eq(&anchor.aggregate_root)) {
        return Err(AnchorError::InvalidInclusionProof(
            "rebuilt Merkle root does not match signed aggregate_root",
        ));
    }
    verify_anchor_light(anchor, ledger)?;
    Ok(proof.leaf.quantum_class)
}
