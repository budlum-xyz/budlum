//! Verification of the post-quantum anchors [`super::pq_anchor`] emits.
//!
//! WIRING: unwired - the node emits and rotates anchors today
//! (`emit_anchor_node_local`, `rotate_anchor_key_with_committee`), but no
//! production path ingests a remote anchor yet: the light client verifies
//! quorum-certificate checkpoints, not anchor records. These entry points
//! are pinned by the `pq_anchor` test suite and wait for the remote-anchor
//! consumer (light client or peer sync) they were written for; they stay
//! public so that consumer needs no API change to call them.

use super::pq_anchor::{
    anchor_payload_for, AnchorError, AnchorKeyEntry, AnchorSignature, AnchorSignatureAlgorithm,
    PqAnchor,
};

pub(crate) fn verify_one(
    algorithm: AnchorSignatureAlgorithm,
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), AnchorError> {
    if !algorithm.is_supported() {
        return Err(AnchorError::UnsupportedAlgorithm { algorithm });
    }
    crate::crypto::primitives::verify_ml_dsa_87_signature(payload, signature, public_key)
        .map_err(|_| AnchorError::InvalidSignature)
}

/// Ensures a signer's (algorithm, key) pair is authorized by the keybook
/// **for the anchor's key epoch** (BLG-0070): a rotated-out entry cannot
/// authorize anything, however it got into the book.
fn in_keybook(
    keybook: &[AnchorKeyEntry],
    algorithm: AnchorSignatureAlgorithm,
    public_key: &[u8],
    key_epoch: u32,
) -> bool {
    keybook
        .iter()
        .any(|e| e.algorithm == algorithm && e.public_key == public_key && e.key_epoch == key_epoch)
}

/// BLG-0075 (P03-F18): how many signatures one anchor may carry. Each one
/// costs an ML-DSA-87 verification; an unbounded list is a DoS multiplier.
pub const MAX_ANCHOR_SIGNATURES: usize = 8;

/// BLG-0075: refuse oversized or self-duplicate signature lists before any
/// expensive verification runs.
pub(crate) fn check_signature_list(signatures: &[AnchorSignature]) -> Result<(), AnchorError> {
    if signatures.is_empty() {
        return Err(AnchorError::MissingAlgorithm {
            algorithm: AnchorSignatureAlgorithm::MlDsa87,
        });
    }
    if signatures.len() > MAX_ANCHOR_SIGNATURES {
        return Err(AnchorError::TooManySignatures {
            max: MAX_ANCHOR_SIGNATURES,
            presented: signatures.len(),
        });
    }
    for (i, sig) in signatures.iter().enumerate() {
        for prev in signatures.iter().take(i) {
            if prev.algorithm == sig.algorithm && prev.public_key == sig.public_key {
                return Err(AnchorError::DuplicateSignature);
            }
        }
    }
    Ok(())
}

/// Full verification: every signature verifies, every signer is keybooked,
/// and every supported algorithm the production profile expects is present.
/// A reserved-algorithm signature does not breed an automatic pass: reserved
/// families fail closed at signature verification anyway.
///
/// # Errors
///
/// The first [`AnchorError`] that applies.
pub fn verify_anchor_full(
    anchor: &PqAnchor,
    keybook: &[AnchorKeyEntry],
    current_key_epoch: u32,
) -> Result<(), AnchorError> {
    check_signature_list(&anchor.signatures)?;
    // BLG-0070 (P03-F13): an anchor from a rotated-out epoch is dead on
    // arrival. Without this comparison an old key kept verifying until the
    // keybook was edited by hand.
    if anchor.key_epoch != current_key_epoch {
        return Err(AnchorError::StaleAnchorEpoch {
            anchor_epoch: anchor.key_epoch,
            current_epoch: current_key_epoch,
        });
    }
    let payload = anchor_payload_for(
        anchor.height,
        &anchor.aggregate_root,
        anchor.stark_root.as_ref(),
        anchor.crossdomain_root.as_ref(),
        anchor.key_epoch,
    );
    for sig in &anchor.signatures {
        if !in_keybook(keybook, sig.algorithm, &sig.public_key, anchor.key_epoch) {
            return Err(AnchorError::SignerNotInKeybook);
        }
        verify_one(sig.algorithm, &sig.public_key, &payload, &sig.signature)?;
    }
    if !anchor
        .signatures
        .iter()
        .any(|s| s.algorithm == AnchorSignatureAlgorithm::MlDsa87)
    {
        return Err(AnchorError::MissingAlgorithm {
            algorithm: AnchorSignatureAlgorithm::MlDsa87,
        });
    }
    Ok(())
}

/// Light verification for wallets and mesh nodes (threshold-of-algorithms):
/// any ONE supported, keybooked, verifying signature is enough. The
/// heavy-node rule ([`verify_anchor_full`]) still applies to everything
/// carrying production weight; accepting one-algorithm verification is how
/// the small-payload goal survives the future dual-signature upgrade rather
/// than being undone by it.
///
/// # Errors
///
/// [`AnchorError::MissingAlgorithm`] when no single supported signature
/// verifies against the keybook.
pub fn verify_anchor_light(
    anchor: &PqAnchor,
    keybook: &[AnchorKeyEntry],
    current_key_epoch: u32,
) -> Result<(), AnchorError> {
    // BLG-0075: the same list bound applies to the light path.
    check_signature_list(&anchor.signatures)?;
    // BLG-0070: light verification applies the same epoch rule.
    if anchor.key_epoch != current_key_epoch {
        return Err(AnchorError::StaleAnchorEpoch {
            anchor_epoch: anchor.key_epoch,
            current_epoch: current_key_epoch,
        });
    }
    let payload = anchor_payload_for(
        anchor.height,
        &anchor.aggregate_root,
        anchor.stark_root.as_ref(),
        anchor.crossdomain_root.as_ref(),
        anchor.key_epoch,
    );
    for sig in &anchor.signatures {
        if !in_keybook(keybook, sig.algorithm, &sig.public_key, anchor.key_epoch) {
            continue;
        }
        if verify_one(sig.algorithm, &sig.public_key, &payload, &sig.signature).is_ok() {
            return Ok(());
        }
    }
    Err(AnchorError::MissingAlgorithm {
        algorithm: AnchorSignatureAlgorithm::MlDsa87,
    })
}
