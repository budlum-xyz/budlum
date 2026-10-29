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
use super::pq_anchor::{AnchorError, AnchorSignature, AnchorSignatureAlgorithm, PqAnchor};

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
/// DoS multiplier.
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
