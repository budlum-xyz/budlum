//! WIRING: unwired - standalone Bitcoin SPV raw-transaction and confirmed-payment
//! Merkle verifiers await the BTC bridge redemption transaction door.

use super::{
    sha256d, verify_spv_tx_inclusion, VerifiedBitcoinChain, VerifiedSpvTransaction,
    FORBIDDEN_INNER_NODE_TX_BYTES, MAX_STRIPPED_TX_BYTES,
};
use crate::cross_domain::external::spec::AdapterError;

/// Verify inclusion of a raw stripped Bitcoin transaction against `merkle_root`
/// while enforcing CVE-2017-12842 (forbidding 64-byte stripped transactions)
/// and CVE-2012-2459 (duplicate-branch guard in [`verify_spv_tx_inclusion`]).
///
/// # Errors
///
/// Returns [`AdapterError`] if `stripped_tx` exceeds bounds, measures
/// exactly 64 bytes, violates coinbase position rules, or fails Merkle proof
/// verification against `merkle_root`.
///
/// Convenience: kept for the CLI and bridge Bitcoin payment settlement callers.
pub fn verify_spv_raw_tx_inclusion(
    stripped_tx: &[u8],
    merkle_root: &[u8; 32],
    tx_index: u32,
    branch: &[[u8; 32]],
    expect_coinbase: bool,
) -> Result<VerifiedSpvTransaction, AdapterError> {
    if stripped_tx.is_empty() || stripped_tx.len() > MAX_STRIPPED_TX_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: format!(
                "stripped Bitcoin tx length {} is outside 1..={MAX_STRIPPED_TX_BYTES}",
                stripped_tx.len()
            ),
        });
    }
    if stripped_tx.len() == FORBIDDEN_INNER_NODE_TX_BYTES {
        return Err(AdapterError::ConsensusRule {
            rule: "64-byte stripped Bitcoin tx refused (CVE-2017-12842 inner-node guard)"
                .to_string(),
        });
    }
    let is_coinbase = tx_index == 0;
    if expect_coinbase != is_coinbase {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Bitcoin coinbase flag mismatch: expect_coinbase={expect_coinbase} at tx_index={tx_index}"
            ),
        });
    }
    let txid = sha256d(stripped_tx);
    if !verify_spv_tx_inclusion(&txid, merkle_root, tx_index, branch) {
        return Err(AdapterError::ConsensusRule {
            rule: "Bitcoin SPV Merkle branch does not verify against header merkle_root"
                .to_string(),
        });
    }
    Ok(VerifiedSpvTransaction {
        txid,
        tx_index,
        is_coinbase,
        confirmations: 1,
    })
}

impl VerifiedBitcoinChain {
    /// Verify a raw stripped transaction inside `block_hash` with at least
    /// `min_confirmations` proof-of-work confirmations on this verified chain.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if `block_hash` is absent from this verified
    /// chain, has fewer than `min_confirmations` confirmations, or the stripped
    /// transaction fails CVE-2017-12842 / CVE-2012-2459 Merkle verification.
    ///
    /// Convenience: kept for the CLI and bridge Bitcoin payment verifiers.
    pub fn verify_confirmed_payment(
        &self,
        block_hash: &[u8; 32],
        stripped_tx: &[u8],
        tx_index: u32,
        branch: &[[u8; 32]],
        expect_coinbase: bool,
        min_confirmations: u64,
    ) -> Result<VerifiedSpvTransaction, AdapterError> {
        let header = self
            .headers
            .iter()
            .find(|h| h.hash == *block_hash)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Bitcoin payment block hash is not part of the verified chain".to_string(),
            })?;
        let confirmations = self
            .attestation
            .height
            .checked_sub(header.height)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Bitcoin confirmation depth underflowed".to_string(),
            })?;
        let required = min_confirmations.max(1);
        if confirmations < required {
            return Err(AdapterError::InsufficientDepth {
                observed: confirmations,
                required,
            });
        }
        let mut verified = verify_spv_raw_tx_inclusion(
            stripped_tx,
            &header.merkle_root,
            tx_index,
            branch,
            expect_coinbase,
        )?;
        verified.confirmations = confirmations;
        Ok(verified)
    }
}
