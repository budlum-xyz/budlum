//! Universal Blockchain Unification Engine.
//!
//! Coordinates four foundational surfaces without mutating any external chain's
//! consensus rules or any virtual machine's internal execution semantics:
//!
//! - [`domain_catalog`]: Universal chain-as-domain catalog mapping every
//!   blockchain, consensus family, virtual machine, and storage network to a
//!   canonical domain record and Merkle commitment.
//! - [`output_composer`]: Cross-VM and multi-language execution output
//!   normalizer and cycle-free DAG composer producing one Merkle-verifiable
//!   bundle from EVM, WASM, SVM, Move, Cairo, UTXO, and `BudZero` outputs.
//! - [`payment_router`]: Atomic multi-token split-tender payment router (with
//!   on-chain, POS terminal, and card-network settlement rails) and cross-domain
//!   collateral liquidation coordinator.
//! - [`abi_bridge`]: Cross-VM and multi-language canonical call envelope bridge
//!   projecting typed calls across EVM, SVM, Move, `CosmWasm`, UTXO, Cairo, and
//!   `BudZero` without altering any domain's inner rules.
//! - [`storage_fabric`]: Unified Web3 and decentralized storage fabric binding
//!   B.U.D. 3.0, IPFS, Arweave, Filecoin, Walrus, Swarm, Sia, and Storj under
//!   one verified content-addressed URI and failover resolver.
//!
//! WIRING: wired through `src/lib.rs` and the read-only JSON-RPC doors
//! `bud_getUniversalDomains`, `bud_quoteUniversalPayment`,
//! `bud_composeExecutionOutputs`, `bud_resolveUnifiedStorage`,
//! `bud_encodeCrossVmCall`, and `bud_verifyUniversalBundle` in
//! `src/rpc/api.rs` and `src/rpc/server.rs`.

pub mod abi_bridge;
pub mod domain_catalog;
pub mod output_composer;
pub mod payment_router;
pub mod storage_fabric;

pub use abi_bridge::{
    AbiBridgeError, CanonicalCallArg, CrossVmBridge, CrossVmCallEnvelope, CrossVmCallRequest,
    TargetWireEncoding,
};

pub use domain_catalog::{
    CatalogError, DomainCapability, UniversalDomainCatalog, UniversalDomainRecord,
};
pub use output_composer::{
    CanonicalValue, CompositionError, LanguageTag, NormalizedEvent, NormalizedMachineOutput,
    NormalizedStateEffect, OutputBinding, OutputComposer, OutputCompositionPlan, OutputSelector,
    UnifiedOutputBundle,
};
pub use payment_router::{
    CollateralAsset, CrossDomainPosition, DomainTokenBalance, LiquidationError, LiquidationReceipt,
    LiquidityQuote, PaymentError, PaymentRail, SeizedCollateralLeg, SplitTenderLeg,
    UniversalLiquidationCoordinator, UniversalPaymentIntent, UniversalPaymentReceipt,
    UniversalPaymentRouter,
};
pub use storage_fabric::{
    ReplicaResolution, StorageFabricError, StorageNetworkKind, StoragePaymentRequest,
    StorageReplica, UnifiedContentRecord, UnifiedStorageFabric, UniversalContentUri,
    VerificationStrength, Web3SiteAsset,
};

use crate::domain::types::Hash32;
use sha3::{Digest, Sha3_256};

/// Domain-separated SHA3-256 hash over length-prefixed byte slices.
///
/// Every slice is prefixed with its 8-byte little-endian length so distinct
/// field boundaries can never collide.
#[must_use]
pub(crate) fn hash_domain_fields(domain_tag: &[u8], fields: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(
        u64::try_from(domain_tag.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain_tag);
    hasher.update(
        u64::try_from(fields.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Domain-separated binary Merkle node hash (`0x01 || left || right`).
#[must_use]
pub(crate) fn merkle_node_hash(domain_tag: &[u8], left: &Hash32, right: &Hash32) -> Hash32 {
    hash_domain_fields(domain_tag, &[&[0x01], left, right])
}

/// Domain-separated binary Merkle leaf hash (`0x00 || index_le || leaf`).
#[must_use]
pub(crate) fn merkle_leaf_hash(domain_tag: &[u8], index: usize, leaf: &Hash32) -> Hash32 {
    let idx_bytes = u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes();
    hash_domain_fields(domain_tag, &[&[0x00], &idx_bytes, leaf])
}

/// Computes the deterministic binary Merkle root of `leaves`.
///
/// An empty leaf slice commits to the tagged empty hash. Odd levels duplicate
/// the trailing hash cleanly without mutating earlier indices.
#[must_use]
pub(crate) fn unification_merkle_root(domain_tag: &[u8], leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return hash_domain_fields(domain_tag, &[b"EMPTY"]);
    }
    let mut level: Vec<Hash32> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| merkle_leaf_hash(domain_tag, i, leaf))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let Some(&left) = pair.first() else {
                continue;
            };
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(merkle_node_hash(domain_tag, &left, &right));
        }
        level = next;
    }
    level
        .first()
        .copied()
        .unwrap_or_else(|| hash_domain_fields(domain_tag, &[b"EMPTY"]))
}

/// Builds a sibling inclusion proof for `leaf_index` in `leaves`.
#[must_use]
pub(crate) fn build_merkle_proof(
    domain_tag: &[u8],
    leaves: &[Hash32],
    leaf_index: usize,
) -> Option<Vec<Hash32>> {
    if leaf_index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Hash32> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| merkle_leaf_hash(domain_tag, i, leaf))
        .collect();
    let mut idx = leaf_index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            (idx + 1).min(level.len() - 1)
        } else {
            idx - 1
        };
        proof.push(*level.get(sibling_idx)?);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let Some(&left) = pair.first() else {
                continue;
            };
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(merkle_node_hash(domain_tag, &left, &right));
        }
        level = next;
        idx /= 2;
    }
    Some(proof)
}

/// Verifies a sibling inclusion proof against `root` for `leaf` at `leaf_index`.
#[must_use]
pub(crate) fn verify_merkle_proof(
    domain_tag: &[u8],
    root: &Hash32,
    leaf_index: usize,
    leaf_count: usize,
    leaf: &Hash32,
    proof: &[Hash32],
) -> bool {
    if leaf_count == 0 || leaf_index >= leaf_count {
        return false;
    }
    let expected_depth = if leaf_count == 1 {
        0
    } else {
        usize::try_from((leaf_count - 1).ilog2() + 1).unwrap_or(usize::MAX)
    };
    if proof.len() != expected_depth {
        return false;
    }
    let mut current = merkle_leaf_hash(domain_tag, leaf_index, leaf);
    let mut idx = leaf_index;
    for sibling in proof {
        current = if idx.is_multiple_of(2) {
            merkle_node_hash(domain_tag, &current, sibling)
        } else {
            merkle_node_hash(domain_tag, sibling, &current)
        };
        idx /= 2;
    }
    current == *root
}

/// Exact 256-bit unsigned product of two `u128` values, returned as `(hi, lo)`.
#[must_use]
const fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let mid1 = (p0 >> 64) + (p1 & 0xFFFF_FFFF_FFFF_FFFF) + (p2 & 0xFFFF_FFFF_FFFF_FFFF);
    let lo = (p0 & 0xFFFF_FFFF_FFFF_FFFF) | (mid1 << 64);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid1 >> 64);
    (hi, lo)
}

/// Exact division of a 256-bit value `(hi, lo)` by a non-zero `u128` divisor.
///
/// Returns `(quotient, remainder)` when the quotient fits in `u128`, or `None`
/// if `denom == 0` or the quotient exceeds `u128::MAX`.
#[must_use]
fn div_u256_by_u128(hi: u128, lo: u128, denom: u128) -> Option<(u128, u128)> {
    if denom == 0 || hi >= denom {
        return None;
    }
    let mut rem = hi;
    let mut quot = 0u128;
    for bit in (0..128).rev() {
        let carry = rem >> 127;
        rem = (rem << 1) | ((lo >> bit) & 1);
        quot <<= 1;
        if carry != 0 || rem >= denom {
            rem = rem.wrapping_sub(denom);
            quot |= 1;
        }
    }
    Some((quot, rem))
}

/// Computes `floor(a * b / denom)` without intermediate `u128` overflow.
///
/// Returns `None` if `denom == 0` or the final quotient exceeds `u128::MAX`.
#[must_use]
pub(crate) fn mul_div_floor(a: u128, b: u128, denom: u128) -> Option<u128> {
    let (hi, lo) = mul_u128_wide(a, b);
    let (q, _) = div_u256_by_u128(hi, lo, denom)?;
    Some(q)
}

/// Computes `ceil(a * b / denom)` without intermediate `u128` overflow.
///
/// Returns `None` if `denom == 0` or the final ceiling exceeds `u128::MAX`.
#[must_use]
pub(crate) fn mul_div_ceil(a: u128, b: u128, denom: u128) -> Option<u128> {
    let (hi, lo) = mul_u128_wide(a, b);
    let (q, r) = div_u256_by_u128(hi, lo, denom)?;
    if r == 0 {
        Some(q)
    } else {
        q.checked_add(1)
    }
}

/// Validates a short ASCII identifier (non-empty, bounded length, no control
/// bytes or path-traversal markers).
pub(crate) fn validate_safe_label(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max_len {
        return Err(format!("{field} length must be within 1..={max_len}"));
    }
    if value.contains("..")
        || value.contains('\\')
        || value.bytes().any(|b| b == 0 || b.is_ascii_control())
    {
        return Err(format!("{field} contains forbidden characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_mul_div_avoids_u128_intermediate_overflow_and_rounds_safely() {
        let big = u128::MAX / 2;
        assert_eq!(mul_div_floor(big, 4, 4), Some(big));
        assert_eq!(mul_div_ceil(big, 4, 4), Some(big));
        // Rounding up protects payments from rounding down to zero.
        assert_eq!(mul_div_floor(1, 1, 1_000_000), Some(0));
        assert_eq!(mul_div_ceil(1, 1, 1_000_000), Some(1));
        assert_eq!(mul_div_ceil(10, 3, 4), Some(8));
        assert_eq!(mul_div_floor(10, 3, 4), Some(7));
        assert_eq!(mul_div_ceil(1, 1, 0), None);
        assert_eq!(mul_div_floor(u128::MAX, 2, 1), None);
    }

    #[test]
    fn merkle_proofs_verify_and_reject_tampering() {
        let leaves: Vec<Hash32> = (0u8..5).map(|i| [i.wrapping_add(1); 32]).collect();
        let root = unification_merkle_root(b"TEST_MERKLE", &leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = build_merkle_proof(b"TEST_MERKLE", &leaves, i).unwrap();
            assert!(verify_merkle_proof(
                b"TEST_MERKLE",
                &root,
                i,
                leaves.len(),
                leaf,
                &proof
            ));
            let mut bad_leaf = *leaf;
            bad_leaf[0] ^= 0xFF;
            assert!(!verify_merkle_proof(
                b"TEST_MERKLE",
                &root,
                i,
                leaves.len(),
                &bad_leaf,
                &proof
            ));
        }
    }
}
