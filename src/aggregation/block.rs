//! The block rules of the aggregation layer.
//!
//! A block carries at most one claim frame, and its header carries the hash
//! of that frame. The rules here decide whether the frame and the
//! transactions of a block agree; they are pure, so every node decides the
//! same.
//!
//! Block validation reaches [`check_block_claims`] through
//! [`super::chain::check_block`], and the [`BlockClaims`] it returns go to
//! the fee settlement.

use std::collections::{BTreeMap, BTreeSet};

use super::backend::{AggBackend, AggError};
use super::frame::{verify_segment_attestations, ClaimFrame, FrameError, FrameLimits};
use super::params::{AggMode, AggParams};
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::{DomainId, Hash32};

/// What the block rules need to know about one transaction of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxClaims<'a> {
    /// Whether the transaction is authorized by a claim, and by which.
    pub claimed: Option<Hash32>,
    /// The digest of the claim the account rule asks for: for a scheme
    /// account `Claim::Sig { scheme, signer: from, msg_hash: signing_hash }`
    /// under the domain of the block. `None` when the account cannot be
    /// authorized by a claim.
    pub account_claim: Option<Hash32>,
    /// Whether the account signs with a quantum-safe scheme.
    pub quantum_safe: bool,
    /// The digests of the other claims the transaction uses.
    pub claim_refs: &'a [Hash32],
}

/// Why the claims of a block are not valid.
///
/// The type is exposed for the callers of [`check_block_claims`]:
/// `chain::check_block` turns it into the refusal text of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockClaimError {
    /// The mode is not `On` and the block carries a frame, a frame hash, a
    /// claimed transaction or a claim reference.
    AggregationOff,
    /// A quantum-safe transaction carries its signature inline under `On`.
    InlineQuantumSafe(usize),
    /// The frame and the frame hash of the header are not both present or
    /// both absent.
    FramePresence,
    /// The frame hash of the header is not the hash of the frame (rule 10).
    FrameHashMismatch,
    /// The frame breaks a structure rule (rules 1, 2, 3, 4 and 9).
    Frame(FrameError),
    /// The transaction at this index claims another digest than the account
    /// rule asks for (rule 6).
    WrongAuthClaim(usize),
    /// The transaction at this index refers to a claim that is not in the
    /// frame (rule 7).
    MissingClaim(usize),
    /// No transaction refers to the claim at this index of the frame (rule 8).
    UnusedClaim(usize),
    /// The proof does not verify (rule 5).
    Proof(AggError),
}

impl std::fmt::Display for BlockClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AggregationOff => write!(f, "aggregation is not on and the block uses it"),
            Self::InlineQuantumSafe(at) => {
                write!(
                    f,
                    "transaction {at} carries a quantum-safe signature inline"
                )
            }
            Self::FramePresence => write!(f, "frame and frame hash are not both present"),
            Self::FrameHashMismatch => write!(f, "frame hash of the header does not match"),
            Self::Frame(e) => write!(f, "frame: {e}"),
            Self::WrongAuthClaim(at) => write!(f, "transaction {at} claims the wrong digest"),
            Self::MissingClaim(at) => {
                write!(f, "transaction {at} refers to a claim outside the frame")
            }
            Self::UnusedClaim(at) => write!(f, "no transaction refers to claim {at}"),
            Self::Proof(e) => write!(f, "proof: {e}"),
        }
    }
}

impl std::error::Error for BlockClaimError {}

/// What a valid block says about its claims.
///
/// The type is exposed for the callers of [`check_block_claims`]: the
/// payers are what the fee settlement charges.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockClaims {
    /// Per claim of the frame, in frame order: the index of the first
    /// transaction that refers to it. That transaction pays the claim fee.
    pub payers: Vec<usize>,
}

/// Check the claims of a block.
///
/// Under `Off` and `Shadow` a block must not use the aggregation layer at
/// all: a claimed transaction there would be a transaction nobody verified.
/// Under `On` the ten block rules hold and a quantum-safe transaction may
/// only be authorized by a claim.
///
/// The cheap rules run first and the proof is checked last, so a block that
/// is wrong on its face costs no proof verification.
///
/// # Errors
///
/// The [`BlockClaimError`] of the first rule that fails.
pub fn check_block_claims<B: AggBackend + ?Sized>(
    params: &AggParams,
    domain: DomainId,
    header_frame_hash: Option<&Hash32>,
    frame: Option<&ClaimFrame>,
    txs: &[TxClaims<'_>],
    registry: &SchemeStatusRegistry,
    backend: &B,
) -> Result<BlockClaims, BlockClaimError> {
    if params.mode != AggMode::On {
        let unused = header_frame_hash.is_none()
            && frame.is_none()
            && txs
                .iter()
                .all(|tx| tx.claimed.is_none() && tx.claim_refs.is_empty());
        return if unused {
            Ok(BlockClaims::default())
        } else {
            Err(BlockClaimError::AggregationOff)
        };
    }
    if let Some(at) = txs
        .iter()
        .position(|tx| tx.quantum_safe && tx.claimed.is_none())
    {
        return Err(BlockClaimError::InlineQuantumSafe(at));
    }
    // Rule 6.
    if let Some(at) = txs
        .iter()
        .position(|tx| tx.claimed.is_some() && tx.claimed != tx.account_claim)
    {
        return Err(BlockClaimError::WrongAuthClaim(at));
    }
    let (Some(frame), Some(header_frame_hash)) = (frame, header_frame_hash) else {
        if frame.is_some() || header_frame_hash.is_some() {
            return Err(BlockClaimError::FramePresence);
        }
        // No frame: no transaction may refer to a claim (rule 7).
        return txs
            .iter()
            .position(|tx| tx.claimed.is_some() || !tx.claim_refs.is_empty())
            .map_or_else(
                || Ok(BlockClaims::default()),
                |at| Err(BlockClaimError::MissingClaim(at)),
            );
    };
    // Rules 9, 2, 1, 3 and 4.
    let facts = frame
        .check_structure(domain, &FrameLimits::from(params))
        .map_err(BlockClaimError::Frame)?;
    // Rule 10.
    if super::frame::frame_hash(&facts.master_pi, &frame.segments, &frame.proof)
        != *header_frame_hash
    {
        return Err(BlockClaimError::FrameHashMismatch);
    }
    // Rules 7 and 8.
    let payers = claim_payers(&facts.claim_digests, txs)?;
    // Rule 5: segment aggregator ownership attestations and proof verification.
    verify_segment_attestations(registry, domain, &frame.segments)
        .map_err(BlockClaimError::Proof)?;
    backend
        .verify(frame, domain)
        .map_err(BlockClaimError::Proof)?;
    Ok(BlockClaims { payers })
}

/// Per claim of a frame, in frame order: the index of the first transaction
/// that refers to it (rules 7 and 8). `claim_digests` are the digests of the
/// claims of the frame in frame order.
///
/// This reads the frame and the transactions only; it checks no proof. A
/// path that replays a block the chain accepted earlier uses it to find who
/// paid for which claim.
///
/// # Errors
///
/// [`BlockClaimError::MissingClaim`] when a transaction refers to a claim
/// outside the frame, [`BlockClaimError::UnusedClaim`] when no transaction
/// refers to a claim of the frame.
pub fn claim_payers(
    claim_digests: &[Hash32],
    txs: &[TxClaims<'_>],
) -> Result<Vec<usize>, BlockClaimError> {
    let in_frame: BTreeSet<&Hash32> = claim_digests.iter().collect();
    let mut first_user: BTreeMap<&Hash32, usize> = BTreeMap::new();
    for (at, tx) in txs.iter().enumerate() {
        for digest in tx.claimed.iter().chain(tx.claim_refs) {
            if !in_frame.contains(digest) {
                return Err(BlockClaimError::MissingClaim(at));
            }
            first_user.entry(digest).or_insert(at);
        }
    }
    let mut payers = Vec::with_capacity(claim_digests.len());
    for (at, digest) in claim_digests.iter().enumerate() {
        payers.push(
            *first_user
                .get(digest)
                .ok_or(BlockClaimError::UnusedClaim(at))?,
        );
    }
    Ok(payers)
}
