//! E7: Deterministic equal-weight fork resolver (2-2 split).
//!
//! When two competing fork tips carry identical accumulated weight (a 2-2
//! stake split), `fork_choice_score` alone cannot order them, and the old
//! `max_by_key` / strict `>` paths either picked whichever slice happened to
//! come last or refused to reorg at all. Both leave the ordering to gossip
//! arrival order, so honest nodes that saw the two tips in opposite orders
//! diverged.
//!
//! This module supplies one deterministic, arrival-order-independent
//! tie-break. The inputs are all in the block itself (hash, proposer,
//! height) plus the already-computed score, so every node that sees the same
//! two tips computes the same winner.
//!
//! Tie-break order:
//! 1. Higher weight.
//! 2. Higher height.
//! 3. Lower block hash (lexicographic byte comparison).
//! 4. Lower proposer address.
//! 5. `LeftWins` (identical candidates are indistinguishable; the incumbent
//!    is kept, which for `is_better_chain` means no reorg).

use crate::core::block::Block;
use crate::domain::types::Hash32;

/// One fork tip as seen by the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitCandidate {
    pub block_hash: Hash32,
    /// Zero-filled when the tip has no producer.
    pub proposer: Hash32,
    pub height: u64,
    pub weight: u128,
}

impl SplitCandidate {
    /// Build a candidate from a chain tip and its already-computed score.
    ///
    /// The block hash is recomputed from content (`Block::calculate_hash_bytes`)
    /// rather than read from the `hash` field: at the point fork choice runs
    /// the candidate has not yet been validated, so the stored field is not
    /// trusted.
    #[must_use]
    pub fn from_chain_tip(chain: &[Block], score: u128) -> Self {
        match chain.last() {
            Some(block) => SplitCandidate {
                block_hash: block.calculate_hash_bytes(),
                proposer: block
                    .producer
                    .as_ref()
                    .map(|p| *p.as_bytes())
                    .unwrap_or([0u8; 32]),
                height: block.index,
                weight: score,
            },
            None => SplitCandidate {
                block_hash: [0u8; 32],
                proposer: [0u8; 32],
                height: 0,
                weight: 0,
            },
        }
    }
}

/// Which side of an equal-weight split wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitDecision {
    LeftWins,
    RightWins,
}

/// Deterministically resolve a tie between two candidates.
///
/// Pure function of its inputs: no wall clock, no VDF, no per-node state, so
/// every honest node arrives at the same decision.
#[must_use]
pub fn resolve_split_tie(left: &SplitCandidate, right: &SplitCandidate) -> SplitDecision {
    if left.weight != right.weight {
        return if left.weight > right.weight {
            SplitDecision::LeftWins
        } else {
            SplitDecision::RightWins
        };
    }
    if left.height != right.height {
        return if left.height > right.height {
            SplitDecision::LeftWins
        } else {
            SplitDecision::RightWins
        };
    }
    if left.block_hash != right.block_hash {
        return if left.block_hash < right.block_hash {
            SplitDecision::LeftWins
        } else {
            SplitDecision::RightWins
        };
    }
    if left.proposer != right.proposer {
        return if left.proposer < right.proposer {
            SplitDecision::LeftWins
        } else {
            SplitDecision::RightWins
        };
    }
    // Identical on every field: keep the incumbent (no reorg, no churn).
    SplitDecision::LeftWins
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(hash: u8, proposer: u8, height: u64, weight: u128) -> SplitCandidate {
        SplitCandidate {
            block_hash: [hash; 32],
            proposer: [proposer; 32],
            height,
            weight,
        }
    }

    #[test]
    fn higher_weight_wins_even_when_hashes_disagree() {
        let left = candidate(0x02, 0xAA, 10, 200);
        let right = candidate(0x01, 0xBB, 10, 100);
        assert_eq!(
            resolve_split_tie(&left, &right),
            SplitDecision::LeftWins,
            "weight must dominate the hash tie-break"
        );
    }

    #[test]
    fn equal_weight_higher_height_wins() {
        let left = candidate(0x02, 0xAA, 11, 100);
        let right = candidate(0x01, 0xBB, 10, 100);
        assert_eq!(resolve_split_tie(&left, &right), SplitDecision::LeftWins);
    }

    #[test]
    fn equal_weight_and_height_lower_hash_wins() {
        let left = candidate(0x02, 0xAA, 10, 100);
        let right = candidate(0x01, 0xBB, 10, 100);
        assert_eq!(resolve_split_tie(&left, &right), SplitDecision::RightWins);
    }

    #[test]
    fn equal_weight_height_hash_lower_proposer_wins() {
        let left = candidate(0x01, 0xAA, 10, 100);
        let right = candidate(0x01, 0xBB, 10, 100);
        assert_eq!(resolve_split_tie(&left, &right), SplitDecision::LeftWins);
    }

    #[test]
    fn tie_is_arrival_order_independent() {
        let left = candidate(0x02, 0xAA, 10, 100);
        let right = candidate(0x01, 0xBB, 10, 100);
        let a = resolve_split_tie(&left, &right);
        let b = resolve_split_tie(&right, &left);
        assert_ne!(a, b);
        assert_eq!(a, SplitDecision::RightWins);
        assert_eq!(b, SplitDecision::LeftWins);
    }

    #[test]
    fn identical_candidates_keep_the_incumbent() {
        let c = candidate(0x01, 0xAA, 10, 100);
        assert_eq!(resolve_split_tie(&c, &c), SplitDecision::LeftWins);
    }
}
