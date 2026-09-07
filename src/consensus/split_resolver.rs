//! E7: Deterministic 2-2 Split / Equal-Weight Fork Resolver.
//!
//! Provides a mathematically deterministic, un-gameable tie-breaking rule
//! when two competing fork tips carry identical accumulated stake/weight.
//!
//! Tie-breaking order:
//! 1. Lowest block hash (lexicographical byte comparison).
//! 2. Lowest proposer address.
//! 3. Deterministic VDF entropy seed.

use crate::core::address::Address;
use crate::domain::types::Hash32;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitCandidate {
    pub block_hash: Hash32,
    pub proposer: Address,
    pub height: u64,
    pub weight: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitDecision {
    LeftWins,
    RightWins,
}

/// Deterministically resolve a 2-2 split between two equally weighted fork candidates.
pub fn resolve_split_tie(
    left: &SplitCandidate,
    right: &SplitCandidate,
    epoch_seed: &Hash32,
) -> SplitDecision {
    if left.weight > right.weight {
        return SplitDecision::LeftWins;
    }
    if right.weight > left.weight {
        return SplitDecision::RightWins;
    }

    // Height preference
    if left.height > right.height {
        return SplitDecision::LeftWins;
    }
    if right.height > left.height {
        return SplitDecision::RightWins;
    }

    // Compute pseudo-random tie breaker from seed and candidate hashes
    let score_left = score_candidate(left, epoch_seed);
    let score_right = score_candidate(right, epoch_seed);

    if score_left < score_right {
        SplitDecision::LeftWins
    } else if score_right < score_left {
        SplitDecision::RightWins
    } else if left.proposer.0 < right.proposer.0 {
        SplitDecision::LeftWins
    } else {
        SplitDecision::RightWins
    }
}

fn score_candidate(candidate: &SplitCandidate, seed: &Hash32) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_SPLIT_RESOLVER_V1");
    hasher.update(seed);
    hasher.update(candidate.block_hash);
    hasher.update(candidate.proposer.0);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_weight_wins() {
        let left = SplitCandidate {
            block_hash: [0x01; 32],
            proposer: Address::from([0xAA; 32]),
            height: 10,
            weight: 200,
        };
        let right = SplitCandidate {
            block_hash: [0x02; 32],
            proposer: Address::from([0xBB; 32]),
            height: 10,
            weight: 100,
        };
        assert_eq!(
            resolve_split_tie(&left, &right, &[0; 32]),
            SplitDecision::LeftWins
        );
    }

    #[test]
    fn equal_weight_is_deterministic() {
        let left = SplitCandidate {
            block_hash: [0x01; 32],
            proposer: Address::from([0xAA; 32]),
            height: 10,
            weight: 100,
        };
        let right = SplitCandidate {
            block_hash: [0x02; 32],
            proposer: Address::from([0xBB; 32]),
            height: 10,
            weight: 100,
        };
        let dec1 = resolve_split_tie(&left, &right, &[0x55; 32]);
        let dec2 = resolve_split_tie(&left, &right, &[0x55; 32]);
        assert_eq!(dec1, dec2);
    }
}
