//! Locks on fork choice for the two engines that score chains numerically.
//!
//! Two findings, both measured before the fix:
//!
//! 1. **`PoS` treated its checkpoint as a term in the score**, so chain length
//!    could buy the difference and a fork branching from an earlier
//!    checkpoint could win outright.
//! 2. **`PoW` accumulated work in a `u128` that saturates**, and the retarget
//!    ceiling sits exactly at the overflow boundary, so at high difficulty
//!    every candidate scored `u128::MAX` and no reorg was ever accepted.
//!
//! Each test below fails if its fix is reverted.

use crate::consensus::pos::{PoSConfig, PoSEngine};
use crate::consensus::pow::{PoWConfig, PoWEngine, U256};
use crate::consensus::ConsensusEngine;
use crate::core::block::Block;

/// A chain of `len` blocks whose hashes are distinct per `tag`, linked so
/// `chain[i].previous_hash == chain[i-1].hash`.
fn chain_of(len: usize, tag: &str) -> Vec<Block> {
    let mut chain: Vec<Block> = Vec::with_capacity(len);
    for index in 0..len {
        let previous_hash = chain
            .last()
            .map_or_else(|| "0".repeat(64), |b: &Block| b.hash.clone());
        let mut block = Block::new(index as u64, previous_hash, vec![]);
        // Deterministic, distinct, and 64 hex chars like a real block hash.
        block.hash = format!("{tag:0>60}{index:0>4x}");
        block.index = index as u64;
        chain.push(block);
    }
    chain
}

mod pos_checkpoint_is_a_limit_not_a_score {
    use super::*;

    fn engine() -> PoSEngine {
        PoSEngine::new(PoSConfig::default(), None)
    }

    #[test]
    fn a_fork_that_drops_the_checkpoint_cannot_win_on_length() {
        // Measured against the old formula
        // `score = checkpoint_height * 1000 + chain.len()`:
        //
        //     honest   cp=10 len=1000 -> 11000
        //     attacker cp= 9 len=2001 -> 11001
        //
        // Length bought the checkpoint difference. A checkpoint is a revert
        // limit; there should be no exchange rate at all.
        let engine = engine();
        let honest = chain_of(40, "aa");
        engine
            .add_checkpoint(&honest[32], None)
            .expect("checkpoint at height 32 records");

        // A fork sharing only the first 30 blocks, then diverging, and far
        // longer than the honest chain.
        let mut attacker = honest[..30].to_vec();
        let mut forged = chain_of(400, "bb");
        forged.drain(..30);
        attacker.append(&mut forged);
        assert!(
            attacker.len() > honest.len(),
            "the attacking chain must be the longer one for this to mean anything"
        );

        assert_eq!(
            engine.fork_choice_score(&attacker),
            0,
            "a chain missing the checkpoint scores zero, not merely less"
        );
        assert!(
            !engine.is_better_chain(&honest, &attacker),
            "a longer chain that abandons the checkpoint must be refused"
        );
    }

    #[test]
    fn a_fork_keeping_the_checkpoint_still_wins_on_length() {
        // The limit must not freeze the chain: honest growth past a
        // checkpoint has to remain adoptable.
        let engine = engine();
        let short = chain_of(40, "aa");
        engine
            .add_checkpoint(&short[32], None)
            .expect("checkpoint records");

        let mut longer = short.clone();
        let mut extra = chain_of(60, "aa");
        extra.drain(..40);
        longer.append(&mut extra);

        assert!(
            engine.fork_choice_score(&longer) > engine.fork_choice_score(&short),
            "a longer chain containing the checkpoint scores higher"
        );
        assert!(
            engine.is_better_chain(&short, &longer),
            "honest growth past a checkpoint must still be adoptable"
        );
    }

    #[test]
    fn a_chain_with_the_right_height_but_the_wrong_hash_is_refused() {
        // Height alone is not the checkpoint. A fork that reaches the same
        // height with a different block has not honoured it.
        let engine = engine();
        let honest = chain_of(40, "aa");
        engine
            .add_checkpoint(&honest[32], None)
            .expect("checkpoint records");

        let impostor = chain_of(40, "cc");
        assert_eq!(
            impostor.len(),
            honest.len(),
            "same length, so only the hash can distinguish them"
        );
        assert_eq!(
            engine.fork_choice_score(&impostor),
            0,
            "matching the checkpoint height with a different hash is not honouring it"
        );
    }

    #[test]
    fn a_chain_shorter_than_the_checkpoint_is_refused() {
        // There is no block at the checkpoint height to compare, which is not
        // the same as "no violation".
        let engine = engine();
        let honest = chain_of(40, "aa");
        engine
            .add_checkpoint(&honest[32], None)
            .expect("checkpoint records");

        let stub = chain_of(10, "aa");
        assert_eq!(
            engine.fork_choice_score(&stub),
            0,
            "a chain that does not reach the checkpoint cannot contain it"
        );
    }

    #[test]
    fn with_no_checkpoint_established_length_decides() {
        // A node that has seen no checkpoint has nothing to anchor to; it must
        // not behave as though anchored at genesis, nor refuse everything.
        let engine = engine();
        let short = chain_of(10, "aa");
        let long = chain_of(20, "aa");
        assert_eq!(engine.fork_choice_score(&short), 10);
        assert_eq!(engine.fork_choice_score(&long), 20);
        assert!(engine.is_better_chain(&short, &long));
    }

    #[test]
    fn a_violating_candidate_loses_even_when_the_current_chain_also_scores_zero() {
        // The node least able to tell the difference is one whose own chain
        // has not reached the checkpoint height. Scoring alone would let the
        // candidate win 0 > 0 being false only by luck of the comparison; the
        // candidate has to be refused outright.
        let engine = engine();
        let honest = chain_of(40, "aa");
        engine
            .add_checkpoint(&honest[32], None)
            .expect("checkpoint records");

        let our_stub = chain_of(5, "aa");
        let attacker = chain_of(400, "bb");
        assert_eq!(engine.fork_choice_score(&our_stub), 0);
        assert_eq!(engine.fork_choice_score(&attacker), 0);
        assert!(
            !engine.is_better_chain(&our_stub, &attacker),
            "a checkpoint-violating candidate must be refused, not tie-broken"
        );
    }
}

mod pow_work_does_not_saturate {
    use super::*;

    #[test]
    fn u256_pow2_reaches_past_a_u128() {
        // The exact boundary the old accumulator hit: 16^32 == 2^128.
        assert!(U256::pow2(128) > U256::pow2(127));
        assert!(U256::pow2(200) > U256::pow2(128));
        assert_eq!(
            U256::pow2(127).saturating_to_u128(),
            1u128 << 127,
            "below the boundary the low 128 bits are exact"
        );
        assert_eq!(
            U256::pow2(128).saturating_to_u128(),
            u128::MAX,
            "at the boundary the u128 view saturates, which is why it cannot order chains"
        );
    }

    #[test]
    fn u256_addition_carries_across_limbs() {
        // A carry that fails to propagate would make a large chainwork wrap to
        // a small one, which is the bug this type exists to prevent.
        let almost = U256::pow2(64).saturating_add(U256::pow2(0));
        assert!(almost > U256::pow2(64));

        let mut acc = U256::ZERO;
        for _ in 0..4 {
            acc = acc.saturating_add(U256::pow2(126));
        }
        assert_eq!(
            acc,
            U256::pow2(128),
            "four times 2^126 is 2^128, carried across the limb boundary"
        );
    }

    #[test]
    fn u256_saturates_rather_than_wrapping() {
        assert_eq!(U256::MAX.saturating_add(U256::pow2(0)), U256::MAX);
        assert_eq!(U256::pow2(256), U256::MAX);
        assert_eq!(U256::pow2(1000), U256::MAX);
    }

    #[test]
    fn u256_ordering_is_by_magnitude_not_limb_order() {
        // Little-endian limbs compared in the wrong direction would order
        // 2^0 above 2^255.
        assert!(U256::pow2(255) > U256::pow2(0));
        assert!(U256::pow2(0) < U256::pow2(64));
        assert_eq!(U256::ZERO, U256::ZERO);
        assert!(U256::ZERO < U256::pow2(0));
    }

    #[test]
    fn a_longer_chain_still_wins_at_the_difficulty_that_used_to_saturate() {
        // Measured with the old accumulator: at difficulty 32 every chain
        // scored u128::MAX, so `is_better_chain` was false for every reorg and
        // the node locked onto whatever it saw first. Difficulty 32 is not
        // hypothetical — `adjusted_difficulty` clamps to exactly 32.
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 32,
            target_block_time: 10,
            adjustment_interval: 0,
        });
        let short = chain_of(4, "aa");
        let long = chain_of(9, "aa");

        assert_eq!(
            engine.fork_choice_score(&short),
            u128::MAX,
            "the u128 view saturates here, which is the whole point"
        );
        assert_eq!(engine.fork_choice_score(&long), u128::MAX);
        assert!(
            engine.is_better_chain(&short, &long),
            "the reorg must still be accepted despite the u128 view being equal"
        );
        assert!(
            !engine.is_better_chain(&long, &short),
            "and the comparison must not be symmetric"
        );
    }

    #[test]
    fn low_difficulty_chains_are_still_ordered() {
        // A fix that scaled work down by a shared constant would order high
        // difficulties correctly and flatten devnet, which runs at 1 or 2.
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 1,
            target_block_time: 10,
            adjustment_interval: 0,
        });
        let short = chain_of(3, "aa");
        let long = chain_of(7, "aa");
        assert!(engine.fork_choice_score(&long) > engine.fork_choice_score(&short));
        assert!(engine.is_better_chain(&short, &long));
    }

    #[test]
    fn equal_chains_do_not_trigger_a_reorg() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 4,
            target_block_time: 10,
            adjustment_interval: 0,
        });
        let a = chain_of(6, "aa");
        let b = chain_of(6, "bb");
        assert!(
            !engine.is_better_chain(&a, &b),
            "equal work is not better work"
        );
    }
}
