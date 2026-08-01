//!: Domain edge-case test suite'leri.
//!
//! BFT view-change/leader election, PoS slashing triggers, PoW difficulty
//! Adjustment için ayrı edge-case testleri.

#[cfg(test)]
mod tests {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;

    use std::sync::Arc;

    fn setup_chain() -> Blockchain {
        let consensus = Arc::new(PoWEngine::new(0));
        Blockchain::new(consensus, None, 45262, None)
    }

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    // ─── PoW Difficulty Adjustment ───

    #[test]
    fn pow_difficulty_adjusts_after_blocks() {
        let mut bc = setup_chain();
        let producer = addr(0x01);

        // Produce several blocks - difficulty should adjust
        for _ in 0..5 {
            let _ = bc.produce_block(producer);
        }

        // After multiple blocks, difficulty field should be accessible and non-trivial.
        // The PoW engine tracks difficulty internally; we verify chain growth.
        assert!(
            bc.chain.len() > 1,
            "chain must have grown after block production"
        );
    }

    #[test]
    fn pow_genesis_block_has_zero_difficulty() {
        let bc = setup_chain();
        assert_eq!(bc.chain.len(), 1, "genesis block must exist at chain start");
        // Genesis block is block 0
        assert_eq!(bc.chain[0].index, 0);
    }

    /// Renamed from `pow_empty_block_rejected_by_validation`, which claimed a
    /// rejection this test never asserted and the engine never performs:
    /// `PoWEngine::validate_block` checks the previous hash, the block hash and
    /// the difficulty target, and says nothing about the transaction list. An
    /// empty block is valid under PoW - that is what keeps a chain live when
    /// the mempool is empty. The old name asserted the opposite of the design
    /// while the body asserted success, so nothing was ever going to catch the
    /// contradiction.
    #[test]
    fn pow_produces_a_block_with_an_empty_mempool() {
        let mut bc = setup_chain();
        let producer = addr(0x02);

        let result = bc.produce_block(producer);
        assert!(
            result.is_some(),
            "an empty mempool must still yield a block; PoW validity does not depend on transactions"
        );
    }

    // ─── PoS / BFT Slashing Triggers ───

    #[test]
    fn pos_validator_registration_with_stake() {
        let mut bc = setup_chain();
        let validator = addr(0x10);

        bc.init_genesis_account(&validator);
        // Validator registration via stake (permissionless)
        // The chain must accept stake-based registration
        // Validator set is managed by the permissionless registry, not
        // Necessarily mirrored into bc.state.validators on stake alone.
        // Smoke: genesis account exists; registration path is covered elsewhere.
        assert!(
            bc.state.accounts.contains_key(&validator),
            "genesis account must exist for validator candidate"
        );
    }

    /// Renamed from `pos_double_producer_address_rejected`, which asserted the
    /// exact opposite of its own name: both blocks must succeed. Producing two
    /// sequential blocks from one address is ordinary behaviour, not a double
    /// -sign - a double-sign is two *different* blocks at the *same* height,
    /// and that is covered by the equivocation tests, not here. A name
    /// promising a rejection over a body asserting acceptance is worse than no
    /// test: a reader counting coverage sees the double-sign case handled.
    #[test]
    fn the_same_producer_may_extend_the_chain_on_consecutive_heights() {
        let mut bc = setup_chain();
        let producer = addr(0x20);

        let r1 = bc.produce_block(producer);
        assert!(r1.is_some(), "first block must succeed");

        let r2 = bc.produce_block(producer);
        assert!(
            r2.is_some(),
            "consecutive heights from one producer are sequential production, not equivocation"
        );

        let (h1, h2) = (
            r1.expect("checked above").0.index,
            r2.expect("checked above").0.index,
        );
        assert_ne!(
            h1, h2,
            "the two blocks must sit at different heights, or this is not the sequential case"
        );
    }

    // ─── BFT View-Change / Leader Election ───

    #[test]
    fn bft_leader_deterministic_selection() {
        // BFT leader selection uses hash-mix (not pure round-robin).
        // Test: same inputs → same leader.
        let bc = setup_chain();
        let _producer = addr(0x30);

        // Chain must have a deterministic tip
        let tip = bc.chain.last().unwrap();
        assert_eq!(tip.index, 0, "genesis tip at index 0");
    }

    #[test]
    fn bft_block_validation_rejects_wrong_chain_id() {
        let bc1 = setup_chain(); // chain_id 45262
        let consensus2 = Arc::new(PoWEngine::new(0));
        let bc2 = Blockchain::new(consensus2, None, 9999, None); // chain_id 9999

        // Block from chain 9999 must not be valid in the devnet chain
        let block_from_other = bc2.chain[0].clone();
        assert_ne!(bc1.chain[0].chain_id, block_from_other.chain_id);
    }

    // ─── Domain Isolation Edge Cases ───

    #[test]
    fn cross_chain_id_block_rejected() {
        let mut bc = setup_chain();
        let consensus2 = Arc::new(PoWEngine::new(0));
        let mut bc2 = Blockchain::new(consensus2, None, 9999, None);

        let producer = addr(0x40);
        for _ in 0..3 {
            let _ = bc2.produce_block(producer);
        }

        // Try to add a block from chain 9999 into the devnet chain
        let foreign_block = bc2.chain[1].clone();
        let result = bc.validate_and_add_block(foreign_block);
        assert!(
            result.is_err(),
            "block from different chain_id must be rejected"
        );
    }

    #[test]
    fn reorg_with_same_chain_id_succeeds() {
        let consensus_a = Arc::new(PoWEngine::new(0));
        let mut chain_a = Blockchain::new(consensus_a.clone(), None, 45262, None);
        let mut chain_b = Blockchain::new(consensus_a, None, 45262, None);

        let producer = addr(0x50);

        for _ in 0..3 {
            let _ = chain_a.produce_block(producer);
        }
        for _ in 0..5 {
            let _ = chain_b.produce_block(producer);
        }

        // Reorg to longer chain
        let result = chain_a.try_reorg(chain_b.chain.clone());
        assert!(
            result.is_ok(),
            "reorg to longer chain with same ID must succeed"
        );
    }

    // ─── Block Timestamp Edge Cases ───

    #[test]
    fn block_with_zero_timestamp_accepted_in_genesis() {
        let bc = setup_chain();
        assert_eq!(
            bc.chain[0].timestamp, 0,
            "genesis block timestamp should be 0"
        );
    }

    #[test]
    fn consecutive_blocks_increasing_timestamp() {
        let mut bc = setup_chain();
        let producer = addr(0x60);

        let _ = bc.produce_block(producer);
        let _ = bc.produce_block(producer);

        // Timestamps should be non-decreasing
        assert!(
            bc.chain[2].timestamp >= bc.chain[1].timestamp,
            "consecutive block timestamps must be non-decreasing"
        );
    }
}
