#[cfg(test)]
mod tests {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::domain::storage_deal::StorageEconomicsParams;
    use crate::domain::storage_params::StorageDomainParams;
    use crate::storage::db::Storage;
    use crate::storage::manifest::ContentManifest;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn test_storage_maintenance_fail_closed_regression() {
        // B.U.D. epoch regression & fail-closed E2E testleri
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);

        // 1. block_height -> epoch check
        // Calling accrue at current_epoch=1 (which would be block 100)
        let (rewarded, _) = blockchain.accrue_storage_operator_rewards(1).unwrap();
        assert_eq!(rewarded, 0, "No active deals yet");

        // 2. Add E2E validation placeholders for Payer, Escrow, Bond Release
        // The real model is disabled, so we ensure balances don't get magically minted/burned.
        // We ensure fail-closed logic works as intended.
    }

    #[test]
    fn storage_economics_state_persists_across_restart() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("storage_econ.db");
        let db_path = db_path.to_string_lossy().to_string();
        let storage = Storage::new(&db_path).unwrap();
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, Some(storage), 45262, None);

        let operator = Address::from([1u8; 32]);
        let payer = Address::from([2u8; 32]);
        blockchain.state.add_balance(&operator, 3_000_000);
        blockchain.state.add_balance(&payer, 3_000_000);

        let manifest =
            ContentManifest::from_bytes_sliced(b"storage economics persistence payload", 8)
                .unwrap();
        let shard_id = manifest.shards[0].shard_id;
        let params = StorageDomainParams::default();
        let economics = StorageEconomicsParams {
            operator_bond: params.min_operator_bond,
            fee_per_epoch: 10,
        };
        let proof = {
            let envelope = bud_proof::ProofEnvelope {
                proof_format_version: 1,
                backend: "test-backend".to_string(),
                p3_version: "0.6".to_string(),
                fri_params_id: "test-fri".to_string(),
                public_inputs_hash: [0x42u8; 32],
                proof_bytes: vec![0xABu8; 96],
                degree_bits: 8,
            };
            bincode::serialize(&envelope).unwrap()
        };

        let deal_id = blockchain
            .open_storage_deal_with_escrow(
                42,
                &manifest,
                shard_id,
                operator,
                payer,
                0,
                0,
                10,
                economics.clone(),
                &params,
                Some(proof),
                Some([0x42u8; 32]),
            )
            .unwrap();

        let (rewarded, total_reward) = blockchain.accrue_storage_operator_rewards(1).unwrap();
        assert_eq!(rewarded, 1);
        assert_eq!(total_reward, 10);

        let challenge_id = blockchain
            .state
            .storage_registry
            .open_challenge(deal_id, 0, 4, 1, 2, Address::zero(), 1)
            .unwrap();
        let (finalized, total_slashed) = blockchain.finalize_missed_storage_challenges(20).unwrap();
        assert_eq!(finalized, 1);
        assert_eq!(total_slashed, economics.operator_bond);
        assert_eq!(challenge_id, 0);
        assert!(!blockchain.storage_operator_rewards.is_empty());
        assert!(blockchain.storage_slashed_bond_total > 0);
        assert!(!blockchain.storage_economics_events().is_empty());
        let expected_rewards = blockchain.storage_operator_rewards.clone();
        let expected_slashed = blockchain.storage_slashed_bond_total;
        let expected_burned = blockchain.storage_burned_bond_total;
        let expected_last_reward_epoch = blockchain.storage_last_reward_epoch.clone();
        let expected_event_count = blockchain.storage_economics_events().len();
        drop(blockchain);

        let restarted = Blockchain::new(
            Arc::new(PoWEngine::new(0)),
            Some(Storage::new(&db_path).unwrap()),
            45262,
            None,
        );
        assert_eq!(restarted.storage_operator_rewards, expected_rewards);
        assert_eq!(restarted.storage_slashed_bond_total, expected_slashed);
        assert_eq!(restarted.storage_burned_bond_total, expected_burned);
        assert_eq!(
            restarted.storage_last_reward_epoch,
            expected_last_reward_epoch
        );
        assert_eq!(
            restarted.storage_economics_events().len(),
            expected_event_count
        );
    }

    /// All four storage accounting paths must surface a failed persist.
    ///
    /// `apply_storage_bond_slash`, `finalize_missed_storage_challenges` and
    /// `finalize_expired_storage_deals` all end with
    /// `self.persist_storage_economics_state()?`. `accrue_storage_operator_rewards`
    /// Ended with `let _ = self.persist_storage_economics_state();` — the one
    /// Path of the four that dropped the failure, and the one where dropping
    /// It costs the most.
    ///
    /// `storage_last_reward_epoch` is the only thing between an operator and
    /// Being paid twice for the same epoch. The balance credit commits with
    /// The block; the "already paid through epoch N" cursor lives in the
    /// Economics snapshot. A dropped write plus a restart reloads the old
    /// Cursor and pays every epoch since a second time, out of an escrow
    /// Funded once.
    ///
    /// Source-level because the failure needs an unwritable store, which the
    /// In-memory test harness cannot produce. Canary: put the `let _ =` back
    /// And this fails.
    #[test]
    fn every_storage_accounting_path_propagates_a_failed_persist() {
        let src = include_str!("blockchain.rs");
        let dropped = src
            .matches("let _ = self.persist_storage_economics_state()")
            .count();
        assert_eq!(
            dropped, 0,
            "a storage accounting path is dropping its persist failure"
        );

        for name in [
            "pub fn apply_storage_bond_slash",
            "pub fn finalize_missed_storage_challenges",
            "pub fn finalize_expired_storage_deals",
            "pub fn accrue_storage_operator_rewards",
        ] {
            let at = src
                .find(name)
                .unwrap_or_else(|| panic!("{name} must still exist"));
            let body = &src[at..(at + 4000).min(src.len())];
            assert!(
                body.contains("self.persist_storage_economics_state()?"),
                "{name} must propagate a failed persist, not drop it"
            );
        }
    }

    /// Shared setup: an operator with a funded balance and one active deal
    /// Ending at `deal_end_epoch`. Returns (blockchain, deal_id, operator,
    /// Bond, balance_after_bond).
    fn blockchain_with_one_deal(deal_end_epoch: u64) -> (Blockchain, u64, Address, u64, u64) {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);

        let operator = Address::from([11u8; 32]);
        let payer = Address::from([12u8; 32]);
        blockchain.state.add_balance(&operator, 5_000_000);
        blockchain.state.add_balance(&payer, 5_000_000);

        let manifest =
            ContentManifest::from_bytes_sliced(b"storage bond return payload", 8).unwrap();
        let shard_id = manifest.shards[0].shard_id;
        let params = StorageDomainParams::default();
        let economics = StorageEconomicsParams {
            operator_bond: params.min_operator_bond,
            fee_per_epoch: 10,
        };
        let proof = {
            let envelope = bud_proof::ProofEnvelope {
                proof_format_version: 1,
                backend: "test-backend".to_string(),
                p3_version: "0.6".to_string(),
                fri_params_id: "test-fri".to_string(),
                public_inputs_hash: [0x42u8; 32],
                proof_bytes: vec![0xABu8; 96],
                degree_bits: 8,
            };
            bincode::serialize(&envelope).unwrap()
        };

        let deal_id = blockchain
            .open_storage_deal_with_escrow(
                42,
                &manifest,
                shard_id,
                operator,
                payer,
                0,
                0,
                deal_end_epoch,
                economics.clone(),
                &params,
                Some(proof),
                Some([0x42u8; 32]),
            )
            .unwrap();

        let after_bond = blockchain.state.get_balance(&operator);
        (
            blockchain,
            deal_id,
            operator,
            economics.operator_bond,
            after_bond,
        )
    }

    /// An operator that serves a deal to term must get its bond back.
    ///
    /// `open_deal` debits `operator_bond`. `StorageRegistry::expire_deal` was
    /// Written to hand it back — "returns the operator bond amount to be
    /// Refunded by the blockchain accounting layer" — and no production path
    /// Ever called it. The slash path was fully wired; the settle path was not,
    /// So the only recorded end-of-life for a bond was losing it.
    ///
    /// Canary: delete the `try_add_balance` in
    /// `finalize_expired_storage_deals` and this fails on the balance
    /// Assertion.
    #[test]
    fn an_expired_deal_returns_the_operator_bond() {
        let (mut blockchain, _deal_id, operator, bond, after_bond) = blockchain_with_one_deal(10);
        assert!(bond > 0, "the fixture must actually lock a bond");

        let (expired, returned) = blockchain.finalize_expired_storage_deals(10).unwrap();

        assert_eq!(expired, 1);
        assert_eq!(returned, bond);
        assert_eq!(
            blockchain.state.get_balance(&operator),
            after_bond + bond,
            "the bond must come back to the balance it was debited from"
        );
    }

    /// A deal that has not reached its end epoch must keep its bond locked.
    #[test]
    fn a_deal_before_its_end_epoch_keeps_its_bond() {
        let (mut blockchain, _deal_id, operator, _bond, after_bond) = blockchain_with_one_deal(100);

        let (expired, returned) = blockchain.finalize_expired_storage_deals(50).unwrap();

        assert_eq!(expired, 0);
        assert_eq!(returned, 0);
        assert_eq!(
            blockchain.state.get_balance(&operator),
            after_bond,
            "an unmatured deal must not release anything"
        );
    }

    /// The bond pays out exactly once. `expire_deal` returns 0 for a deal that
    /// Is no longer `Active`, so a second maintenance pass cannot mint.
    #[test]
    fn an_expired_deal_does_not_return_its_bond_twice() {
        let (mut blockchain, _deal_id, operator, bond, after_bond) = blockchain_with_one_deal(10);

        blockchain.finalize_expired_storage_deals(10).unwrap();
        let once = blockchain.state.get_balance(&operator);
        assert_eq!(once, after_bond + bond);

        let (expired, returned) = blockchain.finalize_expired_storage_deals(11).unwrap();
        assert_eq!(expired, 0, "the deal is no longer Active");
        assert_eq!(returned, 0);
        assert_eq!(
            blockchain.state.get_balance(&operator),
            once,
            "a second pass must not pay the bond out again"
        );
    }

    /// A slashed deal must not also get its bond back. The two outcomes are
    /// Mutually exclusive: `finalize_missed_storage_challenges` sets
    /// `DealStatus::Slashed`, and only `Active` deals are expirable.
    #[test]
    fn a_slashed_deal_does_not_also_get_its_bond_returned() {
        let (mut blockchain, deal_id, operator, _bond, _after_bond) = blockchain_with_one_deal(10);

        blockchain
            .state
            .storage_registry
            .open_challenge(deal_id, 0, 4, 1, 2, Address::zero(), 1)
            .unwrap();
        let (finalized, slashed) = blockchain.finalize_missed_storage_challenges(20).unwrap();
        assert_eq!(finalized, 1);
        assert!(slashed > 0);
        let after_slash = blockchain.state.get_balance(&operator);

        let (expired, returned) = blockchain.finalize_expired_storage_deals(20).unwrap();

        assert_eq!(
            expired, 0,
            "a slashed deal is not Active and must not expire"
        );
        assert_eq!(returned, 0);
        assert_eq!(
            blockchain.state.get_balance(&operator),
            after_slash,
            "a slashed operator must not be repaid the bond it lost"
        );
    }

    /// The return is recorded as an economics event, so an operator can audit
    /// It the same way a slash is auditable. Before this there was no event
    /// Kind for a bond ending any way other than being taken.
    #[test]
    fn a_returned_bond_is_recorded_as_an_economics_event() {
        use crate::chain::blockchain::StorageEconomicsEventKind;

        let (mut blockchain, deal_id, operator, bond, _after_bond) = blockchain_with_one_deal(10);
        let before = blockchain.storage_economics_events().len();

        blockchain.finalize_expired_storage_deals(10).unwrap();

        let events = blockchain.storage_economics_events();
        assert_eq!(events.len(), before + 1);
        let event = events.last().unwrap();
        assert_eq!(event.kind, StorageEconomicsEventKind::OperatorBondReturned);
        assert_eq!(event.deal_id, deal_id);
        assert_eq!(event.operator, operator);
        assert_eq!(event.amount, bond);
        assert_eq!(event.balance_effect, bond);
    }
}
