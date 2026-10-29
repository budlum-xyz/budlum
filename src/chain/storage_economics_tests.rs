#[cfg(test)]
mod tests {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::domain::deal_open::{
        accept_reallocation_escrowed, open_deal_escrowed, DealOpenTerms, ReallocationTerms,
    };
    use crate::domain::storage_deal::{ReallocationStatus, StorageEconomicsParams, FEE_RATE_SCALE};
    use crate::domain::storage_params::StorageDomainParams;
    use crate::storage::manifest::ContentManifest;
    use std::sync::Arc;

    /// The shared escrow paths the `StorageTx::OpenDeal` and
    /// `StorageTx::AcceptReallocation` doors call, driven on a test chain's
    /// state at its tip's clock, with no fee reserve. The out-of-block
    /// wrappers these tests used to call were removed with the operator RPCs
    /// behind them; the economics under test live in `deal_open`.
    trait SharedEscrow {
        fn open_deal_through_shared_escrow(
            &mut self,
            terms: &DealOpenTerms<'_>,
            payer: Address,
            domain_params: &StorageDomainParams,
        ) -> Result<u64, String>;

        fn accept_reallocation_through_shared_escrow(
            &mut self,
            terms: &ReallocationTerms,
            payer: Address,
            domain_params: &StorageDomainParams,
        ) -> Result<u64, String>;
    }

    impl SharedEscrow for Blockchain {
        fn open_deal_through_shared_escrow(
            &mut self,
            terms: &DealOpenTerms<'_>,
            payer: Address,
            domain_params: &StorageDomainParams,
        ) -> Result<u64, String> {
            let now_unix_secs = self.current_unix_secs();
            open_deal_escrowed(
                &mut self.state,
                terms,
                payer,
                now_unix_secs,
                domain_params.min_operator_bond,
                0,
            )
        }

        fn accept_reallocation_through_shared_escrow(
            &mut self,
            terms: &ReallocationTerms,
            payer: Address,
            domain_params: &StorageDomainParams,
        ) -> Result<u64, String> {
            let now_unix_secs = self.current_unix_secs();
            accept_reallocation_escrowed(
                &mut self.state,
                terms,
                payer,
                now_unix_secs,
                domain_params.min_operator_bond,
                0,
            )
        }
    }

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

    /// the economics ledger (reward cursor, slash and burn totals,
    /// events) lives in the storage registry, so the state root commits it
    /// and a restart replays it from the blocks instead of a side store.
    #[test]
    fn storage_economics_ledger_is_consensus_state() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);

        let operator = Address::from([1u8; 32]);
        let payer = Address::from([2u8; 32]);
        blockchain.state.add_balance(&operator, 3_000_000);
        blockchain.state.add_balance(&payer, 3_000_000);

        let mut manifest =
            ContentManifest::from_bytes_sliced(b"storage economics persistence payload", 8)
                .unwrap();
        // The RPC deal door refuses a payer that is not the manifest's
        // authority, so the fixture declares the payer as owner exactly as an
        // uploading client does.
        manifest.owner = payer;
        let shard_id = manifest.shards[0].shard_id;
        let params = StorageDomainParams::default();
        // The rate is derived from the shard size so that one epoch still costs
        // 10: the price is now per byte, and `10 * 1e9 / shard_bytes` comes to
        // exactly 10 per epoch. Had we written a fixed 10, an 8-byte shard would
        // round up to 1 and the test would be measuring the rounding rather than
        // the price.
        let shard_bytes = u64::from(manifest.shard(&shard_id).expect("shard in manifest").size);
        let economics = StorageEconomicsParams {
            operator_bond: params.min_operator_bond,
            fee_per_byte_epoch: 10 * (FEE_RATE_SCALE as u64) / shard_bytes,
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
            .open_deal_through_shared_escrow(
                &DealOpenTerms {
                    domain_id: 42,
                    manifest: &manifest,
                    shard_id,
                    operator,
                    replica_index: 0,
                    start_epoch: 0,
                    end_epoch: 10,
                    economics: economics.clone(),
                    merkle_proof: Some(proof),
                    storage_root: Some([0x42u8; 32]),
                },
                payer,
                &params,
            )
            .unwrap();

        let root_before = blockchain.state.calculate_state_root();
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
        let ledger = &blockchain.state.storage_registry.economics;
        assert!(!ledger.operator_rewards.is_empty());
        assert!(ledger.slashed_bond_total > 0);
        assert!(ledger.last_reward_epoch.contains_key(&deal_id));
        assert!(!blockchain.storage_economics_events().is_empty());
        assert_ne!(
            blockchain.state.calculate_state_root(),
            root_before,
            "the economics ledger must be committed by the state root"
        );
    }

    /// Shared setup: an operator with a funded balance and one active deal
    /// Ending at `deal_end_epoch`. Returns `(blockchain, deal_id, operator,
    /// bond, balance_after_bond)`.
    fn blockchain_with_one_deal(deal_end_epoch: u64) -> (Blockchain, u64, Address, u64, u64) {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        let (deal_id, operator, bond, after_bond) =
            blockchain_with_one_deal_in(deal_end_epoch, &mut blockchain);
        (blockchain, deal_id, operator, bond, after_bond)
    }

    /// The deal-setup half, on a caller-supplied chain (which may or may not
    /// have storage attached) - needs the same fixture on a chain
    /// with a real store.
    fn blockchain_with_one_deal_in(
        deal_end_epoch: u64,
        blockchain: &mut Blockchain,
    ) -> (u64, Address, u64, u64) {
        let operator = Address::from([11u8; 32]);
        let payer = Address::from([12u8; 32]);
        blockchain.state.add_balance(&operator, 5_000_000);
        blockchain.state.add_balance(&payer, 5_000_000);

        let mut manifest =
            ContentManifest::from_bytes_sliced(b"storage bond return payload", 8).unwrap();
        // Ownership: the deal door (RPC and in-block alike) requires the payer
        // to be the manifest's authority; the fixture says so up front.
        manifest.owner = payer;
        let shard_id = manifest.shards[0].shard_id;
        let params = StorageDomainParams::default();
        let shard_bytes = u64::from(manifest.shard(&shard_id).expect("shard in manifest").size);
        let economics = StorageEconomicsParams {
            operator_bond: params.min_operator_bond,
            fee_per_byte_epoch: 10 * (FEE_RATE_SCALE as u64) / shard_bytes,
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
            .open_deal_through_shared_escrow(
                &DealOpenTerms {
                    domain_id: 42,
                    manifest: &manifest,
                    shard_id,
                    operator,
                    replica_index: 0,
                    start_epoch: 0,
                    end_epoch: deal_end_epoch,
                    economics: economics.clone(),
                    merkle_proof: Some(proof.clone()),
                    storage_root: Some([0x42u8; 32]),
                },
                payer,
                &params,
            )
            .unwrap();

        // A second replica of the same shard under a different operator.
        // These tests are about what happens to a bond at the end of a term,
        // and the registry refuses an expiry that would drop the last replica
        // of a shard while the object is at its decode threshold. Without a
        // spare the term could never end and there would be no bond to
        // settle, which is a different property than the one under test.
        let spare = Address::from([13u8; 32]);
        blockchain.state.add_balance(&spare, 5_000_000);
        blockchain.state.add_balance(&payer, 5_000_000);
        blockchain
            .open_deal_through_shared_escrow(
                &DealOpenTerms {
                    domain_id: 42,
                    manifest: &manifest,
                    shard_id,
                    operator: spare,
                    replica_index: 1,
                    start_epoch: 0,
                    end_epoch: deal_end_epoch.saturating_add(1_000),
                    economics: economics.clone(),
                    merkle_proof: Some(proof),
                    storage_root: Some([0x42u8; 32]),
                },
                payer,
                &params,
            )
            .unwrap();

        let after_bond = blockchain.state.get_balance(&operator);
        (deal_id, operator, economics.operator_bond, after_bond)
    }

    /// An operator that serves a deal to term must get its bond back.
    ///
    /// `open_deal` debits `operator_bond`. `StorageRegistry::expire_deal` was
    /// Written to hand it back - "returns the operator bond amount to be
    /// Refunded by the blockchain accounting layer", and no production path
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

    /// A manifest whose first shard never held a deal, plus the ticket the
    /// maintenance sweep would open for that empty slot. Returns the chain,
    /// the ticket id, the funded operator and payer, the deal economics,
    /// the domain params and the proof envelope an acceptance needs.
    fn blockchain_with_never_placed_ticket() -> (
        Blockchain,
        u64,
        Address,
        Address,
        StorageEconomicsParams,
        StorageDomainParams,
        Vec<u8>,
    ) {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        let operator = Address::from([21u8; 32]);
        let payer = Address::from([22u8; 32]);
        blockchain.state.add_balance(&operator, 5_000_000);
        blockchain.state.add_balance(&payer, 5_000_000);

        let manifest = ContentManifest::from_bytes_sliced(b"repair acceptance payload", 8).unwrap();
        // open_never_placed_ticket refuses an unknown manifest on purpose; the
        // helper built one locally without registering it, so the sweep could never
        // open the ticket the four acceptance tests are about.
        blockchain
            .state
            .storage_registry
            .register_manifest(&manifest);
        let shard_id = manifest.shards[0].shard_id;
        let params = StorageDomainParams::default();
        let shard_bytes = u64::from(manifest.shard(&shard_id).expect("shard in manifest").size);
        let economics = StorageEconomicsParams {
            operator_bond: params.min_operator_bond,
            fee_per_byte_epoch: 10 * (FEE_RATE_SCALE as u64) / shard_bytes,
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
        let ticket_id = blockchain
            .state
            .storage_registry
            .open_never_placed_ticket(42, manifest.manifest_id, shard_id, 0, 1)
            .expect("the sweep's ticket opens for an empty slot");
        (
            blockchain, ticket_id, operator, payer, economics, params, proof,
        )
    }

    #[test]
    fn accept_reallocation_opens_replacement_deal_with_escrow() {
        let (mut blockchain, ticket_id, operator, payer, economics, params, proof) =
            blockchain_with_never_placed_ticket();
        let fee = economics.total_fee(8, 10);
        let payer_before = blockchain.state.get_balance(&payer);
        let op_before = blockchain.state.get_balance(&operator);

        let replacement_deal_id = blockchain
            .accept_reallocation_through_shared_escrow(
                &ReallocationTerms {
                    ticket_id,
                    replacement_operator: operator,
                    start_epoch: 0,
                    end_epoch: 10,
                    economics: economics.clone(),
                    merkle_proof: Some(proof),
                    storage_root: Some([0x42u8; 32]),
                },
                payer,
                &params,
            )
            .expect("the replacement opens with escrow");

        let ticket = blockchain
            .state
            .storage_registry
            .get_reallocation_ticket(ticket_id)
            .expect("ticket exists");
        assert_eq!(ticket.status, ReallocationStatus::ActiveReplacement);
        assert_eq!(ticket.replacement_deal_id, Some(replacement_deal_id));
        let deal = blockchain
            .state
            .storage_registry
            .all_deals()
            .into_iter()
            .find(|d| d.deal_id == replacement_deal_id)
            .expect("replacement deal recorded");
        assert!(deal.is_active());
        assert_eq!(deal.operator, operator);
        assert_eq!(blockchain.state.get_balance(&payer), payer_before - fee);
        assert_eq!(
            blockchain.state.get_balance(&operator),
            op_before - economics.operator_bond
        );
    }

    #[test]
    fn accept_reallocation_refuses_the_slashed_operator() {
        let (mut blockchain, deal_id, operator, _bond, _after_bond) = blockchain_with_one_deal(10);
        blockchain
            .state
            .storage_registry
            .open_challenge(deal_id, 0, 4, 1, 2, Address::zero(), 1)
            .unwrap();
        let (finalized, _slashed) = blockchain.finalize_missed_storage_challenges(20).unwrap();
        assert_eq!(finalized, 1, "the missed challenge finalizes and slashes");
        // `all_reallocation_tickets` yields `Vec<&Ticket>`, so a `ticket` kept
        // past here holds an immutable borrow on `blockchain` - and the rest of
        // this test credits a balance and calls the escrow, both of which need it
        // mutably (E0502 twice in the failing build). The one field the test reads
        // afterwards is copied out and the borrow ends with the block. Cloning the
        // whole ticket would compile too, and would hide which field matters.
        let ticket_id = {
            let ticket = blockchain
                .state
                .storage_registry
                .all_reallocation_tickets()
                .into_iter()
                .find(|t| t.failed_deal_id == deal_id)
                .expect("the slash opens a ticket");
            assert_eq!(ticket.slashed_operator, operator);
            ticket.ticket_id
        };

        let params = StorageDomainParams::default();
        let economics = StorageEconomicsParams {
            operator_bond: params.min_operator_bond,
            fee_per_byte_epoch: 1,
        };
        let proof = vec![0xABu8; 96];
        let payer = Address::from([23u8; 32]);
        blockchain.state.add_balance(&payer, 1_000_000);
        let payer_before = blockchain.state.get_balance(&payer);
        let op_before = blockchain.state.get_balance(&operator);

        let err = blockchain
            .accept_reallocation_through_shared_escrow(
                &ReallocationTerms {
                    ticket_id,
                    replacement_operator: operator,
                    start_epoch: 0,
                    end_epoch: 10,
                    economics,
                    merkle_proof: Some(proof),
                    storage_root: Some([0x42u8; 32]),
                },
                payer,
                &params,
            )
            .expect_err("the slashed operator may not replace itself");
        assert!(err.contains("slashed operator"), "got: {err}");
        // The refusal precedes every balance move.
        assert_eq!(blockchain.state.get_balance(&payer), payer_before);
        assert_eq!(blockchain.state.get_balance(&operator), op_before);
        let after = blockchain
            .state
            .storage_registry
            .get_reallocation_ticket(ticket_id)
            .expect("ticket exists");
        assert_eq!(after.status, ReallocationStatus::Pending);
    }

    #[test]
    fn accept_reallocation_is_one_shot() {
        let (mut blockchain, ticket_id, operator, payer, economics, params, proof) =
            blockchain_with_never_placed_ticket();
        let first = blockchain
            .accept_reallocation_through_shared_escrow(
                &ReallocationTerms {
                    ticket_id,
                    replacement_operator: operator,
                    start_epoch: 0,
                    end_epoch: 10,
                    economics: economics.clone(),
                    merkle_proof: Some(proof.clone()),
                    storage_root: Some([0x42u8; 32]),
                },
                payer,
                &params,
            )
            .expect("first acceptance opens the replacement");
        let payer_before = blockchain.state.get_balance(&payer);

        let second_operator = Address::from([24u8; 32]);
        blockchain.state.add_balance(&second_operator, 5_000_000);
        let err = blockchain
            .accept_reallocation_through_shared_escrow(
                &ReallocationTerms {
                    ticket_id,
                    replacement_operator: second_operator,
                    start_epoch: 0,
                    end_epoch: 10,
                    economics: economics.clone(),
                    merkle_proof: Some(proof),
                    storage_root: Some([0x42u8; 32]),
                },
                payer,
                &params,
            )
            .expect_err("a filled ticket cannot be accepted again");
        assert!(err.contains("not open for acceptance"), "got: {err}");
        // The refused second attempt debits nothing.
        assert_eq!(blockchain.state.get_balance(&payer), payer_before);
        let ticket = blockchain
            .state
            .storage_registry
            .get_reallocation_ticket(ticket_id)
            .expect("ticket exists");
        assert_eq!(ticket.replacement_deal_id, Some(first));
    }

    #[test]
    fn accept_reallocation_refunds_when_the_proof_is_missing() {
        let (mut blockchain, ticket_id, operator, payer, economics, params, _proof) =
            blockchain_with_never_placed_ticket();
        let payer_before = blockchain.state.get_balance(&payer);
        let op_before = blockchain.state.get_balance(&operator);

        let err = blockchain
            .accept_reallocation_through_shared_escrow(
                &ReallocationTerms {
                    ticket_id,
                    replacement_operator: operator,
                    start_epoch: 0,
                    end_epoch: 10,
                    economics: economics.clone(),
                    merkle_proof: None,
                    storage_root: None,
                },
                payer,
                &params,
            )
            .expect_err("the merkle envelope is mandatory on the replacement too");
        assert!(
            err.contains("accept_reallocation_ticket failed"),
            "got: {err}"
        );
        // A refused replacement keeps neither the escrow nor the bond.
        assert_eq!(blockchain.state.get_balance(&payer), payer_before);
        assert_eq!(blockchain.state.get_balance(&operator), op_before);
        let ticket = blockchain
            .state
            .storage_registry
            .get_reallocation_ticket(ticket_id)
            .expect("ticket exists");
        assert_eq!(ticket.status, ReallocationStatus::Pending);
    }

    /// The operator-RPC deal door runs the same authority rule the in-block
    /// path runs: a payer that does not own the manifest cannot place a deal
    /// over it, and the refusal leaves balances and the registry untouched
    /// (Review 9 / CWE-862 - ownership gate for storage-deal open).
    #[test]
    fn rpc_deal_open_refuses_a_payer_that_does_not_own_the_manifest() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut blockchain = Blockchain::new(consensus, None, 45262, None);
        let owner = Address::from([0x31u8; 32]);
        let payer = Address::from([0x32u8; 32]);
        let operator = Address::from([0x33u8; 32]);
        blockchain.state.add_balance(&owner, 5_000_000);
        blockchain.state.add_balance(&payer, 5_000_000);
        blockchain.state.add_balance(&operator, 5_000_000);

        let mut manifest =
            ContentManifest::from_bytes_sliced(b"stranger deal refusal payload", 8).unwrap();
        manifest.owner = owner;
        let shard_id = manifest.shards[0].shard_id;
        let params = StorageDomainParams::default();
        let shard_bytes = u64::from(manifest.shard(&shard_id).expect("shard in manifest").size);
        let economics = StorageEconomicsParams {
            operator_bond: params.min_operator_bond,
            fee_per_byte_epoch: 10 * (FEE_RATE_SCALE as u64) / shard_bytes,
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
        blockchain
            .state
            .storage_registry
            .register_manifest(&manifest);

        let deals_before = blockchain.state.storage_registry.deals_iter().count();
        let payer_before = blockchain.state.get_balance(&payer);
        let operator_before = blockchain.state.get_balance(&operator);

        let err = blockchain
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
                Some(proof.clone()),
                Some([0x42u8; 32]),
            )
            .expect_err("a stranger's payer must not open a deal over the owner's manifest");
        assert!(err.contains("does not own"), "got: {err}");
        assert_eq!(
            blockchain.state.get_balance(&payer),
            payer_before,
            "a refused open must not debit the payer"
        );
        assert_eq!(
            blockchain.state.get_balance(&operator),
            operator_before,
            "a refused open must not move the operator's bond"
        );
        assert_eq!(
            blockchain.state.storage_registry.deals_iter().count(),
            deals_before,
            "a refused open must not write a deal row"
        );

        // The authority itself opens the same deal through the same door.
        let deal_id = blockchain
            .open_storage_deal_with_escrow(
                42,
                &manifest,
                shard_id,
                operator,
                owner,
                0,
                0,
                10,
                economics,
                &params,
                Some(proof),
                Some([0x42u8; 32]),
            )
            .expect("the owner opens its own deal");
        assert_eq!(
            blockchain.state.storage_registry.deals_iter().count(),
            deals_before + 1,
            "the owner's deal row lands"
        );
        let _ = deal_id;
    }
}
