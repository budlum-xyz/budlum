#[cfg(test)]
mod byzantine_settlement_tests {
    use crate::chain::blockchain::Blockchain;
    use crate::chain::finality::{FinalityCert, ValidatorSetSnapshot};
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    #[cfg(test)]
    fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
        let mut b = [0u8; 32];
        b[0] = byte;
        crate::core::address::Address::from(b)
    }

    use crate::core::block::Block;
    use crate::domain::finality_adapter::{hash_finality_proof, FinalityProof};
    use crate::domain::plugin::default_domain;
    use crate::domain::{ConsensusKind, DomainCommitment, DomainStatus};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Apply a commitment's nonce writes the way they reach state under
    /// decision 50 (C3): through a StateUpdateTx executed by the executor.
    /// `accept` no longer writes the nonce out of block; this helper builds
    /// the tx and runs the executor arm that does.
    fn apply_state_updates(
        node: &mut Blockchain,
        sender: Address,
        domain_id: crate::domain::types::DomainId,
        domain_height: u64,
        updates: Vec<(Address, u64)>,
    ) -> Result<(), String> {
        let nonce = node.state.get_nonce(&sender);
        let tx = crate::core::transaction::Transaction::new_with_chain_id(
            sender,
            Address::zero(),
            0,
            1,
            nonce,
            Vec::new(),
            45262,
            crate::core::transaction::TransactionType::StateUpdate {
                domain_id,
                domain_height,
                state_updates: updates,
            },
        );
        crate::execution::executor::Executor::apply_transaction(&mut node.state, &tx)
    }

    #[tokio::test]
    async fn test_multi_consensus_settlement_determinism_and_invalid_commitment_rejection() {
        let make_node = || {
            let consensus = Arc::new(PoWEngine::new(0));
            let mut node = Blockchain::new(consensus, None, 45262, None);

            let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
            let pos = default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0);
            let poa = default_domain(3, ConsensusKind::PoA, 1339, "poa-authority-quorum", 0);

            node.register_consensus_domain(pow).unwrap();
            node.register_consensus_domain(pos).unwrap();
            node.register_consensus_domain(poa).unwrap();
            node
        };

        let mut node_a = make_node();
        let mut node_b = make_node();

        let pow_domain = node_a.domain_registry.get(1).unwrap().clone();
        let pos_domain = node_a.domain_registry.get(2).unwrap().clone();
        let poa_domain = node_a.domain_registry.get(3).unwrap().clone();

        let mut pow_commitments = Vec::new();
        let mut pos_commitments = Vec::new();
        let mut poa_commitments = Vec::new();

        // Each domain's commitments have to form a contiguous chain: the
        // commitment at height N+1 names the one at height N as its parent.
        // `DomainCommitment::from_block` derives `parent_domain_block_hash`
        // from `block.previous_hash`, so the blocks themselves must be linked.
        // These used to all carry the same placeholder parent, which only went
        // unnoticed because the chain-continuity check was compiled out under
        // `#[cfg(test)]`.
        let mut prev_pow = "pow".repeat(16);
        let mut prev_pos = "pos".repeat(16);
        let mut prev_poa = "poa".repeat(16);

        for i in 1..=100 {
            let mut b_pow = Block::new(i, prev_pow.clone(), vec![]);
            b_pow.state_root = format!("pow_state_{i}").repeat(16)[0..64].to_string();
            b_pow.tx_root = b_pow.calculate_tx_root();
            b_pow.hash = b_pow.calculate_hash();
            let mut com_pow =
                DomainCommitment::from_block(&pow_domain, &b_pow, [i as u8; 32], [0u8; 32], i)
                    .unwrap();
            let proof_pow = FinalityProof::PoWHeaderChain { headers: vec![] };
            com_pow.finality_proof_hash = hash_finality_proof(&proof_pow).unwrap();
            prev_pow = b_pow.hash.clone();
            pow_commitments.push((com_pow, proof_pow));

            let mut b_pos = Block::new(i, prev_pos.clone(), vec![]);
            b_pos.state_root = format!("pos_state_{i}").repeat(16)[0..64].to_string();
            b_pos.tx_root = b_pos.calculate_tx_root();
            b_pos.hash = b_pos.calculate_hash();
            let mut com_pos =
                DomainCommitment::from_block(&pos_domain, &b_pos, [i as u8; 32], [0u8; 32], i)
                    .unwrap();
            let proof_pos = FinalityProof::PoS {
                cert: FinalityCert {
                    epoch: 1,
                    checkpoint_height: i,
                    checkpoint_hash: b_pos.hash.clone(),
                    agg_sig_bls: vec![0u8; 48],
                    bitmap: vec![1],
                    set_hash: "set".to_string(),
                },
                validator_snapshot: ValidatorSetSnapshot {
                    epoch: 1,
                    validators: vec![],
                    set_hash: "set".to_string(),
                    total_stake: 100,
                },
            };
            com_pos.finality_proof_hash = hash_finality_proof(&proof_pos).unwrap();
            prev_pos = b_pos.hash.clone();
            pos_commitments.push((com_pos, proof_pos));

            let mut b_poa = Block::new(i, prev_poa.clone(), vec![]);
            b_poa.state_root = format!("poa_state_{i}").repeat(16)[0..64].to_string();
            b_poa.tx_root = b_poa.calculate_tx_root();
            b_poa.hash = b_poa.calculate_hash();
            let mut com_poa =
                DomainCommitment::from_block(&poa_domain, &b_poa, [i as u8; 32], [0u8; 32], i)
                    .unwrap();
            let proof_poa = FinalityProof::PoA {
                authorities: vec![],
                signatures: vec![],
            };
            com_poa.finality_proof_hash = hash_finality_proof(&proof_poa).unwrap();
            prev_poa = b_poa.hash.clone();
            poa_commitments.push((com_poa, proof_poa));
        }

        let mut all_commitments = Vec::new();
        all_commitments.extend(pow_commitments.clone());
        all_commitments.extend(pos_commitments.clone());
        all_commitments.extend(poa_commitments.clone());

        for (com, _proof) in all_commitments.iter() {
            node_a.submit_domain_commitment(com.clone()).unwrap();
        }
        let root_a = node_a.build_global_header(None).domain_commitment_root;

        let mut all_commitments_shuffled = all_commitments.clone();
        all_commitments_shuffled.reverse();
        for (com, _proof) in all_commitments_shuffled.iter() {
            node_b.submit_domain_commitment(com.clone()).unwrap();
        }
        let root_b = node_b.build_global_header(None).domain_commitment_root;

        assert_eq!(root_a, root_b, "Global root must be order-independent");

        let (mut fake_com, proof) = pow_commitments[0].clone();
        fake_com.state_root = [0xFFu8; 32];
        fake_com.sequence = 9999;
        assert!(
            node_a
                .submit_verified_domain_commitment(fake_com, proof)
                .is_err(),
            "Invalid state root in proof must be rejected"
        );

        let header = node_a.seal_global_header(None).unwrap();
        let (mut rollback_com, _proof) = pow_commitments[0].clone();
        rollback_com.sequence = 0;
        assert!(
            node_a.submit_domain_commitment(rollback_com).is_ok(),
            "Exact duplicate finalized height is idempotent"
        );

        let header_after = node_a.seal_global_header(None).unwrap();
        assert_eq!(
            header.calculate_hash_bytes(),
            header_after.previous_global_hash,
            "Global hash chain must be stable"
        );

        let poa_domain_id = poa_domain.id;
        node_a
            .domain_registry
            .set_status(poa_domain_id, DomainStatus::Frozen)
            .unwrap();
        let mut com_poa_new = poa_commitments[0].0.clone();
        com_poa_new.domain_height = 999;
        com_poa_new.sequence = 999;
        assert!(
            node_a.submit_domain_commitment(com_poa_new).is_err(),
            "Frozen domain should not accept commitments"
        );

        assert!(
            node_a
                .submit_domain_commitment(pow_commitments[0].0.clone())
                .is_ok(),
            "Already committed PoW exact duplicate is idempotent"
        );
    }

    #[tokio::test]
    async fn test_cross_domain_double_spend_protection() {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut node = Blockchain::new(consensus, None, 45262, None);

        let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        let pos = default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0);
        node.register_consensus_domain(pow.clone()).unwrap();
        node.register_consensus_domain(pos.clone()).unwrap();

        let alice = Address::from([0xA1u8; 32]);
        node.state.add_balance(&alice, 1000);
        assert_eq!(node.state.get_nonce(&alice), 0);

        let mut b_pow = Block::new(1, "pow".repeat(16), vec![]);
        b_pow.state_root = "pow_state".repeat(16)[0..64].to_string();
        b_pow.tx_root = b_pow.calculate_tx_root();
        b_pow.hash = b_pow.calculate_hash();

        let mut com_pow =
            DomainCommitment::from_block(&pow, &b_pow, [0u8; 32], [0u8; 32], 1).unwrap();
        com_pow.state_updates.insert(alice, 1); // Claims consuming nonce 0 -> 1

        let mut b_pos = Block::new(1, "pos".repeat(16), vec![]);
        b_pos.state_root = "pos_state".repeat(16)[0..64].to_string();
        b_pos.tx_root = b_pos.calculate_tx_root();
        b_pos.hash = b_pos.calculate_hash();

        let mut com_pos =
            DomainCommitment::from_block(&pos, &b_pos, [0u8; 32], [0u8; 32], 1).unwrap();
        com_pos.state_updates.insert(alice, 1); // Also claims consuming nonce 0 -> 1

        // C3 (decision 50): acceptance records the commitment in the registry
        // but no longer writes the account nonce out of block. The write
        // travels in a StateUpdateTx and is applied inside block execution.
        let pow_res = node.submit_domain_commitment(com_pow);
        assert!(
            pow_res.is_ok(),
            "First commitment should be accepted: {:?}",
            pow_res.err()
        );
        assert_eq!(
            node.state.get_nonce(&alice),
            0,
            "Accept must not write the nonce out of block"
        );

        let res2 = node.submit_domain_commitment(com_pos);
        assert!(
            res2.is_ok(),
            "Second commitment records in the registry: {:?}",
            res2.err()
        );

        let sender = test_addr_from_byte(0xEE);
        node.state.add_balance(&sender, 1_000_000);

        let first = apply_state_updates(&mut node, sender, 1, 1, vec![(alice, 1)]);
        assert!(
            first.is_ok(),
            "First state update must apply: {:?}",
            first.err()
        );
        assert_eq!(node.state.get_nonce(&alice), 1);

        let second = apply_state_updates(&mut node, sender, 2, 1, vec![(alice, 1)]);
        assert!(
            second.is_err(),
            "Conflicting nonce claim must be rejected at execution"
        );
        assert_eq!(
            node.state.get_nonce(&alice),
            1,
            "Nonce must not be double-spent"
        );
    }

    #[tokio::test]
    async fn test_cross_domain_double_spend_order_independence() {
        let make_node = || {
            let consensus = std::sync::Arc::new(crate::consensus::pow::PoWEngine::new(0));
            let mut node = Blockchain::new(consensus, None, 45262, None);
            let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
            let pos = default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0);
            node.register_consensus_domain(pow.clone()).unwrap();
            node.register_consensus_domain(pos.clone()).unwrap();
            let alice = Address::from([0xA1u8; 32]);
            node.state.add_balance(&alice, 1000);
            (node, pow, pos, alice)
        };

        let (mut node_a, pow_a, pos_a, alice_a) = make_node();
        let (mut node_b, _pow_b, _pos_b, alice_b) = make_node();

        let mut b_pow = Block::new(1, "pow".repeat(16), vec![]);
        b_pow.state_root = "pow_state".repeat(16)[0..64].to_string();
        b_pow.tx_root = b_pow.calculate_tx_root();
        b_pow.hash = b_pow.calculate_hash();
        let mut com_pow =
            DomainCommitment::from_block(&pow_a, &b_pow, [0u8; 32], [0u8; 32], 1).unwrap();
        com_pow.state_updates.insert(alice_a, 1);

        let mut b_pos = Block::new(1, "pos".repeat(16), vec![]);
        b_pos.state_root = "pos_state".repeat(16)[0..64].to_string();
        b_pos.tx_root = b_pos.calculate_tx_root();
        b_pos.hash = b_pos.calculate_hash();
        let mut com_pos =
            DomainCommitment::from_block(&pos_a, &b_pos, [0u8; 32], [0u8; 32], 1).unwrap();
        com_pos.state_updates.insert(alice_a, 1);

        let com_pow_b = com_pow.clone();
        let com_pos_b = com_pos.clone();

        // Acceptance order no longer decides the nonce (C3, decision 50): both
        // commitments are recorded and the conflicting claim is rejected at
        // execution time, not at accept time.
        assert!(node_a.submit_domain_commitment(com_pow).is_ok());
        assert!(node_a.submit_domain_commitment(com_pos).is_ok());
        assert!(node_b.submit_domain_commitment(com_pos_b).is_ok());
        assert!(node_b.submit_domain_commitment(com_pow_b).is_ok());

        let sender_a = test_addr_from_byte(0xEE);
        node_a.state.add_balance(&sender_a, 1_000_000);
        let sender_b = test_addr_from_byte(0xEE);
        node_b.state.add_balance(&sender_b, 1_000_000);

        // node_a applies the PoW claim first, node_b the PoS claim first; the
        // winning nonce and the rejection of the loser are order-independent.
        assert!(apply_state_updates(&mut node_a, sender_a, 1, 1, vec![(alice_a, 1)]).is_ok());
        assert!(apply_state_updates(&mut node_a, sender_a, 2, 1, vec![(alice_a, 1)]).is_err());
        assert!(apply_state_updates(&mut node_b, sender_b, 2, 1, vec![(alice_b, 1)]).is_ok());
        assert!(apply_state_updates(&mut node_b, sender_b, 1, 1, vec![(alice_b, 1)]).is_err());

        assert_eq!(node_a.state.get_nonce(&alice_a), 1);
        assert_eq!(node_b.state.get_nonce(&alice_b), 1);
        assert_eq!(
            node_a.state.get_nonce(&alice_a),
            node_b.state.get_nonce(&alice_b)
        );
    }

    #[tokio::test]
    async fn test_cross_domain_non_conflicting_updates_can_coexist() {
        let consensus = std::sync::Arc::new(crate::consensus::pow::PoWEngine::new(0));
        let mut node = Blockchain::new(consensus, None, 45262, None);
        let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        let pos = default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0);
        node.register_consensus_domain(pow.clone()).unwrap();
        node.register_consensus_domain(pos.clone()).unwrap();

        let alice = Address::from([0xA1u8; 32]);
        let bob = Address::from([0xB2u8; 32]);
        node.state.add_balance(&alice, 1000);
        node.state.add_balance(&bob, 1000);

        let mut b_pow = Block::new(1, "pow".repeat(16), vec![]);
        b_pow.state_root = "pow_state".repeat(16)[0..64].to_string();
        b_pow.tx_root = b_pow.calculate_tx_root();
        b_pow.hash = b_pow.calculate_hash();
        let mut com_pow =
            DomainCommitment::from_block(&pow, &b_pow, [0u8; 32], [0u8; 32], 1).unwrap();
        com_pow.state_updates.insert(alice, 1);

        let mut b_pos = Block::new(1, "pos".repeat(16), vec![]);
        b_pos.state_root = "pos_state".repeat(16)[0..64].to_string();
        b_pos.tx_root = b_pos.calculate_tx_root();
        b_pos.hash = b_pos.calculate_hash();
        let mut com_pos =
            DomainCommitment::from_block(&pos, &b_pos, [0u8; 32], [0u8; 32], 1).unwrap();
        com_pos.state_updates.insert(bob, 1);

        assert!(node.submit_domain_commitment(com_pow).is_ok());
        assert!(node.submit_domain_commitment(com_pos).is_ok());

        let sender = test_addr_from_byte(0xEE);
        node.state.add_balance(&sender, 1_000_000);

        assert!(apply_state_updates(&mut node, sender, 1, 1, vec![(alice, 1)]).is_ok());
        assert!(apply_state_updates(&mut node, sender, 2, 1, vec![(bob, 1)]).is_ok());

        assert_eq!(node.state.get_nonce(&alice), 1);
        assert_eq!(node.state.get_nonce(&bob), 1);
    }

    #[tokio::test]
    async fn test_parallel_cross_domain_stress_determinism() {
        use rand::rng;
        use rand::seq::SliceRandom;

        let make_node = || {
            let consensus = std::sync::Arc::new(crate::consensus::pow::PoWEngine::new(0));
            let mut node = Blockchain::new(consensus, None, 45262, None);
            for i in 1..=5 {
                let pow = default_domain(
                    i,
                    ConsensusKind::PoW,
                    45262 + i as u64,
                    "pow-header-chain-v1",
                    0,
                );
                node.register_consensus_domain(pow).unwrap();
            }
            node
        };

        let mut node_a = make_node();
        let mut node_b = make_node();

        let mut commitments = Vec::new();
        let accounts: Vec<Address> = (0..100).map(|i| Address::from([i as u8; 32])).collect();

        for i in 0..1000 {
            let domain_id = (i % 5) + 1;
            let addr_idx = i % 100;
            let nonce = (i / 100) + 1;

            let mut block = Block::new(i as u64, format!("hash_{i}"), vec![]);
            block.state_root = format!("state_{i}");
            block.tx_root = block.calculate_tx_root();
            block.hash = block.calculate_hash();

            let domain = node_a.domain_registry.get(domain_id).unwrap();
            let mut com =
                DomainCommitment::from_block(domain, &block, [0u8; 32], [0u8; 32], i as u64)
                    .unwrap();
            com.state_updates
                .insert(accounts[addr_idx as usize], nonce as u64);
            commitments.push(com);
        }

        let mut commitments_a = commitments.clone();
        let mut commitments_b = commitments.clone();

        let mut rng = rng();
        commitments_a.shuffle(&mut rng);
        commitments_b.shuffle(&mut rng);

        for com in commitments_a {
            let _ = node_a.submit_domain_commitment(com);
        }
        for com in commitments_b {
            let _ = node_b.submit_domain_commitment(com);
        }

        // C3 (decision 50): the nonce writes apply at execution. Each node
        // applies the same set of claims in a different order; the monotonic
        // guard makes the final nonce per account identical.
        let claims: Vec<(crate::domain::types::DomainId, u64, Address, u64)> = commitments
            .iter()
            .map(|com| {
                let (addr, nonce) = com.state_updates.iter().next().unwrap();
                (com.domain_id, com.domain_height, *addr, *nonce)
            })
            .collect();
        let sender = test_addr_from_byte(0xEE);
        node_a.state.add_balance(&sender, 1_000_000);
        node_b.state.add_balance(&sender, 1_000_000);

        let mut claims_a = claims.clone();
        let mut claims_b = claims.clone();
        claims_a.shuffle(&mut rng);
        claims_b.shuffle(&mut rng);
        for (domain_id, height, addr, nonce) in claims_a {
            let _ =
                apply_state_updates(&mut node_a, sender, domain_id, height, vec![(addr, nonce)]);
        }
        for (domain_id, height, addr, nonce) in claims_b {
            let _ =
                apply_state_updates(&mut node_b, sender, domain_id, height, vec![(addr, nonce)]);
        }

        for addr in &accounts {
            assert_eq!(
                node_a.state.get_nonce(addr),
                node_b.state.get_nonce(addr),
                "Determinism failed for account {:?}",
                addr
            );
        }
    }

    #[tokio::test]
    async fn test_concurrent_tokio_submission() {
        let consensus = Arc::new(crate::consensus::pow::PoWEngine::new(0));
        let node = Blockchain::new(consensus, None, 45262, None);
        let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        let mut node = node;
        node.register_consensus_domain(pow.clone()).unwrap();
        let alice = Address::from([0xA1u8; 32]);
        node.state.add_balance(&alice, 1000);

        let node_shared = Arc::new(RwLock::new(node));
        let mut handles = Vec::new();

        for i in 0..100 {
            let n_arc = node_shared.clone();
            let p_arc = pow.clone();
            let h = tokio::spawn(async move {
                let block = linked_test_block(1, i as u64 + 1);
                let mut com =
                    DomainCommitment::from_block(&p_arc, &block, [0u8; 32], [0u8; 32], i as u64)
                        .unwrap();
                com.state_updates.clear();

                let mut node_write = n_arc.write().await;
                node_write.submit_domain_commitment(com)
            });
            handles.push(h);
        }

        let mut success_count = 0;
        for h in handles {
            if h.await.unwrap().is_ok() {
                success_count += 1;
            }
        }

        assert_eq!(
            success_count, 100,
            "All unique heights should be accepted into registry"
        );
        let node_final = node_shared.read().await;
        assert_eq!(
            node_final.state.get_nonce(&alice),
            0,
            "Commitments without state updates must not change nonce"
        );
    }

    #[tokio::test]
    async fn test_crash_recovery() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("crash_recovery_db");
        let path_str = path.to_str().unwrap();

        let alice = Address::from([0xA1u8; 32]);
        let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);

        {
            let storage = crate::storage::db::Storage::new(path_str).unwrap();
            let consensus = Arc::new(crate::consensus::pow::PoWEngine::new(0));
            let mut node = Blockchain::new(consensus, Some(storage), 45262, None);
            node.register_consensus_domain(pow.clone()).unwrap();
            node.state.add_balance(&alice, 1000);

            let mut block = Block::new(1, "h1".to_string(), vec![]);
            block.hash = block.calculate_hash();
            let mut com =
                DomainCommitment::from_block(&pow, &block, [0u8; 32], [0u8; 32], 1).unwrap();
            com.state_updates.insert(alice, 1);
            node.submit_domain_commitment(com).unwrap();

            // The nonce write is applied in block execution (StateUpdateTx),
            // not at accept (C3, decision 50).
            let sender = test_addr_from_byte(0xEE);
            node.state.add_balance(&sender, 1_000_000);
            apply_state_updates(&mut node, sender, 1, 1, vec![(alice, 1)]).unwrap();

            assert_eq!(node.state.get_nonce(&alice), 1);
        }

        {
            let storage = crate::storage::db::Storage::new(path_str).unwrap();
            let consensus = Arc::new(crate::consensus::pow::PoWEngine::new(0));
            let node = Blockchain::new(consensus, Some(storage), 45262, None);

            // C3 (decision 50): the registry and the commitment are durable and
            // survive the restart. The nonce is not: it only lands when a block
            // commits the StateUpdateTx, and no block was produced here, so the
            // restart does not resurrect an out-of-block nonce write.
            assert_eq!(node.state.get_nonce(&alice), 0);
            assert!(node.domain_registry.get(1).is_some());
            assert_eq!(node.domain_commitment_registry.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_merkle_root_replay() {
        let make_node = || {
            let consensus = Arc::new(crate::consensus::pow::PoWEngine::new(0));
            let mut node = Blockchain::new(consensus, None, 45262, None);
            let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
            node.register_consensus_domain(pow.clone()).unwrap();
            (node, pow)
        };

        let (mut node_a, pow_a) = make_node();
        let (mut node_b, _) = make_node();

        let mut block = Block::new(1, "h1".to_string(), vec![]);
        block.hash = block.calculate_hash();
        let mut com =
            DomainCommitment::from_block(&pow_a, &block, [0u8; 32], [0u8; 32], 1).unwrap();
        com.state_updates.insert(test_addr_from_byte(1u8), 1);

        node_a.submit_domain_commitment(com.clone()).unwrap();
        node_b.submit_domain_commitment(com).unwrap();

        let root_a = node_a.build_global_header(None).domain_commitment_root;
        let root_b = node_b.build_global_header(None).domain_commitment_root;

        assert_eq!(root_a, root_b);
        assert_ne!(root_a, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_network_partition_convergence() {
        let make_node = || {
            let consensus = Arc::new(crate::consensus::pow::PoWEngine::new(0));
            let mut node = Blockchain::new(consensus, None, 45262, None);
            let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
            let pos = default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0);
            node.register_consensus_domain(pow.clone()).unwrap();
            node.register_consensus_domain(pos.clone()).unwrap();
            (node, pow, pos)
        };

        let (mut node_a, pow_a, pos_a) = make_node();
        let (mut node_b, _, _) = make_node();

        let alice = test_addr_from_byte(1u8);
        let bob = test_addr_from_byte(2u8);
        node_a.state.add_balance(&alice, 1000);
        node_a.state.add_balance(&bob, 1000);
        node_b.state.add_balance(&alice, 1000);
        node_b.state.add_balance(&bob, 1000);

        let b1 = Block::new(1, "h1".to_string(), vec![]);
        let mut com1 = DomainCommitment::from_block(&pow_a, &b1, [0u8; 32], [0u8; 32], 1).unwrap();
        com1.state_updates.insert(alice, 1);

        let b2 = Block::new(1, "h2".to_string(), vec![]);
        let mut com2 = DomainCommitment::from_block(&pos_a, &b2, [0u8; 32], [0u8; 32], 1).unwrap();
        com2.state_updates.insert(bob, 1);

        node_a.submit_domain_commitment(com1.clone()).unwrap();
        node_b.submit_domain_commitment(com2.clone()).unwrap();

        // Partitioned: each side records a different commitment, so the
        // commitment roots diverge until the two sides exchange (the nonce
        // writes no longer move at accept time, C3 decision 50).
        assert_ne!(
            node_a.build_global_header(None).domain_commitment_root,
            node_b.build_global_header(None).domain_commitment_root
        );

        node_a.submit_domain_commitment(com2).unwrap();
        node_b.submit_domain_commitment(com1).unwrap();

        let sender_a = test_addr_from_byte(0xEE);
        node_a.state.add_balance(&sender_a, 1_000_000);
        let sender_b = test_addr_from_byte(0xEE);
        node_b.state.add_balance(&sender_b, 1_000_000);
        assert!(apply_state_updates(&mut node_a, sender_a, 1, 1, vec![(alice, 1)]).is_ok());
        assert!(apply_state_updates(&mut node_a, sender_a, 2, 1, vec![(bob, 1)]).is_ok());
        assert!(apply_state_updates(&mut node_b, sender_b, 2, 1, vec![(bob, 1)]).is_ok());
        assert!(apply_state_updates(&mut node_b, sender_b, 1, 1, vec![(alice, 1)]).is_ok());

        assert_eq!(node_a.state.get_nonce(&alice), 1);
        assert_eq!(node_a.state.get_nonce(&bob), 1);
        assert_eq!(node_b.state.get_nonce(&alice), 1);
        assert_eq!(node_b.state.get_nonce(&bob), 1);
        let mut h_a = node_a.build_global_header(None);
        h_a.timestamp_ms = 0;
        let mut h_b = node_b.build_global_header(None);
        h_b.timestamp_ms = 0;
        assert_eq!(h_a.calculate_hash(), h_b.calculate_hash());
    }

    #[tokio::test]
    async fn test_byzantine_domain_equivocation() {
        let consensus = Arc::new(crate::consensus::pow::PoWEngine::new(0));
        let mut node = Blockchain::new(consensus, None, 45262, None);
        let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        node.register_consensus_domain(pow.clone()).unwrap();

        let alice = test_addr_from_byte(1u8);
        node.state.add_balance(&alice, 1000);

        let b1 = Block::new(1, "h1".to_string(), vec![]);
        let mut com1 = DomainCommitment::from_block(&pow, &b1, [0u8; 32], [0u8; 32], 1).unwrap();
        com1.state_updates.insert(alice, 1);

        let b2 = Block::new(1, "h2".to_string(), vec![]);
        let mut com2 = DomainCommitment::from_block(&pow, &b2, [0u8; 32], [0u8; 32], 2).unwrap();
        com2.state_updates.insert(alice, 1);

        node.submit_domain_commitment(com1).unwrap();
        let res = node.submit_domain_commitment(com2);

        assert!(
            res.is_err(),
            "Equivocation (same height, different hash) must be rejected"
        );
        // C3 (decision 50): the nonce write no longer happens at accept; the
        // freeze is the registry-level outcome, the nonce moves in execution.
        assert_eq!(node.state.get_nonce(&alice), 0);
        assert_eq!(
            node.domain_registry.get(1).unwrap().status,
            DomainStatus::Frozen
        );
    }

    #[tokio::test]
    async fn test_async_gossip_packet_duplication_idempotency() {
        let mut node = make_node();
        let alice = Address::from([0xA1u8; 32]);
        node.state.add_balance(&alice, 1000);
        let com = make_commitment_for_account(&node, 1, alice, 1, 1);
        let mut accepted = 0;
        let mut rejected = 0;
        for _ in 0..20 {
            let res = node.submit_domain_commitment(com.clone());
            if res.is_ok() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert_eq!(accepted, 20);
        assert_eq!(rejected, 0);
        // C3 (decision 50): the nonce moves at execution, not at accept.
        assert_eq!(node.state.get_nonce(&alice), 0);
        let sender = test_addr_from_byte(0xEE);
        node.state.add_balance(&sender, 1_000_000);
        assert!(apply_state_updates(&mut node, sender, 1, 1, vec![(alice, 1)]).is_ok());
        assert_eq!(node.state.get_nonce(&alice), 1);
    }

    #[tokio::test]
    async fn test_old_partition_replay_message_rejected() {
        let mut node = make_node();
        let alice = Address::from([0xA1u8; 32]);
        node.state.add_balance(&alice, 1000);
        let c1 = make_commitment_for_account(&node, 1, alice, 1, 1);
        let c2 = make_commitment_for_account(&node, 1, alice, 2, 2);
        let c3 = make_commitment_for_account(&node, 1, alice, 3, 3);
        assert!(node.submit_domain_commitment(c1.clone()).is_ok());
        assert!(node.submit_domain_commitment(c2).is_ok());
        assert!(node.submit_domain_commitment(c3).is_ok());
        // C3 (decision 50): nonces move at execution, not at accept.
        assert_eq!(node.state.get_nonce(&alice), 0);

        let sender = test_addr_from_byte(0xEE);
        node.state.add_balance(&sender, 1_000_000);
        assert!(apply_state_updates(&mut node, sender, 1, 1, vec![(alice, 1)]).is_ok());
        assert!(apply_state_updates(&mut node, sender, 1, 2, vec![(alice, 2)]).is_ok());
        assert!(apply_state_updates(&mut node, sender, 1, 3, vec![(alice, 3)]).is_ok());
        assert_eq!(node.state.get_nonce(&alice), 3);

        let replay = node.submit_domain_commitment(c1);
        assert!(replay.is_ok(), "Exact duplicate should be idempotent (Ok)");
        assert_eq!(node.state.get_nonce(&alice), 3);
    }

    #[tokio::test]
    async fn test_async_gossip_message_delay_reordering_convergence() {
        let mut nodes = [make_node(), make_node(), make_node()];
        let accounts: Vec<Address> = (0..10).map(|i| Address::from([i as u8; 32])).collect();
        for node in nodes.iter_mut() {
            for acc in &accounts {
                node.state.add_balance(acc, 1000);
            }
        }
        let commitments = make_non_conflicting_commitments(&nodes[0], &accounts, 30);
        let order_a = commitments.clone();
        let mut order_b = commitments.clone();
        let mut order_c = commitments.clone();
        order_b.reverse();
        order_c.rotate_left(7);
        for com in order_a {
            let _ = nodes[0].submit_domain_commitment(com);
        }
        for com in order_b {
            let _ = nodes[1].submit_domain_commitment(com);
        }
        for com in order_c {
            let _ = nodes[2].submit_domain_commitment(com);
        }

        // C3 (decision 50): nonces move at execution. Each node applies the
        // same claims in its own order; the monotonic guard makes the final
        // nonce per account identical.
        let sender = test_addr_from_byte(0xEE);
        for node in nodes.iter_mut() {
            node.state.add_balance(&sender, 1_000_000);
        }
        let mut claims_a = Vec::new();
        let mut claims_b = Vec::new();
        let mut claims_c = Vec::new();
        for com in commitments {
            let (addr, nonce) = com.state_updates.iter().next().unwrap();
            let claim = (com.domain_id, com.domain_height, *addr, *nonce);
            claims_a.push(claim);
            claims_b.push(claim);
            claims_c.push(claim);
        }
        // Node 0 in original order, node 1 reversed, node 2 rotated.
        claims_b.reverse();
        claims_c.rotate_left(7);
        for (d, h, addr, nonce) in claims_a {
            let _ = apply_state_updates(&mut nodes[0], sender, d, h, vec![(addr, nonce)]);
        }
        for (d, h, addr, nonce) in claims_b {
            let _ = apply_state_updates(&mut nodes[1], sender, d, h, vec![(addr, nonce)]);
        }
        for (d, h, addr, nonce) in claims_c {
            let _ = apply_state_updates(&mut nodes[2], sender, d, h, vec![(addr, nonce)]);
        }

        for acc in &accounts {
            let expected = nodes[0].state.get_nonce(acc);
            for node in &nodes[1..] {
                assert_eq!(expected, node.state.get_nonce(acc));
            }
        }
    }

    #[tokio::test]
    async fn test_async_gossip_packet_drop_later_recovery() {
        let mut nodes = [make_node(), make_node(), make_node()];
        let accounts: Vec<Address> = (0..10).map(|i| Address::from([i as u8; 32])).collect();
        for node in nodes.iter_mut() {
            for acc in &accounts {
                node.state.add_balance(acc, 1000);
            }
        }
        let commitments = make_non_conflicting_commitments(&nodes[0], &accounts, 30);
        for com in commitments[0..30].iter().cloned() {
            let _ = nodes[0].submit_domain_commitment(com);
        }
        for com in commitments[0..10].iter().cloned() {
            let _ = nodes[1].submit_domain_commitment(com);
        }
        for com in commitments[10..20].iter().cloned() {
            let _ = nodes[2].submit_domain_commitment(com);
        }
        let mut h0_header = nodes[0].build_global_header(None);
        h0_header.timestamp_ms = 0;
        let h0_hash = h0_header.calculate_hash();

        let mut h1_header = nodes[1].build_global_header(None);
        h1_header.timestamp_ms = 0;
        let h1_hash = h1_header.calculate_hash();

        assert_ne!(h0_hash, h1_hash);

        for node in nodes.iter_mut() {
            for com in commitments.iter().cloned() {
                let _ = node.submit_domain_commitment(com);
            }
        }

        let mut expected_header = nodes[0].build_global_header(None);
        expected_header.timestamp_ms = 0;
        let expected_hash = expected_header.calculate_hash();

        for node in nodes.iter().skip(1) {
            let mut hi_header = node.build_global_header(None);
            hi_header.timestamp_ms = 0;
            assert_eq!(expected_hash, hi_header.calculate_hash());
        }
    }

    #[tokio::test]
    async fn test_partial_commit_propagation_conflict_deterministic_tiebreak() {
        let mut nodes = vec![make_node(), make_node(), make_node()];
        let alice = Address::from([0xA1u8; 32]);
        for node in nodes.iter_mut() {
            node.state.add_balance(&alice, 1000);
        }
        let com_pow = make_commitment_for_account(&nodes[0], 1, alice, 1, 1);
        let com_pos = make_commitment_for_account(&nodes[0], 2, alice, 1, 1);
        let _ = nodes[0].submit_domain_commitment(com_pow.clone());
        let _ = nodes[1].submit_domain_commitment(com_pos.clone());
        // C3 (decision 50): partial propagation records commitments only; the
        // nonce does not move until execution.
        assert_eq!(nodes[0].state.get_nonce(&alice), 0);
        assert_eq!(nodes[1].state.get_nonce(&alice), 0);
        assert_eq!(nodes[2].state.get_nonce(&alice), 0);

        for node in nodes.iter_mut() {
            let _ = node.submit_domain_commitment(com_pow.clone());
            let _ = node.submit_domain_commitment(com_pos.clone());
        }

        let sender = test_addr_from_byte(0xEE);
        for node in nodes.iter_mut() {
            node.state.add_balance(&sender, 1_000_000);
            // Deterministic tiebreak: the domain-1 claim applies first, the
            // domain-2 claim for the same nonce is rejected at execution.
            assert!(apply_state_updates(node, sender, 1, 1, vec![(alice, 1)]).is_ok());
            assert!(
                apply_state_updates(node, sender, 2, 1, vec![(alice, 1)]).is_err(),
                "conflicting claim must be rejected at execution"
            );
        }
        for node in &nodes {
            assert_eq!(node.state.get_nonce(&alice), 1);
        }
    }

    #[tokio::test]
    async fn test_async_gossip_random_delay_duplicate_drop_convergence() {
        use rand::rngs::StdRng;
        use rand::seq::SliceRandom;
        use rand::{RngExt, SeedableRng};
        let mut rng = StdRng::seed_from_u64(42);
        let node_count = 5;
        let mut nodes: Vec<Blockchain> = (0..node_count).map(|_| make_node()).collect();
        let accounts: Vec<Address> = (0..50).map(|i| Address::from([i as u8; 32])).collect();
        for node in nodes.iter_mut() {
            for acc in &accounts {
                node.state.add_balance(acc, 1000);
            }
        }
        let commitments = make_non_conflicting_commitments(&nodes[0], &accounts, 500);
        for com in commitments.iter() {
            for node in nodes.iter_mut().take(node_count) {
                if rng.random::<f64>() < 0.20 {
                    continue;
                }
                let duplicates = if rng.random::<f64>() < 0.30 { 2 } else { 1 };
                for _ in 0..duplicates {
                    let _ = node.submit_domain_commitment(com.clone());
                }
            }
        }
        for _round in 0..5 {
            let mut shuffled = commitments.clone();
            shuffled.shuffle(&mut rng);
            for node in nodes.iter_mut() {
                for com in shuffled.iter().cloned() {
                    let _ = node.submit_domain_commitment(com);
                }
            }
        }
        let mut expected_header = nodes[0].build_global_header(None);
        expected_header.timestamp_ms = 0;
        let expected_hash = expected_header.calculate_hash();

        for (i, node) in nodes.iter().enumerate().take(node_count).skip(1) {
            let mut hi_header = node.build_global_header(None);
            hi_header.timestamp_ms = 0;
            assert_eq!(
                expected_hash,
                hi_header.calculate_hash(),
                "node {} failed convergence under random gossip chaos",
                i
            );
        }
        // C3 (decision 50): the nonce moves at execution, not at accept. Apply
        // the same canonical claim set on every node so the nonce convergence
        // below stays a real assertion rather than a trivially-zero one.
        let sender = test_addr_from_byte(0xEE);
        for node in nodes.iter_mut() {
            node.state.add_balance(&sender, 1_000_000);
        }
        let mut claims: Vec<(crate::domain::types::DomainId, u64, Address, u64)> = commitments
            .iter()
            .map(|com| {
                let (addr, nonce) = com.state_updates.iter().next().unwrap();
                (com.domain_id, com.domain_height, *addr, *nonce)
            })
            .collect();
        claims.sort_by_key(|(d, h, _, _)| (*d, *h));
        for (d, h, addr, nonce) in claims {
            for node in nodes.iter_mut() {
                let _ = apply_state_updates(node, sender, d, h, vec![(addr, nonce)]);
            }
        }
        for acc in &accounts {
            let expected_nonce = nodes[0].state.get_nonce(acc);
            for node in nodes.iter().take(node_count).skip(1) {
                assert_eq!(expected_nonce, node.state.get_nonce(acc));
            }
        }
    }

    #[tokio::test]
    async fn test_gossip_equivocation_detection_freezes_domain_globally() {
        let mut nodes = [make_node(), make_node(), make_node()];
        let domain_id = 1;
        let c1 = make_domain_commitment_at_height(&nodes[0], domain_id, 10, "state_a", 10);
        let c2 = make_domain_commitment_at_height(&nodes[0], domain_id, 10, "state_b", 11);
        let _ = nodes[0].submit_domain_commitment(c1.clone());
        let _ = nodes[1].submit_domain_commitment(c2.clone());
        for node in nodes.iter_mut() {
            let _ = node.submit_domain_commitment(c1.clone());
            let _ = node.submit_domain_commitment(c2.clone());
        }
        for node in nodes.iter() {
            let domain = node.domain_registry.get(domain_id).unwrap();
            assert_eq!(domain.status, DomainStatus::Frozen);
        }
        let c3 = make_domain_commitment_at_height(&nodes[0], domain_id, 11, "state_c", 12);
        for node in nodes.iter_mut() {
            assert!(node.submit_domain_commitment(c3.clone()).is_err());
        }
    }

    #[tokio::test]
    async fn test_out_of_order_domain_height_buffering_or_rejection() {
        let mut node = make_node();
        let alice = Address::from([0xA1u8; 32]);
        node.state.add_balance(&alice, 1000);

        let c8 = make_commitment_for_account(&node, 1, alice, 8, 8);
        let c9 = make_commitment_for_account(&node, 1, alice, 9, 9);
        let c10 = make_commitment_for_account(&node, 1, alice, 10, 10);

        let r10 = node.submit_domain_commitment(c10);
        assert!(r10.is_ok(), "height 10 should be buffered in registry");
        assert_eq!(node.state.get_nonce(&alice), 0);

        for i in 1..8 {
            let ci = make_commitment_for_account(&node, 1, alice, i, i);
            node.submit_domain_commitment(ci).unwrap();
        }
        // C3 (decision 50): buffering and acceptance move the registry, not the
        // account nonce; the nonce moves at execution.
        assert_eq!(node.state.get_nonce(&alice), 0);

        node.submit_domain_commitment(c8).unwrap();
        node.submit_domain_commitment(c9).unwrap();

        // Apply the claims in height order (the buffered height-10 claim last)
        // the way a block would: each nonce is a strict increase over the last.
        let sender = test_addr_from_byte(0xEE);
        node.state.add_balance(&sender, 1_000_000);
        for i in 1..=10 {
            apply_state_updates(&mut node, sender, 1, i, vec![(alice, i)]).unwrap();
        }
        assert_eq!(node.state.get_nonce(&alice), 10);
    }

    fn make_node() -> Blockchain {
        let consensus = Arc::new(crate::consensus::pow::PoWEngine::new(0));
        let mut node = Blockchain::new(consensus, None, 45262, None);

        for i in 1..=5 {
            let (kind, adapter) = match i {
                1 => (ConsensusKind::PoW, "pow-header-chain-v1"),
                2 => (ConsensusKind::PoS, "pos-qc-finality"),
                3 => (ConsensusKind::PoA, "poa-authority-quorum"),
                _ => (ConsensusKind::PoW, "pow-header-chain-v1"),
            };

            let domain = default_domain(i as u32, kind, 45262 + i as u64, adapter, 0);

            node.register_consensus_domain(domain).unwrap();
        }

        node
    }

    fn make_commitment_for_account(
        node: &Blockchain,
        domain_id: u32,
        account: Address,
        nonce: u64,
        sequence: u64,
    ) -> DomainCommitment {
        let domain = node.domain_registry.get(domain_id).unwrap();

        let height = nonce;
        let mut block = linked_test_block(domain_id, height);

        block.state_root = format!("state_{domain_id}_{height}").repeat(8)[0..64].to_string();

        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();

        let mut com =
            DomainCommitment::from_block(domain, &block, [0u8; 32], [0u8; 32], sequence).unwrap();

        com.state_updates.insert(account, nonce);
        com
    }

    fn make_non_conflicting_commitments(
        node: &Blockchain,
        accounts: &[Address],
        count: usize,
    ) -> Vec<DomainCommitment> {
        let mut commitments = Vec::new();

        for i in 0..count {
            let domain_id = ((i % 5) + 1) as u32;
            let account = accounts[i % accounts.len()];
            let height = (i / 5) as u64 + 1;
            let nonce = height; // Simplified: 1 commitment = 1 nonce increment

            let mut com =
                make_commitment_for_account(node, domain_id, account, height, i as u64 + 1);
            com.state_updates.insert(account, nonce);
            commitments.push(com);
        }

        commitments
    }

    fn make_domain_commitment_at_height(
        node: &Blockchain,
        domain_id: u32,
        height: u64,
        state_root: &str,
        sequence: u64,
    ) -> DomainCommitment {
        let domain = node.domain_registry.get(domain_id).unwrap();

        let mut block = linked_test_block(domain_id, height);

        block.state_root = format!("{:0<64}", state_root.repeat(16))[0..64].to_string();
        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();

        DomainCommitment::from_block(domain, &block, [0u8; 32], [0u8; 32], sequence).unwrap()
    }

    fn linked_test_block(domain_id: u32, height: u64) -> Block {
        let previous_hash = if height <= 1 {
            format!("parent_{domain_id}_0")
        } else {
            linked_test_block(domain_id, height - 1).hash
        };
        let mut block = Block::new(height, previous_hash, vec![]);
        block.timestamp = 0;
        block.state_root = format!("state_{domain_id}_{height}").repeat(8)[0..64].to_string();
        block.tx_root = block.calculate_tx_root();
        block.hash = block.calculate_hash();
        block
    }
}
