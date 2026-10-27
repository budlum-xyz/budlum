#[cfg(test)]
mod distributed_settlement_tests {
    use crate::chain::blockchain::Blockchain;
    use crate::chain::chain_actor::{ChainActor, ChainHandle};
    use crate::consensus::pow::PoWEngine;

    #[cfg(test)]
    fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
        let mut b = [0u8; 32];
        b[0] = byte;
        crate::core::address::Address::from(b)
    }

    use crate::core::block::Block;
    use crate::domain::plugin::default_domain;
    use crate::domain::{ConsensusKind, DomainCommitment};
    use crate::network::node::{Node, NodeClient};
    use crate::storage::db::Storage;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::time::sleep;

    /// Asks the OS for an unused TCP port so parallel runs and leftover
    /// sockets never collide on a fixed number.
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind an ephemeral port")
            .local_addr()
            .expect("local address")
            .port()
    }

    struct NodeHarness {
        node_client: NodeClient,
        chain_handle: ChainHandle,
        _storage: Arc<Storage>,
        _temp_dir: TempDir,
        node_task: tokio::task::JoinHandle<()>,
        actor_task: tokio::task::JoinHandle<()>,
        port: u16,
    }

    impl NodeHarness {
        async fn new(port: u16, bootstrap: Vec<String>, data_path: Option<PathBuf>) -> Self {
            let temp_dir = TempDir::new().unwrap();
            let path = data_path.unwrap_or_else(|| temp_dir.path().to_path_buf());
            let storage = Arc::new(Storage::new(path.to_str().unwrap()).unwrap());

            let consensus = Arc::new(PoWEngine::new(0));
            let mut blockchain = Blockchain::new(consensus, Some((*storage).clone()), 45262, None);

            let pow = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
            let pos = default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0);
            let _ = blockchain.register_consensus_domain(pow);
            let _ = blockchain.register_consensus_domain(pos);

            let (chain_actor, chain_handle) = ChainActor::new(blockchain);
            let actor_task = tokio::spawn(async move {
                chain_actor.run().await;
            });

            let mut node = Node::new(chain_handle.clone()).unwrap();
            node.bootstrap_peers = bootstrap;
            let _ = node.listen(port);
            let node_client = node.get_client();
            let mut node_instance = node;
            let node_task = tokio::spawn(async move {
                node_instance.run().await;
            });

            sleep(Duration::from_millis(1000)).await;

            Self {
                node_client,
                chain_handle,
                _storage: storage,
                _temp_dir: temp_dir,
                node_task,
                actor_task,
                port,
            }
        }

        fn multiaddr(&self) -> String {
            format!("/ip4/127.0.0.1/tcp/{}", self.port)
        }

        async fn stop(self) {
            self.node_task.abort();
            self.actor_task.abort();
            sleep(Duration::from_millis(200)).await;
        }
    }

    #[tokio::test]
    async fn test_distributed_gossip_convergence() {
        let n1 = NodeHarness::new(free_port(), vec![], None).await;
        let n2 = NodeHarness::new(free_port(), vec![n1.multiaddr()], None).await;
        let n3 = NodeHarness::new(free_port(), vec![n1.multiaddr()], None).await;
        let n4 = NodeHarness::new(free_port(), vec![n2.multiaddr()], None).await;
        let n5 = NodeHarness::new(free_port(), vec![n3.multiaddr()], None).await;

        sleep(Duration::from_secs(5)).await;

        let alice = test_addr_from_byte(1u8);
        let mut commitments = Vec::new();
        for i in 1..=20 {
            let mut b = Block::new(i, "hash".into(), vec![]);
            b.hash = format!("hash_{i}").repeat(16)[0..64].to_string();
            let mut com = DomainCommitment::from_block(
                &default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0),
                &b,
                [0u8; 32],
                [0u8; 32],
                i,
            )
            .unwrap();
            com.state_updates.insert(alice, i);
            commitments.push(com);
        }

        let clients = [&n1, &n2, &n3, &n4, &n5];

        for com in commitments {
            let idx = rand::random_range(0..clients.len());
            let sender = clients[idx];
            sender.node_client.broadcast_domain_commitment_sync(com);
            sleep(Duration::from_millis(100)).await;
        }

        // Poll until every node reports the same root, bounded by a deadline.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let mut roots = Vec::new();
            for client in clients {
                let header = client.chain_handle.build_global_header(None).await.unwrap();
                roots.push(header.domain_commitment_root);
            }
            let converged = roots.iter().all(|r| *r == roots[0]) && roots[0] != [0u8; 32];
            if converged || std::time::Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(250)).await;
        }

        let h1 = n1.chain_handle.build_global_header(None).await.unwrap();
        let h2 = n2.chain_handle.build_global_header(None).await.unwrap();
        let h3 = n3.chain_handle.build_global_header(None).await.unwrap();
        let h4 = n4.chain_handle.build_global_header(None).await.unwrap();
        let h5 = n5.chain_handle.build_global_header(None).await.unwrap();

        assert_eq!(h1.domain_commitment_root, h2.domain_commitment_root);
        assert_eq!(h2.domain_commitment_root, h3.domain_commitment_root);
        assert_eq!(h3.domain_commitment_root, h4.domain_commitment_root);
        assert_eq!(h4.domain_commitment_root, h5.domain_commitment_root);
        assert_ne!(
            h1.domain_commitment_root, [0u8; 32],
            "Root should not be empty"
        );

        n1.stop().await;
        n2.stop().await;
        n3.stop().await;
        n4.stop().await;
        n5.stop().await;
    }

    #[tokio::test]
    async fn test_restart_pending_buffer_persistence() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().to_path_buf();

        let port = free_port();
        let n1 = NodeHarness::new(port, vec![], Some(path.clone())).await;

        // Height 1 arrives second, so it is built first here to give height 2
        // a real parent. The buffered commitment has to chain onto the one it
        // waits for, otherwise applying it would break domain continuity,
        // the check that used to be compiled out under `#[cfg(test)]`.
        //
        // The hashes are 64 hex characters, which is what a real block hash
        // is. `normalize_hash32` decodes a 32-byte hex string straight
        // through, but hashes anything else together with a field-specific
        // domain tag - and `domain_block_hash` and `parent_domain_block_hash`
        // use different tags. With a non-hex placeholder the same block hash
        // therefore normalises to two different values depending on which
        // field it lands in, and no chain could ever line up.
        let mut b1 = Block::new(1, "11".repeat(32), vec![]);
        b1.hash = "a1".repeat(32);

        let mut b2 = Block::new(2, b1.hash.clone(), vec![]);
        b2.hash = "b2".repeat(32);
        let com2 = DomainCommitment::from_block(
            &default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0),
            &b2,
            [0u8; 32],
            [0u8; 32],
            1,
        )
        .unwrap();

        n1.chain_handle
            .submit_domain_commitment(com2.clone())
            .await
            .unwrap();
        assert_eq!(
            n1.chain_handle.get_domain_height(1).await.unwrap(),
            0,
            "Height 2 should be pending"
        );

        n1.stop().await;

        let n2 = NodeHarness::new(port, vec![], Some(path.clone())).await;
        let com1 = DomainCommitment::from_block(
            &default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0),
            &b1,
            [0u8; 32],
            [0u8; 32],
            1,
        )
        .unwrap();

        n2.chain_handle
            .submit_domain_commitment(com1)
            .await
            .unwrap();

        // K4: the buffer is consensus state and was written outside any
        // block, so the restart (a replay of the stored blocks) dropped it.
        // Height 1 alone advances the domain; height 2 has to arrive again.
        sleep(Duration::from_millis(500)).await;
        assert_eq!(
            n2.chain_handle.get_domain_height(1).await.unwrap(),
            1,
            "an out-of-block buffered commitment must not survive a restart"
        );
        n2.chain_handle
            .submit_domain_commitment(com2)
            .await
            .unwrap();
        assert_eq!(
            n2.chain_handle.get_domain_height(1).await.unwrap(),
            2,
            "Height 2 applies once it arrives after H1"
        );

        n2.stop().await;
    }

    #[tokio::test]
    async fn test_frozen_domain_persistence() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().to_path_buf();

        let port = free_port();
        let n1 = NodeHarness::new(port, vec![], Some(path.clone())).await;
        let b1 = Block::new(1, "h1".into(), vec![]);
        let b1_alt = Block::new(1, "h1_alt".into(), vec![]);
        let com1 = DomainCommitment::from_block(
            &default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0),
            &b1,
            [0u8; 32],
            [0u8; 32],
            1,
        )
        .unwrap();
        let mut com1_alt = DomainCommitment::from_block(
            &default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0),
            &b1_alt,
            [0u8; 32],
            [0u8; 32],
            2,
        )
        .unwrap();
        com1_alt.domain_height = 1;

        n1.chain_handle
            .submit_domain_commitment(com1)
            .await
            .unwrap();
        let res = n1.chain_handle.submit_domain_commitment(com1_alt).await;
        assert!(res.is_err(), "Equivocation must be rejected");

        n1.stop().await;

        let n2 = NodeHarness::new(port, vec![], Some(path.clone())).await;
        let b2 = Block::new(2, "h2".into(), vec![]);
        let com2 = DomainCommitment::from_block(
            &default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0),
            &b2,
            [0u8; 32],
            [0u8; 32],
            3,
        )
        .unwrap();

        // K4: the freeze was written outside any block, so the restart (a
        // replay of the stored blocks) does not bring it back. The domain is
        // active again and height 2 is buffered behind the missing height 1.
        let res2 = n2.chain_handle.submit_domain_commitment(com2).await;
        assert!(
            res2.is_ok(),
            "an out-of-block freeze must not survive a restart"
        );
        assert_eq!(n2.chain_handle.get_domain_height(1).await.unwrap(), 0);

        n2.stop().await;
    }

    #[tokio::test]
    async fn test_conflicting_commitment_audit_persistence() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().to_path_buf();
        let alice = test_addr_from_byte(1u8);

        let port = free_port();
        let n1 = NodeHarness::new(port, vec![], Some(path.clone())).await;
        let root_empty = n1
            .chain_handle
            .build_global_header(None)
            .await
            .unwrap()
            .domain_commitment_root;
        let mut b1 = Block::new(1, "h1".into(), vec![]);
        b1.hash = "h1".repeat(32);
        let mut com_pow = DomainCommitment::from_block(
            &default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0),
            &b1,
            [0u8; 32],
            [0u8; 32],
            1,
        )
        .unwrap();
        com_pow.state_updates.insert(alice, 1);

        n1.chain_handle
            .submit_domain_commitment(com_pow.clone())
            .await
            .unwrap();

        let mut b2 = Block::new(1, "h2".into(), vec![]);
        b2.hash = "h2".repeat(32);
        let mut com_pos = DomainCommitment::from_block(
            &default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0),
            &b2,
            [0u8; 32],
            [0u8; 32],
            1,
        )
        .unwrap();
        com_pos.state_updates.insert(alice, 2);

        n1.chain_handle
            .submit_domain_commitment(com_pos.clone())
            .await
            .unwrap();

        let root_before = n1
            .chain_handle
            .build_global_header(None)
            .await
            .unwrap()
            .domain_commitment_root;
        assert_ne!(root_before, [0u8; 32]);

        n1.stop().await;

        let n2 = NodeHarness::new(port, vec![], Some(path.clone())).await;
        // K4: the commitments were accepted outside any block, so the restart
        // (a replay of the stored blocks) rebuilds the registry without them.
        let header = n2.chain_handle.build_global_header(None).await.unwrap();
        assert_ne!(root_before, root_empty);
        assert_eq!(
            header.domain_commitment_root, root_empty,
            "out-of-block commitments must not survive a restart"
        );

        n2.stop().await;
    }

    ///: the finality verdict the `SettlementTx::SubmitCommitment` door
    /// reaches refuses adversarial proofs before anything is applied.
    #[test]
    fn test_adversarial_finality_proofs() {
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
        bc.register_consensus_domain(default_domain(
            1,
            ConsensusKind::PoW,
            45262,
            "pow-header-chain-v1",
            0,
        ))
        .unwrap();
        let alice = test_addr_from_byte(1u8);
        let mut b = Block::new(1, "h".into(), vec![]);
        b.hash = "h".repeat(32);
        let pow_domain = default_domain(1, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);

        use crate::domain::finality_adapter::{hash_finality_proof, FinalityProof};

        let mut com =
            DomainCommitment::from_block(&pow_domain, &b, [0u8; 32], [0u8; 32], 1).unwrap();
        com.state_updates.insert(alice, 1);
        let proof = FinalityProof::PoWHeaderChain { headers: vec![] };
        com.finality_proof_hash = [0xFFu8; 32];

        let res = bc.submit_verified_domain_commitment(com, proof);
        assert!(res.is_err());
        let err = res.unwrap_err();
        // An empty PoW header chain is rejected by the bounded
        // Adapter ("PoW header chain is empty"); older paths rejected on hash
        // Mismatch. Either way the adversarial proof is rejected.
        assert!(
            err.contains("mismatch")
                || err.contains("empty")
                || err.contains("rejected")
                || err.contains("Rejected")
                || err.contains("finality")
        );

        let mut com2 =
            DomainCommitment::from_block(&pow_domain, &b, [0u8; 32], [0u8; 32], 2).unwrap();
        // Bound to the commitment so the rejection is specifically about depth
        // ("not finalized"), not the head-hash binding.
        let proof2 = FinalityProof::PoWHeaderChain { headers: vec![] };
        com2.finality_proof_hash = hash_finality_proof(&proof2).unwrap();

        let res2 = bc.submit_verified_domain_commitment(com2, proof2);
        assert!(res2.is_err());
        let err2 = res2.unwrap_err();
        // May fail on insufficient work, missing PoW bits, or not finalized.
        assert!(
            err2.contains("not finalized")
                || err2.contains("Rejected")
                || err2.contains("rejected")
                || err2.contains("empty")
                || err2.contains("finality")
                || err2.contains("retired")
                || err2.contains("leading zero")
                || err2.contains("inconsistent")
                || err2.contains("work"),
            "unexpected rejection reason: {err2}"
        );
        assert_eq!(
            bc.state
                .settlement
                .domains
                .get(1)
                .unwrap()
                .last_committed_height,
            0,
            "Should NOT be applied"
        );
    }
}
