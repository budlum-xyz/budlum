//! The aggregation layer over the real network: four aggregators and one
//! producer, each a chain actor and a libp2p node on localhost. Signed
//! quantum-safe transactions are handed to the aggregators the way the RPC
//! hands them over, travel as objects on `agg/object`, are proven, travel
//! as frames on `agg/frame`, and the producer carries them in blocks that
//! every node accepts.
//!
//! The backend is the native one, whose proof is the objects themselves:
//! a block holds what 262144 proof bytes hold, 36 signatures. The block of
//! a thousand claims of the directive needs the STARK backend (phase 3).

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod aggregation_network_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::time::sleep;

    use crate::aggregation::params::{AggMode, AggParams};
    use crate::chain::blockchain::Blockchain;
    use crate::chain::chain_actor::{ChainActor, ChainHandle};
    use crate::chain::genesis::GenesisConfig;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::core::transaction::Transaction;
    use crate::crypto::primitives::WalletKeyPair;
    use crate::network::node::{Node, NodeClient};
    use crate::network::protocol::{NetworkMessage, TOPIC_AGG_FRAME};

    const CHAIN: u64 = 45262;
    const FEE: u64 = 100_000;
    const AMOUNT: u64 = 10;
    /// Fee of one signature claim under the default parameters.
    const SIG_CLAIM_FEE: u64 = 4288;
    const AGGREGATORS: usize = 4;
    const PER_AGGREGATOR: usize = 4;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind an ephemeral port")
            .local_addr()
            .expect("local address")
            .port()
    }

    fn recipient() -> Address {
        Address::from([0x44; 32])
    }

    struct Peer {
        client: NodeClient,
        chain: ChainHandle,
        address: Address,
        port: u16,
        peer_id: String,
        tasks: [tokio::task::JoinHandle<()>; 2],
    }

    impl Peer {
        /// A node of the chain `genesis` that runs its aggregation side for
        /// `address` and dials `bootstrap`.
        async fn start(genesis: GenesisConfig, address: Address, bootstrap: Vec<String>) -> Self {
            let blockchain = Blockchain::new_with_genesis(
                Arc::new(PoWEngine::new(0)),
                None,
                CHAIN,
                None,
                Some(genesis),
            );
            let (actor, chain) = ChainActor::new(blockchain);
            let actor_task = tokio::spawn(async move {
                actor.run().await;
            });
            assert!(
                chain.enable_aggregator(address).await.is_some(),
                "the layer is on"
            );
            let mut node = Node::new(chain.clone()).expect("node");
            node.bootstrap_peers = bootstrap;
            let port = free_port();
            let _ = node.listen(port);
            let client = node.get_client();
            let peer_id = node.peer_id.to_string();
            let node_task = tokio::spawn(async move {
                node.run().await;
            });
            client.subscribe("blocks".to_string()).await;
            client.subscribe("transactions".to_string()).await;
            client.enable_aggregation().await;
            sleep(Duration::from_millis(500)).await;
            Self {
                client,
                chain,
                address,
                port,
                peer_id,
                tasks: [actor_task, node_task],
            }
        }

        fn multiaddr(&self) -> String {
            format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", self.port, self.peer_id)
        }

        /// One tick of the aggregator, published the way the node does it.
        async fn tick(&self) {
            for frame in self.chain.aggregation_tick().await {
                self.client
                    .broadcast(TOPIC_AGG_FRAME.to_string(), NetworkMessage::AggFrame(frame))
                    .await;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn four_aggregators_and_a_producer_carry_claimed_transactions_over_gossip() {
        let wallets: Vec<WalletKeyPair> = (0..AGGREGATORS * PER_AGGREGATOR)
            .map(|n| WalletKeyPair::from_seed(&[u8::try_from(n + 1).expect("small"); 32]))
            .collect();
        let mut genesis = GenesisConfig::new(CHAIN);
        for wallet in &wallets {
            genesis = genesis.with_allocation(wallet.address(), 10_000_000);
        }
        genesis.aggregation = Some(AggParams {
            mode: AggMode::On,
            ..AggParams::default()
        });

        let producer = Peer::start(genesis.clone(), Address::from([0xB7; 32]), Vec::new()).await;
        let mut aggregators = Vec::new();
        for n in 0..AGGREGATORS {
            let address = Address::from([0xA0 + u8::try_from(n).expect("small"); 32]);
            let peer = Peer::start(genesis.clone(), address, vec![producer.multiaddr()]).await;
            aggregators.push(peer);
        }
        // Handshakes and the gossip meshes of the two topics.
        sleep(Duration::from_secs(6)).await;

        // Every aggregator is handed its transactions the way the RPC hands
        // them over: into the chain, then to the network.
        for (n, wallet) in wallets.iter().enumerate() {
            let mut tx =
                Transaction::new_with_fee(wallet.address(), recipient(), AMOUNT, FEE, 0, vec![]);
            tx.chain_id = CHAIN;
            tx.sign_v5(wallet);
            let peer = &aggregators[n % AGGREGATORS];
            peer.chain
                .add_transaction(tx.clone())
                .await
                .expect("admitted");
            peer.client.broadcast_tx_sync(tx);
        }

        // Rounds: the aggregators tick and publish, the producer builds a
        // block and every node takes it.
        let total = wallets.len();
        let mut carried = 0usize;
        let mut segments_seen = std::collections::BTreeSet::new();
        let mut largest = 0usize;
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while carried < total && std::time::Instant::now() < deadline {
            sleep(Duration::from_millis(1500)).await;
            for peer in &aggregators {
                peer.tick().await;
            }
            sleep(Duration::from_millis(1500)).await;
            let Some((block, _)) = producer.chain.produce_block(producer.address).await else {
                continue;
            };
            if let Some(frame) = block.claim_frame.as_ref() {
                assert_eq!(frame.claims.len(), block.transactions.len());
                for tx in &block.transactions {
                    // No signature bytes are in the block.
                    assert!(tx.signature.is_none() && tx.signer_public_key.is_empty());
                    assert!(tx.auth_claim.is_some());
                }
                carried += frame.claims.len();
                largest = largest.max(frame.claims.len());
                segments_seen.extend(frame.segments.iter().map(|segment| segment.aggregator));
            }
            for peer in &aggregators {
                if let Err(error) = peer.chain.validate_and_add_block(block.clone()).await {
                    // The node may have pulled the block over `/sync`
                    // before it was handed over here.
                    let held = peer.chain.get_block(block.index).await;
                    assert_eq!(
                        held.map(|held| held.hash),
                        Some(block.hash.clone()),
                        "a node refused the block: {error}"
                    );
                }
            }
        }

        assert_eq!(
            carried, total,
            "every transaction reached a block through the two topics"
        );
        // The producer never ticked: it got every transaction from
        // `agg/object` and every frame from `agg/frame`, and each segment it
        // carried belongs to one of the aggregators. Which of them proved an
        // object first is a race, so the shares are not fixed.
        let known: std::collections::BTreeSet<Address> =
            aggregators.iter().map(|peer| peer.address).collect();
        assert!(!segments_seen.is_empty() && segments_seen.is_subset(&known));
        // A frame over more objects than one aggregator was handed: objects
        // or frames of the others reached the one that built it.
        assert!(
            largest > PER_AGGREGATOR,
            "largest block frame: {largest} claims"
        );

        // Every node ends on the same tip: same block, same state root.
        let height = producer.chain.get_height().await;
        let tip = producer
            .chain
            .get_block(height)
            .await
            .map(|block| (block.hash, block.state_root));
        assert!(tip.is_some());
        let mut paid = 0u64;
        for peer in &aggregators {
            assert_eq!(peer.chain.get_height().await, height);
            let theirs = peer
                .chain
                .get_block(height)
                .await
                .map(|block| (block.hash, block.state_root));
            assert_eq!(theirs, tip);
            paid += producer.chain.get_balance(&peer.address).await;
        }
        // Every claim paid the aggregator share once, to whoever proved it.
        let claims = u64::try_from(total).expect("small");
        assert_eq!(paid, claims * (SIG_CLAIM_FEE / 2));
        let sent = claims * AMOUNT;
        assert_eq!(producer.chain.get_balance(&recipient()).await, sent);

        for peer in aggregators.into_iter().chain([producer]) {
            for task in peer.tasks {
                task.abort();
            }
        }
    }
}
