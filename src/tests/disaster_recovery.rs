#[cfg(test)]
mod tests {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;
    use crate::core::transaction::{Transaction, TransactionType};
    use crate::storage::db::Storage;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tracing::info;

    #[tokio::test]
    async fn test_chaos_v2_disaster_recovery_full_state() {
        let temp_dir = tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("dr_test.db");
        let db_path_str = db_path.to_str().unwrap();

        let alice = Address::from([0xAA; 32]);
        let cid = crate::storage::content_id::ContentId([0x42; 32]);

        // 1. Initial Setup and State Creation
        {
            let storage = Storage::new(db_path_str).expect("failed to open storage");
            let consensus = Arc::new(PoWEngine::new(0));
            let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);
            bc.state.base_fee = 0;

            // Fund Alice
            bc.state.add_balance(&alice, 1_000_000);

            // Register a BNS name
            let bns_data = bincode::serialize(&("ayaz.bud".to_string(), 100u64)).unwrap();
            bns_tx.fee = 1;
            let mut bns_tx = Transaction::new(alice, Address::zero(), 10000, bns_data);
            bns_tx.tx_type = TransactionType::BnsRegister;
            bns_tx.hash = bns_tx.calculate_hash();
            bc.mempool.add_transaction(bns_tx).unwrap();

            // Mint an NFT (SocialFi)
            let nft_data = bincode::serialize(&(cid, Some("ayaz.bud".to_string()))).unwrap();
            nft_tx.fee = 1;
            let mut nft_tx = Transaction::new(alice, Address::zero(), 0, nft_data);
            nft_tx.tx_type = TransactionType::NftMint;
            nft_tx.hash = nft_tx.calculate_hash();
            bc.mempool.add_transaction(nft_tx).unwrap();

            // Produce a block to persist state
            bc.produce_block(Address::zero());

            assert!(bc.state.bns_registry.resolve("ayaz.bud", 0).is_some());
            assert_eq!(bc.state.nft_registry.nfts.len(), 1);

            // FORCE HALT: bc and storage are dropped here
            info!("SIMULATED CRASH: Node process killed.");
        }

        // 2. Recovery from Disk
        {
            info!("RECOVERY: Starting node from disk...");
            let storage = Storage::new(db_path_str).expect("failed to open storage");
            let consensus = Arc::new(PoWEngine::new(0));

            // Reconstruct blockchain from existing storage
            let bc = Blockchain::new(consensus, Some(storage), 1337, None);

            // 3. Verify Integrity of "Universal Consensus Layer"

            // Verify BNS survived
            let resolved = bc.state.bns_registry.resolve("ayaz.bud", 0);
            assert_eq!(resolved, Some(alice), "BNS record must survive crash");

            // Verify NFT survived
            assert_eq!(
                bc.state.nft_registry.nfts.len(),
                1,
                "NFT records must survive crash"
            );
            let nft = bc.state.nft_registry.get_nft(0).unwrap();
            assert_eq!(nft.content_id, cid);
            assert_eq!(nft.owner, alice);

            // Verify Balances
            let balance = bc.state.get_balance(&alice);
            assert!(balance > 0, "Alice's balance must survive crash");

            info!("SUCCESS: Disaster Recovery verified. Budlum is immortal.");
        }
    }

    #[tokio::test]
    async fn test_chaos_v2_nft_burn_pruning_after_restart() {
        let temp_dir = tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("pruning_test.db");
        let db_path_str = db_path.to_str().unwrap();

        let alice = Address::from([0xAA; 32]);
        let cid = crate::storage::content_id::ContentId([0xEE; 32]);

        // 1. Create NFT
        {
            let storage = Storage::new(db_path_str).unwrap();
            let consensus = Arc::new(PoWEngine::new(0));
            let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);
            bc.state.base_fee = 0;
            bc.state.add_balance(&alice, 1000);

            let nft_data = bincode::serialize(&(cid, None::<String>)).unwrap();
            nft_tx.fee = 1;
            let mut nft_tx = Transaction::new(alice, Address::zero(), 0, nft_data);
            nft_tx.tx_type = TransactionType::NftMint;
            nft_tx.hash = nft_tx.calculate_hash();
            bc.mempool.add_transaction(nft_tx).unwrap();
            bc.produce_block(Address::zero());
        }

        // 2. Burn NFT and Simulate Pruning Signal
        {
            let storage = Storage::new(db_path_str).unwrap();
            let consensus = Arc::new(PoWEngine::new(0));
            let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);
            bc.state.base_fee = 0;

            let burn_data = bincode::serialize(&0u64).unwrap(); // nft_id 0
            burn_tx.fee = 1;
            let mut burn_tx = Transaction::new(alice, Address::zero(), 0, burn_data);
            burn_tx.tx_type = TransactionType::NftBurn;
            burn_tx.hash = burn_tx.calculate_hash();

            // The executor emits a tracing signal here
            bc.mempool.add_transaction(burn_tx).unwrap();
            bc.produce_block(Address::zero());

            assert_eq!(
                bc.state.nft_registry.nfts.len(),
                0,
                "NFT must be burned in state"
            );
        }

        // 3. Verify State consistency after another restart
        {
            let storage = Storage::new(db_path_str).unwrap();
            let consensus = Arc::new(PoWEngine::new(0));
            let bc = Blockchain::new(consensus, Some(storage), 1337, None);

            assert_eq!(
                bc.state.nft_registry.nfts.len(),
                0,
                "NFT burn must be persistent"
            );
        }
    }
}

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::storage::db::Storage;
use std::sync::Arc;
use tempfile::tempdir;
use tracing::info;

#[tokio::test]
async fn test_chaos_v2_heavy_network_partition_with_forks() {
    let temp_dir_a = tempdir().unwrap();
    let temp_dir_b = tempdir().unwrap();
    let db_a = temp_dir_a.path().join("dr_heavy_a.db");
    let db_b = temp_dir_b.path().join("dr_heavy_b.db");

    let producer_a = Address::from([0x0A; 32]);
    let producer_b = Address::from([0x0B; 32]);

    // 1. Partition A grows
    {
        let storage = Storage::new(db_a.to_str().unwrap()).unwrap();
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
        bc.state.base_fee = 0;
        for _ in 0..10 {
            bc.produce_block(producer_a);
        }
        assert_eq!((bc.chain.len() as u64).saturating_sub(1), 10);
    }

    // 2. Partition B grows longer with different data
    {
        let storage = Storage::new(db_b.to_str().unwrap()).unwrap();
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
        bc.state.base_fee = 0;
        for _ in 0..15 {
            bc.produce_block(producer_b);
        }
        assert_eq!((bc.chain.len() as u64).saturating_sub(1), 15);
    }

    // 3. Rejoin and Recovery: Node A sees Node B's chain and must reorg
    {
        let storage = Storage::new(db_a.to_str().unwrap()).unwrap();
        let mut bc_a = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

        let storage_b = Storage::new(db_b.to_str().unwrap()).unwrap();
        let bc_b = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage_b), 1337, None);

        let reorg_result = bc_a
            .try_reorg(bc_b.chain.clone())
            .expect("Heavy reorg failed");
        assert!(reorg_result, "Reorg must happen");
        assert_eq!((bc_a.chain.len() as u64).saturating_sub(1), 15);
        assert_eq!(bc_a.last_block().hash, bc_b.last_block().hash);
    }
}

#[tokio::test]
async fn test_chaos_v2_ultimate_byzantine_recovery() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("ultimate_chaos.db");
    let db_path_str = db_path.to_str().unwrap();

    let alice = Address::from([0x01; 32]);
    let bob = Address::from([0x02; 32]);
    let relayer = Address::from([0x0A; 32]);

    // PHASE 1: Normal Operation
    {
        let storage = Storage::new(db_path_str).unwrap();
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
        bc.state.base_fee = 0;
        bc.state.add_balance(&alice, 1_000_000);
        bc.state.add_balance(&relayer, 1_000_000);

        // Relayer Result for an external tx
        let res = crate::core::transaction::RelayerExternalResult {
            chain: crate::core::transaction::ExternalChain::Ethereum,
            tx_hash: "0xHASH".to_string(),
            success: true,
            receipt_proof: vec![1, 2, 3],
        };
        let mut tx = Transaction::new_with_chain_id(
            relayer,
            Address::zero(),
            0,
            1,
            0,
            Vec::new(),
            1337,
            TransactionType::RelayerResult(res),
        );
        bc.mempool.add_transaction(tx).unwrap();
        bc.produce_block(Address::zero());
    }

    // PHASE 2: Sudden Crash during heavy writing
    {
        let storage = Storage::new(db_path_str).unwrap();
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
        bc.state.base_fee = 0;

        for _i in 0..100 {
            tx.fee = 1;
            let mut tx = Transaction::new(alice, bob, 1, vec![]);
            tx.nonce = bc.state.get_nonce(&alice);
            tx.fee = 1;
            tx.hash = tx.calculate_hash();
            let _ = bc.mempool.add_transaction(tx);
        }
        // Block production interrupted! (Simulation: Process Exit)
        info!("INTERRUPTED: System crash during block processing.");
    }

    // PHASE 3: Recovery and Chain Sync with a longer fork
    {
        let storage = Storage::new(db_path_str).unwrap();
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
        bc.state.base_fee = 0;

        // Node sees a much longer chain from the network
        let mut longer_chain = Vec::new();
        longer_chain.push(bc.chain[0].clone()); // Genesis
        let mut prev_hash = bc.chain[0].hash.clone();
        for i in 1..20 {
            let block = crate::core::block::Block::new(i as u64, prev_hash.clone(), vec![]);
            prev_hash = block.hash.clone();
            longer_chain.push(block);
        }

        let _ = bc.try_reorg(longer_chain);
        assert_eq!(
            (bc.chain.len() as u64).saturating_sub(1),
            19,
            "Must recover and follow the longest valid chain"
        );
        info!("ULTIMATE SUCCESS: Budlum recovered from partial block processing and performed deep reorg.");
    }
}
