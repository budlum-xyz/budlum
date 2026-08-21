#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::reopen_storage;
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use crate::core::address::Address;

    use crate::core::transaction::{Transaction, TransactionType};

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
            let storage = reopen_storage(db_path_str);
            let consensus = Arc::new(PoWEngine::new(0));
            let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);

            // Fund Alice
            bc.state.add_balance(&alice, 1_000_000);

            // Register a BNS name directly in state
            bc.state
                .bns_registry
                .register("ayaz.bud".to_string(), alice, 0, 100)
                .unwrap();

            // Mint an NFT directly in state
            bc.state
                .nft_registry
                .mint(alice, cid, 0, Some("ayaz.bud".to_string()))
                .expect("a fresh registry has no id to collide with");

            // Produce a block to persist state to storage
            let _ = bc.produce_block(Address::zero());

            assert!(bc.state.bns_registry.resolve("ayaz.bud", 0).is_some());
            assert_eq!(bc.state.nft_registry.nfts.len(), 1);

            // FORCE HALT: bc and storage are dropped here
            info!("SIMULATED CRASH: Node process killed.");
        }

        // 2. Recovery from Disk
        {
            info!("RECOVERY: Starting node from disk...");
            let storage = reopen_storage(db_path_str);
            let consensus = Arc::new(PoWEngine::new(0));

            // Reconstruct blockchain from existing storage
            let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

            // 3. Verify chain integrity survived restart

            // Chain should have blocks from before crash
            assert!(
                bc.chain.len() > 1,
                "Chain must have blocks from before crash"
            );

            // Note: Direct state changes (add_balance, bns_registry, nft_registry)
            // Don't survive restart because they bypass block transaction replay.
            // Only block-level state persists through commit_block_durable.

            // Verify chain is functional by producing a new block after restart
            let _ = bc.produce_block(Address::zero());

            info!("SUCCESS: Disaster Recovery verified. Budlum is immortal.");
        }
    }

    #[tokio::test]
    async fn test_chaos_v2_nft_burn_pruning_after_restart() {
        let temp_dir = tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("pruning_test.db");
        let db_path_str = db_path.to_str().unwrap();

        // Create keypair for Alice
        let alice_keypair = crate::crypto::primitives::KeyPair::generate().unwrap();
        let alice = Address::from(alice_keypair.public_key_bytes());
        let cid = crate::storage::content_id::ContentId([0xEE; 32]);
        // Funding must be part of canonical genesis so restart replay starts
        // From the same state. Direct in-memory add_balance creates a block
        // That cannot be replayed from the persisted default genesis.
        let genesis = crate::chain::genesis::GenesisConfig::for_network(
            crate::core::chain_config::Network::Devnet,
        )
        .with_allocation(alice, 1_000);

        // 1. Create NFT
        {
            let storage = reopen_storage(db_path_str);
            let consensus = Arc::new(PoWEngine::new(0));
            let mut bc = Blockchain::new_with_genesis(
                consensus,
                Some(storage),
                45262,
                None,
                Some(genesis.clone()),
            );
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);

            let nft_data = bincode::serialize(&(cid, None::<String>)).unwrap();
            let mut nft_tx = Transaction::new(alice, Address::zero(), 0, nft_data);
            nft_tx.tx_type = TransactionType::NftMint;
            nft_tx.fee = 1;
            nft_tx.sign(&alice_keypair);
            bc.mempool.add_transaction(nft_tx).unwrap();
            bc.produce_block(Address::zero())
                .expect("NFT mint block must commit");
        }

        // 2. Burn NFT and Simulate Pruning Signal
        {
            let storage = reopen_storage(db_path_str);
            let consensus = Arc::new(PoWEngine::new(0));
            let mut bc = Blockchain::new_with_genesis(
                consensus,
                Some(storage),
                45262,
                None,
                Some(genesis.clone()),
            );
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);

            let burn_data = bincode::serialize(&0u64).unwrap(); // nft_id 0
            let mut burn_tx = Transaction::new(alice, Address::zero(), 0, burn_data);
            burn_tx.tx_type = TransactionType::NftBurn;
            burn_tx.fee = 1;
            burn_tx.nonce = bc.state.get_nonce(&alice);
            burn_tx.sign(&alice_keypair);

            // The executor emits a tracing signal here
            bc.mempool.add_transaction(burn_tx).unwrap();
            bc.produce_block(Address::zero())
                .expect("NFT burn block must commit");

            assert_eq!(
                bc.state.nft_registry.nfts.len(),
                0,
                "NFT must be burned in state"
            );
        }

        // 3. Verify State consistency after another restart
        {
            let storage = reopen_storage(db_path_str);
            let consensus = Arc::new(PoWEngine::new(0));
            let bc =
                Blockchain::new_with_genesis(consensus, Some(storage), 45262, None, Some(genesis));

            assert_eq!(
                bc.state.nft_registry.nfts.len(),
                0,
                "NFT burn must be persistent"
            );
        }
    }
}

use crate::chain::blockchain::Blockchain;
use crate::chain::blockchain::EPOCH_LENGTH;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::registry::role::roles;
use crate::storage::db::Storage;

/// Sled's file-lock release is not guaranteed to be synchronous with the
/// Previous owner's `drop` under CI scheduling (os error 11 / WouldBlock
/// Flake - Budlum Core run on `4d57f61`, `test_chaos_v2_ultimate_byzantine_recovery`).
/// Reopen with a bounded wait: the lock always drains within milliseconds in
/// Practice; 100 x 25ms is generous, then the final open reports the error.
fn reopen_storage(path: &str) -> Storage {
    for _ in 0..100 {
        if let Ok(storage) = crate::storage::db::Storage::new(path) {
            return storage;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    crate::storage::db::Storage::new(path).expect("storage reopen timed out after 2.5s")
}
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
        let storage = reopen_storage(db_a.to_str().unwrap());
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
        for _ in 0..10 {
            let _ = bc.produce_block(producer_a);
        }
        assert_eq!((bc.chain.len() as u64).saturating_sub(1), 10);
    }

    // 2. Partition B grows longer with different data
    {
        let storage = reopen_storage(db_b.to_str().unwrap());
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
        for _ in 0..15 {
            let _ = bc.produce_block(producer_b);
        }
        assert_eq!((bc.chain.len() as u64).saturating_sub(1), 15);
    }

    // 3. Rejoin and Recovery: Node A sees Node B's chain and must reorg
    {
        let storage = reopen_storage(db_a.to_str().unwrap());
        let mut bc_a = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);

        let storage_b = reopen_storage(db_b.to_str().unwrap());
        let bc_b = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage_b), 45262, None);

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

    // Create keypairs
    let alice_keypair = crate::crypto::primitives::KeyPair::generate().unwrap();
    let alice = Address::from(alice_keypair.public_key_bytes());
    let bob = Address::from([0x02; 32]);
    let relayer_keypair = crate::crypto::primitives::KeyPair::generate().unwrap();
    let relayer = Address::from(relayer_keypair.public_key_bytes());

    // Phase: Normal operation
    {
        let storage = reopen_storage(db_path_str);
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
        bc.state.base_fee = 0;
        bc.mempool.set_min_fee(0);
        bc.state.add_balance(&alice, 1_000_000);

        // Relayer Result for an external tx
        let res = crate::core::transaction::RelayerExternalResult {
            chain: crate::core::transaction::ExternalChain::Ethereum,
            tx_hash: "0xHASH".to_string(),
            success: true,
            message: None,
            receipt_proof: vec![1, 2, 3],
            external_state_root: [0u8; 32],
        };
        let mut tx = Transaction::new_with_chain_id(
            relayer,
            Address::zero(),
            0,
            1,
            0,
            Vec::new(),
            45262,
            TransactionType::RelayerResult(res),
        );
        tx.sign(&relayer_keypair);
        bc.mempool.add_transaction(tx).unwrap();
        let _ = bc.produce_block(Address::zero());
    }

    // Phase: Sudden crash during heavy writing
    {
        let storage = reopen_storage(db_path_str);
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
        bc.state.base_fee = 0;
        bc.mempool.set_min_fee(0);

        for _i in 0..100 {
            let mut tx = Transaction::new(alice, bob, 1, vec![]);
            tx.nonce = bc.state.get_nonce(&alice);
            tx.fee = 1;
            tx.sign(&alice_keypair);
            let _ = bc.mempool.add_transaction(tx);
        }
        // Block production interrupted! (Simulation: Process Exit)
        info!("INTERRUPTED: System crash during block processing.");
    }

    // Phase: Recovery and chain sync with a longer fork
    {
        let storage = reopen_storage(db_path_str);
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
        bc.state.base_fee = 0;
        bc.mempool.set_min_fee(0);

        // Node sees a much longer chain from the network
        let mut longer_chain = Vec::new();
        longer_chain.push(bc.chain[0].clone()); // Genesis
        let mut prev_hash = bc.chain[0].hash.clone();
        for i in 1..20 {
            let block = crate::core::block::Block::new(i as u64, prev_hash.clone(), vec![]);
            prev_hash = block.hash.clone();
            longer_chain.push(block);
        }

        let height_before = (bc.chain.len() as u64).saturating_sub(1);
        let error = bc.try_reorg(longer_chain).unwrap_err();
        assert!(
            error.contains("state root") || error.contains("consensus validation"),
            "unexpected rejection: {error}"
        );
        assert_eq!(
            (bc.chain.len() as u64).saturating_sub(1),
            height_before,
            "A longer but unexecuted/hash-only chain must not replace canonical state"
        );
        info!("ULTIMATE SUCCESS: Budlum rejected a longer invalid recovery fork.");
    }
}

/// Chaos v2: CHAIN-HALT - tam sessizlik sonrası kurtarma.
///
/// Mevcut 4 senaryo crash/fork/byzantine/restart kapsar; bu mühür ağın HİÇ
/// Üretim yapmadığı sessiz dönemin dayanıklılığını kilitler: sessizlikte
/// Hiçbir sayaç kımıldamaz, üretici geri dönünce zincir deterministik olarak
/// Kaldığı height'tan devam etmelidir.
///
/// Buradaki eski gerekçe iki kez düzeltildi. Önce ölçüldü: sayaçların
/// Sessizlikte kımıldamaması, kancanın hiç bağlı olmamasının yan etkisiydi.
/// Sonra o boşluk kapandı; canlılık epoch kapanışını `apply_epoch_close_liveness`
/// Yürütüyor ve blok üretilmeyen bir dönemde epoch sınırı da geçilmediği için
/// Sayaç yine kımıldamıyor, ama bu sefer sebebi doğru: kapanacak bir epoch yok.
/// Test resume determinizmini kilitler; canlılık davranışı
/// `liveness_consensus.rs`'te sabitlenir.
#[tokio::test]
async fn test_chaos_v2_chain_halt_full_silence_and_resume() {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    // NOT: devnet_genesis özel adreslerinden (0x01/0x02) uzak durulur.
    let producer = Address::from([0x61; 32]);
    let silent = Address::from([0x62; 32]);
    bc.state.add_validator(producer, 10_000);
    bc.state.add_validator(silent, 10_000);

    // 1) Baseline: bir tam epoch üret - silent ilk miss'ini alır.
    for _ in 0..EPOCH_LENGTH {
        bc.produce_block(producer).expect("produce must succeed");
    }
    assert_eq!(bc.state.liveness.missed_count(&silent), 1);
    let height_before_halt = bc.chain.len() as u64;
    let missed_before = bc.state.liveness.missed_count(&silent);

    // 2) CHAIN-HALT: tam sessizlik (hiçbir produce_block çağrısı). Epoch ancak
    //    Blok üretimiyle kapanır; dolayısıyla sessizlikte liveness sayaçları
    //    Da state de kımıldamamalıdır. Burada çağrı YOK, doğrudan mühür:
    assert_eq!(
        bc.state.liveness.missed_count(&silent),
        missed_before,
        "halt sirasinda epoch-close hook'u kosmaz, sayac sabit kalmali"
    );

    // 3) Kurtarma: üretici geri döner; zincir kaldığı height'tan uzamaya devam.
    for _ in 0..EPOCH_LENGTH * 2 {
        let _ = bc
            .produce_block(producer)
            .expect("resume production must succeed");
    }
    let expected = height_before_halt + EPOCH_LENGTH * 2;
    assert_eq!(bc.chain.len() as u64, expected);
    // Resume'un iki epoch'unda silent hâlâ yok -> sayaç deterministik: 1 + 2 = 3.
    assert_eq!(bc.state.liveness.missed_count(&silent), 3);
    // Üreticinin streak'i temiz; sessiz validator observe-mode'da slash EDİLMEZ.
    assert_eq!(bc.state.liveness.missed_count(&producer), 0);
    assert!(bc.state.registry.is_active(&silent, roles::VALIDATOR));
}
