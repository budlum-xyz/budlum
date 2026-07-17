//! SocialFi boost dağılımı regresyon mühürleri (F4 — ARENAX raporu bulgusu,
//! ARENA3 test mühürü, 2026-07-17).
//!
//! Constitution §3: boost %4 B.U.D. operatörlerine, %16 creator'a, %80
//! protocol'e. Mevcut birleşik semantik (5322e00 + 7f054d7): executor
//! bud_share'i `pending_bud_boost_share`'de biriktirir; blok commit sonrası
//! `distribute_bud_boost_share` bunu aktif deal'lerin fee_per_epoch ağırlığına
//! göre dağıtır (yuvarlama tozu ilk deal'in operatörüne), aktif deal yoksa
//! dürüst burn. Bu testler ağırlıklı dağıtımı, dust determinizmini, pending
//! drain'i ve burn fallback'ini kilitler.
//!
//! NOT (ARENA3, CI kanıtlı): mempool zincir-seviyesi tx doğrulaması imza ister
//! (`Transaction::verify` — imzasız tx sessizce blok dışı kalır). Bu yüzden
//! aktörler gerçek `KeyPair` ile imzalar; nonce `bc.get_nonce` ile zincirden
//! okunur, nft_id registry'den okunur (id sayacı varsayımı yoktur).

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;
use crate::domain::storage_deal::StorageEconomicsParams;
use crate::domain::storage_params::StorageDomainParams;
use crate::storage::content_id::ContentId;
use crate::storage::db::Storage;
use crate::storage::manifest::ContentManifest;
use std::sync::Arc;
use tempfile::tempdir;

const BOOST_AMOUNT: u64 = 250; // bud_share = 10, creator_share = 40, protocol = 200

fn fresh_chain(db_path: &str) -> Blockchain {
    let storage = Storage::new(db_path).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);
    bc.state.base_fee = 0;
    bc.mempool.set_min_fee(0);
    bc
}

fn domain_params() -> StorageDomainParams {
    StorageDomainParams {
        chunk_size: 256,
        max_committed_chunks: 1000,
        challenge_interval: 10,
        min_operator_bond: 1_000_000,
    }
}

fn deal_econ(fee_per_epoch: u64) -> StorageEconomicsParams {
    StorageEconomicsParams {
        operator_bond: 5_000_000,
        fee_per_epoch,
    }
}

/// Format-geçerli test zarfı (dürüst marker — GERÇEK STARK kanıtı değil;
/// storage_deal.rs test helper'ıyla birebir aynı minimal ProofEnvelope).
fn valid_merkle_proof() -> Vec<u8> {
    let envelope = bud_proof::ProofEnvelope {
        proof_format_version: 1,
        backend: "test-backend".to_string(),
        p3_version: "0.6".to_string(),
        fri_params_id: "test-fri".to_string(),
        public_inputs_hash: [0x42u8; 32],
        proof_bytes: vec![0xABu8; 96],
        degree_bits: 8,
    };
    bincode::serialize(&envelope).expect("test envelope serialize")
}

fn open_weighted_deal(
    bc: &mut Blockchain,
    m: &ContentManifest,
    op: Address,
    replica: u8,
    fee: u64,
) {
    let shard_id = m.shards[0].shard_id;
    bc.storage_registry
        .open_deal(
            42,
            m,
            shard_id,
            op,
            replica,
            100,
            200,
            deal_econ(fee),
            &domain_params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
}

/// İmzalı tx gönderir ve tek blok üretir.
fn submit_tx(bc: &mut Blockchain, mut tx: Transaction, kp: &KeyPair) {
    tx.sign(kp);
    bc.mempool.add_transaction(tx).unwrap();
    bc.produce_block(Address::zero());
}

fn mint_nft(bc: &mut Blockchain, kp: &KeyPair, cid: ContentId) {
    let from = Address::from(kp.public_key_bytes());
    let data = bincode::serialize(&(cid, None::<String>)).unwrap();
    let mut tx = Transaction::new_with_fee(
        from,
        Address::zero(),
        0,
        1,
        bc.get_nonce(&from),
        data,
    );
    tx.tx_type = TransactionType::NftMint;
    submit_tx(bc, tx, kp);
}

fn boost_nft(bc: &mut Blockchain, kp: &KeyPair, nft_id: u64, amount: u64) {
    let from = Address::from(kp.public_key_bytes());
    let mut tx = Transaction::new_with_fee(
        from,
        Address::zero(),
        0,
        1,
        bc.get_nonce(&from),
        Vec::new(),
    );
    tx.tx_type = TransactionType::NftBoost { nft_id, amount };
    submit_tx(bc, tx, kp);
}

#[tokio::test]
async fn boost_share_distributes_by_deal_fee_weight_with_dust_to_first() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("boost_weighted.db");
    let mut bc = fresh_chain(db.to_str().unwrap());

    let alice_kp = KeyPair::generate().unwrap();
    let bob_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = Address::from(bob_kp.public_key_bytes());
    let op1 = Address::from([0x01; 32]);
    let op2 = Address::from([0x02; 32]);
    bc.state.add_balance(&alice, 1000);
    bc.state.add_balance(&bob, 1_000_000);

    // Aktif deal'ler: op1 fee=100, op2 fee=300 (toplam ağırlık 400).
    let manifest = ContentManifest::from_bytes_sliced(b"boost pool content", 4).unwrap();
    open_weighted_deal(&mut bc, &manifest, op1, 0, 100);
    open_weighted_deal(&mut bc, &manifest, op2, 1, 300);

    mint_nft(&mut bc, &alice_kp, ContentId([0x77; 32]));
    assert_eq!(bc.state.get_balance(&alice), 999);

    // NFT id'si registry'den okunur (id sayacı varsayımı yok).
    let nft_id = *bc.state.nft_registry.nfts.keys().next().unwrap();
    boost_nft(&mut bc, &bob_kp, nft_id, BOOST_AMOUNT);

    // bud_share = 10: op1 = 10*100/400 = 2, op2 = 10*300/400 = 7, dağıtılan 9.
    // dust 1 ilk deal'in operatörüne (deal_id sırası deterministik) -> op1 = 3.
    assert_eq!(bc.state.get_balance(&op1), 3);
    assert_eq!(bc.state.get_balance(&op2), 7);
    // %16 creator
    assert_eq!(bc.state.get_balance(&alice), 999 + 40);
    // booster: 1_000_000 - 250 (boost) - 1 (fee)
    assert_eq!(bc.state.get_balance(&bob), 999_749);
    // Havuz blok sonunda boşaltıldı (drain) — sonraki bloğa borç kalmaz.
    assert_eq!(bc.state.pending_bud_boost_share, 0);
}

#[tokio::test]
async fn boost_without_active_deals_burns_share_and_drains_pool() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("boost_burn.db");
    let mut bc = fresh_chain(db.to_str().unwrap());

    let alice_kp = KeyPair::generate().unwrap();
    let bob_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = Address::from(bob_kp.public_key_bytes());
    let ghost = Address::from([0x09; 32]);
    bc.state.add_balance(&alice, 1000);
    bc.state.add_balance(&bob, 1_000_000);

    mint_nft(&mut bc, &alice_kp, ContentId([0x79; 32]));
    let nft_id = *bc.state.nft_registry.nfts.keys().next().unwrap();
    boost_nft(&mut bc, &bob_kp, nft_id, BOOST_AMOUNT);

    // Aktif deal yok: creator %16'sını yine alır, %4 + %80 dürüst burn —
    // hiçbir operatör hesabı oluşmamalı ve havuz yine drain edilmeli.
    assert_eq!(bc.state.get_balance(&alice), 999 + 40);
    assert_eq!(bc.state.get_balance(&bob), 999_749);
    assert_eq!(bc.state.get_balance(&ghost), 0);
    assert_eq!(bc.state.pending_bud_boost_share, 0);
}
