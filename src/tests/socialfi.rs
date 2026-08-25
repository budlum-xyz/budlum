//! Regression seals for the SocialFi boost distribution (F4 - a report finding,
//! the SocialFi test seal).
//!
//! Constitution section 3: 4 percent of the boost goes to the B.U.D. operators,
//! 16 percent to the creator and 80 percent to the protocol. The current
//! combined semantics (5322e00 plus 7f054d7): the executor accumulates
//! bud_share in `pending_bud_boost_share`; after the block commit
//! `distribute_bud_boost_share` distributes it by the fee_per_byte_epoch weight
//! of the active deals (the rounding dust goes to the operator of the first
//! deal), and with no active deal it is an honest burn. These tests seal the
//! weighted distribution, the dust determinism, the pending
//! Drain'i ve burn fallback'ini kilitler.
//!
//! NOTE: chain-level mempool transaction validation requires a signature
//! (`Transaction::verify` - an unsigned transaction silently stays out of the
//! block). So the actors sign with a real `KeyPair`, the nonce is read from the
//! chain through `bc.get_nonce`, and the nft_id is read from the registry, with
//! no assumption about an id counter.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;
use crate::domain::storage_deal::{StorageEconomicsParams, FEE_RATE_SCALE};
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
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);
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

fn deal_econ(fee_per_byte_epoch: u64) -> StorageEconomicsParams {
    StorageEconomicsParams {
        operator_bond: 5_000_000,
        fee_per_byte_epoch,
    }
}

/// A format-valid test envelope, with an honest marker - it is NOT a real STARK
/// proof, but exactly the same minimal ProofEnvelope as the test helper in
/// storage_deal.rs.
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
    bc.state
        .storage_registry
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

/// Submits a signed transaction and produces a single block.
fn submit_tx(bc: &mut Blockchain, mut tx: Transaction, kp: &KeyPair) {
    tx.sign(kp);
    bc.mempool.add_transaction(tx).unwrap();
    let _ = bc.produce_block(Address::zero());
}

fn mint_nft(bc: &mut Blockchain, kp: &KeyPair, cid: ContentId) {
    let from = Address::from(kp.public_key_bytes());
    let data = bincode::serialize(&(cid, None::<String>)).unwrap();
    let mut tx = Transaction::new_with_fee(from, Address::zero(), 0, 1, bc.get_nonce(&from), data);
    tx.tx_type = TransactionType::NftMint;
    submit_tx(bc, tx, kp);
}

fn boost_nft(bc: &mut Blockchain, kp: &KeyPair, nft_id: u64, amount: u64) {
    let from = Address::from(kp.public_key_bytes());
    let mut tx =
        Transaction::new_with_fee(from, Address::zero(), 0, 1, bc.get_nonce(&from), Vec::new());
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
    // NOT: devnet_genesis'te [0x01;32] 1e9 alokasyonlu, [0x02;32] validator'dur
    // (genesis.rs:284). Chain tests have to stay away from these special addresses.
    let op1 = Address::from([0x51; 32]);
    let op2 = Address::from([0x52; 32]);
    bc.state.add_balance(&alice, 1000);
    bc.state.add_balance(&bob, 1_000_000);

    // The active deals: the weight is now `total_fee(1)`, the cost of one epoch,
    // and that cost depends on the shard size. The shard is 4 bytes and the scale
    // is 1e9, so for a weight of 100 the rate has to be 100 * 1e9 / 4 = 25e9. We
    // derive the rates from that so what the test measures stays the 100/300
    // share.
    let manifest = ContentManifest::from_bytes_sliced(b"boost pool content", 4).unwrap();
    let shard_bytes = u64::from(manifest.shards[0].size);
    let rate_for = |weight: u64| weight * (FEE_RATE_SCALE as u64) / shard_bytes;
    open_weighted_deal(&mut bc, &manifest, op1, 0, rate_for(100));
    open_weighted_deal(&mut bc, &manifest, op2, 1, rate_for(300));

    mint_nft(&mut bc, &alice_kp, ContentId([0x77; 32]));
    assert_eq!(bc.state.get_balance(&alice), 999);

    // The NFT id is read from the registry, with no assumption about an id counter.
    let nft_id = *bc.state.nft_registry.nfts.keys().next().unwrap();

    // The distribution is locked as a delta, so it holds even if the genesis
    // allocation changes.
    let op1_pre = bc.state.get_balance(&op1);
    let op2_pre = bc.state.get_balance(&op2);
    boost_nft(&mut bc, &bob_kp, nft_id, BOOST_AMOUNT);

    // bud_share = 10: op1 = 10*100/400 = 2, op2 = 10*300/400 = 7, so 9 are
    // distributed. The dust of 1 goes to the operator of the first deal (the
    // deal_id order is deterministic), giving op1 = 3.
    assert_eq!(bc.state.get_balance(&op1), op1_pre + 3);
    assert_eq!(bc.state.get_balance(&op2), op2_pre + 7);
    // %16 creator
    assert_eq!(bc.state.get_balance(&alice), 999 + 40);
    // Booster: 1_000_000 - 250 (boost) - 1 (fee)
    assert_eq!(bc.state.get_balance(&bob), 999_749);
    // The pool is drained at the end of the block, so no debt carries into the
    // next one.
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

    // With no active deal the creator still takes its 16 percent, and the 4 plus
    // 80 percent are an honest burn: no operator account may be created and the
    // pool still has to be drained.
    assert_eq!(bc.state.get_balance(&alice), 999 + 40);
    assert_eq!(bc.state.get_balance(&bob), 999_749);
    assert_eq!(bc.state.get_balance(&ghost), 0);
    assert_eq!(bc.state.pending_bud_boost_share, 0);
}
