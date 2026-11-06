//! SocialFi registry regression seals (mint and tag behaviour).
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
use crate::storage::bud3::content_id::ContentId;
use crate::persistence::db::Storage;
use std::sync::Arc;
use tempfile::tempdir;

fn fresh_chain(db_path: &str) -> Blockchain {
    let storage = Storage::new(db_path).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);
    bc.state.base_fee = 0;
    bc.mempool.set_min_fee(0);
    bc
}

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

fn mint_nft(bc: &mut Blockchain, kp: &KeyPair, cid: ContentId) {
    let from = Address::from(kp.public_key_bytes());
    let data = bincode::serialize(&(cid, None::<String>)).unwrap();
    let mut tx = Transaction::new_with_fee(from, Address::zero(), 0, 1, bc.get_nonce(&from), data);
    tx.tx_type = TransactionType::NftMint;
    submit_tx(bc, tx, kp);
}

fn tag_nft(bc: &mut Blockchain, kp: &KeyPair, nft_id: u64, tag: &str) {
    let from = Address::from(kp.public_key_bytes());
    let mut tx =
        Transaction::new_with_fee(from, Address::zero(), 0, 1, bc.get_nonce(&from), Vec::new());
    tx.tx_type = TransactionType::NftTag {
        nft_id,
        tag: tag.to_string(),
    };
    submit_tx(bc, tx, kp);
}

#[tokio::test]
async fn nft_tag_is_stored_for_the_owner_only() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("nft_tag.db");
    let mut bc = fresh_chain(db.to_str().unwrap());

    let alice_kp = KeyPair::generate().unwrap();
    let bob_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = Address::from(bob_kp.public_key_bytes());
    bc.state.add_balance(&alice, 1000);
    bc.state.add_balance(&bob, 1000);

    mint_nft(&mut bc, &alice_kp, ContentId::referenced([0x77; 32]));
    let nft_id = *bc.state.nft_registry.nfts.keys().next().unwrap();

    tag_nft(&mut bc, &bob_kp, nft_id, "#spam");
    assert!(bc
        .state
        .nft_registry
        .get_nft(nft_id)
        .unwrap()
        .tags
        .is_empty());

    tag_nft(&mut bc, &alice_kp, nft_id, "#art");
    assert_eq!(
        bc.state.nft_registry.get_nft(nft_id).unwrap().tags,
        vec!["#art".to_string()]
    );
}
