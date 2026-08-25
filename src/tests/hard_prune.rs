//! The chain-level seal for hard pruning (F1 - a report finding, sealed by test
//! on 2026-07-17).
//!
//! Constitution section 1: when an NFT is burned, the B.U.D. content bound to it
//! has to be deleted.
//! The canonical mechanism (b65f058; reduced to a single mechanism in 62c7509):
//! after a block commit, collect_nft_burn_cids plus
//! process_nft_burn_storage_pruning call prune_content, which expires the active
//! deals and removes the manifest from the registry. This test locks the
//! chain-level effect on the produce_block path.
//! Physically deleting the chunks (the NodeCommand::StoragePrune worker) is a
//! separate verification matter (see the STATUS_ONLINE finding R1: the sender
//! wiring is missing).
//!
//! NOTE (proved in CI): mempool transaction validation requires a signature, so
//! the transactions are signed with a real KeyPair, the nonce is read from the
//! chain and the nft_id is read from the registry.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;
use crate::storage::db::Storage;
use crate::storage::manifest::ContentManifest;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn nft_burn_prunes_matching_storage_manifest_on_produce() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("hard_prune_produce.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);
    bc.state.base_fee = 0;
    bc.mempool.set_min_fee(0);

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    bc.state.add_balance(&alice, 1000);

    // The manifest is registered in the chain registry, and the NFT is bound to
    // the same content_id.
    let manifest = ContentManifest::from_bytes_sliced(b"hard prune target", 4).unwrap();
    let cid = manifest.manifest_id;
    bc.state.storage_registry.register_manifest(&manifest);
    assert!(bc.state.storage_registry.get_manifest(&cid).is_some());

    // Mint.
    let data = bincode::serialize(&(cid, None::<String>)).unwrap();
    let mut mint_tx =
        Transaction::new_with_fee(alice, Address::zero(), 0, 1, bc.get_nonce(&alice), data);
    mint_tx.tx_type = TransactionType::NftMint;
    mint_tx.sign(&alice_kp);
    bc.mempool.add_transaction(mint_tx).unwrap();
    let _ = bc.produce_block(Address::zero()).unwrap();
    assert_eq!(bc.state.nft_registry.nfts.len(), 1);

    // The NFT id is read from the registry, with no assumption about an id counter.
    let nft_id = *bc.state.nft_registry.nfts.keys().next().unwrap();

    // Burn.
    let burn_data = bincode::serialize(&nft_id).unwrap();
    let mut burn_tx = Transaction::new_with_fee(
        alice,
        Address::zero(),
        0,
        1,
        bc.get_nonce(&alice),
        burn_data,
    );
    burn_tx.tx_type = TransactionType::NftBurn;
    burn_tx.sign(&alice_kp);
    bc.mempool.add_transaction(burn_tx).unwrap();
    let (_block, pruned_cids) = bc.produce_block(Address::zero()).unwrap();

    // The NFT was burned and the matching manifest was hard-pruned.
    assert_eq!(bc.state.nft_registry.nfts.len(), 0);
    assert!(bc.state.storage_registry.get_manifest(&cid).is_none());

    // F1 Physical Pruning check: return value of produce_block carries the CID
    assert_eq!(pruned_cids.len(), 1);
    assert_eq!(pruned_cids[0], cid.0);
}
