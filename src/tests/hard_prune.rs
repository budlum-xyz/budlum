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
    // the same content_id. The owner is set because the prune is bound to it:
    // burning a token that merely names a content id is not evidence of owning
    // that content (`NftMint` accepts any id), so the burn only prunes when the
    // burner is the registered claimant.
    let mut manifest = ContentManifest::from_bytes_sliced(b"hard prune target", 4).unwrap();
    manifest.owner = alice;
    let cid = manifest.manifest_id;
    bc.state.storage_registry.register_manifest(&manifest);
    assert!(
        bc.state.storage_registry.has_claim(&cid, &alice),
        "the registered owner holds the claim the prune checks"
    );
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

/// The authorization the prune needs. `NftMint` accepts an arbitrary content
/// id, so before this check any funded account could mint a token over
/// somebody else's id, burn it, and have the chain destroy that manifest and
/// settle every deal on it - paying operator bonds and payer refunds on
/// content it did not own.
#[tokio::test]
async fn nft_burn_by_a_stranger_cannot_prune_someone_elses_manifest() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("hard_prune_owner_gate.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);
    bc.state.base_fee = 0;
    bc.mempool.set_min_fee(0);

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let mallory_kp = KeyPair::generate().unwrap();
    let mallory = Address::from(mallory_kp.public_key_bytes());
    bc.state.add_balance(&alice, 1000);
    bc.state.add_balance(&mallory, 1000);

    let mut manifest = ContentManifest::from_bytes_sliced(b"somebody else's object", 4).unwrap();
    manifest.owner = alice;
    let cid = manifest.manifest_id;
    bc.state.storage_registry.register_manifest(&manifest);

    // Mallory mints a token that names Alice's content id.
    let data = bincode::serialize(&(cid, None::<String>)).unwrap();
    let mut mint_tx =
        Transaction::new_with_fee(mallory, Address::zero(), 0, 1, bc.get_nonce(&mallory), data);
    mint_tx.tx_type = TransactionType::NftMint;
    mint_tx.sign(&mallory_kp);
    bc.mempool.add_transaction(mint_tx).unwrap();
    let _ = bc.produce_block(Address::zero()).unwrap();
    let nft_id = *bc.state.nft_registry.nfts.keys().next().unwrap();

    // And burns it.
    let burn_data = bincode::serialize(&nft_id).unwrap();
    let mut burn_tx = Transaction::new_with_fee(
        mallory,
        Address::zero(),
        0,
        1,
        bc.get_nonce(&mallory),
        burn_data,
    );
    burn_tx.tx_type = TransactionType::NftBurn;
    burn_tx.sign(&mallory_kp);
    bc.mempool.add_transaction(burn_tx).unwrap();
    let (_block, pruned_cids) = bc.produce_block(Address::zero()).unwrap();

    assert_eq!(bc.state.nft_registry.nfts.len(), 0, "the token is burned");
    assert!(
        bc.state.storage_registry.get_manifest(&cid).is_some(),
        "a stranger's burn must not destroy another account's manifest"
    );
    assert!(
        pruned_cids.is_empty(),
        "no content may be pruned on a stranger's burn"
    );
}
