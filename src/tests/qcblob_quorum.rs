//! (security audit, section 4) Tests of the minimum signature count of
//! `import_qc_blob` (2/3 quorum). A QcBlob insert without enough signatures
//! must not be accepted below the threshold; exactly the threshold must be
//! accepted; an empty signature set must be refused.
//!
//! This file was rewritten once. Its earlier form **never called**
//! `import_qc_blob`: all four tests recomputed the quorum arithmetic inside
//! themselves and compared it against `blob.pq_signatures.len()`. What they
//! measured was not the behaviour of the production code but their own two
//! lines - had `import_qc_blob` been deleted entirely, all four would have
//! stayed green.
//!
//! Worse, what they counted was the **raw input count**. That is exactly why the
//! production code had been fixed: repeating the same validator's signature
//! could push the raw count over the quorum. The fix applies the quorum against
//! the set of **distinct verified signers** returned by
//! `verify_against_snapshot`. The tests, by treating the raw count as correct,
//! preserved the logic of the very hole that had been closed.
//!
//! All of them now call `Blockchain::import_qc_blob` and look at the `Result` it
//! returns.

use crate::chain::blockchain::Blockchain;
use crate::chain::finality::ValidatorEntry;
use crate::chain::finality::ValidatorSetSnapshot;
use crate::consensus::pow::PoWEngine;
use crate::consensus::qc::{sign_attestation, PqSignatureEntry, QcBlob};
use crate::core::address::Address;
use crate::crypto::primitives::PqKeyPair;
use std::sync::Arc;

/// Devnet (`chain_id` 45262) has `finality_checkpoint_interval = 2`, so height
/// 10 is a valid checkpoint height. `import_qc_blob` refuses any other height
/// before it looks at signatures at all, which would make every rejection test
/// below pass for a reason that has nothing to do with the quorum.
const CHECKPOINT_HEIGHT: u64 = 10;
const CHAIN_ID: u64 = 45262;

/// The epoch the certificate rule derives for that height: the checkpoint
/// paths refuse a blob whose epoch disagrees with the height it certifies
/// before signatures are ever looked at, so the fixture signs and stores the
/// derived epoch rather than a literal.
fn checkpoint_epoch() -> u64 {
    CHECKPOINT_HEIGHT
        / crate::core::chain_config::epoch_len_for_chain_id(CHAIN_ID).max(1)
}

fn validator_address(i: u8) -> Address {
    let mut bytes = [0u8; 32];
    bytes[0] = i + 1;
    Address::from(bytes)
}

/// A 3-validator snapshot with real post-quantum keys. The signatures in the
/// blobs below are genuine, so every blob gets through the signature check and
/// reaches the quorum comparison this file is about.
fn snapshot_3_validators(epoch: u64, keys: &[PqKeyPair]) -> ValidatorSetSnapshot {
    let validators: Vec<ValidatorEntry> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| ValidatorEntry {
            address: validator_address(i as u8),
            stake: 1_000_000,
            bls_public_key: Vec::new(),
            pop_signature: Vec::new(),
            pq_public_key: key.public_key_bytes().to_vec(),
        })
        .collect();
    ValidatorSetSnapshot::new(epoch, validators)
}

/// A chain with a real block at the checkpoint height and a validator
/// snapshot registered under the derived checkpoint epoch, so
/// `import_qc_blob` gets past its structural checks and reaches the quorum
/// comparison this file is about.
fn chain_ready_for_checkpoint() -> (Blockchain, String, Vec<PqKeyPair>) {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, CHAIN_ID, None);

    let producer = validator_address(0);
    while (bc.chain.len() as u64) <= CHECKPOINT_HEIGHT {
        assert!(
            bc.produce_block(producer).is_some(),
            "the fixture needs a block at every height up to the checkpoint"
        );
    }

    let checkpoint_hash = bc
        .chain
        .get(CHECKPOINT_HEIGHT as usize)
        .expect("just produced")
        .hash
        .clone();

    let keys: Vec<PqKeyPair> = (0..3).map(|_| PqKeyPair::generate()).collect();
    let epoch = checkpoint_epoch();
    // The lookup answers from the live state when the asked epoch is the
    // chain's current one, and this PoW fixture has no bonded validators to
    // build a live set from. The registered snapshot below IS the fixture's
    // validator set, so the current index moves off the derived epoch the
    // same way other fixtures pin it - the certificate rule above still
    // derives the epoch from the height, and the signatures still carry it.
    bc.state.epoch_index = epoch.wrapping_sub(1);
    bc.validator_snapshots
        .insert(epoch, snapshot_3_validators(epoch, &keys));

    (bc, checkpoint_hash, keys)
}

/// One genuine signature entry of validator `index`. The address is rendered
/// with `to_string`, which is what `verify_against_snapshot` compares against.
fn signed_entry(keys: &[PqKeyPair], index: usize, checkpoint_hash: &str) -> PqSignatureEntry {
    sign_attestation(
        &keys[index],
        checkpoint_epoch(),
        CHECKPOINT_HEIGHT,
        checkpoint_hash,
        index as u32,
        validator_address(index as u8).to_string(),
    )
    .expect("the fixture key signs")
}

/// A blob carrying `count` distinct validators' genuine signatures.
fn blob_with_distinct_sigs(count: usize, checkpoint_hash: &str, keys: &[PqKeyPair]) -> QcBlob {
    let sigs: Vec<PqSignatureEntry> = (0..count)
        .map(|i| signed_entry(keys, i, checkpoint_hash))
        .collect();
    QcBlob::new(
        checkpoint_epoch(),
        CHECKPOINT_HEIGHT,
        checkpoint_hash.to_string(),
        sigs,
    )
}

/// A blob where one validator's genuine entry is repeated. The raw entry count
/// reaches the quorum; the unique verified-signer count cannot.
fn blob_with_repeated_sig(count: usize, checkpoint_hash: &str, keys: &[PqKeyPair]) -> QcBlob {
    let sigs: Vec<PqSignatureEntry> = (0..count)
        .map(|_| signed_entry(keys, 0, checkpoint_hash))
        .collect();
    QcBlob::new(
        checkpoint_epoch(),
        CHECKPOINT_HEIGHT,
        checkpoint_hash.to_string(),
        sigs,
    )
}

/// Canary for the fixture itself. Every test below asserts a refusal, and a
/// refusal is easy to get for the wrong reason: a height that is not a
/// checkpoint, a missing block, a hash mismatch, an unregistered validator set,
/// or a signature that does not verify. A blob with one genuine signature must
/// get past all of those and be refused by the quorum comparison itself.
#[test]
fn the_fixture_reaches_the_quorum_check_and_not_an_earlier_rejection() {
    let (mut bc, hash, keys) = chain_ready_for_checkpoint();
    let err = bc
        .import_qc_blob(blob_with_distinct_sigs(1, &hash, &keys))
        .expect_err("one signature out of three must not be accepted");

    assert!(
        err.contains("unique verified signers"),
        "the fixture fails before the quorum check is reached: {err}"
    );
}

#[test]
fn import_qc_blob_rejects_empty_signature_set() {
    let (mut bc, hash, keys) = chain_ready_for_checkpoint();

    let err = bc
        .import_qc_blob(blob_with_distinct_sigs(0, &hash, &keys))
        .expect_err("a blob with no signatures at all must be refused");

    assert!(err.contains("unique verified signers"), "got: {err}");
    assert!(
        bc.get_qc_blob(CHECKPOINT_HEIGHT).is_none(),
        "a refused blob must not be stored"
    );
}

#[test]
fn import_qc_blob_rejects_below_quorum_signature_count() {
    // Quorum for a 3-validator set is ceil(3*2/3) = 2. One is below it.
    let (mut bc, hash, keys) = chain_ready_for_checkpoint();

    let err = bc
        .import_qc_blob(blob_with_distinct_sigs(1, &hash, &keys))
        .expect_err("one signature out of three is below quorum");

    assert!(
        err.contains("1 unique verified signers, need at least 2"),
        "got: {err}"
    );
    assert!(
        bc.get_qc_blob(CHECKPOINT_HEIGHT).is_none(),
        "a refused blob must not be stored"
    );
}

#[test]
fn import_qc_blob_accepts_exactly_the_threshold() {
    let (mut bc, hash, keys) = chain_ready_for_checkpoint();

    bc.import_qc_blob(blob_with_distinct_sigs(2, &hash, &keys))
        .expect("two genuine signatures out of three meet the quorum");

    assert!(bc.get_qc_blob(CHECKPOINT_HEIGHT).is_some());
}

/// The regression the production fix exists for. `pq_signatures.len()` counted
/// duplicate entries, so repeating one validator's signature inflated the raw
/// count past the threshold while a single validator had attested. Two entries
/// clear the raw quorum of 2; only one validator is behind them. The refusal
/// must name the duplicate.
#[test]
fn duplicate_signatures_do_not_inflate_the_quorum() {
    let (mut bc, hash, keys) = chain_ready_for_checkpoint();

    let blob = blob_with_repeated_sig(2, &hash, &keys);
    assert!(
        blob.pq_signatures.len() >= 2,
        "the fixture must clear the threshold on raw count, or it proves nothing"
    );

    let err = bc
        .import_qc_blob(blob)
        .expect_err("one validator signing twice is one attestation, not two");

    assert!(err.contains("Duplicate PQ signature"), "got: {err}");
    assert!(
        bc.get_qc_blob(CHECKPOINT_HEIGHT).is_none(),
        "a refused blob must not be stored"
    );
}
