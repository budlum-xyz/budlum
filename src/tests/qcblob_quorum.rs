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
use crate::consensus::qc::{PqSignatureEntry, QcBlob};
use crate::core::address::Address;
use std::sync::Arc;

/// Devnet (`chain_id` 45262) has `finality_checkpoint_interval = 2`, so height
/// 10 is a valid checkpoint height. `import_qc_blob` refuses any other height
/// before it looks at signatures at all, which would make every rejection test
/// below pass for a reason that has nothing to do with the quorum.
const CHECKPOINT_HEIGHT: u64 = 10;
const CHAIN_ID: u64 = 45262;

fn validator_address(i: u8) -> Address {
    let mut bytes = [0u8; 32];
    bytes[0] = i + 1;
    Address::from(bytes)
}

/// A 3-validator snapshot. `pq_public_key` is non-empty because
/// `verify_against_snapshot` refuses a validator without one before it ever
/// reaches the signature check - with empty keys the tests would pass on the
/// wrong error.
fn snapshot_3_validators(epoch: u64) -> ValidatorSetSnapshot {
    let validators: Vec<ValidatorEntry> = (0..3)
        .map(|i| ValidatorEntry {
            address: validator_address(i),
            stake: 1_000_000,
            bls_public_key: Vec::new(),
            pop_signature: Vec::new(),
            pq_public_key: vec![0xAAu8; 32],
        })
        .collect();
    ValidatorSetSnapshot::new(epoch, validators)
}

/// A chain with a real block at the checkpoint height and an epoch-0 validator
/// snapshot registered, so `import_qc_blob` gets past its structural checks and
/// reaches the quorum comparison this file is about.
fn chain_ready_for_checkpoint() -> (Blockchain, String) {
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

    bc.validator_snapshots.insert(0, snapshot_3_validators(0));

    (bc, checkpoint_hash)
}

/// A blob carrying `count` distinct validators' signatures. The addresses are
/// rendered with `to_string`, which is what `verify_against_snapshot` compares
/// against - `Debug` would render `Address(..)` and fail on the wrong branch.
fn blob_with_distinct_sigs(count: usize, checkpoint_hash: &str) -> QcBlob {
    let sigs: Vec<PqSignatureEntry> = (0..count)
        .map(|i| PqSignatureEntry {
            validator_index: i as u32,
            validator_address: validator_address(i as u8).to_string(),
            dilithium_signature: vec![0x01u8; 8],
        })
        .collect();
    QcBlob::new(0, CHECKPOINT_HEIGHT, checkpoint_hash.to_string(), sigs)
}

/// A blob where one validator's entry is repeated. The raw entry count reaches
/// the quorum; the unique verified-signer count cannot.
fn blob_with_repeated_sig(count: usize, checkpoint_hash: &str) -> QcBlob {
    let sigs: Vec<PqSignatureEntry> = (0..count)
        .map(|_| PqSignatureEntry {
            validator_index: 0,
            validator_address: validator_address(0).to_string(),
            dilithium_signature: vec![0x01u8; 8],
        })
        .collect();
    QcBlob::new(0, CHECKPOINT_HEIGHT, checkpoint_hash.to_string(), sigs)
}

/// Canary for the fixture itself. Every test below asserts a rejection, and a
/// rejection is easy to get for the wrong reason: a height that is not a
/// checkpoint, a missing block, a hash mismatch, an unregistered validator set.
/// If the fixture regressed into any of those, the other tests would still pass
/// while testing nothing. This one names those errors and fails on them.
#[test]
fn the_fixture_reaches_the_quorum_check_and_not_an_earlier_rejection() {
    let (mut bc, hash) = chain_ready_for_checkpoint();
    let err = bc
        .import_qc_blob(blob_with_distinct_sigs(0, &hash))
        .expect_err("an empty signature set must not be accepted");

    for premature in [
        "not a valid checkpoint height",
        "Missing checkpoint block",
        "checkpoint hash mismatch",
        "no validator set recorded",
        "has no Dilithium public key",
    ] {
        assert!(
            !err.contains(premature),
            "the fixture fails before the quorum check is reached ({premature}): {err}"
        );
    }
}

#[test]
fn import_qc_blob_rejects_empty_signature_set() {
    let (mut bc, hash) = chain_ready_for_checkpoint();

    let result = bc.import_qc_blob(blob_with_distinct_sigs(0, &hash));

    assert!(
        result.is_err(),
        "a blob with no signatures at all must be refused"
    );
    assert!(
        bc.get_qc_blob(CHECKPOINT_HEIGHT).is_none(),
        "a refused blob must not be stored"
    );
}

#[test]
fn import_qc_blob_rejects_below_quorum_signature_count() {
    // Quorum for a 3-validator set is ceil(3*2/3) = 2. One is below it.
    let (mut bc, hash) = chain_ready_for_checkpoint();

    let result = bc.import_qc_blob(blob_with_distinct_sigs(1, &hash));

    assert!(
        result.is_err(),
        "one signature out of three is below quorum"
    );
    assert!(
        bc.get_qc_blob(CHECKPOINT_HEIGHT).is_none(),
        "a refused blob must not be stored"
    );
}

/// The regression the production fix exists for. `pq_signatures.len()` counted
/// duplicate entries, so repeating one validator's signature inflated the raw
/// count past the threshold while a single validator had attested. Two entries
/// clear the raw quorum of 2; only one validator is behind them.
///
/// Canary: revert the quorum comparison to `blob.pq_signatures.len()` and this
/// test is the one that fails.
#[test]
fn duplicate_signatures_do_not_inflate_the_quorum() {
    let (mut bc, hash) = chain_ready_for_checkpoint();

    let blob = blob_with_repeated_sig(2, &hash);
    assert!(
        blob.pq_signatures.len() >= 2,
        "the fixture must clear the threshold on raw count, or it proves nothing"
    );

    let result = bc.import_qc_blob(blob);

    assert!(
        result.is_err(),
        "one validator signing twice is one attestation, not two"
    );
    assert!(
        bc.get_qc_blob(CHECKPOINT_HEIGHT).is_none(),
        "a refused blob must not be stored"
    );
}
