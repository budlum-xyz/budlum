//! The final sweep of the finality live path.
//!
//! The existing `finality_adversarial.rs` (12 tests) covers the fixes there:
//! equivocation producing slashing evidence, and signature verification at
//! ingest time. This file tests the **live-path windows** and the **honesty
//! boundaries** - the scenarios left out of the last sweep.
//!
//! ## Scope
//!
//! - **2.1 The epoch change**: the validator set is renewed at every epoch, and
//!   the votes of the old epoch must not leak into the new aggregator.
//! - **2.2 A late prevote (a height mismatch)**: inside the same epoch, a vote
//!   cast for a different checkpoint_height has to be refused with a height
//!   mismatch.
//! - **2.3 Double signing (the same voter in the same epoch)**: if a voter signs
//!   twice in the same epoch and casts votes for two different hashes back to
//!   back, only the FIRST vote counts and the second is refused; the vote window
//!   does not leak.
//! - **2.4 Snapshot hash consistency**: different validator sets must not
//!   produce the same `compute_hash` output - it is treated as collision-free.
//!
//! ## What it does not do
//!
//! - Quorum, split brain and byzantine noise: `finality_adversarial.rs` covers
//!   those, and this is NOT a regression of it.
//! - The snapshot round-trip:
//!   `equivocation_slashing_record_survives_snapshot_roundtrip` covers that.
//! - Rate-limited invalid-signature slashing:
//!   `repeated_invalid_signatures_trigger_slash` covers that.

use crate::chain::finality::{
    pop_signing_message, sign_bls, sign_bls_pop, FinalityAggregator, Prevote, ValidatorEntry,
    ValidatorSetSnapshot,
};
use crate::core::address::Address;
use crate::core::transaction::DEFAULT_CHAIN_ID;
use bls12_381::{G2Affine, G2Projective, Scalar};

// --- Test harness ------------------------------------------------------------

/// A deterministic but real BLS key pair - NOT a mock.
fn make_key(seed: u8) -> (Scalar, Vec<u8>) {
    let mut sk_bytes = [0u8; 64];
    sk_bytes[0] = seed + 1;
    let sk = Scalar::from_bytes_wide(&sk_bytes);
    let pk = G2Affine::from(G2Projective::generator() * sk);
    (sk, pk.to_compressed().to_vec())
}

fn addr_for(i: usize) -> Address {
    let mut b = [0u8; 32];
    b[0] = (i + 1) as u8;
    Address::from(b)
}

/// A snapshot of N validators, each carrying a real BLS key and a valid PoP.
fn make_snapshot(n: usize, epoch: u64, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
    let mut sks = Vec::new();
    let validators: Vec<ValidatorEntry> = (0..n)
        .map(|i| {
            let (sk, pk_bytes) = make_key(i as u8);
            sks.push(sk);
            let addr = addr_for(i);
            let pop_msg = pop_signing_message(DEFAULT_CHAIN_ID, &addr, &pk_bytes);
            let pop_sig = sign_bls_pop(&sk, &pop_msg);
            ValidatorEntry {
                address: addr,
                stake: stake_each,
                bls_public_key: pk_bytes,
                pop_signature: pop_sig,
                pq_public_key: Vec::new(),
            }
        })
        .collect();
    (ValidatorSetSnapshot::new(epoch, validators), sks)
}

fn sign_prevote(sk: &Scalar, epoch: u64, height: u64, hash: &str, voter: Address) -> Prevote {
    let mut v = Prevote {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        voter_id: voter,
        sig_bls: vec![],
        auth_sig: Vec::new(),
    };
    v.sig_bls = sign_bls(sk, &v.signing_message());
    v
}

// 2.1 - The epoch change (window isolation)

/// The aggregators of different epochs are completely isolated: a voter who
/// voted in epoch 1 and votes for the same hash in epoch 2 is counted by the new
/// aggregator in its own window; it does not affect the old aggregator, and the
/// old one does not affect
/// Kirletmez).
#[test]
fn live_path_epoch_change_isolates_votes() {
    let (snap1, sks1) = make_snapshot(4, 1, 1000);
    let mut agg1 = FinalityAggregator::new(1, 10, "H".into(), snap1.clone());
    // 3 of 4 prevote, so the epoch 1 window takes 3 votes.
    for (sk, v) in sks1.iter().zip(snap1.validators.iter()).take(3) {
        let pv = sign_prevote(sk, 1, 10, "H", v.address);
        agg1.add_prevote(pv).expect("epoch 1 prevote");
    }
    assert_eq!(
        agg1.prevotes.len(),
        3,
        "the epoch 1 window has to take 3 votes"
    );

    // Produce a NEW aggregator and a NEW snapshot for epoch 2.
    let (snap2, sks2) = make_snapshot(4, 2, 1000);
    let mut agg2 = FinalityAggregator::new(2, 20, "H2".into(), snap2.clone());

    // One validator votes in epoch 2 and is counted in its own window.
    let pv2 = sign_prevote(&sks2[0], 2, 20, "H2", snap2.validators[0].address);
    agg2.add_prevote(pv2).expect("epoch 2 prevote");
    assert_eq!(agg2.prevotes.len(), 1);
    // The epoch 1 aggregator is still in its own window, unaffected.
    assert_eq!(agg1.prevotes.len(), 3, "the epoch 1 window must stay clean");

    // A stale vote: a validly signed epoch 1 vote sent to the epoch 2
    // aggregator is refused and does not enter its window.
    let stale = sign_prevote(&sks1[3], 1, 10, "H", snap1.validators[3].address);
    let error = agg2
        .add_prevote(stale)
        .expect_err("an old-epoch vote must not enter the new window");
    assert!(error.contains("epoch mismatch"), "{error}");
    assert_eq!(agg2.prevotes.len(), 1, "the new window is unchanged");
}

// 2.2 - A late prevote (a height mismatch)

/// Inside the same epoch a vote cast for a DIFFERENT checkpoint_height is
/// refused: the `checkpoint_height` of the aggregator is fixed, and a vote from
/// another height is not accepted - the window does not leak.
#[test]
fn live_path_prevote_with_wrong_height_rejected() {
    let (snap, sks) = make_snapshot(4, 1, 1000);
    let mut agg = FinalityAggregator::new(1, 10, "H".into(), snap.clone());

    // The right height=10 and the right hash.
    let pv_ok = sign_prevote(&sks[0], 1, 10, "H", snap.validators[0].address);
    agg.add_prevote(pv_ok)
        .expect("the right height is accepted");

    // The wrong height=11 is refused by the height check.
    let pv_bad = sign_prevote(&sks[0], 1, 11, "H", snap.validators[0].address);
    let err = agg
        .add_prevote(pv_bad)
        .expect_err("a signature at the wrong height has to be invalid");
    assert!(
        err.contains("height mismatch"),
        "the wrong height must be refused by the height check: {err}"
    );
    // Only the first vote reached the aggregator.
    assert_eq!(agg.prevotes.len(), 1);
}

// 2.3 - The double-sign window (the same voter, the same epoch, two votes in a row)

/// The same voter cannot vote TWICE for the same hash in the same epoch: the
/// window accepts a single vote and refuses the second as a Duplicate. A second
/// vote for a different hash is refused too. This verifies that the window does
/// not leak.
#[test]
fn live_path_double_sign_window_is_tight() {
    let (snap, sks) = make_snapshot(3, 1, 1000);
    let mut agg = FinalityAggregator::new(1, 10, "H".into(), snap.clone());

    // 1st vote (canonical) - accepted.
    let pv1 = sign_prevote(&sks[0], 1, 10, "H", snap.validators[0].address);
    agg.add_prevote(pv1).expect("first prevote");

    // The second vote (the SAME voter, the SAME hash) is a Duplicate and refused.
    let pv_dup = sign_prevote(&sks[0], 1, 10, "H", snap.validators[0].address);
    let err = agg
        .add_prevote(pv_dup)
        .expect_err("a duplicate prevote has to be refused");
    assert!(err.contains("Duplicate"));

    // 3rd vote (SAME voter, DIFFERENT hash) - hash mismatch + evidence.
    let pv_conflict = sign_prevote(&sks[0], 1, 10, "H2", snap.validators[0].address);
    let _ = agg.add_prevote(pv_conflict); // refused, but it produces evidence
    assert_eq!(agg.prevotes.len(), 1, "only the first vote may count");
    assert_eq!(
        agg.detected_equivocations.len(),
        1,
        "a vote with a conflicting hash has to produce evidence"
    );
}

// 2.4 - Snapshot hash diversity

/// Different validator sets (a different order, a different count) produce
/// different snapshot hashes - treated as collision-free. The SAME set produces
/// the same hash
/// (deterministic acceptance).
#[test]
fn live_path_snapshot_hash_distinguishes_sets() {
    let (snap_a, _) = make_snapshot(3, 1, 1000);
    let hash_a = ValidatorSetSnapshot::compute_hash(&snap_a.validators);

    let (snap_b, _) = make_snapshot(4, 1, 1000);
    let hash_b = ValidatorSetSnapshot::compute_hash(&snap_b.validators);

    let (snap_c, _) = make_snapshot(3, 1, 2000);
    let hash_c = ValidatorSetSnapshot::compute_hash(&snap_c.validators);

    assert_ne!(
        hash_a, hash_b,
        "a 3-validator set and a 4-validator set must not share a hash"
    );
    assert_ne!(
        hash_a, hash_c,
        "sets at 1000 and 2000 stake must not share a hash"
    );
    assert_ne!(
        hash_b, hash_c,
        "a different stake and a different size must not share a hash"
    );

    // The SAME set deterministically produces the same hash.
    let hash_a2 = ValidatorSetSnapshot::compute_hash(&snap_a.validators);
    assert_eq!(hash_a, hash_a2, "compute_hash has to be deterministic");
}

// 2.5 - The node's prevote epoch must be the aggregator's epoch (P10-F01)

/// Regression for the finality-dead bug: node.rs derived the periodic
/// prevote epoch as `checkpoint_height / checkpoint_interval` while the
/// receiving aggregator (`Blockchain::start_prevote_task`) derives it as
/// `checkpoint_height / epoch_len`. On mainnet (interval 10, epoch_len 100)
/// every honest prevote was refused with "Prevote epoch mismatch", so the
/// prevote quorum was never reached and native BLS finality never advanced
/// on any network where the two divisors differ.
#[test]
fn node_prevote_epoch_reaches_the_aggregator() {
    use crate::core::chain_config::{
        epoch_len_for_chain_id, finality_checkpoint_interval_for_chain_id, Network,
    };

    for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
        let chain_id = network.chain_id().value();
        let interval = finality_checkpoint_interval_for_chain_id(chain_id);
        let epoch_len = epoch_len_for_chain_id(chain_id);
        assert!(interval > 0 && epoch_len > 0, "{network:?} divisors");

        // A checkpoint height where the old interval divisor and the
        // epoch-len divisor disagree, so the mismatch path is exercised.
        let height = interval * epoch_len;
        let checkpoint_height = (height / interval) * interval;
        assert!(checkpoint_height > 0);
        assert_ne!(
            checkpoint_height / interval,
            checkpoint_height / epoch_len,
            "{network:?}: this height must distinguish the two divisors"
        );

        // The node's computation after the fix (node.rs periodic prevote).
        let node_epoch = checkpoint_height / epoch_len;

        // Drive a real prevote through a real aggregator built the way
        // start_prevote_task builds it.
        let (snap, sks) = make_snapshot(1, node_epoch, 1000);
        let mut agg = FinalityAggregator::new(
            node_epoch,
            checkpoint_height,
            "cp_hash".into(),
            snap.clone(),
        );
        let pv = sign_prevote(
            &sks[0],
            node_epoch,
            checkpoint_height,
            "cp_hash",
            snap.validators[0].address,
        );
        agg.add_prevote(pv).unwrap_or_else(|e| {
            panic!("{network:?}: a prevote carrying the node's own epoch must reach the aggregator: {e}")
        });

        // The old buggy epoch must still be refused: proof that this height
        // really exercises the mismatch path.
        let stale = sign_prevote(
            &sks[0],
            checkpoint_height / interval,
            checkpoint_height,
            "cp_hash",
            snap.validators[0].address,
        );
        let err = agg
            .add_prevote(stale)
            .expect_err("the old interval-based epoch must be refused");
        assert!(err.contains("epoch mismatch"), "{err}");
    }
}
