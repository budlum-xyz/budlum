//! Multi-node / adversarial finality tests.
//!
//! Without standing up a real libp2p network, this suite calls `FinalityAggregator` + `sign_bls` +
//! `FinalityCert::verify` directly to simulate several
//! "virtual" validator identities, each with its own REAL BLS keypair.
//! It is a natural extension of the existing test-harness pattern in
//! `src/chain/finality.rs` (`make_test_key`, `make_snapshot_with_keys`, real `sign_bls`
//! signatures) - NO mock/placeholder signature is used.
//!
//! ## Behaviour after the fixes
//!
//! * **1.1 Equivocation:** a vote the same voter casts for a DIFFERENT hash still
//!   does not count, BUT a `DoubleSign` slashing evidence is now
//!   PRODUCED and passed through the existing `submit_registry_slashing_report` path,
//!   leading to a real slash (see `equivocation_generates_slashing_evidence`).
//! * **1.3 Invalid signature:** `add_prevote`/`add_precommit` now verify the individual BLS
//!   signature AT INGEST (Option A). An invalid signature
//!   NEVER enters the aggregate; the honest subset can always finalize and a single
//!   bad actor cannot stall the round (see
//!   `finality_recovers_honest_subset_after_invalid_signature`).

// These tests pair the parallel arrays `sks[i]` and `snap.validators[i]` by the SAME index;
// an index-based loop reads better here than `enumerate`.
#![allow(clippy::needless_range_loop)]

use crate::chain::blockchain::Blockchain;
use crate::chain::finality::{
    checkpoint_signing_message, pop_signing_message, sign_bls, sign_bls_pop, FinalityAggregator,
    Precommit, Prevote, ValidatorEntry, ValidatorSetSnapshot,
};
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
#[cfg(test)]
fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
    let mut b = [0u8; 32];
    b[0] = byte;
    crate::core::address::Address::from(b)
}

use crate::crypto::primitives::ValidatorKeys;
use crate::registry::role::roles;
use crate::registry::MemberStatus;
use bls12_381::{G2Affine, G2Projective, Scalar};
use std::sync::Arc;

// --- Test harness: real BLS keypairs --------------------------------

/// Produces a deterministic but real BLS keypair (NOT a mock).
fn make_test_key(seed: u8) -> (Scalar, Vec<u8>) {
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

fn install_consensus_keys(
    blockchain: &mut Blockchain,
    address: Address,
    bls_secret: &Scalar,
    bls_public: Vec<u8>,
) {
    let support_keys = ValidatorKeys::generate().unwrap();
    let pop_message = pop_signing_message(
        crate::core::transaction::DEFAULT_CHAIN_ID,
        &address,
        &bls_public,
    );
    let validator = blockchain.state.validators.get_mut(&address).unwrap();
    validator.vrf_public_key = support_keys.vrf_key.public.to_bytes().to_vec();
    validator.bls_public_key = bls_public;
    validator.pop_signature = sign_bls_pop(bls_secret, &pop_message);
    validator.pq_public_key = support_keys.pq_key.unwrap().public_key_bytes().to_vec();
    validator.active = true;
}

/// A snapshot of `n` validators, each carrying a real BLS key and a valid PoP.
fn make_snapshot_with_keys(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
    let mut sks = Vec::new();
    let validators: Vec<ValidatorEntry> = (0..n)
        .map(|i| {
            let (sk, pk_bytes) = make_test_key(i as u8);
            sks.push(sk);
            let addr = addr_for(i);
            let pop_msg =
                pop_signing_message(crate::core::transaction::DEFAULT_CHAIN_ID, &addr, &pk_bytes);
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
    (ValidatorSetSnapshot::new(1, validators), sks)
}

/// Produces a prevote with a real BLS signature.
fn signed_prevote(sk: &Scalar, epoch: u64, height: u64, hash: &str, voter: Address) -> Prevote {
    let mut v = Prevote {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        voter_id: voter,
        sig_bls: vec![],
    };
    v.sig_bls = sign_bls(sk, &v.signing_message());
    v
}

/// Produces a precommit with a real BLS signature (signed over `hash`).
fn signed_precommit(sk: &Scalar, epoch: u64, height: u64, hash: &str, voter: Address) -> Precommit {
    let msg = checkpoint_signing_message(epoch, height, hash);
    Precommit {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        voter_id: voter,
        sig_bls: sign_bls(sk, &msg),
    }
}

/// Casts prevotes with the first `count` validators until the prevote quorum is reached.
fn drive_prevote_quorum(
    agg: &mut FinalityAggregator,
    snap: &ValidatorSetSnapshot,
    sks: &[Scalar],
    count: usize,
    epoch: u64,
    height: u64,
    hash: &str,
) {
    for i in 0..count {
        let pv = signed_prevote(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_prevote(pv).expect("prevote must be accepted");
    }
}

// 1.1 - Equivocation (conflicting vote)

/// A voter signs prevotes for two DIFFERENT checkpoint hashes at the same height/epoch.
/// The conflicting vote DOES NOT count (the aggregator is bound to a single hash) BUT an
/// equivocation slashing evidence is now PRODUCED rather than silently swallowed.
/// A repeat vote for the same hash becomes "Duplicate" and produces no new evidence.
#[test]
fn finality_rejects_equivocating_voter() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let mut agg = FinalityAggregator::new(epoch, height, "HASH_A".into());
    agg.set_validator_snapshot(snap.clone());

    // Voter 0 votes for the correct hash (HASH_A) -> accepted, no evidence.
    let pv_a = signed_prevote(&sks[0], epoch, height, "HASH_A", snap.validators[0].address);
    agg.add_prevote(pv_a).expect("first (honest) vote accepted");
    assert!(
        agg.detected_equivocations.is_empty(),
        "a single honest vote must produce no evidence"
    );

    // The same voter votes for a CONFLICTING hash (HASH_B) -> does not count but
    // produces equivocation evidence.
    let pv_b = signed_prevote(&sks[0], epoch, height, "HASH_B", snap.validators[0].address);
    let err = agg
        .add_prevote(pv_b)
        .expect_err("equivocating (conflicting-hash) vote must not count");
    assert!(err.contains("hash mismatch"));
    assert_eq!(
        agg.detected_equivocations.len(),
        1,
        "a conflicting vote must produce exactly one slashing evidence"
    );

    // If the same voter votes a second time for the SAME hash -> Duplicate, NO new evidence.
    let pv_a2 = signed_prevote(&sks[0], epoch, height, "HASH_A", snap.validators[0].address);
    let err2 = agg
        .add_prevote(pv_a2)
        .expect_err("duplicate vote must be rejected");
    assert!(
        err2.contains("Duplicate"),
        "expected 'Duplicate', got: {err2}"
    );
    assert_eq!(
        agg.detected_equivocations.len(),
        1,
        "a duplicate must produce no new evidence"
    );

    // Only the single honest vote counted; the equivocation could not force a quorum.
    assert_eq!(agg.prevotes.len(), 1);
    assert!(!agg.prevote_quorum_reached);
}

// 1.2 - Below-quorum scenario

/// N=4, quorum 2/3 -> 2667 required. If only 2 validators (2000 stake) sign,
/// no cert is produced and finality stays Pending.
#[test]
fn finality_stays_pending_below_quorum() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    // Only 2/4 prevotes -> 2000 < 2667.
    drive_prevote_quorum(&mut agg, &snap, &sks, 2, epoch, height, hash);
    assert!(!agg.prevote_quorum_reached, "2/4 must not meet the quorum");

    // Without a prevote quorum the precommit is refused.
    let pc = signed_precommit(&sks[0], epoch, height, hash, snap.validators[0].address);
    assert!(agg.add_precommit(pc).is_err());

    // No cert can be produced.
    assert!(agg.try_produce_cert().is_none());
}

// 1.3 - Mixed invalid signature (Option A: ingest-time verification)

/// **DELIBERATE behaviour change** (NOT a regression):
/// the old `finality_invalid_signature_poisons_aggregate` test verified that a single invalid
/// signature brought down the whole aggregation (fail-closed).
/// With Option A an invalid signature NEVER ENTERS THE AGGREGATE; it is refused at
/// ingest. So the honest subset (3/4) can still finalize and a single
/// bad actor cannot stall the round (DoS prevented).
#[test]
fn finality_recovers_honest_subset_after_invalid_signature() {
    // 4 validators, quorum 3 (2667). Pass the prevote quorum with 4 honest prevotes.
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    drive_prevote_quorum(&mut agg, &snap, &sks, 4, epoch, height, hash);
    assert!(agg.prevote_quorum_reached);

    // Validator 3 sends a precommit with an INVALID signature (signed over the wrong message).
    let wrong_msg = checkpoint_signing_message(epoch, height, "WRONG_HASH");
    let bad_pc = Precommit {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        voter_id: snap.validators[3].address,
        sig_bls: sign_bls(&sks[3], &wrong_msg),
    };
    // REFUSED at ingest, never enters the aggregate.
    let err = agg
        .add_precommit(bad_pc)
        .expect_err("an invalid signature must be refused at ingest");
    assert!(err.contains("Invalid precommit signature"));

    // Honest 3/4 precommits -> quorum met.
    for i in 0..3 {
        let pc = signed_precommit(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_precommit(pc).expect("honest precommit accepted");
    }
    assert!(
        agg.precommit_quorum_reached,
        "an honest 3/4 must meet the quorum"
    );

    // The cert is produced AND verifies - the honest subset finalized despite the bad actor.
    let cert = agg.try_produce_cert().expect("honest subset cert produced");
    assert_eq!(
        cert.signer_count(4),
        3,
        "only the 3 honest signatures must count"
    );
    cert.verify(&snap)
        .expect("the honest subset certificate must verify");
}

/// Counter-evidence: if all 3 of the same validators sign validly the cert verifies.
/// This proves the failure in 1.3 really came from the invalid signature and
/// not from the harness.
#[test]
fn finality_valid_quorum_produces_verifiable_cert() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    drive_prevote_quorum(&mut agg, &snap, &sks, 3, epoch, height, hash);
    for i in 0..3 {
        let pc = signed_precommit(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_precommit(pc).expect("precommit accepted");
    }
    let cert = agg.try_produce_cert().expect("cert produced");
    assert_eq!(cert.signer_count(4), 3);
    cert.verify(&snap).expect("valid quorum cert must verify");
}

// 1.4 - Network partition (split quorum) / split-brain

/// 4 validators, quorum 3 (2667). Two subgroups split 2-2, each voting for a DIFFERENT
/// checkpoint hash. Neither side reaches a quorum on its own,
/// so two conflicting certs at the same height (split-brain) CANNOT form.
#[test]
fn finality_prevents_split_brain_on_partition() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;

    // Grup A: validator 0,1 -> HASH_A
    let mut agg_a = FinalityAggregator::new(epoch, height, "HASH_A".into());
    agg_a.set_validator_snapshot(snap.clone());
    for i in 0..2 {
        let pv = signed_prevote(&sks[i], epoch, height, "HASH_A", snap.validators[i].address);
        agg_a.add_prevote(pv).expect("group A prevote");
    }

    // Grup B: validator 2,3 -> HASH_B
    let mut agg_b = FinalityAggregator::new(epoch, height, "HASH_B".into());
    agg_b.set_validator_snapshot(snap.clone());
    for i in 2..4 {
        let pv = signed_prevote(&sks[i], epoch, height, "HASH_B", snap.validators[i].address);
        agg_b.add_prevote(pv).expect("group B prevote");
    }

    // Both sides are below quorum -> no cert at all.
    assert!(
        !agg_a.prevote_quorum_reached,
        "group A must not finalize on its own"
    );
    assert!(
        !agg_b.prevote_quorum_reached,
        "group B must not finalize on its own"
    );
    assert!(agg_a.try_produce_cert().is_none());
    assert!(agg_b.try_produce_cert().is_none());
}

// 1.5 - Late votes (after the cert is produced)

/// Votes arriving after the cert do not break the system: (a) a repeat vote from an
/// already counted voter is refused as "Duplicate", (b) even if a new late vote is
/// added, the first cert's checkpoint context does not change and stays verifiable.
#[test]
fn finality_ignores_late_votes_after_cert() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    drive_prevote_quorum(&mut agg, &snap, &sks, 3, epoch, height, hash);
    for i in 0..3 {
        let pc = signed_precommit(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_precommit(pc).expect("precommit accepted");
    }
    let cert = agg.try_produce_cert().expect("cert produced");
    cert.verify(&snap).expect("cert verifies");
    let original_hash = cert.checkpoint_hash.clone();
    let original_height = cert.checkpoint_height;

    // (a) A late/repeat vote from an already counted voter -> Duplicate, safely refused.
    let dup = signed_precommit(&sks[0], epoch, height, hash, snap.validators[0].address);
    assert!(
        agg.add_precommit(dup).is_err(),
        "a late repeat vote must be refused"
    );

    // (b) A late vote from a new (4th) validator; state must not break, cert context fixed.
    let late = signed_precommit(&sks[3], epoch, height, hash, snap.validators[3].address);
    agg.add_precommit(late)
        .expect("new late precommit ingested");
    let cert2 = agg.try_produce_cert().expect("cert still producible");
    assert_eq!(
        cert2.checkpoint_hash, original_hash,
        "the checkpoint hash must not change"
    );
    assert_eq!(
        cert2.checkpoint_height, original_height,
        "the height must not change"
    );
    cert2.verify(&snap).expect("post-late cert still verifies");
}

// 1.6 - Honest quorum under noise

/// 7 validators, quorum 2/3 -> 4667. 5 honest validators vote for the HONEST hash
/// (5000 >= 4667). 2 byzantine validators send a "noise" vote for a CONFLICTING
/// hash; these are refused by the honest aggregator and do NOT block honest
/// finality - the honest quorum still produces a verifiable cert.
#[test]
fn finality_honest_quorum_survives_byzantine_noise() {
    let (snap, sks) = make_snapshot_with_keys(7, 1000);
    let epoch = 1;
    let height = 10;
    let honest_hash = "HONEST";
    let byz_hash = "BYZANTINE";
    let mut agg = FinalityAggregator::new(epoch, height, honest_hash.into());
    agg.set_validator_snapshot(snap.clone());

    // Let the byzantine noise arrive FIRST (conflicting hash) -> must be refused.
    for i in 5..7 {
        let noise = signed_prevote(&sks[i], epoch, height, byz_hash, snap.validators[i].address);
        assert!(
            agg.add_prevote(noise).is_err(),
            "byzantine (conflicting-hash) noise must be refused"
        );
    }

    // 5 honest prevotes.
    drive_prevote_quorum(&mut agg, &snap, &sks, 5, epoch, height, honest_hash);
    assert!(
        agg.prevote_quorum_reached,
        "an honest 5/7 must meet the quorum"
    );

    // Let the byzantine noise try again in the precommit phase -> refused again.
    for i in 5..7 {
        let noise = Precommit {
            epoch,
            checkpoint_height: height,
            checkpoint_hash: byz_hash.to_string(),
            voter_id: snap.validators[i].address,
            sig_bls: sign_bls(
                &sks[i],
                &checkpoint_signing_message(epoch, height, byz_hash),
            ),
        };
        assert!(
            agg.add_precommit(noise).is_err(),
            "the byzantine precommit must be refused"
        );
    }

    // 5 honest precommits -> quorum, the cert is produced and VERIFIES.
    for i in 0..5 {
        let pc = signed_precommit(
            &sks[i],
            epoch,
            height,
            honest_hash,
            snap.validators[i].address,
        );
        agg.add_precommit(pc).expect("honest precommit accepted");
    }
    assert!(agg.precommit_quorum_reached);
    let cert = agg.try_produce_cert().expect("honest cert produced");
    assert_eq!(cert.signer_count(7), 5);
    cert.verify(&snap)
        .expect("honest quorum cert must verify despite noise");
}

// End to end: equivocation -> evidence -> slash (Blockchain flow)

/// Sets up a Blockchain, produces real blocks up to `checkpoint_height`,
/// and starts the prevote phase. With a real BLS key, `voter` signs the correct hash first,
/// then a conflicting one. `Blockchain::handle_prevote` passes the detected
/// equivocation evidence through the existing `submit_registry_slashing_report`
/// path and applies a real slash.
#[test]
fn equivocation_generates_slashing_evidence() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;

    // Two validators: `honest` produces the blocks, `equivocator` will double-sign.
    let mut hsk = [0u8; 64];
    hsk[0] = 11;
    let honest_bls = Scalar::from_bytes_wide(&hsk);
    let honest_pk = G2Affine::from(G2Projective::generator() * honest_bls)
        .to_compressed()
        .to_vec();
    let honest = test_addr_from_byte(1u8);

    let mut esk = [0u8; 64];
    esk[0] = 22;
    let equiv_bls = Scalar::from_bytes_wide(&esk);
    let equiv_pk = G2Affine::from(G2Projective::generator() * equiv_bls)
        .to_compressed()
        .to_vec();
    let equivocator = test_addr_from_byte(2u8);

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(equivocator, 10_000);
    install_consensus_keys(&mut bc, honest, &honest_bls, honest_pk);
    install_consensus_keys(&mut bc, equivocator, &equiv_bls, equiv_pk);

    // Before the slash: the equivocator is registered, active, at full stake.
    let before = bc
        .state
        .registry
        .get(&equivocator, roles::VALIDATOR)
        .expect("equivocator registered")
        .clone();
    assert_eq!(before.stake, 10_000);
    assert!(matches!(before.status, MemberStatus::Active));

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    assert_eq!(block.index, cp);

    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc
        .finality_aggregator
        .as_ref()
        .expect("aggregator active")
        .epoch;

    // The equivocator signs the CANONICAL hash first (counts), then a CONFLICTING one.
    let mut pv1 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv1.sig_bls = sign_bls(&equiv_bls, &pv1.signing_message());
    bc.handle_prevote(pv1).expect("canonical prevote accepted");

    let mut pv2 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: "CONFLICTING_HASH".to_string(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv2.sig_bls = sign_bls(&equiv_bls, &pv2.signing_message());
    // The conflicting vote does not count (hash mismatch) but produces evidence and triggers a slash.
    let _ = bc.handle_prevote(pv2);

    // After the slash: the equivocator is jailed (Slashed) and 50% of the stake is cut.
    let after = bc
        .state
        .registry
        .get(&equivocator, roles::VALIDATOR)
        .expect("still present after slash");
    assert!(
        matches!(after.status, MemberStatus::Slashed),
        "the equivocator must be jailed, got: {:?}",
        after.status
    );
    assert_eq!(
        after.stake, 5_000,
        "double-sign %50 kesmeli (10000 -> 5000)"
    );
    // The honest validator is unaffected.
    let honest_reg = bc.state.registry.get(&honest, roles::VALIDATOR).unwrap();
    assert!(matches!(honest_reg.status, MemberStatus::Active));
    assert_eq!(honest_reg.stake, 10_000);
}

// Equivocation -> slash -> KALICILIK (snapshot round-trip)

/// A snapshot is taken AFTER the equivocation is produced and the slash applied
/// (`try_to_bytes`) and restored (`from_snapshot_v2`). It verifies the persistent slashing
/// history record survives and is byte-identical.
#[test]
fn equivocation_slashing_record_survives_snapshot_roundtrip() {
    use crate::chain::snapshot::{StateSnapshotV2, StateSnapshotV2Params};
    use crate::core::account::AccountState;
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
    use crate::registry::evidence::SlashingProof;

    // A BLS-keyed equivocator + an honest producer.
    let mut esk = [0u8; 64];
    esk[0] = 44;
    let equiv_bls = Scalar::from_bytes_wide(&esk);
    let equiv_pk = G2Affine::from(G2Projective::generator() * equiv_bls)
        .to_compressed()
        .to_vec();
    let equivocator = test_addr_from_byte(2u8);
    let honest = test_addr_from_byte(1u8);
    let (honest_bls, honest_pk) = make_test_key(55);

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(equivocator, 10_000);
    install_consensus_keys(&mut bc, honest, &honest_bls, honest_pk);
    install_consensus_keys(&mut bc, equivocator, &equiv_bls, equiv_pk);

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    let mut pv1 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv1.sig_bls = sign_bls(&equiv_bls, &pv1.signing_message());
    bc.handle_prevote(pv1).expect("canonical prevote accepted");

    let mut pv2 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: "CONFLICTING_HASH".to_string(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv2.sig_bls = sign_bls(&equiv_bls, &pv2.signing_message());
    let _ = bc.handle_prevote(pv2);

    // The slash was applied AND written to the persistent history.
    let history_before = bc.state.registry.slashing_history_for(&equivocator);
    assert_eq!(
        history_before.len(),
        1,
        "the equivocation must be written to the persistent history"
    );
    let rec_penalty = history_before[0].penalty;
    let rec_remaining = history_before[0].remaining_stake;
    assert!(matches!(
        history_before[0].report.proof,
        SlashingProof::DoubleSign { .. }
    ));

    // Take a snapshot -> restore it.
    let params = StateSnapshotV2Params {
        height: cp,
        block_hash: block.hash.clone(),
        genesis_hash: "aa".repeat(32),
        chain_id: 45262,
        finalized_height: 0,
        finalized_hash: String::new(),
        finality_certificates: vec![],
    };
    let v2 = StateSnapshotV2::from_state(&bc.state, params);
    let bytes = v2.try_to_bytes().expect("snapshot serialize must succeed");
    let restored = StateSnapshotV2::from_bytes(&bytes).expect("snapshot deserialize");
    let restored_state = AccountState::from_snapshot_v2(&restored);

    // The record survives and is byte-identical.
    let history_after = restored_state.registry.slashing_history_for(&equivocator);
    assert_eq!(
        history_after.len(),
        1,
        "the record must not be lost after restore"
    );
    assert_eq!(history_after[0].report.offender, equivocator);
    assert_eq!(history_after[0].penalty, rec_penalty);
    assert_eq!(history_after[0].remaining_stake, rec_remaining);
    assert!(matches!(
        history_after[0].report.proof,
        SlashingProof::DoubleSign { .. }
    ));
}

// Repeated invalid signatures -> rate-limit based slash

/// A validator sends as many invalid-signature votes as the threshold
/// (`max_invalid_votes_per_epoch`) allows -> a slash is triggered through the end-to-end `handle_prevote` flow.
#[test]
fn repeated_invalid_signatures_trigger_slash() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
    use crate::registry::params::RegistryParams;

    let honest = test_addr_from_byte(1u8);
    let spammer = test_addr_from_byte(2u8);
    // Give the spammer a real BLS key (so it passes the membership check) but let it send
    // an invalid signature.
    let mut ssk = [0u8; 64];
    ssk[0] = 55;
    let spammer_bls = Scalar::from_bytes_wide(&ssk);
    let spammer_pk = G2Affine::from(G2Projective::generator() * spammer_bls)
        .to_compressed()
        .to_vec();

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(spammer, 10_000);
    bc.state
        .validators
        .get_mut(&spammer)
        .unwrap()
        .bls_public_key = spammer_pk;

    // Speed the test up with a small threshold.
    let threshold = 3u64;
    bc.state.registry.set_params(RegistryParams {
        max_invalid_votes_per_epoch: threshold,
        ..RegistryParams::default()
    });

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    // Threshold-1 invalid signatures: no slash yet.
    for _ in 0..(threshold - 1) {
        let bad = Prevote {
            epoch,
            checkpoint_height: cp,
            checkpoint_hash: block.hash.clone(),
            voter_id: spammer,
            sig_bls: vec![0u8; 48], // invalid
        };
        let _ = bc.handle_prevote(bad);
    }
    let mid = bc.state.registry.get(&spammer, roles::VALIDATOR).unwrap();
    assert!(
        matches!(mid.status, MemberStatus::Active),
        "there must be no slash below the threshold"
    );
    assert_eq!(mid.stake, 10_000);

    // An invalid signature past the threshold -> slash.
    let bad = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: spammer,
        sig_bls: vec![0u8; 48],
    };
    let _ = bc.handle_prevote(bad);

    let after = bc.state.registry.get(&spammer, roles::VALIDATOR).unwrap();
    assert!(
        matches!(after.status, MemberStatus::Slashed),
        "crossing the threshold must slash and jail, got: {:?}",
        after.status
    );
    // The MaliciousBehaviour rate is 100% (approved decision): the stake is zeroed.
    assert_eq!(
        after.stake, 0,
        "invalid-sig spam MaliciousBehaviour %100 kesmeli"
    );
    // There is an InvalidSignatureSpam record in the persistent history.
    let hist = bc.state.registry.slashing_history_for(&spammer);
    assert_eq!(hist.len(), 1);
    assert!(matches!(
        hist[0].report.proof,
        crate::registry::evidence::SlashingProof::InvalidSignatureSpam { .. }
    ));
    // The honest validator is unaffected.
    assert!(matches!(
        bc.state
            .registry
            .get(&honest, roles::VALIDATOR)
            .unwrap()
            .status,
        MemberStatus::Active
    ));
}

/// A number of invalid signatures BELOW the threshold does not trigger a slash (false-positive
/// Yok).
#[test]
fn invalid_signatures_below_threshold_do_not_slash() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
    use crate::registry::params::RegistryParams;

    let honest = test_addr_from_byte(1u8);
    let spammer = test_addr_from_byte(2u8);
    let mut ssk = [0u8; 64];
    ssk[0] = 66;
    let spammer_bls = Scalar::from_bytes_wide(&ssk);
    let spammer_pk = G2Affine::from(G2Projective::generator() * spammer_bls)
        .to_compressed()
        .to_vec();

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(spammer, 10_000);
    bc.state
        .validators
        .get_mut(&spammer)
        .unwrap()
        .bls_public_key = spammer_pk;

    let threshold = 5u64;
    bc.state.registry.set_params(RegistryParams {
        max_invalid_votes_per_epoch: threshold,
        ..RegistryParams::default()
    });

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    // Threshold-1 invalid signatures: NO slash.
    for _ in 0..(threshold - 1) {
        let bad = Prevote {
            epoch,
            checkpoint_height: cp,
            checkpoint_hash: block.hash.clone(),
            voter_id: spammer,
            sig_bls: vec![0u8; 48],
        };
        let _ = bc.handle_prevote(bad);
    }

    let reg = bc.state.registry.get(&spammer, roles::VALIDATOR).unwrap();
    assert!(
        matches!(reg.status, MemberStatus::Active),
        "there must be no slash below the threshold"
    );
    assert_eq!(reg.stake, 10_000);
    assert!(bc.state.registry.slashing_history_for(&spammer).is_empty());
    assert_eq!(
        bc.state.invalid_votes.invalid_count(&spammer),
        threshold - 1
    );
}

/// End to end: `Blockchain::handle_prevote` refuses a vote with an invalid BLS
/// signature at ingest - it never enters the aggregate and state does not change.
#[test]
fn blockchain_rejects_invalid_vote_signature_at_ingest() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;

    let mut hsk = [0u8; 64];
    hsk[0] = 33;
    let honest_bls = Scalar::from_bytes_wide(&hsk);
    let honest_pk = G2Affine::from(G2Projective::generator() * honest_bls)
        .to_compressed()
        .to_vec();
    let honest = test_addr_from_byte(1u8);

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.validators.get_mut(&honest).unwrap().bls_public_key = honest_pk;

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    // A vote with an invalid signature -> refused at ingest.
    let bad = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: honest,
        sig_bls: vec![0u8; 48],
    };
    let err = bc
        .handle_prevote(bad)
        .expect_err("garbage sig must be rejected");
    assert!(err.contains("Invalid prevote signature"));
    assert_eq!(
        bc.finality_aggregator.as_ref().unwrap().prevotes.len(),
        0,
        "an invalid vote must not enter the aggregate"
    );
}
