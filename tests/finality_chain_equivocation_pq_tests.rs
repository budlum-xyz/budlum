//! Adversarial finality tests for chain-id vote binding, equivocating voter
//! exclusion, and ML-DSA precommit attestation verification before slot admission.

use bls12_381::{G2Affine, G2Projective, Scalar};
use budlum_core::chain::finality::{
    pop_signing_message, sign_bls, sign_bls_pop, FinalityAggregator, Precommit, Prevote,
    ValidatorEntry, ValidatorSetSnapshot,
};
use budlum_core::core::address::Address;
use budlum_core::core::transaction::DEFAULT_CHAIN_ID;
use budlum_core::crypto::primitives::PqKeyPair;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn make_key(seed: u8) -> (Scalar, Vec<u8>) {
    let mut sk_bytes = [0u8; 64];
    sk_bytes[0] = seed.saturating_add(1);
    let sk = Scalar::from_bytes_wide(&sk_bytes);
    let pk = G2Affine::from(G2Projective::generator() * sk)
        .to_compressed()
        .to_vec();
    (sk, pk)
}

fn sign_msg(sk: Scalar, msg: &[u8]) -> Vec<u8> {
    sign_bls(&sk, msg)
}

fn make_snapshot_with_keys(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
    let mut sks = Vec::with_capacity(n);
    let validators: Vec<ValidatorEntry> = (0..n)
        .map(|i| {
            let idx = must(u8::try_from(i), "small test index");
            let next = must(u8::try_from(i + 1), "small test index");
            let (sk, pk_bytes) = make_key(idx);
            sks.push(sk);
            let mut addr_bytes = [0u8; 32];
            addr_bytes[0] = next;
            let addr = Address::from(addr_bytes);
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
    (ValidatorSetSnapshot::new(1, validators), sks)
}

fn signed_prevote(
    snap: &ValidatorSetSnapshot,
    sks: &[Scalar],
    idx: usize,
    epoch: u64,
    height: u64,
    hash: &str,
) -> Prevote {
    let mut vote = Prevote {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        chain_id: DEFAULT_CHAIN_ID,
        voter_id: snap.validators[idx].address,
        sig_bls: Vec::new(),
        auth_sig: Vec::new(),
    };
    vote.sig_bls = sign_msg(sks[idx], &vote.signing_message());
    vote
}

/// A vote minted for another chain must be refused even when its BLS signature
/// verifies cleanly for that foreign chain id.
#[test]
fn aggregator_refuses_votes_signed_for_another_chain() {
    let (snap, sks) = make_snapshot_with_keys(4, 1_000);
    let expected = DEFAULT_CHAIN_ID;
    let foreign = expected.saturating_add(1);
    let mut agg = FinalityAggregator::new(expected, 1, 10, "cp_hash".into(), snap.clone());

    let mut prevote = signed_prevote(&snap, &sks, 0, 1, 10, "cp_hash");
    prevote.chain_id = foreign;
    prevote.sig_bls = sign_msg(sks[0], &prevote.signing_message());
    match agg.add_prevote(prevote) {
        Err(err) => assert!(err.contains("aggregator expects"), "got: {err}"),
        Ok(()) => panic!("foreign-chain prevote must not be admitted"),
    }

    let mut precommit = Precommit {
        chain_id: foreign,
        epoch: 1,
        checkpoint_height: 10,
        checkpoint_hash: "cp_hash".into(),
        voter_id: snap.validators[0].address,
        sig_bls: Vec::new(),
        auth_sig: Vec::new(),
        pq_sig: Vec::new(),
    };
    precommit.sig_bls = sign_msg(sks[0], &precommit.signing_message());
    match agg.add_precommit(precommit) {
        Err(err) => assert!(err.contains("aggregator expects"), "got: {err}"),
        Ok(()) => panic!("foreign-chain precommit must not be admitted"),
    }
}

/// Once a voter equivocates across two conflicting hashes, it is excluded from
/// the round and cannot later vote for the canonical checkpoint.
#[test]
fn equivocating_validator_is_excluded_from_finality_round() {
    let (snap, sks) = make_snapshot_with_keys(4, 1_000);
    let mut agg = FinalityAggregator::new(DEFAULT_CHAIN_ID, 1, 10, "cp_hash".into(), snap.clone());

    match agg.add_prevote(signed_prevote(&snap, &sks, 0, 1, 10, "hash_a")) {
        Err(err) => assert!(err.contains("checkpoint hash mismatch"), "got: {err}"),
        Ok(()) => panic!("non-canonical prevote must be refused"),
    }
    match agg.add_prevote(signed_prevote(&snap, &sks, 0, 1, 10, "hash_b")) {
        Err(err) => assert!(err.contains("checkpoint hash mismatch"), "got: {err}"),
        Ok(()) => panic!("second non-canonical prevote must be refused"),
    }
    assert_eq!(agg.detected_equivocations.len(), 1);

    match agg.add_prevote(signed_prevote(&snap, &sks, 0, 1, 10, "cp_hash")) {
        Err(err) => assert!(err.contains("Equivocating"), "got: {err}"),
        Ok(()) => panic!("equivocating voter must be excluded from canonical vote"),
    }
    assert!(agg.prevotes.is_empty());
}

/// A forged ML-DSA PQ attestation on a precommit is rejected before occupying
/// the honest voter slot.
#[test]
fn precommit_with_forged_pq_attestation_is_rejected() {
    let (mut snap, sks) = make_snapshot_with_keys(4, 1_000);
    let pq = PqKeyPair::generate();
    snap.validators[0].pq_public_key = pq.public_key_bytes().to_vec();
    snap.set_hash = ValidatorSetSnapshot::compute_hash(&snap.validators);

    let mut agg = FinalityAggregator::new(DEFAULT_CHAIN_ID, 1, 10, "cp_hash".into(), snap.clone());
    for i in 0..4 {
        must(
            agg.add_prevote(signed_prevote(&snap, &sks, i, 1, 10, "cp_hash")),
            "canonical prevote",
        );
    }
    assert!(agg.prevote_quorum_reached);

    let mut precommit = Precommit {
        chain_id: DEFAULT_CHAIN_ID,
        epoch: 1,
        checkpoint_height: 10,
        checkpoint_hash: "cp_hash".into(),
        voter_id: snap.validators[0].address,
        sig_bls: Vec::new(),
        auth_sig: Vec::new(),
        pq_sig: vec![0x41; 64],
    };
    precommit.sig_bls = sign_msg(sks[0], &precommit.signing_message());
    match agg.add_precommit(precommit) {
        Err(err) => assert!(err.contains("PQ"), "got: {err}"),
        Ok(()) => panic!("forged PQ attestation must be refused"),
    }
    assert!(agg.precommits.is_empty());
}
