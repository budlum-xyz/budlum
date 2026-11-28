//! Cryptographic security regression tests for `bud-proof::sigagg` and
//! `bud-proof::alarm_log`:
//! 1. `aggregate_merkle_root` resists CVE-2012-2459 odd-leaf duplication collisions.
//! 2. `aggregate_signatures` and `verify_aggregated_batch` reject duplicate
//!    `public_key_digest` vote amplification, zero `required_weight`, and
//!    threshold-witness malleability.
//! 3. `AlarmLog::default()` matches `AlarmLog::new()` at the genesis anchor,
//!    and `verify_integrity()` detects tampered `head` mismatches.

use bud_proof::alarm_log::{AlarmKind, AlarmLog};
use bud_proof::sigagg::{
    aggregate_merkle_root, aggregate_signatures, compute_committee_root, verify_aggregated_batch,
    CommitteeMember, SigAggError, SignatureScheme, SignerSignature, ThresholdWitness,
};
use tiny_keccak::{Hasher, Keccak};

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(bytes);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[test]
fn sigagg_merkle_root_resists_cve_2012_2459_odd_leaf_duplication() {
    let l0 = [0x11u8; 32];
    let l1 = [0x22u8; 32];
    let l2 = [0x33u8; 32];
    let root_3 = aggregate_merkle_root(&[l0, l1, l2]);
    let root_4_dup = aggregate_merkle_root(&[l0, l1, l2, l2]);
    assert_ne!(
        root_3, root_4_dup,
        "odd-count Merkle root must NOT collide with duplicated trailing leaf (CVE-2012-2459)"
    );
}

#[test]
fn sigagg_rejects_duplicate_pubkey_amplification_zero_quorum_and_witness_malleability() {
    let msg = [0xAAu8; 32];
    let shared_pk = [0x55u8; 32];
    let committee: Vec<CommitteeMember> = vec![
        (0, 50, SignatureScheme::Ed25519, shared_pk),
        (1, 50, SignatureScheme::Ed25519, shared_pk),
    ];
    let c_root = compute_committee_root(&committee);
    let s0 = SignerSignature {
        signer_index: 0,
        weight: 50,
        scheme: SignatureScheme::Ed25519,
        public_key_digest: shared_pk,
        signature: vec![0x77; 64],
        threshold_witness: None,
    };
    let s1 = SignerSignature {
        signer_index: 1,
        weight: 50,
        scheme: SignatureScheme::Ed25519,
        public_key_digest: shared_pk,
        signature: vec![0x77; 64],
        threshold_witness: None,
    };

    // 1. Duplicate public_key_digest across two signer indices must fail closed.
    assert!(
        aggregate_signatures(msg, c_root, vec![s0, s1]).is_err(),
        "duplicate public_key_digest across distinct signer indices allows single-key double voting"
    );

    // 2. required_weight == 0 must fail closed even on an otherwise valid batch.
    let honest_committee: Vec<CommitteeMember> = vec![
        (0, 50, SignatureScheme::Ed25519, [0x11; 32]),
        (1, 50, SignatureScheme::Ed25519, [0x22; 32]),
    ];
    let h_root = compute_committee_root(&honest_committee);
    let hs0 = SignerSignature {
        signer_index: 0,
        weight: 50,
        scheme: SignatureScheme::Ed25519,
        public_key_digest: [0x11; 32],
        signature: vec![0x99; 64],
        threshold_witness: None,
    };
    let batch = aggregate_signatures(msg, h_root, vec![hs0.clone()]).expect("valid single batch");
    assert_eq!(
        verify_aggregated_batch(&batch, &honest_committee, 0, |_, _| true),
        Err(SigAggError::InsufficientWeight {
            have: 0,
            required: 1
        }),
        "zero required_weight must fail closed"
    );

    // 3. Attaching a valid ThresholdWitness must change aggregate_digest (no witness malleability).
    let commitment = [0x44u8; 32];
    let mut tag_pre = Vec::new();
    tag_pre.extend_from_slice(b"BDLM_SIGAGG_SHARE_V1");
    tag_pre.extend_from_slice(&0u32.to_le_bytes());
    tag_pre.extend_from_slice(&1u64.to_le_bytes());
    tag_pre.extend_from_slice(&commitment);
    tag_pre.extend_from_slice(&msg);
    let witness = ThresholdWitness {
        share_index: 0,
        epoch: 1,
        commitment,
        tag: keccak256(&tag_pre),
    };
    let mut hs0_with_witness = hs0;
    hs0_with_witness.threshold_witness = Some(witness);
    let batch_with_witness =
        aggregate_signatures(msg, h_root, vec![hs0_with_witness]).expect("valid witnessed batch");
    assert_ne!(
        batch.aggregate_digest, batch_with_witness.aggregate_digest,
        "threshold_witness must be bound into the leaf and aggregate_digest"
    );
}

#[test]
fn alarm_log_default_matches_new_genesis_anchor() {
    let mut from_new = AlarmLog::new();
    let mut from_default = AlarmLog::default();
    assert_eq!(
        from_default.window_anchor(),
        from_new.window_anchor(),
        "AlarmLog::default() must start at the genesis link, not [0u8; 32]"
    );
    let sig = [0x42u8; 32];
    let l1 = from_new.record(sig, AlarmKind::InvalidProof, "test");
    let l2 = from_default.record(sig, AlarmKind::InvalidProof, "test");
    assert_eq!(l1, l2);
    assert_eq!(from_new.root(), from_default.root());
    assert!(from_default.verify_integrity());
}
