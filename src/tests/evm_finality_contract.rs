//! / F01-F06 regression locks for the Ethereum finality verifier.
//!
//! The Solidity workflow compiles the contract, while these tests pin the
//! security boundaries that are otherwise easy to regress in a source-only
//! repository: immutable key commitments, pending challenge semantics, the
//! pairing gas floor, the cross-language signing-root encoder, and the
//! one-attestation-per-height rule. They are deliberately negative tests:
//! malformed or ambiguous inputs must be refused before any acceptance state
//! can be reached.

use crate::cross_domain::external::evm_hybrid::{
    EvmEncodingError, EvmFinalityAttestation, EvmHybridProof, MessageBinding,
};

fn contract_source() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("contracts/external-domain/BudlumFinalityVerifier.sol"),
    )
    .expect("the quarantined verifier source is present")
}

fn attestation() -> EvmFinalityAttestation {
    EvmFinalityAttestation {
        height: 42,
        state_root: [7; 32],
        epoch: 3,
        budlum_chain_id: 45_261,
        g2_aggregate_pubkey: vec![2; 256],
        g2_generator: vec![3; 256],
        g1_neg_signature: vec![4; 128],
        ml_dsa_signature: vec![5; 3_293],
        ml_dsa_pubkey: vec![6; 1_952],
        ml_dsa_eth_variant: false,
    }
}

#[test]
fn f01_license_and_immutable_key_commitments_are_pinned() {
    let source = contract_source();
    assert!(source.starts_with("// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0"));
    assert!(!source.contains("License: Polyfield"));
    assert!(source.contains("bytes32 public immutable committeePubkeyHash"));
    assert!(source.contains("bytes32 public immutable g2GeneratorHash"));
    assert!(source.contains("bytes32 public immutable mlDsaPubkeyHash"));
    assert!(source.contains("keccak256(a.g2AggregatePubkey) != committeePubkeyHash"));
    assert!(source.contains("keccak256(a.g2Generator) != g2GeneratorHash"));
    assert!(source.contains("keccak256(a.mlDsaPubkey) != mlDsaPubkeyHash"));
    assert!(!source.contains("function setCommittee"));
}

#[test]
fn f02_missing_verifiers_remain_pending_not_accepted() {
    let source = contract_source();
    assert!(source.contains("pendingRootAtHeight[a.height] = a.stateRoot"));
    assert!(source.contains("pendingAttestationAtHeight[a.height] = digest"));
    assert!(source.contains("accepted[digest] = true;\n            rootAtHeight"));
    assert!(source.contains("accepted[digest] = true;\n        rootAtHeight"));
    assert!(source.contains("ChallengeWindowOpen"));
    // The acceptance sentence wraps across the comment's line break in the
    // current source, so it is pinned as the two fragments it is written
    // in; acceptance still happens only in `settle`, when the window
    // closes.
    assert!(source.contains("marked accepted only when the window"));
    assert!(source.contains("closes, via `settle`"));
    // And an attestation neither half could verify never reaches the
    // window at all: the no-precompile chain is refused outright.
    assert!(source.contains("if (!blsOk && !pqOk) {"));
    assert!(source.contains("revert NoVerificationPath();"));
}

#[test]
fn f03_pairing_probe_and_verification_have_a_realistic_gas_floor() {
    let source = contract_source();
    assert!(source.contains("GAS_BLS_PAIRING_PROBE = 150_000"));
    assert!(source.contains("staticcall{gas: GAS_BLS_PAIRING_PROBE}"));
    assert!(source.contains("PRECOMPILE_BLS_PAIRING.staticcall{gas: 400_000}"));
    assert!(source.contains("out.length == 32"));
}

#[test]
fn f04_signing_root_changes_for_every_bound_field() {
    let mut base = attestation();
    let root = base.signing_root(11_155_111);
    let digest = base.attestation_digest();
    base.ml_dsa_pubkey[0] ^= 1;
    assert_ne!(digest, base.attestation_digest());
    base.ml_dsa_pubkey[0] ^= 1;
    base.height += 1;
    assert_ne!(root, base.signing_root(11_155_111));
    base.height -= 1;
    base.epoch += 1;
    assert_ne!(root, base.signing_root(11_155_111));
    base.epoch -= 1;
    base.state_root[0] ^= 1;
    assert_ne!(root, base.signing_root(11_155_111));
    base.state_root[0] ^= 1;
    base.budlum_chain_id += 1;
    assert_ne!(root, base.signing_root(11_155_111));
    assert!(contract_source().contains("bud-finality-signing-root-v1"));
}

#[test]
fn f05_encoder_refuses_compressed_or_missing_points() {
    let mut value = attestation();
    value.g2_generator.truncate(96);
    assert!(matches!(
        value.encode_verify_calldata(11_155_111),
        Err(EvmEncodingError::WrongLength {
            field: "g2_generator",
            ..
        })
    ));
    let mut value = attestation();
    value.ml_dsa_signature.clear();
    assert!(matches!(
        value.encode_verify_calldata(11_155_111),
        Err(EvmEncodingError::WrongLength {
            field: "ml_dsa_signature",
            ..
        })
    ));
    let calldata = attestation()
        .encode_verify_calldata(11_155_111)
        .expect("well-shaped ABI payload");
    assert!(calldata.len() > 4);
    assert!(contract_source().contains("function verify(Attestation calldata a)"));
}

#[test]
fn f06_one_pending_attestation_claims_one_height() {
    let source = contract_source();
    assert!(source.contains("mapping(uint64 => bytes32) public pendingRootAtHeight"));
    assert!(source.contains("mapping(uint64 => bytes32) public pendingAttestationAtHeight"));
    assert!(source.contains("error PendingAttestation"));
    assert!(source.contains("pendingDigest != bytes32(0) && pendingDigest != digest"));
    assert!(source.contains("pendingAttestationAtHeight[c.height] != digest"));
}

#[test]
fn planner_shape_lock_does_not_reintroduce_the_old_local_message_point() {
    let mut proof = EvmHybridProof {
        chain_id: 45_261,
        epoch: 3,
        height: 42,
        state_root: [7; 32],
        g1_hashed_message: vec![1; 128],
        g2_aggregate_pubkey: vec![2; 256],
        g1_generator: vec![3; 128],
        g2_negated_signature: vec![4; 256],
        ml_dsa_public_key: vec![5; 1_952],
        ml_dsa_signature: vec![6; 3_293],
        ml_dsa_variant: crate::cross_domain::external::evm_hybrid::MlDsaVariant::Fips204,
        message_binding: MessageBinding::Unbound,
        calldata_zero_bytes: 0,
        calldata_nonzero_bytes: 0,
    };
    assert!(proof.validate_shape().is_ok());
    proof.g1_hashed_message.clear();
    assert!(proof.validate_shape().is_err());
}
