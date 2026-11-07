//! Locks for the twenty highest-priority source-code review findings.
//!
//! Several findings were already fail-closed. These tests pin the remaining
//! holes closed here; names the findings that remain
//! fail-closed rather than pretending a missing AIR is now live.

use crate::ai::types::{AiModelId, AiModelSpec};
use crate::ai::{AiRegistry, FULL_AI_STARK_VERIFICATION_LIVE};
use crate::core::address::Address;
use crate::core::chain_config::first_placeholder_peer;
use crate::crypto::mainnet_policy::{
    check_mainnet_validator_key_policy, MainnetKeyPolicyViolation, MainnetValidatorKeyConfig,
};

fn addr(b: u8) -> Address {
    Address([b; 32])
}

#[test]
fn f01_checked_in_mainnet_bootnodes_are_placeholders() {
    let peer = "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWCeremonyBootstrap1BudlumMainnetNod0001";
    let boot = vec![peer.to_string()];
    assert!(
        first_placeholder_peer(&boot).is_some(),
        "F-01: ceremony template bootnodes must trip the placeholder guard"
    );
    let dns = vec!["_dnsaddr.placeholder-seed-1.mainnet.budlum.network".to_string()];
    assert!(first_placeholder_peer(&dns).is_some());
}

#[test]
fn f02_mainnet_toml_without_pkcs11_section_is_refused() {
    let cfg = MainnetValidatorKeyConfig {
        signer_backend: Some("pkcs11"),
        raw_signer_backend: Some("pkcs11"),
        validator_key_file: None,
        pkcs11_module_path: None,
        pkcs11_token_pin_env: None,
        resolve_pin_env: false,
    };
    assert_eq!(
        check_mainnet_validator_key_policy(&cfg),
        Err(MainnetKeyPolicyViolation::MissingPkcs11ModulePath),
        "F-02: a mainnet validator with only [validator] backend=pkcs11 and no module must not start"
    );
}

#[test]
fn f03_f04_f07_proof_required_models_cannot_register() {
    const {
        assert!(
            !FULL_AI_STARK_VERIFICATION_LIVE,
            "F-03: flipping this without an AIR that binds memory (F-08) and Fiat-Shamir (F-09) reopens the finding"
        );
    };
    let mut reg = AiRegistry::new();
    let err = reg
        .register_model(AiModelSpec {
            model_id: AiModelId([1u8; 32]),
            model_hash: [2u8; 32],
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
            owner: addr(3),
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 64,
            max_output_ref_bytes: 64,
            request_deadline_blocks: 10,
            result_deadline_blocks: 10,
            version: 1,
            active: true,
            require_execution_proof: true,
            execution_program_hash: Some([4u8; 32]),
            execution_class: 1,
            execution_weights_digest: Some([5u8; 32]),
            execution_dims: Some(vec![2, 1]),
        })
        .expect_err("F-04");
    assert!(err.contains("full AI STARK"), "{err}");
}

#[test]
fn f06_f13_verify_inference_and_merkle_stay_closed() {
    let d = bud_isa::MainnetActivation::default();
    assert!(!d.verify_merkle_enabled, "F-13");
    assert!(!d.verify_inference_enabled, "F-06");
    let toml = include_str!("../../config/mainnet.toml");
    assert!(
        toml.contains("verify_merkle = false"),
        "F-13: checked-in mainnet profile must not advertise an open gate"
    );
}

#[test]
fn f12_grant_builder_is_requester_bound() {
    let owner = addr(2);
    let requester = addr(9);
    let grant = crate::ai_inference::build_ai_inference_grant(
        crate::pollen::AssetId([1; 32]),
        owner,
        requester,
        10,
        0,
        100,
        3,
        [0; 32],
    );
    assert_eq!(grant.grantee, requester, "F-12: grantee is the requester");
    assert_eq!(grant.payer, requester, "F-12: payer is the requester");
    assert!(grant.is_active_for(&requester, 1));
    assert!(
        !grant.is_active_for(&addr(3), 1),
        "operator is not the grantee"
    );
}

#[test]
fn f20_dockerfile_healthcheck_is_jsonrpc() {
    let docker = include_str!("../../ops/Dockerfile");
    assert!(
        docker.contains("bud_netListening"),
        "F-20: image healthcheck must POST a JSON-RPC method, not GET /"
    );
    assert!(
        !docker.contains("http://localhost:8545/"),
        "F-20: bare GET of the public RPC path is not a health probe"
    );
    assert!(
        docker.contains("127.0.0.1:8545"),
        "F-20: default image binds the public listener, not the opt-in operator port"
    );
}

#[test]
fn f05_readiness_does_not_claim_stark_verification() {
    let src = include_str!("../rpc/server.rs");
    assert!(src.contains("structural_envelope_checks_only"));
    assert!(src.contains("verification_level"));
    assert!(src.contains("full_execution_proof_verification"));
}

/// The recorded program hash has to match the program the recorded dimensions
/// produce.
///
/// `execution_program_hash` and `execution_dims` are supplied separately. At
/// verification time the program is **rebuilt from the dims** and the proof is
/// measured against the recorded hash; if the two disagree, no valid proof can
/// ever pass for that model.
///
/// This is not a forgery hole - the AI path takes the program from the record
/// rather than from the submitter, so it is fail-closed. It is a silent trap: it
/// surfaces the mistake not at the record itself but much later, at
/// verification. It has to be refused at its source.
#[test]
fn a_model_hash_that_contradicts_its_dims_is_refused() {
    let mut reg = AiRegistry::new();
    let err = reg
        .register_model(AiModelSpec {
            model_id: AiModelId([9u8; 32]),
            model_hash: [2u8; 32],
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
            owner: addr(3),
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 64,
            max_output_ref_bytes: 64,
            request_deadline_blocks: 10,
            result_deadline_blocks: 10,
            version: 1,
            active: true,
            // A proof is NOT required here: the point is to reach this gate
            // without getting caught on the gate.
            require_execution_proof: false,
            // This hash is not the hash of the program the dimensions below produce.
            execution_program_hash: Some([4u8; 32]),
            execution_class: 1,
            execution_weights_digest: Some([5u8; 32]),
            execution_dims: Some(vec![2, 1]),
        })
        .expect_err("an inconsistent hash/dims pair has to be refused");
    assert!(
        err.contains("does not match the program execution_dims build"),
        "the reason has to say that the hash and the dims disagree, got: {err}"
    );
}

/// Control: a consistent pair is accepted.
///
/// It shows that the gate refuses only the wrong case and does not also refuse
/// the right one -
/// otherwise "refuse everything" would count as a gate too.
#[test]
fn a_model_hash_that_matches_its_dims_registers() {
    let dims = vec![2u16, 1];
    let spec_for_hash = crate::ai::execution::FixedPointMlpSpec {
        dims: dims.clone(),
        weights: vec![0i32; 2],
        biases: vec![0i32; 1],
    };
    let expected = crate::ai::execution::matmul_program_hash(&spec_for_hash)
        .expect("the program hash has to be producible");

    let mut reg = AiRegistry::new();
    reg.register_model(AiModelSpec {
        model_id: AiModelId([10u8; 32]),
        model_hash: [2u8; 32],
        modalities: crate::ai_inference::perception::ModalitySet::text_only(),
        owner: addr(3),
        min_verifier_count: 1,
        agreement_threshold: 1,
        max_input_ref_bytes: 64,
        max_output_ref_bytes: 64,
        request_deadline_blocks: 10,
        result_deadline_blocks: 10,
        version: 1,
        active: true,
        require_execution_proof: false,
        execution_program_hash: Some(expected),
        execution_class: 1,
        execution_weights_digest: Some([5u8; 32]),
        execution_dims: Some(dims),
    })
    .expect("a consistent pair has to be accepted");
}
