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
use crate::domain::storage_deal::{OperatorClass, StorageEconomicsParams, StorageRegistry};
use crate::domain::storage_params::StorageDomainParams;
use crate::storage::ContentManifest;

fn addr(b: u8) -> Address {
    Address([b; 32])
}

fn proof_envelope() -> Vec<u8> {
    let envelope = bud_proof::ProofEnvelope {
        proof_format_version: 1,
        backend: "test-backend".to_string(),
        p3_version: "0.6".to_string(),
        fri_params_id: "test-fri".to_string(),
        public_inputs_hash: [0x42u8; 32],
        proof_bytes: vec![0xAB; 96],
        degree_bits: 8,
    };
    bincode::serialize(&envelope).expect("envelope")
}

#[test]
fn mainnet_bootnode_templates_are_rejected() {
    let peer = "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWCeremonyBootstrap1BudlumMainnetNod0001";
    let boot = vec![peer.to_string()];
    assert!(
        first_placeholder_peer(&boot).is_some(),
        "ceremony template bootnodes must trip the placeholder guard"
    );
    let dns = vec!["_dnsaddr.placeholder-seed-1.mainnet.budlum.network".to_string()];
    assert!(first_placeholder_peer(&dns).is_some());
}

#[test]
fn mainnet_pkcs11_requires_a_module_path() {
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
        "a mainnet validator without a PKCS11 module must not start"
    );
}

#[test]
fn proof_required_models_are_refused_without_a_live_verifier() {
    const {
        assert!(
            !FULL_AI_STARK_VERIFICATION_LIVE,
            "activation requires an AIR that binds memory and Fiat-Shamir"
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
        .expect_err("proof-required models are refused while verification is unavailable");
    assert!(err.contains("full AI STARK"), "{err}");
}

#[test]
fn mainnet_inference_and_merkle_features_stay_closed() {
    let d = bud_isa::MainnetActivation::default();
    assert!(!d.verify_merkle_enabled, "Merkle verification remains disabled");
    assert!(!d.verify_inference_enabled, "inference verification remains disabled");
    assert!(
        !StorageRegistry::storage_challenge_proofs_are_checkable(),
        "enabling an unverifiable challenge proof could slash honest operators"
    );
    let toml = include_str!("../../config/mainnet.toml");
    assert!(
        toml.contains("verify_merkle = false"),
        "the checked-in mainnet profile keeps the gate closed"
    );
}

#[test]
fn inference_grants_bind_the_requester() {
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
    assert_eq!(grant.grantee, requester, "grantee is the requester");
    assert_eq!(grant.payer, requester, "payer is the requester");
    assert!(grant.is_active_for(&requester, 1));
    assert!(
        !grant.is_active_for(&addr(3), 1),
        "operator is not the grantee"
    );
}

#[test]
fn operator_wide_challenge_limit_is_enforced() {
    let mut reg = StorageRegistry::new();
    let params = StorageDomainParams {
        chunk_size: 256,
        max_committed_chunks: 1000,
        challenge_interval: 10,
        min_operator_bond: 1,
    };
    let econ = StorageEconomicsParams {
        operator_bond: 5_000_000,
        fee_per_byte_epoch: 100,
    };
    let operator = addr(1);
    let opener = addr(2);
    // One challenge per manifest so the (operator, manifest) interval never
    // fires. The operator ceiling must still trip.
    let mut last_deal;
    for i in 0..=StorageRegistry::MAX_OPEN_CHALLENGES_PER_OPERATOR {
        let mut bytes = b"challenge-manifest-xxxxxxxxxxxxxxxx".to_vec();
        bytes.extend_from_slice(&i.to_le_bytes());
        let manifest = ContentManifest::from_bytes_sliced(&bytes, 8).unwrap();
        last_deal = reg
            .open_deal(
                1,
                &manifest,
                manifest.shards[0].shard_id,
                operator,
                0,
                10,
                200,
                econ.clone(),
                &params,
                Some(proof_envelope()),
                Some([0x42; 32]),
            )
            .unwrap();
        let result = reg.open_challenge(last_deal, 0, 4, 20, 30, opener, 50);
        if i < StorageRegistry::MAX_OPEN_CHALLENGES_PER_OPERATOR {
            result.unwrap_or_else(|e| panic!("challenge {i} should open: {e:?}"));
        } else {
            assert!(
                matches!(
                    result,
                    Err(
                        crate::domain::storage_deal::StorageError::TooManyOpenChallengesPerOperator { .. }
                    )
                ),
                "expected the operator-wide challenge limit, got {result:?}"
            );
        }
    }
}

#[test]
fn mobile_storage_operators_cannot_hold_primary_assignments() {
    let mut reg = StorageRegistry::new();
    assert_eq!(reg.operator_class(&addr(1)), OperatorClass::AlwaysOn);
    reg.set_operator_class(addr(1), OperatorClass::Mobile);
    assert!(!reg.operator_class(&addr(1)).may_hold_primary());
}

#[test]
fn mainnet_bond_floor_exceeds_the_unit_rate() {
    assert!(
        StorageRegistry::MAINNET_MIN_OPENER_BOND
            > StorageRegistry::required_opener_bond(16 * 1024 * 1024),
        "mainnet floor must exceed the uncalibrated 1-unit-per-KiB rate"
    );
}

#[test]
fn container_healthcheck_uses_jsonrpc() {
    let docker = include_str!("../../ops/Dockerfile");
    assert!(
        docker.contains("bud_netListening"),
        "image healthcheck must POST a JSON-RPC method, not GET /"
    );
    assert!(
        !docker.contains("http://localhost:8545/"),
        "bare GET of the public RPC path is not a health probe"
    );
    assert!(
        docker.contains("127.0.0.1:8545"),
        "default image binds the public listener, not the opt-in operator port"
    );
}

#[test]
fn maintenance_hash_domain_is_inventoried() {
    assert!(
        crate::crypto::DOMAIN_TAGS.contains(&"BDLM_MAINTENANCE_CODING_AUDIT_V1"),
        "a new hash domain must be listed before it ships"
    );
}

#[test]
fn operator_class_changes_only_through_a_block_transaction() {
    let tx_src = include_str!("../domain/storage_tx.rs");
    assert!(tx_src.contains("DeclareOperatorClass"));
    let actor = include_str!("../chain/chain_actor.rs");
    assert!(
        !actor.contains("SetStorageOperatorClass"),
        "the class changes only through a signed transaction in a block"
    );
}

#[test]
fn readiness_does_not_claim_stark_verification() {
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
