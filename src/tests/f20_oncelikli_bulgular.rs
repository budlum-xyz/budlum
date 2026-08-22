//! Locks for the 20-priority source-code review (workspace, 13 Aug 2026).
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
            modalities: crate::lubot::perception::ModalitySet::text_only(),
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
    assert!(
        !StorageRegistry::storage_challenge_proofs_are_checkable(),
        "F-13: turning this on slashes honest operators"
    );
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
    let grant = crate::lubot::build_lubot_inference_grant(
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
fn f18_operator_wide_challenge_ceiling() {
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
        let mut bytes = b"f18-manifest-xxxxxxxxxxxxxxxx".to_vec();
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
                "F-18: expected operator ceiling, got {result:?}"
            );
        }
    }
}

#[test]
fn f17_mobile_class_is_enforced_once_declared() {
    let mut reg = StorageRegistry::new();
    assert_eq!(reg.operator_class(&addr(1)), OperatorClass::AlwaysOn);
    reg.set_operator_class(addr(1), OperatorClass::Mobile);
    assert!(!reg.operator_class(&addr(1)).may_hold_primary());
}

#[test]
fn f19_mainnet_bond_floor_is_above_the_unit_rate() {
    assert!(
        StorageRegistry::MAINNET_MIN_OPENER_BOND
            > StorageRegistry::required_opener_bond(16 * 1024 * 1024),
        "F-19: mainnet floor must dominate the uncalibrated 1-unit-per-KiB rate"
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
fn f15_maintenance_audit_tag_is_inventoried() {
    assert!(
        crate::crypto::DOMAIN_TAGS.contains(&"BDLM_MAINTENANCE_CODING_AUDIT_V1"),
        "F-15: a new hash domain must be listed before it ships"
    );
}

#[test]
fn f17_class_command_cannot_name_a_third_party() {
    let src = include_str!("../chain/chain_actor.rs");
    assert!(src.contains("set_storage_operator_class"));
    assert!(
        src.contains("no validator key is loaded"),
        "F-17: the actor must refuse when it has no local signer"
    );
}

#[test]
fn f05_readiness_does_not_claim_stark_verification() {
    let src = include_str!("../rpc/server.rs");
    assert!(src.contains("structural_envelope_checks_only"));
    assert!(src.contains("verification_level"));
    assert!(src.contains("full_execution_proof_verification"));
}

/// Kaydedilen program hash'i, kaydedilen boyutlarin urettigi programa uymali.
///
/// `execution_program_hash` ile `execution_dims` ayri ayri veriliyor. Dogrulama
/// zamaninda program **dims'ten yeniden kuruluyor** ve kanit kaydedilen hash'e
/// karsi olculuyor; ikisi ayrisirsa hicbir gecerli kanit o modeli gecemez.
///
/// Bu bir sahtecilik acigi degildir - AI yolu programi gonderenden degil
/// kayittan alir, dolayisiyla fail-closed. Sessiz bir tuzaktir: hatayi
/// kaydin kendisinde degil, cok sonra dogrulamada gosterir. Kaynaginda
/// reddedilmesi gerekir.
#[test]
fn a_model_hash_that_contradicts_its_dims_is_refused() {
    let mut reg = AiRegistry::new();
    let err = reg
        .register_model(AiModelSpec {
            model_id: AiModelId([9u8; 32]),
            model_hash: [2u8; 32],
            modalities: crate::lubot::perception::ModalitySet::text_only(),
            owner: addr(3),
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 64,
            max_output_ref_bytes: 64,
            request_deadline_blocks: 10,
            result_deadline_blocks: 10,
            version: 1,
            active: true,
            // Kanit zorunlu DEGIL: F-04 kapisina takilmadan bu kapiya gelinsin.
            require_execution_proof: false,
            // Bu hash, asagidaki boyutlarin urettigi programin hash'i degil.
            execution_program_hash: Some([4u8; 32]),
            execution_class: 1,
            execution_weights_digest: Some([5u8; 32]),
            execution_dims: Some(vec![2, 1]),
        })
        .expect_err("tutarsiz hash/dims cifti reddedilmeli");
    assert!(
        err.contains("does not match the program execution_dims build"),
        "gerekce hash ile dims'in ayristigini soylemeli, gelen: {err}"
    );
}

/// Kontrol: tutarli cift kabul edilir.
///
/// Kapinin yalnizca yanlisi reddettigini, dogruyu da reddetmedigini gosterir -
/// yoksa "her seyi reddet" de bir kapi sayilirdi.
#[test]
fn a_model_hash_that_matches_its_dims_registers() {
    let dims = vec![2u16, 1];
    let spec_for_hash = crate::ai::execution::FixedPointMlpSpec {
        dims: dims.clone(),
        weights: vec![0i32; 2],
        biases: vec![0i32; 1],
    };
    let expected = crate::ai::execution::matmul_program_hash(&spec_for_hash)
        .expect("program hash uretilebilmeli");

    let mut reg = AiRegistry::new();
    reg.register_model(AiModelSpec {
        model_id: AiModelId([10u8; 32]),
        model_hash: [2u8; 32],
        modalities: crate::lubot::perception::ModalitySet::text_only(),
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
    .expect("tutarli cift kabul edilmeli");
}
