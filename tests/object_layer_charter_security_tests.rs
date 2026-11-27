//! Security regression tests for object-layer domain charter bytecode hash pinning.

use budlum_core::object_layer::charter::{
    check_charter, check_charter_at_state_root, CanonicalCodeHashes, CharterRefusal, CharterStatus,
    CodeProof, DataPolicy, DomainCharter, HomeCodeStateProof,
};
use budlum_core::object_layer::family::HomeVmFamily;

fn sample_evm_charter(endpoint_hash: [u8; 32], verifier_hash: [u8; 32]) -> DomainCharter {
    DomainCharter {
        vm_family: HomeVmFamily::Evm,
        chain_reference: "eip155:11155111".to_string(),
        address_prefix: String::new(),
        endpoint: vec![0x11; 20],
        endpoint_code_hash: endpoint_hash,
        verifier: vec![0x22; 20],
        verifier_code_hash: verifier_hash,
        upgrade_notice: 3600,
        silence_window: 86_400,
        data_policy: DataPolicy::Public,
        status: CharterStatus::Active,
        operator: None,
    }
}

#[test]
fn charter_refuses_all_zero_endpoint_or_verifier_code_hashes() {
    let valid_hash = [0xAA; 32];

    let zero_endpoint = sample_evm_charter([0u8; 32], valid_hash);
    let proof_zero_ep = CodeProof {
        endpoint_code_hash: [0u8; 32],
        verifier_code_hash: valid_hash,
        home_proof: None,
    };
    let canonical_zero_ep = CanonicalCodeHashes {
        endpoint: [0u8; 32],
        verifier: valid_hash,
    };
    assert_eq!(
        check_charter(
            &zero_endpoint,
            &proof_zero_ep,
            Some(&canonical_zero_ep),
            true
        ),
        Err(CharterRefusal::NotCanonicalEndpoint),
        "all-zero endpoint code hash must never be accepted even if canonical table is zero"
    );

    let zero_verifier = sample_evm_charter(valid_hash, [0u8; 32]);
    let proof_zero_ver = CodeProof {
        endpoint_code_hash: valid_hash,
        verifier_code_hash: [0u8; 32],
        home_proof: None,
    };
    let canonical_zero_ver = CanonicalCodeHashes {
        endpoint: valid_hash,
        verifier: [0u8; 32],
    };
    assert_eq!(
        check_charter(
            &zero_verifier,
            &proof_zero_ver,
            Some(&canonical_zero_ver),
            true
        ),
        Err(CharterRefusal::NotCanonicalVerifier),
        "all-zero verifier code hash must never be accepted even if canonical table is zero"
    );
}

#[test]
fn charter_refuses_all_zero_home_state_root() {
    let ep_hash = [0xAA; 32];
    let ver_hash = [0xBB; 32];
    let charter = sample_evm_charter(ep_hash, ver_hash);
    let canonical = CanonicalCodeHashes {
        endpoint: ep_hash,
        verifier: ver_hash,
    };
    let proof = CodeProof {
        endpoint_code_hash: ep_hash,
        verifier_code_hash: ver_hash,
        home_proof: Some(HomeCodeStateProof {
            state_root: [0u8; 32],
            endpoint_proof: Vec::new(),
            verifier_proof: Vec::new(),
        }),
    };

    let res =
        check_charter_at_state_root(&charter, &proof, Some(&canonical), true, Some([0u8; 32]));
    assert_eq!(
        res,
        Err(CharterRefusal::ProofDisagrees),
        "all-zero home state_root must fail closed"
    );
}
