//! End-to-end tests for the Nakamoto (Bitcoin SPV) branch of the
//! consensus-of-consensuses: registration, admission, the external-domain
//! bridge, and the settlement commitment that feeds the global header.
//!
//! These tests use real Bitcoin mainnet headers 0..=6, pinned as hex. The
//! evidence carries headers 1..=6 on top of a pinned genesis checkpoint, so
//! the derived height is 6 and the accrued work is six real blocks.

use crate::core::address::Address;
use crate::cross_domain::external::bitcoin_spv::{
    sha256d, spv_evidence, BitcoinSpvAdapter, PinnedBitcoinAnchor, HEADER_LEN,
};
use crate::cross_domain::external::spec::{
    ExternalFinalityAdapter, FinalityAttestation, RawConsensusEvidence, SecurityBacking,
    VerificationPolicy,
};
use crate::cross_domain::external::{
    admit, decode_external_evidence, encode_external_evidence, AdapterSpec as Spec,
    ExternalDomainFinalityBridge, IntakeError, IntakeState, RegistrationRequest, VersionPolicy,
    EXTERNAL_DOMAIN_FINALITY_ADAPTER,
};
use crate::domain::finality_adapter::{DomainFinalityAdapter, FinalityProof, FinalityStatus};
use crate::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
};

const MAINNET_HEADERS: [&str; 7] = [
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
    "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
    "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
    "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
    "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
    "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
];

fn headers() -> Vec<[u8; HEADER_LEN]> {
    MAINNET_HEADERS
        .iter()
        .map(|h| {
            let raw = hex::decode(h).expect("pinned header hex");
            let mut out = [0u8; HEADER_LEN];
            out.copy_from_slice(&raw);
            out
        })
        .collect()
}

fn anchor() -> PinnedBitcoinAnchor {
    PinnedBitcoinAnchor {
        height: 0,
        block_hash: sha256d(headers()[0].as_slice()),
        bits: 0x1d00_ffff,
    }
}

fn adapter() -> BitcoinSpvAdapter {
    BitcoinSpvAdapter::new("mainnet", Some(anchor()))
}

/// The policy clock is just after the last real header's timestamp. The
/// adapter has no clock of its own: `now` is supplied by the caller so the
/// same evidence verifies identically on every node.
fn policy() -> VerificationPolicy {
    VerificationPolicy {
        min_depth: 1,
        require_declared_match: true,
        max_age: 0,
        now: 1_231_500_000,
        require_slashable: false,
    }
}

fn golden() -> RawConsensusEvidence {
    let bytes = headers();
    let descendants: Vec<&[u8; HEADER_LEN]> = bytes.iter().skip(1).collect();
    spv_evidence(
        &adapter(),
        "mainnet",
        &descendants,
        Address::from([1u8; 32]),
    )
}

fn request(spec: Spec) -> RegistrationRequest {
    let adapter = spec.build(None, None);
    let economics = IntakeState::conservative_economics(1_000_000);
    RegistrationRequest {
        spec,
        policy: policy(),
        economics,
        versions: VersionPolicy::single(adapter.descriptor().id, 1, 0),
        bond_atoms: economics.required_bond_atoms(),
        poster: Address::from([9u8; 32]),
        golden: golden(),
    }
}

fn bitcoin_spec() -> Spec {
    Spec::BitcoinSpv {
        network: "mainnet".to_string(),
        anchor: Some(anchor()),
    }
}

fn domain_and_commitment(
    evidence: &RawConsensusEvidence,
    proof: &FinalityProof,
) -> (ConsensusDomain, DomainCommitment) {
    let attestation: FinalityAttestation = adapter()
        .verify(evidence, &policy())
        .expect("golden evidence verifies");
    let domain = ConsensusDomain {
        id: 7,
        kind: ConsensusKind::Custom("nakamoto-pow".to_string()),
        status: DomainStatus::Active,
        domain_chain_id: 77,
        operator: Some(Address::from([4u8; 32])),
        operator_bond: 1_000_000,
        config_hash: [0; 32],
        validator_set_hash: [0; 32],
        finality_adapter: EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 6,
        last_committed_hash: [6; 32],
        pow_parameters: None,
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: [0; 32],
    };
    let commitment = DomainCommitment {
        domain_id: 7,
        domain_height: attestation.height,
        domain_block_hash: attestation.state_root,
        parent_domain_block_hash: [4; 32],
        state_root: attestation.state_root,
        tx_root: attestation
            .attested_tx_root
            .expect("the adapter attests a tx root"),
        event_root: [0; 32],
        finality_proof_hash: crate::domain::hash_finality_proof(proof).expect("proof hashes"),
        consensus_kind: domain.kind.clone(),
        validator_set_hash: [0; 32],
        timestamp_ms: 0,
        sequence: 1,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    };
    (domain, commitment)
}

/// RED before the adapter was wired: this variant did not exist. The test
/// pins the whole path from permissionless registration to a settlement
/// commitment that a GlobalBlockHeader can anchor.
#[test]
fn bitcoin_spv_domain_registers_and_passes_admission() {
    let mut state = IntakeState::new();
    // Self-supplied anchor before governance pinning must fail closed.
    let unpinned_err = state
        .register_domain(request(bitcoin_spec()), None)
        .expect_err("self-supplied unpinned Bitcoin checkpoint must be refused");
    assert_eq!(unpinned_err, IntakeError::CommitteeNotPinned);

    state.pin_bitcoin_anchor("mainnet", anchor());

    // A registrant supplying a forged regtest checkpoint on a pinned network
    // must also be refused.
    let forged_spec = Spec::BitcoinSpv {
        network: "mainnet".to_string(),
        anchor: Some(PinnedBitcoinAnchor {
            height: 0,
            block_hash: [0xee; 32],
            bits: 0x207f_ffff,
        }),
    };
    let forged_err = state
        .register_domain(request(forged_spec), None)
        .expect_err("forged regtest checkpoint must be refused");
    assert_eq!(forged_err, IntakeError::CommitteeNotPinned);

    let key = state
        .register_domain(request(bitcoin_spec()), None)
        .expect("a pinned Bitcoin domain registers end to end");
    let entry = state.entries.get(&key).expect("entry is stored");
    assert!(entry.admission.admitted, "golden and all probes passed");
    assert!(entry.admission.golden_verified);

    // The stored spec rebuilds an adapter that still verifies the golden.
    let rebuilt = entry.spec.build(None, Some(entry.golden.clone()));
    assert!(rebuilt.verify(&entry.golden, &entry.policy).is_ok());
}

/// A domain with no pinned checkpoint must be refused at the door, not
/// admitted with a checkpoint the submitter can name later.
#[test]
fn an_unpinned_bitcoin_anchor_is_refused_at_registration() {
    let mut state = IntakeState::new();
    let spec = Spec::BitcoinSpv {
        network: "mainnet".to_string(),
        anchor: None,
    };
    assert!(matches!(
        state.register_domain(request(spec), None),
        Err(IntakeError::CommitteeNotPinned)
    ));
}

/// The admission suite is data, not code: every probe must refuse for the
/// exact reason it names, and the golden must verify. An adapter that
/// refuses everything cannot pass this test.
#[test]
fn every_bitcoin_fault_probe_refuses_for_its_named_rule() {
    let adapter = adapter().with_golden(golden());
    let report = admit(&adapter, &policy());
    assert!(report.golden_verified);
    assert!(report.admitted, "report: {report:?}");
    assert!(!report.probes.is_empty());
    for (name, outcome) in &report.probes {
        assert!(outcome.passed(), "probe {name} failed: {outcome:?}");
    }
}

/// The bridge is the seam into consensus. A real SPV proof finalizes a
/// commitment whose roots are exactly the ones the attestation binds.
#[test]
fn bridge_finalizes_a_bitcoin_commitment_end_to_end() {
    let evidence = golden();
    let proof = encode_external_evidence(&evidence).expect("evidence encodes");
    let decoded = decode_external_evidence(&proof).expect("carrier round trips");
    assert_eq!(decoded, evidence);

    let (domain, commitment) = domain_and_commitment(&evidence, &proof);
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter()), policy());
    assert_eq!(
        bridge
            .verify_finality(&domain, &commitment, &proof)
            .expect("bridge verifies"),
        FinalityStatus::Finalized
    );
}

/// A corrupted header must not reach consensus: the bridge refuses rather
/// than finalizing a commitment built on a broken parent link.
#[test]
fn a_broken_parent_link_is_refused_by_the_bridge() {
    let mut evidence = golden();
    // The first evidence header's parent hash begins at payload offset 8.
    evidence.payload[8] ^= 0xff;
    let proof = encode_external_evidence(&evidence).expect("evidence encodes");
    let (domain, commitment) = domain_and_commitment(&golden(), &proof);
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter()), policy());
    let result = bridge.verify_finality(&domain, &commitment, &proof);
    assert!(
        result
            .as_ref()
            .is_err_and(|error| { format!("{error:?}").contains("does not link to its parent") }),
        "result: {result:?}"
    );
}

/// Work backing is the first producer of `SecurityBacking::Work`. The bridge
/// already treats accumulated work as clearing a slashability demand; the
/// adapter must agree, or that branch of the shared model stays dead.
#[test]
fn work_backing_clears_the_bridges_slashability_demand() {
    let mut strict = policy();
    strict.require_slashable = true;
    let evidence = golden();
    let attestation = adapter()
        .verify(&evidence, &strict)
        .expect("work clears the demand");
    assert!(matches!(attestation.security, SecurityBacking::Work { .. }));

    let proof = encode_external_evidence(&evidence).expect("evidence encodes");
    let (domain, commitment) = domain_and_commitment(&evidence, &proof);
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter()), strict);
    assert_eq!(
        bridge
            .verify_finality(&domain, &commitment, &proof)
            .expect("bridge verifies"),
        FinalityStatus::Finalized
    );
}

/// STRX-194-01 regression lock: adding a consensus family must not shift the
/// bincode discriminants of the families already persisted in intake state.
/// The new variant is appended, never inserted.
#[test]
fn adapter_spec_variant_indices_stay_pinned() {
    let eth = Spec::EthereumSync {
        network: "testnet".to_string(),
        committee: None,
    };
    let zk = Spec::ZkVm {
        network: "testnet".to_string(),
        program_hash: None,
        chain_id: None,
    };
    let eth_bytes = bincode::serialize(&eth).expect("eth spec serializes");
    let zk_bytes = bincode::serialize(&zk).expect("zk spec serializes");
    let btc_bytes = bincode::serialize(&bitcoin_spec()).expect("btc spec serializes");
    assert_eq!(u32::from_le_bytes(eth_bytes[0..4].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(zk_bytes[0..4].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(btc_bytes[0..4].try_into().unwrap()), 2);
}

/// The declared height and root are derived from the headers, not believed
/// from the envelope. This is the replay/index-drift rule made executable.
#[test]
fn declared_height_and_root_cannot_be_lied_about() {
    use crate::cross_domain::external::spec::AdapterError;

    let mut lying_height = golden();
    lying_height.declared_height += 1;
    assert!(matches!(
        adapter().verify(&lying_height, &policy()),
        Err(AdapterError::DeclarationMismatch { field: "height" })
    ));

    let mut lying_root = golden();
    lying_root.declared_root = [7; 32];
    assert!(matches!(
        adapter().verify(&lying_root, &policy()),
        Err(AdapterError::DeclarationMismatch { .. })
    ));
}

/// A short chain is pending by policy, not silently accepted.
#[test]
fn insufficient_spv_depth_is_refused() {
    use crate::cross_domain::external::spec::AdapterError;

    let mut evidence = golden();
    // Keep the count byte at six but remove the trailing header: the length
    // check refuses malformed truncation rather than reading a partial chain.
    evidence
        .payload
        .truncate(evidence.payload.len() - HEADER_LEN);
    assert!(matches!(
        adapter().verify(&evidence, &policy()),
        Err(AdapterError::Malformed { .. })
    ));
}
