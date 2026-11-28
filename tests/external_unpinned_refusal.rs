//! Pin fail-closed canaries across all 32 `AdapterSpec` variants on `testnet-50`.
//!
//! Every `AdapterSpec` variant with an omitted governance anchor/pin must fail
//! closed at `IntakeState::register_domain` with `IntakeError::CommitteeNotPinned`.

use budlum_core::core::address::Address;
use budlum_core::cross_domain::external::ethereum::BlsVerifier;
use budlum_core::cross_domain::external::intake::{
    AdapterSpec, IntakeError, IntakeState, RegistrationRequest,
};
use budlum_core::cross_domain::external::spec::{RawConsensusEvidence, VerificationPolicy};
use budlum_core::cross_domain::external::versioning::VersionPolicy;

const NETWORK: &str = "testnet";

struct ShapeOnlyBls;

impl BlsVerifier for ShapeOnlyBls {
    fn verify_aggregate(
        &self,
        _signing_root: &[u8; 32],
        _aggregate_pubkey: &[u8],
        _signature: &[u8],
        participants: u64,
    ) -> Result<(), String> {
        if participants == 0 {
            return Err("nobody signed".to_string());
        }
        Ok(())
    }

    fn sync_committee_closed(&self) -> bool {
        false
    }
}

fn all_unpinned_variants() -> Vec<(&'static str, AdapterSpec)> {
    vec![
        (
            "EthereumSync",
            AdapterSpec::EthereumSync {
                network: NETWORK.to_string(),
                committee: None,
            },
        ),
        (
            "ZkVm",
            AdapterSpec::ZkVm {
                network: NETWORK.to_string(),
                program_hash: None,
                chain_id: None,
            },
        ),
        (
            "BitcoinSpv",
            AdapterSpec::BitcoinSpv {
                network: NETWORK.to_string(),
                anchor: None,
            },
        ),
        (
            "TendermintCommit",
            AdapterSpec::TendermintCommit {
                network: NETWORK.to_string(),
                chain_id: "cosmoshub-4".to_string(),
                validator_set_hash: None,
            },
        ),
        (
            "DataAvailability",
            AdapterSpec::DataAvailability {
                network: NETWORK.to_string(),
                committee: None,
            },
        ),
        (
            "HotStuffQc",
            AdapterSpec::HotStuffQc {
                network: NETWORK.to_string(),
                committee: None,
            },
        ),
        (
            "DagCertificate",
            AdapterSpec::DagCertificate {
                network: NETWORK.to_string(),
                committee: None,
            },
        ),
        (
            "CasperFfg",
            AdapterSpec::CasperFfg {
                network: NETWORK.to_string(),
                committee: None,
            },
        ),
        (
            "MysticetiDag",
            AdapterSpec::MysticetiDag {
                network: NETWORK.to_string(),
                committee: None,
            },
        ),
        (
            "BitVmCovenant",
            AdapterSpec::BitVmCovenant {
                network: NETWORK.to_string(),
                anchor: None,
            },
        ),
        (
            "SolanaTowerBft",
            AdapterSpec::SolanaTowerBft {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "PoSpaceVdf",
            AdapterSpec::PoSpaceVdf {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "AptosJolteonBft",
            AdapterSpec::AptosJolteonBft {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "NearDoomslugBft",
            AdapterSpec::NearDoomslugBft {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "ChainKeyNiDkg",
            AdapterSpec::ChainKeyNiDkg {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "BabylonEots",
            AdapterSpec::BabylonEots {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "NipopowSuperblock",
            AdapterSpec::NipopowSuperblock {
                network: NETWORK.to_string(),
                genesis: None,
            },
        ),
        (
            "Ghostdag",
            AdapterSpec::Ghostdag {
                network: NETWORK.to_string(),
                anchor: None,
            },
        ),
        (
            "HoneyBadgerBft",
            AdapterSpec::HoneyBadgerBft {
                network: NETWORK.to_string(),
                committee: None,
            },
        ),
        (
            "HeterogeneousMultiProver",
            AdapterSpec::HeterogeneousMultiProver {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "StarkValidityRollup",
            AdapterSpec::StarkValidityRollup {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "AlgorandStateProof",
            AdapterSpec::AlgorandStateProof {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "ArweaveSpOra",
            AdapterSpec::ArweaveSpOra {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "AuxPowPop",
            AdapterSpec::AuxPowPop {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "BasedPreconf",
            AdapterSpec::BasedPreconf {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "MinaSuccinctRecursive",
            AdapterSpec::MinaSuccinctRecursive {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "OuroborosMithril",
            AdapterSpec::OuroborosMithril {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "RestakingAvs",
            AdapterSpec::RestakingAvs {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "SimplexBft",
            AdapterSpec::SimplexBft {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "StellarScp",
            AdapterSpec::StellarScp {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "SymbioticVault",
            AdapterSpec::SymbioticVault {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
        (
            "TonCatchainBft",
            AdapterSpec::TonCatchainBft {
                network: NETWORK.to_string(),
                pinned: None,
            },
        ),
    ]
}

fn request(spec: AdapterSpec) -> RegistrationRequest {
    let adapter = spec.build(Some(Box::new(ShapeOnlyBls)), None);
    let id = adapter.descriptor().id;
    let evidence_version = adapter
        .descriptor()
        .accepted_evidence_versions
        .first()
        .copied()
        .unwrap_or(1);
    let economics = IntakeState::conservative_economics(1_000_000);
    let bond_atoms = economics.required_bond_atoms();
    RegistrationRequest {
        spec,
        policy: VerificationPolicy::strict(1_000),
        economics,
        versions: VersionPolicy::single(id, evidence_version, 0),
        bond_atoms,
        poster: Address([9; 32]),
        golden: RawConsensusEvidence {
            adapter: id,
            evidence_version,
            network: NETWORK.to_string(),
            payload: Vec::new(),
            declared_height: 0,
            declared_root: [0; 32],
            submitter: Address([1; 32]),
        },
    }
}

#[test]
fn every_adapter_spec_variant_refuses_registration_without_pin() {
    let mut leaked = Vec::new();
    for (name, spec) in all_unpinned_variants() {
        let mut state = IntakeState::new();
        match state.register_domain(request(spec), Some(Box::new(ShapeOnlyBls))) {
            Err(IntakeError::CommitteeNotPinned) => {}
            Err(other) => leaked.push(format!("{name}: refused with unexpected error: {other:?}")),
            Ok(_) => leaked.push(format!("{name}: unpinned registration was ACCEPTED")),
        }
    }
    assert!(
        leaked.is_empty(),
        "pin fail-closed canary broken: {leaked:?}"
    );
}

#[test]
fn a_pinned_zkvm_spec_passes_the_pin_gate() {
    let spec = AdapterSpec::ZkVm {
        network: NETWORK.to_string(),
        program_hash: Some([0x42; 32]),
        chain_id: Some(1),
    };
    let mut state = IntakeState::new();
    let outcome = state.register_domain(request(spec), Some(Box::new(ShapeOnlyBls)));
    assert!(
        !matches!(outcome, Err(IntakeError::CommitteeNotPinned)),
        "a pinned spec was refused as unpinned: {outcome:?}"
    );
}
