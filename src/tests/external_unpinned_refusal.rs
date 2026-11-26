//! Pin fail-closed canaries: an unpinned `AdapterSpec` must not be admitted.
//!
//! Principle (`mimari/2026-11-24-vuslat-tek-kabul-yolu-tasari-mi.md`, "pin
//! fail-closed"): a `None` in an `AdapterSpec` pin field is the closed admission
//! state. `register_domain` must admit no variant without its pin, and each
//! must refuse with exactly `IntakeError::CommitteeNotPinned`.
//!
//! Table-driven: every variant appended to `AdapterSpec` needs a `None` row
//! here. `the_table_tracks_the_variant_baseline` ties the row count to the
//! committed baseline, so a new variant cannot stay silently uncanaried.
//!
//! Scope: this file pins the **admission moment** only. The claim that an
//! adapter built from a `None` pin (e.g. `BabylonEots`: chain id 0, no keys)
//! "verifies nothing" needs its own verification test; it is not made here.

use crate::core::address::Address;
use crate::cross_domain::external::ethereum::BlsVerifier;
use crate::cross_domain::external::intake::{
    AdapterSpec, IntakeError, IntakeState, RegistrationRequest,
};
use crate::cross_domain::external::spec::{RawConsensusEvidence, VerificationPolicy};
use crate::cross_domain::external::versioning::VersionPolicy;

const NETWORK: &str = "testnet";
/// `.github/adapter-spec-variant-baseline.txt`: the variant order the gate pins.
const BASELINE: &str = include_str!("../../.github/adapter-spec-variant-baseline.txt");

/// A shape-correct BLS that verifies no real signature. It exists so the
/// `EthereumSync` canary is not refused for `MissingBlsVerifier` before the pin
/// branch is reached (same shape as `StrictTestBls` in intake.rs's own tests).
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

/// The unpinned (`None`) form of every variant, in baseline order.
fn unpinned() -> Vec<(&'static str, AdapterSpec)> {
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
    ]
}

/// A registration request. Pin refusals are given before the rest of the body
/// is looked at, so `golden` and `versions` are only well-formed placeholders.
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
fn every_variant_refuses_registration_without_its_pin() {
    let mut leaked = Vec::new();
    for (name, spec) in unpinned() {
        let mut state = IntakeState::new();
        match state.register_domain(request(spec), Some(Box::new(ShapeOnlyBls))) {
            Err(IntakeError::CommitteeNotPinned) => {}
            Err(other) => leaked.push(format!("{name}: refused for another reason: {other:?}")),
            Ok(_) => leaked.push(format!("{name}: unpinned registration was ACCEPTED")),
        }
    }
    assert!(
        leaked.is_empty(),
        "pin fail-closed canary broken: {leaked:?}"
    );
}

#[test]
fn a_pinned_spec_is_not_refused_for_a_missing_pin() {
    // Negative control: the canary is not red for everything. The `ZkVm` pin
    // branch only looks at whether the fields are set; with the pin present the
    // registration proceeds or fails for another reason (empty golden sample),
    // but never with `CommitteeNotPinned`.
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

#[test]
fn the_table_tracks_the_variant_baseline() {
    let pinned = BASELINE
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count();
    assert_eq!(
        unpinned().len(),
        pinned,
        "a variant was appended to AdapterSpec (baseline {pinned}); add its `None` row here"
    );
}
