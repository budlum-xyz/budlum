//! Every built-in verifier family refuses an anchor it does not hold.
//!
//! # Why this test exists
//!
//! `ExternalVerifierFamily::verify_descriptor` opens with the pin check:
//! `if !anchor_pinned { return Err(ExternalShapeError::MissingTrustAnchor) }`.
//! That one line is the only place the bridge consults before it evaluates
//! untrusted bytes, and it is reached through `from_consensus_kind`, a 32-arm
//! string table. A family that drifts out of that table - a kind string edited
//! on one side, a family added to `ExternalVerifierFamily` but not to the table
//! - would fall to the bridge's `else` branch, which is a different refusal
//! with different semantics. This test pins the refusal for every family by
//! name, so the table and the refusal cannot diverge silently.
//!
//! # What it does not do
//!
//! It does not construct a real adapter per family: the unpinned adapter
//! contract is `has_pinned_trust_anchor() == false`, and a fixture that returns
//! `false` exercises exactly the branch a real unpinned adapter takes. Whether
//! each real adapter's own body is a single presence test is measured by the
//! `finality-acceptance-surface-has-one-path` gate, and whether the real
//! adapters refuse registration without a pin is pinned by
//! `external_unpinned_refusal.rs`.

use crate::core::address::Address;
use crate::cross_domain::external::selftest::FaultProbe;
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, ExternalFinalityAdapter, FinalityAttestation,
    FinalityKind, RawConsensusEvidence, TimeUnit, TrustModel, VerificationPolicy,
};
use crate::cross_domain::external::{
    encode_external_evidence, ExternalDomainFinalityBridge, EXTERNAL_DOMAIN_FINALITY_ADAPTER,
};
use crate::domain::finality_adapter::{DomainFinalityAdapter, FinalityProof, FinalityStatus};
use crate::domain::finality_proof_model::ExternalVerifierFamily;
use crate::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
};

/// Every family and the consensus kind it must resolve from.
///
/// Kept in the same order as `ExternalVerifierFamily`'s discriminants so a
/// reader can compare the two side by side; the count is asserted below.
const FAMILIES: &[(&str, &str)] = &[
    ("algorand-pure-pos-stateproof-pq", "AlgorandStateProof"),
    ("aptos-jolteon-2chain-bft", "AptosJolteonBft"),
    ("arweave-spora-recall", "ArweaveSpOra"),
    ("auxpow-pop-merged-mining", "AuxPowPop"),
    ("babylon-btc-restaking-eots", "BabylonEots"),
    ("based-preconf-focil", "BasedPreconf"),
    ("nakamoto-pow", "BitcoinNakamotoPow"),
    ("bitvm2-pow-covenant", "BitVmCovenant"),
    ("casper-ffg-checkpoint", "CasperFfg"),
    ("chain-key-nidkg-threshold-bls", "ChainKeyNiDkg"),
    ("modular-das-nmt-2d", "CelestiaDas"),
    ("bullshark-round-dag-bft", "BullsharkDagBft"),
    ("gasper-pos", "EthereumGasperSync"),
    ("ghostdag-k-cluster-pow", "GhostdagPow"),
    ("heterogeneous-multiprover-2of3", "HeterogeneousMultiProver"),
    ("asynchronous-common-subset-bft", "HoneyBadgerBft"),
    ("hotstuff-chained-bft", "HotStuffChainedBft"),
    ("succinct-recursive-samasika-stark", "MinaSuccinctRecursive"),
    ("mysticeti-uncertified-dag", "MysticetiDag"),
    ("near-nightshade-doomslug-bft", "NearDoomslugBft"),
    ("nipopow-superblock", "NipopowSuperblock"),
    ("ouroboros-praos-with-mithril-stm", "OuroborosMithril"),
    ("pospace-hash-vdf", "PoSpaceVdf"),
    ("restaking-avs-eots", "RestakingAvs"),
    ("simplex-monadbft-2round", "SimplexBft"),
    ("solana-tower-bft", "SolanaTowerBft"),
    ("stark-state-diff-validity-rollup", "StarkValidityRollup"),
    ("federated-bft-scp", "StellarScp"),
    ("symbiotic-curated-vault", "SymbioticVault"),
    ("tendermint-bft", "TendermintBft"),
    ("ton-masterchain-catchain-bft", "TonCatchainBft"),
    ("zkvm-execution", "BudZkVmExecution"),
];

/// An adapter that holds no anchor at all. Its body is the literal contract an
/// unpinned adapter must honour.
struct UnpinnedAdapter(AdapterDescriptor, RawConsensusEvidence);

impl ExternalFinalityAdapter for UnpinnedAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.0.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        false
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        _policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        Err(AdapterError::WrongAdapter {
            expected: self.0.name.clone(),
            found: evidence.network.clone(),
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        Vec::new()
    }
}

/// The fixture pair for one consensus kind.
fn fixture(
    kind: &str,
) -> (
    UnpinnedAdapter,
    ConsensusDomain,
    DomainCommitment,
    FinalityProof,
) {
    let descriptor = AdapterDescriptor {
        id: AdapterId::from_name("unpinned-fixture"),
        name: "unpinned-fixture".to_string(),
        adapter_version: 1,
        accepted_evidence_versions: vec![1],
        consensus_kind: kind.to_string(),
        finality_kind: FinalityKind::ProtocolFinality,
        required_depth: 0,
        time_unit: TimeUnit::Height,
        trust_model: TrustModel::HonestMajority { set_size: 3 },
    };
    let evidence = RawConsensusEvidence {
        adapter: descriptor.id,
        evidence_version: 1,
        network: "unpinned".to_string(),
        payload: vec![9, 9, 9],
        declared_height: 11,
        declared_root: [7; 32],
        submitter: Address::from([3; 32]),
    };
    let domain = ConsensusDomain {
        id: 9,
        kind: ConsensusKind::Custom(kind.to_string()),
        status: DomainStatus::Active,
        domain_chain_id: 99,
        operator: Some(Address::from([4; 32])),
        operator_bond: 1_000_000,
        config_hash: [0; 32],
        validator_set_hash: [0; 32],
        finality_adapter: EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 10,
        last_committed_hash: [6; 32],
        pow_parameters: None,
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: [0; 32],
    };
    let commitment = DomainCommitment {
        domain_id: 9,
        domain_height: 11,
        domain_block_hash: [5; 32],
        parent_domain_block_hash: [4; 32],
        state_root: [7; 32],
        tx_root: [2; 32],
        event_root: [1; 32],
        finality_proof_hash: [0; 32],
        consensus_kind: domain.kind.clone(),
        validator_set_hash: [0; 32],
        timestamp_ms: 0,
        sequence: 1,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    };
    let proof = encode_external_evidence(&evidence).expect("encode fixture evidence");
    (
        UnpinnedAdapter(descriptor, evidence),
        domain,
        commitment,
        proof,
    )
}

#[test]
fn every_family_refuses_an_unpinned_anchor() {
    assert_eq!(
        FAMILIES.len(),
        32,
        "the family table must cover every discriminant"
    );
    let mut refused: Vec<&str> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    for (kind, family) in FAMILIES {
        // The kind must resolve to the family this row names; a row whose kind
        // no longer resolves is a finding here rather than a silent skip.
        match ExternalVerifierFamily::from_consensus_kind(kind) {
            None => wrong.push(format!("{family}: kind `{kind}` does not resolve")),
            Some(resolved) => {
                if resolved.consensus_kind() != *kind {
                    wrong.push(format!(
                        "{family}: kind `{kind}` resolves to `{}`",
                        resolved.consensus_kind()
                    ));
                }
            }
        }
        let (adapter, domain, mut commitment, proof) = fixture(kind);
        commitment.finality_proof_hash =
            crate::domain::hash_finality_proof(&proof).expect("the encoded evidence hashes");
        let bridge =
            ExternalDomainFinalityBridge::new(Box::new(adapter), VerificationPolicy::proven(100));
        let status = bridge
            .verify_finality(&domain, &commitment, &proof)
            .expect("verify_finality reports a status, not a parse error");
        let FinalityStatus::Rejected(message) = status else {
            wrong.push(format!(
                "{family}: an unpinned adapter was not rejected: {status:?}"
            ));
            continue;
        };
        if message.contains("requires a pinned trust anchor") {
            refused.push(family);
        } else {
            wrong.push(format!("{family}: refused for the wrong reason: {message}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} family/families did not refuse an unpinned anchor as `MissingTrustAnchor`: {:#?}",
        wrong.len(),
        wrong
    );
    assert_eq!(
        refused.len(),
        FAMILIES.len(),
        "every family must have been measured exactly once"
    );
}
