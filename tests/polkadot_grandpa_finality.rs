//! Integration tests for the Polkadot / Substrate GRANDPA prefix-finality
//! justification, scheduled authority-set rotation, and equivocation adapter.

use budlum_core::core::address::Address;
use budlum_core::cross_domain::external::polkadot_grandpa::{
    adjudicate_grandpa_equivocation, advance_grandpa_authority_set,
    compute_grandpa_authority_set_hash, compute_grandpa_header_hash,
    encode_grandpa_justification_evidence, grandpa_precommit_sign_bytes, GrandpaAuthority,
    GrandpaEquivocationProof, GrandpaHeader, GrandpaScheduledChange, GrandpaSignedPrecommit,
    PinnedGrandpaSet, PolkadotGrandpaAdapter, EVIDENCE_VERSION,
};
use budlum_core::cross_domain::external::selftest::admit;
use budlum_core::cross_domain::external::spec::{
    AdapterError, ExternalFinalityAdapter, RawConsensusEvidence, SecurityBacking, TimeUnit,
    VerificationPolicy,
};
use budlum_core::crypto::ctx::CROSS_DOMAIN_V1;
use budlum_core::crypto::facts::{CryptoObserver, ObservedScheme};
use budlum_core::crypto::primitives::{KeyPair, PqKeyPair};
use budlum_core::crypto::scheme::SchemeId;

const NET: &str = "polkadot:91b171bb158e2d3848fa23a9f1c25182";

struct VoterKeys {
    ed: KeyPair,
    pq: Option<PqKeyPair>,
    weight: u64,
}

impl VoterKeys {
    fn classical(weight: u64) -> Self {
        Self {
            ed: KeyPair::generate().expect("Ed25519 keygen"),
            pq: None,
            weight,
        }
    }

    fn hybrid(weight: u64) -> Self {
        Self {
            ed: KeyPair::generate().expect("Ed25519 keygen"),
            pq: Some(PqKeyPair::generate()),
            weight,
        }
    }

    fn to_authority(&self, idx: usize) -> GrandpaAuthority {
        GrandpaAuthority {
            authority_id: format!("polkadot-val-{idx}"),
            ed25519_pubkey: self.ed.public_key_bytes(),
            weight: self.weight,
            pq_pubkey: self
                .pq
                .as_ref()
                .map_or_else(Vec::new, |k| k.public_key_bytes().to_vec()),
        }
    }

    fn sign_precommit(
        &self,
        network: &str,
        set_id: u64,
        round: u64,
        target_hash: [u8; 32],
        target_number: u64,
    ) -> GrandpaSignedPrecommit {
        let msg = grandpa_precommit_sign_bytes(network, set_id, round, &target_hash, target_number);
        let ed25519_sig = self.ed.sign(&msg).to_vec();
        let pq_sig = self.pq.as_ref().map_or_else(Vec::new, |pq| {
            pq.sign(CROSS_DOMAIN_V1, &msg).expect("ML-DSA-65 sign")
        });
        GrandpaSignedPrecommit {
            target_hash,
            target_number,
            authority_pubkey: self.ed.public_key_bytes(),
            ed25519_sig,
            pq_sig,
        }
    }
}

fn build_header(
    number: u64,
    parent_hash: [u8; 32],
    state_tag: u8,
    tx_tag: u8,
    timestamp_ms: u64,
    scheduled_change: Option<GrandpaScheduledChange>,
) -> GrandpaHeader {
    let state_root = [state_tag; 32];
    let extrinsics_root = [tx_tag; 32];
    let block_hash = compute_grandpa_header_hash(
        NET,
        number,
        &parent_hash,
        &state_root,
        &extrinsics_root,
        timestamp_ms,
        scheduled_change.as_ref(),
    );
    GrandpaHeader {
        number,
        parent_hash,
        state_root,
        extrinsics_root,
        timestamp_ms,
        scheduled_change,
        block_hash,
    }
}

#[derive(Default)]
struct RecordingObserver {
    schemes: Vec<ObservedScheme>,
}

impl CryptoObserver for RecordingObserver {
    fn observe(&mut self, scheme: ObservedScheme) {
        self.schemes.push(scheme);
    }
}

#[test]
fn grandpa_prefix_finality_accumulates_descendant_precommits_and_passes_selftest() {
    let voters = [
        VoterKeys::classical(30),
        VoterKeys::classical(25),
        VoterKeys::classical(25),
        VoterKeys::classical(20),
    ];
    let pinned = PinnedGrandpaSet {
        set_id: 7,
        authorities: voters
            .iter()
            .enumerate()
            .map(|(i, v)| v.to_authority(i))
            .collect(),
        has_slashable_bond_escrow: true,
    };

    let b100 = build_header(100, [0x99; 32], 0xA0, 0xB0, 1_700_000_000_000, None);
    let b101 = build_header(101, b100.block_hash, 0xA1, 0xB1, 1_700_000_006_000, None);
    let b102 = build_header(102, b101.block_hash, 0xA2, 0xB2, 1_700_000_012_000, None);

    let round = 42;
    let precommits = vec![
        voters[0].sign_precommit(NET, 7, round, b100.block_hash, 100),
        voters[1].sign_precommit(NET, 7, round, b101.block_hash, 101),
        voters[2].sign_precommit(NET, 7, round, b102.block_hash, 102),
    ];
    let payload =
        encode_grandpa_justification_evidence(7, round, b100.clone(), vec![b101, b102], precommits)
            .expect("canonical GRANDPA justification encodes");

    let base_adapter = PolkadotGrandpaAdapter::new(NET, Some(pinned));
    let golden = RawConsensusEvidence {
        adapter: base_adapter.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload,
        declared_height: 100,
        declared_root: b100.state_root,
        submitter: Address::from([0x11; 32]),
    };
    let adapter = base_adapter.with_golden(golden.clone());

    let mut policy = VerificationPolicy::strict(round);
    policy.require_slashable = true;
    let att = adapter
        .verify(&golden, &policy)
        .expect("prefix justification with >2/3 descendant weight must finalize B_100");
    assert_eq!(att.height, 100);
    assert_eq!(att.state_root, b100.state_root);
    assert_eq!(att.finalized_at, round);
    assert_eq!(att.time_unit, TimeUnit::Round);
    assert_eq!(att.attested_block_hash, Some(b100.block_hash));
    assert_eq!(att.attested_tx_root, Some(b100.extrinsics_root));
    assert_eq!(adapter.attested_parent(&golden), Some(b100.parent_hash));
    assert_eq!(
        att.security,
        SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::ED25519),
            signers: 80,
            required: 67,
            total_weight: 100,
            slashable: true,
        }
    );

    let report = admit(&adapter, &VerificationPolicy::strict(round));
    assert!(report.golden_verified, "golden sample must verify");
    let failed: Vec<&String> = report
        .probes
        .iter()
        .filter(|(_, o)| !o.passed())
        .map(|(n, _)| n)
        .collect();
    assert!(
        failed.is_empty(),
        "all fault probes must refuse corrupted evidence: {failed:?}"
    );
    assert!(report.admitted);
}

#[test]
fn grandpa_refuses_precommit_on_unconnected_fork_branch() {
    let voters = [
        VoterKeys::classical(30),
        VoterKeys::classical(25),
        VoterKeys::classical(25),
        VoterKeys::classical(20),
    ];
    let pinned = PinnedGrandpaSet {
        set_id: 7,
        authorities: voters
            .iter()
            .enumerate()
            .map(|(i, v)| v.to_authority(i))
            .collect(),
        has_slashable_bond_escrow: true,
    };

    let b100 = build_header(100, [0x99; 32], 0xA0, 0xB0, 1_700_000_000_000, None);
    let b101 = build_header(101, b100.block_hash, 0xA1, 0xB1, 1_700_000_006_000, None);
    let fork_101 = build_header(101, [0xEE; 32], 0xF1, 0xF2, 1_700_000_006_000, None);

    let round = 42;
    let precommits = vec![
        voters[0].sign_precommit(NET, 7, round, b100.block_hash, 100),
        voters[1].sign_precommit(NET, 7, round, b101.block_hash, 101),
        voters[2].sign_precommit(NET, 7, round, fork_101.block_hash, 101),
    ];
    let payload = encode_grandpa_justification_evidence(
        7,
        round,
        b100.clone(),
        vec![b101, fork_101],
        precommits,
    )
    .expect("payload encodes");

    let adapter = PolkadotGrandpaAdapter::new(NET, Some(pinned));
    let ev = RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload,
        declared_height: 100,
        declared_root: b100.state_root,
        submitter: Address::from([0x11; 32]),
    };

    let err = adapter
        .verify(&ev, &VerificationPolicy::strict(round))
        .expect_err("precommit on sibling fork must not count toward target prefix");
    assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");
}

#[test]
fn grandpa_refuses_exact_two_thirds_boundary_and_duplicate_signers() {
    let voters = [
        VoterKeys::classical(30),
        VoterKeys::classical(30),
        VoterKeys::classical(30),
    ];
    let pinned = PinnedGrandpaSet {
        set_id: 1,
        authorities: voters
            .iter()
            .enumerate()
            .map(|(i, v)| v.to_authority(i))
            .collect(),
        has_slashable_bond_escrow: false,
    };
    let b50 = build_header(50, [0x11; 32], 0xC0, 0xD0, 1_700_000_000_000, None);
    let adapter = PolkadotGrandpaAdapter::new(NET, Some(pinned));

    let two_thirds_payload = encode_grandpa_justification_evidence(
        1,
        10,
        b50.clone(),
        Vec::new(),
        vec![
            voters[0].sign_precommit(NET, 1, 10, b50.block_hash, 50),
            voters[1].sign_precommit(NET, 1, 10, b50.block_hash, 50),
        ],
    )
    .expect("encodes");
    let ev_boundary = RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload: two_thirds_payload,
        declared_height: 50,
        declared_root: b50.state_root,
        submitter: Address::from([0x22; 32]),
    };
    let err = adapter
        .verify(&ev_boundary, &VerificationPolicy::strict(10))
        .expect_err("exact 2/3 weight (60/90) must be refused");
    assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");

    let dup_payload = encode_grandpa_justification_evidence(
        1,
        10,
        b50.clone(),
        Vec::new(),
        vec![
            voters[0].sign_precommit(NET, 1, 10, b50.block_hash, 50),
            voters[0].sign_precommit(NET, 1, 10, b50.block_hash, 50),
            voters[1].sign_precommit(NET, 1, 10, b50.block_hash, 50),
        ],
    )
    .expect("encodes");
    let ev_dup = RawConsensusEvidence {
        payload: dup_payload,
        ..ev_boundary
    };
    let err = adapter
        .verify(&ev_dup, &VerificationPolicy::strict(10))
        .expect_err("duplicate authority precommit must be refused");
    assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");
}

#[test]
fn grandpa_enforces_hybrid_ml_dsa_65_cosignatures_and_observes_schemes() {
    let voters = [
        VoterKeys::hybrid(40),
        VoterKeys::hybrid(35),
        VoterKeys::hybrid(25),
    ];
    let pinned = PinnedGrandpaSet {
        set_id: 3,
        authorities: voters
            .iter()
            .enumerate()
            .map(|(i, v)| v.to_authority(i))
            .collect(),
        has_slashable_bond_escrow: true,
    };
    let b10 = build_header(10, [0x44; 32], 0x55, 0x66, 1_700_000_000_000, None);
    let adapter = PolkadotGrandpaAdapter::new(NET, Some(pinned));

    let p0 = voters[0].sign_precommit(NET, 3, 5, b10.block_hash, 10);
    let p1 = voters[1].sign_precommit(NET, 3, 5, b10.block_hash, 10);
    let valid_payload = encode_grandpa_justification_evidence(
        3,
        5,
        b10.clone(),
        Vec::new(),
        vec![p0.clone(), p1.clone()],
    )
    .expect("encodes");
    let ev_ok = RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload: valid_payload,
        declared_height: 10,
        declared_root: b10.state_root,
        submitter: Address::from([0x33; 32]),
    };

    let mut obs = RecordingObserver::default();
    let att = adapter
        .verify_observed(&ev_ok, &VerificationPolicy::strict(5), &mut obs)
        .expect("hybrid Ed25519 + ML-DSA-65 GRANDPA precommits must verify");
    assert_eq!(
        att.security,
        SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
            signers: 75,
            required: 67,
            total_weight: 100,
            slashable: true,
        }
    );
    assert!(obs
        .schemes
        .contains(&ObservedScheme::Scheme(SchemeId::ED25519)));
    assert!(obs
        .schemes
        .contains(&ObservedScheme::Scheme(SchemeId::ML_DSA_65)));

    let mut stripped = p1;
    stripped.pq_sig.clear();
    let bad_payload =
        encode_grandpa_justification_evidence(3, 5, b10.clone(), Vec::new(), vec![p0, stripped])
            .expect("encodes");
    let ev_stripped = RawConsensusEvidence {
        payload: bad_payload,
        ..ev_ok
    };
    let err = adapter
        .verify(&ev_stripped, &VerificationPolicy::strict(5))
        .expect_err("stripped ML-DSA-65 co-signature must fail closed");
    assert!(matches!(err, AdapterError::Crypto { .. }), "{err:?}");
}

#[test]
fn grandpa_refuses_unanchored_unslashable_and_stale_evidence() {
    let voters = [VoterKeys::classical(60), VoterKeys::classical(40)];
    let unanchored = PolkadotGrandpaAdapter::new(NET, None);
    assert!(!unanchored.has_pinned_trust_anchor());

    let b1 = build_header(1, [0x01; 32], 0x11, 0x22, 1_700_000_000_000, None);
    let payload = encode_grandpa_justification_evidence(
        0,
        10,
        b1.clone(),
        Vec::new(),
        vec![
            voters[0].sign_precommit(NET, 0, 10, b1.block_hash, 1),
            voters[1].sign_precommit(NET, 0, 10, b1.block_hash, 1),
        ],
    )
    .expect("encodes");
    let ev = RawConsensusEvidence {
        adapter: unanchored.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload,
        declared_height: 1,
        declared_root: b1.state_root,
        submitter: Address::from([0x44; 32]),
    };

    let err = unanchored
        .verify(&ev, &VerificationPolicy::strict(10))
        .expect_err("unanchored adapter must fail closed");
    assert!(matches!(err, AdapterError::Unavailable { .. }), "{err:?}");

    let pinned = PinnedGrandpaSet {
        set_id: 0,
        authorities: voters
            .iter()
            .enumerate()
            .map(|(i, v)| v.to_authority(i))
            .collect(),
        has_slashable_bond_escrow: false,
    };
    let anchored = PolkadotGrandpaAdapter::new(NET, Some(pinned));
    assert!(anchored.has_pinned_trust_anchor());

    let mut slash_req = VerificationPolicy::strict(10);
    slash_req.require_slashable = true;
    let err = anchored
        .verify(&ev, &slash_req)
        .expect_err("unslashable authority set must refuse require_slashable=true");
    assert_eq!(err, AdapterError::UnslashableBacking);

    let mut stale_pol = VerificationPolicy::strict(20);
    stale_pol.max_age = 5;
    let err = anchored
        .verify(&ev, &stale_pol)
        .expect_err("round older than max_age must refuse as Stale");
    assert_eq!(
        err,
        AdapterError::Stale {
            age: 10,
            max_age: 5
        }
    );
}

#[test]
fn grandpa_rotates_authority_set_via_scheduled_change_and_slashes_equivocation() {
    let set7_voters = [
        VoterKeys::classical(40),
        VoterKeys::classical(40),
        VoterKeys::classical(20),
    ];
    let pinned7 = PinnedGrandpaSet {
        set_id: 7,
        authorities: set7_voters
            .iter()
            .enumerate()
            .map(|(i, v)| v.to_authority(i))
            .collect(),
        has_slashable_bond_escrow: true,
    };

    let set8_voters = [
        VoterKeys::classical(50),
        VoterKeys::classical(30),
        VoterKeys::classical(20),
    ];
    let next_authorities: Vec<GrandpaAuthority> = set8_voters
        .iter()
        .enumerate()
        .map(|(i, v)| v.to_authority(i))
        .collect();
    let next_hash = compute_grandpa_authority_set_hash(8, &next_authorities)
        .expect("valid next authority set hashes");

    let change = GrandpaScheduledChange {
        next_set_id: 8,
        next_authorities_hash: next_hash,
    };
    let handoff_hdr = build_header(200, [0x77; 32], 0x88, 0x99, 1_700_000_100_000, Some(change));
    let payload = encode_grandpa_justification_evidence(
        7,
        19,
        handoff_hdr.clone(),
        Vec::new(),
        vec![
            set7_voters[0].sign_precommit(NET, 7, 19, handoff_hdr.block_hash, 200),
            set7_voters[1].sign_precommit(NET, 7, 19, handoff_hdr.block_hash, 200),
        ],
    )
    .expect("encodes");

    let mut tampered = next_authorities.clone();
    tampered[0].weight = 51;
    let err = advance_grandpa_authority_set(NET, &pinned7, &payload, tampered, true)
        .expect_err("tampered authority weight must mismatch scheduled_change hash");
    assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");

    let pinned8 = advance_grandpa_authority_set(NET, &pinned7, &payload, next_authorities, true)
        .expect("valid scheduled change rotates authority set to set_id 8");
    assert_eq!(pinned8.set_id, 8);
    assert_eq!(pinned8.authorities.len(), 3);

    let eq_valid = GrandpaEquivocationProof {
        set_id: 8,
        round: 1,
        first: set8_voters[0].sign_precommit(NET, 8, 1, [0xAA; 32], 201),
        second: set8_voters[0].sign_precommit(NET, 8, 1, [0xBB; 32], 201),
    };
    let slashed = adjudicate_grandpa_equivocation(NET, &pinned8, &eq_valid)
        .expect("conflicting precommits in identical (set_id, round) must be adjudicated");
    assert_eq!(
        slashed.authority_pubkey,
        set8_voters[0].ed.public_key_bytes()
    );
    assert_eq!(slashed.slashed_weight, 50);

    let eq_same = GrandpaEquivocationProof {
        set_id: 8,
        round: 1,
        first: eq_valid.first.clone(),
        second: eq_valid.first.clone(),
    };
    let err = adjudicate_grandpa_equivocation(NET, &pinned8, &eq_same)
        .expect_err("identical precommits are not an equivocation");
    assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");
}

#[test]
fn grandpa_registry_lifecycle_admits_submits_and_faults_on_equivocation() {
    use budlum_core::cross_domain::external::profile::DomainState;
    use budlum_core::cross_domain::external::prover::DomainEconomics;
    use budlum_core::cross_domain::external::registry::{ExternalDomainRegistry, RegistryError};
    use budlum_core::cross_domain::external::versioning::VersionPolicy;

    let voters = [
        VoterKeys::classical(40),
        VoterKeys::classical(35),
        VoterKeys::classical(25),
    ];
    let pinned = PinnedGrandpaSet {
        set_id: 5,
        authorities: voters
            .iter()
            .enumerate()
            .map(|(i, v)| v.to_authority(i))
            .collect(),
        has_slashable_bond_escrow: true,
    };

    let b10 = build_header(10, [0x10; 32], 0x20, 0x30, 1_700_000_000_000, None);
    let payload10 = encode_grandpa_justification_evidence(
        5,
        1,
        b10.clone(),
        Vec::new(),
        vec![
            voters[0].sign_precommit(NET, 5, 1, b10.block_hash, 10),
            voters[1].sign_precommit(NET, 5, 1, b10.block_hash, 10),
        ],
    )
    .expect("encodes");

    let prover = Address::from([0x7A; 32]);
    let base = PolkadotGrandpaAdapter::new(NET, Some(pinned.clone()));
    let golden = RawConsensusEvidence {
        adapter: base.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload: payload10,
        declared_height: 10,
        declared_root: b10.state_root,
        submitter: prover,
    };
    let adapter = base.with_golden(golden.clone());
    let policy = VerificationPolicy::strict(1);
    let admission = admit(&adapter, &policy);
    assert!(admission.admitted);

    let economics = DomainEconomics::default();
    let required_bond = economics.required_bond_atoms();
    let versions = VersionPolicy::single(adapter.descriptor().id, EVIDENCE_VERSION, 0);

    let mut registry = ExternalDomainRegistry::new();
    registry.set_height(100);
    let domain_key = registry
        .register(
            NET,
            adapter.descriptor(),
            economics,
            versions,
            &admission,
            required_bond,
            prover,
        )
        .expect("GRANDPA domain registers cleanly");

    let att = registry
        .submit(&adapter, &golden, &policy)
        .expect("valid justification transitions GRANDPA domain to Active");
    assert_eq!(att.height, 10);
    assert_eq!(
        registry.domain(&domain_key).expect("domain").record.state,
        DomainState::Active
    );

    let eq = GrandpaEquivocationProof {
        set_id: 5,
        round: 2,
        first: voters[0].sign_precommit(NET, 5, 2, [0xD1; 32], 11),
        second: voters[0].sign_precommit(NET, 5, 2, [0xD2; 32], 11),
    };
    let slashed = registry
        .fault_on_grandpa_equivocation(NET, &pinned, &eq)
        .expect("verified GRANDPA equivocation faults the domain");
    assert_eq!(slashed.slashed_weight, 40);
    assert_eq!(
        registry.domain(&domain_key).expect("domain").record.state,
        DomainState::Faulted
    );

    // Subsequent submissions are refused fail-closed while Faulted.
    let b11 = build_header(11, b10.block_hash, 0x21, 0x31, 1_700_000_006_000, None);
    let payload11 = encode_grandpa_justification_evidence(
        5,
        2,
        b11.clone(),
        Vec::new(),
        vec![
            voters[0].sign_precommit(NET, 5, 2, b11.block_hash, 11),
            voters[1].sign_precommit(NET, 5, 2, b11.block_hash, 11),
        ],
    )
    .expect("encodes");
    let ev11 = RawConsensusEvidence {
        payload: payload11,
        declared_height: 11,
        declared_root: b11.state_root,
        ..golden
    };
    let err = registry
        .submit(&adapter, &ev11, &VerificationPolicy::strict(2))
        .expect_err("faulted GRANDPA domain must refuse new attestations");
    assert!(matches!(err, RegistryError::NotServing { .. }), "{err:?}");
}
