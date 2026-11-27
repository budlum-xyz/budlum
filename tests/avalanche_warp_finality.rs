//! Integration tests for the Avalanche Snowman / Warp Messaging (ICM / ACP-77)
//! external finality, P-Chain validator rotation, and contradiction adapter.

use budlum_core::chain::finality::sign_bls;
use budlum_core::core::address::Address;
use budlum_core::cross_domain::external::avalanche_warp::{
    adjudicate_avalanche_warp_contradiction, advance_avalanche_pchain_set,
    avalanche_warp_sign_bytes, compute_avalanche_pchain_set_hash,
    compute_avalanche_warp_block_hash, encode_avalanche_warp_evidence, AvalancheSubnetValidator,
    AvalancheWarpAdapter, AvalancheWarpContradictionProof, AvalancheWarpHeader,
    AvalancheWarpSignature, PinnedAvalancheSubnet, EVIDENCE_VERSION,
};
use budlum_core::cross_domain::external::selftest::admit;
use budlum_core::cross_domain::external::spec::{
    AdapterError, ExternalFinalityAdapter, RawConsensusEvidence, SecurityBacking, TimeUnit,
    VerificationPolicy,
};
use budlum_core::crypto::ctx::CROSS_DOMAIN_V1;
use budlum_core::crypto::facts::{CryptoObserver, ObservedScheme};
use budlum_core::crypto::primitives::{BlsKeypair, PqKeyPair};
use budlum_core::crypto::scheme::SchemeId;

const NET: &str = "avalanche:43114";
const NETWORK_ID: u32 = 1;
const SUBNET_ID: [u8; 32] = [0xA1; 32];
const CHAIN_ID: [u8; 32] = [0xC1; 32];

struct WarpVoter {
    node_id: [u8; 20],
    bls: BlsKeypair,
    pq: Option<PqKeyPair>,
    weight: u64,
}

impl WarpVoter {
    fn classical(seed: u8, weight: u64) -> Self {
        Self {
            node_id: [seed; 20],
            bls: BlsKeypair::from_seed(&[seed; 64]).expect("BLS keygen"),
            pq: None,
            weight,
        }
    }

    fn hybrid(seed: u8, weight: u64) -> Self {
        Self {
            node_id: [seed; 20],
            bls: BlsKeypair::from_seed(&[seed; 64]).expect("BLS keygen"),
            pq: Some(PqKeyPair::generate()),
            weight,
        }
    }

    fn to_validator(&self) -> AvalancheSubnetValidator {
        AvalancheSubnetValidator {
            node_id: self.node_id,
            bls_pubkey: self.bls.public_key.clone(),
            weight: self.weight,
            pq_pubkey: self
                .pq
                .as_ref()
                .map_or_else(Vec::new, |k| k.public_key_bytes().to_vec()),
        }
    }

    fn sign_header(&self, network: &str, hdr: &AvalancheWarpHeader) -> AvalancheWarpSignature {
        let msg = avalanche_warp_sign_bytes(
            network,
            NETWORK_ID,
            &SUBNET_ID,
            &CHAIN_ID,
            hdr.p_chain_height,
            hdr.height,
            &hdr.block_hash,
        );
        let bls_sig = sign_bls(&self.bls.secret_key, &msg);
        let pq_sig = self.pq.as_ref().map_or_else(Vec::new, |pq| {
            pq.sign(CROSS_DOMAIN_V1, &msg).expect("ML-DSA-65 sign")
        });
        AvalancheWarpSignature {
            node_id: self.node_id,
            bls_sig,
            pq_sig,
        }
    }
}

fn make_header(
    p_chain_height: u64,
    height: u64,
    parent_hash: [u8; 32],
    state_tag: u8,
    tx_tag: u8,
    outbox_tag: u8,
    timestamp_secs: u64,
    next_validator_set_hash: Option<(u64, [u8; 32])>,
) -> AvalancheWarpHeader {
    let mut hdr = AvalancheWarpHeader {
        p_chain_height,
        height,
        parent_hash,
        state_root: [state_tag; 32],
        tx_root: [tx_tag; 32],
        warp_outbox_root: [outbox_tag; 32],
        timestamp_secs,
        next_validator_set_hash,
        block_hash: [0u8; 32],
    };
    hdr.block_hash =
        compute_avalanche_warp_block_hash(NET, NETWORK_ID, &SUBNET_ID, &CHAIN_ID, &hdr);
    hdr
}

#[derive(Default)]
struct Obs {
    seen: Vec<ObservedScheme>,
}

impl CryptoObserver for Obs {
    fn observe(&mut self, scheme: ObservedScheme) {
        self.seen.push(scheme);
    }
}

#[test]
fn avalanche_warp_verifies_pchain_weighted_bls_quorum_discloses_unslashable_and_passes_selftest() {
    let voters = [
        WarpVoter::classical(1, 35),
        WarpVoter::classical(2, 35),
        WarpVoter::classical(3, 30),
    ];
    let pinned = PinnedAvalancheSubnet {
        network_id: NETWORK_ID,
        subnet_id: SUBNET_ID,
        blockchain_id: CHAIN_ID,
        p_chain_height: 500,
        quorum_numerator: 67,
        quorum_denominator: 100,
        validators: voters.iter().map(WarpVoter::to_validator).collect(),
    };

    let hdr = make_header(
        500,
        1_200,
        [0x44; 32],
        0x55,
        0x66,
        0x77,
        1_750_000_000,
        None,
    );
    let sigs = vec![
        voters[0].sign_header(NET, &hdr),
        voters[1].sign_header(NET, &hdr),
    ];
    let payload = encode_avalanche_warp_evidence(hdr.clone(), sigs).expect("encodes");

    let base = AvalancheWarpAdapter::new(NET, Some(pinned));
    let golden = RawConsensusEvidence {
        adapter: base.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload,
        declared_height: 1_200,
        declared_root: hdr.state_root,
        submitter: Address::from([0x12; 32]),
    };
    let adapter = base.with_golden(golden.clone());

    let att = adapter
        .verify(&golden, &VerificationPolicy::strict(1_750_000_000))
        .expect("70/100 weight satisfies >2/3 and 67/100 P-Chain Warp quorum");
    assert_eq!(att.height, 1_200);
    assert_eq!(att.state_root, hdr.state_root);
    assert_eq!(att.time_unit, TimeUnit::UnixSeconds);
    assert_eq!(att.attested_block_hash, Some(hdr.block_hash));
    assert_eq!(att.attested_tx_root, Some(hdr.tx_root));
    assert_eq!(att.attested_event_root, Some(hdr.warp_outbox_root));
    assert_eq!(adapter.attested_parent(&golden), Some(hdr.parent_hash));
    // Honest KK-9 disclosure: Avalanche Snowman has no in-protocol equivocation stake-slashing!
    assert_eq!(
        att.security,
        SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG),
            signers: 70,
            required: 67,
            total_weight: 100,
            slashable: false,
        }
    );

    // Caller requiring protocol-slashable backing must be refused automatically.
    let mut slash_pol = VerificationPolicy::strict(1_750_000_000);
    slash_pol.require_slashable = true;
    assert_eq!(
        adapter.verify(&golden, &slash_pol),
        Err(AdapterError::UnslashableBacking)
    );

    let report = admit(&adapter, &VerificationPolicy::strict(1_750_000_000));
    assert!(report.golden_verified);
    let failed: Vec<&String> = report
        .probes
        .iter()
        .filter(|(_, o)| !o.passed())
        .map(|(n, _)| n)
        .collect();
    assert!(failed.is_empty(), "failed probes: {failed:?}");
    assert!(report.admitted);
}

#[test]
fn avalanche_warp_refuses_sub_two_thirds_quorum_config_and_enforces_hybrid_pq() {
    let voters = [
        WarpVoter::hybrid(11, 45),
        WarpVoter::hybrid(12, 35),
        WarpVoter::hybrid(13, 20),
    ];
    // Attempting to pin a weak 50/100 (<= 2/3) quorum must be refused even if 60% sign!
    let weak_pinned = PinnedAvalancheSubnet {
        network_id: NETWORK_ID,
        subnet_id: SUBNET_ID,
        blockchain_id: CHAIN_ID,
        p_chain_height: 500,
        quorum_numerator: 50,
        quorum_denominator: 100,
        validators: voters.iter().map(WarpVoter::to_validator).collect(),
    };
    let hdr = make_header(500, 10, [0x11; 32], 0x22, 0x33, 0x44, 1_750_000_100, None);
    let payload_ok = encode_avalanche_warp_evidence(
        hdr.clone(),
        vec![
            voters[0].sign_header(NET, &hdr),
            voters[1].sign_header(NET, &hdr),
        ],
    )
    .expect("encodes");
    let weak_adapter = AvalancheWarpAdapter::new(NET, Some(weak_pinned));
    let ev = RawConsensusEvidence {
        adapter: weak_adapter.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload: payload_ok,
        declared_height: 10,
        declared_root: hdr.state_root,
        submitter: Address::from([0x21; 32]),
    };
    let err = weak_adapter
        .verify(&ev, &VerificationPolicy::strict(1_750_000_100))
        .expect_err("<= 2/3 quorum config must fail closed");
    assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");

    // Strict 75/100 quorum with hybrid BLS + ML-DSA-65 co-signatures succeeds (45 + 35 = 80 >= 75).
    let strong_pinned = PinnedAvalancheSubnet {
        network_id: NETWORK_ID,
        subnet_id: SUBNET_ID,
        blockchain_id: CHAIN_ID,
        p_chain_height: 500,
        quorum_numerator: 75,
        quorum_denominator: 100,
        validators: voters.iter().map(WarpVoter::to_validator).collect(),
    };
    let strong_adapter = AvalancheWarpAdapter::new(NET, Some(strong_pinned));
    let mut obs = Obs::default();
    let att = strong_adapter
        .verify_observed(&ev, &VerificationPolicy::strict(1_750_000_100), &mut obs)
        .expect("80/100 hybrid BLS + ML-DSA-65 satisfies 75% quorum");
    assert_eq!(
        att.security,
        SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
            signers: 80,
            required: 75,
            total_weight: 100,
            slashable: false,
        }
    );
    assert!(obs
        .seen
        .contains(&ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG)));
    assert!(obs
        .seen
        .contains(&ObservedScheme::Scheme(SchemeId::ML_DSA_65)));

    // Stripped PQ signature on a PQ-enrolled subnet validator must fail closed.
    let mut stripped = voters[1].sign_header(NET, &hdr);
    stripped.pq_sig.clear();
    let bad_payload = encode_avalanche_warp_evidence(
        hdr,
        vec![
            voters[0].sign_header(
                NET,
                &make_header(500, 10, [0x11; 32], 0x22, 0x33, 0x44, 1_750_000_100, None),
            ),
            stripped,
        ],
    )
    .expect("encodes");
    let err = strong_adapter
        .verify(
            &RawConsensusEvidence {
                payload: bad_payload,
                ..ev
            },
            &VerificationPolicy::strict(1_750_000_100),
        )
        .expect_err("stripped ML-DSA-65 co-signature must fail closed");
    assert!(matches!(err, AdapterError::Crypto { .. }), "{err:?}");
}

#[test]
fn avalanche_warp_rotates_pchain_validators_and_adjudicates_contradiction() {
    let v_cur = [
        WarpVoter::classical(21, 50),
        WarpVoter::classical(22, 30),
        WarpVoter::classical(23, 20),
    ];
    let pinned_cur = PinnedAvalancheSubnet {
        network_id: NETWORK_ID,
        subnet_id: SUBNET_ID,
        blockchain_id: CHAIN_ID,
        p_chain_height: 1_000,
        quorum_numerator: 67,
        quorum_denominator: 100,
        validators: v_cur.iter().map(WarpVoter::to_validator).collect(),
    };

    let v_next = [WarpVoter::classical(31, 60), WarpVoter::classical(32, 40)];
    let next_vals: Vec<AvalancheSubnetValidator> =
        v_next.iter().map(WarpVoter::to_validator).collect();
    let next_hash =
        compute_avalanche_pchain_set_hash(1_050, &next_vals).expect("next P-Chain set hash");

    let rot_hdr = make_header(
        1_000,
        55,
        [0x88; 32],
        0x91,
        0x92,
        0x93,
        1_750_000_500,
        Some((1_050, next_hash)),
    );
    let rot_payload = encode_avalanche_warp_evidence(
        rot_hdr.clone(),
        vec![
            v_cur[0].sign_header(NET, &rot_hdr),
            v_cur[1].sign_header(NET, &rot_hdr),
        ],
    )
    .expect("encodes");

    let rotated = advance_avalanche_pchain_set(NET, &pinned_cur, &rot_payload, 1_050, next_vals)
        .expect("verified Warp handoff advances P-Chain validator set");
    assert_eq!(rotated.p_chain_height, 1_050);

    // Conflicting double-signed Warp headers at identical height=56 by v_next[0] are adjudicated.
    let h_a = make_header(
        1_050,
        56,
        rot_hdr.block_hash,
        0xA1,
        0xA2,
        0xA3,
        1_750_000_600,
        None,
    );
    let h_b = make_header(
        1_050,
        56,
        rot_hdr.block_hash,
        0xB1,
        0xB2,
        0xB3,
        1_750_000_600,
        None,
    );
    let contra = AvalancheWarpContradictionProof {
        height: 56,
        first_block_hash: h_a.block_hash,
        first_sig: v_next[0].sign_header(NET, &h_a),
        second_block_hash: h_b.block_hash,
        second_sig: v_next[0].sign_header(NET, &h_b),
    };
    let offender = adjudicate_avalanche_warp_contradiction(NET, &rotated, &contra)
        .expect("conflicting Warp signatures at same height must be proven");
    assert_eq!(offender.node_id, v_next[0].node_id);
    assert_eq!(offender.offending_weight, 60);
}

#[test]
fn avalanche_warp_registry_lifecycle_admits_submits_and_faults_on_contradiction() {
    use budlum_core::cross_domain::external::profile::DomainState;
    use budlum_core::cross_domain::external::prover::DomainEconomics;
    use budlum_core::cross_domain::external::registry::{ExternalDomainRegistry, RegistryError};
    use budlum_core::cross_domain::external::versioning::VersionPolicy;

    let voters = [
        WarpVoter::classical(41, 45),
        WarpVoter::classical(42, 35),
        WarpVoter::classical(43, 20),
    ];
    let pinned = PinnedAvalancheSubnet {
        network_id: NETWORK_ID,
        subnet_id: SUBNET_ID,
        blockchain_id: CHAIN_ID,
        p_chain_height: 700,
        quorum_numerator: 67,
        quorum_denominator: 100,
        validators: voters.iter().map(WarpVoter::to_validator).collect(),
    };

    let h1 = make_header(700, 10, [0x01; 32], 0x11, 0x22, 0x33, 1_750_010_000, None);
    let p1 = encode_avalanche_warp_evidence(
        h1.clone(),
        vec![
            voters[0].sign_header(NET, &h1),
            voters[1].sign_header(NET, &h1),
        ],
    )
    .expect("encodes");

    let prover = Address::from([0x66; 32]);
    let base = AvalancheWarpAdapter::new(NET, Some(pinned.clone()));
    let golden = RawConsensusEvidence {
        adapter: base.descriptor().id,
        evidence_version: EVIDENCE_VERSION,
        network: NET.to_string(),
        payload: p1,
        declared_height: 10,
        declared_root: h1.state_root,
        submitter: prover,
    };
    let adapter = base.with_golden(golden.clone());
    let policy = VerificationPolicy::strict(1_750_010_000);
    let admission = admit(&adapter, &policy);
    assert!(admission.admitted);

    let economics = DomainEconomics::default();
    let required_bond = economics.required_bond_atoms();
    let versions = VersionPolicy::single(adapter.descriptor().id, EVIDENCE_VERSION, 0);

    let mut registry = ExternalDomainRegistry::new();
    registry.set_height(50);
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
        .expect("Avalanche Warp domain registers");

    let att = registry
        .submit(&adapter, &golden, &policy)
        .expect("valid Warp bundle activates domain");
    assert_eq!(att.height, 10);
    assert_eq!(
        registry.domain(&domain_key).expect("domain").record.state,
        DomainState::Active
    );

    let fork_a = make_header(
        700,
        11,
        h1.block_hash,
        0x41,
        0x42,
        0x43,
        1_750_010_002,
        None,
    );
    let fork_b = make_header(
        700,
        11,
        h1.block_hash,
        0x51,
        0x52,
        0x53,
        1_750_010_002,
        None,
    );
    let contra = AvalancheWarpContradictionProof {
        height: 11,
        first_block_hash: fork_a.block_hash,
        first_sig: voters[0].sign_header(NET, &fork_a),
        second_block_hash: fork_b.block_hash,
        second_sig: voters[0].sign_header(NET, &fork_b),
    };
    let offender = registry
        .fault_on_avalanche_warp_contradiction(NET, &pinned, &contra)
        .expect("verified Warp contradiction faults the domain");
    assert_eq!(offender.offending_weight, 45);
    assert_eq!(
        registry.domain(&domain_key).expect("domain").record.state,
        DomainState::Faulted
    );

    let p2 = encode_avalanche_warp_evidence(
        fork_a.clone(),
        vec![
            voters[0].sign_header(NET, &fork_a),
            voters[1].sign_header(NET, &fork_a),
        ],
    )
    .expect("encodes");
    let err = registry
        .submit(
            &adapter,
            &RawConsensusEvidence {
                payload: p2,
                declared_height: 11,
                declared_root: fork_a.state_root,
                ..golden
            },
            &VerificationPolicy::strict(1_750_010_002),
        )
        .expect_err("faulted Avalanche Warp domain must refuse subsequent submissions");
    assert!(matches!(err, RegistryError::NotServing { .. }), "{err:?}");
}
