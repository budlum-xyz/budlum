use budlum_core::cross_domain::external::algorand_stateproof::{
    AlgorandStateProofAdapter, PinnedAlgorandVerifier,
};
use budlum_core::cross_domain::external::aptos_jolteon_bft::{
    encode_jolteon_evidence, jolteon_vote_sign_bytes, AptosJolteonAdapter, JolteonBlock,
    JolteonQuorumCert, JolteonTwoChainEvidence, JolteonValidator, JolteonValidatorSig,
    PinnedJolteonEpochState,
};
use budlum_core::cross_domain::external::arweave_spora::ArweaveSpOraAdapter;
use budlum_core::cross_domain::external::auxpow_pop::{AuxPowPopAdapter, PinnedAuxPowAnchor};
use budlum_core::cross_domain::external::based_preconf::{
    BasedPreconfAdapter, BasedPreconfValidator, PinnedBasedPreconfCommittee,
};
use budlum_core::cross_domain::external::domain_bridge::{
    encode_external_evidence, ExternalDomainFinalityBridge, EXTERNAL_DOMAIN_FINALITY_ADAPTER,
};
use budlum_core::cross_domain::external::heterogeneous_multiprover::CommitteeAttestationSig;
use budlum_core::cross_domain::external::mina_recursive::{
    PinnedSuccinctGenesis, SuccinctRecursiveAdapter,
};
use budlum_core::cross_domain::external::ouroboros_mithril::{
    EpochSigner, EpochStake, OuroborosMithrilAdapter,
};
use budlum_core::cross_domain::external::restaking_avs::{
    AvsQuorumMember, PinnedRestakingAvsSet, RestakedOperator, RestakingAvsAdapter,
};
use budlum_core::cross_domain::external::simplex_bft::{
    PinnedSimplexCommittee, SimplexBftAdapter, SimplexValidator,
};
use budlum_core::cross_domain::external::spec::{
    ExternalFinalityAdapter, RawConsensusEvidence, SecurityBacking, VerificationPolicy,
};
use budlum_core::cross_domain::external::stellar_fba::{
    PinnedScpTier, ScpQuorumSet, ScpValidatorNode, StellarScpAdapter,
};
use budlum_core::cross_domain::external::symbiotic_vault::SymbioticVaultAdapter;
use budlum_core::cross_domain::external::tendermint::{
    validator_address_of, validator_set_hash, TendermintCommitEvidence, TendermintFinalityAdapter,
    TendermintSignature, TendermintValidator,
};
use budlum_core::cross_domain::external::ton_catchain::{
    PinnedTonMasterchainAnchor, TonCatchainAdapter, TonValidator,
};
use budlum_core::cross_domain::external::{
    AttestedCommitteeLeg, FaultWindowLeg, HeterogeneousMultiProverAdapter,
    MultiProverCommitteeMember, MultiProverEvidence, PinnedFaultProposer, PinnedMultiProverConfig,
    RollupBatchClaim,
};
use budlum_core::crypto::ctx::CROSS_DOMAIN_V1;
use budlum_core::crypto::facts::CryptoFacts;
use budlum_core::crypto::primitives::{KeyPair, PqKeyPair};
use budlum_core::domain::finality_adapter::{DomainFinalityAdapter, FinalityStatus};
use budlum_core::domain::plugin::default_domain;
use budlum_core::domain::types::{ConsensusKind, DomainCommitment};

#[test]
fn all_eleven_external_adapters_enforce_fail_closed_pinned_trust_anchor() {
    assert!(!AlgorandStateProofAdapter::new("algorand-mainnet", None).has_pinned_trust_anchor());
    let zero_algo = PinnedAlgorandVerifier {
        genesis_hash: [1u8; 32],
        interval_index: 1,
        first_round: 1,
        last_round: 100,
        voters_commitment: [0u8; 32],
        voter_count: 1,
        total_weight: 100,
        threshold_bps: 6667,
    };
    assert!(
        !AlgorandStateProofAdapter::new("algorand-mainnet", Some(zero_algo))
            .has_pinned_trust_anchor()
    );
    let ok_algo = PinnedAlgorandVerifier {
        genesis_hash: [1u8; 32],
        interval_index: 1,
        first_round: 1,
        last_round: 100,
        voters_commitment: [2u8; 32],
        voter_count: 4,
        total_weight: 1000,
        threshold_bps: 6667,
    };
    assert!(
        AlgorandStateProofAdapter::new("algorand-mainnet", Some(ok_algo)).has_pinned_trust_anchor()
    );

    assert!(!ArweaveSpOraAdapter::new("arweave-mainnet").has_pinned_trust_anchor());
    assert!(!ArweaveSpOraAdapter::new("arweave-mainnet")
        .with_pinned_operator([0u8; 32], vec![1, 2, 3])
        .has_pinned_trust_anchor());
    assert!(ArweaveSpOraAdapter::new("arweave-mainnet")
        .with_pinned_operator([7u8; 32], vec![1, 2, 3])
        .has_pinned_trust_anchor());

    assert!(!AuxPowPopAdapter::new("doge-mainnet", None).has_pinned_trust_anchor());
    let zero_aux = PinnedAuxPowAnchor {
        aux_chain_id: 1,
        trusted_parent_hash: [0u8; 32],
        max_target_bits: 0x1d00_ffff,
        min_cumulative_work: [0u8; 32],
        min_confirmations: 6,
        pop_signers: Vec::new(),
    };
    assert!(!AuxPowPopAdapter::new("doge-mainnet", Some(zero_aux)).has_pinned_trust_anchor());
    let ok_aux = PinnedAuxPowAnchor {
        aux_chain_id: 1,
        trusted_parent_hash: [9u8; 32],
        max_target_bits: 0x1d00_ffff,
        min_cumulative_work: [0u8; 32],
        min_confirmations: 6,
        pop_signers: Vec::new(),
    };
    assert!(AuxPowPopAdapter::new("doge-mainnet", Some(ok_aux)).has_pinned_trust_anchor());

    assert!(!BasedPreconfAdapter::new("based-l2", None).has_pinned_trust_anchor());
    let empty_based = PinnedBasedPreconfCommittee {
        epoch: 1,
        l1_chain_id: 1,
        require_focil: true,
        members: Vec::new(),
    };
    assert!(!BasedPreconfAdapter::new("based-l2", Some(empty_based)).has_pinned_trust_anchor());
    let ok_based = PinnedBasedPreconfCommittee {
        epoch: 1,
        l1_chain_id: 1,
        require_focil: true,
        members: vec![BasedPreconfValidator {
            ed25519_pubkey: [3u8; 32],
            voting_weight: 100,
            pq_pubkey: Vec::new(),
        }],
    };
    assert!(BasedPreconfAdapter::new("based-l2", Some(ok_based)).has_pinned_trust_anchor());

    assert!(!SuccinctRecursiveAdapter::new("mina-mainnet", None).has_pinned_trust_anchor());
    let ok_mina = PinnedSuccinctGenesis {
        genesis_state_hash: [1u8; 32],
        genesis_staking_ledger_root: [2u8; 32],
        step_program_hash: [3u8; 32],
        slots_per_sub_window: 7,
        slots_per_epoch: 77,
        min_window_density_slots: 50,
        aggregator_pq_pubkey: vec![4u8; 32],
    };
    assert!(SuccinctRecursiveAdapter::new("mina-mainnet", Some(ok_mina)).has_pinned_trust_anchor());

    assert!(!OuroborosMithrilAdapter::new("cardano-mainnet", 1).has_pinned_trust_anchor());
    assert!(!OuroborosMithrilAdapter::new("cardano-mainnet", 1)
        .with_epoch_stake(EpochStake {
            epoch: 1,
            signers: Vec::new(),
        })
        .has_pinned_trust_anchor());
    assert!(OuroborosMithrilAdapter::new("cardano-mainnet", 1)
        .with_epoch_stake(EpochStake {
            epoch: 1,
            signers: vec![EpochSigner {
                public_key: [5u8; 32],
                stake: 1_000,
            }],
        })
        .has_pinned_trust_anchor());

    assert!(!RestakingAvsAdapter::new("avs-mainnet", None).has_pinned_trust_anchor());
    let ok_avs = PinnedRestakingAvsSet {
        epoch: 1,
        min_withdrawal_delay: 10,
        max_shared_avs_per_operator: 4,
        min_effective_restaked_stake: 100,
        native_validators: vec![AvsQuorumMember {
            ed25519_pubkey: [6u8; 32],
            stake_weight: 100,
            pq_pubkey: Vec::new(),
        }],
        restaked_operators: vec![RestakedOperator {
            ed25519_pubkey: [7u8; 32],
            raw_stake: 200,
            shared_avs_count: 1,
            pq_pubkey: Vec::new(),
        }],
        eots_providers: Vec::new(),
    };
    assert!(RestakingAvsAdapter::new("avs-mainnet", Some(ok_avs)).has_pinned_trust_anchor());

    assert!(!SimplexBftAdapter::new("simplex-mainnet", None).has_pinned_trust_anchor());
    let ok_simplex = PinnedSimplexCommittee {
        epoch: 1,
        validators: vec![SimplexValidator {
            ed25519_pubkey: [8u8; 32],
            stake_weight: 100,
            pq_pubkey: Vec::new(),
        }],
    };
    assert!(SimplexBftAdapter::new("simplex-mainnet", Some(ok_simplex)).has_pinned_trust_anchor());

    assert!(!StellarScpAdapter::new("stellar-mainnet", None).has_pinned_trust_anchor());
    let ok_scp = PinnedScpTier {
        network_passphrase: "Public Global Stellar Network ; September 2015".into(),
        has_bonded_slash_escrow: false,
        nodes: vec![ScpValidatorNode {
            ed25519_pubkey: [9u8; 32],
            quorum_set: ScpQuorumSet {
                threshold: 1,
                validators: vec![[9u8; 32]],
                inner_sets: Vec::new(),
            },
            pq_pubkey: Vec::new(),
        }],
    };
    assert!(StellarScpAdapter::new("stellar-mainnet", Some(ok_scp)).has_pinned_trust_anchor());

    assert!(!SymbioticVaultAdapter::new("symbiotic-mainnet").has_pinned_trust_anchor());
    assert!(SymbioticVaultAdapter::new("symbiotic-mainnet")
        .with_pinned_committee_keys(&[vec![1u8; 32]], &[vec![2u8; 32]])
        .has_pinned_trust_anchor());

    assert!(!TonCatchainAdapter::new("ton-mainnet", None).has_pinned_trust_anchor());
    let ok_ton = PinnedTonMasterchainAnchor {
        key_block_seqno: 1,
        utime_since: 100,
        utime_until: 200,
        validators: vec![TonValidator {
            ed25519_pubkey: [10u8; 32],
            weight: 100,
            pq_pubkey: Vec::new(),
        }],
    };
    assert!(TonCatchainAdapter::new("ton-mainnet", Some(ok_ton)).has_pinned_trust_anchor());
}

#[test]
fn heterogeneous_multiprover_fault_plus_committee_bridge_preserves_valid_signature_quorum() {
    use budlum_core::cross_domain::external::heterogeneous_multiprover::{
        committee_vote_sign_bytes, encode_multiprover_evidence, fault_claim_sign_bytes,
        ADAPTER_NAME, EVIDENCE_VERSION,
    };
    use budlum_core::cross_domain::external::spec::{
        AdapterId, RawConsensusEvidence, SecurityBacking, VerificationPolicy,
    };

    let net = "stage2-rollup-mainnet";
    let batch_ts = 1_700_000_000u64;
    let window_secs = 604_800u64;
    let fault_key = (KeyPair::generate().unwrap(), PqKeyPair::generate());
    let committee_keys: Vec<_> = (0..4)
        .map(|_| (KeyPair::generate().unwrap(), PqKeyPair::generate()))
        .collect();
    let measurement = [0x7Au8; 32];
    let pinned = PinnedMultiProverConfig {
        stark_program_hash: [0x55u8; 32],
        chain_id: 42_161,
        challenge_window_secs: window_secs,
        min_fault_bond_atoms: 10_000,
        fault_proposers: vec![PinnedFaultProposer {
            ed25519_pk: fault_key.0.public_key_bytes(),
            pq_pk: fault_key.1.public_key_bytes().to_vec(),
        }],
        expected_measurement: measurement,
        // Realistic stake weights summing to 100 > legs.len() == 2!
        committee: committee_keys
            .iter()
            .map(|(ed, pq)| MultiProverCommitteeMember {
                ed25519_pk: ed.public_key_bytes(),
                pq_pk: pq.public_key_bytes().to_vec(),
                weight: 25,
            })
            .collect(),
        require_canonical_stark_set: false,
        require_pq_leg: true,
    };
    let claim = RollupBatchClaim {
        batch_index: 42,
        l1_batch_hash: [0xC3; 32],
        pre_state_root: [0xA1; 32],
        post_state_root: [0xB2; 32],
        withdrawal_root: [0xD4; 32],
        batch_timestamp_secs: batch_ts,
    };
    let proposed_at_secs = batch_ts + 60;
    let bond = 50_000u128;
    let fault_digest = fault_claim_sign_bytes(
        net,
        &claim,
        &claim.post_state_root,
        &claim.withdrawal_root,
        proposed_at_secs,
        bond,
    );
    let fault_leg = FaultWindowLeg {
        post_state_root: claim.post_state_root,
        withdrawal_root: claim.withdrawal_root,
        proposed_at_secs,
        proposer_bond_atoms: bond,
        open_challenges: 0,
        proposer_ed25519_pk: fault_key.0.public_key_bytes(),
        proposer_ed25519_sig: fault_key.0.sign(&fault_digest).to_vec(),
        proposer_pq_sig: fault_key.1.sign(CROSS_DOMAIN_V1, &fault_digest).unwrap(),
    };

    let comm_digest = committee_vote_sign_bytes(
        net,
        &claim,
        &claim.post_state_root,
        &claim.withdrawal_root,
        &measurement,
    );
    // 3 of 4 members sign (weight 75 > 66 = 2/3 of 100).
    let signatures = committee_keys
        .iter()
        .take(3)
        .map(|(ed, pq)| CommitteeAttestationSig {
            signer_ed25519_pk: ed.public_key_bytes(),
            ed25519_sig: ed.sign(&comm_digest).to_vec(),
            pq_sig: pq.sign(CROSS_DOMAIN_V1, &comm_digest).unwrap(),
        })
        .collect();
    let committee_leg = AttestedCommitteeLeg {
        post_state_root: claim.post_state_root,
        withdrawal_root: claim.withdrawal_root,
        measurement_digest: measurement,
        signatures,
    };

    let bundle = MultiProverEvidence {
        claim: claim.clone(),
        stark_leg: None,
        fault_leg: Some(fault_leg),
        committee_leg: Some(committee_leg),
    };
    let raw = RawConsensusEvidence {
        adapter: AdapterId::from_name(ADAPTER_NAME),
        network: net.into(),
        evidence_version: EVIDENCE_VERSION,
        declared_height: claim.batch_index,
        declared_root: claim.post_state_root,
        payload: encode_multiprover_evidence(&bundle).unwrap(),
        submitter: budlum_core::core::address::Address([0x09; 32]),
    };

    let policy = VerificationPolicy {
        min_depth: 0,
        max_age: 0,
        now: proposed_at_secs + window_secs + 1,
        require_declared_match: true,
        require_slashable: false,
    };
    let adapter = HeterogeneousMultiProverAdapter::new(net, Some(pinned));
    let att = adapter
        .verify(&raw, &policy)
        .expect("mature 2-of-3 FaultWindow + PqAttestedCommittee bundle verifies");

    // Invariant 1: `SecurityBacking::SignatureSet` must never invert `signers < required`
    // by mixing leg count (signers) with weight threshold (required).
    if let SecurityBacking::SignatureSet {
        signers,
        required,
        total_weight,
        ..
    } = att.security
    {
        assert!(
            signers >= required && required > 0 && total_weight >= u128::from(signers),
            "degenerate SignatureSet backing: signers={signers}, required={required}, total_weight={total_weight}"
        );
    } else {
        panic!(
            "expected SignatureSet backing on non-STARK 2-of-3 legs, got {:?}",
            att.security
        );
    }

    // Invariant 2: Bridging through `ExternalDomainFinalityBridge` (which invokes
    // `FinalityProofShape::from_external_attestation`) must succeed (`Finalized`)
    // rather than failing with `DegenerateSignatureQuorum`!
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter), policy);
    let kind = ConsensusKind::Custom("heterogeneous-multiprover-2of3".to_string());
    let mut dom = default_domain(314, kind.clone(), 42_161, net, 0);
    dom.finality_adapter = EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string();
    let proof = encode_external_evidence(&raw).expect("encode external evidence");
    let finality_proof_hash =
        budlum_core::domain::hash_finality_proof(&proof).expect("hash finality proof");
    let commitment = DomainCommitment {
        domain_id: 314,
        domain_height: claim.batch_index,
        domain_block_hash: claim.l1_batch_hash,
        parent_domain_block_hash: [0u8; 32],
        state_root: claim.post_state_root,
        tx_root: [0u8; 32],
        event_root: claim.withdrawal_root,
        finality_proof_hash,
        consensus_kind: kind,
        validator_set_hash: [0u8; 32],
        timestamp_ms: 0,
        sequence: 1,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    };
    let mut facts = CryptoFacts::new();
    let status = bridge
        .verify_finality_observed(&dom, &commitment, &proof, &mut facts)
        .expect("bridge call succeeds");
    assert_eq!(
        status,
        FinalityStatus::Finalized,
        "ExternalDomainFinalityBridge must finalize valid 2-of-3 FaultWindow + Committee evidence without DegenerateSignatureQuorum"
    );
}

#[test]
fn tendermint_unequal_voting_power_bridge_preserves_valid_signature_quorum() {
    // 4 validators with unequal voting powers [70, 10, 10, 10] (total = 100, required > 2/3 => 67).
    // Validator 0 alone holds 70 >= 67 voting power!
    let k0 = KeyPair::generate().expect("ed25519 0");
    let k1 = KeyPair::generate().expect("ed25519 1");
    let k2 = KeyPair::generate().expect("ed25519 2");
    let k3 = KeyPair::generate().expect("ed25519 3");
    let pk0: [u8; 32] = k0.public_key_bytes();
    let pk1: [u8; 32] = k1.public_key_bytes();
    let pk2: [u8; 32] = k2.public_key_bytes();
    let pk3: [u8; 32] = k3.public_key_bytes();

    let validators = vec![
        TendermintValidator {
            address: validator_address_of(&pk0),
            public_key: pk0,
            voting_power: 70,
        },
        TendermintValidator {
            address: validator_address_of(&pk1),
            public_key: pk1,
            voting_power: 10,
        },
        TendermintValidator {
            address: validator_address_of(&pk2),
            public_key: pk2,
            voting_power: 10,
        },
        TendermintValidator {
            address: validator_address_of(&pk3),
            public_key: pk3,
            voting_power: 10,
        },
    ];
    let vhash = validator_set_hash(&validators);
    let commit_ts = 1_795_000_000u64;
    let mut commit = TendermintCommitEvidence {
        chain_id: "cosmos-weighted-1".to_string(),
        height: 42,
        round: 0,
        block_hash: [0u8; 32],
        parts_total: 1,
        parts_hash: [0x22; 32],
        version_block: 11,
        last_block_hash: [0x33; 32],
        last_parts_total: 1,
        last_parts_hash: [0x44; 32],
        last_commit_hash: [0x55; 32],
        data_hash: [0x66; 32],
        validators_hash: vhash,
        next_validators_hash: vhash,
        consensus_hash: [0x77; 32],
        app_hash: [0x88; 32],
        last_results_hash: [0x99; 32],
        evidence_hash: [0xAA; 32],
        proposer_address: validators[0].address,
        commit_time: commit_ts,
        commit_time_nanos: 0,
        validators,
        signatures: Vec::new(),
    };
    commit.block_hash = commit.header_hash();
    let mut sig0 = TendermintSignature {
        address: commit.validators[0].address,
        timestamp_seconds: i64::try_from(commit_ts).expect("i64"),
        timestamp_nanos: 0,
        signature: Vec::new(),
    };
    let sign_bytes = commit.canonical_vote_bytes(&sig0);
    sig0.signature = k0.sign(&sign_bytes).to_vec();
    commit.signatures = vec![sig0];

    let adapter =
        TendermintFinalityAdapter::new_pinned("cosmos-weighted", "cosmos-weighted-1", Some(vhash));
    let raw = RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: 2,
        network: "cosmos-weighted".to_string(),
        payload: commit.encode().expect("encode tendermint commit"),
        declared_height: commit.height,
        declared_root: commit.app_hash,
        submitter: budlum_core::core::address::Address([0x05; 32]),
    };
    let policy = VerificationPolicy::strict(commit_ts);
    let att = adapter
        .verify(&raw, &policy)
        .expect("70/100 CometBFT single heavy validator commit is valid");
    if let SecurityBacking::SignatureSet {
        signers,
        required,
        total_weight,
        ..
    } = att.security
    {
        assert!(
            signers >= required && required > 0 && total_weight >= u128::from(signers),
            "degenerate Tendermint SignatureSet: signers={signers}, required={required}, total_weight={total_weight}"
        );
    } else {
        panic!("expected SignatureSet backing");
    }

    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter), policy);
    let kind = ConsensusKind::Custom("tendermint-bft".to_string());
    let mut dom = default_domain(315, kind.clone(), 9001, "cosmos-weighted", 0);
    dom.finality_adapter = EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string();
    let proof = encode_external_evidence(&raw).expect("encode external evidence");
    let finality_proof_hash =
        budlum_core::domain::hash_finality_proof(&proof).expect("hash finality proof");
    let commitment = DomainCommitment {
        domain_id: 315,
        domain_height: commit.height,
        domain_block_hash: commit.block_hash,
        parent_domain_block_hash: [0u8; 32],
        state_root: commit.app_hash,
        tx_root: [0u8; 32],
        event_root: [0u8; 32],
        finality_proof_hash,
        consensus_kind: kind,
        validator_set_hash: [0u8; 32],
        timestamp_ms: 0,
        sequence: 1,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    };
    let mut facts = CryptoFacts::new();
    let status = bridge
        .verify_finality_observed(&dom, &commitment, &proof, &mut facts)
        .expect("bridge call succeeds");
    assert_eq!(
        status,
        FinalityStatus::Finalized,
        "ExternalDomainFinalityBridge must finalize valid 70/100 Tendermint commit without DegenerateSignatureQuorum"
    );
}

#[test]
fn aptos_jolteon_unequal_voting_power_bridge_preserves_valid_signature_quorum() {
    // 4 validators with unequal voting powers [70, 10, 10, 10] (total = 100 > 2/3 when validator 0 signs).
    let net = "aptos-weighted";
    let ed0 = KeyPair::generate().expect("ed0");
    let pq0 = PqKeyPair::generate();
    let pk0: [u8; 32] = ed0.public_key_bytes();

    let mut validators = vec![JolteonValidator {
        ed25519_pubkey: pk0,
        voting_power: 70,
        pq_pubkey: pq0.public_key_bytes().to_vec(),
    }];
    for _ in 0..3 {
        let ed = KeyPair::generate().expect("ed");
        let pq = PqKeyPair::generate();
        validators.push(JolteonValidator {
            ed25519_pubkey: ed.public_key_bytes(),
            voting_power: 10,
            pq_pubkey: pq.public_key_bytes().to_vec(),
        });
    }
    let epoch_state = PinnedJolteonEpochState {
        epoch: 4,
        validators,
    };

    let mut b0 = JolteonBlock {
        epoch: 4,
        round: 11,
        parent_round: 10,
        height: 9_000,
        timestamp_usecs: 1_770_000_000_000_000,
        parent_hash: [0x11; 32],
        state_root: [0x22; 32],
        tx_accumulator_root: [0x33; 32],
        event_root: [0x44; 32],
        next_epoch_state_digest: None,
        block_hash: [0u8; 32],
    };
    b0.block_hash = b0.compute_hash(net);

    let mut b1 = JolteonBlock {
        epoch: 4,
        round: 12,
        parent_round: 11,
        height: 9_001,
        timestamp_usecs: 1_770_000_000_500_000,
        parent_hash: b0.block_hash,
        state_root: [0x55; 32],
        tx_accumulator_root: [0x66; 32],
        event_root: [0x77; 32],
        next_epoch_state_digest: None,
        block_hash: [0u8; 32],
    };
    b1.block_hash = b1.compute_hash(net);

    let d0 = jolteon_vote_sign_bytes(net, 4, 11, &b0.block_hash, &b0.state_root);
    let d1 = jolteon_vote_sign_bytes(net, 4, 12, &b1.block_hash, &b1.state_root);
    let sig_for = |digest: &[u8; 32]| {
        vec![JolteonValidatorSig {
            signer_pubkey: pk0,
            ed25519_sig: ed0.sign(digest).to_vec(),
            pq_sig: pq0.sign(CROSS_DOMAIN_V1, digest).expect("pq sign"),
        }]
    };
    let bundle = JolteonTwoChainEvidence {
        ordered_block: b0.clone(),
        ordered_qc: JolteonQuorumCert {
            epoch: 4,
            round: 11,
            block_hash: b0.block_hash,
            certified_state_root: b0.state_root,
            signatures: sig_for(&d0),
        },
        round_skip_tc: None,
        commit_block: b1.clone(),
        commit_qc: JolteonQuorumCert {
            epoch: 4,
            round: 12,
            block_hash: b1.block_hash,
            certified_state_root: b1.state_root,
            signatures: sig_for(&d1),
        },
    };
    let adapter = AptosJolteonAdapter::new(net, Some(epoch_state));
    let raw = RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: 1,
        network: net.to_string(),
        payload: encode_jolteon_evidence(&bundle).expect("encode jolteon"),
        declared_height: b0.height,
        declared_root: b0.state_root,
        submitter: budlum_core::core::address::Address([0x06; 32]),
    };
    let mut policy = VerificationPolicy::strict(0);
    policy.require_slashable = false;
    let att = adapter
        .verify(&raw, &policy)
        .expect("70/100 Jolteon single heavy validator 2-chain QC is valid");
    if let SecurityBacking::SignatureSet {
        signers,
        required,
        total_weight,
        ..
    } = att.security
    {
        assert!(
            signers >= required && required > 0 && total_weight >= u128::from(signers),
            "degenerate Jolteon SignatureSet: signers={signers}, required={required}, total_weight={total_weight}"
        );
    } else {
        panic!("expected SignatureSet backing");
    }

    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter), policy);
    let kind = ConsensusKind::Custom("aptos-jolteon-2chain-bft".to_string());
    let mut dom = default_domain(316, kind.clone(), 9002, net, 0);
    dom.finality_adapter = EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string();
    let proof = encode_external_evidence(&raw).expect("encode external evidence");
    let finality_proof_hash =
        budlum_core::domain::hash_finality_proof(&proof).expect("hash finality proof");
    let commitment = DomainCommitment {
        domain_id: 316,
        domain_height: b0.height,
        domain_block_hash: b0.block_hash,
        parent_domain_block_hash: [0u8; 32],
        state_root: b0.state_root,
        tx_root: b0.tx_accumulator_root,
        event_root: b0.event_root,
        finality_proof_hash,
        consensus_kind: kind,
        validator_set_hash: [0u8; 32],
        timestamp_ms: 0,
        sequence: 1,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    };
    let mut facts = CryptoFacts::new();
    let status = bridge
        .verify_finality_observed(&dom, &commitment, &proof, &mut facts)
        .expect("bridge call succeeds");
    assert_eq!(
        status,
        FinalityStatus::Finalized,
        "ExternalDomainFinalityBridge must finalize valid 70/100 Aptos Jolteon 2-chain evidence without DegenerateSignatureQuorum"
    );
}
