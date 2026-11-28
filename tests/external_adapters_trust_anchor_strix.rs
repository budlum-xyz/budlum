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
fn quorum_refusal_votes_do_not_consume_claim_seats_or_spoof_unassailable_claim_lead() {
    use budlum_core::core::address::Address;
    use budlum_core::cross_domain::external::ethereum::{
        build_deneb_update_payload, BlsVerifier, PinnedCommittee,
    };
    use budlum_core::cross_domain::external::intake::{
        AdapterSpec, IntakeError, IntakeState, RegistrationRequest,
    };
    use budlum_core::cross_domain::external::profile::DomainState;
    use budlum_core::cross_domain::external::quorum::{
        decide, lead_is_unassailable, Answer, QuorumOutcome, QuorumPolicy,
    };
    use budlum_core::cross_domain::external::selftest::RefusalKind;
    use budlum_core::cross_domain::external::spec::{RawConsensusEvidence, VerificationPolicy};
    use budlum_core::cross_domain::external::versioning::VersionPolicy;

    struct TestBls;
    impl BlsVerifier for TestBls {
        fn verify_aggregate(
            &self,
            _signing_root: &[u8; 32],
            aggregate_pubkey: &[u8],
            signature: &[u8],
            participants: u64,
        ) -> Result<(), String> {
            if participants == 0 {
                return Err("nobody signed".to_string());
            }
            if signature.iter().all(|b| *b == 0) {
                return Err("signature is not a valid curve point".to_string());
            }
            if aggregate_pubkey.iter().all(|b| *b == 0) {
                return Err("public key is not a valid curve point".to_string());
            }
            Ok(())
        }
        fn sync_committee_closed(&self) -> bool {
            false
        }
    }

    let policy_3_8 = QuorumPolicy::strict(3, 8);
    let tied_claim_and_refusal = [
        Answer::Claim([0xaa; 32]),
        Answer::Claim([0xaa; 32]),
        Answer::Claim([0xaa; 32]),
        Answer::ConsensusRefusal(RefusalKind::Crypto),
        Answer::ConsensusRefusal(RefusalKind::Crypto),
        Answer::ConsensusRefusal(RefusalKind::Crypto),
    ];
    assert_eq!(
        decide(&tied_claim_and_refusal, &policy_3_8),
        QuorumOutcome::AgreedClaim {
            claim: [0xaa; 32],
            count: 3,
        }
    );

    // Even when 4 provers refused and 3 claim seats remain under threshold 3,
    // the refusal lead is NOT unassailable because threshold-many claims can
    // still arrive and overrule refusals.
    let four_refusals = [Answer::ConsensusRefusal(RefusalKind::Crypto); 4];
    assert!(
        !lead_is_unassailable(&four_refusals, &QuorumPolicy::strict(3, 5), 3),
        "a refusal lead cannot be unassailable while remaining claim seats can still reach threshold"
    );
    assert!(
        lead_is_unassailable(&four_refusals, &QuorumPolicy::strict(3, 5), 2),
        "once fewer than threshold claim seats remain and no claim arrived, the refusal lead holds"
    );

    // End-to-end IntakeState round griefing resistance: threshold=4, max_participants=5.
    // Two bad-signature refusals must not lock out the fourth honest claim or fault the domain.
    let committee = PinnedCommittee {
        period: 0,
        aggregate_pubkey: vec![0x11; 96],
        next_committee_root: [0xbb; 32],
    };
    let spec = AdapterSpec::EthereumSync {
        network: "testnet".to_string(),
        committee: Some(committee.clone()),
    };
    let good_payload =
        build_deneb_update_payload(64, 128, 0, &committee, &[0x22; 96], &[0xff; 64], [0xcc; 32]);
    let bad_sig_payload =
        build_deneb_update_payload(64, 128, 0, &committee, &[0x00; 96], &[0xff; 64], [0xcc; 32]);
    let adapter = spec.build(Some(Box::new(TestBls)), None);
    let adapter_id = adapter.descriptor().id;
    let ev_ver = adapter.descriptor().accepted_evidence_versions[0];

    let mut state = IntakeState::new();
    state.pin_ethereum_committee("testnet".to_string(), committee);
    let economics = IntakeState::conservative_economics(1_000_000);
    let bond = economics.required_bond_atoms();
    let golden = RawConsensusEvidence {
        adapter: adapter_id,
        evidence_version: ev_ver,
        network: "testnet".to_string(),
        payload: good_payload.clone(),
        declared_height: 64,
        declared_root: [0xcc; 32],
        submitter: Address([9; 32]),
    };
    let key = state
        .register_domain(
            RegistrationRequest {
                spec,
                policy: VerificationPolicy::strict(1_000),
                economics,
                versions: VersionPolicy::single(adapter_id, ev_ver, 0),
                bond_atoms: bond,
                poster: Address([9; 32]),
                golden,
            },
            Some(Box::new(TestBls)),
        )
        .expect("domain registration");

    for prover in 1u8..=6u8 {
        state
            .bond_prover(&key, Address([prover; 32]), bond)
            .expect("bond prover");
    }
    state
        .set_quorum_policy(&key, QuorumPolicy::strict(4, 5))
        .expect("install 4-of-5 strict quorum policy");

    for bad_prover in [1u8, 2u8] {
        let bad_ev = RawConsensusEvidence {
            adapter: adapter_id,
            evidence_version: ev_ver,
            network: "testnet".to_string(),
            payload: bad_sig_payload.clone(),
            declared_height: 64,
            declared_root: [0xcc; 32],
            submitter: Address([bad_prover; 32]),
        };
        let res = state.submit_evidence(&bad_ev, Some(Box::new(TestBls)));
        assert!(
            matches!(res, Err(IntakeError::RoundPending)),
            "bad-signature refusal {bad_prover} must leave the round pending, got {res:?}"
        );
    }

    for honest_prover in [3u8, 4u8, 5u8] {
        let ev = RawConsensusEvidence {
            adapter: adapter_id,
            evidence_version: ev_ver,
            network: "testnet".to_string(),
            payload: good_payload.clone(),
            declared_height: 64,
            declared_root: [0xcc; 32],
            submitter: Address([honest_prover; 32]),
        };
        let res = state.submit_evidence(&ev, Some(Box::new(TestBls)));
        assert!(
            matches!(res, Err(IntakeError::RoundPending)),
            "honest prover {honest_prover} must keep the round open (not Disputed/Faulted), got {res:?}"
        );
    }

    let closer = RawConsensusEvidence {
        adapter: adapter_id,
        evidence_version: ev_ver,
        network: "testnet".to_string(),
        payload: good_payload,
        declared_height: 64,
        declared_root: [0xcc; 32],
        submitter: Address([6u8; 32]),
    };
    let committed = state
        .submit_evidence(&closer, Some(Box::new(TestBls)))
        .expect("fourth honest prover still has a claim seat and commits the attestation");
    assert_eq!(committed.state_root, [0xcc; 32]);
    assert_eq!(
        state.registry.domain(&key).expect("domain").record.state,
        DomainState::Active
    );
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

#[test]
fn symbiotic_vault_refuses_zero_or_dust_free_collateral_in_finality_verification() {
    use budlum_core::cross_domain::external::spec::AdapterError;
    use budlum_core::cross_domain::external::symbiotic_vault::{
        SymbioticSignature, SymbioticVaultEvidence,
    };
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature as SecpSignature, SigningKey as SecpSigningKey};

    let net = "mainnet";
    let secp0 = SecpSigningKey::from_bytes(&[0x31u8; 32].into()).expect("secp0");
    let secp1 = SecpSigningKey::from_bytes(&[0x32u8; 32].into()).expect("secp1");
    let c_keys = vec![
        secp0
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
        secp1
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
    ];
    let pq0 = PqKeyPair::generate();
    let pq1 = PqKeyPair::generate();
    let pq_keys = vec![
        pq0.public_key_bytes().to_vec(),
        pq1.public_key_bytes().to_vec(),
    ];

    let sign_ev = |gross: u128, encumbered: u128| -> SymbioticVaultEvidence {
        let mut ev = SymbioticVaultEvidence {
            magic: *b"BDLSYM01",
            vault_id: b"vault-eth-strix".to_vec(),
            asset_symbol: b"ETH".to_vec(),
            epoch: 42,
            gross_collateral: gross,
            encumbered_collateral: encumbered,
            collateral_root: [0xAB; 32],
            classical_signatures: Vec::new(),
            classical_threshold: 2,
            pq_signatures: Vec::new(),
            pq_threshold: 2,
            classical_signer_keys: c_keys.clone(),
            pq_signer_keys: pq_keys.clone(),
        };
        let msg = ev.signing_digest(net);
        ev.classical_signatures = [&secp0, &secp1]
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let raw: SecpSignature = sk.sign_prehash(&msg).expect("secp sign");
                SymbioticSignature {
                    signer_index: i as u32,
                    signature: raw.normalize_s().to_bytes().to_vec(),
                }
            })
            .collect();
        ev.pq_signatures = [&pq0, &pq1]
            .iter()
            .enumerate()
            .map(|(i, kp)| SymbioticSignature {
                signer_index: i as u32,
                signature: kp
                    .sign(budlum_core::crypto::ctx::CROSS_DOMAIN_V1, &msg)
                    .expect("pq sign"),
            })
            .collect();
        ev
    };

    let adapter = SymbioticVaultAdapter::new(net).with_pinned_committee_keys(&c_keys, &pq_keys);
    let mut policy = VerificationPolicy::strict(0);
    policy.require_slashable = false;

    // 1. Standalone contamination helper still returns 0 on gross=0, encumbered=0,
    //    but `ExternalFinalityAdapter::verify` MUST refuse zero-collateral economic finality!
    let zero_ev = sign_ev(0, 0);
    assert_eq!(adapter.verify_collateral(&zero_ev).expect("zero ratio"), 0);
    let zero_raw = RawConsensusEvidence {
        adapter: adapter.descriptor().id,
        evidence_version: 1,
        network: net.to_string(),
        payload: serde_json::to_vec(&zero_ev).expect("json"),
        declared_height: zero_ev.epoch,
        declared_root: zero_ev.collateral_root,
        submitter: budlum_core::core::address::Address([0x07; 32]),
    };
    let err_zero = adapter
        .verify(&zero_raw, &policy)
        .expect_err("zero free_collateral must be refused by Symbiotic finality verify");
    assert!(
        matches!(err_zero, AdapterError::ConsensusRule { ref rule } if rule.contains("zero free collateral")),
        "unexpected error on zero collateral: {err_zero:?}"
    );

    // 2. Dust collateral below signer count (`free_collateral = 1 < 2 PQ signers`) must also
    //    fail closed in `verify` instead of emitting a degenerate SignatureSet (`total_weight < signers`).
    let dust_ev = sign_ev(1, 0);
    let dust_raw = RawConsensusEvidence {
        payload: serde_json::to_vec(&dust_ev).expect("json"),
        ..zero_raw.clone()
    };
    let err_dust = adapter
        .verify(&dust_raw, &policy)
        .expect_err("free_collateral < pq_signatures.len() must fail closed");
    assert!(
        matches!(err_dust, AdapterError::ConsensusRule { ref rule } if rule.contains("below PQ signer count")),
        "unexpected error on dust collateral: {err_dust:?}"
    );

    // 3. Valid economic collateral (`free_collateral >= signers`) passes both adapter and bridge!
    let ok_ev = sign_ev(1_000_000, 200_000);
    let ok_raw = RawConsensusEvidence {
        payload: serde_json::to_vec(&ok_ev).expect("json"),
        ..zero_raw
    };
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter), policy);
    let kind = ConsensusKind::Custom("symbiotic-curated-vault".to_string());
    let mut dom = default_domain(317, kind.clone(), 9003, net, 0);
    dom.finality_adapter = EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string();
    let proof = encode_external_evidence(&ok_raw).expect("encode external evidence");
    let finality_proof_hash =
        budlum_core::domain::hash_finality_proof(&proof).expect("hash finality proof");
    let commitment = DomainCommitment {
        domain_id: 317,
        domain_height: ok_ev.epoch,
        domain_block_hash: ok_ev.collateral_root,
        parent_domain_block_hash: [0u8; 32],
        state_root: ok_ev.collateral_root,
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
    assert_eq!(status, FinalityStatus::Finalized);

    // 4. `ArweaveSpOraAdapter` also binds `FinalityAttestation::evidence_digest` to
    //    `RawConsensusEvidence::digest()`, so `ExternalDomainFinalityBridge` finalizes it!
    use budlum_core::cross_domain::external::arweave_spora::{
        compute_weave_leaf, fold_weave_merkle_path, ArweaveSpOraEvidence,
    };
    let ar_net = "arweave-mainnet";
    let ar_ed = KeyPair::generate().expect("ed25519");
    let ar_pq = PqKeyPair::generate();
    let chunk_id = b"arweave-chunk-strix-01".to_vec();
    let chunk_data_hash = [0x5A; 32];
    let chunk_size = 256 * 1024;
    let chunk_offset = 262_144;
    let merkle_proof = vec![[0x01; 32], [0x02; 32]];
    let leaf = compute_weave_leaf(&chunk_id, &chunk_data_hash, chunk_offset, chunk_size);
    let weave_root = fold_weave_merkle_path(leaf, 1, &merkle_proof);
    let mut ar_ev = ArweaveSpOraEvidence {
        magic: *b"BDLARA01",
        chunk_id,
        chunk_data_hash,
        block_height: 1_200_000,
        epoch: 5_000,
        weave_root,
        merkle_proof,
        chunk_offset,
        chunk_size,
        gross_endowment: 10_000_000_000_000,
        encumbered_endowment: 1_000_000_000_000,
        spora_rate: 1_000,
        operator_signature: Vec::new(),
        operator_key: ar_ed.public_key_bytes().to_vec(),
        operator_pq_signature: Vec::new(),
        operator_pq_key: ar_pq.public_key_bytes().to_vec(),
    };
    let ar_msg = ar_ev.signing_digest(ar_net);
    ar_ev.operator_signature = ar_ed.sign(&ar_msg).to_vec();
    ar_ev.operator_pq_signature = ar_pq
        .sign(budlum_core::crypto::ctx::CROSS_DOMAIN_V1, &ar_msg)
        .expect("ar pq sign");
    let ar_adapter = ArweaveSpOraAdapter::new(ar_net)
        .with_pinned_operator(ar_ed.public_key_bytes(), ar_pq.public_key_bytes().to_vec());
    let ar_raw = RawConsensusEvidence {
        adapter: ar_adapter.descriptor().id,
        evidence_version: 1,
        network: ar_net.to_string(),
        payload: serde_json::to_vec(&ar_ev).expect("ar json"),
        declared_height: ar_ev.block_height,
        declared_root: ar_ev.weave_root,
        submitter: budlum_core::core::address::Address([0x08; 32]),
    };
    let mut ar_policy = VerificationPolicy::strict(0);
    ar_policy.require_slashable = false;
    let ar_bridge = ExternalDomainFinalityBridge::new(Box::new(ar_adapter), ar_policy);
    let ar_kind = ConsensusKind::Custom("arweave-spora".to_string());
    let mut ar_dom = default_domain(318, ar_kind.clone(), 9004, ar_net, 0);
    ar_dom.finality_adapter = EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string();
    let ar_proof = encode_external_evidence(&ar_raw).expect("encode ar external evidence");
    let ar_proof_hash =
        budlum_core::domain::hash_finality_proof(&ar_proof).expect("hash finality proof");
    let ar_commitment = DomainCommitment {
        domain_id: 318,
        domain_height: ar_ev.block_height,
        domain_block_hash: ar_ev.weave_root,
        parent_domain_block_hash: [0u8; 32],
        state_root: ar_ev.weave_root,
        tx_root: [0u8; 32],
        event_root: [0u8; 32],
        finality_proof_hash: ar_proof_hash,
        consensus_kind: ar_kind,
        validator_set_hash: [0u8; 32],
        timestamp_ms: 0,
        sequence: 1,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    };
    let mut ar_facts = CryptoFacts::new();
    let ar_status = ar_bridge
        .verify_finality_observed(&ar_dom, &ar_commitment, &ar_proof, &mut ar_facts)
        .expect("arweave bridge call succeeds");
    assert_eq!(ar_status, FinalityStatus::Finalized);
}
