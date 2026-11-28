use budlum_core::cross_domain::external::algorand_stateproof::{
    AlgorandStateProofAdapter, PinnedAlgorandVerifier,
};
use budlum_core::cross_domain::external::arweave_spora::ArweaveSpOraAdapter;
use budlum_core::cross_domain::external::auxpow_pop::{AuxPowPopAdapter, PinnedAuxPowAnchor};
use budlum_core::cross_domain::external::based_preconf::{
    BasedPreconfAdapter, BasedPreconfValidator, PinnedBasedPreconfCommittee,
};
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
use budlum_core::cross_domain::external::spec::ExternalFinalityAdapter;
use budlum_core::cross_domain::external::stellar_fba::{
    PinnedScpTier, ScpQuorumSet, ScpValidatorNode, StellarScpAdapter,
};
use budlum_core::cross_domain::external::symbiotic_vault::SymbioticVaultAdapter;
use budlum_core::cross_domain::external::ton_catchain::{
    PinnedTonMasterchainAnchor, TonCatchainAdapter, TonValidator,
};

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
