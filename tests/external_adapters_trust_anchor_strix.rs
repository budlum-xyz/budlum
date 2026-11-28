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
