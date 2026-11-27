//! Regression and feature tests for cold-wallet single-device quorum refusal
//! and dynamic external-finality settlement ceilings.

use budlum_core::cross_domain::external::spec::{ProofSystem, SecurityBacking};
use budlum_core::crypto::facts::ObservedScheme;
use budlum_core::crypto::scheme::SchemeId;
use budlum_core::settlement::cold_wallet::{
    ColdRefusal, ColdWalletPolicy, ColdWalletState, SettlementRequest,
};

fn base_policy() -> ColdWalletPolicy {
    ColdWalletPolicy {
        chain_id: 45_261,
        max_value_per_settlement_atoms: 1_000_000,
        max_value_per_epoch_atoms: 10_000_000,
        min_height_advance: 1,
        epoch_length_blocks: 100,
        required_quorum: 2,
        device_count: 3,
        refusal_history_capacity: 16,
    }
}

#[test]
fn cold_wallet_refuses_single_device_quorum_policy() {
    let mut single_device_quorum = base_policy();
    single_device_quorum.required_quorum = 1;
    assert!(
        single_device_quorum.validate().is_err(),
        "ColdWalletPolicy must refuse required_quorum=1 (no single cold device may sign alone)"
    );
}

#[test]
fn cold_wallet_enforces_external_finality_proof_shape_and_slashable_bond_ceilings() {
    let wallet = ColdWalletState::new(base_policy());
    let req = |value_atoms: u128| SettlementRequest {
        chain_id: 45_261,
        height: 5,
        epoch: 0,
        global_root: [0xAB; 32],
        value_atoms,
        nonce: 1,
    };

    // 1. Unanchored domain or Authority / None backing -> ceiling = 0!
    let sig_slashable = SecurityBacking::SignatureSet {
        scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
        signers: 70,
        required: 67,
        total_weight: 100,
        slashable: true,
    };
    assert_eq!(
        wallet.check_for_external_finality(&req(1), 1, 2, &sig_slashable, false, 5_000_000),
        Err(ColdRefusal::ValueAboveCeiling {
            ceiling: 0,
            requested: 1,
        })
    );
    assert_eq!(
        wallet.check_for_external_finality(
            &req(1),
            1,
            2,
            &SecurityBacking::Authority { count: 5 },
            true,
            5_000_000,
        ),
        Err(ColdRefusal::ValueAboveCeiling {
            ceiling: 0,
            requested: 1,
        })
    );

    // 2. Shallow PoW (difficulty_bits = 32 < 64) caps exit to 10% (100_000 atoms).
    let shallow_pow = SecurityBacking::Work {
        difficulty_bits: 32,
    };
    assert_eq!(
        wallet.check_for_external_finality(&req(100_001), 1, 2, &shallow_pow, true, 0),
        Err(ColdRefusal::ValueAboveCeiling {
            ceiling: 100_000,
            requested: 100_001,
        })
    );
    assert!(wallet
        .check_for_external_finality(&req(100_000), 1, 2, &shallow_pow, true, 0)
        .is_ok());

    // 3. SignatureSet claiming slashable=true BUT local_slashable_bond_atoms=0 caps to 10% (100_000)!
    assert_eq!(
        wallet.check_for_external_finality(&req(250_000), 1, 2, &sig_slashable, true, 0),
        Err(ColdRefusal::ValueAboveCeiling {
            ceiling: 100_000,
            requested: 250_000,
        })
    );
    // With 400_000 local slashable bond (< 1_000_000 policy max), ceiling binds to 400_000.
    assert_eq!(
        wallet.check_for_external_finality(&req(400_001), 1, 2, &sig_slashable, true, 400_000),
        Err(ColdRefusal::ValueAboveCeiling {
            ceiling: 400_000,
            requested: 400_001,
        })
    );
    assert!(wallet
        .check_for_external_finality(&req(400_000), 1, 2, &sig_slashable, true, 400_000)
        .is_ok());

    // 4. Validity-proven ZK backing with pinned anchor admits up to full policy ceiling (1_000_000).
    let zk_backing = SecurityBacking::Zk {
        system: ProofSystem::Stark,
        public_inputs_digest: [0x55; 32],
    };
    assert!(wallet
        .check_for_external_finality(&req(1_000_000), 1, 2, &zk_backing, true, 0)
        .is_ok());
}
