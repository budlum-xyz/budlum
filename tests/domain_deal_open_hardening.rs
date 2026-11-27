//! Regression tests for paid storage deal-open refusing zero-address payer or
//! operator and self-dealing zero-fee bypasses.

use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::domain::deal_open::{open_deal_escrowed, DealOpenTerms};
use budlum_core::domain::storage_deal::{StorageEconomicsParams, FEE_RATE_SCALE};
use budlum_core::storage::ContentManifest;

#[test]
fn open_deal_escrowed_refuses_zero_payer_zero_operator_and_zero_fee_rate() {
    let manifest =
        ContentManifest::from_bytes_sliced(b"paid storage deal test payload", 8).expect("manifest");
    let shard_id = manifest.shards[0].shard_id;
    let valid_operator = Address::from([0x11; 32]);
    let valid_payer = Address::from([0x22; 32]);

    let mut state = AccountState::new();
    state.add_balance(&valid_payer, 100_000_000);
    state.add_balance(&valid_operator, 100_000_000);

    let base_terms = DealOpenTerms {
        domain_id: 1,
        manifest: &manifest,
        shard_id,
        operator: valid_operator,
        replica_index: 0,
        start_epoch: 0,
        end_epoch: 10,
        economics: StorageEconomicsParams {
            operator_bond: 1_000,
            fee_per_byte_epoch: FEE_RATE_SCALE as u64,
        },
        merkle_proof: None,
        storage_root: Some([0x44; 32]),
    };

    // 1. Address::zero() payer must be refused before any funds check or registry mutation.
    assert!(
        open_deal_escrowed(
            &mut state,
            &base_terms,
            Address::zero(),
            1_000,
            1_000,
            0,
            false
        )
        .is_err(),
        "Address::zero() payer must be refused"
    );

    // 2. Address::zero() operator must be refused.
    let zero_op_terms = DealOpenTerms {
        operator: Address::zero(),
        ..base_terms
    };
    assert!(
        open_deal_escrowed(
            &mut state,
            &zero_op_terms,
            valid_payer,
            1_000,
            1_000,
            0,
            false
        )
        .is_err(),
        "Address::zero() storage operator must be refused"
    );

    // 3. Zero-fee storage deal (`fee_per_byte_epoch == 0` -> `total_fee == 0`) must be refused on paid deal path.
    let free_terms = DealOpenTerms {
        operator: valid_operator,
        economics: StorageEconomicsParams {
            operator_bond: 0,
            fee_per_byte_epoch: 0,
        },
        ..zero_op_terms
    };
    assert!(
        open_deal_escrowed(&mut state, &free_terms, valid_payer, 1_000, 0, 0, false).is_err(),
        "paid storage deal with zero computed total fee must be refused"
    );
}
