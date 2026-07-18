//! Integration tests for $BUD tokenomics (Phase 0.14): genesis supply/distribution,
//! timed reserve burn (3.1), metabolic tx-fee burn (3.2), and the
//! "supply only decreases on burn paths" property.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::execution::executor::Executor;
use crate::storage::content_id::ContentId;
use crate::tokenomics::{
    bud, genesis_allocations, TokenomicsAddresses, TokenomicsParams, BUD_TOTAL_SUPPLY,
};

/// Build an AccountState seeded with the full $BUD genesis distribution.
fn genesis_state() -> (AccountState, TokenomicsAddresses) {
    let params = TokenomicsParams::default();
    let addrs = TokenomicsAddresses::reserved();
    let mut state = AccountState::new();
    for (addr, amount) in genesis_allocations(&params, &addrs) {
        state.add_balance(&addr, amount);
    }
    (state, addrs)
}

// --- Genesis supply & distribution -----------------------------------------

#[test]
fn genesis_total_supply_is_100m_and_distribution_matches() {
    let (state, addrs) = genesis_state();
    // Total supply is exactly 100M * 10^6.
    assert_eq!(state.circulating_supply(), BUD_TOTAL_SUPPLY as u128);
    assert_eq!(BUD_TOTAL_SUPPLY, bud(100_000_000));

    // Per-category amounts match the approved distribution.
    assert_eq!(state.get_balance(&addrs.community), bud(10_000_000));
    assert_eq!(state.get_balance(&addrs.liquidity), bud(10_000_000));
    assert_eq!(state.get_balance(&addrs.ecosystem), bud(20_000_000));
    assert_eq!(state.get_balance(&addrs.team), bud(20_000_000));
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(40_000_000));
}

#[test]
fn distribution_params_are_balanced() {
    assert!(TokenomicsParams::default().is_balanced());
}

// --- Timed reserve burn (3.1) ----------------------------------------------

#[test]
fn timed_burn_triggers_at_year_boundary_not_before() {
    let (mut state, addrs) = genesis_state();
    let per_year = state.tokenomics.annual_burn_amount(); // 4M
    let epochs_per_year = state.tokenomics.epochs_per_year; // 1000

    // Before the first year: nothing burns.
    state.epoch_index = epochs_per_year - 1;
    assert_eq!(state.process_timed_burn(0, &addrs.burn_reserve), 0);
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(40_000_000));
    assert_eq!(state.timed_burn.years_burned, 0);

    // At exactly one year: one annual burn.
    state.epoch_index = epochs_per_year;
    let burned = state.process_timed_burn(0, &addrs.burn_reserve);
    assert_eq!(burned, per_year);
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(36_000_000));
    assert_eq!(state.timed_burn.years_burned, 1);

    // Calling again within the same year burns nothing (idempotent per year).
    assert_eq!(state.process_timed_burn(0, &addrs.burn_reserve), 0);
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(36_000_000));
}

#[test]
fn timed_burn_catches_up_multiple_years() {
    let (mut state, addrs) = genesis_state();
    // Jump straight to year 3.
    state.epoch_index = 3 * state.tokenomics.epochs_per_year;
    let burned = state.process_timed_burn(0, &addrs.burn_reserve);
    assert_eq!(burned, bud(12_000_000)); // 3 * 4M
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(28_000_000));
    assert_eq!(state.timed_burn.years_burned, 3);
}

#[test]
fn timed_burn_stops_when_reserve_exhausted() {
    let (mut state, addrs) = genesis_state();
    // Far future: more years than the reserve can fund (40M / 4M = 10 years).
    state.epoch_index = 100 * state.tokenomics.epochs_per_year;
    let burned = state.process_timed_burn(0, &addrs.burn_reserve);
    // At most the whole reserve is burned, never more.
    assert_eq!(burned, bud(40_000_000));
    assert_eq!(state.get_balance(&addrs.burn_reserve), 0);
}

// --- Supply only decreases (no mint compensates a burn) ---------------------

#[test]
fn burn_strictly_reduces_supply_no_mint_offset() {
    let (mut state, addrs) = genesis_state();
    let before = state.circulating_supply();

    state.epoch_index = state.tokenomics.epochs_per_year;
    let burned = state.process_timed_burn(0, &addrs.burn_reserve);
    let after = state.circulating_supply();

    assert!(burned > 0);
    // Supply decreased by EXACTLY the burned amount — nothing minted it back.
    assert_eq!(after, before - burned as u128);
    assert!(after < before);
}

// --- Metabolic (tx-fee) burn (3.2) -----------------------------------------

#[test]
fn metabolic_burn_removes_fee_fraction_on_block_apply() {
    use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};

    let mut state = AccountState::new();
    let sender = Address::from([0x11u8; 32]);
    let receiver = Address::from([0x22u8; 32]);
    let producer = Address::from([0x33u8; 32]);
    state.add_balance(&sender, 1_000_000);

    // A transfer with a fee large enough that 1% is non-zero.
    let fee = 10_000u64;
    let mut tx = Transaction::new_with_chain_id(
        sender,
        receiver,
        100,
        fee,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    tx.hash = tx.calculate_hash();

    let supply_before = state.circulating_supply();
    let expected_burn = state.tokenomics.metabolic_burn(fee); // 1% of 10_000 = 100

    Executor::apply_block(&mut state, &[tx], Some(&producer)).unwrap();

    // Producer got block_reward + (fee - burn); the burned fraction left supply.
    let supply_after = state.circulating_supply();
    // Net supply change = +block_reward (minted) - metabolic_burn (burned).
    let expected_after =
        supply_before + state.tokenomics.block_reward as u128 - expected_burn as u128;
    assert_eq!(supply_after, expected_after);
    assert!(expected_burn > 0, "1% of 10_000 must be non-zero");

    // Producer balance excludes the burned fraction.
    let producer_bal = state.get_balance(&producer);
    assert_eq!(
        producer_bal,
        state.tokenomics.block_reward + (fee - expected_burn)
    );
}

#[test]
fn zero_fee_burns_nothing() {
    let params = TokenomicsParams::default();
    assert_eq!(params.metabolic_burn(0), 0);
    // Tiny fee below the 1% granularity rounds down to zero burn (acceptable).
    assert_eq!(params.metabolic_burn(50), 0);
}

// --- Phase 0.14b: REAL-FLOW integration (genesis / epoch / vesting) --------------

use crate::chain::genesis::GenesisConfig;
use crate::tokenomics::VestingSchedule;

/// Genesis distribution flows through the REAL GenesisConfig::build_state()
/// (not a hand-filled AccountState).
#[test]
fn genesis_build_state_seeds_bud_distribution_via_real_flow() {
    let addrs = TokenomicsAddresses::reserved();
    let state = GenesisConfig::new(1337).with_bud_tokenomics().build_state();

    // Distribution accounts exist with the right balances.
    assert_eq!(state.get_balance(&addrs.community), bud(10_000_000));
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(40_000_000));
    assert_eq!(state.get_balance(&addrs.team), bud(20_000_000));
    // Supply includes the full 100M (genesis had no other allocations for chain 1337).
    assert_eq!(state.circulating_supply(), BUD_TOTAL_SUPPLY as u128);
    // Burn reserve + team vesting are wired into state.
    assert_eq!(state.burn_reserve_address, Some(addrs.burn_reserve));
    assert!(state.team_vesting.is_some());
}

/// Default genesis (no tokenomics) is unchanged — regression guard for Decision B.
#[test]
fn plain_genesis_has_no_tokenomics_wiring() {
    let state = GenesisConfig::new(1337).build_state();
    assert_eq!(state.burn_reserve_address, None);
    assert!(state.team_vesting.is_none());
}

/// Timed burn fires through the REAL epoch-transition function
/// (`advance_epoch`), without manually setting `epoch_index`.
#[test]
fn timed_burn_fires_via_real_epoch_advance() {
    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(1337).with_bud_tokenomics().build_state();
    let epochs_per_year = state.tokenomics.epochs_per_year;
    let per_year = state.tokenomics.annual_burn_amount();

    // Advance epochs one-by-one via the canonical transition until just before a year.
    for _ in 0..(epochs_per_year - 1) {
        state.advance_epoch(0);
    }
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(40_000_000));
    assert_eq!(state.timed_burn.years_burned, 0);

    // One more advance crosses the year boundary → timed burn auto-fires.
    state.advance_epoch(0);
    assert_eq!(state.timed_burn.years_burned, 1);
    assert_eq!(
        state.get_balance(&addrs.burn_reserve),
        bud(40_000_000) - per_year
    );
    // Supply dropped by exactly the burn.
    assert_eq!(
        state.circulating_supply(),
        BUD_TOTAL_SUPPLY as u128 - per_year as u128
    );
}

/// Team vesting is ENFORCED on transfers through the real executor path.
#[test]
fn team_vesting_enforced_on_transfer() {
    use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
    use crate::execution::executor::Executor;

    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(1337).with_bud_tokenomics().build_state();

    // At genesis epoch 0 (before cliff) the entire 20M team balance is locked.
    let sched: VestingSchedule = state.team_vesting.unwrap().1;
    assert_eq!(sched.locked_at(0), bud(20_000_000));
    assert_eq!(state.spendable_balance(&addrs.team), 0);

    // A transfer of any locked amount is rejected with `vesting_locked`.
    let mut tx = Transaction::new_with_chain_id(
        addrs.team,
        Address::from([0x77u8; 32]),
        bud(1_000_000),
        1,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    tx.hash = tx.calculate_hash();
    let err = Executor::apply_transaction_checked(&mut state, &tx).unwrap_err();
    assert_eq!(err.code(), "vesting_locked");

    // Advance to the cliff (25% unlocked = 5M spendable), then a 5M transfer works.
    for _ in 0..state.tokenomics.team_cliff_epochs {
        state.advance_epoch(0);
    }
    assert_eq!(state.spendable_balance(&addrs.team), bud(5_000_000));

    let mut ok_tx = Transaction::new_with_chain_id(
        addrs.team,
        Address::from([0x77u8; 32]),
        bud(4_000_000),
        1,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    ok_tx.hash = ok_tx.calculate_hash();
    Executor::apply_transaction_checked(&mut state, &ok_tx).unwrap();

    // But spending beyond the unlocked portion is still rejected.
    let mut over_tx = Transaction::new_with_chain_id(
        addrs.team,
        Address::from([0x77u8; 32]),
        bud(2_000_000),
        1,
        1,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    over_tx.hash = over_tx.calculate_hash();
    let err2 = Executor::apply_transaction_checked(&mut state, &over_tx).unwrap_err();
    assert_eq!(err2.code(), "vesting_locked");
}

/// F4 (Constitution §3): NftBoost 4% B.U.D. share accumulates in
/// `pending_bud_boost_share` for later distribution to storage operators.
/// REGRESSION LOCK — verifies the executor-side wiring.
#[test]
fn f4_boost_share_accumulates_in_pending_bud_boost_share() {
    let mut state = AccountState::new();
    let booster = Address::from([1u8; 32]);
    let creator = Address::from([2u8; 32]);

    state.add_balance(&booster, 10_000_000);

    // Mint an NFT for the creator.
    let cid = ContentId([0xABu8; 32]);
    let nft_id = state.nft_registry.mint(creator, cid, 1, None);

    // Boost the NFT with 1000 — 4% = 40 should go to pending_bud_boost_share.
    let boost_amount: u64 = 1000;
    let tx = Transaction {
        from: booster,
        to: Address::zero(),
        amount: 0,
        fee: 100,
        nonce: 1,
        data: bincode::serialize(&(nft_id, boost_amount)).unwrap(),
        timestamp: 1000,
        hash: String::new(),
        signature: None,
        chain_id: DEFAULT_CHAIN_ID,
        signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
        tx_type: TransactionType::NftBoost {
            nft_id,
            amount: boost_amount,
        },
    };

    Executor::apply_transaction_checked(&mut state, &tx).unwrap();

    let expected_bud_share = boost_amount * 4 / 100; // 40
    let expected_creator_share = boost_amount * 16 / 100; // 160

    // Creator should have received 16%.
    assert_eq!(state.get_balance(&creator), expected_creator_share);

    // 4% should be in pending_bud_boost_share.
    assert_eq!(state.pending_bud_boost_share, expected_bud_share);

    // Booster should have lost amount + fee.
    assert_eq!(state.get_balance(&booster), 10_000_000 - boost_amount - 100);
}
