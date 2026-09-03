//! Integration tests for $BUD tokenomics: genesis supply/distribution,
//! Timed reserve burn (3.1), metabolic tx-fee burn (3.2), and the
//! "supply only decreases on burn paths" property.

use crate::core::account::AccountState;
use crate::core::address::Address;
#[cfg(test)]
fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
    let mut b = [0u8; 32];
    b[0] = byte;
    crate::core::address::Address::from(b)
}

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
fn timed_burn_can_use_wall_clock_year_boundaries() {
    let (mut state, addrs) = genesis_state();
    let per_year = state.tokenomics.annual_burn_amount();
    let one_year_secs = state.tokenomics.seconds_per_year();

    state.epoch_index = state.tokenomics.epochs_per_year * 99;
    assert_eq!(
        state.process_timed_burn_at_time(0, one_year_secs - 1, &addrs.burn_reserve),
        0
    );
    assert_eq!(state.timed_burn.years_burned, 0);

    let burned = state.process_timed_burn_at_time(0, one_year_secs, &addrs.burn_reserve);
    assert_eq!(burned, per_year);
    assert_eq!(state.timed_burn.years_burned, 1);
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
    // Supply decreased by EXACTLY the burned amount, nothing minted it back.
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

    // Validator income is exclusively fee - metabolic burn; no block emission.
    let supply_after = state.circulating_supply();
    assert_eq!(supply_after, supply_before - expected_burn as u128);
    assert!(expected_burn > 0, "1% of 10_000 must be non-zero");
    assert_eq!(state.get_balance(&producer), fee - expected_burn);
}

#[test]
fn zero_fee_burns_nothing() {
    let params = TokenomicsParams::default();
    assert_eq!(params.metabolic_burn(0), 0);
    // Tiny fee below the 1% granularity rounds down to zero burn (acceptable).
    assert_eq!(params.metabolic_burn(50), 0);
}

// ---: REAL-FLOW integration (genesis / epoch / vesting) --------------

use crate::chain::genesis::GenesisConfig;
use crate::tokenomics::VestingSchedule;

/// Genesis distribution flows through the REAL GenesisConfig::build_state
/// (not a hand-filled AccountState).
#[test]
fn genesis_build_state_seeds_bud_distribution_via_real_flow() {
    let addrs = TokenomicsAddresses::reserved();
    let state = GenesisConfig::new(45262)
        .with_bud_tokenomics()
        .build_state();

    // Distribution accounts exist with the right balances.
    assert_eq!(state.get_balance(&addrs.community), bud(10_000_000));
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(40_000_000));
    assert_eq!(state.get_balance(&addrs.team), bud(20_000_000));
    // Supply includes the full 100M (genesis had no other allocations for devnet).
    assert_eq!(state.circulating_supply(), BUD_TOTAL_SUPPLY as u128);
    // Burn reserve + team vesting are wired into state.
    assert_eq!(state.burn_reserve_address, Some(addrs.burn_reserve));
    assert!(state.team_vesting.is_some());
}

#[test]
fn genesis_build_state_uses_configured_tokenomics_destinations() {
    let configured = TokenomicsAddresses {
        community: Address::from([10; 32]),
        liquidity: Address::from([11; 32]),
        ecosystem: Address::from([12; 32]),
        team: Address::from([13; 32]),
        burn_reserve: Address::from([14; 32]),
    };
    let mut genesis = GenesisConfig::new(45262).with_bud_tokenomics();
    genesis.tokenomics_addresses = Some(configured);
    let state = genesis.build_state();

    assert_eq!(state.get_balance(&configured.community), bud(10_000_000));
    assert_eq!(state.get_balance(&configured.liquidity), bud(10_000_000));
    assert_eq!(state.get_balance(&configured.ecosystem), bud(20_000_000));
    assert_eq!(state.get_balance(&configured.team), bud(20_000_000));
    assert_eq!(state.get_balance(&configured.burn_reserve), bud(40_000_000));
    assert_eq!(state.burn_reserve_address, Some(configured.burn_reserve));
    assert_eq!(state.team_vesting.unwrap().0, configured.team);
    assert_eq!(
        state.get_balance(&TokenomicsAddresses::reserved().community),
        0
    );
}

#[test]
fn burn_reserve_cannot_bypass_schedule_with_transaction() {
    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(45262)
        .with_bud_tokenomics()
        .build_state();
    let mut tx = crate::core::transaction::Transaction::new(
        addrs.burn_reserve,
        addrs.community,
        1,
        Vec::new(),
    );
    tx.fee = 1;
    tx.max_fee = 1;
    assert!(Executor::apply_transaction(&mut state, &tx).is_err());
    assert_eq!(state.spendable_balance(&addrs.burn_reserve), 0);
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(40_000_000));
}

/// Default genesis (no tokenomics) is unchanged, regression guard for Decision B.
#[test]
fn plain_genesis_has_no_tokenomics_wiring() {
    let state = GenesisConfig::new(45262).build_state();
    assert_eq!(state.burn_reserve_address, None);
    assert!(state.team_vesting.is_none());
}

/// Timed burn fires through the REAL epoch-transition function
/// (`advance_epoch`), without manually setting `epoch_index`.
#[test]
fn timed_burn_fires_via_real_epoch_advance() {
    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(45262)
        .with_bud_tokenomics()
        .build_state();
    let epochs_per_year = state.tokenomics.epochs_per_year;
    let per_year = state.tokenomics.annual_burn_amount();

    // Advance epochs one-by-one via the canonical transition until just before a year.
    for _ in 0..(epochs_per_year - 1) {
        state.advance_epoch(0, crate::core::transaction::DEFAULT_CHAIN_ID);
    }
    assert_eq!(state.get_balance(&addrs.burn_reserve), bud(40_000_000));
    assert_eq!(state.timed_burn.years_burned, 0);

    // One more advance crosses the year boundary → timed burn auto-fires.
    state.advance_epoch(0, crate::core::transaction::DEFAULT_CHAIN_ID);
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
fn fixed_supply_tokenomics_disables_epoch_yield_minting() {
    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(45262)
        .with_bud_tokenomics()
        .build_state();
    state.add_validator(addrs.community, 1_000);
    let before = state.get_balance(&addrs.community);
    state.advance_epoch(0, crate::core::transaction::DEFAULT_CHAIN_ID);
    let after = state.get_balance(&addrs.community);
    assert_eq!(before, after, "fixed-supply tokenomics chain must not mint epoch yield without explicit reward-pool wiring");
}

/// Vesting advances with the epoch counter the schedule was written against.
///
/// Previously set `last_epoch_time` to
/// `seconds_per_epoch() * team_cliff_epochs` and assert the cliff had just
/// opened. That number is synthetic: it is the value
/// `epoch_at_timestamp` needs in order to return `cliff_epochs`, not a value
/// production can produce. Production passes `block.timestamp` - absolute Unix
/// time in milliseconds - so the same call returned about 5.5 billion, and the
/// cliff was long expired before the chain made its second block.
///
/// The schedule is genesis-relative (`start_epoch = 0`), so the epoch counter
/// is the quantity that belongs on the other side of the comparison. Unlike a
/// wall-clock division it is also anchored: it starts at zero at genesis and
/// only ever advances by one.
#[test]
fn team_vesting_tracks_the_genesis_relative_epoch_counter() {
    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(45262)
        .with_bud_tokenomics()
        .build_state();
    assert_eq!(state.spendable_balance(&addrs.team), 0);

    // A wall-clock timestamp, however large, is not an epoch count.
    state.last_epoch_time = 1_785_450_000_000;
    assert_eq!(
        state.spendable_balance(&addrs.team),
        0,
        "a Unix timestamp must not be read as a genesis-relative epoch"
    );

    // At the cliff, the linear tail has released cliff/duration of the total.
    state.epoch_index = state.tokenomics.team_cliff_epochs;
    assert_eq!(state.spendable_balance(&addrs.team), bud(5_000_000));
}

#[test]
fn team_vesting_enforced_on_transfer() {
    use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
    use crate::execution::executor::Executor;

    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(45262)
        .with_bud_tokenomics()
        .build_state();

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
        state.advance_epoch(0, crate::core::transaction::DEFAULT_CHAIN_ID);
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

/// The vesting lock must hold on every path that moves value, not only on
/// `Transfer`.
///
/// `spendable_balance` is the gate, and three executor branches asked
/// `get_balance` instead: the AI request `max_fee` escrow, `AiPurchaseData`,
/// and `AiAgentPayment`. Each debits the sender's account, so the team
/// account could move locked $BUD simply by picking a different transaction
/// type. `AiAgentPayment` is the cleanest of the three to drive from a test:
/// it needs no marketplace offer and no ZKVM receipt.
///
/// The admission side is checked with the same account, because a mempool
/// that accepts what the executor refuses relays transactions that can never
/// apply.
#[test]
fn team_vesting_holds_on_every_value_path_not_only_transfer() {
    use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
    use crate::execution::executor::Executor;

    let addrs = TokenomicsAddresses::reserved();
    let mut state = GenesisConfig::new(45262)
        .with_bud_tokenomics()
        .build_state();
    assert_eq!(
        state.spendable_balance(&addrs.team),
        0,
        "the whole team allocation is locked at genesis"
    );
    assert!(
        state.get_balance(&addrs.team) > 0,
        "the locked balance still exists in the account"
    );

    let payment = crate::ai::types::AiAgentPayment {
        payment_id: [0x5Au8; 32],
        from_agent: addrs.team,
        to_agent: Address::from([0x77u8; 32]),
        amount: bud(1_000_000),
        request_id: None,
        require_proof: false,
        submitted_at_block: 0,
        expiry_block: 10_000,
    };
    let mut tx = Transaction::new_with_chain_id(
        addrs.team,
        Address::zero(),
        0,
        1,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiAgentPayment(payment),
    );
    tx.hash = tx.calculate_hash();
    let err = Executor::apply_transaction_checked(&mut state, &tx).unwrap_err();
    assert_eq!(
        err.code(),
        "ai_payment_insufficient_funds",
        "an agent payment must not move locked team funds"
    );
    assert_eq!(
        state.get_balance(&addrs.team),
        bud(20_000_000),
        "the refused payment must not have debited anything"
    );

    // Admission asks the same question as execution.
    let mut transfer = Transaction::new_with_chain_id(
        addrs.team,
        Address::from([0x77u8; 32]),
        bud(1_000_000),
        1,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    transfer.hash = transfer.calculate_hash();
    assert!(
        state.validate_transaction(&transfer).is_err(),
        "validate_transaction must not admit a spend of locked team funds"
    );
}

/// F4 (Constitution §3): NftBoost 4% B.U.D. share accumulates in
/// `pending_bud_boost_share` for later distribution to storage operators.
/// REGRESSION LOCK - verifies the executor-side wiring.
#[test]
fn f4_boost_share_accumulates_in_pending_bud_boost_share() {
    let mut state = AccountState::new();
    let booster = test_addr_from_byte(1u8);
    let creator = test_addr_from_byte(2u8);

    state.add_balance(&booster, 10_000_000);

    // Mint an NFT for the creator.
    let cid = ContentId([0xABu8; 32]);
    let nft_id = state
        .nft_registry
        .mint(creator, cid, 1, None)
        .expect("a fresh registry has no id to collide with");

    // Boost the NFT with 1000 - 4% = 40 should go to pending_bud_boost_share.
    let boost_amount: u64 = 1000;
    let tx = Transaction {
        from: booster,
        to: Address::zero(),
        amount: 0,
        fee: 100,
        max_fee: 100,
        priority_fee: 0,
        nonce: 1,
        data: bincode::serialize(&(nft_id, boost_amount)).unwrap(),
        timestamp: 1000,
        hash: String::new(),
        signature: None,
        signer_public_key: Vec::new(),
        authorization: None,
        chain_id: DEFAULT_CHAIN_ID,
        signature_version: crate::core::transaction::SIGNATURE_VERSION_V5,
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

/// The mainnet template seeds no $BUD distribution until the ceremony
/// addresses are set (marker accounts must not enter the mainnet state
/// root). These tests measure the epoch arithmetic of the burn reserve and
/// the team cliff, so they run the template with ceremony addresses.
fn mainnet_state_with_distribution() -> AccountState {
    let mut genesis = crate::chain::genesis::mainnet_genesis();
    genesis.tokenomics_addresses = Some(TokenomicsAddresses {
        community: test_addr_from_byte(0xC1),
        liquidity: test_addr_from_byte(0xC2),
        ecosystem: test_addr_from_byte(0xC3),
        team: test_addr_from_byte(0xC4),
        burn_reserve: test_addr_from_byte(0xC5),
    });
    genesis.build_state()
}

/// One epoch boundary must not expire a one-year cliff.
///
/// `spendable_balance` read the team schedule at
/// `tokenomics.epoch_at_timestamp(last_epoch_time)`. That function divides an
/// absolute Unix timestamp by the epoch length, so it returns epochs elapsed
/// since 1970 - around 5.5 billion. The schedule counts from genesis
/// (`team_vesting(0)` sets `start_epoch = 0`) with a cliff of 52_560 epochs.
///
/// Measured with a canary before the fix, on `mainnet_genesis()`:
///
///     epoch_at_timestamp       = 5579531250
///     spendable before advance = 0
///     spendable after  advance = 20000000000000
///
/// 20M $BUD, 20% of total supply, unlocked at the first epoch close.
/// `spendable_balance` gates transfers (`executor.rs`), so this was spendable.
#[test]
fn one_epoch_close_does_not_expire_the_team_cliff() {
    let mut state = mainnet_state_with_distribution();
    let (team, schedule) = state.team_vesting.expect("mainnet vests the team");

    assert_eq!(schedule.start_epoch, 0, "schedule is genesis-relative");
    assert!(schedule.cliff_epochs > 1, "cliff spans many epochs");
    assert_eq!(state.spendable_balance(&team), 0, "locked at genesis");

    // A real block timestamp, in milliseconds, exactly as
    // `apply_system_effects` passes it.
    state.advance_epoch(
        1_785_450_000_000,
        crate::core::transaction::DEFAULT_CHAIN_ID,
    );

    assert_eq!(
        state.spendable_balance(&team),
        0,
        "one epoch close must not unlock a {}-epoch cliff",
        schedule.cliff_epochs
    );
}

/// The cliff must still open once enough epochs actually pass.
///
/// Without this, the test above would be satisfied by a schedule that never
/// unlocks anything.
#[test]
fn the_team_cliff_still_opens_after_its_epochs_elapse() {
    let mut state = mainnet_state_with_distribution();
    let (team, schedule) = state.team_vesting.expect("mainnet vests the team");

    state.epoch_index = schedule.cliff_epochs;
    let at_cliff = state.spendable_balance(&team);
    assert!(
        at_cliff > 0,
        "the cliff must release something once it is reached"
    );

    state.epoch_index = schedule.start_epoch + schedule.duration_epochs;
    assert_eq!(
        state.spendable_balance(&team),
        state.get_balance(&team),
        "fully vested at the end of the schedule"
    );
}

/// One epoch boundary must not burn a ten-year reserve.
///
/// `advance_epoch` passed `block.timestamp` - absolute Unix time in
/// milliseconds - to `process_timed_burn_at_time`, whose parameter is seconds
/// since genesis, with the genesis anchor hardcoded to `0`.
///
/// Measured with a canary before the fix, on `mainnet_genesis()`:
///
///     years_burned    0 -> 106155
///     reserve balance 40000000000000 -> 0
#[test]
fn one_epoch_close_does_not_drain_the_burn_reserve() {
    let mut state = mainnet_state_with_distribution();
    let reserve = state
        .burn_reserve_address
        .expect("mainnet configures a burn reserve");
    let before = state.get_balance(&reserve);
    assert!(before > 0, "reserve is funded at genesis");

    state.advance_epoch(
        1_785_450_000_000,
        crate::core::transaction::DEFAULT_CHAIN_ID,
    );

    assert_eq!(
        state.timed_burn.years_burned, 0,
        "no annual burn is due one epoch after genesis"
    );
    assert_eq!(
        state.get_balance(&reserve),
        before,
        "the reserve must be untouched one epoch after genesis"
    );
}

/// The annual burn must still fire once a year of epochs elapses.
#[test]
fn the_annual_burn_still_fires_after_a_year_of_epochs() {
    let mut state = mainnet_state_with_distribution();
    let reserve = state
        .burn_reserve_address
        .expect("mainnet configures a burn reserve");
    let before = state.get_balance(&reserve);
    let per_year = state.tokenomics.annual_burn_amount();

    // Step to one epoch short of a year, then across it.
    state.epoch_index = state.tokenomics.epochs_per_year - 1;
    state.advance_epoch(
        1_785_450_000_000,
        crate::core::transaction::DEFAULT_CHAIN_ID,
    );

    assert_eq!(
        state.timed_burn.years_burned, 1,
        "one year of epochs is due exactly one burn"
    );
    assert_eq!(
        state.get_balance(&reserve),
        before - per_year,
        "exactly one annual increment leaves the reserve"
    );
}
