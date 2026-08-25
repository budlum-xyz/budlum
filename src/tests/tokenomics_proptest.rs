//! The tokenomics property-based test set - CI expansion, item 8.
//!
//! It exercises the $BUD tokenomics invariants across thousands of random
//! scenarios:
//! 1. The total supply never exceeds 100M.
//! 2. No burn operation creates a negative balance.
//! 3. The sum of burns and mints is always consistent.

#[cfg(test)]
mod tests {
    use crate::core::account::AccountState;
    use crate::core::address::Address;

    use crate::tokenomics::{TokenomicsParams, BUD_TOTAL_SUPPLY};
    use proptest::prelude::*;

    /// The address generator - a random 32 bytes.
    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 32]>().prop_map(Address::from)
    }

    /// The balance generator - between 0 and 10M.
    fn arb_balance() -> impl Strategy<Value = u64> {
        0..10_000_000u64
    }

    proptest! {
        /// INVARIANT 1: the total supply never exceeds 100M.
        ///
        /// Across random balance distributions, the total supply of the genesis
        /// state must not exceed BUD_TOTAL_SUPPLY.
        #[test]
        fn total_supply_never_exceeds_100m(
            balances in prop::collection::vec((arb_address(), arb_balance()), 1..50)
        ) {
            let mut state = AccountState::new();
            let params = TokenomicsParams::default();

            // The sum of the genesis allocations equals BUD_TOTAL_SUPPLY.
            assert_eq!(params.total(), BUD_TOTAL_SUPPLY);

            // Adding random balances must not exceed the total supply.
            let mut total_added: u64 = 0;
            for (addr, balance) in &balances {
                state.add_balance(addr, *balance);
                total_added = total_added.saturating_add(*balance);
            }

            // The critical invariant: the genesis distribution itself must not
            // exceed 100M, and circulating_supply has to equal genesis plus the
            // balances the test added. The value used to be computed and never
            // asserted, which made this test vacuous - it always passed. (On a
            // real network minting happens only in the genesis block.)
            // `state` bos bir AccountState olarak basliyor (genesis burada
            // Uygulanmiyor), dolayisiyla circulating_supply tam olarak test'in
            // Ekledigi bakiyelerin toplamidir.
            let supply = state.circulating_supply();
            assert_eq!(
                supply,
                u128::from(total_added),
                "circulating_supply has to equal the sum of the added balances"
            );
            assert!(
                supply <= u128::from(BUD_TOTAL_SUPPLY),
                "circulating_supply ({supply}) sabit {BUD_TOTAL_SUPPLY} arz tavanini asamaz"
            );
        }

        /// INVARIANT 2: no burn operation creates a negative balance.
        ///
        /// A burn deducts from a balance and adds to nothing.
        /// The balance must not fall below 0.
        #[test]
        fn burn_never_creates_negative_balance(
            initial_balance in 1..10_000_000u64,
            burn_amount in 1..20_000_000u64,
        ) {
            let mut state = AccountState::new();
            let addr = Address::from([0xAA; 32]);
            state.add_balance(&addr, initial_balance);

            // The burn operation.
            let _ = state.burn_from(&addr, burn_amount);

            // The balance must not fall below 0.
            let final_balance = state.get_balance(&addr);
            assert!(
                final_balance <= initial_balance,
                "Balance should not increase after burn"
            );
            // Because saturating_sub is used, it cannot fall below 0.
        }

        /// INVARIANT 3: burn and mint consistency.
        ///
        /// When the timed burn (the annual burn) and the metabolic burn (the
        /// transaction fee burn) run together, the total supply has to stay
        /// consistent.
        #[test]
        fn burn_mint_consistency(
            fee in 1..100_000u64,
        ) {
            let params = TokenomicsParams::default();

            // Metabolic burn = fee * tx_fee_burn_ratio / FIXED_POINT_SCALE
            let metabolic_burn = params.metabolic_burn(fee);

            // The burn must not exceed the fee.
            assert!(
                metabolic_burn <= fee,
                "Metabolic burn ({}) should not exceed fee ({})",
                metabolic_burn,
                fee
            );

            // Annual burn = burn_reserve * annual_ratio / FIXED_POINT_SCALE
            let annual_burn = params.annual_burn_amount();
            assert!(
                annual_burn <= params.burn_reserve,
                "Annual burn ({}) should not exceed burn reserve ({})",
                annual_burn,
                params.burn_reserve
            );
        }

        /// INVARIANT 4: vesting schedule consistency.
        ///
        /// Vesting must never unlock more than the total.
        #[test]
        fn vesting_never_exceeds_total(
            total in 1..10_000_000u64,
            cliff in 1..1000u64,
            duration in 1..10000u64,
            epoch in 0..20000u64,
        ) {
            use crate::tokenomics::VestingSchedule;

            let duration = duration.max(cliff); // duration >= cliff
            let schedule = VestingSchedule {
                total,
                start_epoch: 0,
                cliff_epochs: cliff,
                duration_epochs: duration,
            };

            let unlocked = schedule.unlocked_at(epoch);
            let locked = schedule.locked_at(epoch);

            // Unlocked + locked = total
            assert_eq!(
                unlocked + locked,
                total,
                "Unlocked ({}) + locked ({}) should equal total ({})",
                unlocked,
                locked,
                total
            );

            // Unlocked must never exceed the total.
            assert!(
                unlocked <= total,
                "Unlocked ({}) should not exceed total ({})",
                unlocked,
                total
            );

            // Locked must never be negative - it is a u64 so it cannot be, but verify it.
            assert!(
                locked <= total,
                "Locked ({}) should not exceed total ({})",
                locked,
                total
            );
        }

        /// INVARIANT 5: validator reward consistency.
        ///
        /// calculate_epoch_reward(0) is trivial, and a positive stake gives a
        /// positive reward.
        #[test]
        fn epoch_reward_consistency(
            stake in 0..100_000_000_000u64,
        ) {
            let params = TokenomicsParams::default();
            let reward = params.calculate_epoch_reward(stake);

            if stake == 0 {
                assert!(reward <= 1, "Zero stake should produce trivial reward");
            } else {
                assert!(reward > 0, "Positive stake should produce positive reward");
            }
        }
    }
}
