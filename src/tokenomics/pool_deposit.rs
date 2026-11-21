//! Shared-pool occupancy deposits: the single K/TTL table.
//!
//! Four registries share one failure shape: a fixed-capacity pool with a
//! cheap, non-expiring entry. Per-owner quotas bound one KEY, but addresses
//! are free, so `capacity / per_owner_quota` addresses fill a pool for
//! everyone (the privacy note pool needs only
//! `MAX_LIVE_COMMITMENTS / MAX_LIVE_COMMITMENTS_PER_OWNER = 64`). The answer
//! is economic, not structural: every live row LOCKS capital while it
//! occupies a slot, and the lock is a deposit, never a burn, so a legitimate
//! heavy user loses nothing while a squatter pays rent in locked supply.
//!
//! This module is the only place deposit sizes and TTLs may be defined.
//! Consumers take a [`PoolDepositPolicy`] from [`policy_of`] and carry no
//! deposit constants of their own; a repository lock test refuses an inline
//! deposit amount at any call site, so the table cannot fork silently.
//!
//! The class split is a compile-time lock: [`PoolDepositClass::ShieldedBalance`]
//! carries no TTL field at all, so a sweeper for a shielded pool cannot even
//! be written against this type. Shielded rows conserve their count across a
//! transfer (k spent rows always mint k output rows), so the deposit RIDES
//! the rollover instead of being refunded: a refund at spend would leave the
//! freshly minted output rows occupying the pool with nothing locked behind
//! them. TTL sweeping, where it exists at all, applies only to LIVE rows of
//! an owner-refundable pool - replay-protection rows (spent sets, nullifier
//! sets) are append-only forever, and the registries enforce that themselves.

use crate::tokenomics::BUD_UNIT;

/// One deposit atom: 0.01 BUD in base units. Every deposit in the table is
/// `K * POOL_DEPOSIT_ATOM`, so re-pricing the whole economy is one constant,
/// and no pool can drift to its own unit.
pub const POOL_DEPOSIT_ATOM: u64 = BUD_UNIT / 100;

/// The shared pools the deposit economy covers. One variant per bounded
/// registry; a new bounded registry earns a row here before it may charge
/// anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedPool {
    /// DID records in the identity registry.
    IdentityRecord,
    /// Credentials issued against an identity record.
    IssuedCredential,
    /// Data-market content listings.
    ContentOffer,
    /// Live note commitments in the L1 privacy pool.
    PrivacyNote,
}

/// How a locked deposit comes back - the type IS the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolDepositClass {
    /// The row's owner gets the deposit back when the row closes
    /// (revoke/cancel/settle), and a row that outlives `ttl_blocks` may be
    /// swept, returning the deposit to its owner. Sweeping never burns.
    OwnerRefundable {
        /// Blocks a live row may occupy its slot before anyone may sweep it.
        ttl_blocks: u64,
    },
    /// The deposit rides the row through 1-for-1 transfer rollovers and is
    /// never refunded at spend. No TTL field exists on this variant, so a
    /// TTL sweep over a shielded pool is unrepresentable.
    ShieldedBalance,
}

/// One row of the table: what entering the pool locks, and how it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolDepositPolicy {
    /// Refund class of the deposit.
    pub class: PoolDepositClass,
    /// Base units locked per live row.
    pub deposit: u64,
}

/// The single K/TTL table. K values price pool saturation as locked capital:
/// an identity slot locks 10 BUD (filling all identity slots locks ~655k
/// BUD), a privacy note locks 0.1 BUD (saturating the 65,536-row pool locks
/// ~6,553 BUD across at least 64 addresses - the per-owner quota forces the
/// spread). The numbers live here and nowhere else.
#[must_use]
pub const fn policy_of(pool: SharedPool) -> PoolDepositPolicy {
    match pool {
        SharedPool::IdentityRecord => PoolDepositPolicy {
            class: PoolDepositClass::OwnerRefundable {
                ttl_blocks: crate::registry::params::MAX_DURATION,
            },
            deposit: 1_000 * POOL_DEPOSIT_ATOM,
        },
        SharedPool::IssuedCredential => PoolDepositPolicy {
            class: PoolDepositClass::OwnerRefundable {
                ttl_blocks: crate::registry::params::MAX_DURATION,
            },
            deposit: 50 * POOL_DEPOSIT_ATOM,
        },
        SharedPool::ContentOffer => PoolDepositPolicy {
            class: PoolDepositClass::OwnerRefundable {
                ttl_blocks: 100_000,
            },
            deposit: 100 * POOL_DEPOSIT_ATOM,
        },
        SharedPool::PrivacyNote => PoolDepositPolicy {
            class: PoolDepositClass::ShieldedBalance,
            deposit: 10 * POOL_DEPOSIT_ATOM,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::{MAX_LIVE_COMMITMENTS, MAX_LIVE_COMMITMENTS_PER_OWNER};

    #[test]
    fn the_privacy_note_row_is_shielded_and_carries_no_ttl() {
        let p = policy_of(SharedPool::PrivacyNote);
        assert_eq!(p.class, PoolDepositClass::ShieldedBalance);
        assert_eq!(p.deposit, 10 * POOL_DEPOSIT_ATOM);
    }

    #[test]
    fn owner_refundable_rows_declare_a_nonzero_ttl() {
        for pool in [
            SharedPool::IdentityRecord,
            SharedPool::IssuedCredential,
            SharedPool::ContentOffer,
        ] {
            match policy_of(pool).class {
                PoolDepositClass::OwnerRefundable { ttl_blocks } => {
                    assert!(ttl_blocks > 0, "{pool:?} declares a zero TTL");
                }
                PoolDepositClass::ShieldedBalance => {
                    panic!("{pool:?} must be owner-refundable")
                }
            }
        }
    }

    /// The occupancy arithmetic the K values price: the per-owner quota
    /// forces at least 64 addresses to saturate the note pool, and the
    /// saturation capital is deterministic from the table.
    #[test]
    fn note_pool_saturation_needs_64_addresses_and_locks_the_table_capital() {
        assert_eq!(MAX_LIVE_COMMITMENTS / MAX_LIVE_COMMITMENTS_PER_OWNER, 64);
        let per_row = policy_of(SharedPool::PrivacyNote).deposit;
        let saturation = (MAX_LIVE_COMMITMENTS as u64) * per_row;
        assert_eq!(saturation, 65_536 * 10 * POOL_DEPOSIT_ATOM);
    }

    #[test]
    fn every_deposit_is_a_whole_multiple_of_the_atom() {
        for pool in [
            SharedPool::IdentityRecord,
            SharedPool::IssuedCredential,
            SharedPool::ContentOffer,
            SharedPool::PrivacyNote,
        ] {
            let p = policy_of(pool);
            assert!(p.deposit > 0, "{pool:?} locks nothing");
            assert_eq!(p.deposit % POOL_DEPOSIT_ATOM, 0, "{pool:?} off-atom");
        }
    }
}
