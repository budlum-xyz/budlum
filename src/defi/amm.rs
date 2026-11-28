//! Deterministic Constant-Product AMM (`x * y = k`) with locked minimum liquidity
//! (anti-inflation attack) and built-in multi-epoch TWAP snapshots reusing
//! [`crate::settlement::liquidation_proof::MIN_TWAP_EPOCHS`].
//!
//! WIRING: wired through `src/defi/mod.rs` (`DeFiTx`) into `TransactionType::DeFi`
//! and `AccountState::defi`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;
use crate::settlement::liquidation_proof::{MAX_OBSERVATIONS, MIN_TWAP_EPOCHS};

/// Permanently locked initial LP shares to block share-inflation attacks.
pub const MINIMUM_LIQUIDITY: u128 = 1_000;
/// Fee denominator in basis points.
pub const BPS_DENOMINATOR: u128 = 10_000;
/// Maximum allowed swap fee (10% = 1,000 bps).
pub const MAX_FEE_BPS: u64 = 1_000;
/// Fixed-point 1e18 price scalar matching `liquidation_proof`.
pub const PRICE_SCALE: u128 = 1_000_000_000_000_000_000;

/// Integer square root (`floor(sqrt(n))`), strictly overflow-free across all `u128`.
#[must_use]
pub const fn isqrt_u128(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x0 = n >> 1;
    let mut x1 = (x0 + n / x0) >> 1;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + n / x0) >> 1;
    }
    x0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwapSnapshot {
    pub epoch: u64,
    pub reserve_a: u128,
    pub reserve_b: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityPool {
    pub pool_id: [u8; 32],
    pub asset_a: [u8; 32],
    pub asset_b: [u8; 32],
    pub reserve_a: u128,
    pub reserve_b: u128,
    pub fee_bps: u64,
    pub total_lp_shares: u128,
    pub lp_balances: BTreeMap<Address, u128>,
    pub twap_history: Vec<TwapSnapshot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub pools: BTreeMap<[u8; 32], LiquidityPool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatePoolParams {
    pub pool_id: [u8; 32],
    pub asset_a: [u8; 32],
    pub asset_b: [u8; 32],
    pub amount_a: u128,
    pub amount_b: u128,
    pub fee_bps: u64,
}

impl AmmRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pools: BTreeMap::new(),
        }
    }

    pub fn create_pool(
        &mut self,
        creator: Address,
        params: CreatePoolParams,
        epoch: u64,
    ) -> Result<u128, String> {
        let CreatePoolParams {
            pool_id,
            asset_a,
            asset_b,
            amount_a,
            amount_b,
            fee_bps,
        } = params;
        if pool_id == [0u8; 32] || asset_a == asset_b {
            return Err(String::from("invalid pool_id or identical assets"));
        }
        if self.pools.contains_key(&pool_id) {
            return Err(String::from("pool already exists"));
        }
        if fee_bps > MAX_FEE_BPS {
            return Err(String::from("fee_bps exceeds MAX_FEE_BPS"));
        }
        if amount_a == 0 || amount_b == 0 {
            return Err(String::from("initial reserves must be positive"));
        }
        let product = amount_a
            .checked_mul(amount_b)
            .ok_or_else(|| String::from("initial reserve product overflows u128"))?;
        let root = isqrt_u128(product);
        if root <= MINIMUM_LIQUIDITY {
            return Err(String::from(
                "initial liquidity must exceed MINIMUM_LIQUIDITY",
            ));
        }
        let creator_shares = root - MINIMUM_LIQUIDITY;
        let mut lp_balances = BTreeMap::new();
        lp_balances.insert(Address::zero(), MINIMUM_LIQUIDITY);
        lp_balances.insert(creator, creator_shares);
        self.pools.insert(
            pool_id,
            LiquidityPool {
                pool_id,
                asset_a,
                asset_b,
                reserve_a: amount_a,
                reserve_b: amount_b,
                fee_bps,
                total_lp_shares: root,
                lp_balances,
                twap_history: vec![TwapSnapshot {
                    epoch,
                    reserve_a: amount_a,
                    reserve_b: amount_b,
                }],
            },
        );
        Ok(creator_shares)
    }

    pub fn add_liquidity(
        &mut self,
        provider: Address,
        pool_id: &[u8; 32],
        amount_a: u128,
        amount_b: u128,
        epoch: u64,
    ) -> Result<u128, String> {
        let pool = self
            .pools
            .get_mut(pool_id)
            .ok_or_else(|| String::from("unknown AMM pool"))?;
        if amount_a == 0 || amount_b == 0 || pool.total_lp_shares == 0 {
            return Err(String::from("liquidity amounts must be positive"));
        }
        let share_a = amount_a
            .checked_mul(pool.total_lp_shares)
            .ok_or_else(|| String::from("share_a overflow"))?
            / pool.reserve_a.max(1);
        let share_b = amount_b
            .checked_mul(pool.total_lp_shares)
            .ok_or_else(|| String::from("share_b overflow"))?
            / pool.reserve_b.max(1);
        let minted = share_a.min(share_b);
        if minted == 0 {
            return Err(String::from("insufficient deposit for >= 1 LP share"));
        }
        pool.reserve_a = pool
            .reserve_a
            .checked_add(amount_a)
            .ok_or_else(|| String::from("reserve_a overflow"))?;
        pool.reserve_b = pool
            .reserve_b
            .checked_add(amount_b)
            .ok_or_else(|| String::from("reserve_b overflow"))?;
        pool.total_lp_shares = pool
            .total_lp_shares
            .checked_add(minted)
            .ok_or_else(|| String::from("total_lp_shares overflow"))?;
        let next = pool
            .lp_balances
            .get(&provider)
            .copied()
            .unwrap_or(0)
            .checked_add(minted)
            .ok_or_else(|| String::from("lp balance overflow"))?;
        pool.lp_balances.insert(provider, next);
        push_twap(
            &mut pool.twap_history,
            epoch,
            pool.reserve_a,
            pool.reserve_b,
        );
        Ok(minted)
    }

    pub fn remove_liquidity(
        &mut self,
        provider: Address,
        pool_id: &[u8; 32],
        shares: u128,
        epoch: u64,
    ) -> Result<(u128, u128), String> {
        let pool = self
            .pools
            .get_mut(pool_id)
            .ok_or_else(|| String::from("unknown AMM pool"))?;
        if provider == Address::zero() || shares == 0 {
            return Err(String::from("invalid provider or zero shares"));
        }
        let owned = pool.lp_balances.get(&provider).copied().unwrap_or(0);
        if owned < shares {
            return Err(String::from("insufficient LP shares"));
        }
        let out_a = shares
            .checked_mul(pool.reserve_a)
            .ok_or_else(|| String::from("out_a overflow"))?
            / pool.total_lp_shares;
        let out_b = shares
            .checked_mul(pool.reserve_b)
            .ok_or_else(|| String::from("out_b overflow"))?
            / pool.total_lp_shares;
        if out_a == 0 && out_b == 0 {
            return Err(String::from("withdrawal rounds to zero"));
        }
        pool.reserve_a -= out_a;
        pool.reserve_b -= out_b;
        pool.total_lp_shares -= shares;
        let rem = owned - shares;
        if rem == 0 {
            pool.lp_balances.remove(&provider);
        } else {
            pool.lp_balances.insert(provider, rem);
        }
        push_twap(
            &mut pool.twap_history,
            epoch,
            pool.reserve_a,
            pool.reserve_b,
        );
        Ok((out_a, out_b))
    }

    pub fn swap(
        &mut self,
        pool_id: &[u8; 32],
        a_to_b: bool,
        amount_in: u128,
        min_amount_out: u128,
        epoch: u64,
    ) -> Result<u128, String> {
        let pool = self
            .pools
            .get_mut(pool_id)
            .ok_or_else(|| String::from("unknown AMM pool"))?;
        if amount_in == 0 {
            return Err(String::from("swap amount_in must be positive"));
        }
        let (res_in, res_out) = if a_to_b {
            (pool.reserve_a, pool.reserve_b)
        } else {
            (pool.reserve_b, pool.reserve_a)
        };
        let fee_factor = BPS_DENOMINATOR - u128::from(pool.fee_bps);
        let amount_in_with_fee = amount_in
            .checked_mul(fee_factor)
            .ok_or_else(|| String::from("amount_in_with_fee overflow"))?;
        let numerator = amount_in_with_fee
            .checked_mul(res_out)
            .ok_or_else(|| String::from("swap numerator overflow"))?;
        let denominator = res_in
            .checked_mul(BPS_DENOMINATOR)
            .and_then(|d| d.checked_add(amount_in_with_fee))
            .ok_or_else(|| String::from("swap denominator overflow"))?;
        let amount_out = numerator / denominator;
        if amount_out == 0 || amount_out >= res_out {
            return Err(String::from("swap drained reserve or produced zero output"));
        }
        if amount_out < min_amount_out {
            return Err(String::from("slippage limit exceeded"));
        }
        if a_to_b {
            pool.reserve_a = pool
                .reserve_a
                .checked_add(amount_in)
                .ok_or_else(|| String::from("reserve_a overflow"))?;
            pool.reserve_b -= amount_out;
        } else {
            pool.reserve_b = pool
                .reserve_b
                .checked_add(amount_in)
                .ok_or_else(|| String::from("reserve_b overflow"))?;
            pool.reserve_a -= amount_out;
        }
        push_twap(
            &mut pool.twap_history,
            epoch,
            pool.reserve_a,
            pool.reserve_b,
        );
        Ok(amount_out)
    }

    /// Compute integer TWAP (`reserve_b * 1e18 / reserve_a`) requiring at least `MIN_TWAP_EPOCHS`.
    pub fn twap_b_per_a_scaled(&self, pool_id: &[u8; 32]) -> Result<u128, String> {
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| String::from("unknown AMM pool"))?;
        let need = usize::try_from(MIN_TWAP_EPOCHS).unwrap_or(3);
        let start = pool.twap_history.len().checked_sub(need).ok_or_else(|| {
            format!(
                "insufficient TWAP epochs: have {}, need {MIN_TWAP_EPOCHS}",
                pool.twap_history.len()
            )
        })?;
        let slice = pool
            .twap_history
            .get(start..)
            .ok_or_else(|| String::from("TWAP history range out of bounds"))?;
        let mut sum: u128 = 0;
        for snap in slice {
            if snap.reserve_a == 0 {
                return Err(String::from("zero reserve_a in TWAP history"));
            }
            let spot = snap
                .reserve_b
                .checked_mul(PRICE_SCALE)
                .ok_or_else(|| String::from("TWAP price scale overflow"))?
                / snap.reserve_a;
            sum = sum
                .checked_add(spot)
                .ok_or_else(|| String::from("TWAP accumulator overflow"))?;
        }
        Ok(sum / u128::from(MIN_TWAP_EPOCHS))
    }

    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_DEFI_AMM_V1");
        for (id, pool) in &self.pools {
            h.update(id);
            h.update(pool.reserve_a.to_le_bytes());
            h.update(pool.reserve_b.to_le_bytes());
            h.update(pool.total_lp_shares.to_le_bytes());
        }
        h.finalize().into()
    }
}

fn push_twap(history: &mut Vec<TwapSnapshot>, epoch: u64, reserve_a: u128, reserve_b: u128) {
    if let Some(last) = history.last_mut() {
        if last.epoch == epoch {
            last.reserve_a = reserve_a;
            last.reserve_b = reserve_b;
            return;
        }
    }
    history.push(TwapSnapshot {
        epoch,
        reserve_a,
        reserve_b,
    });
    if history.len() > MAX_OBSERVATIONS {
        history.remove(0);
    }
}
