//! Deterministic Over-Collateralized Lending Pool + Oracle-Free TWAP Liquidations
//! using [`crate::settlement::liquidation_proof::LIQUIDATION_PENALTY_BPS`].
//!
//! WIRING: wired through `src/defi/mod.rs` (`DeFiTx`) into `TransactionType::DeFi`
//! and `AccountState::defi`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;
use crate::defi::amm::PRICE_SCALE;
use crate::settlement::liquidation_proof::LIQUIDATION_PENALTY_BPS;

const BPS: u128 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingPosition {
    pub collateral_amount: u128,
    pub debt_amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingMarket {
    pub market_id: [u8; 32],
    pub total_supplied: u128,
    pub total_borrowed: u128,
    /// Collateral threshold required to borrow (e.g., 15_000 = 150%).
    pub borrow_collateral_ratio_bps: u64,
    /// Maintenance threshold below which TWAP liquidation triggers (e.g., 12_000 = 120%).
    pub liquidation_threshold_bps: u64,
    /// Annual interest rate at 100% utilization in bps.
    pub base_rate_bps: u64,
    pub suppliers: BTreeMap<Address, u128>,
    pub positions: BTreeMap<Address, LendingPosition>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub markets: BTreeMap<[u8; 32], LendingMarket>,
}

impl LendingRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            markets: BTreeMap::new(),
        }
    }

    pub fn create_market(
        &mut self,
        market_id: [u8; 32],
        borrow_collateral_ratio_bps: u64,
        liquidation_threshold_bps: u64,
        base_rate_bps: u64,
    ) -> Result<(), String> {
        if market_id == [0u8; 32] {
            return Err(String::from("zero market_id"));
        }
        if self.markets.contains_key(&market_id) {
            return Err(String::from("market already exists"));
        }
        if liquidation_threshold_bps < 10_500
            || borrow_collateral_ratio_bps < liquidation_threshold_bps
        {
            return Err(String::from("unsafe collateralization parameters"));
        }
        self.markets.insert(
            market_id,
            LendingMarket {
                market_id,
                total_supplied: 0,
                total_borrowed: 0,
                borrow_collateral_ratio_bps,
                liquidation_threshold_bps,
                base_rate_bps,
                suppliers: BTreeMap::new(),
                positions: BTreeMap::new(),
            },
        );
        Ok(())
    }

    pub fn supply(
        &mut self,
        lender: Address,
        market_id: &[u8; 32],
        amount: u128,
    ) -> Result<(), String> {
        let m = self
            .markets
            .get_mut(market_id)
            .ok_or_else(|| String::from("unknown lending market"))?;
        if amount == 0 {
            return Err(String::from("zero supply"));
        }
        m.total_supplied = m
            .total_supplied
            .checked_add(amount)
            .ok_or_else(|| String::from("total_supplied overflow"))?;
        let next = m
            .suppliers
            .get(&lender)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or_else(|| String::from("supplier balance overflow"))?;
        m.suppliers.insert(lender, next);
        Ok(())
    }

    pub fn deposit_collateral_and_borrow(
        &mut self,
        borrower: Address,
        market_id: &[u8; 32],
        collateral_added: u128,
        borrow_amount: u128,
        twap_collateral_per_debt_scaled: u128,
    ) -> Result<(), String> {
        let m = self
            .markets
            .get_mut(market_id)
            .ok_or_else(|| String::from("unknown lending market"))?;
        if twap_collateral_per_debt_scaled == 0 {
            return Err(String::from("zero TWAP price"));
        }
        let avail_liquidity = m.total_supplied.saturating_sub(m.total_borrowed);
        if borrow_amount > avail_liquidity {
            return Err(String::from("insufficient lending liquidity"));
        }
        let pos = m.positions.entry(borrower).or_insert(LendingPosition {
            collateral_amount: 0,
            debt_amount: 0,
        });
        let new_coll = pos
            .collateral_amount
            .checked_add(collateral_added)
            .ok_or_else(|| String::from("collateral overflow"))?;
        let new_debt = pos
            .debt_amount
            .checked_add(borrow_amount)
            .ok_or_else(|| String::from("debt overflow"))?;

        // Health check: coll_value >= new_debt * borrow_ratio / BPS
        // where debt_in_collateral_units = new_debt * twap_collateral_per_debt_scaled / PRICE_SCALE
        let debt_value_in_coll = new_debt
            .checked_mul(twap_collateral_per_debt_scaled)
            .ok_or_else(|| String::from("debt value overflow"))?
            / PRICE_SCALE;
        let required_coll = debt_value_in_coll
            .checked_mul(u128::from(m.borrow_collateral_ratio_bps))
            .ok_or_else(|| String::from("required_coll overflow"))?
            / BPS;
        if new_coll < required_coll {
            return Err(String::from("position under-collateralized at TWAP"));
        }
        pos.collateral_amount = new_coll;
        pos.debt_amount = new_debt;
        m.total_borrowed = m
            .total_borrowed
            .checked_add(borrow_amount)
            .ok_or_else(|| String::from("total_borrowed overflow"))?;
        Ok(())
    }

    pub fn liquidate(
        &mut self,
        borrower: Address,
        market_id: &[u8; 32],
        repay_debt: u128,
        twap_collateral_per_debt_scaled: u128,
    ) -> Result<u128, String> {
        let m = self
            .markets
            .get_mut(market_id)
            .ok_or_else(|| String::from("unknown lending market"))?;
        let pos = m
            .positions
            .get_mut(&borrower)
            .ok_or_else(|| String::from("unknown borrower position"))?;
        if repay_debt == 0 || repay_debt > pos.debt_amount || twap_collateral_per_debt_scaled == 0 {
            return Err(String::from("invalid liquidation repay amount or TWAP"));
        }
        let debt_coll = pos
            .debt_amount
            .checked_mul(twap_collateral_per_debt_scaled)
            .ok_or_else(|| String::from("debt_coll overflow"))?
            / PRICE_SCALE;
        let min_healthy_coll = debt_coll
            .checked_mul(u128::from(m.liquidation_threshold_bps))
            .ok_or_else(|| String::from("min_healthy_coll overflow"))?
            / BPS;
        if pos.collateral_amount >= min_healthy_coll {
            return Err(String::from("position is healthy; cannot liquidate"));
        }
        let repay_coll = repay_debt
            .checked_mul(twap_collateral_per_debt_scaled)
            .ok_or_else(|| String::from("repay_coll overflow"))?
            / PRICE_SCALE;
        let seized = repay_coll
            .checked_mul(BPS + u128::from(LIQUIDATION_PENALTY_BPS))
            .ok_or_else(|| String::from("seized penalty overflow"))?
            / BPS;
        let actual_seized = seized.min(pos.collateral_amount);
        pos.collateral_amount -= actual_seized;
        pos.debt_amount -= repay_debt;
        m.total_borrowed = m.total_borrowed.saturating_sub(repay_debt);
        Ok(actual_seized)
    }

    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_DEFI_LENDING_V1");
        for (id, m) in &self.markets {
            h.update(id);
            h.update(m.total_supplied.to_le_bytes());
            h.update(m.total_borrowed.to_le_bytes());
            for (addr, pos) in &m.positions {
                h.update(addr.0);
                h.update(pos.collateral_amount.to_le_bytes());
                h.update(pos.debt_amount.to_le_bytes());
            }
        }
        h.finalize().into()
    }
}
