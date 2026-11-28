//! Fully-Collateralized Deterministic On-Chain Options (`OptionsRegistry`).
//! Every written call/put locks 100% of maximum possible payout upfront so
//! buyers enjoy mathematical solvency guarantees at expiry.
//!
//! WIRING: wired through `src/defi/mod.rs` (`DeFiTx`) into `TransactionType::DeFi`
//! and `AccountState::defi`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptionKind {
    CoveredCall,
    CashSecuredPut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionSeries {
    pub series_id: [u8; 32],
    pub writer: Address,
    pub holder: Option<Address>,
    pub kind: OptionKind,
    pub strike_price: u128,
    pub size: u128,
    pub premium: u128,
    pub collateral_locked: u128,
    pub expiry_epoch: u64,
    pub settled: bool,
    pub payout_to_holder: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionsRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub series: BTreeMap<[u8; 32], OptionSeries>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteOptionParams {
    pub series_id: [u8; 32],
    pub kind: OptionKind,
    pub strike_price: u128,
    pub size: u128,
    pub premium: u128,
    pub expiry_epoch: u64,
}

impl OptionsRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            series: BTreeMap::new(),
        }
    }

    pub fn write_series(
        &mut self,
        writer: Address,
        params: WriteOptionParams,
    ) -> Result<u128, String> {
        let WriteOptionParams {
            series_id,
            kind,
            strike_price,
            size,
            premium,
            expiry_epoch,
        } = params;
        if series_id == [0u8; 32] || strike_price == 0 || size == 0 {
            return Err(String::from("invalid option series parameters"));
        }
        if self.series.contains_key(&series_id) {
            return Err(String::from("option series already exists"));
        }
        let collateral_locked = match kind {
            OptionKind::CoveredCall => size,
            OptionKind::CashSecuredPut => size
                .checked_mul(strike_price)
                .ok_or_else(|| String::from("put collateral overflow"))?,
        };
        self.series.insert(
            series_id,
            OptionSeries {
                series_id,
                writer,
                holder: None,
                kind,
                strike_price,
                size,
                premium,
                collateral_locked,
                expiry_epoch,
                settled: false,
                payout_to_holder: 0,
            },
        );
        Ok(collateral_locked)
    }

    pub fn buy_series(&mut self, buyer: Address, series_id: &[u8; 32]) -> Result<u128, String> {
        let s = self
            .series
            .get_mut(series_id)
            .ok_or_else(|| String::from("unknown option series"))?;
        if s.holder.is_some() || s.settled {
            return Err(String::from("option series already purchased or settled"));
        }
        s.holder = Some(buyer);
        Ok(s.premium)
    }

    pub fn settle_at_expiry(
        &mut self,
        series_id: &[u8; 32],
        current_epoch: u64,
        twap_settlement_price: u128,
    ) -> Result<u128, String> {
        let s = self
            .series
            .get_mut(series_id)
            .ok_or_else(|| String::from("unknown option series"))?;
        if s.settled {
            return Err(String::from("option already settled"));
        }
        if current_epoch < s.expiry_epoch {
            return Err(String::from("option has not reached expiry_epoch"));
        }
        let payout = if s.holder.is_none() {
            0
        } else {
            match s.kind {
                OptionKind::CoveredCall => {
                    if twap_settlement_price > s.strike_price && twap_settlement_price > 0 {
                        let intrinsic = (twap_settlement_price - s.strike_price)
                            .checked_mul(s.size)
                            .ok_or_else(|| String::from("call payout overflow"))?
                            / twap_settlement_price;
                        intrinsic.min(s.collateral_locked)
                    } else {
                        0
                    }
                }
                OptionKind::CashSecuredPut => {
                    if s.strike_price > twap_settlement_price {
                        let intrinsic = (s.strike_price - twap_settlement_price)
                            .checked_mul(s.size)
                            .ok_or_else(|| String::from("put payout overflow"))?;
                        intrinsic.min(s.collateral_locked)
                    } else {
                        0
                    }
                }
            }
        };
        s.settled = true;
        s.payout_to_holder = payout;
        Ok(payout)
    }

    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_DEFI_OPTIONS_V1");
        for (id, s) in &self.series {
            h.update(id);
            h.update([u8::from(s.settled)]);
            h.update(s.payout_to_holder.to_le_bytes());
        }
        h.finalize().into()
    }
}
