//! Universal Multi-Token Atomic Payment Router, POS/Card Rails & Cross-Domain
//! Liquidation Coordinator (`S-1`, `D-5`, `D-6`).
//!
//! Enables two universal financial primitives across every registered domain:
//!
//! 1. **Simultaneous Multi-Token Atomic Payments**: A merchant, POS terminal,
//!    or card network requests an exact target token on a specific chain (for
//!    example `100 USDC` on Ethereum or Solana). The payer settles seamlessly
//!    in a single atomic step from any mix of tokens held across any chains
//!    (`BUD`, `ETH`, `SOL`, `ATOM`, `APT`, `BTC`, stablecoins) without knowing
//!    which chain holds which leg. Ceiling integer math (`mul_div_ceil`)
//!    prevents rounding-to-zero exploits, deadlines and slippage limits are
//!    enforced deterministically, and settled intent IDs cannot be replayed.
//! 2. **Cross-Domain Liquidations**: Repay unhealthy debt on Domain A by
//!    atomically seizing collateral assets spread across Domains B, C, and D
//!    with oracle-freshness checks, strict close-factor caps, and capped
//!    liquidation bonuses.
//!
//! WIRING: wired through `bud_quoteUniversalPayment` in `src/rpc/server.rs`
//! and re-exported by `src/unification/mod.rs`.

use crate::domain::types::{DomainId, Hash32};
use crate::unification::{
    hash_domain_fields, mul_div_ceil, mul_div_floor, unification_merkle_root, validate_safe_label,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Fixed-point basis-points denominator (`10_000` bps = 100%).
pub const BPS_DENOM: u128 = 10_000;

/// Fixed-point quote rate scale (`10^18` target base units per source base unit).
pub const RATE_SCALE: u128 = 1_000_000_000_000_000_000;

/// Hard slippage ceiling (`1_000` bps = 10%) preventing runaway quote abuse.
pub const MAX_SLIPPAGE_BPS: u16 = 1_000;

/// Maximum source token legs combined inside one atomic split-tender payment.
pub const MAX_SPLIT_TENDER_LEGS: usize = 16;

/// Maximum quotes inspected in one routing request.
pub const MAX_PAYMENT_QUOTES: usize = 64;

/// Maximum settled intent IDs retained in one router replay table.
pub const MAX_SETTLED_INTENTS: usize = 65_536;

/// Maximum liquidation bonus (`1_500` bps = 15%).
pub const MAX_LIQUIDATION_BONUS_BPS: u16 = 1_500;

/// Maximum close factor (`5_000` bps = 50%) for non-bad-debt positions.
pub const MAX_CLOSE_FACTOR_BPS: u16 = 5_000;

/// Maximum oracle price age accepted before liquidation refuses stale prices.
pub const MAX_ORACLE_AGE_SECS: u64 = 120;

/// Settlement rail attached to a [`UniversalPaymentIntent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum PaymentRail {
    /// Native blockchain transfer / contract settlement.
    OnChain,
    /// Physical or virtual point-of-sale terminal (`ISO-4217` currency code).
    PosTerminal {
        terminal_id: String,
        merchant_code: String,
        iso_currency_code: String,
    },
    /// Card network authorization bridge (`Visa`, `Mastercard`, `Troy`, etc.).
    CardNetwork {
        network: String,
        auth_reference: String,
        iso_currency_code: String,
    },
}

impl PaymentRail {
    fn validate(&self) -> Result<(), PaymentError> {
        match self {
            Self::OnChain => Ok(()),
            Self::PosTerminal {
                terminal_id,
                merchant_code,
                iso_currency_code,
            } => {
                validate_safe_label("terminal_id", terminal_id, 48)
                    .map_err(PaymentError::InvalidIntent)?;
                validate_safe_label("merchant_code", merchant_code, 32)
                    .map_err(PaymentError::InvalidIntent)?;
                validate_iso_currency(iso_currency_code)?;
                Ok(())
            }
            Self::CardNetwork {
                network,
                auth_reference,
                iso_currency_code,
            } => {
                validate_safe_label("network", network, 32).map_err(PaymentError::InvalidIntent)?;
                validate_safe_label("auth_reference", auth_reference, 64)
                    .map_err(PaymentError::InvalidIntent)?;
                validate_iso_currency(iso_currency_code)?;
                Ok(())
            }
        }
    }

    fn commitment_hash(&self) -> Hash32 {
        match self {
            Self::OnChain => hash_domain_fields(b"BDLM_RAIL_ONCHAIN", &[]),
            Self::PosTerminal {
                terminal_id,
                merchant_code,
                iso_currency_code,
            } => hash_domain_fields(
                b"BDLM_RAIL_POS",
                &[
                    terminal_id.as_bytes(),
                    merchant_code.as_bytes(),
                    iso_currency_code.as_bytes(),
                ],
            ),
            Self::CardNetwork {
                network,
                auth_reference,
                iso_currency_code,
            } => hash_domain_fields(
                b"BDLM_RAIL_CARD",
                &[
                    network.as_bytes(),
                    auth_reference.as_bytes(),
                    iso_currency_code.as_bytes(),
                ],
            ),
        }
    }
}

fn validate_iso_currency(code: &str) -> Result<(), PaymentError> {
    if code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(PaymentError::InvalidIntent(String::from(
            "iso_currency_code must be a 3-letter uppercase ISO-4217 code",
        )))
    }
}

/// Payment request submitted by a merchant, POS terminal, or cross-chain dApp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalPaymentIntent {
    pub payer_id: Hash32,
    pub merchant_id: Hash32,
    pub nonce: u64,
    pub target_domain: DomainId,
    pub target_asset_id: Hash32,
    pub target_amount: u128,
    pub max_slippage_bps: u16,
    pub deadline_unix_secs: u64,
    pub invoice_hash: Hash32,
    pub rail: PaymentRail,
}

impl UniversalPaymentIntent {
    /// Deterministic replay-protection digest uniquely identifying this intent.
    #[must_use]
    pub fn intent_id(&self) -> Hash32 {
        let nonce_bytes = self.nonce.to_le_bytes();
        let domain_bytes = self.target_domain.to_le_bytes();
        let amt_bytes = self.target_amount.to_le_bytes();
        let slip_bytes = self.max_slippage_bps.to_le_bytes();
        let dl_bytes = self.deadline_unix_secs.to_le_bytes();
        let rail_hash = self.rail.commitment_hash();
        hash_domain_fields(
            b"BDLM_PAYMENT_INTENT_V1",
            &[
                &self.payer_id,
                &self.merchant_id,
                &nonce_bytes,
                &domain_bytes,
                &self.target_asset_id,
                &amt_bytes,
                &slip_bytes,
                &dl_bytes,
                &self.invoice_hash,
                &rail_hash,
            ],
        )
    }

    fn validate(&self, now_unix_secs: u64) -> Result<(), PaymentError> {
        if self.target_domain == 0 {
            return Err(PaymentError::InvalidIntent(String::from(
                "target_domain must be non-zero",
            )));
        }
        if self.target_amount == 0 {
            return Err(PaymentError::InvalidIntent(String::from(
                "target_amount must be non-zero",
            )));
        }
        if self.max_slippage_bps > MAX_SLIPPAGE_BPS {
            return Err(PaymentError::InvalidIntent(format!(
                "max_slippage_bps cannot exceed {MAX_SLIPPAGE_BPS}"
            )));
        }
        if now_unix_secs > self.deadline_unix_secs {
            return Err(PaymentError::Expired {
                now: now_unix_secs,
                deadline: self.deadline_unix_secs,
            });
        }
        self.rail.validate()
    }
}

/// One asset balance held by the payer on a specific blockchain domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainTokenBalance {
    pub domain_id: DomainId,
    pub asset_id: Hash32,
    pub symbol: String,
    pub available_amount: u128,
}

/// Deterministic liquidity quote converting a source `(domain, asset)` into the
/// merchant's `(target_domain, target_asset)` while keeping both domains'
/// native token rules untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityQuote {
    pub quote_id: Hash32,
    pub source_domain: DomainId,
    pub source_asset_id: Hash32,
    pub target_domain: DomainId,
    pub target_asset_id: Hash32,
    /// Target base units received per `RATE_SCALE` source base units.
    pub rate_scaled: u128,
    /// Maximum target units this liquidity source can deliver.
    pub max_target_liquidity: u128,
    /// Protocol / liquidity spread charged in basis points (`<= MAX_SLIPPAGE_BPS`).
    pub fee_bps: u16,
    /// Expiry timestamp in Unix seconds.
    pub valid_until_unix_secs: u64,
}

/// One executed leg in a simultaneous multi-token atomic split-tender payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTenderLeg {
    pub source_domain: DomainId,
    pub source_asset_id: Hash32,
    pub source_symbol: String,
    pub source_debited: u128,
    pub target_delivered: u128,
    pub fee_bps: u16,
    pub direct_same_domain: bool,
    pub quote_id: Option<Hash32>,
}

impl SplitTenderLeg {
    #[must_use]
    fn commitment_hash(&self) -> Hash32 {
        let dom = self.source_domain.to_le_bytes();
        let src = self.source_debited.to_le_bytes();
        let dst = self.target_delivered.to_le_bytes();
        let fee = self.fee_bps.to_le_bytes();
        let direct = [u8::from(self.direct_same_domain)];
        let qid = self.quote_id.unwrap_or([0u8; 32]);
        hash_domain_fields(
            b"BDLM_SPLIT_LEG_V1",
            &[
                &dom,
                &self.source_asset_id,
                self.source_symbol.as_bytes(),
                &src,
                &dst,
                &fee,
                &direct,
                &qid,
            ],
        )
    }
}

/// Cryptographic proof that all source legs settled atomically into the exact
/// requested target asset on the target domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalPaymentReceipt {
    pub intent_id: Hash32,
    pub target_domain: DomainId,
    pub target_asset_id: Hash32,
    pub target_amount_delivered: u128,
    pub legs: Vec<SplitTenderLeg>,
    pub legs_merkle_root: Hash32,
    /// Deterministic 12-character uppercase POS / card authorization code when
    /// settling a POS terminal or card-network rail.
    pub pos_auth_code: Option<String>,
    pub receipt_hash: Hash32,
}

/// Errors returned while planning or settling a universal multi-token payment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaymentError {
    #[error("invalid payment intent: {0}")]
    InvalidIntent(String),
    #[error("payment intent expired (now={now}, deadline={deadline})")]
    Expired { now: u64, deadline: u64 },
    #[error("payment intent has already been settled (replay rejected)")]
    ReplayDetected,
    #[error("too many balances or quotes supplied")]
    InputLimitExceeded,
    #[error("insufficient multi-domain liquidity: short by {shortfall} target units")]
    InsufficientMultiDomainLiquidity { shortfall: u128 },
    #[error("arithmetic overflow while computing settlement leg")]
    ArithmeticOverflow,
}

/// Stateful router enforcing atomic split-tender settlement and anti-replay.
#[derive(Debug, Clone, Default)]
pub struct UniversalPaymentRouter {
    settled_intents: BTreeSet<Hash32>,
}

impl UniversalPaymentRouter {
    /// Creates a fresh router with an empty replay table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes a deterministic dry-run atomic split-tender settlement receipt
    /// without mutating balances or recording replay state.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError`] if the intent is malformed or expired, limits
    /// are exceeded, or combined multi-domain liquidity cannot cover the exact
    /// `target_amount`.
    pub fn quote_payment(
        intent: &UniversalPaymentIntent,
        balances: &[DomainTokenBalance],
        quotes: &[LiquidityQuote],
        now_unix_secs: u64,
    ) -> Result<UniversalPaymentReceipt, PaymentError> {
        intent.validate(now_unix_secs)?;
        if balances.len() > MAX_SPLIT_TENDER_LEGS || quotes.len() > MAX_PAYMENT_QUOTES {
            return Err(PaymentError::InputLimitExceeded);
        }

        let mut seen_balances: BTreeSet<(DomainId, Hash32)> = BTreeSet::new();
        for bal in balances {
            if !seen_balances.insert((bal.domain_id, bal.asset_id)) {
                return Err(PaymentError::InvalidIntent(String::from(
                    "duplicate balance entry for (domain_id, asset_id)",
                )));
            }
        }
        let mut remaining_quote_liquidity: BTreeMap<Hash32, u128> = BTreeMap::new();
        for quote in quotes {
            if remaining_quote_liquidity
                .insert(quote.quote_id, quote.max_target_liquidity)
                .is_some()
            {
                return Err(PaymentError::InvalidIntent(String::from(
                    "duplicate quote_id",
                )));
            }
        }

        let mut remaining = intent.target_amount;
        let mut legs = Vec::new();
        let mut used_balance_indices = BTreeSet::new();

        // Pass 1: consume direct same-domain, same-asset liquidity first (zero spread).
        for (idx, bal) in balances.iter().enumerate() {
            if remaining == 0 {
                break;
            }
            if bal.available_amount == 0
                || bal.domain_id != intent.target_domain
                || bal.asset_id != intent.target_asset_id
            {
                continue;
            }
            let take = bal.available_amount.min(remaining);
            legs.push(SplitTenderLeg {
                source_domain: bal.domain_id,
                source_asset_id: bal.asset_id,
                source_symbol: bal.symbol.clone(),
                source_debited: take,
                target_delivered: take,
                fee_bps: 0,
                direct_same_domain: true,
                quote_id: None,
            });
            used_balance_indices.insert(idx);
            remaining = remaining.saturating_sub(take);
        }

        // Pass 2: draw across any other domains/tokens simultaneously via best valid quotes.
        for (idx, bal) in balances.iter().enumerate() {
            if remaining == 0 {
                break;
            }
            if used_balance_indices.contains(&idx) || bal.available_amount == 0 {
                continue;
            }
            let Some(best_quote) = select_best_quote(
                intent,
                bal,
                quotes,
                &remaining_quote_liquidity,
                now_unix_secs,
            ) else {
                continue;
            };
            let quote_cap = remaining_quote_liquidity
                .get(&best_quote.quote_id)
                .copied()
                .unwrap_or(0);
            let max_deliverable = max_target_from_source(
                bal.available_amount,
                best_quote.rate_scaled,
                best_quote.fee_bps,
            )?
            .min(quote_cap);
            if max_deliverable == 0 {
                continue;
            }
            let deliver = max_deliverable.min(remaining);
            // Ceiling math guarantees a non-zero target delivery ALWAYS charges
            // at least 1 base unit of source token (blocks rounding-to-zero drain).
            let required_source =
                required_source_for_target(deliver, best_quote.rate_scaled, best_quote.fee_bps)?;
            if required_source == 0 || required_source > bal.available_amount {
                continue;
            }
            if let Some(rem_cap) = remaining_quote_liquidity.get_mut(&best_quote.quote_id) {
                *rem_cap = rem_cap.saturating_sub(deliver);
            }
            legs.push(SplitTenderLeg {
                source_domain: bal.domain_id,
                source_asset_id: bal.asset_id,
                source_symbol: bal.symbol.clone(),
                source_debited: required_source,
                target_delivered: deliver,
                fee_bps: best_quote.fee_bps,
                direct_same_domain: false,
                quote_id: Some(best_quote.quote_id),
            });
            remaining = remaining.saturating_sub(deliver);
        }

        if remaining > 0 {
            return Err(PaymentError::InsufficientMultiDomainLiquidity {
                shortfall: remaining,
            });
        }

        let intent_id = intent.intent_id();
        let leg_hashes: Vec<Hash32> = legs.iter().map(SplitTenderLeg::commitment_hash).collect();
        let legs_merkle_root = unification_merkle_root(b"BDLM_PAYMENT_LEGS_V1", &leg_hashes);
        let pos_auth_code = match &intent.rail {
            PaymentRail::OnChain => None,
            PaymentRail::PosTerminal { .. } | PaymentRail::CardNetwork { .. } => {
                let code_hash =
                    hash_domain_fields(b"BDLM_POS_AUTH_CODE_V1", &[&intent_id, &legs_merkle_root]);
                let prefix = code_hash.get(..6).unwrap_or(&code_hash);
                Some(hex::encode(prefix).to_ascii_uppercase())
            }
        };
        let dom_bytes = intent.target_domain.to_le_bytes();
        let amt_bytes = intent.target_amount.to_le_bytes();
        let receipt_hash = hash_domain_fields(
            b"BDLM_PAYMENT_RECEIPT_V1",
            &[
                &intent_id,
                &dom_bytes,
                &intent.target_asset_id,
                &amt_bytes,
                &legs_merkle_root,
            ],
        );

        Ok(UniversalPaymentReceipt {
            intent_id,
            target_domain: intent.target_domain,
            target_asset_id: intent.target_asset_id,
            target_amount_delivered: intent.target_amount,
            legs,
            legs_merkle_root,
            pos_auth_code,
            receipt_hash,
        })
    }

    /// Executes an atomic multi-token split-tender settlement, debiting
    /// `balances` in place ONLY after all legs succeed and recording `intent_id`
    /// to prevent replay.
    ///
    /// Convenience: exposed for atomic settlement execution callers alongside
    /// the dry-run `quote_payment` RPC path.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError`] without mutating any balance if the intent is a
    /// replay, expired, malformed, or underfunded.
    pub fn settle_payment(
        &mut self,
        intent: &UniversalPaymentIntent,
        balances: &mut [DomainTokenBalance],
        quotes: &[LiquidityQuote],
        now_unix_secs: u64,
    ) -> Result<UniversalPaymentReceipt, PaymentError> {
        let id = intent.intent_id();
        if self.settled_intents.contains(&id) {
            return Err(PaymentError::ReplayDetected);
        }
        if self.settled_intents.len() >= MAX_SETTLED_INTENTS {
            return Err(PaymentError::InputLimitExceeded);
        }
        let receipt = Self::quote_payment(intent, balances, quotes, now_unix_secs)?;
        // Pre-validate every debit into a provisional plan before mutating any balance.
        let mut provisional: Vec<(usize, u128)> = Vec::with_capacity(receipt.legs.len());
        for leg in &receipt.legs {
            let (idx, bal) = balances
                .iter()
                .enumerate()
                .find(|(_, b)| {
                    b.domain_id == leg.source_domain && b.asset_id == leg.source_asset_id
                })
                .ok_or(PaymentError::ArithmeticOverflow)?;
            let next_amount = bal
                .available_amount
                .checked_sub(leg.source_debited)
                .ok_or(PaymentError::ArithmeticOverflow)?;
            provisional.push((idx, next_amount));
        }
        // Atomic commit: apply all validated debits together.
        for (idx, next_amount) in provisional {
            if let Some(bal) = balances.get_mut(idx) {
                bal.available_amount = next_amount;
            }
        }
        self.settled_intents.insert(id);
        Ok(receipt)
    }

    /// Returns whether `intent_id` has already been settled.
    #[must_use]
    pub fn is_settled(&self, intent_id: &Hash32) -> bool {
        self.settled_intents.contains(intent_id)
    }
}

fn select_best_quote<'a>(
    intent: &UniversalPaymentIntent,
    balance: &DomainTokenBalance,
    quotes: &'a [LiquidityQuote],
    remaining_liquidity: &BTreeMap<Hash32, u128>,
    now_unix_secs: u64,
) -> Option<&'a LiquidityQuote> {
    quotes
        .iter()
        .filter(|q| {
            let avail_cap = remaining_liquidity.get(&q.quote_id).copied().unwrap_or(0);
            q.source_domain == balance.domain_id
                && q.source_asset_id == balance.asset_id
                && q.target_domain == intent.target_domain
                && q.target_asset_id == intent.target_asset_id
                && q.rate_scaled > 0
                && avail_cap > 0
                && q.fee_bps <= intent.max_slippage_bps
                && q.valid_until_unix_secs >= now_unix_secs
        })
        .max_by(|a, b| {
            let eff_a = mul_div_floor(a.rate_scaled, BPS_DENOM - u128::from(a.fee_bps), BPS_DENOM)
                .unwrap_or(0);
            let eff_b = mul_div_floor(b.rate_scaled, BPS_DENOM - u128::from(b.fee_bps), BPS_DENOM)
                .unwrap_or(0);
            eff_a.cmp(&eff_b).then_with(|| b.quote_id.cmp(&a.quote_id))
        })
}

fn max_target_from_source(
    source_amount: u128,
    rate_scaled: u128,
    fee_bps: u16,
) -> Result<u128, PaymentError> {
    let gross = mul_div_floor(source_amount, rate_scaled, RATE_SCALE)
        .ok_or(PaymentError::ArithmeticOverflow)?;
    let net_bps = BPS_DENOM
        .checked_sub(u128::from(fee_bps))
        .ok_or(PaymentError::ArithmeticOverflow)?;
    mul_div_floor(gross, net_bps, BPS_DENOM).ok_or(PaymentError::ArithmeticOverflow)
}

fn required_source_for_target(
    target_amount: u128,
    rate_scaled: u128,
    fee_bps: u16,
) -> Result<u128, PaymentError> {
    let net_bps = BPS_DENOM
        .checked_sub(u128::from(fee_bps))
        .ok_or(PaymentError::ArithmeticOverflow)?;
    let gross_target =
        mul_div_ceil(target_amount, BPS_DENOM, net_bps).ok_or(PaymentError::ArithmeticOverflow)?;
    mul_div_ceil(gross_target, RATE_SCALE, rate_scaled).ok_or(PaymentError::ArithmeticOverflow)
}

/// One collateral holding pledged on an external domain inside a cross-domain
/// borrowing position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralAsset {
    pub domain_id: DomainId,
    pub asset_id: Hash32,
    pub amount: u128,
    /// USD-equivalent price per `RATE_SCALE` base units (18-decimal fixed point).
    pub price_usd_scaled: u128,
    /// Timestamp when the oracle attested `price_usd_scaled`.
    pub oracle_updated_unix_secs: u64,
    /// Liquidation threshold in basis points (for example `8_000` = 80%).
    pub liquidation_threshold_bps: u16,
}

/// Multi-domain lending position whose debt lives on one chain and collateral
/// basket spans any number of other chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainPosition {
    pub position_id: Hash32,
    pub debt_domain: DomainId,
    pub debt_asset_id: Hash32,
    pub debt_amount: u128,
    pub debt_price_usd_scaled: u128,
    pub debt_oracle_updated_unix_secs: u64,
    pub collateral: Vec<CollateralAsset>,
}

impl CrossDomainPosition {
    /// Computes deterministic health factor in basis points (`10_000` = 1.00x).
    ///
    /// # Errors
    ///
    /// Returns [`LiquidationError`] if any oracle price is stale, zero, or
    /// overflows 256-bit intermediate math.
    pub fn health_factor_bps(&self, now_unix_secs: u64) -> Result<u128, LiquidationError> {
        if self.debt_amount == 0 {
            return Ok(u128::MAX);
        }
        check_oracle_fresh(self.debt_oracle_updated_unix_secs, now_unix_secs)?;
        if self.debt_price_usd_scaled == 0 {
            return Err(LiquidationError::InvalidOraclePrice);
        }
        let debt_usd = mul_div_ceil(self.debt_amount, self.debt_price_usd_scaled, RATE_SCALE)
            .ok_or(LiquidationError::ArithmeticOverflow)?;
        if debt_usd == 0 {
            return Err(LiquidationError::InvalidOraclePrice);
        }
        let mut weighted_collateral_usd = 0u128;
        for col in &self.collateral {
            check_oracle_fresh(col.oracle_updated_unix_secs, now_unix_secs)?;
            if col.price_usd_scaled == 0 || col.liquidation_threshold_bps > 10_000 {
                return Err(LiquidationError::InvalidOraclePrice);
            }
            let raw_usd = mul_div_floor(col.amount, col.price_usd_scaled, RATE_SCALE)
                .ok_or(LiquidationError::ArithmeticOverflow)?;
            let weighted = mul_div_floor(
                raw_usd,
                u128::from(col.liquidation_threshold_bps),
                BPS_DENOM,
            )
            .ok_or(LiquidationError::ArithmeticOverflow)?;
            weighted_collateral_usd = weighted_collateral_usd
                .checked_add(weighted)
                .ok_or(LiquidationError::ArithmeticOverflow)?;
        }
        mul_div_floor(weighted_collateral_usd, BPS_DENOM, debt_usd)
            .ok_or(LiquidationError::ArithmeticOverflow)
    }
}

const fn check_oracle_fresh(updated: u64, now: u64) -> Result<(), LiquidationError> {
    if updated > now || now.saturating_sub(updated) > MAX_ORACLE_AGE_SECS {
        return Err(LiquidationError::StaleOracle { updated, now });
    }
    Ok(())
}

/// One cross-domain collateral seizure leg executed during liquidation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeizedCollateralLeg {
    pub domain_id: DomainId,
    pub asset_id: Hash32,
    pub amount_seized: u128,
    pub value_usd_scaled: u128,
}

/// Atomic receipt proving cross-domain debt repayment and collateral seizure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationReceipt {
    pub position_id: Hash32,
    pub health_factor_before_bps: u128,
    pub debt_repaid: u128,
    pub bonus_bps: u16,
    pub seized_legs: Vec<SeizedCollateralLeg>,
    pub receipt_hash: Hash32,
}

/// Errors returned by [`UniversalLiquidationCoordinator`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiquidationError {
    #[error("position is healthy (health_factor_bps={health_factor_bps} >= 10000)")]
    PositionHealthy { health_factor_bps: u128 },
    #[error("stale or future oracle timestamp (updated={updated}, now={now})")]
    StaleOracle { updated: u64, now: u64 },
    #[error("oracle price or threshold is invalid")]
    InvalidOraclePrice,
    #[error("repay amount is zero or exceeds close-factor cap ({max_repay})")]
    InvalidRepayAmount { max_repay: u128 },
    #[error("liquidation bonus exceeds {MAX_LIQUIDATION_BONUS_BPS} bps ceiling")]
    BonusTooHigh,
    #[error("insufficient collateral across domains to satisfy seizure value")]
    InsufficientCollateral,
    #[error("arithmetic overflow during cross-domain liquidation")]
    ArithmeticOverflow,
}

/// Stateless deterministic coordinator for cross-domain liquidations (`§3.3`).
pub struct UniversalLiquidationCoordinator;

impl UniversalLiquidationCoordinator {
    /// Atomically liquidates an unhealthy [`CrossDomainPosition`], reducing
    /// `debt_amount` and seizing collateral across external domains up to the
    /// close-factor and liquidation-bonus caps.
    ///
    /// Convenience: exposed for cross-domain liquidation settlement callers.
    ///
    /// # Errors
    ///
    /// Returns [`LiquidationError`] without mutating `position` if the position
    /// is healthy, any oracle is stale, the bonus or repay amount exceeds caps,
    /// or collateral is insufficient.
    pub fn execute_liquidation(
        position: &mut CrossDomainPosition,
        repay_debt_amount: u128,
        bonus_bps: u16,
        now_unix_secs: u64,
    ) -> Result<LiquidationReceipt, LiquidationError> {
        if bonus_bps > MAX_LIQUIDATION_BONUS_BPS {
            return Err(LiquidationError::BonusTooHigh);
        }
        let hf_before = position.health_factor_bps(now_unix_secs)?;
        if hf_before >= BPS_DENOM {
            return Err(LiquidationError::PositionHealthy {
                health_factor_bps: hf_before,
            });
        }
        let max_repay = mul_div_floor(
            position.debt_amount,
            u128::from(MAX_CLOSE_FACTOR_BPS),
            BPS_DENOM,
        )
        .ok_or(LiquidationError::ArithmeticOverflow)?
        .max(1)
        .min(position.debt_amount);
        if repay_debt_amount == 0 || repay_debt_amount > max_repay {
            return Err(LiquidationError::InvalidRepayAmount { max_repay });
        }

        // Floor rounding ensures dust repayments cannot round up to seize
        // disproportionate collateral.
        let repay_usd = mul_div_floor(
            repay_debt_amount,
            position.debt_price_usd_scaled,
            RATE_SCALE,
        )
        .ok_or(LiquidationError::ArithmeticOverflow)?;
        if repay_usd == 0 {
            return Err(LiquidationError::InvalidRepayAmount { max_repay });
        }
        let bonus_factor = BPS_DENOM
            .checked_add(u128::from(bonus_bps))
            .ok_or(LiquidationError::ArithmeticOverflow)?;
        let mut remaining_seize_usd = mul_div_floor(repay_usd, bonus_factor, BPS_DENOM)
            .ok_or(LiquidationError::ArithmeticOverflow)?;
        if remaining_seize_usd == 0 {
            return Err(LiquidationError::InvalidRepayAmount { max_repay });
        }

        // Compute provisional seizures first so failure leaves `position` untouched.
        let mut plan: Vec<(usize, SeizedCollateralLeg)> = Vec::new();
        for (idx, col) in position.collateral.iter().enumerate() {
            if remaining_seize_usd == 0 {
                break;
            }
            if col.amount == 0 {
                continue;
            }
            let max_col_usd = mul_div_floor(col.amount, col.price_usd_scaled, RATE_SCALE)
                .ok_or(LiquidationError::ArithmeticOverflow)?;
            if max_col_usd == 0 {
                continue;
            }
            let take_usd = max_col_usd.min(remaining_seize_usd);
            let take_units = mul_div_floor(take_usd, RATE_SCALE, col.price_usd_scaled)
                .ok_or(LiquidationError::ArithmeticOverflow)?
                .min(col.amount);
            if take_units == 0 {
                continue;
            }
            plan.push((
                idx,
                SeizedCollateralLeg {
                    domain_id: col.domain_id,
                    asset_id: col.asset_id,
                    amount_seized: take_units,
                    value_usd_scaled: take_usd,
                },
            ));
            remaining_seize_usd = remaining_seize_usd.saturating_sub(take_usd);
        }

        if remaining_seize_usd > 0 {
            return Err(LiquidationError::InsufficientCollateral);
        }

        // Atomic commit: apply debt reduction and cross-domain seizures together.
        position.debt_amount = position
            .debt_amount
            .checked_sub(repay_debt_amount)
            .ok_or(LiquidationError::ArithmeticOverflow)?;
        let mut seized_legs = Vec::with_capacity(plan.len());
        for (idx, leg) in plan {
            let col = position
                .collateral
                .get_mut(idx)
                .ok_or(LiquidationError::ArithmeticOverflow)?;
            col.amount = col
                .amount
                .checked_sub(leg.amount_seized)
                .ok_or(LiquidationError::ArithmeticOverflow)?;
            seized_legs.push(leg);
        }

        let leg_hashes: Vec<Hash32> = seized_legs
            .iter()
            .map(|l| {
                hash_domain_fields(
                    b"BDLM_SEIZED_LEG_V1",
                    &[
                        &l.domain_id.to_le_bytes(),
                        &l.asset_id,
                        &l.amount_seized.to_le_bytes(),
                        &l.value_usd_scaled.to_le_bytes(),
                    ],
                )
            })
            .collect();
        let legs_root = unification_merkle_root(b"BDLM_LIQUIDATION_LEGS_V1", &leg_hashes);
        let receipt_hash = hash_domain_fields(
            b"BDLM_LIQUIDATION_RECEIPT_V1",
            &[
                &position.position_id,
                &repay_debt_amount.to_le_bytes(),
                &bonus_bps.to_le_bytes(),
                &legs_root,
            ],
        );

        Ok(LiquidationReceipt {
            position_id: position.position_id,
            health_factor_before_bps: hf_before,
            debt_repaid: repay_debt_amount,
            bonus_bps,
            seized_legs,
            receipt_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pos_dollar_payment_settles_atomically_across_three_chains_and_blocks_replay() {
        let usdc_eth = [0x01; 32];
        let bud_asset = [0x02; 32];
        let sol_asset = [0x03; 32];
        let atom_asset = [0x04; 32];

        // Merchant POS terminal requests $100.00 (100_000_000 micro-USDC on Ethereum).
        let intent = UniversalPaymentIntent {
            payer_id: [0xA1; 32],
            merchant_id: [0xB2; 32],
            nonce: 7,
            target_domain: 3, // Ethereum
            target_asset_id: usdc_eth,
            target_amount: 100_000_000,
            max_slippage_bps: 100, // 1%
            deadline_unix_secs: 2_000,
            invoice_hash: [0xCC; 32],
            rail: PaymentRail::PosTerminal {
                terminal_id: String::from("POS-TERM-0042"),
                merchant_code: String::from("MCC5411"),
                iso_currency_code: String::from("USD"),
            },
        };

        // Payer holds NO Ethereum USDC - only BUD on Budlum, SOL on Solana, and ATOM on Cosmos.
        let mut balances = vec![
            DomainTokenBalance {
                domain_id: 1,
                asset_id: bud_asset,
                symbol: String::from("BUD"),
                available_amount: 40_000_000, // $40 worth at 1:1
            },
            DomainTokenBalance {
                domain_id: 4,
                asset_id: sol_asset,
                symbol: String::from("SOL"),
                available_amount: 35_000_000, // $35 worth at 1:1
            },
            DomainTokenBalance {
                domain_id: 5,
                asset_id: atom_asset,
                symbol: String::from("ATOM"),
                available_amount: 50_000_000, // $50 worth at 1:1
            },
        ];

        let quotes = vec![
            LiquidityQuote {
                quote_id: [0x11; 32],
                source_domain: 1,
                source_asset_id: bud_asset,
                target_domain: 3,
                target_asset_id: usdc_eth,
                rate_scaled: RATE_SCALE,
                max_target_liquidity: 100_000_000,
                fee_bps: 20, // 0.20%
                valid_until_unix_secs: 2_500,
            },
            LiquidityQuote {
                quote_id: [0x22; 32],
                source_domain: 4,
                source_asset_id: sol_asset,
                target_domain: 3,
                target_asset_id: usdc_eth,
                rate_scaled: RATE_SCALE,
                max_target_liquidity: 100_000_000,
                fee_bps: 30, // 0.30%
                valid_until_unix_secs: 2_500,
            },
            LiquidityQuote {
                quote_id: [0x33; 32],
                source_domain: 5,
                source_asset_id: atom_asset,
                target_domain: 3,
                target_asset_id: usdc_eth,
                rate_scaled: RATE_SCALE,
                max_target_liquidity: 100_000_000,
                fee_bps: 50, // 0.50%
                valid_until_unix_secs: 2_500,
            },
        ];

        let mut router = UniversalPaymentRouter::new();
        let receipt = router
            .settle_payment(&intent, &mut balances, &quotes, 1_500)
            .unwrap();
        assert_eq!(receipt.target_amount_delivered, 100_000_000);
        assert_eq!(receipt.legs.len(), 3);
        assert_eq!(receipt.pos_auth_code.as_deref().map(str::len), Some(12));
        // Replay is strictly refused.
        assert_eq!(
            router.settle_payment(&intent, &mut balances, &quotes, 1_500),
            Err(PaymentError::ReplayDetected)
        );
    }

    #[test]
    fn rounding_up_blocks_free_micro_payments_and_shortfall_leaves_balances_untouched() {
        let intent = UniversalPaymentIntent {
            payer_id: [0x10; 32],
            merchant_id: [0x20; 32],
            nonce: 1,
            target_domain: 3,
            target_asset_id: [0x99; 32],
            target_amount: 1,
            max_slippage_bps: 50,
            deadline_unix_secs: 1_000,
            invoice_hash: [0x01; 32],
            rail: PaymentRail::OnChain,
        };
        let mut balances = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: [0x88; 32],
            symbol: String::from("BUD"),
            available_amount: 5,
        }];
        // High exchange rate: 1 source = 1000 target. Ceiling math must still debit >= 1 source.
        let quotes = vec![LiquidityQuote {
            quote_id: [0x55; 32],
            source_domain: 1,
            source_asset_id: [0x88; 32],
            target_domain: 3,
            target_asset_id: [0x99; 32],
            rate_scaled: RATE_SCALE * 1_000,
            max_target_liquidity: 10_000,
            fee_bps: 10,
            valid_until_unix_secs: 1_000,
        }];
        let mut router = UniversalPaymentRouter::new();
        let receipt = router
            .settle_payment(&intent, &mut balances, &quotes, 500)
            .unwrap();
        assert_eq!(receipt.legs[0].source_debited, 1);
        assert_eq!(balances[0].available_amount, 4);

        // Underfunded intent leaves remaining balance strictly untouched.
        let huge = UniversalPaymentIntent {
            nonce: 2,
            target_amount: 999_999_999,
            ..intent
        };
        assert!(matches!(
            router.settle_payment(&huge, &mut balances, &quotes, 500),
            Err(PaymentError::InsufficientMultiDomainLiquidity { .. })
        ));
        assert_eq!(balances[0].available_amount, 4);
    }

    #[test]
    fn cross_domain_liquidation_seizes_multi_chain_collateral_and_blocks_healthy_or_stale() {
        let mut pos = CrossDomainPosition {
            position_id: [0xD0; 32],
            debt_domain: 3, // Ethereum USDC debt: $1_000
            debt_asset_id: [0x01; 32],
            debt_amount: 1_000,
            debt_price_usd_scaled: RATE_SCALE,
            debt_oracle_updated_unix_secs: 1_000,
            collateral: vec![
                CollateralAsset {
                    domain_id: 4, // Solana collateral: $600 at 80% threshold = $480 weighted
                    asset_id: [0x04; 32],
                    amount: 600,
                    price_usd_scaled: RATE_SCALE,
                    oracle_updated_unix_secs: 1_000,
                    liquidation_threshold_bps: 8_000,
                },
                CollateralAsset {
                    domain_id: 6, // Aptos collateral: $500 at 80% threshold = $400 weighted
                    asset_id: [0x06; 32],
                    amount: 500,
                    price_usd_scaled: RATE_SCALE,
                    oracle_updated_unix_secs: 1_000,
                    liquidation_threshold_bps: 8_000,
                },
            ],
        };

        // Stale oracle is rejected.
        assert!(matches!(
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos, 400, 500, 2_000),
            Err(LiquidationError::StaleOracle { .. })
        ));
        // Close factor cap (> 50% of 1_000 = 500) is rejected.
        assert!(matches!(
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos, 501, 500, 1_050),
            Err(LiquidationError::InvalidRepayAmount { max_repay: 500 })
        ));

        // Health factor = (480 + 400) / 1000 = 0.88 (8800 bps < 10000): liquidatable!
        // Repaying 500 with 5% bonus seizes 525 USD from Solana collateral.
        let receipt =
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos, 500, 500, 1_050)
                .unwrap();
        assert_eq!(receipt.health_factor_before_bps, 8_800);
        assert_eq!(receipt.debt_repaid, 500);
        assert_eq!(pos.debt_amount, 500);
        assert_eq!(pos.collateral[0].amount, 75);
        assert_eq!(pos.collateral[1].amount, 500);

        // Now weighted collateral = (75 + 500) * 0.8 = 460 vs debt 500 -> HF = 9200 -> still < 10000.
        // Raise price so position becomes healthy and verify liquidation refuses.
        pos.collateral[1].price_usd_scaled = RATE_SCALE * 2;
        assert!(matches!(
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos, 100, 500, 1_050),
            Err(LiquidationError::PositionHealthy { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_balances_and_tracks_quote_liquidity_atomically() {
        let usdc = [0x01; 32];
        let bud = [0x02; 32];
        let intent = UniversalPaymentIntent {
            payer_id: [0xA1; 32],
            merchant_id: [0xB2; 32],
            nonce: 99,
            target_domain: 3,
            target_asset_id: usdc,
            target_amount: 100,
            max_slippage_bps: 100,
            deadline_unix_secs: 2_000,
            invoice_hash: [0xEE; 32],
            rail: PaymentRail::OnChain,
        };
        let mut dup_balances = vec![
            DomainTokenBalance {
                domain_id: 1,
                asset_id: bud,
                symbol: String::from("BUD"),
                available_amount: 60,
            },
            DomainTokenBalance {
                domain_id: 1,
                asset_id: bud,
                symbol: String::from("BUD"),
                available_amount: 60,
            },
        ];
        let quotes = vec![LiquidityQuote {
            quote_id: [0x44; 32],
            source_domain: 1,
            source_asset_id: bud,
            target_domain: 3,
            target_asset_id: usdc,
            rate_scaled: RATE_SCALE,
            max_target_liquidity: 80,
            fee_bps: 0,
            valid_until_unix_secs: 2_500,
        }];
        let mut router = UniversalPaymentRouter::new();
        assert!(matches!(
            router.settle_payment(&intent, &mut dup_balances, &quotes, 1_500),
            Err(PaymentError::InvalidIntent(_))
        ));
        assert_eq!(dup_balances[0].available_amount, 60);
        assert_eq!(dup_balances[1].available_amount, 60);

        // Duplicate quote_id is also rejected cleanly.
        let mut single_bal = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: bud,
            symbol: String::from("BUD"),
            available_amount: 200,
        }];
        let dup_quotes = vec![quotes[0].clone(), quotes[0].clone()];
        assert!(matches!(
            router.settle_payment(&intent, &mut single_bal, &dup_quotes, 1_500),
            Err(PaymentError::InvalidIntent(_))
        ));
        assert_eq!(single_bal[0].available_amount, 200);
    }

    #[test]
    fn liquidation_refuses_zero_value_dust_repay_without_over_seizing() {
        let mut pos = CrossDomainPosition {
            position_id: [0xD1; 32],
            debt_domain: 3,
            debt_asset_id: [0x01; 32],
            debt_amount: 100_000,
            // Sub-1 USD per base unit so 1 base unit of debt has 0 whole USD value.
            debt_price_usd_scaled: RATE_SCALE / 10,
            debt_oracle_updated_unix_secs: 1_000,
            collateral: vec![CollateralAsset {
                domain_id: 4,
                asset_id: [0x04; 32],
                amount: 10_000,
                price_usd_scaled: RATE_SCALE / 2,
                oracle_updated_unix_secs: 1_000,
                liquidation_threshold_bps: 8_000,
            }],
        };

        // 1 wei of debt floors to 0 USD -> must be rejected rather than rounding up to 1 USD.
        assert!(matches!(
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos, 1, 500, 1_050),
            Err(LiquidationError::InvalidRepayAmount { .. })
        ));
        assert_eq!(pos.debt_amount, 100_000);
        assert_eq!(pos.collateral[0].amount, 10_000);
    }
}
