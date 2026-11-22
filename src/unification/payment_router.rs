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

/// Stateful router enforcing atomic split-tender settlement, cross-intent quote
/// liquidity accounting, and anti-replay.
#[derive(Debug, Clone, Default)]
pub struct UniversalPaymentRouter {
    settled_intents: BTreeSet<Hash32>,
    consumed_quote_liquidity: BTreeMap<Hash32, u128>,
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
        let empty = BTreeMap::new();
        Self::quote_payment_with_consumed(intent, balances, quotes, &empty, now_unix_secs)
    }

    fn quote_payment_with_consumed(
        intent: &UniversalPaymentIntent,
        balances: &[DomainTokenBalance],
        quotes: &[LiquidityQuote],
        prior_consumed: &BTreeMap<Hash32, u128>,
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
            let already_used = prior_consumed.get(&quote.quote_id).copied().unwrap_or(0);
            let avail = quote.max_target_liquidity.saturating_sub(already_used);
            if remaining_quote_liquidity
                .insert(quote.quote_id, avail)
                .is_some()
            {
                return Err(PaymentError::InvalidIntent(String::from(
                    "duplicate quote_id",
                )));
            }
        }

        let mut remaining = intent.target_amount;
        let mut legs = Vec::new();
        let mut remaining_balances: Vec<u128> =
            balances.iter().map(|b| b.available_amount).collect();

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
            if let Some(rem_bal) = remaining_balances.get_mut(idx) {
                *rem_bal = rem_bal.saturating_sub(take);
            }
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
            remaining = remaining.saturating_sub(take);
        }

        // Pass 2: canonical, caller-slice-order-independent greedy selection across all
        // remaining balances and valid quotes (lowest `fee_bps` first, deterministic
        // `(domain_id, asset_id, quote_id)` tie-breaker, allowing one balance to span
        // multiple quotes up to `MAX_SPLIT_TENDER_LEGS`).
        while remaining > 0 && legs.len() < MAX_SPLIT_TENDER_LEGS {
            let mut best_step: Option<(usize, &DomainTokenBalance, &LiquidityQuote, u128, u128)> =
                None;
            for (idx, bal) in balances.iter().enumerate() {
                if bal.domain_id == intent.target_domain && bal.asset_id == intent.target_asset_id {
                    continue;
                }
                let rem_bal = remaining_balances.get(idx).copied().unwrap_or(0);
                if rem_bal == 0 {
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
                let max_deliverable =
                    max_target_from_source(rem_bal, best_quote.rate_scaled, best_quote.fee_bps)?
                        .min(quote_cap);
                if max_deliverable == 0 {
                    continue;
                }
                let deliver = max_deliverable.min(remaining);
                // Ceiling math guarantees a non-zero target delivery ALWAYS charges
                // at least 1 base unit of source token (blocks rounding-to-zero drain).
                let required_source = required_source_for_target(
                    deliver,
                    best_quote.rate_scaled,
                    best_quote.fee_bps,
                )?;
                if required_source == 0 || required_source > rem_bal {
                    continue;
                }
                let replace = match best_step {
                    None => true,
                    Some((_, cur_bal, cur_quote, _, _)) => {
                        (
                            best_quote.fee_bps,
                            bal.domain_id,
                            bal.asset_id,
                            best_quote.quote_id,
                        ) < (
                            cur_quote.fee_bps,
                            cur_bal.domain_id,
                            cur_bal.asset_id,
                            cur_quote.quote_id,
                        )
                    }
                };
                if replace {
                    best_step = Some((idx, bal, best_quote, deliver, required_source));
                }
            }

            let Some((win_idx, win_bal, win_quote, deliver, required_source)) = best_step else {
                break;
            };
            if let Some(rem_bal) = remaining_balances.get_mut(win_idx) {
                *rem_bal = rem_bal.saturating_sub(required_source);
            }
            if let Some(rem_cap) = remaining_quote_liquidity.get_mut(&win_quote.quote_id) {
                *rem_cap = rem_cap.saturating_sub(deliver);
            }
            legs.push(SplitTenderLeg {
                source_domain: win_bal.domain_id,
                source_asset_id: win_bal.asset_id,
                source_symbol: win_bal.symbol.clone(),
                source_debited: required_source,
                target_delivered: deliver,
                fee_bps: win_quote.fee_bps,
                direct_same_domain: false,
                quote_id: Some(win_quote.quote_id),
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
        let receipt = Self::quote_payment_with_consumed(
            intent,
            balances,
            quotes,
            &self.consumed_quote_liquidity,
            now_unix_secs,
        )?;
        // Pre-validate cumulative debits per balance index AND cumulative quote
        // liquidity draws before mutating any state (atomic rollback guarantee).
        let quotes_by_id: BTreeMap<Hash32, &LiquidityQuote> =
            quotes.iter().map(|q| (q.quote_id, q)).collect();
        let mut provisional_quotes: BTreeMap<Hash32, u128> = BTreeMap::new();
        let mut new_quote_entries = 0usize;
        let mut cumulative_debits: BTreeMap<usize, u128> = BTreeMap::new();
        let mut source_total_value = 0u128;
        let mut total_fees = 0u128;
        for leg in &receipt.legs {
            let (idx, _) = balances
                .iter()
                .enumerate()
                .find(|(_, b)| {
                    b.domain_id == leg.source_domain && b.asset_id == leg.source_asset_id
                })
                .ok_or(PaymentError::ArithmeticOverflow)?;
            let entry = cumulative_debits.entry(idx).or_insert(0);
            *entry = entry
                .checked_add(leg.source_debited)
                .ok_or(PaymentError::ArithmeticOverflow)?;
            let leg_gross_value = if let Some(qid) = leg.quote_id {
                let quote = quotes_by_id
                    .get(&qid)
                    .copied()
                    .ok_or(PaymentError::ArithmeticOverflow)?;
                let cap = quote.max_target_liquidity;
                let base = if let Some(&staged) = provisional_quotes.get(&qid) {
                    staged
                } else if let Some(&existing) = self.consumed_quote_liquidity.get(&qid) {
                    existing
                } else {
                    new_quote_entries = new_quote_entries.saturating_add(1);
                    0
                };
                let updated = base
                    .checked_add(leg.target_delivered)
                    .ok_or(PaymentError::ArithmeticOverflow)?;
                if updated > cap {
                    return Err(PaymentError::InsufficientMultiDomainLiquidity {
                        shortfall: updated - cap,
                    });
                }
                provisional_quotes.insert(qid, updated);
                mul_div_floor(leg.source_debited, quote.rate_scaled, RATE_SCALE)
                    .ok_or(PaymentError::ArithmeticOverflow)?
            } else {
                leg.source_debited
            };
            let leg_fee = leg_gross_value
                .checked_sub(leg.target_delivered)
                .ok_or_else(|| {
                    PaymentError::InvalidIntent(String::from(
                        "split-tender leg delivered more target value than debited source value",
                    ))
                })?;
            source_total_value = source_total_value
                .checked_add(leg_gross_value)
                .ok_or(PaymentError::ArithmeticOverflow)?;
            total_fees = total_fees
                .checked_add(leg_fee)
                .ok_or(PaymentError::ArithmeticOverflow)?;
        }
        verify_split_tender_supply_conservation(
            &receipt,
            source_total_value,
            intent.target_amount,
            total_fees,
        )?;
        if self
            .consumed_quote_liquidity
            .len()
            .saturating_add(new_quote_entries)
            > MAX_SETTLED_INTENTS
        {
            return Err(PaymentError::InputLimitExceeded);
        }
        let mut provisional: Vec<(usize, u128)> = Vec::with_capacity(cumulative_debits.len());
        for (idx, total_debited) in cumulative_debits {
            let bal = balances.get(idx).ok_or(PaymentError::ArithmeticOverflow)?;
            let next_amount = bal
                .available_amount
                .checked_sub(total_debited)
                .ok_or(PaymentError::ArithmeticOverflow)?;
            provisional.push((idx, next_amount));
        }
        // Atomic commit: apply validated debits, quote fills, and anti-replay together.
        for (idx, next_amount) in provisional {
            if let Some(bal) = balances.get_mut(idx) {
                bal.available_amount = next_amount;
            }
        }
        for (qid, used) in provisional_quotes {
            self.consumed_quote_liquidity.insert(qid, used);
        }
        self.settled_intents.insert(id);
        Ok(receipt)
    }

    /// Returns cumulative target liquidity already consumed from `quote_id`.
    #[must_use]
    pub fn consumed_quote_liquidity(&self, quote_id: &Hash32) -> u128 {
        self.consumed_quote_liquidity
            .get(quote_id)
            .copied()
            .unwrap_or(0)
    }

    /// Deterministic Merkle commitment over settled intent IDs and quote fills.
    #[must_use]
    pub(crate) fn state_commitment(&self) -> Hash32 {
        let intent_leaves: Vec<Hash32> = self.settled_intents.iter().copied().collect();
        let quote_leaves: Vec<Hash32> = self
            .consumed_quote_liquidity
            .iter()
            .map(|(qid, used)| {
                hash_domain_fields(b"BDLM_ROUTER_QUOTE_FILL_V1", &[qid, &used.to_le_bytes()])
            })
            .collect();
        let intents_root = unification_merkle_root(b"BDLM_ROUTER_INTENTS_V1", &intent_leaves);
        let quotes_root = unification_merkle_root(b"BDLM_ROUTER_QUOTES_V1", &quote_leaves);
        hash_domain_fields(
            b"BDLM_PAYMENT_ROUTER_ROOT_V1",
            &[&intents_root, &quotes_root],
        )
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
        if self.debt_domain == 0 || self.collateral.len() > MAX_SPLIT_TENDER_LEGS {
            return Err(LiquidationError::InvalidOraclePrice);
        }
        let mut seen_collateral: BTreeSet<(DomainId, Hash32)> = BTreeSet::new();
        for col in &self.collateral {
            if col.domain_id == 0 || !seen_collateral.insert((col.domain_id, col.asset_id)) {
                return Err(LiquidationError::InvalidOraclePrice);
            }
        }
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

        // Compute provisional seizures in canonical `(domain_id, asset_id)` order
        // so seizure legs and receipt hashes are caller-order-invariant, and failure
        // leaves `position` untouched.
        let mut canonical_order: Vec<usize> = (0..position.collateral.len()).collect();
        canonical_order.sort_by(|&i, &j| {
            let key_i = position
                .collateral
                .get(i)
                .map(|c| (c.domain_id, c.asset_id));
            let key_j = position
                .collateral
                .get(j)
                .map(|c| (c.domain_id, c.asset_id));
            key_i.cmp(&key_j)
        });
        let mut plan: Vec<(usize, SeizedCollateralLeg)> = Vec::new();
        for idx in canonical_order {
            if remaining_seize_usd == 0 {
                break;
            }
            let Some(col) = position.collateral.get(idx) else {
                continue;
            };
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
            let actual_seized_usd = mul_div_floor(take_units, col.price_usd_scaled, RATE_SCALE)
                .ok_or(LiquidationError::ArithmeticOverflow)?;
            if actual_seized_usd == 0 {
                continue;
            }
            plan.push((
                idx,
                SeizedCollateralLeg {
                    domain_id: col.domain_id,
                    asset_id: col.asset_id,
                    amount_seized: take_units,
                    value_usd_scaled: actual_seized_usd,
                },
            ));
            remaining_seize_usd = remaining_seize_usd.saturating_sub(actual_seized_usd);
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

/// Maximum number of domain asset members grouped inside a single
/// [`AssetEquivalenceClass`].
const MAX_EQUIVALENCE_MEMBERS: usize = 64;

/// One domain-native representation participating in a proof-backed
/// [`AssetEquivalenceClass`] (for example, native USDC on Ethereum, Solana, or
/// Cosmos).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEquivalenceMember {
    /// Canonical domain identifier in the settlement registry.
    pub domain_id: DomainId,
    /// Canonical 32-byte domain-namespaced asset identifier (`bridge::AssetId::for_domain`).
    pub asset_id: Hash32,
    /// Human-readable symbol on that domain.
    pub symbol: String,
    /// Effective settlement routing fee in basis points (`<= MAX_SLIPPAGE_BPS`).
    pub fee_bps: u16,
    /// Available liquidity in base units on this domain.
    pub available_liquidity: u128,
    /// Finality or provenance Merkle root attesting that this member is backed
    /// by an admitted external finality proof rather than an unverified claim.
    pub provenance_proof_root: Hash32,
    /// Whether this member's external domain finality proof verified on the
    /// settlement layer.
    pub finality_proven: bool,
}

impl AssetEquivalenceMember {
    #[must_use]
    fn commitment_hash(&self) -> Hash32 {
        hash_domain_fields(
            b"BDLM_ASSET_EQUIV_MEMBER_V1",
            &[
                &self.domain_id.to_le_bytes(),
                &self.asset_id,
                self.symbol.as_bytes(),
                &self.fee_bps.to_le_bytes(),
                &self.available_liquidity.to_le_bytes(),
                &self.provenance_proof_root,
                &[u8::from(self.finality_proven)],
            ],
        )
    }
}

/// Fungible cross-domain equivalence class grouping proof-verified native
/// representations of the same logical asset across multiple chains so the
/// payment router can select the cheapest proven route without minting
/// synthetic wrappers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEquivalenceClass {
    /// Deterministic commitment identifying this equivalence class.
    pub class_id: Hash32,
    /// Logical asset symbol (for example `USDC`).
    pub logical_symbol: String,
    /// Canonical members sorted by `(domain_id, asset_id)`.
    pub members: Vec<AssetEquivalenceMember>,
}

impl AssetEquivalenceClass {
    /// Build a canonical [`AssetEquivalenceClass`] after validating symbol,
    /// capacity bounds, fee caps, and `(domain_id, asset_id)` uniqueness.
    ///
    /// Convenience: constructs verified cross-domain asset equivalence classes
    /// for multi-chain payment routing without synthetic wrappers.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::InvalidIntent`] if `logical_symbol` is invalid,
    /// `members` is empty, a fee exceeds `MAX_SLIPPAGE_BPS`, or duplicate
    /// `(domain_id, asset_id)` members are supplied, or
    /// [`PaymentError::InputLimitExceeded`] if `members.len() > MAX_EQUIVALENCE_MEMBERS`.
    pub fn new(
        logical_symbol: String,
        mut members: Vec<AssetEquivalenceMember>,
    ) -> Result<Self, PaymentError> {
        validate_safe_label("logical_symbol", &logical_symbol, 32)
            .map_err(PaymentError::InvalidIntent)?;
        if members.is_empty() {
            return Err(PaymentError::InvalidIntent(String::from(
                "asset equivalence class must contain at least one member",
            )));
        }
        if members.len() > MAX_EQUIVALENCE_MEMBERS {
            return Err(PaymentError::InputLimitExceeded);
        }

        let mut seen = BTreeSet::new();
        for member in &members {
            validate_safe_label("member.symbol", &member.symbol, 32)
                .map_err(PaymentError::InvalidIntent)?;
            if member.fee_bps > MAX_SLIPPAGE_BPS {
                return Err(PaymentError::InvalidIntent(format!(
                    "member fee {} bps exceeds MAX_SLIPPAGE_BPS ({MAX_SLIPPAGE_BPS})",
                    member.fee_bps
                )));
            }
            if !seen.insert((member.domain_id, member.asset_id)) {
                return Err(PaymentError::InvalidIntent(format!(
                    "duplicate equivalence member for domain {}",
                    member.domain_id
                )));
            }
        }

        members.sort_by_key(|m| (m.domain_id, m.asset_id));
        let member_hashes: Vec<Hash32> = members
            .iter()
            .map(AssetEquivalenceMember::commitment_hash)
            .collect();
        let members_root = unification_merkle_root(b"BDLM_ASSET_EQUIV_CLASS_V1", &member_hashes);
        let class_id = hash_domain_fields(
            b"BDLM_ASSET_EQUIV_CLASS_V1",
            &[logical_symbol.as_bytes(), &members_root],
        );
        Ok(Self {
            class_id,
            logical_symbol,
            members,
        })
    }

    /// Select the cheapest finality-proven member with a non-zero provenance
    /// root and enough liquidity to fill `required_amount`.
    ///
    /// Unproven members (`finality_proven == false`) or members carrying an
    /// all-zero `provenance_proof_root` are ignored fail-closed even if they
    /// advertise a lower fee. Ties break deterministically by `(domain_id, asset_id)`.
    ///
    /// Convenience: routes universal payments to the cheapest cryptographically
    /// proven native asset member in an equivalence class.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::InvalidIntent`] if `required_amount == 0`, or
    /// [`PaymentError::InsufficientMultiDomainLiquidity`] if no proven member
    /// can satisfy `required_amount`.
    pub fn select_cheapest_proven(
        &self,
        required_amount: u128,
    ) -> Result<&AssetEquivalenceMember, PaymentError> {
        if required_amount == 0 {
            return Err(PaymentError::InvalidIntent(String::from(
                "required_amount must be positive",
            )));
        }
        let mut best: Option<&AssetEquivalenceMember> = None;
        let mut max_available = 0u128;

        for member in &self.members {
            if !member.finality_proven || member.provenance_proof_root == [0u8; 32] {
                continue;
            }
            if member.available_liquidity > max_available {
                max_available = member.available_liquidity;
            }
            if member.available_liquidity < required_amount {
                continue;
            }
            let better = match best {
                None => true,
                Some(cur) => {
                    (member.fee_bps, member.domain_id, member.asset_id)
                        < (cur.fee_bps, cur.domain_id, cur.asset_id)
                }
            };
            if better {
                best = Some(member);
            }
        }

        best.ok_or(PaymentError::InsufficientMultiDomainLiquidity {
            shortfall: required_amount.saturating_sub(max_available),
        })
    }
}

/// Derive the unified 32-byte cross-domain asset identifier for `(domain, local_asset)`
/// using the bridge's canonical domain-namespaced rule.
///
/// Convenience: keeps payment router balances and quotes aligned on the exact
/// same 32-byte asset identity used by the bridge, object layer, and UEL.
#[must_use]
pub fn universal_asset_id(domain: DomainId, local_asset: &[u8]) -> Hash32 {
    *crate::cross_domain::bridge::AssetId::for_domain(domain, local_asset).as_bytes()
}

/// Verify supply conservation on a [`UniversalPaymentReceipt`]:
/// 1. The sum of `target_delivered` across all `legs` must equal
///    `receipt.target_amount_delivered` without overflow.
/// 2. `delivered_total_value + total_fees` must equal `source_total_value`
///    without overflow (no unbacked minting or silent value leak).
///
/// Convenience: external and test verifier enforcing strict conservation of
/// value across multi-leg split-tender payment receipts.
///
/// # Errors
///
/// Returns [`PaymentError::ArithmeticOverflow`] on overflow or
/// [`PaymentError::InvalidIntent`] if conservation is violated.
pub fn verify_split_tender_supply_conservation(
    receipt: &UniversalPaymentReceipt,
    source_total_value: u128,
    delivered_total_value: u128,
    total_fees: u128,
) -> Result<(), PaymentError> {
    let legs_delivered = receipt.legs.iter().try_fold(0u128, |acc, leg| {
        acc.checked_add(leg.target_delivered)
            .ok_or(PaymentError::ArithmeticOverflow)
    })?;
    if legs_delivered != receipt.target_amount_delivered {
        return Err(PaymentError::InvalidIntent(format!(
            "split-tender leg sum ({legs_delivered}) disagrees with receipt target_amount_delivered ({})",
            receipt.target_amount_delivered
        )));
    }
    let accounted = delivered_total_value
        .checked_add(total_fees)
        .ok_or(PaymentError::ArithmeticOverflow)?;
    if accounted != source_total_value {
        return Err(PaymentError::InvalidIntent(format!(
            "supply conservation violated: delivered ({delivered_total_value}) + fees ({total_fees}) != source ({source_total_value})"
        )));
    }
    Ok(())
}

/// Three distinct completion levels answering when a payment is "done" and what
/// backs it at that instant:
/// 1. [`Self::Guaranteed`]: included in a Budlum block with escrowed payer funds
///    and sufficient solver bond (~3s).
/// 2. [`Self::Finalized`]: sealed inside a Budlum finality checkpoint (~15s).
/// 3. [`Self::Delivered`]: target-domain delivery proof verified on Budlum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentCompletionLevel {
    Guaranteed = 1,
    Finalized = 2,
    Delivered = 3,
}

/// Block-level guarantee evidence attached once a payment intent enters a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuaranteedPaymentProof {
    pub block_height: u64,
    pub escrow_commitment: Hash32,
    pub solver_bond_commitment: Hash32,
}

/// Checkpoint-level finality evidence attached once Budlum finality seals the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedPaymentProof {
    pub checkpoint_height: u64,
    pub finality_certificate_digest: Hash32,
}

/// Target-domain delivery evidence attached once merchant receipt is proven on Budlum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveredPaymentProof {
    pub target_domain: DomainId,
    pub delivery_proof_root: Hash32,
    pub merchant_receipt_hash: Hash32,
}

/// Three-tier payment status report exposing each completion level separately so
/// terminals and wallets never conflate block inclusion, finality, and delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentStatusReport {
    pub intent_id: Hash32,
    pub guaranteed: Option<GuaranteedPaymentProof>,
    pub finalized: Option<FinalizedPaymentProof>,
    pub delivered: Option<DeliveredPaymentProof>,
}

impl PaymentStatusReport {
    /// Validate strict monotonicity and non-zero commitments across the three
    /// completion tiers (`Delivered` requires `Finalized`, which requires
    /// `Guaranteed`).
    ///
    /// Convenience: validates three-tier payment completion status before
    /// exposing it to wallets, POS terminals, or JSON-RPC consumers.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::InvalidIntent`] if any commitment is all-zero or
    /// a higher tier is claimed without its prerequisite lower tier.
    pub fn validate(&self) -> Result<(), PaymentError> {
        if self.intent_id == [0u8; 32] {
            return Err(PaymentError::InvalidIntent(String::from(
                "payment status intent_id must be non-zero",
            )));
        }
        if let Some(g) = &self.guaranteed {
            if g.block_height == 0
                || g.escrow_commitment == [0u8; 32]
                || g.solver_bond_commitment == [0u8; 32]
            {
                return Err(PaymentError::InvalidIntent(String::from(
                    "guaranteed proof requires non-zero height, escrow, and solver bond commitments",
                )));
            }
        }
        if let Some(f) = &self.finalized {
            let Some(g) = &self.guaranteed else {
                return Err(PaymentError::InvalidIntent(String::from(
                    "finalized status requires prior guaranteed block inclusion proof",
                )));
            };
            if f.checkpoint_height < g.block_height || f.finality_certificate_digest == [0u8; 32] {
                return Err(PaymentError::InvalidIntent(String::from(
                    "finalized proof requires checkpoint_height >= block_height and non-zero certificate digest",
                )));
            }
        }
        if let Some(d) = &self.delivered {
            if self.finalized.is_none() {
                return Err(PaymentError::InvalidIntent(String::from(
                    "delivered status requires prior finalized checkpoint proof",
                )));
            }
            if d.delivery_proof_root == [0u8; 32] || d.merchant_receipt_hash == [0u8; 32] {
                return Err(PaymentError::InvalidIntent(String::from(
                    "delivered proof requires non-zero delivery root and merchant receipt hash",
                )));
            }
        }
        Ok(())
    }

    /// Return the highest verified [`PaymentCompletionLevel`] reached so far.
    ///
    /// Convenience: lets POS terminals and wallets display exact completion tier.
    #[must_use]
    pub fn highest_level(&self) -> Option<PaymentCompletionLevel> {
        if self.delivered.is_some() {
            Some(PaymentCompletionLevel::Delivered)
        } else if self.finalized.is_some() {
            Some(PaymentCompletionLevel::Finalized)
        } else if self.guaranteed.is_some() {
            Some(PaymentCompletionLevel::Guaranteed)
        } else {
            None
        }
    }

    /// Whether this report validates cleanly and satisfies a merchant's required
    /// minimum [`PaymentCompletionLevel`].
    ///
    /// Convenience: enforces merchant risk thresholds per ticket size.
    #[must_use]
    pub fn meets_threshold(&self, required: PaymentCompletionLevel) -> bool {
        if self.validate().is_err() {
            return false;
        }
        self.highest_level().is_some_and(|level| level >= required)
    }
}

/// Domain separation context for PQ-hybrid offline spend vouchers.
pub const OFFLINE_VOUCHER_CTX: &[u8] = b"BDLM_OFFLINE_VOUCHER_V1";

/// Maximum offline vouchers settled in a single batch call.
const MAX_OFFLINE_VOUCHERS_PER_BATCH: usize = 256;

/// Pre-authorized spend account backed by an on-chain escrow cap so an offline
/// POS terminal can verify PQ-hybrid signed vouchers in sub-second latency and
/// settle them in batch when connectivity resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreauthorizedSpendAccount {
    pub account_id: Hash32,
    /// Encoded [`crate::crypto::composite::CompositePublicKey`] of the payer.
    pub payer_composite_pubkey: Vec<u8>,
    pub asset_id: Hash32,
    /// Hard upper bound on cumulative offline spend backed by escrow.
    pub spend_cap_atoms: u128,
    /// Cumulative atoms already settled from previous batches.
    pub spent_atoms: u128,
    /// Account expiry timestamp (Unix seconds).
    pub valid_until_unix_secs: u64,
    /// Nonces already consumed (strict replay guard).
    pub used_nonces: BTreeSet<u64>,
}

/// Offline-verifiable payment voucher signed by the payer's PQ-hybrid composite
/// keypair against a [`PreauthorizedSpendAccount`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOfflineVoucher {
    pub account_id: Hash32,
    pub voucher_nonce: u64,
    pub merchant_id: Hash32,
    pub amount_atoms: u128,
    pub valid_until_unix_secs: u64,
    /// Encoded [`crate::crypto::composite::CompositeSignature`].
    pub signature: Vec<u8>,
}

impl SignedOfflineVoucher {
    /// Deterministic signing payload committing every voucher field.
    ///
    /// Convenience: shared by payer wallets signing vouchers and offline POS
    /// terminals verifying them without network access.
    #[must_use]
    pub fn signing_payload(&self) -> Hash32 {
        hash_domain_fields(
            OFFLINE_VOUCHER_CTX,
            &[
                &self.account_id,
                &self.voucher_nonce.to_le_bytes(),
                &self.merchant_id,
                &self.amount_atoms.to_le_bytes(),
                &self.valid_until_unix_secs.to_le_bytes(),
            ],
        )
    }

    /// Verify this voucher completely offline against `account` at `now_unix_secs`
    /// without mutating state.
    ///
    /// Convenience: enables sub-second offline POS verification using Budlum's
    /// PQ-hybrid composite signature verification.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError`] if the account mismatches, the voucher or account
    /// is expired, the amount is zero or exceeds remaining escrow, the nonce was
    /// already spent, or the PQ-hybrid signature fails verification.
    pub fn verify_offline(
        &self,
        account: &PreauthorizedSpendAccount,
        now_unix_secs: u64,
    ) -> Result<(), PaymentError> {
        if self.account_id != account.account_id {
            return Err(PaymentError::InvalidIntent(String::from(
                "voucher account_id disagrees with pre-authorized spend account",
            )));
        }
        if self.merchant_id == [0u8; 32] {
            return Err(PaymentError::InvalidIntent(String::from(
                "voucher merchant_id must be non-zero",
            )));
        }
        if self.amount_atoms == 0 {
            return Err(PaymentError::InvalidIntent(String::from(
                "voucher amount must be positive",
            )));
        }
        if now_unix_secs > account.valid_until_unix_secs {
            return Err(PaymentError::Expired {
                now: now_unix_secs,
                deadline: account.valid_until_unix_secs,
            });
        }
        if now_unix_secs > self.valid_until_unix_secs {
            return Err(PaymentError::Expired {
                now: now_unix_secs,
                deadline: self.valid_until_unix_secs,
            });
        }
        if account.used_nonces.contains(&self.voucher_nonce) {
            return Err(PaymentError::ReplayDetected);
        }
        let remaining = account.spend_cap_atoms.saturating_sub(account.spent_atoms);
        if self.amount_atoms > remaining {
            return Err(PaymentError::InsufficientMultiDomainLiquidity {
                shortfall: self.amount_atoms.saturating_sub(remaining),
            });
        }

        let pk =
            crate::crypto::composite::CompositePublicKey::decode(&account.payer_composite_pubkey)
                .map_err(|err| {
                PaymentError::InvalidIntent(format!("invalid payer composite public key: {err}"))
            })?;
        let sig = crate::crypto::composite::CompositeSignature::decode(&self.signature).map_err(
            |err| {
                PaymentError::InvalidIntent(format!("invalid voucher composite signature: {err}"))
            },
        )?;
        let digest = self.signing_payload();
        crate::crypto::composite::verify(&pk, OFFLINE_VOUCHER_CTX, &digest, &sig).map_err(
            |err| {
                PaymentError::InvalidIntent(format!(
                    "offline voucher signature verification failed: {err}"
                ))
            },
        )?;
        Ok(())
    }
}

impl PreauthorizedSpendAccount {
    /// Atomically verify and settle a batch of [`SignedOfflineVoucher`] items.
    ///
    /// Rejects duplicate nonces (within the batch or against previously settled
    /// nonces), expired vouchers, invalid signatures, and cumulative spend
    /// exceeding `spend_cap_atoms` without mutating the account on any failure.
    ///
    /// Convenience: settles batched offline POS vouchers in one atomic step.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError`] without mutating `self` if any voucher fails.
    pub fn settle_voucher_batch(
        &mut self,
        vouchers: &[SignedOfflineVoucher],
        now_unix_secs: u64,
    ) -> Result<u128, PaymentError> {
        if vouchers.is_empty() {
            return Err(PaymentError::InvalidIntent(String::from(
                "voucher batch must not be empty",
            )));
        }
        if vouchers.len() > MAX_OFFLINE_VOUCHERS_PER_BATCH {
            return Err(PaymentError::InputLimitExceeded);
        }

        let mut batch_nonces = BTreeSet::new();
        let mut batch_total = 0u128;
        for v in vouchers {
            v.verify_offline(self, now_unix_secs)?;
            if !batch_nonces.insert(v.voucher_nonce) {
                return Err(PaymentError::ReplayDetected);
            }
            batch_total = batch_total
                .checked_add(v.amount_atoms)
                .ok_or(PaymentError::ArithmeticOverflow)?;
        }

        let next_spent = self
            .spent_atoms
            .checked_add(batch_total)
            .ok_or(PaymentError::ArithmeticOverflow)?;
        if next_spent > self.spend_cap_atoms {
            return Err(PaymentError::InsufficientMultiDomainLiquidity {
                shortfall: next_spent.saturating_sub(self.spend_cap_atoms),
            });
        }

        // All checks passed: commit atomically.
        self.spent_atoms = next_spent;
        for nonce in batch_nonces {
            self.used_nonces.insert(nonce);
        }
        Ok(batch_total)
    }
}

/// Versioned, canonically-encoded universal payment request URI/QR standard
/// (`budlum:pay/v1?...`) so POS terminals, websites, and invoices produce
/// byte-for-byte identical encodings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalPaymentRequestUri {
    pub version: u8,
    pub recipient: Hash32,
    pub target_domain: DomainId,
    pub target_asset_id: Hash32,
    pub target_amount: u128,
    pub invoice_digest: Hash32,
    pub deadline_unix_secs: u64,
    pub callback_ref: Option<String>,
}

impl UniversalPaymentRequestUri {
    /// Encode into the canonical `budlum:pay/v1?...` URI string with fixed
    /// parameter order and lowercase hex digests.
    ///
    /// Convenience: produces identical URI/QR bytes across terminals, websites,
    /// and merchant invoices.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::InvalidIntent`] if version != 1, recipient or
    /// asset or amount is zero, or `callback_ref` contains unsafe characters.
    pub fn encode_canonical(&self) -> Result<String, PaymentError> {
        if self.version != 1 {
            return Err(PaymentError::InvalidIntent(format!(
                "unsupported payment request URI version {}",
                self.version
            )));
        }
        if self.recipient == [0u8; 32]
            || self.target_asset_id == [0u8; 32]
            || self.target_amount == 0
        {
            return Err(PaymentError::InvalidIntent(String::from(
                "payment request requires non-zero recipient, asset, and amount",
            )));
        }
        let mut out = format!(
            "budlum:pay/v1?amount={}&asset={}&deadline={}&domain={}&invoice={}&recipient={}",
            self.target_amount,
            hex::encode(self.target_asset_id),
            self.deadline_unix_secs,
            self.target_domain,
            hex::encode(self.invoice_digest),
            hex::encode(self.recipient),
        );
        if let Some(cb) = &self.callback_ref {
            validate_safe_label("callback_ref", cb, 64).map_err(PaymentError::InvalidIntent)?;
            out.push_str("&callback=");
            out.push_str(cb);
        }
        Ok(out)
    }

    /// Parse a canonical `budlum:pay/v1?...` URI string fail-closed.
    ///
    /// Rejects unknown keys, duplicate keys, malformed hex, or missing fields.
    ///
    /// Convenience: decodes terminal/web/invoice payment URIs in wallets.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::InvalidIntent`] on any syntax or semantic violation.
    pub fn decode_canonical(raw: &str) -> Result<Self, PaymentError> {
        let Some(query) = raw.strip_prefix("budlum:pay/v1?") else {
            return Err(PaymentError::InvalidIntent(String::from(
                "payment request URI must start with `budlum:pay/v1?`",
            )));
        };
        if raw.len() > 512 || !raw.is_ascii() {
            return Err(PaymentError::InvalidIntent(String::from(
                "payment request URI exceeds 512 ASCII bytes",
            )));
        }
        let mut kv: BTreeMap<&str, &str> = BTreeMap::new();
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                return Err(PaymentError::InvalidIntent(String::from(
                    "malformed query parameter in payment request URI",
                )));
            };
            if kv.insert(k, v).is_some() {
                return Err(PaymentError::InvalidIntent(format!(
                    "duplicate parameter `{k}` in payment request URI"
                )));
            }
        }

        let parse_h32 = |key: &str| -> Result<Hash32, PaymentError> {
            let val = kv.get(key).ok_or_else(|| {
                PaymentError::InvalidIntent(format!("missing `{key}` in payment request URI"))
            })?;
            let bytes = hex::decode(val).map_err(|_| {
                PaymentError::InvalidIntent(format!(
                    "invalid hex for `{key}` in payment request URI"
                ))
            })?;
            let arr: Hash32 = bytes.try_into().map_err(|_| {
                PaymentError::InvalidIntent(format!(
                    "`{key}` must be 32 bytes in payment request URI"
                ))
            })?;
            Ok(arr)
        };

        for key in kv.keys() {
            if !matches!(
                *key,
                "amount" | "asset" | "callback" | "deadline" | "domain" | "invoice" | "recipient"
            ) {
                return Err(PaymentError::InvalidIntent(format!(
                    "unknown parameter `{key}` in payment request URI"
                )));
            }
        }

        let target_amount = kv
            .get("amount")
            .ok_or_else(|| PaymentError::InvalidIntent(String::from("missing `amount`")))?
            .parse::<u128>()
            .map_err(|_| PaymentError::InvalidIntent(String::from("invalid `amount`")))?;
        let target_domain = kv
            .get("domain")
            .ok_or_else(|| PaymentError::InvalidIntent(String::from("missing `domain`")))?
            .parse::<DomainId>()
            .map_err(|_| PaymentError::InvalidIntent(String::from("invalid `domain`")))?;
        let deadline_unix_secs = kv
            .get("deadline")
            .ok_or_else(|| PaymentError::InvalidIntent(String::from("missing `deadline`")))?
            .parse::<u64>()
            .map_err(|_| PaymentError::InvalidIntent(String::from("invalid `deadline`")))?;
        let recipient = parse_h32("recipient")?;
        let target_asset_id = parse_h32("asset")?;
        let invoice_digest = parse_h32("invoice")?;
        let callback_ref = match kv.get("callback") {
            Some(cb) => {
                validate_safe_label("callback_ref", cb, 64).map_err(PaymentError::InvalidIntent)?;
                Some(String::from(*cb))
            }
            None => None,
        };

        let parsed = Self {
            version: 1,
            recipient,
            target_domain,
            target_asset_id,
            target_amount,
            invoice_digest,
            deadline_unix_secs,
            callback_ref,
        };
        let canonical = parsed.encode_canonical()?;
        if canonical != raw {
            return Err(PaymentError::InvalidIntent(String::from(
                "payment request URI is not in canonical byte order",
            )));
        }
        Ok(parsed)
    }

    /// Deterministic domain-separated digest committing every field of this request.
    ///
    /// Convenience: binds merchant invoices and QR codes to on-chain payment intents.
    #[must_use]
    pub fn request_digest(&self) -> Hash32 {
        let cb = self.callback_ref.as_deref().unwrap_or("");
        hash_domain_fields(
            b"BDLM_PAY_REQUEST_URI_V1",
            &[
                &[self.version],
                &self.recipient,
                &self.target_domain.to_le_bytes(),
                &self.target_asset_id,
                &self.target_amount.to_le_bytes(),
                &self.invoice_digest,
                &self.deadline_unix_secs.to_le_bytes(),
                cb.as_bytes(),
            ],
        )
    }
}

/// Reverse payment intent bound cryptographically to an original
/// [`UniversalPaymentReceipt`] so a merchant refund can never be forged or
/// issued twice for the same settled payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundIntent {
    pub original_intent_id: Hash32,
    pub original_receipt_hash: Hash32,
    pub merchant_id: Hash32,
    pub refund_recipient: Hash32,
    pub refund_amount: u128,
    pub reason_code: u16,
}

impl RefundIntent {
    /// Deterministic identifier committing every refund field.
    ///
    /// Convenience: identifies merchant refund intents for accounting and replay checks.
    #[must_use]
    pub fn refund_id(&self) -> Hash32 {
        hash_domain_fields(
            b"BDLM_REFUND_INTENT_V1",
            &[
                &self.original_intent_id,
                &self.original_receipt_hash,
                &self.merchant_id,
                &self.refund_recipient,
                &self.refund_amount.to_le_bytes(),
                &self.reason_code.to_le_bytes(),
            ],
        )
    }
}

/// Single-use refund tracker ensuring each settled [`UniversalPaymentReceipt`]
/// can be refunded at most once and never above its delivered amount.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundRegistry {
    #[serde(with = "crate::core::map_keys")]
    refunded_receipts: BTreeMap<Hash32, Hash32>,
}

impl RefundRegistry {
    /// Validate and record `refund` against `original` receipt fail-closed.
    ///
    /// Convenience: prevents duplicate or over-amount refunds against settled receipts.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::ReplayDetected`] if `original.receipt_hash` was
    /// already refunded, or [`PaymentError::InvalidIntent`] if bindings or amount
    /// bounds disagree.
    pub fn record_refund(
        &mut self,
        original: &UniversalPaymentReceipt,
        refund: &RefundIntent,
    ) -> Result<Hash32, PaymentError> {
        if refund.original_intent_id != original.intent_id
            || refund.original_receipt_hash != original.receipt_hash
        {
            return Err(PaymentError::InvalidIntent(String::from(
                "refund intent does not match original payment receipt proof",
            )));
        }
        if refund.merchant_id == [0u8; 32] || refund.refund_recipient == [0u8; 32] {
            return Err(PaymentError::InvalidIntent(String::from(
                "refund requires non-zero merchant_id and refund_recipient",
            )));
        }
        if refund.refund_amount == 0 || refund.refund_amount > original.target_amount_delivered {
            return Err(PaymentError::InvalidIntent(format!(
                "refund_amount ({}) must be in 1..={}",
                refund.refund_amount, original.target_amount_delivered
            )));
        }
        if self.refunded_receipts.contains_key(&original.receipt_hash) {
            return Err(PaymentError::ReplayDetected);
        }
        let rid = refund.refund_id();
        self.refunded_receipts.insert(original.receipt_hash, rid);
        Ok(rid)
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

    #[test]
    fn routing_is_order_independent_and_splits_single_balance_across_quotes() {
        let usdc = [0x01; 32];
        let bud = [0x02; 32];
        let sol = [0x03; 32];
        let intent = UniversalPaymentIntent {
            payer_id: [0xA1; 32],
            merchant_id: [0xB2; 32],
            nonce: 42,
            target_domain: 3,
            target_asset_id: usdc,
            target_amount: 100,
            max_slippage_bps: 100,
            deadline_unix_secs: 2_000,
            invoice_hash: [0x77; 32],
            rail: PaymentRail::OnChain,
        };

        // Reversing balance order must pick the exact same lower-fee route first.
        let bal_ab = vec![
            DomainTokenBalance {
                domain_id: 1,
                asset_id: bud,
                symbol: String::from("BUD"),
                available_amount: 100,
            },
            DomainTokenBalance {
                domain_id: 4,
                asset_id: sol,
                symbol: String::from("SOL"),
                available_amount: 100,
            },
        ];
        let mut bal_ba = bal_ab.clone();
        bal_ba.reverse();
        let quotes = vec![
            LiquidityQuote {
                quote_id: [0x10; 32],
                source_domain: 1,
                source_asset_id: bud,
                target_domain: 3,
                target_asset_id: usdc,
                rate_scaled: RATE_SCALE,
                max_target_liquidity: 60,
                fee_bps: 0,
                valid_until_unix_secs: 2_500,
            },
            LiquidityQuote {
                quote_id: [0x11; 32],
                source_domain: 1,
                source_asset_id: bud,
                target_domain: 3,
                target_asset_id: usdc,
                rate_scaled: RATE_SCALE,
                max_target_liquidity: 50,
                fee_bps: 0,
                valid_until_unix_secs: 2_500,
            },
            LiquidityQuote {
                quote_id: [0x20; 32],
                source_domain: 4,
                source_asset_id: sol,
                target_domain: 3,
                target_asset_id: usdc,
                rate_scaled: RATE_SCALE,
                max_target_liquidity: 100,
                fee_bps: 80,
                valid_until_unix_secs: 2_500,
            },
        ];
        let mut quotes_rev = quotes.clone();
        quotes_rev.reverse();

        let r1 = UniversalPaymentRouter::quote_payment(&intent, &bal_ab, &quotes, 1_500).unwrap();
        let r2 =
            UniversalPaymentRouter::quote_payment(&intent, &bal_ba, &quotes_rev, 1_500).unwrap();
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
        assert_eq!(r1.legs, r2.legs);
        // Both legs draw from the 0-bps BUD balance across Q1 (60) + Q2 (40), avoiding 80-bps SOL.
        assert_eq!(r1.legs.len(), 2);
        assert_eq!(r1.legs[0].target_delivered, 60);
        assert_eq!(r1.legs[1].target_delivered, 40);

        let mut settle_bals = bal_ba;
        let mut router = UniversalPaymentRouter::new();
        router
            .settle_payment(&intent, &mut settle_bals, &quotes_rev, 1_500)
            .unwrap();
        assert_eq!(settle_bals[0].available_amount, 100); // SOL untouched
        assert_eq!(settle_bals[1].available_amount, 0); // BUD cumulatively debited 60 + 40 = 100
    }

    #[test]
    fn liquidation_blocks_duplicate_collateral_and_accounts_actual_truncated_seizure() {
        let wbtc = CollateralAsset {
            domain_id: 2,
            asset_id: [0xB7; 32],
            amount: 2,
            price_usd_scaled: 3_500 * RATE_SCALE,
            oracle_updated_unix_secs: 1_000,
            liquidation_threshold_bps: 7_000,
        };
        let dup_pos = CrossDomainPosition {
            position_id: [0xE1; 32],
            debt_domain: 3,
            debt_asset_id: [0x01; 32],
            debt_amount: 10_000,
            debt_price_usd_scaled: RATE_SCALE,
            debt_oracle_updated_unix_secs: 1_000,
            collateral: vec![wbtc.clone(), wbtc.clone()],
        };
        assert_eq!(
            dup_pos.health_factor_bps(1_010),
            Err(LiquidationError::InvalidOraclePrice)
        );

        // High-unit-price collateral truncates 5_000 USD -> 1 WBTC (3_500 USD); remaining
        // 1_500 USD MUST carry over to USDC collateral rather than vanishing into bad debt.
        let mut pos = CrossDomainPosition {
            position_id: [0xE2; 32],
            debt_domain: 3,
            debt_asset_id: [0x01; 32],
            debt_amount: 10_000,
            debt_price_usd_scaled: RATE_SCALE,
            debt_oracle_updated_unix_secs: 1_000,
            collateral: vec![
                wbtc,
                CollateralAsset {
                    domain_id: 4,
                    asset_id: [0xCC; 32],
                    amount: 2_000,
                    price_usd_scaled: RATE_SCALE,
                    oracle_updated_unix_secs: 1_000,
                    liquidation_threshold_bps: 8_000,
                },
            ],
        };
        let receipt =
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos, 5_000, 0, 1_010)
                .unwrap();
        assert_eq!(receipt.seized_legs.len(), 2);
        assert_eq!(receipt.seized_legs[0].amount_seized, 1);
        assert_eq!(receipt.seized_legs[0].value_usd_scaled, 3_500);
        assert_eq!(receipt.seized_legs[1].amount_seized, 1_500);
        assert_eq!(receipt.seized_legs[1].value_usd_scaled, 1_500);
        assert_eq!(pos.collateral[0].amount, 1);
        assert_eq!(pos.collateral[1].amount, 500);
    }

    #[test]
    fn settle_payment_tracks_quote_liquidity_across_intents_and_liquidation_is_order_invariant() {
        let usdc_eth = [0x01; 32];
        let bud_asset = [0x02; 32];
        let quote = LiquidityQuote {
            quote_id: [0x77; 32],
            source_domain: 1,
            source_asset_id: bud_asset,
            target_domain: 3,
            target_asset_id: usdc_eth,
            rate_scaled: RATE_SCALE,
            fee_bps: 0,
            max_target_liquidity: 100,
            valid_until_unix_secs: 2_000,
        };
        let mut balances = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: bud_asset,
            symbol: "BUD".into(),
            available_amount: 500,
        }];
        let make_intent = |nonce: u64| UniversalPaymentIntent {
            payer_id: [0xA1; 32],
            merchant_id: [0xB2; 32],
            nonce,
            target_domain: 3,
            target_asset_id: usdc_eth,
            target_amount: 80,
            max_slippage_bps: 50,
            deadline_unix_secs: 2_000,
            invoice_hash: [u8::try_from(nonce).unwrap_or(0); 32],
            rail: PaymentRail::OnChain,
        };
        let mut router = UniversalPaymentRouter::new();
        router
            .settle_payment(
                &make_intent(1),
                &mut balances,
                std::slice::from_ref(&quote),
                1_500,
            )
            .expect("first intent consumes 80/100 quote liquidity");
        let second = router.settle_payment(
            &make_intent(2),
            &mut balances,
            std::slice::from_ref(&quote),
            1_500,
        );
        assert_eq!(
            second,
            Err(PaymentError::InsufficientMultiDomainLiquidity { shortfall: 60 }),
            "quote with 20 remaining liquidity must not settle a second 80-unit intent"
        );
        // Failed second intent must leave balances untouched at 420.
        assert_eq!(balances[0].available_amount, 420);

        // Liquidation seizure order and receipt_hash must be independent of collateral Vec order.
        let c_a = CollateralAsset {
            domain_id: 2,
            asset_id: [0x10; 32],
            amount: 4_000,
            price_usd_scaled: RATE_SCALE,
            oracle_updated_unix_secs: 1_000,
            liquidation_threshold_bps: 8_000,
        };
        let c_b = CollateralAsset {
            domain_id: 5,
            asset_id: [0x20; 32],
            amount: 4_000,
            price_usd_scaled: RATE_SCALE,
            oracle_updated_unix_secs: 1_000,
            liquidation_threshold_bps: 8_000,
        };
        let mut pos_ab = CrossDomainPosition {
            position_id: [0xF1; 32],
            debt_domain: 3,
            debt_asset_id: usdc_eth,
            debt_amount: 10_000,
            debt_price_usd_scaled: RATE_SCALE,
            debt_oracle_updated_unix_secs: 1_000,
            collateral: vec![c_a.clone(), c_b.clone()],
        };
        let mut pos_ba = CrossDomainPosition {
            collateral: vec![c_b, c_a],
            ..pos_ab.clone()
        };
        let r_ab =
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos_ab, 3_000, 0, 1_010)
                .unwrap();
        let r_ba =
            UniversalLiquidationCoordinator::execute_liquidation(&mut pos_ba, 3_000, 0, 1_010)
                .unwrap();
        assert_eq!(r_ab.receipt_hash, r_ba.receipt_hash);
        assert_eq!(r_ab.seized_legs, r_ba.seized_legs);
    }

    #[test]
    fn settle_payment_enforces_non_tautological_split_tender_conservation() {
        let bud_asset = [0x01; 32];
        let usdc_asset = [0x02; 32];
        let mut balances = vec![
            DomainTokenBalance {
                domain_id: 1,
                asset_id: bud_asset,
                symbol: String::from("BUD"),
                available_amount: 600,
            },
            DomainTokenBalance {
                domain_id: 3,
                asset_id: usdc_asset,
                symbol: String::from("USDC"),
                available_amount: 1_000,
            },
        ];
        let quotes = vec![LiquidityQuote {
            quote_id: [0x91; 32],
            source_domain: 3,
            source_asset_id: usdc_asset,
            target_domain: 1,
            target_asset_id: bud_asset,
            rate_scaled: RATE_SCALE,
            fee_bps: 100, // 1%
            max_target_liquidity: 1_000,
            valid_until_unix_secs: 2_000,
        }];
        let intent = UniversalPaymentIntent {
            payer_id: [0xA1; 32],
            merchant_id: [0xB2; 32],
            target_domain: 1,
            target_asset_id: bud_asset,
            target_amount: 1_000,
            max_slippage_bps: 200,
            rail: PaymentRail::OnChain,
            invoice_hash: [0xC3; 32],
            deadline_unix_secs: 2_000,
            nonce: 77,
        };
        let mut router = UniversalPaymentRouter::new();
        let receipt = router
            .settle_payment(&intent, &mut balances, &quotes, 1_500)
            .expect("valid split-tender payment must pass supply conservation");
        assert_eq!(receipt.target_amount_delivered, 1_000);

        // Tampered receipt where leg sum diverges from delivered amount fails closed.
        let mut bad_receipt = receipt.clone();
        bad_receipt.target_amount_delivered = 1_001;
        assert!(verify_split_tender_supply_conservation(&bad_receipt, 1_005, 1_001, 4).is_err());

        // Conservation violation where delivered + fees != source_total_value fails closed.
        assert!(verify_split_tender_supply_conservation(&receipt, 1_005, 1_000, 3).is_err());
    }
}
