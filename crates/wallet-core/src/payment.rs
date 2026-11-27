//! Universal payment intents, liquidity quote verification, deterministic
//! payment receipts, remote/foreign account address derivation, and
//! light-client proof-backed unified balances for wallets.
//!
//! exposed for: the wallet crate's SDK surface - browser and mobile hosts call these directly.
//!
//! Every hash tag, field framing, and ceiling arithmetic helper in this module
//! matches the node's unification router (`src/unification/payment_router.rs`),
//! account alias derivation (`src/execution/coordinator/alias.rs`), and remote
//! state view (`src/light_client/mod.rs`) byte-for-byte.
//!
//! Trust boundary: balance proofs are NEVER verified against a caller-supplied
//! `(root, epoch)` pair; all roots are read from a trusted [`BalanceHeaderSource`]
//! with strict tip-lag enforcement so a lying RPC node cannot invent a root
//! along with a forged balance.

use crate::{PublicKeyBytes, SignatureBytes, Wallet};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;
use std::collections::{BTreeMap, BTreeSet};

/// Fixed-point basis-points denominator (`10_000` bps = 100%).
pub const BPS_DENOM: u128 = 10_000;
/// Fixed-point quote rate scale (`10^18` target base units per source base unit).
pub const RATE_SCALE: u128 = 1_000_000_000_000_000_000;
/// Hard slippage ceiling (`1_000` bps = 10%), matching the node payment router.
pub const MAX_SLIPPAGE_BPS: u16 = 1_000;
/// Maximum split-tender legs allowed in one payment receipt.
pub const MAX_SPLIT_TENDER_LEGS: usize = 16;
/// Maximum Merkle path depth accepted for balance inclusion proofs.
pub const MAX_BALANCE_PROOF_DEPTH: usize = 64;
/// Maximum block lag allowed between a balance proof header and the wallet's tip.
pub const MAX_BALANCE_PROOF_LAG_BLOCKS: u64 = 5;
/// Maximum canonical `budlum:pay/v1?...` URI length in ASCII bytes.
pub const MAX_PAYMENT_URI_BYTES: usize = 512;

/// Domain-separated SHA3-256 hash over length-prefixed byte slices.
///
/// Exact byte-for-byte parity with `src/unification/mod.rs::hash_domain_fields`.
#[must_use]
fn hash_domain_fields(domain_tag: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(
        u64::try_from(domain_tag.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain_tag);
    hasher.update(
        u64::try_from(fields.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// SHA-256 over length-prefixed slices, matching `src/core/hash.rs::hash_fields_bytes`.
#[must_use]
fn sha256_fields(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

#[must_use]
fn merkle_leaf_hash(domain_tag: &[u8], index: usize, leaf: &[u8; 32]) -> [u8; 32] {
    let idx_bytes = u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes();
    hash_domain_fields(domain_tag, &[&[0x00], &idx_bytes, leaf])
}

#[must_use]
fn merkle_node_hash(domain_tag: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_domain_fields(domain_tag, &[&[0x01], left, right])
}

#[must_use]
fn merkle_odd_hash(domain_tag: &[u8], lone: &[u8; 32]) -> [u8; 32] {
    hash_domain_fields(domain_tag, &[&[0x02], lone])
}

#[must_use]
fn merkle_root_envelope(domain_tag: &[u8], leaf_count: usize, tree_root: &[u8; 32]) -> [u8; 32] {
    let count_bytes = u64::try_from(leaf_count).unwrap_or(u64::MAX).to_le_bytes();
    hash_domain_fields(domain_tag, &[&[0x03], &count_bytes, tree_root])
}

/// Binary Merkle root matching `src/unification/mod.rs::unification_merkle_root`.
#[must_use]
fn unification_merkle_root(domain_tag: &[u8], leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return hash_domain_fields(domain_tag, &[b"EMPTY"]);
    }
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| merkle_leaf_hash(domain_tag, i, leaf))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(merkle_node_hash(domain_tag, left, right)),
                [lone] => next.push(merkle_odd_hash(domain_tag, lone)),
                _ => {}
            }
        }
        level = next;
    }
    let tree_root = level
        .first()
        .copied()
        .unwrap_or_else(|| hash_domain_fields(domain_tag, &[b"EMPTY"]));
    merkle_root_envelope(domain_tag, leaves.len(), &tree_root)
}

#[must_use]
fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let mid1 = (p0 >> 64) + (p1 & 0xFFFF_FFFF_FFFF_FFFF) + (p2 & 0xFFFF_FFFF_FFFF_FFFF);
    let lo = (p0 & 0xFFFF_FFFF_FFFF_FFFF) | (mid1 << 64);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid1 >> 64);
    (hi, lo)
}

#[must_use]
fn div_u256_by_u128(hi: u128, lo: u128, denom: u128) -> Option<(u128, u128)> {
    if denom == 0 || hi >= denom {
        return None;
    }
    let mut rem = hi;
    let mut quot = 0u128;
    for bit in (0..128).rev() {
        let carry = rem >> 127;
        rem = (rem << 1) | ((lo >> bit) & 1);
        quot <<= 1;
        if carry != 0 || rem >= denom {
            rem = rem.wrapping_sub(denom);
            quot |= 1;
        }
    }
    Some((quot, rem))
}

/// Computes `ceil(a * b / denom)` without intermediate `u128` overflow.
#[must_use]
pub fn mul_div_ceil(a: u128, b: u128, denom: u128) -> Option<u128> {
    let (hi, lo) = mul_u128_wide(a, b);
    let (q, r) = div_u256_by_u128(hi, lo, denom)?;
    if r == 0 {
        Some(q)
    } else {
        q.checked_add(1)
    }
}

fn validate_safe_label(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max_len {
        return Err(format!("{field} length must be within 1..={max_len}"));
    }
    if value.contains("..")
        || value.contains('\\')
        || value.bytes().any(|b| b == 0 || b.is_ascii_control())
    {
        return Err(format!("{field} contains forbidden characters"));
    }
    Ok(())
}

fn validate_iso_currency(code: &str) -> Result<(), String> {
    if code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err("iso_currency_code must be a 3-letter uppercase ISO-4217 code".into())
    }
}

// ---------------------------------------------------------------------------
// 1. Canonical Payment Request URI (`budlum:pay/v1?...`)
// ---------------------------------------------------------------------------

/// Canonical payment request URI parsed from QR codes, links, or POS terminals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequestUri {
    pub version: u8,
    pub recipient: [u8; 32],
    pub target_domain: u64,
    pub target_asset_id: [u8; 32],
    pub target_amount: u128,
    pub invoice_digest: [u8; 32],
    pub deadline_unix_secs: u64,
    pub callback_ref: Option<String>,
}

impl PaymentRequestUri {
    /// Encode into canonical `budlum:pay/v1?...` form matching the node router.
    ///
    /// # Errors
    ///
    /// Refuses unsupported versions, zero recipient/domain/asset/amount, or unsafe callbacks.
    pub fn encode_canonical(&self) -> Result<String, String> {
        if self.version != 1 {
            return Err(format!(
                "unsupported payment request URI version {}",
                self.version
            ));
        }
        if self.target_domain == 0 {
            return Err("payment request requires non-zero target_domain".into());
        }
        if self.recipient == [0u8; 32]
            || self.target_asset_id == [0u8; 32]
            || self.target_amount == 0
        {
            return Err("payment request requires non-zero recipient, asset, and amount".into());
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
            validate_safe_label("callback_ref", cb, 64)?;
            out.push_str("&callback=");
            out.push_str(cb);
        }
        if out.len() > MAX_PAYMENT_URI_BYTES {
            return Err("payment request URI exceeds 512 ASCII bytes".into());
        }
        Ok(out)
    }

    /// Decode a canonical `budlum:pay/v1?...` URI fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses non-canonical byte order, duplicate/unknown/missing keys, invalid hex,
    /// zero identifiers, or oversized/non-ASCII input.
    pub fn decode_canonical(raw: &str) -> Result<Self, String> {
        let Some(query) = raw.strip_prefix("budlum:pay/v1?") else {
            return Err("payment request URI must start with `budlum:pay/v1?`".into());
        };
        if raw.len() > MAX_PAYMENT_URI_BYTES || !raw.is_ascii() {
            return Err("payment request URI exceeds 512 ASCII bytes".into());
        }
        let mut kv: BTreeMap<&str, &str> = BTreeMap::new();
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                return Err("malformed query parameter in payment request URI".into());
            };
            if kv.insert(k, v).is_some() {
                return Err(format!("duplicate parameter `{k}` in payment request URI"));
            }
        }
        for key in kv.keys() {
            if !matches!(
                *key,
                "amount" | "asset" | "callback" | "deadline" | "domain" | "invoice" | "recipient"
            ) {
                return Err(format!("unknown parameter `{key}` in payment request URI"));
            }
        }
        let parse_h32 = |key: &str| -> Result<[u8; 32], String> {
            let val = kv
                .get(key)
                .ok_or_else(|| format!("missing `{key}` in payment request URI"))?;
            let bytes = hex::decode(val)
                .map_err(|_| format!("invalid hex for `{key}` in payment request URI"))?;
            bytes
                .try_into()
                .map_err(|_| format!("`{key}` must be 32 bytes in payment request URI"))
        };
        let target_amount = kv
            .get("amount")
            .ok_or_else(|| "missing `amount`".to_string())?
            .parse::<u128>()
            .map_err(|_| "invalid `amount`".to_string())?;
        let target_domain = kv
            .get("domain")
            .ok_or_else(|| "missing `domain`".to_string())?
            .parse::<u64>()
            .map_err(|_| "invalid `domain`".to_string())?;
        let deadline_unix_secs = kv
            .get("deadline")
            .ok_or_else(|| "missing `deadline`".to_string())?
            .parse::<u64>()
            .map_err(|_| "invalid `deadline`".to_string())?;
        let recipient = parse_h32("recipient")?;
        let target_asset_id = parse_h32("asset")?;
        let invoice_digest = parse_h32("invoice")?;
        let callback_ref = match kv.get("callback") {
            Some(cb) => {
                validate_safe_label("callback_ref", cb, 64)?;
                Some((*cb).to_string())
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
            return Err("payment request URI is not in canonical byte order".into());
        }
        Ok(parsed)
    }

    /// Convert this decoded URI into a [`WalletPaymentIntent`] for `payer_id`.
    #[must_use]
    pub fn to_payment_intent(
        &self,
        payer_id: [u8; 32],
        nonce: u64,
        max_slippage_bps: u16,
        rail: PaymentRail,
    ) -> WalletPaymentIntent {
        WalletPaymentIntent {
            payer_id,
            merchant_id: self.recipient,
            nonce,
            target_domain: self.target_domain,
            target_asset_id: self.target_asset_id,
            target_amount: self.target_amount,
            max_slippage_bps,
            deadline_unix_secs: self.deadline_unix_secs,
            invoice_hash: self.invoice_digest,
            rail,
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Payment Intent Construction & ML-DSA-87 Signing
// ---------------------------------------------------------------------------

/// Settlement rail attached to a [`WalletPaymentIntent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentRail {
    OnChain,
    PosTerminal {
        terminal_id: String,
        merchant_code: String,
        iso_currency_code: String,
    },
    CardNetwork {
        network: String,
        auth_reference: String,
        iso_currency_code: String,
    },
}

impl PaymentRail {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::OnChain => Ok(()),
            Self::PosTerminal {
                terminal_id,
                merchant_code,
                iso_currency_code,
            } => {
                validate_safe_label("terminal_id", terminal_id, 48)?;
                validate_safe_label("merchant_code", merchant_code, 32)?;
                validate_iso_currency(iso_currency_code)
            }
            Self::CardNetwork {
                network,
                auth_reference,
                iso_currency_code,
            } => {
                validate_safe_label("network", network, 32)?;
                validate_safe_label("auth_reference", auth_reference, 64)?;
                validate_iso_currency(iso_currency_code)
            }
        }
    }

    #[must_use]
    fn commitment_hash(&self) -> [u8; 32] {
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

/// Wallet-side universal payment intent matching `UniversalPaymentIntent` on the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPaymentIntent {
    pub payer_id: [u8; 32],
    pub merchant_id: [u8; 32],
    pub nonce: u64,
    pub target_domain: u64,
    pub target_asset_id: [u8; 32],
    pub target_amount: u128,
    pub max_slippage_bps: u16,
    pub deadline_unix_secs: u64,
    pub invoice_hash: [u8; 32],
    pub rail: PaymentRail,
}

impl WalletPaymentIntent {
    /// Canonical replay-protection digest matching `UniversalPaymentIntent::intent_id`.
    #[must_use]
    pub fn intent_id(&self) -> [u8; 32] {
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

    /// Chain-bound signing digest preventing cross-chain / testnet-to-mainnet replay.
    #[must_use]
    pub fn signing_digest(&self, chain_id: u64) -> [u8; 32] {
        let chain_bytes = chain_id.to_le_bytes();
        let id = self.intent_id();
        hash_domain_fields(b"BDLM_WALLET_PAYMENT_INTENT_SIG_V1", &[&chain_bytes, &id])
    }

    /// Validate all intent invariants fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses zero payer/merchant/domain/asset/amount, excessive slippage, expiry, or bad rails.
    pub fn validate(&self, now_unix_secs: u64) -> Result<(), String> {
        if self.payer_id == [0u8; 32] {
            return Err("payer_id must be non-zero".into());
        }
        if self.merchant_id == [0u8; 32] {
            return Err("merchant_id must be non-zero".into());
        }
        if self.target_domain == 0 {
            return Err("target_domain must be non-zero".into());
        }
        if self.target_asset_id == [0u8; 32] {
            return Err("target_asset_id must be non-zero".into());
        }
        if self.target_amount == 0 {
            return Err("target_amount must be non-zero".into());
        }
        if self.max_slippage_bps > MAX_SLIPPAGE_BPS {
            return Err(format!("max_slippage_bps cannot exceed {MAX_SLIPPAGE_BPS}"));
        }
        if now_unix_secs > self.deadline_unix_secs {
            return Err(format!(
                "payment intent expired (now={now_unix_secs}, deadline={})",
                self.deadline_unix_secs
            ));
        }
        self.rail.validate()
    }
}

/// ML-DSA-87 signed payment intent bound to `chain_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPaymentIntent {
    pub intent: WalletPaymentIntent,
    pub chain_id: u64,
    pub intent_id: [u8; 32],
    pub signature: SignatureBytes,
}

impl SignedPaymentIntent {
    /// Sign `intent` with `wallet`'s ML-DSA-87 key under `CROSS_DOMAIN_V1`.
    ///
    /// # Errors
    ///
    /// Refuses zero `chain_id`, payer mismatch, or invalid/expired intent.
    pub fn sign_with_wallet(
        wallet: &Wallet,
        intent: &WalletPaymentIntent,
        chain_id: u64,
        now_unix_secs: u64,
    ) -> Result<Self, String> {
        if chain_id == 0 {
            return Err("chain_id must be non-zero".into());
        }
        intent.validate(now_unix_secs)?;
        if intent.payer_id != wallet.address() {
            return Err("intent payer_id does not match signing wallet address".into());
        }
        let digest = intent.signing_digest(chain_id);
        let signature = wallet.sign_for(crate::crypto::ctx::CROSS_DOMAIN_V1, &digest);
        Ok(Self {
            intent: intent.clone(),
            chain_id,
            intent_id: intent.intent_id(),
            signature,
        })
    }

    /// Verify payer binding, chain ID, freshness, intent digest, and ML-DSA-87 signature.
    ///
    /// # Errors
    ///
    /// Refuses any mismatch, expiry, replay across chains, or invalid signature.
    pub fn verify(
        &self,
        public_key: &PublicKeyBytes,
        expected_chain_id: u64,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        if expected_chain_id == 0 || self.chain_id != expected_chain_id {
            return Err("signed payment intent chain_id mismatch".into());
        }
        self.intent.validate(now_unix_secs)?;
        let derived_payer = Wallet::address_from_public_key(public_key);
        if derived_payer != self.intent.payer_id {
            return Err("public key does not match intent payer_id".into());
        }
        let expected_id = self.intent.intent_id();
        if self.intent_id != expected_id {
            return Err("signed payment intent_id does not match intent fields".into());
        }
        let digest = self.intent.signing_digest(expected_chain_id);
        if !Wallet::verify_for(
            public_key,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &digest,
            &self.signature,
        ) {
            return Err("invalid ML-DSA-87 signature on payment intent".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 3. Liquidity Quote Verification
// ---------------------------------------------------------------------------

/// Solver liquidity quote converting a source asset into the merchant's target asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletLiquidityQuote {
    pub quote_id: [u8; 32],
    pub source_domain: u64,
    pub source_asset_id: [u8; 32],
    pub target_domain: u64,
    pub target_asset_id: [u8; 32],
    pub rate_scaled: u128,
    pub max_target_liquidity: u128,
    pub fee_bps: u16,
    pub valid_until_unix_secs: u64,
}

impl WalletLiquidityQuote {
    /// Canonical quote digest binding every field and `chain_id`.
    #[must_use]
    pub fn signing_digest(&self, chain_id: u64) -> [u8; 32] {
        let chain_bytes = chain_id.to_le_bytes();
        let src_dom = self.source_domain.to_le_bytes();
        let dst_dom = self.target_domain.to_le_bytes();
        let rate = self.rate_scaled.to_le_bytes();
        let cap = self.max_target_liquidity.to_le_bytes();
        let fee = self.fee_bps.to_le_bytes();
        let valid = self.valid_until_unix_secs.to_le_bytes();
        hash_domain_fields(
            b"BDLM_SOLVER_QUOTE_V1",
            &[
                &chain_bytes,
                &self.quote_id,
                &src_dom,
                &self.source_asset_id,
                &dst_dom,
                &self.target_asset_id,
                &rate,
                &cap,
                &fee,
                &valid,
            ],
        )
    }
}

/// Verified quote evaluation result computed with ceiling integer arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedQuoteEvaluation {
    pub quote_id: [u8; 32],
    pub required_source_amount: u128,
    pub target_delivered: u128,
    pub fee_bps: u16,
}

/// Validate a solver quote against `intent` and compute exact required source units
/// using ceiling integer math (`mul_div_ceil`) so rounding-to-zero exploits are impossible.
///
/// # Errors
///
/// Refuses expired quotes, mismatched target domain/asset, excessive fees, zero rates,
/// insufficient liquidity, or arithmetic overflow.
pub fn verify_payment_quote(
    intent: &WalletPaymentIntent,
    quote: &WalletLiquidityQuote,
    requested_target_amount: u128,
    now_unix_secs: u64,
) -> Result<VerifiedQuoteEvaluation, String> {
    intent.validate(now_unix_secs)?;
    if requested_target_amount == 0 || requested_target_amount > intent.target_amount {
        return Err("requested_target_amount must be within 1..=intent.target_amount".into());
    }
    if quote.quote_id == [0u8; 32] {
        return Err("quote_id must be non-zero".into());
    }
    if quote.source_domain == 0 || quote.source_asset_id == [0u8; 32] {
        return Err("quote source_domain and source_asset_id must be non-zero".into());
    }
    if quote.target_domain != intent.target_domain
        || quote.target_asset_id != intent.target_asset_id
    {
        return Err("quote target does not match payment intent".into());
    }
    if quote.rate_scaled == 0 {
        return Err("quote rate_scaled must be non-zero".into());
    }
    if quote.fee_bps > MAX_SLIPPAGE_BPS || quote.fee_bps > intent.max_slippage_bps {
        return Err("quote fee_bps exceeds allowed slippage ceiling".into());
    }
    if now_unix_secs > quote.valid_until_unix_secs {
        return Err("quote has expired".into());
    }
    if requested_target_amount > quote.max_target_liquidity {
        return Err("requested target amount exceeds quote liquidity".into());
    }
    let base_source = mul_div_ceil(requested_target_amount, RATE_SCALE, quote.rate_scaled)
        .ok_or_else(|| "arithmetic overflow computing base source amount".to_string())?;
    let fee_factor = BPS_DENOM
        .checked_add(u128::from(quote.fee_bps))
        .ok_or_else(|| "arithmetic overflow computing fee factor".to_string())?;
    let required_source_amount = mul_div_ceil(base_source, fee_factor, BPS_DENOM)
        .ok_or_else(|| "arithmetic overflow applying quote fee".to_string())?;
    if required_source_amount == 0 {
        return Err("computed required source amount cannot be zero".into());
    }
    Ok(VerifiedQuoteEvaluation {
        quote_id: quote.quote_id,
        required_source_amount,
        target_delivered: requested_target_amount,
        fee_bps: quote.fee_bps,
    })
}

/// Solver-signed binding liquidity quote verified with ML-DSA-87.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedLiquidityQuote {
    pub quote: WalletLiquidityQuote,
    pub chain_id: u64,
    pub solver_address: [u8; 32],
    pub signature: SignatureBytes,
}

impl SignedLiquidityQuote {
    /// Sign `quote` with `solver_wallet`'s ML-DSA-87 key.
    ///
    /// # Errors
    ///
    /// Refuses zero `chain_id`, zero `quote_id`, zero `rate_scaled`, or excessive `fee_bps`.
    pub fn sign_with_wallet(
        solver_wallet: &Wallet,
        quote: &WalletLiquidityQuote,
        chain_id: u64,
    ) -> Result<Self, String> {
        if chain_id == 0 {
            return Err("chain_id must be non-zero".into());
        }
        if quote.quote_id == [0u8; 32] || quote.rate_scaled == 0 || quote.fee_bps > MAX_SLIPPAGE_BPS
        {
            return Err("cannot sign malformed liquidity quote".into());
        }
        let digest = quote.signing_digest(chain_id);
        let signature = solver_wallet.sign_for(crate::crypto::ctx::CROSS_DOMAIN_V1, &digest);
        Ok(Self {
            quote: quote.clone(),
            chain_id,
            solver_address: solver_wallet.address(),
            signature,
        })
    }

    /// Verify chain ID, expiry, solver address binding, and ML-DSA-87 signature.
    ///
    /// # Errors
    ///
    /// Refuses mismatched chain/solver, expired quote, or invalid signature.
    pub fn verify(
        &self,
        solver_public_key: &PublicKeyBytes,
        expected_chain_id: u64,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        if expected_chain_id == 0 || self.chain_id != expected_chain_id {
            return Err("signed quote chain_id mismatch".into());
        }
        if now_unix_secs > self.quote.valid_until_unix_secs {
            return Err("signed quote has expired".into());
        }
        let derived = Wallet::address_from_public_key(solver_public_key);
        if derived != self.solver_address {
            return Err("solver public key does not match solver_address".into());
        }
        let digest = self.quote.signing_digest(expected_chain_id);
        if !Wallet::verify_for(
            solver_public_key,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &digest,
            &self.signature,
        ) {
            return Err("invalid ML-DSA-87 signature on liquidity quote".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 4. Deterministic Payment Receipt & Three-Tier Completion Summary
// ---------------------------------------------------------------------------

/// One executed leg inside a split-tender universal payment receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSplitLeg {
    pub source_domain: u64,
    pub source_asset_id: [u8; 32],
    pub source_symbol: String,
    pub source_debited: u128,
    pub target_delivered: u128,
    pub fee_bps: u16,
    pub direct_same_domain: bool,
    pub quote_id: Option<[u8; 32]>,
}

impl WalletSplitLeg {
    /// Commitment hash matching `SplitTenderLeg::commitment_hash` (`BDLM_SPLIT_LEG_V1`).
    #[must_use]
    pub fn commitment_hash(&self) -> [u8; 32] {
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

/// Deterministic payment receipt matching `UniversalPaymentReceipt` on the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPaymentReceipt {
    pub intent_id: [u8; 32],
    pub target_domain: u64,
    pub target_asset_id: [u8; 32],
    pub target_amount_delivered: u128,
    pub legs: Vec<WalletSplitLeg>,
    pub legs_merkle_root: [u8; 32],
    pub pos_auth_code: Option<String>,
    pub receipt_hash: [u8; 32],
}

/// Build a canonical [`WalletPaymentReceipt`] from `intent` and its executed `legs`.
///
/// # Errors
///
/// Refuses empty/oversized leg lists, zero-value legs, slippage breaches, or sum mismatches.
pub fn build_payment_receipt(
    intent: &WalletPaymentIntent,
    legs: Vec<WalletSplitLeg>,
) -> Result<WalletPaymentReceipt, String> {
    if legs.is_empty() || legs.len() > MAX_SPLIT_TENDER_LEGS {
        return Err("receipt must contain 1..=16 split-tender legs".into());
    }
    let mut delivered_sum = 0u128;
    for leg in &legs {
        if leg.source_domain == 0
            || leg.source_asset_id == [0u8; 32]
            || leg.source_debited == 0
            || leg.target_delivered == 0
        {
            return Err(
                "each split-tender leg must have non-zero domain, asset, and amounts".into(),
            );
        }
        if leg.fee_bps > MAX_SLIPPAGE_BPS || leg.fee_bps > intent.max_slippage_bps {
            return Err("split-tender leg fee exceeds intent slippage ceiling".into());
        }
        validate_safe_label("source_symbol", &leg.source_symbol, 16)?;
        delivered_sum = delivered_sum
            .checked_add(leg.target_delivered)
            .ok_or_else(|| "overflow summing leg target_delivered amounts".to_string())?;
    }
    if delivered_sum != intent.target_amount {
        return Err(
            "sum of split-tender leg deliveries does not equal intent.target_amount".into(),
        );
    }
    let intent_id = intent.intent_id();
    let leg_hashes: Vec<[u8; 32]> = legs.iter().map(WalletSplitLeg::commitment_hash).collect();
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
    Ok(WalletPaymentReceipt {
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

impl WalletPaymentReceipt {
    /// Recompute and verify every cryptographic commitment in this receipt against `intent`.
    ///
    /// # Errors
    ///
    /// Refuses tampered fields, mismatched intent/domain/asset/amount, forged leg roots,
    /// wrong POS auth code, or forged `receipt_hash`.
    pub fn verify(&self, intent: &WalletPaymentIntent) -> Result<(), String> {
        let recomputed = build_payment_receipt(intent, self.legs.clone())?;
        if self.intent_id != recomputed.intent_id
            || self.target_domain != recomputed.target_domain
            || self.target_asset_id != recomputed.target_asset_id
            || self.target_amount_delivered != recomputed.target_amount_delivered
            || self.legs_merkle_root != recomputed.legs_merkle_root
            || self.pos_auth_code != recomputed.pos_auth_code
            || self.receipt_hash != recomputed.receipt_hash
        {
            return Err("payment receipt commitment verification failed".into());
        }
        Ok(())
    }
}

/// Three distinct payment completion tiers matching `PaymentCompletionLevel` on the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PaymentCompletionLevel {
    Guaranteed = 1,
    Finalized = 2,
    Delivered = 3,
}

/// Block-level guarantee proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuaranteedPaymentProof {
    pub block_height: u64,
    pub escrow_commitment: [u8; 32],
    pub solver_bond_commitment: [u8; 32],
}

/// Checkpoint-level finality proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedPaymentProof {
    pub checkpoint_height: u64,
    pub finality_certificate_digest: [u8; 32],
}

/// Target-domain merchant delivery proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveredPaymentProof {
    pub target_domain: u64,
    pub delivery_proof_root: [u8; 32],
    pub merchant_receipt_hash: [u8; 32],
}

/// Strict monotonic three-tier payment completion status report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentStatusReport {
    pub intent_id: [u8; 32],
    pub guaranteed: Option<GuaranteedPaymentProof>,
    pub finalized: Option<FinalizedPaymentProof>,
    pub delivered: Option<DeliveredPaymentProof>,
}

impl PaymentStatusReport {
    /// Enforce non-zero commitments and strict tier monotonicity
    /// (`Delivered` -> `Finalized` -> `Guaranteed`).
    ///
    /// # Errors
    ///
    /// Refuses zero commitments or any higher tier missing its prerequisite tier.
    pub fn validate(&self) -> Result<(), String> {
        if self.intent_id == [0u8; 32] {
            return Err("payment status intent_id must be non-zero".into());
        }
        if let Some(g) = self.guaranteed {
            if g.block_height == 0
                || g.escrow_commitment == [0u8; 32]
                || g.solver_bond_commitment == [0u8; 32]
            {
                return Err("guaranteed proof has zero height or commitment".into());
            }
        }
        if let Some(f) = self.finalized {
            let Some(g) = self.guaranteed else {
                return Err("finalized status requires guaranteed proof".into());
            };
            if f.checkpoint_height < g.block_height || f.finality_certificate_digest == [0u8; 32] {
                return Err("finalized proof has invalid checkpoint height or digest".into());
            }
        }
        if let Some(d) = self.delivered {
            if self.finalized.is_none() {
                return Err("delivered status requires finalized proof".into());
            }
            if d.target_domain == 0
                || d.delivery_proof_root == [0u8; 32]
                || d.merchant_receipt_hash == [0u8; 32]
            {
                return Err("delivered proof has zero domain, proof root, or receipt hash".into());
            }
        }
        Ok(())
    }

    /// Return the highest validated completion level.
    ///
    /// # Errors
    ///
    /// Returns an error if the status report fails validation.
    pub fn highest_level(&self) -> Result<Option<PaymentCompletionLevel>, String> {
        self.validate()?;
        if self.delivered.is_some() {
            Ok(Some(PaymentCompletionLevel::Delivered))
        } else if self.finalized.is_some() {
            Ok(Some(PaymentCompletionLevel::Finalized))
        } else if self.guaranteed.is_some() {
            Ok(Some(PaymentCompletionLevel::Guaranteed))
        } else {
            Ok(None)
        }
    }
}

/// Optional technical routing details disclosed only when the user expands advanced view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAdvancedDetails {
    pub target_domain: u64,
    pub leg_count: usize,
    pub receipt_hash_hex: String,
    pub pos_auth_code: Option<String>,
}

/// User-facing payment screen model: omits raw chain/network names from the primary
/// screen and shows a plain guarantee badge derived from validated proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentDisplaySummary {
    pub primary_headline: String,
    pub guarantee_label: &'static str,
    pub advanced_details: Option<PaymentAdvancedDetails>,
}

impl PaymentDisplaySummary {
    /// Build a network-agnostic user summary from a receipt and validated status report.
    ///
    /// # Errors
    ///
    /// Refuses mismatched intent IDs, invalid status reports, or unsafe asset labels.
    pub fn from_receipt_and_status(
        receipt: &WalletPaymentReceipt,
        status: &PaymentStatusReport,
        asset_display_symbol: &str,
    ) -> Result<Self, String> {
        validate_safe_label("asset_display_symbol", asset_display_symbol, 16)?;
        if receipt.intent_id != status.intent_id {
            return Err("status report intent_id does not match receipt".into());
        }
        let level = status.highest_level()?;
        let guarantee_label = match level {
            None => "Pending",
            Some(PaymentCompletionLevel::Guaranteed) => "Guaranteed",
            Some(PaymentCompletionLevel::Finalized) => "Finalized",
            Some(PaymentCompletionLevel::Delivered) => "Delivered",
        };
        Ok(Self {
            primary_headline: format!("{} {asset_display_symbol}", receipt.target_amount_delivered),
            guarantee_label,
            advanced_details: Some(PaymentAdvancedDetails {
                target_domain: receipt.target_domain,
                leg_count: receipt.legs.len(),
                receipt_hash_hex: hex::encode(receipt.receipt_hash),
                pos_auth_code: receipt.pos_auth_code.clone(),
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// 5. Remote / Foreign & Contract Account Derivation (Node Alias Parity)
// ---------------------------------------------------------------------------

/// External chain signature/origin family matching `src/execution/coordinator/alias.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ForeignScheme {
    EthereumSecp256k1 = 1,
    SolanaEd25519 = 2,
    Aptos = 3,
    CosmosSecp256k1 = 4,
    SuiEd25519 = 5,
}

impl ForeignScheme {
    /// Exact required byte length of the native external address for this scheme.
    #[must_use]
    pub const fn expected_local_id_len(self) -> usize {
        match self {
            Self::EthereumSecp256k1 | Self::CosmosSecp256k1 => 20,
            Self::SolanaEd25519 | Self::Aptos | Self::SuiEd25519 => 32,
        }
    }
}

/// Derive the 32-byte Budlum address of a foreign Compatibility Lane account:
/// `SHA3-256("BDLM_FOREIGN_ACCOUNT_V1" || scheme_u8 || len_le64 || local_id)`.
///
/// Exact byte-for-byte parity with `src/execution/coordinator/alias.rs::derive_foreign_account`.
///
/// # Errors
///
/// Refuses wrong-length or all-zero external addresses.
pub fn derive_foreign_account(scheme: ForeignScheme, local_id: &[u8]) -> Result<[u8; 32], String> {
    let expected_len = scheme.expected_local_id_len();
    if local_id.len() != expected_len {
        return Err(format!(
            "foreign local_id length {} does not match required {} bytes",
            local_id.len(),
            expected_len
        ));
    }
    if local_id.iter().all(|&b| b == 0) {
        return Err("foreign local_id cannot be all-zero".into());
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_FOREIGN_ACCOUNT_V1");
    hasher.update([scheme as u8]);
    hasher.update(
        u64::try_from(local_id.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(local_id);
    Ok(hasher.finalize().into())
}

/// Derive the 32-byte Budlum address of a deployed contract account:
/// `SHA3-256("BDLM_CONTRACT_ACCOUNT_V1" || ee_id || len_le64 || local_addr)`.
///
/// Exact byte-for-byte parity with `src/execution/coordinator/alias.rs::derive_contract_account`.
///
/// # Errors
///
/// Refuses empty, oversized (>64 bytes), or all-zero local contract addresses.
pub fn derive_contract_account(ee_id: u8, local_addr: &[u8]) -> Result<[u8; 32], String> {
    if local_addr.is_empty() || local_addr.len() > 64 {
        return Err("contract local_addr length must be within 1..=64 bytes".into());
    }
    if local_addr.iter().all(|&b| b == 0) {
        return Err("contract local_addr cannot be all-zero".into());
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_CONTRACT_ACCOUNT_V1");
    hasher.update([ee_id]);
    hasher.update(
        u64::try_from(local_addr.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(local_addr);
    Ok(hasher.finalize().into())
}

// ---------------------------------------------------------------------------
// 6. Light-Client Proof-Backed Unified Balance Portfolio
// ---------------------------------------------------------------------------

/// One binary Merkle branch step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BalanceMerkleStep {
    pub sibling: [u8; 32],
    pub sibling_is_right: bool,
}

/// Trusted header state anchor for wallet balance proof verification.
///
/// Mirrors `bns::HeaderSource`: proofs are ALWAYS checked against roots read
/// from a trusted light-client header source rather than caller-supplied values.
pub trait BalanceHeaderSource {
    /// Committed native state root at `height`.
    fn state_root_at(&self, height: u64) -> Option<[u8; 32]>;
    /// Committed `GlobalBlockHeader::domain_commitment_root` at `height`.
    fn domain_commitment_root_at(&self, height: u64) -> Option<[u8; 32]>;
    /// Highest verified header height held by the wallet's light client.
    fn latest_height(&self) -> u64;
}

/// One trusted header snapshot stored in [`BalanceHeaderBook`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedBalanceHeader {
    pub height: u64,
    pub state_root: [u8; 32],
    pub domain_commitment_root: [u8; 32],
}

/// In-memory light-client header store for balance proof verification.
#[derive(Debug, Clone, Default)]
pub struct BalanceHeaderBook {
    headers: BTreeMap<u64, TrustedBalanceHeader>,
}

impl BalanceHeaderBook {
    /// Create an empty header book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a verified checkpoint header.
    pub fn trust(&mut self, header: TrustedBalanceHeader) {
        self.headers.insert(header.height, header);
    }
}

impl BalanceHeaderSource for BalanceHeaderBook {
    fn state_root_at(&self, height: u64) -> Option<[u8; 32]> {
        self.headers.get(&height).map(|h| h.state_root)
    }

    fn domain_commitment_root_at(&self, height: u64) -> Option<[u8; 32]> {
        self.headers.get(&height).map(|h| h.domain_commitment_root)
    }

    fn latest_height(&self) -> u64 {
        self.headers.keys().next_back().copied().unwrap_or(0)
    }
}

fn check_header_freshness(header_height: u64, tip: u64) -> Result<(), String> {
    if header_height == 0 || tip == 0 {
        return Err("balance proof requires a non-zero trusted header height".into());
    }
    if header_height > tip {
        return Err(format!(
            "balance proof height {header_height} is ahead of wallet tip {tip}"
        ));
    }
    if tip.saturating_sub(header_height) > MAX_BALANCE_PROOF_LAG_BLOCKS {
        return Err(format!(
            "balance proof anchored at stale header {header_height} (tip={tip}, max_lag={MAX_BALANCE_PROOF_LAG_BLOCKS})"
        ));
    }
    Ok(())
}

/// Native Budlum account balance inclusion proof anchored to a trusted state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBalanceProof {
    pub header_height: u64,
    pub owner: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount: u128,
    pub inclusion_path: Vec<BalanceMerkleStep>,
}

impl NativeBalanceProof {
    /// Canonical leaf digest for `(owner, asset_id, amount)`.
    #[must_use]
    pub fn leaf_digest(owner: &[u8; 32], asset_id: &[u8; 32], amount: u128) -> [u8; 32] {
        let amt = amount.to_le_bytes();
        sha256_fields(&[b"BDLM_NATIVE_BALANCE_LEAF_V1", owner, asset_id, &amt])
    }

    /// Canonical internal Merkle node digest.
    #[must_use]
    pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        sha256_fields(&[b"BDLM_NATIVE_BALANCE_NODE_V1", left, right])
    }

    /// Verify this native balance proof against `headers` fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses unknown/stale headers, zero owner/asset, oversized paths, or root mismatches.
    pub fn verify_from_header<S: BalanceHeaderSource + ?Sized>(
        &self,
        headers: &S,
    ) -> Result<VerifiedBalanceEntry, String> {
        if self.owner == [0u8; 32] || self.asset_id == [0u8; 32] {
            return Err("native balance proof requires non-zero owner and asset_id".into());
        }
        if self.inclusion_path.len() > MAX_BALANCE_PROOF_DEPTH {
            return Err("native balance proof exceeds maximum Merkle depth".into());
        }
        check_header_freshness(self.header_height, headers.latest_height())?;
        let trusted_root = headers.state_root_at(self.header_height).ok_or_else(|| {
            format!(
                "trusted state root unavailable at height {}",
                self.header_height
            )
        })?;
        if trusted_root == [0u8; 32] {
            return Err("trusted state root cannot be all-zero".into());
        }
        let mut current = Self::leaf_digest(&self.owner, &self.asset_id, self.amount);
        for step in &self.inclusion_path {
            current = if step.sibling_is_right {
                Self::node_hash(&current, &step.sibling)
            } else {
                Self::node_hash(&step.sibling, &current)
            };
        }
        if current != trusted_root {
            return Err("native balance Merkle proof does not match trusted state root".into());
        }
        Ok(VerifiedBalanceEntry {
            domain_id: 0,
            owner: self.owner,
            asset_id: self.asset_id,
            amount: self.amount,
            verified_at_height: self.header_height,
        })
    }
}

/// Cross-domain / remote account balance proof matching `RemoteStateView` in
/// `src/light_client/mod.rs` (`BDLM_REMOTE_STATE_VIEW_V1`, `BDLM_REMOTE_STATE_LEAF_V1`,
/// `BDLM_REMOTE_STATE_NODE_V1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBalanceProof {
    pub header_height: u64,
    pub remote_domain_id: u64,
    pub remote_state_root: [u8; 32],
    pub owner: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount: u128,
    pub inclusion_path: Vec<BalanceMerkleStep>,
}

impl RemoteBalanceProof {
    /// Canonical balance state key for `(owner, asset_id)` in a remote state tree.
    #[must_use]
    pub fn balance_state_key(owner: &[u8; 32], asset_id: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(80);
        key.extend_from_slice(b"BDLM_BAL_KEY_V1:");
        key.extend_from_slice(owner);
        key.extend_from_slice(asset_id);
        key
    }

    /// Exact parity with `RemoteStateView::expected_domain_commitment`.
    #[must_use]
    pub fn expected_domain_commitment(
        remote_domain_id: u64,
        remote_state_root: &[u8; 32],
    ) -> [u8; 32] {
        let dom = remote_domain_id.to_le_bytes();
        sha256_fields(&[b"BDLM_REMOTE_STATE_VIEW_V1", &dom, remote_state_root])
    }

    /// Exact parity with `RemoteStateView::leaf_digest`.
    #[must_use]
    pub fn leaf_digest(state_key: &[u8], state_value: &[u8]) -> [u8; 32] {
        sha256_fields(&[b"BDLM_REMOTE_STATE_LEAF_V1", state_key, state_value])
    }

    /// Exact parity with `RemoteStateView::compute_merkle_root`.
    #[must_use]
    pub fn compute_merkle_root(
        state_key: &[u8],
        state_value: &[u8],
        inclusion_path: &[BalanceMerkleStep],
    ) -> [u8; 32] {
        let mut current = Self::leaf_digest(state_key, state_value);
        for step in inclusion_path {
            current = if step.sibling_is_right {
                sha256_fields(&[b"BDLM_REMOTE_STATE_NODE_V1", &current, &step.sibling])
            } else {
                sha256_fields(&[b"BDLM_REMOTE_STATE_NODE_V1", &step.sibling, &current])
            };
        }
        current
    }

    /// Verify remote domain commitment and state inclusion against `headers` fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses unknown/stale headers, zero identifiers, domain commitment mismatch, or
    /// Merkle inclusion mismatch.
    pub fn verify_from_header<S: BalanceHeaderSource + ?Sized>(
        &self,
        headers: &S,
    ) -> Result<VerifiedBalanceEntry, String> {
        if self.remote_domain_id == 0
            || self.remote_state_root == [0u8; 32]
            || self.owner == [0u8; 32]
            || self.asset_id == [0u8; 32]
        {
            return Err(
                "remote balance proof requires non-zero domain, root, owner, and asset".into(),
            );
        }
        if self.inclusion_path.len() > MAX_BALANCE_PROOF_DEPTH {
            return Err("remote balance proof exceeds maximum Merkle depth".into());
        }
        check_header_freshness(self.header_height, headers.latest_height())?;
        let trusted_domain_root = headers
            .domain_commitment_root_at(self.header_height)
            .ok_or_else(|| {
                format!(
                    "trusted domain commitment root unavailable at height {}",
                    self.header_height
                )
            })?;
        let expected_domain_root =
            Self::expected_domain_commitment(self.remote_domain_id, &self.remote_state_root);
        if trusted_domain_root != expected_domain_root {
            return Err(
                "remote_state_root does not match trusted header domain_commitment_root".into(),
            );
        }
        let state_key = Self::balance_state_key(&self.owner, &self.asset_id);
        let state_value = self.amount.to_le_bytes();
        let recomputed = Self::compute_merkle_root(&state_key, &state_value, &self.inclusion_path);
        if recomputed != self.remote_state_root {
            return Err("remote balance Merkle proof does not match remote_state_root".into());
        }
        Ok(VerifiedBalanceEntry {
            domain_id: self.remote_domain_id,
            owner: self.owner,
            asset_id: self.asset_id,
            amount: self.amount,
            verified_at_height: self.header_height,
        })
    }
}

/// One cryptographically verified asset balance line (native, remote, or linked foreign).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedBalanceEntry {
    /// `0` for native Budlum balances, or non-zero external domain ID.
    pub domain_id: u64,
    pub owner: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount: u128,
    pub verified_at_height: u64,
}

/// Proof-backed unified wallet balance portfolio across native, remote, and linked foreign accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedBalancePortfolio {
    entries: Vec<VerifiedBalanceEntry>,
    totals_by_asset: BTreeMap<[u8; 32], u128>,
}

impl UnifiedBalancePortfolio {
    /// Verify every native and remote balance proof against `headers` and build one
    /// unified asset view. Any forged, stale, duplicate, or overflowing balance fails closed.
    ///
    /// # Errors
    ///
    /// Refuses any invalid proof, duplicate `(domain_id, owner, asset_id)`, or total overflow.
    pub fn from_verified_proofs<S: BalanceHeaderSource + ?Sized>(
        native_proofs: &[NativeBalanceProof],
        remote_proofs: &[RemoteBalanceProof],
        headers: &S,
    ) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(native_proofs.len() + remote_proofs.len());
        let mut seen: BTreeSet<(u64, [u8; 32], [u8; 32])> = BTreeSet::new();
        let mut totals_by_asset: BTreeMap<[u8; 32], u128> = BTreeMap::new();

        for proof in native_proofs {
            let entry = proof.verify_from_header(headers)?;
            if !seen.insert((entry.domain_id, entry.owner, entry.asset_id)) {
                return Err("duplicate native balance entry for (owner, asset_id)".into());
            }
            let total = totals_by_asset.entry(entry.asset_id).or_insert(0);
            *total = total
                .checked_add(entry.amount)
                .ok_or_else(|| "overflow aggregating unified balance total".to_string())?;
            entries.push(entry);
        }

        for proof in remote_proofs {
            let entry = proof.verify_from_header(headers)?;
            if !seen.insert((entry.domain_id, entry.owner, entry.asset_id)) {
                return Err(
                    "duplicate remote balance entry for (domain_id, owner, asset_id)".into(),
                );
            }
            let total = totals_by_asset.entry(entry.asset_id).or_insert(0);
            *total = total
                .checked_add(entry.amount)
                .ok_or_else(|| "overflow aggregating unified balance total".to_string())?;
            entries.push(entry);
        }

        Ok(Self {
            entries,
            totals_by_asset,
        })
    }

    /// All individually verified balance rows.
    #[must_use]
    pub fn entries(&self) -> &[VerifiedBalanceEntry] {
        &self.entries
    }

    /// Unified verified total across all domains/accounts for `asset_id`.
    #[must_use]
    pub fn total_for_asset(&self, asset_id: &[u8; 32]) -> u128 {
        self.totals_by_asset.get(asset_id).copied().unwrap_or(0)
    }

    /// Deterministic map of every verified asset ID to its unified total.
    #[must_use]
    pub fn totals_by_asset(&self) -> &BTreeMap<[u8; 32], u128> {
        &self.totals_by_asset
    }
}
