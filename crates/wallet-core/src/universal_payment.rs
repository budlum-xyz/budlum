//! Wallet-side universal payment, light-client unified balance proof
//! verification, remote-account address derivation, and `.bud` address-bar
//! lookalike safety.
//!
//! exposed for: the wallet crate's SDK surface - mobile, browser, and CLI
//! hosts call these primitives directly without trusting an unauthenticated
//! RPC provider.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha3::{Digest, Sha3_256};

use crate::bns::{self, HeaderSource as BnsHeaderSource, RecipientTarget, WalletBnsProof};
use crate::{crypto, BudlumAddress, PublicKeyBytes, SignatureBytes, Wallet};

/// Maximum Merkle branch depth accepted for a balance proof (`u64` / 64 levels).
pub const MAX_BALANCE_PROOF_DEPTH: usize = 64;

/// Maximum foreign address byte length accepted in a unified balance proof.
pub const MAX_FOREIGN_ADDRESS_BYTES: usize = 64;

/// Maximum payment request memo length (printable ASCII only).
pub const MAX_PAYMENT_MEMO_BYTES: usize = 128;

/// Maximum basis points (`100.00%`).
pub const MAX_SLIPPAGE_BPS: u16 = 10_000;

/// Errors returned by wallet universal payment and balance-proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UniversalPaymentError {
    /// Caller supplied an invalid parameter, malformed URI, or out-of-range value.
    InvalidInput(String),
    /// The trusted header store does not contain the height claimed by the proof.
    HeaderUnknown(u64),
    /// A Merkle proof or receipt commitment did not match its trusted anchor.
    ProofMismatch(String),
    /// A cryptographic ML-DSA-87 signature or signer-address binding failed.
    InvalidSignature(String),
    /// A payment intent or solver quote has expired at the evaluation timestamp.
    Expired(String),
    /// A solver quote violated intent asset, amount, slippage, or assurance terms.
    QuoteViolation(String),
    /// Checked integer arithmetic overflowed.
    Overflow(&'static str),
    /// A `.bud` name violated address-bar safety or failed BNS proof verification.
    UnsafeBudRecipient(String),
}

impl fmt::Display for UniversalPaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Self::HeaderUnknown(h) => write!(f, "trusted state header unknown at height {h}"),
            Self::ProofMismatch(m) => write!(f, "proof mismatch: {m}"),
            Self::InvalidSignature(m) => write!(f, "invalid signature: {m}"),
            Self::Expired(m) => write!(f, "expired: {m}"),
            Self::QuoteViolation(m) => write!(f, "quote violation: {m}"),
            Self::Overflow(op) => write!(f, "arithmetic overflow in {op}"),
            Self::UnsafeBudRecipient(m) => write!(f, "unsafe .bud recipient: {m}"),
        }
    }
}

impl std::error::Error for UniversalPaymentError {}

/// Write a length-prefixed byte slice into a SHA3-256 hasher so adjacent
/// variable-length inputs can never collide across boundaries.
fn update_len_prefixed(hasher: &mut Sha3_256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Validate strict CAIP-2 syntax `<namespace>:<reference>`:
/// - namespace: `3..=8` lowercase ASCII `[a-z0-9-]`
/// - reference: `1..=32` ASCII `[a-zA-Z0-9-_]`
///
/// # Errors
///
/// Refuses identifiers that do not match the CAIP-2 grammar.
pub fn validate_caip2(caip2: &str) -> Result<(&str, &str), UniversalPaymentError> {
    let Some((namespace, reference)) = caip2.split_once(':') else {
        return Err(UniversalPaymentError::InvalidInput(
            "CAIP-2 identifier must contain ':'".into(),
        ));
    };
    if reference.contains(':') {
        return Err(UniversalPaymentError::InvalidInput(
            "CAIP-2 identifier must contain exactly one ':'".into(),
        ));
    }
    let ns_ok = (3..=8).contains(&namespace.len())
        && namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !ns_ok {
        return Err(UniversalPaymentError::InvalidInput(format!(
            "invalid CAIP-2 namespace '{namespace}'"
        )));
    }
    let ref_ok = (1..=32).contains(&reference.len())
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ref_ok {
        return Err(UniversalPaymentError::InvalidInput(format!(
            "invalid CAIP-2 reference '{reference}'"
        )));
    }
    Ok((namespace, reference))
}

/// Deterministically derive a Budlum-owned remote-account address on a target
/// external chain identified by its CAIP-2 string.
///
/// The derivation is domain-separated (`BDLM_WALLET_REMOTE_ACCOUNT_V1`) and
/// length-prefixed so Android, iOS, WASM, and desktop clients compute identical
/// 32-byte remote-account identifiers.
///
/// # Errors
///
/// Refuses invalid CAIP-2 identifiers or the zero owner address.
pub fn derive_remote_account_address(
    caip2: &str,
    owner: &BudlumAddress,
    salt: &[u8; 32],
) -> Result<[u8; 32], UniversalPaymentError> {
    validate_caip2(caip2)?;
    if *owner == [0u8; 32] {
        return Err(UniversalPaymentError::InvalidInput(
            "owner address cannot be zero".into(),
        ));
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_WALLET_REMOTE_ACCOUNT_V1");
    update_len_prefixed(&mut hasher, caip2.as_bytes());
    hasher.update(owner);
    hasher.update(salt);
    Ok(hasher.finalize().into())
}

// ============================================================================
// Light-Client Unified Balance Proof Verification
// ============================================================================

/// A wallet-trusted finalized header anchoring account/balance state proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedStateHeader {
    /// Finalized block height.
    pub height: u64,
    /// Authenticated state Merkle root committed in the finalized header.
    pub state_root: [u8; 32],
    /// Finalized timestamp in Unix milliseconds.
    pub finalized_at_ms: u64,
}

/// Trusted header store read by balance-proof verifiers so untrusted RPC
/// callers can never supply their own state root alongside a proof.
pub trait StateHeaderSource {
    /// Return the wallet-trusted finalized header at `height`, if known.
    fn trusted_state_header(&self, height: u64) -> Option<TrustedStateHeader>;
}

/// In-memory book of wallet-trusted state headers indexed by height.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateHeaderBook {
    headers: BTreeMap<u64, TrustedStateHeader>,
}

impl StateHeaderBook {
    /// Create an empty trusted header book.
    #[must_use]
    pub fn new() -> Self {
        Self {
            headers: BTreeMap::new(),
        }
    }

    /// Enroll a verified state header. Refuses zero state roots.
    ///
    /// # Errors
    ///
    /// Returns [`UniversalPaymentError::InvalidInput`] if `state_root` is zero.
    pub fn trust(&mut self, header: TrustedStateHeader) -> Result<(), UniversalPaymentError> {
        if header.state_root == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "trusted state_root cannot be zero".into(),
            ));
        }
        self.headers.insert(header.height, header);
        Ok(())
    }
}

impl StateHeaderSource for StateHeaderBook {
    fn trusted_state_header(&self, height: u64) -> Option<TrustedStateHeader> {
        self.headers.get(&height).copied()
    }
}

/// Where a user's balance resides across the unified multi-chain surface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BalanceLocation {
    /// Direct balance held on Budlum settlement state.
    NativeBudlum,
    /// Balance held in a Budlum-controlled remote account on an external chain.
    RemoteAccount {
        /// Target chain CAIP-2 identifier.
        caip2: String,
        /// Deterministically derived 32-byte remote account identifier.
        remote_address: [u8; 32],
    },
    /// Balance held on a user-linked foreign address proven via external finality.
    LinkedForeign {
        /// External chain CAIP-2 identifier.
        caip2: String,
        /// Raw external chain address bytes (`1..=64` bytes).
        foreign_address: Vec<u8>,
    },
}

impl BalanceLocation {
    fn validate(&self) -> Result<(), UniversalPaymentError> {
        match self {
            Self::NativeBudlum => Ok(()),
            Self::RemoteAccount {
                caip2,
                remote_address,
            } => {
                validate_caip2(caip2)?;
                if *remote_address == [0u8; 32] {
                    return Err(UniversalPaymentError::InvalidInput(
                        "remote_address cannot be zero".into(),
                    ));
                }
                Ok(())
            }
            Self::LinkedForeign {
                caip2,
                foreign_address,
            } => {
                validate_caip2(caip2)?;
                if foreign_address.is_empty() || foreign_address.len() > MAX_FOREIGN_ADDRESS_BYTES {
                    return Err(UniversalPaymentError::InvalidInput(format!(
                        "foreign_address length must be in 1..={MAX_FOREIGN_ADDRESS_BYTES}"
                    )));
                }
                Ok(())
            }
        }
    }

    fn absorb(&self, hasher: &mut Sha3_256) {
        match self {
            Self::NativeBudlum => {
                hasher.update([0x01u8]);
            }
            Self::RemoteAccount {
                caip2,
                remote_address,
            } => {
                hasher.update([0x02u8]);
                update_len_prefixed(hasher, caip2.as_bytes());
                hasher.update(remote_address);
            }
            Self::LinkedForeign {
                caip2,
                foreign_address,
            } => {
                hasher.update([0x03u8]);
                update_len_prefixed(hasher, caip2.as_bytes());
                update_len_prefixed(hasher, foreign_address);
            }
        }
    }
}

/// Compute the domain-separated balance leaf digest (`BDLM_WALLET_BALANCE_LEAF_V1`).
///
/// # Errors
///
/// Refuses zero owner, zero asset id, or invalid balance location.
pub fn build_balance_leaf_digest(
    owner: &BudlumAddress,
    asset_id: &[u8; 32],
    amount: u128,
    location: &BalanceLocation,
) -> Result<[u8; 32], UniversalPaymentError> {
    if *owner == [0u8; 32] {
        return Err(UniversalPaymentError::InvalidInput(
            "balance owner cannot be zero".into(),
        ));
    }
    if *asset_id == [0u8; 32] {
        return Err(UniversalPaymentError::InvalidInput(
            "balance asset_id cannot be zero".into(),
        ));
    }
    location.validate()?;

    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_WALLET_BALANCE_LEAF_V1");
    hasher.update(owner);
    hasher.update(asset_id);
    hasher.update(amount.to_le_bytes());
    location.absorb(&mut hasher);
    Ok(hasher.finalize().into())
}

/// Fold a balance Merkle branch from `leaf` up to its root under
/// `BDLM_WALLET_BALANCE_NODE_V1`.
///
/// Each sibling pair `(digest, sibling_is_right)` places `digest` on the right
/// when `sibling_is_right == true` and on the left otherwise.
#[must_use]
pub fn fold_balance_merkle_branch(leaf: &[u8; 32], siblings: &[([u8; 32], bool)]) -> [u8; 32] {
    let mut acc = *leaf;
    for (sibling, sibling_is_right) in siblings {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_WALLET_BALANCE_NODE_V1");
        if *sibling_is_right {
            hasher.update(acc);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(acc);
        }
        acc = hasher.finalize().into();
    }
    acc
}

/// Untrusted RPC balance proof candidate supplied to the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceProofBranch {
    /// Finalized header height anchoring this proof.
    pub header_height: u64,
    /// Where the balance is held (native, remote account, or linked foreign).
    pub location: BalanceLocation,
    /// Canonical 32-byte asset identifier.
    pub asset_id: [u8; 32],
    /// Budlum owner address.
    pub owner: BudlumAddress,
    /// Claimed balance in smallest asset atoms.
    pub amount: u128,
    /// Merkle inclusion siblings `(sibling_digest, sibling_is_right)`.
    pub siblings: Vec<([u8; 32], bool)>,
}

/// A balance row that passed Merkle proof verification against a trusted header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBalanceRow {
    header_height: u64,
    location: BalanceLocation,
    asset_id: [u8; 32],
    owner: BudlumAddress,
    amount: u128,
}

impl VerifiedBalanceRow {
    /// Finalized height at which this row was verified.
    #[must_use]
    pub const fn header_height(&self) -> u64 {
        self.header_height
    }

    /// Location of this verified balance.
    #[must_use]
    pub const fn location(&self) -> &BalanceLocation {
        &self.location
    }

    /// Canonical 32-byte asset id.
    #[must_use]
    pub const fn asset_id(&self) -> [u8; 32] {
        self.asset_id
    }

    /// Verified owner address.
    #[must_use]
    pub const fn owner(&self) -> BudlumAddress {
        self.owner
    }

    /// Verified balance amount in atoms.
    #[must_use]
    pub const fn amount(&self) -> u128 {
        self.amount
    }
}

/// Verify a single RPC balance proof against a wallet-trusted header source.
///
/// # Errors
///
/// Fails closed if the header height is unknown, the trusted header carries a
/// zero root, the branch exceeds [`MAX_BALANCE_PROOF_DEPTH`], any field is
/// malformed, or the folded Merkle root does not equal the trusted `state_root`.
pub fn verify_balance_proof<S: StateHeaderSource + ?Sized>(
    proof: &BalanceProofBranch,
    headers: &S,
) -> Result<VerifiedBalanceRow, UniversalPaymentError> {
    if proof.siblings.len() > MAX_BALANCE_PROOF_DEPTH {
        return Err(UniversalPaymentError::InvalidInput(format!(
            "balance proof depth {} exceeds {MAX_BALANCE_PROOF_DEPTH}",
            proof.siblings.len()
        )));
    }
    let header = headers
        .trusted_state_header(proof.header_height)
        .ok_or(UniversalPaymentError::HeaderUnknown(proof.header_height))?;
    if header.state_root == [0u8; 32] {
        return Err(UniversalPaymentError::ProofMismatch(
            "trusted header carries zero state_root".into(),
        ));
    }

    let leaf =
        build_balance_leaf_digest(&proof.owner, &proof.asset_id, proof.amount, &proof.location)?;
    let computed_root = fold_balance_merkle_branch(&leaf, &proof.siblings);
    if computed_root != header.state_root {
        return Err(UniversalPaymentError::ProofMismatch(format!(
            "balance proof root {} does not match trusted header root {} at height {}",
            hex::encode(computed_root),
            hex::encode(header.state_root),
            header.height
        )));
    }

    Ok(VerifiedBalanceRow {
        header_height: header.height,
        location: proof.location.clone(),
        asset_id: proof.asset_id,
        owner: proof.owner,
        amount: proof.amount,
    })
}

/// Unified multi-chain wallet portfolio composed exclusively of header-proven
/// balance rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedPortfolio {
    rows: Vec<VerifiedBalanceRow>,
    totals_by_asset: BTreeMap<[u8; 32], u128>,
}

impl UnifiedPortfolio {
    /// Verify every balance proof against `headers` and aggregate totals by
    /// asset id. Rejects duplicate `(owner, asset_id, location)` entries and
    /// fails closed if any proof fails verification or overflows `u128`.
    ///
    /// # Errors
    ///
    /// Propagates any proof verification failure, duplicate row, or overflow.
    pub fn from_verified_proofs<S: StateHeaderSource + ?Sized>(
        proofs: &[BalanceProofBranch],
        headers: &S,
    ) -> Result<Self, UniversalPaymentError> {
        let mut rows = Vec::with_capacity(proofs.len());
        let mut totals_by_asset: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        let mut seen: BTreeSet<(BudlumAddress, [u8; 32], BalanceLocation)> = BTreeSet::new();

        for proof in proofs {
            let verified = verify_balance_proof(proof, headers)?;
            let key = (verified.owner, verified.asset_id, verified.location.clone());
            if !seen.insert(key) {
                return Err(UniversalPaymentError::InvalidInput(
                    "duplicate balance proof row for same (owner, asset, location)".into(),
                ));
            }
            let entry = totals_by_asset.entry(verified.asset_id).or_insert(0);
            *entry = entry
                .checked_add(verified.amount)
                .ok_or(UniversalPaymentError::Overflow("unified portfolio total"))?;
            rows.push(verified);
        }

        Ok(Self {
            rows,
            totals_by_asset,
        })
    }

    /// All verified rows across native, remote-account, and linked-foreign views.
    #[must_use]
    pub fn rows(&self) -> &[VerifiedBalanceRow] {
        &self.rows
    }

    /// Total verified balance across all locations for `asset_id`.
    #[must_use]
    pub fn total_for_asset(&self, asset_id: &[u8; 32]) -> u128 {
        self.totals_by_asset.get(asset_id).copied().unwrap_or(0)
    }
}

// ============================================================================
// Chain-Agnostic Payment Presentation & Assurance Labels
// ============================================================================

/// Finality assurance tier shown in plain user language on a payment screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceClass {
    /// Slashable, irreversible, and post-quantum attested.
    PostQuantumFinal,
    /// Slashable and economically irreversible under classical/hybrid quorum.
    EconomicFinal,
    /// Probabilistic proof-of-work confirmations without slashable stake.
    ProbabilisticWork,
    /// Unconfirmed or pending finality; must warn the user and never clear a binding quote.
    PendingOrUnverified,
}

impl AssuranceClass {
    /// Stable single-byte discriminant absorbed into signed quotes and receipts.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::PostQuantumFinal => 1,
            Self::EconomicFinal => 2,
            Self::ProbabilisticWork => 3,
            Self::PendingOrUnverified => 4,
        }
    }

    /// Plain user-facing label without exposing chain jargon.
    #[must_use]
    pub const fn plain_label(self) -> &'static str {
        match self {
            Self::PostQuantumFinal => "Final (quantum-safe)",
            Self::EconomicFinal => "Final",
            Self::ProbabilisticWork => "Confirmed (probabilistic)",
            Self::PendingOrUnverified => "Pending (unconfirmed)",
        }
    }

    /// Whether the wallet UI must highlight a confirmation-risk warning.
    #[must_use]
    pub const fn requires_user_warning(self) -> bool {
        matches!(self, Self::ProbabilisticWork | Self::PendingOrUnverified)
    }

    /// Whether a solver quote carrying this assurance tier may be accepted.
    #[must_use]
    pub const fn is_admissible_for_quote(self) -> bool {
        !matches!(self, Self::PendingOrUnverified)
    }
}

/// Chain-agnostic payment screen view: the user pays without selecting a chain;
/// routing details stay collapsed unless explicitly requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPresentation {
    /// Recipient shown to the user (`.bud` name or `0x`-prefixed hex address).
    pub recipient_display: String,
    /// Payment amount in smallest units.
    pub amount: u128,
    /// Display asset ticker (for example `"BUD"`).
    pub asset_symbol: String,
    /// Plain assurance label derived from [`AssuranceClass`].
    pub assurance_label: &'static str,
    /// Whether the UI must display an assurance warning before signing.
    pub requires_user_warning: bool,
    /// Always `true`: chain selection is hidden by default.
    pub chain_details_hidden_by_default: bool,
    /// Optional memo text from the payment request.
    pub memo: Option<String>,
}

// ============================================================================
// Strict Payment Request URI Parser (`budlum:pay?...`)
// ============================================================================

/// Parsed wallet payment request from a `budlum:pay?...` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequest {
    /// Recipient (direct 32-byte address or canonical `.bud` name).
    pub recipient: RecipientTarget,
    /// Strictly positive payment amount in smallest units.
    pub amount: u128,
    /// Non-zero 32-byte canonical asset id.
    pub asset_id: [u8; 32],
    /// Optional expiry timestamp in Unix milliseconds.
    pub expiry_ms: Option<u64>,
    /// Optional printable ASCII memo (`<= 128` bytes).
    pub memo: Option<String>,
    /// Optional slippage bound (`<= 10_000` bps).
    pub max_slippage_bps: Option<u16>,
}

impl PaymentRequest {
    /// Parse a `budlum:pay?to=...&amount=...&asset=...` URI fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses unknown schemes, fragments, duplicate or unknown query keys,
    /// zero/overflowing amounts, invalid recipients or asset ids, non-ASCII or
    /// control-character memos, and slippage above `10_000` bps.
    pub fn parse_uri(uri: &str) -> Result<Self, UniversalPaymentError> {
        if !uri.is_ascii() || uri.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(UniversalPaymentError::InvalidInput(
                "payment URI must be printable ASCII without control characters".into(),
            ));
        }
        if uri.contains('#') {
            return Err(UniversalPaymentError::InvalidInput(
                "payment URI fragments are not permitted".into(),
            ));
        }
        let Some(query) = uri.strip_prefix("budlum:pay?") else {
            return Err(UniversalPaymentError::InvalidInput(
                "payment URI must start with 'budlum:pay?'".into(),
            ));
        };
        if query.is_empty() {
            return Err(UniversalPaymentError::InvalidInput(
                "payment URI query cannot be empty".into(),
            ));
        }

        let mut seen_keys: BTreeSet<&str> = BTreeSet::new();
        let mut recipient: Option<RecipientTarget> = None;
        let mut amount: Option<u128> = None;
        let mut asset_id: Option<[u8; 32]> = None;
        let mut expiry_ms: Option<u64> = None;
        let mut memo: Option<String> = None;
        let mut max_slippage_bps: Option<u16> = None;

        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                return Err(UniversalPaymentError::InvalidInput(format!(
                    "malformed query pair '{pair}'"
                )));
            };
            if value.is_empty() {
                return Err(UniversalPaymentError::InvalidInput(format!(
                    "empty value for key '{key}'"
                )));
            }
            if !seen_keys.insert(key) {
                return Err(UniversalPaymentError::InvalidInput(format!(
                    "duplicate query key '{key}'"
                )));
            }
            match key {
                "to" => {
                    let parsed = bns::parse_recipient_input(value)
                        .map_err(UniversalPaymentError::InvalidInput)?;
                    if let RecipientTarget::BudName(ref name) = parsed {
                        check_bud_name_address_bar_safety(name, &[])?;
                    }
                    recipient = Some(parsed);
                }
                "amount" => {
                    if !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(UniversalPaymentError::InvalidInput(
                            "amount must contain only ASCII digits".into(),
                        ));
                    }
                    let parsed = value.parse::<u128>().map_err(|_| {
                        UniversalPaymentError::InvalidInput("amount exceeds u128".into())
                    })?;
                    if parsed == 0 {
                        return Err(UniversalPaymentError::InvalidInput(
                            "amount must be strictly positive".into(),
                        ));
                    }
                    amount = Some(parsed);
                }
                "asset" => {
                    let clean = value
                        .strip_prefix("0x")
                        .or_else(|| value.strip_prefix("0X"))
                        .unwrap_or(value);
                    if clean.len() != 64 {
                        return Err(UniversalPaymentError::InvalidInput(
                            "asset must be a 64-hex 32-byte identifier".into(),
                        ));
                    }
                    let decoded = hex::decode(clean).map_err(|e| {
                        UniversalPaymentError::InvalidInput(format!("invalid asset hex: {e}"))
                    })?;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    if arr == [0u8; 32] {
                        return Err(UniversalPaymentError::InvalidInput(
                            "asset cannot be zero".into(),
                        ));
                    }
                    asset_id = Some(arr);
                }
                "expiry" => {
                    if !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(UniversalPaymentError::InvalidInput(
                            "expiry must be an unsigned millisecond timestamp".into(),
                        ));
                    }
                    let parsed = value.parse::<u64>().map_err(|_| {
                        UniversalPaymentError::InvalidInput("expiry exceeds u64".into())
                    })?;
                    if parsed == 0 {
                        return Err(UniversalPaymentError::InvalidInput(
                            "expiry must be > 0".into(),
                        ));
                    }
                    expiry_ms = Some(parsed);
                }
                "memo" => {
                    if value.len() > MAX_PAYMENT_MEMO_BYTES {
                        return Err(UniversalPaymentError::InvalidInput(format!(
                            "memo exceeds {MAX_PAYMENT_MEMO_BYTES} bytes"
                        )));
                    }
                    if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                        return Err(UniversalPaymentError::InvalidInput(
                            "memo must be printable ASCII".into(),
                        ));
                    }
                    memo = Some(value.to_string());
                }
                "max_slippage_bps" => {
                    if !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(UniversalPaymentError::InvalidInput(
                            "max_slippage_bps must be digits".into(),
                        ));
                    }
                    let parsed = value.parse::<u16>().map_err(|_| {
                        UniversalPaymentError::InvalidInput("max_slippage_bps exceeds u16".into())
                    })?;
                    if parsed > MAX_SLIPPAGE_BPS {
                        return Err(UniversalPaymentError::InvalidInput(format!(
                            "max_slippage_bps {parsed} exceeds {MAX_SLIPPAGE_BPS}"
                        )));
                    }
                    max_slippage_bps = Some(parsed);
                }
                unknown => {
                    return Err(UniversalPaymentError::InvalidInput(format!(
                        "unknown payment URI key '{unknown}'"
                    )));
                }
            }
        }

        Ok(Self {
            recipient: recipient.ok_or_else(|| {
                UniversalPaymentError::InvalidInput("missing required 'to' parameter".into())
            })?,
            amount: amount.ok_or_else(|| {
                UniversalPaymentError::InvalidInput("missing required 'amount' parameter".into())
            })?,
            asset_id: asset_id.ok_or_else(|| {
                UniversalPaymentError::InvalidInput("missing required 'asset' parameter".into())
            })?,
            expiry_ms,
            memo,
            max_slippage_bps,
        })
    }

    /// Build the chain-agnostic payment confirmation view for this request.
    #[must_use]
    pub fn presentation(
        &self,
        asset_symbol: &str,
        assurance: AssuranceClass,
    ) -> PaymentPresentation {
        let recipient_display = match &self.recipient {
            RecipientTarget::BudName(name) => name.clone(),
            RecipientTarget::Direct(addr) => format!("0x{}", hex::encode(addr)),
        };
        PaymentPresentation {
            recipient_display,
            amount: self.amount,
            asset_symbol: asset_symbol.to_string(),
            assurance_label: assurance.plain_label(),
            requires_user_warning: assurance.requires_user_warning(),
            chain_details_hidden_by_default: true,
            memo: self.memo.clone(),
        }
    }
}

// ============================================================================
// ML-DSA-87 Signed Universal Payment Intent, Binding Solver Quote & Receipt
// ============================================================================

/// Unsigned universal payment intent binding every economic and replay field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalPaymentIntent {
    /// Settlement chain identifier (replay protection across networks).
    pub chain_id: u64,
    /// Payer Budlum address (must match the signing ML-DSA-87 public key).
    pub payer: BudlumAddress,
    /// Recipient Budlum address (direct or header-proven `.bud` target).
    pub recipient: BudlumAddress,
    /// Asset the merchant/recipient requires.
    pub output_asset_id: [u8; 32],
    /// Minimum amount the recipient must receive.
    pub output_amount: u128,
    /// Asset the payer authorizes spending.
    pub max_input_asset_id: [u8; 32],
    /// Maximum input amount the payer authorizes spending.
    pub max_input_amount: u128,
    /// Maximum allowed solver slippage in basis points (`<= 10_000`).
    pub max_slippage_bps: u16,
    /// Strictly unique payer intent nonce.
    pub nonce: u64,
    /// Expiry timestamp in Unix milliseconds (`now_ms < expiry_ms`).
    pub expiry_ms: u64,
    /// Hash of optional off-chain invoice/memo (`[0u8; 32]` when absent).
    pub memo_hash: [u8; 32],
}

impl UniversalPaymentIntent {
    /// Validate static intent invariants fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses zero chain id, zero addresses/assets, zero amounts, zero expiry,
    /// or slippage above `10_000` bps.
    pub fn validate(&self) -> Result<(), UniversalPaymentError> {
        if self.chain_id == 0 {
            return Err(UniversalPaymentError::InvalidInput(
                "chain_id must be non-zero".into(),
            ));
        }
        if self.payer == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "payer cannot be zero".into(),
            ));
        }
        if self.recipient == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "recipient cannot be zero".into(),
            ));
        }
        if self.output_asset_id == [0u8; 32] || self.max_input_asset_id == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "asset ids cannot be zero".into(),
            ));
        }
        if self.output_amount == 0 || self.max_input_amount == 0 {
            return Err(UniversalPaymentError::InvalidInput(
                "intent amounts must be strictly positive".into(),
            ));
        }
        if self.max_slippage_bps > MAX_SLIPPAGE_BPS {
            return Err(UniversalPaymentError::InvalidInput(format!(
                "max_slippage_bps {} exceeds {MAX_SLIPPAGE_BPS}",
                self.max_slippage_bps
            )));
        }
        if self.expiry_ms == 0 {
            return Err(UniversalPaymentError::InvalidInput(
                "expiry_ms must be non-zero".into(),
            ));
        }
        Ok(())
    }

    fn absorb_all_fields(&self, hasher: &mut Sha3_256) {
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.payer);
        hasher.update(self.recipient);
        hasher.update(self.output_asset_id);
        hasher.update(self.output_amount.to_le_bytes());
        hasher.update(self.max_input_asset_id);
        hasher.update(self.max_input_amount.to_le_bytes());
        hasher.update(self.max_slippage_bps.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.expiry_ms.to_le_bytes());
        hasher.update(self.memo_hash);
    }

    /// Canonical 32-byte intent identifier binding every field.
    #[must_use]
    pub fn intent_id(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_WALLET_PAYMENT_INTENT_ID_V1");
        self.absorb_all_fields(&mut hasher);
        hasher.finalize().into()
    }

    /// Canonical 32-byte signing digest for ML-DSA-87 under `CROSS_DOMAIN_V1`.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_WALLET_PAYMENT_INTENT_SIG_V1");
        self.absorb_all_fields(&mut hasher);
        hasher.finalize().into()
    }
}

/// ML-DSA-87 signed universal payment intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPaymentIntent {
    /// Signed intent payload.
    pub intent: UniversalPaymentIntent,
    /// Payer ML-DSA-87 public key (`2592` bytes).
    pub payer_public_key: PublicKeyBytes,
    /// Payer ML-DSA-87 signature (`4627` bytes) under `crypto::ctx::CROSS_DOMAIN_V1`.
    pub signature: SignatureBytes,
}

impl SignedPaymentIntent {
    /// Verify intent fields, expiry at `now_ms`, public-key-to-payer binding,
    /// and the ML-DSA-87 signature fail-closed.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid fields, expiry (`now_ms >= expiry_ms`),
    /// public-key/payer mismatch, or invalid ML-DSA-87 signature.
    pub fn verify(&self, now_ms: u64) -> Result<[u8; 32], UniversalPaymentError> {
        self.intent.validate()?;
        if now_ms >= self.intent.expiry_ms {
            return Err(UniversalPaymentError::Expired(format!(
                "intent expired at {} (now={now_ms})",
                self.intent.expiry_ms
            )));
        }
        let derived_payer = Wallet::address_from_public_key(&self.payer_public_key);
        if derived_payer != self.intent.payer {
            return Err(UniversalPaymentError::InvalidSignature(
                "payer_public_key does not derive intent.payer".into(),
            ));
        }
        let digest = self.intent.signing_digest();
        if !Wallet::verify_for(
            &self.payer_public_key,
            crypto::ctx::CROSS_DOMAIN_V1,
            &digest,
            &self.signature,
        ) {
            return Err(UniversalPaymentError::InvalidSignature(
                "ML-DSA-87 intent signature verification failed".into(),
            ));
        }
        Ok(self.intent.intent_id())
    }
}

/// Binding solver quote committing to fill a specific [`UniversalPaymentIntent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolverQuote {
    /// Target intent id this quote binds to.
    pub intent_id: [u8; 32],
    /// Solver Budlum address (must match signing ML-DSA-87 public key).
    pub solver: BudlumAddress,
    /// Input asset debited from payer.
    pub input_asset_id: [u8; 32],
    /// Exact input amount charged by the solver.
    pub input_amount: u128,
    /// Output asset delivered to recipient.
    pub output_asset_id: [u8; 32],
    /// Exact output amount delivered to recipient.
    pub output_amount: u128,
    /// Quote validity deadline in Unix milliseconds.
    pub valid_until_ms: u64,
    /// Finality assurance class guaranteed by this route.
    pub assurance: AssuranceClass,
}

impl SolverQuote {
    /// Validate static quote fields fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses zero ids/addresses/amounts, zero deadline, or unverified assurance.
    pub fn validate(&self) -> Result<(), UniversalPaymentError> {
        if self.intent_id == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "quote intent_id cannot be zero".into(),
            ));
        }
        if self.solver == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "quote solver cannot be zero".into(),
            ));
        }
        if self.input_asset_id == [0u8; 32] || self.output_asset_id == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "quote asset ids cannot be zero".into(),
            ));
        }
        if self.input_amount == 0 || self.output_amount == 0 {
            return Err(UniversalPaymentError::InvalidInput(
                "quote amounts must be strictly positive".into(),
            ));
        }
        if self.valid_until_ms == 0 {
            return Err(UniversalPaymentError::InvalidInput(
                "quote valid_until_ms must be non-zero".into(),
            ));
        }
        if !self.assurance.is_admissible_for_quote() {
            return Err(UniversalPaymentError::QuoteViolation(
                "solver quote cannot carry PendingOrUnverified assurance".into(),
            ));
        }
        Ok(())
    }

    fn absorb_all_fields(&self, hasher: &mut Sha3_256) {
        hasher.update(self.intent_id);
        hasher.update(self.solver);
        hasher.update(self.input_asset_id);
        hasher.update(self.input_amount.to_le_bytes());
        hasher.update(self.output_asset_id);
        hasher.update(self.output_amount.to_le_bytes());
        hasher.update(self.valid_until_ms.to_le_bytes());
        hasher.update([self.assurance.tag()]);
    }

    /// Canonical 32-byte quote identifier binding every field.
    #[must_use]
    pub fn quote_id(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_WALLET_SOLVER_QUOTE_ID_V1");
        self.absorb_all_fields(&mut hasher);
        hasher.finalize().into()
    }

    /// Canonical 32-byte signing digest for ML-DSA-87 under `CROSS_DOMAIN_V1`.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_WALLET_SOLVER_QUOTE_SIG_V1");
        self.absorb_all_fields(&mut hasher);
        hasher.finalize().into()
    }
}

/// ML-DSA-87 signed binding solver quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSolverQuote {
    /// Quote terms committed by the solver.
    pub quote: SolverQuote,
    /// Solver ML-DSA-87 public key (`2592` bytes).
    pub solver_public_key: PublicKeyBytes,
    /// Solver ML-DSA-87 signature (`4627` bytes) under `crypto::ctx::CROSS_DOMAIN_V1`.
    pub signature: SignatureBytes,
}

impl SignedSolverQuote {
    /// Verify solver signature, expiry, and strict compliance with `intent`.
    ///
    /// # Errors
    ///
    /// Fails closed on intent mismatch, asset mismatch, short output, excessive
    /// input (exceeding `max_input_amount`), quote outliving intent, expiry,
    /// unverified assurance, or invalid ML-DSA-87 signature.
    pub fn verify_against_intent(
        &self,
        intent: &UniversalPaymentIntent,
        now_ms: u64,
    ) -> Result<[u8; 32], UniversalPaymentError> {
        intent.validate()?;
        self.quote.validate()?;

        if now_ms >= self.quote.valid_until_ms {
            return Err(UniversalPaymentError::Expired(format!(
                "quote expired at {} (now={now_ms})",
                self.quote.valid_until_ms
            )));
        }
        if self.quote.valid_until_ms > intent.expiry_ms {
            return Err(UniversalPaymentError::QuoteViolation(
                "quote valid_until_ms exceeds intent expiry_ms".into(),
            ));
        }
        if self.quote.intent_id != intent.intent_id() {
            return Err(UniversalPaymentError::QuoteViolation(
                "quote intent_id does not match target intent".into(),
            ));
        }
        if self.quote.input_asset_id != intent.max_input_asset_id {
            return Err(UniversalPaymentError::QuoteViolation(
                "quote input_asset_id does not match intent".into(),
            ));
        }
        if self.quote.output_asset_id != intent.output_asset_id {
            return Err(UniversalPaymentError::QuoteViolation(
                "quote output_asset_id does not match intent".into(),
            ));
        }
        if self.quote.output_amount < intent.output_amount {
            return Err(UniversalPaymentError::QuoteViolation(
                "quote output_amount is below intent output_amount".into(),
            ));
        }
        if self.quote.input_amount > intent.max_input_amount {
            return Err(UniversalPaymentError::QuoteViolation(
                "quote input_amount exceeds intent max_input_amount".into(),
            ));
        }
        if self.quote.input_asset_id == self.quote.output_asset_id {
            let bps_factor = 10_000u128 + u128::from(intent.max_slippage_bps);
            let max_by_slippage = self
                .quote
                .output_amount
                .checked_mul(bps_factor)
                .ok_or(UniversalPaymentError::Overflow("slippage ceiling"))?
                / 10_000u128;
            if self.quote.input_amount > max_by_slippage {
                return Err(UniversalPaymentError::QuoteViolation(
                    "quote input_amount violates intent max_slippage_bps".into(),
                ));
            }
        }

        let derived_solver = Wallet::address_from_public_key(&self.solver_public_key);
        if derived_solver != self.quote.solver {
            return Err(UniversalPaymentError::InvalidSignature(
                "solver_public_key does not derive quote.solver".into(),
            ));
        }
        let digest = self.quote.signing_digest();
        if !Wallet::verify_for(
            &self.solver_public_key,
            crypto::ctx::CROSS_DOMAIN_V1,
            &digest,
            &self.signature,
        ) {
            return Err(UniversalPaymentError::InvalidSignature(
                "ML-DSA-87 solver quote signature verification failed".into(),
            ));
        }
        Ok(self.quote.quote_id())
    }
}

/// Cryptographic payment receipt binding an executed intent, winning solver
/// quote, settlement height, and transaction hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentReceipt {
    /// Canonical intent id.
    pub intent_id: [u8; 32],
    /// Canonical winning solver quote id.
    pub quote_id: [u8; 32],
    /// Payer Budlum address.
    pub payer: BudlumAddress,
    /// Recipient Budlum address.
    pub recipient: BudlumAddress,
    /// Settled output asset id.
    pub output_asset_id: [u8; 32],
    /// Settled output amount delivered to recipient.
    pub output_amount: u128,
    /// Settlement block height (`> 0`).
    pub settlement_block_height: u64,
    /// Non-zero settlement transaction hash.
    pub settlement_tx_hash: [u8; 32],
    /// Finality assurance tier recorded at settlement.
    pub assurance: AssuranceClass,
    /// Canonical receipt digest (`BDLM_WALLET_PAYMENT_RECEIPT_V1`).
    pub receipt_id: [u8; 32],
}

impl PaymentReceipt {
    fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_WALLET_PAYMENT_RECEIPT_V1");
        hasher.update(self.intent_id);
        hasher.update(self.quote_id);
        hasher.update(self.payer);
        hasher.update(self.recipient);
        hasher.update(self.output_asset_id);
        hasher.update(self.output_amount.to_le_bytes());
        hasher.update(self.settlement_block_height.to_le_bytes());
        hasher.update(self.settlement_tx_hash);
        hasher.update([self.assurance.tag()]);
        hasher.finalize().into()
    }

    /// Construct a verified receipt from an authenticated intent + solver quote.
    ///
    /// # Errors
    ///
    /// Refuses unverified intents/quotes, zero settlement block height, or zero
    /// settlement transaction hash.
    pub fn from_verified(
        signed_intent: &SignedPaymentIntent,
        signed_quote: &SignedSolverQuote,
        settlement_block_height: u64,
        settlement_tx_hash: [u8; 32],
        now_ms: u64,
    ) -> Result<Self, UniversalPaymentError> {
        let intent_id = signed_intent.verify(now_ms)?;
        let quote_id = signed_quote.verify_against_intent(&signed_intent.intent, now_ms)?;
        if settlement_block_height == 0 {
            return Err(UniversalPaymentError::InvalidInput(
                "settlement_block_height must be > 0".into(),
            ));
        }
        if settlement_tx_hash == [0u8; 32] {
            return Err(UniversalPaymentError::InvalidInput(
                "settlement_tx_hash cannot be zero".into(),
            ));
        }

        let mut receipt = Self {
            intent_id,
            quote_id,
            payer: signed_intent.intent.payer,
            recipient: signed_intent.intent.recipient,
            output_asset_id: signed_quote.quote.output_asset_id,
            output_amount: signed_quote.quote.output_amount,
            settlement_block_height,
            settlement_tx_hash,
            assurance: signed_quote.quote.assurance,
            receipt_id: [0u8; 32],
        };
        receipt.receipt_id = receipt.compute_digest();
        Ok(receipt)
    }

    /// Re-verify this receipt against `(signed_intent, signed_quote)` fail-closed.
    ///
    /// # Errors
    ///
    /// Refuses any tampered field, mismatched intent/quote, or invalid digest.
    pub fn verify(
        &self,
        signed_intent: &SignedPaymentIntent,
        signed_quote: &SignedSolverQuote,
        now_ms: u64,
    ) -> Result<(), UniversalPaymentError> {
        let expected = Self::from_verified(
            signed_intent,
            signed_quote,
            self.settlement_block_height,
            self.settlement_tx_hash,
            now_ms,
        )?;
        if *self != expected {
            return Err(UniversalPaymentError::ProofMismatch(
                "payment receipt fields or digest do not match verified intent and quote".into(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// `.bud` Address-Bar Lookalike / Punycode Safety & Proof Resolution
// ============================================================================

/// Non-fatal visual-lookalike warning surfaced on the wallet confirmation screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfusableWarning {
    /// Target `.bud` name shares an ASCII visual skeleton with a known contact.
    LookalikeContact {
        /// The trusted contact `.bud` name that this recipient visually resembles.
        similar_to: String,
    },
}

/// Deterministic ASCII visual skeleton for `.bud` labels:
/// folds common lookalike pairs (`0->o`, `1->l`, `i->l`, `rn->m`, `vv->w`, `cl->d`)
/// and drops hyphens so visually similar phishing names collide with trusted contacts.
fn ascii_visual_skeleton(name: &str) -> String {
    let base = name.strip_suffix(".bud").unwrap_or(name);
    let mut single_folded = String::with_capacity(base.len());
    for ch in base.chars() {
        match ch {
            '0' => single_folded.push('o'),
            '1' | 'i' => single_folded.push('l'),
            '-' => {}
            other => single_folded.push(other),
        }
    }
    single_folded
        .replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
}

/// Validate `.bud` address-bar safety and detect lookalike collisions against
/// `known_contacts`.
///
/// # Errors
///
/// Refuses invalid `.bud` names, non-ASCII/control characters, and any label
/// beginning with the punycode ACE prefix `xn--` (address-bar spoofing).
pub fn check_bud_name_address_bar_safety(
    name: &str,
    known_contacts: &[&str],
) -> Result<Vec<ConfusableWarning>, UniversalPaymentError> {
    if !bns::is_valid_resolvable_bud_name(name) {
        return Err(UniversalPaymentError::UnsafeBudRecipient(format!(
            "invalid .bud name '{name}'"
        )));
    }
    let stem = name.strip_suffix(".bud").unwrap_or(name);
    for label in stem.split('.') {
        if label.starts_with("xn--") {
            return Err(UniversalPaymentError::UnsafeBudRecipient(format!(
                "punycode ACE label '{label}' is refused in .bud address bar"
            )));
        }
    }

    let target_skeleton = ascii_visual_skeleton(name);
    let mut warnings = Vec::new();
    let mut seen_contacts: BTreeSet<&str> = BTreeSet::new();
    for contact in known_contacts {
        if *contact == name || !bns::is_valid_resolvable_bud_name(contact) {
            continue;
        }
        if !seen_contacts.insert(*contact) {
            continue;
        }
        if ascii_visual_skeleton(contact) == target_skeleton {
            warnings.push(ConfusableWarning::LookalikeContact {
                similar_to: (*contact).to_string(),
            });
        }
    }
    Ok(warnings)
}

/// Verified `.bud` payment recipient combining header-anchored BNS Merkle proof
/// authentication with address-bar lookalike warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBudRecipient {
    /// Canonical `.bud` name.
    pub name: String,
    /// Authenticated 32-byte settlement target address.
    pub address: BudlumAddress,
    /// Visual lookalike warnings against the user's known contacts.
    pub warnings: Vec<ConfusableWarning>,
}

/// Verify a `.bud` payment recipient against a trusted BNS header book and
/// evaluate address-bar lookalike safety against `known_contacts`.
///
/// # Errors
///
/// Fails closed if the name violates address-bar safety (including `xn--`) or
/// if the BNS Merkle proof fails header-anchored verification.
pub fn resolve_and_check_bud_payment_recipient<S: BnsHeaderSource + ?Sized>(
    name: &str,
    claimed_target: &BudlumAddress,
    proof: &WalletBnsProof,
    headers: &S,
    known_contacts: &[&str],
) -> Result<ResolvedBudRecipient, UniversalPaymentError> {
    let warnings = check_bud_name_address_bar_safety(name, known_contacts)?;
    let address = bns::verify_bns_recipient_proof_from_header(name, claimed_target, proof, headers)
        .map_err(UniversalPaymentError::UnsafeBudRecipient)?;
    Ok(ResolvedBudRecipient {
        name: name.to_string(),
        address,
        warnings,
    })
}
