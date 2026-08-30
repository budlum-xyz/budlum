// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe` block
// enters, compilation FAILS (regression gate). Same policy as the main crate.
#![forbid(unsafe_code)]
//! Budlum Wallet Core - BIP39 mnemonic + FIPS 204 ML-DSA-87 post-quantum key derivation + signing.
//!
//! The signing scheme is ML-DSA-87 (NIST FIPS 204, Category 5, formerly
//! CRYSTALS-Dilithium5). It is the same parameter set validators use for the
//! post-quantum leg of hybrid finality, so user and validator signatures sit
//! at one security level. The 32-byte seed is hashed through a domain-separated
//! SHA3-256 and then expanded by ML-DSA's `KeyGen_internal`; this is a
//! hardened-only derivation (non-hardened public derivation is not defined for
//! ML-DSA and is intentionally absent).
//!
//! **Permissionless relayer rule (see README):** this crate is a WALLET,
//! not a RELAYER. The wallet produces signatures; the user sends the signed transaction to any
//! permissionless relayer (secured by stake + slashing). wallet-core contains NO
//! relayer registration/stake/whitelist code.
//!
//! ## Usage
//!
//! `Wallet::generate` needs the `production` feature, which is what wires in
//! the OS CSPRNG; without it the call fails closed rather than deriving a key
//! from predictable entropy. The example below therefore starts from fixed
//! entropy, which runs everywhere and never suggests that a wallet built this
//! way is safe to hold funds.
//!
//! ```rust
//! use budlum_wallet_core::{Wallet, WalletPrivacyConfig, ML_DSA_87_SIGNATURE_LEN};
//!
//! // Fixed entropy: reproducible, and never a real wallet.
//! let mut wallet = Wallet::from_entropy(&[1u8; 16]).unwrap();
//! assert_eq!(wallet.mnemonic().split_whitespace().count(), 12);
//! assert_eq!(wallet.address_hex().len(), 64);
//!
//! // Signing is what the wallet is for; the relayer it is handed to is not
//! // trusted with anything but delivery.
//! let sig = wallet.sign(b"message to sign");
//! assert_eq!(sig.len(), ML_DSA_87_SIGNATURE_LEN);
//!
//! // Opt-in note privacy, TEE left off.
//! wallet.set_privacy_config(WalletPrivacyConfig::note_privacy_only(true));
//! ```
//!
//! ## Confidentiality
//!
//! - `note_privacy_enabled`: produces a private transfer intent (the PrivacyCommit path).
//! - `tee_enabled`: execution-time confidentiality - **fail-closed** without a
//!   Linked SGX/Nitro runtime (no silent plaintext fallback).

mod bip39_wordlist;
mod privacy_crypto;
mod privacy_transfer;
mod tee;

pub use privacy_crypto::{
    address_to_recipient_tag, field_from_hash, hash_from_field, is_packed, poseidon4_hash,
    poseidon4_hash3, privacy_commit, privacy_nullifier, DOMAIN_NULLIFIER,
};
pub use privacy_transfer::{
    derive_blinding, derive_spend_secret, PrivateNoteInput, PrivateNoteOutput,
    PrivateTransferIntent, PrivateTransferRequest,
};
pub use tee::{
    TeeAttestation, TeeBackendKind, TeeQuoteVerifier, TeeQuoter, TeeRuntime, TeeRuntimeStatus,
    UnavailableTeeQuoteVerifier, UnavailableTeeRuntime,
};

use ml_dsa::{
    EncodedSignature, KeyInit, MlDsa87, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use zeroize::Zeroize;

/// ML-DSA-87 (FIPS 204, Category 5) public key length in bytes.
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
/// ML-DSA-87 encoded signature length in bytes (FIPS 204 final).
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;
/// ML-DSA-87 seed length in bytes (32-byte xi input to KeyGen_internal).
pub const ML_DSA_87_SEED_LEN: usize = 32;
/// Wire version prefix for an ML-DSA-87 signature.
pub const SIGNATURE_VERSION_V5: u8 = 0x05;
/// Wire version prefix for an ML-DSA-87 public key inside an address domain.
pub const ADDRESS_VERSION_V2: u8 = 0x02;
/// Maximum number of distinct owners in a multisig policy (16 × 4627 B ≈ 74 KB).
pub const MAX_MULTISIG_OWNERS: usize = 16;

/// Wallet error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    /// Invalid mnemonic (word count, checksum).
    InvalidMnemonic(String),
    /// Invalid entropy size.
    InvalidEntropy(usize),
    /// Invalid seed.
    InvalidSeed,
    /// Invalid multisig policy.
    InvalidMultisigPolicy(String),
    /// Invalid social recovery policy.
    InvalidRecoveryPolicy(String),
    /// Invalid social recovery proposal.
    InvalidRecoveryProposal(String),
    /// Production entropy (CSPRNG) unavailable, fail-closed.
    ProductionEntropyUnavailable(String),
    /// Note privacy / private transfer builder error.
    InvalidPrivateTransfer(String),
    /// TEE opt-in is on but no runtime is available - fail-closed (no silent plaintext).
    TeeUnavailable(String),
    /// A private transfer was requested while note privacy is off.
    NotePrivacyDisabled,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::InvalidMnemonic(m) => write!(f, "invalid mnemonic: {m}"),
            WalletError::InvalidEntropy(n) => {
                write!(f, "invalid entropy size: {n} bytes (expected 16 or 32)")
            }
            WalletError::InvalidSeed => write!(f, "invalid seed"),
            WalletError::InvalidMultisigPolicy(m) => write!(f, "invalid multisig policy: {m}"),
            WalletError::InvalidRecoveryPolicy(m) => write!(f, "invalid recovery policy: {m}"),
            WalletError::InvalidRecoveryProposal(m) => {
                write!(f, "invalid recovery proposal: {m}")
            }
            WalletError::ProductionEntropyUnavailable(m) => {
                write!(f, "production entropy unavailable: {m}")
            }
            WalletError::InvalidPrivateTransfer(m) => {
                write!(f, "invalid private transfer: {m}")
            }
            WalletError::TeeUnavailable(m) => write!(f, "TEE unavailable: {m}"),
            WalletError::NotePrivacyDisabled => write!(
                f,
                "note privacy disabled - enable WalletPrivacyConfig::note_privacy_enabled"
            ),
        }
    }
}

impl std::error::Error for WalletError {}

/// BIP39 mnemonic → entropy (entropy → checksum → mnemonic).
/// SHA256 checksum: the first (entropy_bits / 32) bits are appended as checksum.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, WalletError> {
    let entropy_len = entropy.len();
    if entropy_len != 16 && entropy_len != 32 {
        return Err(WalletError::InvalidEntropy(entropy_len));
    }

    let entropy_bits = entropy_len * 8;
    let checksum_bits = entropy_bits / 32;
    let total_bits = entropy_bits + checksum_bits;
    let word_count = total_bits / 11;

    // SHA256 hash for checksum
    let hash = Sha256::digest(entropy);
    let checksum_byte = hash[0];

    // Build bit array: entropy bits + checksum bits
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for byte in entropy {
        for i in (0u8..8).rev() {
            bits.push((*byte >> i) & 1u8);
        }
    }
    // Append checksum bits (first `checksum_bits` MSBs of hash)
    for i in (0u8..checksum_bits as u8).rev() {
        bits.push((checksum_byte >> (8 - checksum_bits + i as usize)) & 1u8);
    }

    // Convert 11-bit groups to word indices
    let mut words = Vec::with_capacity(word_count);
    for i in 0..word_count {
        let mut index = 0u16;
        for j in 0..11 {
            index = (index << 1) | (bits[i * 11 + j] as u16);
        }
        let word = bip39_wordlist::index_to_word(index as usize).ok_or_else(|| {
            WalletError::InvalidMnemonic(format!("word index {index} out of range"))
        })?;
        words.push(word);
    }

    Ok(words.join(" "))
}

/// BIP39 mnemonic → entropy (reverse: checksum validation + entropy extraction).
pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>, WalletError> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.len() != 12 && words.len() != 24 {
        return Err(WalletError::InvalidMnemonic(format!(
            "expected 12 or 24 words, got {}",
            words.len()
        )));
    }

    let entropy_bits = words.len() * 32 / 3; // 128 or 256
    let checksum_bits = entropy_bits / 32; // 4 or 8
    let total_bits = entropy_bits + checksum_bits;

    // Convert words to indices
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for word in &words {
        let idx = bip39_wordlist::word_to_index(word)
            .ok_or_else(|| WalletError::InvalidMnemonic(format!("unknown word: {word}")))?;
        for i in (0u8..11).rev() {
            bits.push(((idx >> i) & 1) as u8);
        }
    }

    // Extract entropy and checksum
    let mut entropy = Vec::with_capacity(entropy_bits / 8);
    for i in 0..(entropy_bits / 8) {
        let mut byte = 0u8;
        for j in 0..8 {
            byte = (byte << 1) | (bits[i * 8 + j] as u8);
        }
        entropy.push(byte);
    }

    // Extract checksum
    let mut checksum = 0u8;
    for j in 0..checksum_bits {
        checksum = (checksum << 1) | (bits[entropy_bits + j] as u8);
    }

    // Verify checksum
    let hash = Sha256::digest(&entropy);
    let expected_checksum = hash[0] >> (8 - checksum_bits);
    if checksum != expected_checksum {
        return Err(WalletError::InvalidMnemonic(
            "checksum mismatch - invalid mnemonic".into(),
        ));
    }

    Ok(entropy)
}

/// An ML-DSA-87 public key (2592 bytes, FIPS 204 encoded).
pub type PublicKeyBytes = [u8; ML_DSA_87_PUBLIC_KEY_LEN];

/// An ML-DSA-87 encoded signature (4627 bytes, FIPS 204 final).
pub type SignatureBytes = [u8; ML_DSA_87_SIGNATURE_LEN];

/// Construct an ML-DSA-87 signing key deterministically from a 32-byte seed.
///
/// The seed is the 32-byte `xi` input to `ML-DSA.KeyGen_internal` (FIPS 204
/// Algorithm 6). In this wallet it is the domain-separated SHA3-256 of the
/// BIP39 entropy (see [`Wallet::from_entropy`]), not the entropy itself, so
/// two wallets that happen to share a BIP39 phrase with another chain cannot
/// produce the same ML-DSA key.
fn signing_key_from_seed(seed: &[u8; ML_DSA_87_SEED_LEN]) -> SigningKey<MlDsa87> {
    SigningKey::<MlDsa87>::from_seed(seed.into())
}

/// Encode a signing key's 2592-byte public key.
fn verifying_key_bytes(sk: &SigningKey<MlDsa87>) -> PublicKeyBytes {
    let vk: &VerifyingKey<MlDsa87> = sk.as_ref();
    let enc = vk.encode();
    let mut out = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
    out.copy_from_slice(enc.as_ref());
    out
}

/// Sign a message with an ML-DSA-87 signing key and return the 4627-byte
/// encoded signature.
fn sign_message(sk: &SigningKey<MlDsa87>, message: &[u8]) -> SignatureBytes {
    let sig: Signature<MlDsa87> = sk.sign(message);
    let enc: EncodedSignature<MlDsa87> = sig.encode();
    let mut out = [0u8; ML_DSA_87_SIGNATURE_LEN];
    out.copy_from_slice(enc.as_ref());
    out
}

/// Verify an ML-DSA-87 signature against a 2592-byte public key.
///
/// Returns `false` on any malformed input rather than returning an error: the
/// multisig and social-recovery paths treat an invalid signature as "this
/// approval does not count" and the caller's threshold logic does the rest.
fn verify_signature(
    public_key: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> bool {
    let vk = VerifyingKey::<MlDsa87>::new(public_key.into());
    let Ok(sig) = Signature::<MlDsa87>::try_from(signature.as_slice()) else {
        return false;
    };
    vk.verify(message, &sig).is_ok()
}

/// Guardian-based social recovery policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocialRecoveryPolicy {
    pub guardians: Vec<PublicKeyBytes>,
    pub threshold: usize,
    pub timelock_blocks: u64,
}

/// One guardian approval over a recovery proposal digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianApproval {
    pub public_key: PublicKeyBytes,
    pub signature: SignatureBytes,
}

/// Immutable social recovery proposal bound to the old and new owner keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProposal {
    pub current_owner: PublicKeyBytes,
    pub current_address: BudlumAddress,
    pub new_owner: PublicKeyBytes,
    pub new_address: BudlumAddress,
    pub created_block: u64,
    pub executable_after: u64,
}

impl RecoveryProposal {
    pub fn new(
        current_owner: PublicKeyBytes,
        new_owner: PublicKeyBytes,
        policy: &SocialRecoveryPolicy,
        created_block: u64,
    ) -> Result<Self, WalletError> {
        if current_owner == new_owner {
            return Err(WalletError::InvalidRecoveryProposal(
                "new owner must differ from current owner".into(),
            ));
        }
        let executable_after = created_block
            .checked_add(policy.timelock_blocks)
            .ok_or_else(|| WalletError::InvalidRecoveryProposal("timelock overflow".into()))?;
        Ok(Self {
            current_address: Wallet::address_from_public_key(&current_owner),
            new_address: Wallet::address_from_public_key(&new_owner),
            current_owner,
            new_owner,
            created_block,
            executable_after,
        })
    }

    /// Domain-separated digest guardians must sign for this proposal.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_WALLET_RECOVERY_PROPOSAL_V1");
        hasher.update(&self.current_owner);
        hasher.update(&self.current_address);
        hasher.update(&self.new_owner);
        hasher.update(&self.new_address);
        hasher.update(&self.created_block.to_be_bytes());
        hasher.update(&self.executable_after.to_be_bytes());
        hasher.finalize().into()
    }

    #[must_use]
    pub fn is_timelock_satisfied(&self, current_block: u64) -> bool {
        current_block >= self.executable_after
    }

    #[must_use]
    pub fn verify_guardian_approvals(
        &self,
        policy: &SocialRecoveryPolicy,
        approvals: &[GuardianApproval],
    ) -> bool {
        policy.verify_recovery_threshold(&self.digest(), approvals)
    }

    #[must_use]
    pub fn is_executable(
        &self,
        policy: &SocialRecoveryPolicy,
        approvals: &[GuardianApproval],
        current_block: u64,
    ) -> bool {
        self.is_timelock_satisfied(current_block)
            && self.verify_guardian_approvals(policy, approvals)
    }
}

impl SocialRecoveryPolicy {
    pub fn new(
        mut guardians: Vec<PublicKeyBytes>,
        threshold: usize,
        timelock_blocks: u64,
    ) -> Result<Self, WalletError> {
        guardians.sort();
        guardians.dedup();
        if guardians.is_empty() {
            return Err(WalletError::InvalidRecoveryPolicy("guardians empty".into()));
        }
        if guardians.len() > MAX_MULTISIG_OWNERS {
            return Err(WalletError::InvalidRecoveryPolicy(format!(
                "guardian count {} exceeds MAX_MULTISIG_OWNERS ({MAX_MULTISIG_OWNERS})",
                guardians.len()
            )));
        }
        if threshold == 0 || threshold > guardians.len() {
            return Err(WalletError::InvalidRecoveryPolicy(format!(
                "threshold {threshold} outside 1..={}",
                guardians.len()
            )));
        }
        if timelock_blocks == 0 {
            return Err(WalletError::InvalidRecoveryPolicy(
                "timelock_blocks must be non-zero".into(),
            ));
        }
        Ok(Self {
            guardians,
            threshold,
            timelock_blocks,
        })
    }

    pub fn verify_recovery_threshold(
        &self,
        recovery_digest: &[u8],
        approvals: &[GuardianApproval],
    ) -> bool {
        let mut seen = Vec::<PublicKeyBytes>::new();
        for approval in approvals {
            if !self.guardians.contains(&approval.public_key) {
                continue;
            }
            if seen.contains(&approval.public_key) {
                continue;
            }
            if verify_signature(&approval.public_key, recovery_digest, &approval.signature) {
                seen.push(approval.public_key);
            }
        }
        seen.len() >= self.threshold
    }

    #[must_use]
    pub fn guardian_count(&self) -> usize {
        self.guardians.len()
    }

    pub fn rotate_guardian(
        &self,
        old_guardian: PublicKeyBytes,
        new_guardian: PublicKeyBytes,
    ) -> Result<Self, WalletError> {
        if old_guardian == new_guardian {
            return Err(WalletError::InvalidRecoveryPolicy(
                "new guardian must differ from old guardian".into(),
            ));
        }
        if !self.guardians.contains(&old_guardian) {
            return Err(WalletError::InvalidRecoveryPolicy(
                "old guardian is not in policy".into(),
            ));
        }
        if self.guardians.contains(&new_guardian) {
            return Err(WalletError::InvalidRecoveryPolicy(
                "new guardian already exists in policy".into(),
            ));
        }
        let mut guardians = self.guardians.clone();
        for guardian in &mut guardians {
            if *guardian == old_guardian {
                *guardian = new_guardian;
                break;
            }
        }
        Self::new(guardians, self.threshold, self.timelock_blocks)
    }

    pub fn remove_guardian(&self, guardian: PublicKeyBytes) -> Result<Self, WalletError> {
        if !self.guardians.contains(&guardian) {
            return Err(WalletError::InvalidRecoveryPolicy(
                "guardian is not in policy".into(),
            ));
        }
        let guardians = self
            .guardians
            .iter()
            .copied()
            .filter(|existing| *existing != guardian)
            .collect::<Vec<_>>();
        Self::new(guardians, self.threshold, self.timelock_blocks)
    }
}

/// Budlum wallet: BIP39 mnemonic → ML-DSA-87 seed → Address + Signing.
///
/// Privacy is **opt-in** via [`WalletPrivacyConfig`] (default all-off).
pub struct Wallet {
    mnemonic: String,
    seed: [u8; ML_DSA_87_SEED_LEN],
    signing_key: SigningKey<MlDsa87>,
    /// Per-wallet privacy preferences (note path + TEE toggle + view-key).
    privacy: WalletPrivacyConfig,
    /// The enclave measurement (MRENCLAVE / Nitro PCR0) this wallet deploys
    /// and therefore trusts. `None` = not enrolled: TEE signing stays
    /// fail-closed. A self-attesting software runtime can echo any
    /// `report_data`, so binding the digest alone proves nothing about where
    /// the seal happened; the measurement is the wallet's root of trust
    /// (CWE-347).
    trusted_tee_measurement: Option<[u8; 32]>,
    /// The smallest blinding counter this wallet will still hand out. Two notes
    /// that share a blinding share a commitment, which both links them on-chain
    /// and can make the second one unspendable, so a counter may only be used
    /// once even though the caller picks it.
    next_blinding_counter: u64,
}

// Zeroize sensitive material on drop.
// Prevents seed/mnemonic lingering in memory after Wallet is dropped.
// The ML-DSA signing key is zeroized separately so its expanded private
// state does not outlive the wallet either.
impl Drop for Wallet {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
        self.seed.zeroize();
    }
}

/// Budlum Address = ML-DSA-87 pubkey'nin domain-separated SHA3-256 hash'i (32 byte).
/// `core::address::Address` deseni ile uyumlu.
pub type BudlumAddress = [u8; 32];

/// (2026-07-22) in-wallet privacy surface.
///
/// Two independent opt-in layers (user plan + mainnet decisions):
/// 1. **Note privacy (network option):** the private transfer opcode family
///    (PrivacyCommit/NullifierCheck/SumConservation). A "use private transactions"
///    preference in the user wallet; off by default.
/// 2. **TEE execution-time confidentiality (section 10 #5):** transaction construction
///    runs through a TEE enclave - the operator sees no plaintext. UX prompt:
///    "Should this wallet's transactions be made confidential with the TEE layer?
///    Yes (your transactions get a bit slower)." Off by default.
///
/// View key (section 10 #3, Zcash pattern): the user generates and stores it; presented
/// manually to an authority such as a regulator. Closed to the public, open to the authority: selective disclosure.
///
/// A real TEE enclave (SGX/Nitro) is a separate integration track; this struct holds the preference +
/// view-key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPrivacyConfig {
    /// Whether network-level private transfer (the note/UTXO opcode family) is used.
    /// Default `false` - the user enables it in wallet settings (an option for the network).
    pub note_privacy_enabled: bool,
    /// TEE confidentiality toggle. `false` = default (current flow, the operator sees the data,
    /// only STARK integrity). `true` = transactions are confidential via TEE (slower).
    pub tee_enabled: bool,
    /// Whether client-side TEE is preferred. `true` = the user device first (laptop SGX),
    /// falling back to server-side (AWS Nitro) on failure. `false` = server-side directly.
    pub prefer_client_side_tee: bool,
    /// User-generated view key (32 bytes). `None` = not generated yet.
    /// Shared manually with an authority for selective disclosure; never written to the chain.
    pub view_key: Option<[u8; 32]>,
}

impl Default for WalletPrivacyConfig {
    fn default() -> Self {
        // Section 10 #5 + user plan: OFF by default (opt-in).
        Self {
            note_privacy_enabled: false,
            tee_enabled: false,
            prefer_client_side_tee: true,
            view_key: None,
        }
    }
}

impl WalletPrivacyConfig {
    /// Answer to the toggle prompt (section 10 #5 UX): "Should this wallet's transactions be made
    /// confidential with the TEE layer?" -> `enable`.
    #[must_use]
    pub fn from_user_opt_in(enable: bool) -> Self {
        Self {
            note_privacy_enabled: enable,
            tee_enabled: enable,
            prefer_client_side_tee: true,
            view_key: None,
        }
    }

    /// Network-level note privacy only (TEE off), the lighter option.
    #[must_use]
    pub fn note_privacy_only(enable: bool) -> Self {
        Self {
            note_privacy_enabled: enable,
            tee_enabled: false,
            prefer_client_side_tee: true,
            view_key: None,
        }
    }

    /// Whether TEE confidentiality is active (the slowdown warning applies in this case).
    #[must_use]
    pub fn is_privacy_active(&self) -> bool {
        self.tee_enabled
    }

    /// Whether note privacy (the private transfer opcodes) is active.
    #[must_use]
    pub fn is_note_privacy_active(&self) -> bool {
        self.note_privacy_enabled
    }

    /// The TEE backend to use (client-side-first decision logic).
    /// `"client"` (device SGX) | `"server"` (AWS Nitro) | `"none"` (TEE off).
    #[must_use]
    pub fn effective_backend(&self) -> &'static str {
        if !self.tee_enabled {
            "none"
        } else if self.prefer_client_side_tee {
            "client"
        } else {
            "server"
        }
    }

    /// Generate a view key (section 10 #3). Deterministic derivation from the wallet seed.
    /// Domain-separated SHA3-256("BUDLUM_VIEW_KEY_V1" || seed).
    /// If a view key already exists it is left unchanged (idempotent); to force a refresh
    /// `rotate_view_key`.
    pub fn ensure_view_key(&mut self, wallet_seed: &[u8; 32]) -> [u8; 32] {
        if let Some(vk) = self.view_key {
            return vk;
        }
        let vk = derive_view_key(wallet_seed);
        self.view_key = Some(vk);
        vk
    }

    /// Regenerate the view key (rotation after the old key has been handed to an authority).
    pub fn rotate_view_key(&mut self, wallet_seed: &[u8; 32], rotation_counter: u64) -> [u8; 32] {
        let vk = derive_view_key_rotated(wallet_seed, rotation_counter);
        self.view_key = Some(vk);
        vk
    }

    /// View-key disclosure package (shared manually with an authority). Never written to the chain.
    /// `None` if the view key has not been generated yet.
    #[must_use]
    pub fn export_view_key_for_disclosure(&self) -> Option<ViewKeyDisclosure> {
        self.view_key.map(|key| ViewKeyDisclosure {
            version: VIEW_KEY_VERSION,
            view_key: key,
        })
    }
}

/// View-key format version (selective disclosure protocol).
pub const VIEW_KEY_VERSION: u32 = 1;

/// The view-key package presented to an authority (section 10 #3).
/// Closed to the public; delivered manually from the user wallet to the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewKeyDisclosure {
    pub version: u32,
    pub view_key: [u8; 32],
}

impl ViewKeyDisclosure {
    /// Hex export (for user copy-paste / QR).
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("vk1:{}:{}", self.version, hex::encode(self.view_key))
    }

    /// Hex import; bozuk format → None.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("vk1:")?;
        let (ver, key_hex) = rest.split_once(':')?;
        let version: u32 = ver.parse().ok()?;
        if version != VIEW_KEY_VERSION {
            return None;
        }
        let bytes = hex::decode(key_hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut view_key = [0u8; 32];
        view_key.copy_from_slice(&bytes);
        Some(Self { version, view_key })
    }
}

/// Domain-separated view-key derivation from wallet seed.
fn derive_view_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BUDLUM_VIEW_KEY_V1");
    hasher.update(seed);
    let out = hasher.finalize();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&out);
    vk
}

fn derive_view_key_rotated(seed: &[u8; 32], rotation_counter: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BUDLUM_VIEW_KEY_V1_ROT");
    hasher.update(seed);
    hasher.update(rotation_counter.to_le_bytes());
    let out = hasher.finalize();
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&out);
    vk
}

/// Mobile/browser binding ABI marker.
pub const WALLET_BINDING_STUB_VERSION: &str = "task11.14-binding-stub-v1";

/// What the mobile and browser bindings can actually do today.
///
/// The two flags used to be hard-coded `true`, which read as "mobile and
/// browser are wired up". Measured, neither was: the `uniffi_bindings` module
/// contains one function that returns this same struct, `wasm_bindings` is
/// identical, there is no `.udl` file anywhere in the tree, and
/// `#[wasm_bindgen]` appears on nothing. No wallet operation is exposed to
/// either host. The struct was describing the presence of a module, not the
/// presence of a binding.
///
/// That distinction matters because this is a capability descriptor. Something
/// reading `uniffi_mobile == true` would reasonably conclude it can call the
/// wallet from Kotlin or Swift, and it cannot. A flag that is always true
/// carries no information and a caller cannot tell the difference between "not
/// implemented" and "implemented and reporting itself".
///
/// The flags now say what is true: the feature gates compile, and no operation
/// crosses them. `bindings_are_wired` is the field to flip when a `.udl` or a
/// `#[wasm_bindgen]` export actually lands, and
/// `check-binding-claims-match-reality.sh` fails if it is flipped without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletBindingCapabilities {
    pub stub_version: String,
    /// The `uniffi` feature exists and compiles. It exports no wallet call.
    pub uniffi_feature_compiles: bool,
    /// The `wasm` feature exists and compiles. It exports no wallet call.
    pub wasm_feature_compiles: bool,
    /// True only when a real binding surface exists: a UniFFI interface
    /// definition, or a `#[wasm_bindgen]` export of a wallet operation.
    pub bindings_are_wired: bool,
    pub exports_seed_material: bool,
}

impl WalletBindingCapabilities {
    #[must_use]
    pub fn current() -> Self {
        Self {
            stub_version: WALLET_BINDING_STUB_VERSION.to_string(),
            uniffi_feature_compiles: true,
            wasm_feature_compiles: true,
            // No `.udl`, no `#[wasm_bindgen]` export. Flipping this without
            // one is what the gate is there to catch.
            bindings_are_wired: false,
            exports_seed_material: false,
        }
    }
}

/// FFI-safe wallet public export; mnemonic seed/private key material is redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletBindingExport {
    pub address_hex: String,
    pub public_key_hex: String,
    pub mnemonic_word_count: usize,
}

#[cfg(feature = "uniffi")]
pub mod uniffi_bindings {
    use super::WalletBindingCapabilities;

    #[must_use]
    pub fn binding_capabilities() -> WalletBindingCapabilities {
        WalletBindingCapabilities::current()
    }
}

#[cfg(feature = "wasm")]
pub mod wasm_bindings {
    use super::WalletBindingCapabilities;

    #[must_use]
    pub fn binding_capabilities() -> WalletBindingCapabilities {
        WalletBindingCapabilities::current()
    }
}

/// M-of-N multisig policy.
///
/// Each owner is an ML-DSA-87 public key (2592 bytes). At most
/// [`MAX_MULTISIG_OWNERS`] owners are accepted: at 16 owners a fully-signed
/// approval set is ~74 KB of signatures, which keeps the resulting
/// transaction within block-size budgets while still covering the
/// institutional use cases (3-of-5, 5-of-9, 10-of-15) a self-custodial
/// wallet needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigPolicy {
    pub owners: Vec<PublicKeyBytes>,
    pub threshold: usize,
}

/// One owner approval over a proposal digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigApproval {
    pub public_key: PublicKeyBytes,
    pub signature: SignatureBytes,
}

impl MultisigPolicy {
    pub fn new(mut owners: Vec<PublicKeyBytes>, threshold: usize) -> Result<Self, WalletError> {
        owners.sort();
        owners.dedup();
        if owners.is_empty() {
            return Err(WalletError::InvalidMultisigPolicy("owners empty".into()));
        }
        if owners.len() > MAX_MULTISIG_OWNERS {
            return Err(WalletError::InvalidMultisigPolicy(format!(
                "owner count {} exceeds MAX_MULTISIG_OWNERS ({MAX_MULTISIG_OWNERS})",
                owners.len()
            )));
        }
        if threshold == 0 || threshold > owners.len() {
            return Err(WalletError::InvalidMultisigPolicy(format!(
                "threshold {threshold} outside 1..={}",
                owners.len()
            )));
        }
        Ok(Self { owners, threshold })
    }

    pub fn owner_count(&self) -> usize {
        self.owners.len()
    }

    pub fn verify_threshold(&self, message: &[u8], approvals: &[MultisigApproval]) -> bool {
        let mut seen = Vec::<PublicKeyBytes>::new();
        for approval in approvals {
            if !self.owners.contains(&approval.public_key) {
                continue;
            }
            if seen.contains(&approval.public_key) {
                continue;
            }
            if verify_signature(&approval.public_key, message, &approval.signature) {
                seen.push(approval.public_key);
            }
        }
        seen.len() >= self.threshold
    }
}

impl Wallet {
    /// Create a new wallet (random entropy -> mnemonic -> seed -> keypair).
    ///
    /// `word_count`: 12 (128-bit entropy) or 24 (256-bit entropy).
    ///
    /// **Production safety:** this function only works when the `production` feature
    /// is enabled. Without it `Wallet::generate` returns
    /// **fail-closed** - placeholder/deterministic entropy never leaks into a production
    /// environment. Use `from_entropy` for test/dev environments.
    pub fn generate(word_count: usize) -> Result<Self, WalletError> {
        let entropy_len = match word_count {
            12 => 16, // 128 bit
            24 => 32, // 256 bit
            _ => return Err(WalletError::InvalidEntropy(word_count * 4 / 3)),
        };

        // Production CSPRNG: real random entropy via getrandom
        #[cfg(feature = "production")]
        let entropy = {
            let mut buf = vec![0u8; entropy_len];
            getrandom::getrandom(&mut buf)
                .map_err(|e| WalletError::ProductionEntropyUnavailable(e.to_string()))?;
            buf
        };

        // Production feature olmadan generate fail-closed
        #[cfg(not(feature = "production"))]
        let _ = entropy_len; // touch entropy_len (avoid a compile warning)

        #[cfg(not(feature = "production"))]
        {
            return Err(WalletError::ProductionEntropyUnavailable(
                "Wallet::generate requires the 'production' feature for real CSPRNG entropy. \
                 Use Wallet::from_entropy() for test/dev, or build with --features production."
                    .into(),
            ));
        }

        #[cfg(feature = "production")]
        Self::from_entropy(&entropy)
    }

    /// Build a wallet from entropy (BIP39 mnemonic + ML-DSA-87 seed).
    ///
    /// **Production note:** `from_entropy` is designed for test/dev.
    /// Use `Wallet::generate` for production wallet generation
    /// (production feature + getrandom CSPRNG gerektirir).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, WalletError> {
        if entropy.len() != 16 && entropy.len() != 32 {
            return Err(WalletError::InvalidEntropy(entropy.len()));
        }

        // BIP39 mnemonic: tam wordlist + SHA256 checksum
        let mnemonic = entropy_to_mnemonic(entropy)?;

        // ML-DSA-87 seed: domain-separated SHA3-256 over BIP39 entropy.
        // The domain separator differs from the retired Ed25519 wallet so a
        // phrase shared across chains cannot collide on this scheme, and
        // hardened-only seed expansion matches FIPS 204 KeyGen_internal.
        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_MLDSA87_SEED_V1");
        hasher.update(entropy);
        let seed_bytes = hasher.finalize();

        let mut seed = [0u8; ML_DSA_87_SEED_LEN];
        seed.copy_from_slice(&seed_bytes);

        let signing_key = signing_key_from_seed(&seed);

        Ok(Self {
            mnemonic,
            seed,
            signing_key,
            privacy: WalletPrivacyConfig::default(),
            trusted_tee_measurement: None,
            next_blinding_counter: 0,
        })
    }

    /// Restore a wallet from a mnemonic (with BIP39 checksum verification).
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, WalletError> {
        // BIP39 reverse: mnemonic -> entropy (with checksum verification)
        let entropy = mnemonic_to_entropy(mnemonic)?;

        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_MLDSA87_SEED_V1");
        hasher.update(&entropy);
        let seed_bytes = hasher.finalize();

        let mut seed = [0u8; ML_DSA_87_SEED_LEN];
        seed.copy_from_slice(&seed_bytes);

        let signing_key = signing_key_from_seed(&seed);

        Ok(Self {
            mnemonic: mnemonic.to_string(),
            seed,
            signing_key,
            privacy: WalletPrivacyConfig::default(),
            trusted_tee_measurement: None,
            next_blinding_counter: 0,
        })
    }

    /// Return the mnemonic words.
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// ML-DSA-87 public key (2592 byte).
    #[must_use]
    pub fn public_key(&self) -> PublicKeyBytes {
        verifying_key_bytes(&self.signing_key)
    }

    /// Budlum Address hesapla (ML-DSA-87 pubkey → domain-separated SHA3-256).
    ///
    /// The V2 domain separator keeps addresses distinct from any retired
    /// Ed25519-derived bytes so a legacy key cannot be presented as V2.
    #[must_use]
    pub fn address_from_public_key(public_key: &PublicKeyBytes) -> BudlumAddress {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_ADDRESS_V2");
        hasher.update(public_key);
        hasher.finalize().into()
    }

    /// Budlum Address (ML-DSA-87 pubkey → SHA3-256 → 32 byte).
    #[must_use]
    pub fn address(&self) -> BudlumAddress {
        let pubkey = self.public_key();
        Self::address_from_public_key(&pubkey)
    }

    /// The Budlum address as a hex string.
    #[must_use]
    pub fn address_hex(&self) -> String {
        hex::encode(self.address())
    }

    /// Produce a public-only export for mobile/browser bindings.
    #[must_use]
    pub fn binding_export(&self) -> WalletBindingExport {
        WalletBindingExport {
            address_hex: self.address_hex(),
            public_key_hex: hex::encode(self.public_key()),
            mnemonic_word_count: self.mnemonic.split_whitespace().count(),
        }
    }

    /// Mesaj imzala (ML-DSA-87, 4627 byte FIPS 204 encoded signature).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        sign_message(&self.signing_key, message)
    }

    /// Verify a signature (static helper - without building a wallet).
    pub fn verify(public_key: &PublicKeyBytes, message: &[u8], signature: &SignatureBytes) -> bool {
        verify_signature(public_key, message, signature)
    }

    /// Seed (32-byte ML-DSA-87 xi - use carefully when exporting).
    #[must_use]
    pub fn seed(&self) -> &[u8; ML_DSA_87_SEED_LEN] {
        &self.seed
    }

    // ----- privacy surface (wallet-bound) -----

    /// Current privacy config (borrow).
    #[must_use]
    pub fn privacy_config(&self) -> &WalletPrivacyConfig {
        &self.privacy
    }

    /// Replace privacy config (opt-in toggles + view-key state).
    pub fn set_privacy_config(&mut self, cfg: WalletPrivacyConfig) {
        self.privacy = cfg;
    }

    /// Enable/disable note privacy only (TEE unchanged).
    pub fn set_note_privacy_enabled(&mut self, enable: bool) {
        self.privacy.note_privacy_enabled = enable;
    }

    /// TEE toggle. When `true`, private transfer / sensitive paths require a
    /// Live [`TeeRuntime`] - default is fail-closed.
    pub fn set_tee_enabled(&mut self, enable: bool) {
        self.privacy.tee_enabled = enable;
    }

    /// Client-side TEE preferred? (`false` → server Nitro preference).
    pub fn set_prefer_client_side_tee(&mut self, prefer: bool) {
        self.privacy.prefer_client_side_tee = prefer;
    }

    /// Enrol the enclave measurement (MRENCLAVE / Nitro PCR0) this wallet
    /// deploys. `sign_with_privacy` fails closed until a measurement is
    /// enrolled and refuses any attestation whose `measurement` differs:
    /// the measurement is the wallet's root of trust against a
    /// self-attesting software runtime (security audit, MEDIUM, CWE-347
    /// follow-up).
    pub fn set_trusted_tee_measurement(&mut self, measurement: [u8; 32]) {
        self.trusted_tee_measurement = Some(measurement);
    }

    /// Drop the enrolled measurement, returning TEE signing to fail-closed.
    pub fn clear_trusted_tee_measurement(&mut self) {
        self.trusted_tee_measurement = None;
    }

    /// The enrolled enclave measurement, if any.
    #[must_use]
    pub fn trusted_tee_measurement(&self) -> Option<&[u8; 32]> {
        self.trusted_tee_measurement.as_ref()
    }

    /// Ensure view-key exists (derived from wallet seed). Returns the key.
    pub fn ensure_view_key(&mut self) -> [u8; 32] {
        self.privacy.ensure_view_key(&self.seed)
    }

    /// Rotate view-key with counter (old key invalidated for new disclosures).
    pub fn rotate_view_key(&mut self, rotation_counter: u64) -> [u8; 32] {
        self.privacy.rotate_view_key(&self.seed, rotation_counter)
    }

    /// Export view-key disclosure package (manual share with regulator).
    #[must_use]
    pub fn export_view_key_for_disclosure(&self) -> Option<ViewKeyDisclosure> {
        self.privacy.export_view_key_for_disclosure()
    }

    /// Map privacy config → TEE backend kind.
    #[must_use]
    pub fn tee_backend_kind(&self) -> TeeBackendKind {
        if !self.privacy.tee_enabled {
            TeeBackendKind::None
        } else if self.privacy.prefer_client_side_tee {
            TeeBackendKind::ClientSgx
        } else {
            TeeBackendKind::ServerNitro
        }
    }

    /// Default (unavailable) TEE runtime for this wallet's preference.
    #[must_use]
    pub fn default_tee_runtime(&self) -> UnavailableTeeRuntime {
        UnavailableTeeRuntime::for_backend(self.tee_backend_kind())
    }

    /// Probe TEE. If `tee_enabled` and runtime missing → `TeeUnavailable`.
    pub fn require_tee_ready(
        &self,
        runtime: &dyn TeeRuntime,
    ) -> Result<TeeRuntimeStatus, WalletError> {
        if !self.privacy.tee_enabled {
            return Ok(TeeRuntimeStatus {
                kind: TeeBackendKind::None,
                available: true,
                detail: "TEE opt-in off".into(),
            });
        }
        let st = runtime.status();
        if !st.available {
            return Err(WalletError::TeeUnavailable(st.detail));
        }
        Ok(st)
    }

    /// Sign a message. If TEE is enabled, requires a live runtime, seals the
    /// message, and requires an **attestation** binding the seal digest to
    /// the enclave measurement before signing (fail-closed otherwise). The
    /// attestation's `report_data` is the SHA-256 of the sealed bytes, so a
    /// runtime that substitutes attacker-controlled sealed bytes cannot
    /// produce an attestation for the digest the wallet signs (Strix HIGH,
    /// security audit).
    ///
    /// The trust boundary is structural: the runtime produces only a **raw
    /// quote** ([`TeeQuoter::quote`]) and the wallet verifies it with a
    /// verifier it owns ([`TeeQuoteVerifier`]) that checks the quote against
    /// the hardware root of trust. The runtime never supplies parsed
    /// attestation fields, so a self-attesting software runtime cannot
    /// fabricate an attestation by echoing fields back (Strix MEDIUM,
    /// CWE-347, follow-up work). The wallet additionally requires its
    /// enrolled measurement to match and the backend to match its preference;
    /// signing fails closed while no measurement is enrolled.
    ///
    /// Without TEE, identical to the plain ML-DSA-87 `sign`.
    pub fn sign_with_privacy(
        &self,
        message: &[u8],
        runtime: &dyn TeeQuoter,
        verifier: &dyn TeeQuoteVerifier,
    ) -> Result<SignatureBytes, WalletError> {
        if self.privacy.tee_enabled {
            let _ = self.require_tee_ready(runtime)?;
            let sealed = runtime.seal_private_intent(message)?;
            // Bind the exact sealed bytes to a quote: an untrusted runtime
            // cannot predict SHA-256(sealed) in advance, so replacing the
            // sealed payload breaks the report data the quote is bound to.
            let seal_digest: [u8; 32] = {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(&sealed);
                h.finalize().into()
            };
            let quote = runtime.quote(seal_digest)?;
            // The wallet's root of trust is the verifier it owns, which
            // checks the quote against the hardware attestation root before
            // parsing any field out of it.
            let attestation = verifier.verify_quote(&quote)?;
            // The wallet's deployed measurement is a second, independent
            // gate: even a valid hardware quote must name the enclave this
            // wallet actually deployed, and fail closed while none is
            // enrolled.
            let trusted = self.trusted_tee_measurement.ok_or_else(|| {
                WalletError::TeeUnavailable(
                    "no trusted TEE measurement enrolled; refusing a self-attested runtime".into(),
                )
            })?;
            if !attestation.verify_measurement(&trusted) {
                return Err(WalletError::TeeUnavailable(
                    "TEE attestation measurement does not match the enrolled enclave".into(),
                ));
            }
            if attestation.backend != self.tee_backend_kind() {
                return Err(WalletError::TeeUnavailable(
                    "TEE attestation backend does not match the wallet preference".into(),
                ));
            }
            if !attestation.verify_report_data(&seal_digest) {
                return Err(WalletError::TeeUnavailable(
                    "TEE attestation does not bind the sealed intent digest".into(),
                ));
            }
            // Sign the sealed bytes plus the attestation measurement so the
            // signature commits to the enclave that sealed them.
            let mut to_sign = Vec::with_capacity(sealed.len() + 32);
            to_sign.extend_from_slice(&sealed);
            to_sign.extend_from_slice(&attestation.measurement);
            Ok(self.sign(&to_sign))
        } else {
            Ok(self.sign(message))
        }
    }

    /// Build a private transfer intent (note privacy path).
    ///
    /// Requires `note_privacy_enabled`. If `tee_enabled`, requires a live
    /// [`TeeRuntime`] and refuses to return plaintext witnesses without it.
    pub fn build_private_transfer(
        &self,
        req: PrivateTransferRequest,
        runtime: &dyn TeeRuntime,
    ) -> Result<PrivateTransferIntent, WalletError> {
        if !self.privacy.note_privacy_enabled {
            return Err(WalletError::NotePrivacyDisabled);
        }
        // TEE fail-closed: do not emit plaintext note witnesses if user asked
        // for TEE. Until witness construction itself runs inside the enclave,
        // a `tee_enabled=true` request cannot be honoured honestly: the
        // returned intent would carry plaintext input/output notes, leaking
        // exactly what the user asked the TEE to hide (Strix MEDIUM, deneme
        // Require a live runtime (fail-closed without one) and then
        // still refuse the plaintext intent.
        if self.privacy.tee_enabled {
            let _ = self.require_tee_ready(runtime)?;
            return Err(WalletError::TeeUnavailable(
                "TEE private-transfer witness construction is not implemented; refusing plaintext intent while tee_enabled=true"
                    .into(),
            ));
        }

        let outputs = privacy_transfer::build_outputs(&req)?;
        // Security audit (HIGH): it was not verified that the input note belongs to THIS
        // wallet - a note carrying another wallet's recipient_tag
        // harcanabiliyordu (cross-wallet spending). Notun recipient tag'i
        // must be derived from this wallet's address.
        let wallet_tag = crate::privacy_crypto::address_to_recipient_tag(&self.address());
        if req.input.recipient_tag != wallet_tag {
            return Err(WalletError::InvalidPrivateTransfer(
                "input note recipient tag does not match this wallet's address".into(),
            ));
        }
        let nullifier_fe = req.input.nullifier();
        let nullifiers = vec![hash_from_field(nullifier_fe)];
        let output_commitments: Vec<[u8; 32]> = outputs
            .iter()
            .map(|o| hash_from_field(o.commitment()))
            .collect();
        let sum_in = req.input.amount;
        let sum_out: u64 = outputs.iter().map(|o| o.amount).sum();
        if sum_in != sum_out {
            return Err(WalletError::InvalidPrivateTransfer(format!(
                "sum conservation broken: in={sum_in} out={sum_out}"
            )));
        }
        let digest = privacy_transfer::public_digest(&nullifiers, &output_commitments);
        let authorization_sig = self.sign(&digest);

        Ok(PrivateTransferIntent {
            output_commitments,
            nullifiers,
            sum_in,
            sum_out,
            inputs: vec![req.input],
            outputs,
            public_digest: digest,
            authorization_sig,
        })
    }

    /// Convenience: create a fresh output note commitment for receiving funds
    /// (wallet is recipient). Returns (blinding, commitment_fe, commitment_hash).
    pub fn prepare_receive_note(
        &mut self,
        amount: u64,
        blinding_counter: u64,
    ) -> Result<(u64, u64, [u8; 32]), WalletError> {
        if !self.privacy.note_privacy_enabled {
            return Err(WalletError::NotePrivacyDisabled);
        }
        if amount == 0 {
            return Err(WalletError::InvalidPrivateTransfer(
                "amount must be > 0".into(),
            ));
        }
        // The caller picks the counter, so the wallet is the one that has to
        // remember it. Two notes sharing a blinding share a commitment, which
        // links them on-chain and can make the second one unspendable; a
        // counter may therefore be used once and only forwards.
        if blinding_counter < self.next_blinding_counter {
            return Err(WalletError::InvalidPrivateTransfer(format!(
                "blinding counter {blinding_counter} was already used (next usable is {}); \
                 reusing a blinding links the two notes and can make the second unspendable",
                self.next_blinding_counter
            )));
        }
        self.next_blinding_counter = blinding_counter.saturating_add(1);
        let blinding = derive_blinding(&self.seed, blinding_counter);
        let tag = address_to_recipient_tag(&self.address());
        // privacy_commit(amount, blinding, recipient_tag)
        let commitment = privacy_commit(amount, blinding, tag);
        Ok((blinding, commitment, hash_from_field(commitment)))
    }

    /// Build an input witness for a note this wallet previously received
    /// (spend_secret derived from seed ∥ commitment).
    pub fn note_input_from_receive(
        &self,
        amount: u64,
        blinding: u64,
    ) -> Result<PrivateNoteInput, WalletError> {
        if !self.privacy.note_privacy_enabled {
            return Err(WalletError::NotePrivacyDisabled);
        }
        let tag = address_to_recipient_tag(&self.address());
        // privacy_commit(amount, blinding, recipient_tag)
        let commitment = privacy_commit(amount, blinding, tag);
        let spend_secret = derive_spend_secret(&self.seed, commitment);
        Ok(PrivateNoteInput {
            amount,
            recipient_tag: tag,
            blinding,
            spend_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_word_wallet() {
        let wallet = Wallet::from_entropy(&[0x42u8; 16]).expect("12-word wallet must succeed");
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 12, "must have 12 words");
        assert_eq!(wallet.address().len(), 32, "address must be 32 bytes");
        assert_eq!(
            wallet.public_key().len(),
            ML_DSA_87_PUBLIC_KEY_LEN,
            "pubkey must be ML-DSA-87 encoded (2592 bytes)"
        );
    }

    #[test]
    fn generate_24_word_wallet() {
        let wallet = Wallet::from_entropy(&[0x42u8; 32]).expect("24-word wallet must succeed");
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 24, "must have 24 words");
    }

    #[test]
    fn invalid_word_count_rejected() {
        // Wallet::generate fails-closed without production feature
        assert!(Wallet::generate(15).is_err(), "15 words must be rejected");
        assert!(Wallet::generate(0).is_err(), "0 words must be rejected");
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let wallet = Wallet::from_entropy(&[0x42u8; 16]).unwrap();
        let msg = b"hello budlum";
        let sig = wallet.sign(msg);
        let pubkey = wallet.public_key();
        assert!(Wallet::verify(&pubkey, msg, &sig), "signature must verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let wallet = Wallet::from_entropy(&[0x42u8; 16]).unwrap();
        let sig = wallet.sign(b"original message");
        let pubkey = wallet.public_key();
        assert!(
            !Wallet::verify(&pubkey, b"different message", &sig),
            "wrong message must fail verification"
        );
    }

    #[test]
    fn restore_from_mnemonic() {
        // Generate a valid mnemonic from entropy, then restore from it
        let wallet = Wallet::from_entropy(&[0x42u8; 16]).unwrap();
        let mnemonic = wallet.mnemonic().to_string();
        let restored = Wallet::from_mnemonic(&mnemonic).expect("restore must succeed");
        assert_eq!(restored.mnemonic(), mnemonic);
        // Same mnemonic -> same address
        assert_eq!(
            wallet.address(),
            restored.address(),
            "same mnemonic must produce same address"
        );
    }

    #[test]
    fn different_mnemonics_different_addresses() {
        let w1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let w2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        assert_ne!(
            w1.address(),
            w2.address(),
            "different entropy must produce different addresses"
        );
    }

    #[test]
    fn from_entropy_invalid_size_rejected() {
        assert!(Wallet::from_entropy(&[0u8; 8]).is_err(), "8 bytes rejected");
        assert!(
            Wallet::from_entropy(&[0u8; 64]).is_err(),
            "64 bytes rejected"
        );
    }

    #[test]
    fn from_entropy_valid_sizes() {
        assert!(Wallet::from_entropy(&[0u8; 16]).is_ok(), "16 bytes OK");
        assert!(Wallet::from_entropy(&[0u8; 32]).is_ok(), "32 bytes OK");
    }

    #[test]
    fn entropy_size_preserves_mnemonic_word_count() {
        let short = Wallet::from_entropy(&[0u8; 16]).unwrap();
        let long = Wallet::from_entropy(&[0u8; 32]).unwrap();
        assert_eq!(short.mnemonic().split_whitespace().count(), 12);
        assert_eq!(long.mnemonic().split_whitespace().count(), 24);
    }

    /// Production entropy fail-closed gate: Wallet::generate must fail
    /// Without the `production` feature to prevent deterministic/placeholder
    /// Entropy from reaching production.
    #[test]
    fn wallet_generate_rejects_placeholder_entropy_in_production() {
        // Without --features production, Wallet::generate must fail-closed
        let result = Wallet::generate(12);
        #[cfg(not(feature = "production"))]
        {
            assert!(
                result.is_err(),
                "Wallet::generate must fail-closed without production feature"
            );
            match result {
                Err(WalletError::ProductionEntropyUnavailable(msg)) => {
                    assert!(
                        msg.contains("production"),
                        "error must mention production feature: {msg}"
                    );
                }
                _ => panic!("expected ProductionEntropyUnavailable error"),
            }
        }
        // With --features production, generate should succeed (uses getrandom)
        #[cfg(feature = "production")]
        {
            assert!(
                result.is_ok(),
                "Wallet::generate should succeed with production feature"
            );
        }
    }

    /// BIP39 checksum validation: invalid mnemonic must be rejected.
    #[test]
    fn mnemonic_checksum_validation_rejects_invalid() {
        // Valid 12-word mnemonic from from_entropy (deterministic)
        let wallet = Wallet::from_entropy(&[0x42u8; 16]).unwrap();
        let valid_mnemonic = wallet.mnemonic().to_string();

        // Tampered mnemonic (last word changed) must fail checksum
        let words: Vec<&str> = valid_mnemonic.split_whitespace().collect();
        let mut tampered = words.clone();
        // Replace last word with a different valid word
        if let Some(&last) = words.last() {
            if let Some(idx) = bip39_wordlist::word_to_index(last) {
                let new_idx = (idx + 1) % bip39_wordlist::BIP39_WORDLIST.len();
                if let Some(new_word) = bip39_wordlist::index_to_word(new_idx) {
                    let last_pos = tampered.len() - 1;
                    tampered[last_pos] = new_word;
                }
            }
        }
        let tampered_mnemonic = tampered.join(" ");
        assert_ne!(
            tampered_mnemonic, valid_mnemonic,
            "test setup: mnemonic must be tampered"
        );
        assert!(
            Wallet::from_mnemonic(&tampered_mnemonic).is_err(),
            "tampered mnemonic must fail checksum validation"
        );

        // Valid mnemonic must restore successfully
        assert!(
            Wallet::from_mnemonic(&valid_mnemonic).is_ok(),
            "valid mnemonic must restore successfully"
        );
    }

    #[test]
    fn binding_capabilities_do_not_claim_a_wiring_that_is_absent() {
        let caps = WalletBindingCapabilities::current();
        assert_eq!(caps.stub_version, WALLET_BINDING_STUB_VERSION);
        // The feature gates exist and compile.
        assert!(caps.uniffi_feature_compiles);
        assert!(caps.wasm_feature_compiles);
        // Nothing crosses them yet. This assertion is meant to fail the day a
        // real binding lands, so the descriptor is updated in the same commit
        // rather than staying wrong in the other direction.
        assert!(
            !caps.bindings_are_wired,
            "bindings_are_wired is set, so a UniFFI interface or a \
             #[wasm_bindgen] export must exist; update this test together with \
             whichever one landed"
        );
        assert!(!caps.exports_seed_material);
    }

    #[test]
    fn binding_export_redacts_seed_and_counts_words() {
        let wallet = Wallet::from_entropy(&[0x42u8; 32]).unwrap();
        let export = wallet.binding_export();
        assert_eq!(export.address_hex, wallet.address_hex());
        assert_eq!(export.public_key_hex, hex::encode(wallet.public_key()));
        assert_eq!(export.mnemonic_word_count, 24);
        assert!(!format!("{export:?}").contains(&hex::encode(wallet.seed())));
    }

    #[cfg(feature = "uniffi")]
    #[test]
    fn binding_uniffi_feature_stub_exports_capabilities() {
        let caps = uniffi_bindings::binding_capabilities();
        assert!(caps.uniffi_feature_compiles);
        assert!(!caps.bindings_are_wired);
        assert!(!caps.exports_seed_material);
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn binding_wasm_feature_stub_exports_capabilities() {
        let caps = wasm_bindings::binding_capabilities();
        assert!(caps.wasm_feature_compiles);
        assert!(!caps.bindings_are_wired);
        assert!(!caps.exports_seed_material);
    }

    #[test]
    fn address_is_deterministic() {
        let entropy = [0x42u8; 16];
        let w1 = Wallet::from_entropy(&entropy).unwrap();
        let w2 = Wallet::from_entropy(&entropy).unwrap();
        assert_eq!(
            w1.address(),
            w2.address(),
            "same entropy must produce same address"
        );
        assert_eq!(
            w1.public_key(),
            w2.public_key(),
            "same entropy must produce same pubkey"
        );
    }

    /// Seal for the permissionless relayer rule: wallet-core carries no relayer registration/stake/
    /// whitelist code. This test acts as grep evidence; if someone adds
    /// relayer code the test breaks (a deliberate guard).
    #[test]
    fn no_relayer_registration_code_in_wallet_core() {
        // This test is a seal - it preserves wallet-core's permissionless principle.
        // README: "anyone can be a relayer, security through stake + slashing."
        // wallet-core is a WALLET, not a RELAYER.
        assert!(true, "wallet-core has no relayer registration/stake code");
    }

    #[test]
    fn multisig_policy_validates_threshold() {
        let w1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let w2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let policy = MultisigPolicy::new(vec![w1.public_key(), w2.public_key()], 2).unwrap();
        assert_eq!(policy.owner_count(), 2);
        assert!(MultisigPolicy::new(vec![w1.public_key()], 0).is_err());
        assert!(MultisigPolicy::new(vec![w1.public_key()], 2).is_err());
    }

    #[test]
    fn multisig_requires_distinct_valid_owner_signatures() {
        let w1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let w2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let w3 = Wallet::from_entropy(&[3u8; 16]).unwrap();
        let msg = b"budlum multisig proposal digest";
        let policy =
            MultisigPolicy::new(vec![w1.public_key(), w2.public_key(), w3.public_key()], 2)
                .unwrap();

        let one = [MultisigApproval {
            public_key: w1.public_key(),
            signature: w1.sign(msg),
        }];
        assert!(!policy.verify_threshold(msg, &one));

        let duplicate = [
            MultisigApproval {
                public_key: w1.public_key(),
                signature: w1.sign(msg),
            },
            MultisigApproval {
                public_key: w1.public_key(),
                signature: w1.sign(msg),
            },
        ];
        assert!(!policy.verify_threshold(msg, &duplicate));

        let quorum = [
            MultisigApproval {
                public_key: w1.public_key(),
                signature: w1.sign(msg),
            },
            MultisigApproval {
                public_key: w2.public_key(),
                signature: w2.sign(msg),
            },
        ];
        assert!(policy.verify_threshold(msg, &quorum));
    }

    #[test]
    fn multisig_rejects_wrong_message_or_non_owner() {
        let w1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let w2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let outsider = Wallet::from_entropy(&[9u8; 16]).unwrap();
        let policy = MultisigPolicy::new(vec![w1.public_key(), w2.public_key()], 2).unwrap();
        let msg = b"proposal";
        let approvals = [
            MultisigApproval {
                public_key: w1.public_key(),
                signature: w1.sign(b"different"),
            },
            MultisigApproval {
                public_key: outsider.public_key(),
                signature: outsider.sign(msg),
            },
        ];
        assert!(!policy.verify_threshold(msg, &approvals));
    }

    fn multisig_approvals_for_mask(
        wallets: &[Wallet],
        message: &[u8],
        mask: usize,
    ) -> Vec<MultisigApproval> {
        wallets
            .iter()
            .enumerate()
            .filter(|(idx, _)| (mask & (1usize << idx)) != 0)
            .map(|(_, wallet)| MultisigApproval {
                public_key: wallet.public_key(),
                signature: wallet.sign(message),
            })
            .collect()
    }

    #[test]
    fn multisig_accepts_all_two_of_three_combinations() {
        let wallets = (0u8..3)
            .map(|i| Wallet::from_entropy(&[10u8 + i; 16]).unwrap())
            .collect::<Vec<_>>();
        let policy =
            MultisigPolicy::new(wallets.iter().map(Wallet::public_key).collect(), 2).unwrap();
        let msg = b"two of three exhaustive matrix";

        for mask in 0..(1usize << wallets.len()) {
            let approvals = multisig_approvals_for_mask(&wallets, msg, mask);
            assert_eq!(
                policy.verify_threshold(msg, &approvals),
                mask.count_ones() as usize >= 2,
                "2-of-3 mask {mask:03b}"
            );
        }
    }

    #[test]
    fn multisig_enforces_three_of_five_combinations() {
        let wallets = (0u8..5)
            .map(|i| Wallet::from_entropy(&[20u8 + i; 16]).unwrap())
            .collect::<Vec<_>>();
        let policy =
            MultisigPolicy::new(wallets.iter().map(Wallet::public_key).collect(), 3).unwrap();
        let msg = b"three of five exhaustive matrix";

        for mask in 0..(1usize << wallets.len()) {
            let approvals = multisig_approvals_for_mask(&wallets, msg, mask);
            assert_eq!(
                policy.verify_threshold(msg, &approvals),
                mask.count_ones() as usize >= 3,
                "3-of-5 mask {mask:05b}"
            );
        }
    }

    #[test]
    fn social_recovery_policy_validates_threshold_and_timelock() {
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let policy =
            SocialRecoveryPolicy::new(vec![g1.public_key(), g2.public_key()], 2, 100).unwrap();
        assert_eq!(policy.threshold, 2);
        assert_eq!(policy.timelock_blocks, 100);
        assert!(SocialRecoveryPolicy::new(vec![g1.public_key()], 0, 100).is_err());
        assert!(SocialRecoveryPolicy::new(vec![g1.public_key()], 1, 0).is_err());
    }

    #[test]
    fn social_recovery_requires_distinct_guardian_signatures() {
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let g3 = Wallet::from_entropy(&[3u8; 16]).unwrap();
        let digest = b"recover wallet to new key";
        let policy = SocialRecoveryPolicy::new(
            vec![g1.public_key(), g2.public_key(), g3.public_key()],
            2,
            100,
        )
        .unwrap();
        let duplicate = [
            GuardianApproval {
                public_key: g1.public_key(),
                signature: g1.sign(digest),
            },
            GuardianApproval {
                public_key: g1.public_key(),
                signature: g1.sign(digest),
            },
        ];
        assert!(!policy.verify_recovery_threshold(digest, &duplicate));
        let quorum = [
            GuardianApproval {
                public_key: g1.public_key(),
                signature: g1.sign(digest),
            },
            GuardianApproval {
                public_key: g2.public_key(),
                signature: g2.sign(digest),
            },
        ];
        assert!(policy.verify_recovery_threshold(digest, &quorum));
    }

    #[test]
    fn social_recovery_rejects_non_guardian_or_wrong_digest() {
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let outsider = Wallet::from_entropy(&[9u8; 16]).unwrap();
        let digest = b"recover";
        let policy =
            SocialRecoveryPolicy::new(vec![g1.public_key(), g2.public_key()], 2, 100).unwrap();
        let approvals = [
            GuardianApproval {
                public_key: g1.public_key(),
                signature: g1.sign(b"wrong"),
            },
            GuardianApproval {
                public_key: outsider.public_key(),
                signature: outsider.sign(digest),
            },
        ];
        assert!(!policy.verify_recovery_threshold(digest, &approvals));
    }

    #[test]
    fn social_recovery_rotates_compromised_guardian() {
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let g3 = Wallet::from_entropy(&[3u8; 16]).unwrap();
        let replacement = Wallet::from_entropy(&[4u8; 16]).unwrap();
        let owner = Wallet::from_entropy(&[7u8; 16]).unwrap();
        let new_owner = Wallet::from_entropy(&[8u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(
            vec![g1.public_key(), g2.public_key(), g3.public_key()],
            2,
            100,
        )
        .unwrap();
        let rotated = policy
            .rotate_guardian(g1.public_key(), replacement.public_key())
            .unwrap();
        assert_eq!(rotated.guardian_count(), 3);
        assert!(!rotated.guardians.contains(&g1.public_key()));
        assert!(rotated.guardians.contains(&replacement.public_key()));

        let proposal =
            RecoveryProposal::new(owner.public_key(), new_owner.public_key(), &rotated, 1_000)
                .unwrap();
        let digest = proposal.digest();
        let compromised_quorum = [
            GuardianApproval {
                public_key: g1.public_key(),
                signature: g1.sign(&digest),
            },
            GuardianApproval {
                public_key: g2.public_key(),
                signature: g2.sign(&digest),
            },
        ];
        let rotated_quorum = [
            GuardianApproval {
                public_key: replacement.public_key(),
                signature: replacement.sign(&digest),
            },
            GuardianApproval {
                public_key: g2.public_key(),
                signature: g2.sign(&digest),
            },
        ];
        assert!(!proposal.verify_guardian_approvals(&rotated, &compromised_quorum));
        assert!(proposal.verify_guardian_approvals(&rotated, &rotated_quorum));
    }

    #[test]
    fn social_recovery_removal_preserves_threshold_safety() {
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let g3 = Wallet::from_entropy(&[3u8; 16]).unwrap();
        let unknown = Wallet::from_entropy(&[9u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(
            vec![g1.public_key(), g2.public_key(), g3.public_key()],
            2,
            100,
        )
        .unwrap();
        let reduced = policy.remove_guardian(g3.public_key()).unwrap();
        assert_eq!(reduced.guardian_count(), 2);
        assert_eq!(reduced.threshold, 2);
        assert!(reduced.remove_guardian(g2.public_key()).is_err());
        assert!(reduced.remove_guardian(unknown.public_key()).is_err());
        assert!(reduced
            .rotate_guardian(g1.public_key(), g2.public_key())
            .is_err());
    }

    #[test]
    fn recovery_proposal_sets_timelock_and_addresses() {
        let owner = Wallet::from_entropy(&[7u8; 16]).unwrap();
        let new_owner = Wallet::from_entropy(&[8u8; 16]).unwrap();
        let guardian = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(vec![guardian.public_key()], 1, 100).unwrap();
        let proposal =
            RecoveryProposal::new(owner.public_key(), new_owner.public_key(), &policy, 1_000)
                .unwrap();

        assert_eq!(proposal.current_address, owner.address());
        assert_eq!(proposal.new_address, new_owner.address());
        assert_eq!(proposal.created_block, 1_000);
        assert_eq!(proposal.executable_after, 1_100);
        assert!(!proposal.is_timelock_satisfied(1_099));
        assert!(proposal.is_timelock_satisfied(1_100));
    }

    #[test]
    fn recovery_proposal_digest_binds_target_and_timelock() {
        let owner = Wallet::from_entropy(&[7u8; 16]).unwrap();
        let new_owner = Wallet::from_entropy(&[8u8; 16]).unwrap();
        let other_new_owner = Wallet::from_entropy(&[9u8; 16]).unwrap();
        let guardian = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(vec![guardian.public_key()], 1, 100).unwrap();
        let proposal =
            RecoveryProposal::new(owner.public_key(), new_owner.public_key(), &policy, 1_000)
                .unwrap();
        let changed_target = RecoveryProposal::new(
            owner.public_key(),
            other_new_owner.public_key(),
            &policy,
            1_000,
        )
        .unwrap();
        let mut changed_timelock = proposal.clone();
        changed_timelock.executable_after += 1;

        assert_ne!(proposal.digest(), changed_target.digest());
        assert_ne!(proposal.digest(), changed_timelock.digest());
    }

    #[test]
    fn recovery_proposal_requires_quorum_and_timelock() {
        let owner = Wallet::from_entropy(&[7u8; 16]).unwrap();
        let new_owner = Wallet::from_entropy(&[8u8; 16]).unwrap();
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let g3 = Wallet::from_entropy(&[3u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(
            vec![g1.public_key(), g2.public_key(), g3.public_key()],
            2,
            100,
        )
        .unwrap();
        let proposal =
            RecoveryProposal::new(owner.public_key(), new_owner.public_key(), &policy, 1_000)
                .unwrap();
        let digest = proposal.digest();
        let one = [GuardianApproval {
            public_key: g1.public_key(),
            signature: g1.sign(&digest),
        }];
        let quorum = [
            GuardianApproval {
                public_key: g1.public_key(),
                signature: g1.sign(&digest),
            },
            GuardianApproval {
                public_key: g2.public_key(),
                signature: g2.sign(&digest),
            },
        ];
        let wrong_digest = [
            GuardianApproval {
                public_key: g1.public_key(),
                signature: g1.sign(b"wrong recovery digest"),
            },
            GuardianApproval {
                public_key: g2.public_key(),
                signature: g2.sign(&digest),
            },
        ];

        assert!(!proposal.verify_guardian_approvals(&policy, &one));
        assert!(!proposal.verify_guardian_approvals(&policy, &wrong_digest));
        assert!(proposal.verify_guardian_approvals(&policy, &quorum));
        assert!(!proposal.is_executable(&policy, &quorum, 1_099));
        assert!(proposal.is_executable(&policy, &quorum, 1_100));
    }

    #[test]
    fn recovery_proposal_rejects_same_owner_or_overflow() {
        let owner = Wallet::from_entropy(&[7u8; 16]).unwrap();
        let new_owner = Wallet::from_entropy(&[8u8; 16]).unwrap();
        let guardian = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(vec![guardian.public_key()], 1, 100).unwrap();
        assert!(
            RecoveryProposal::new(owner.public_key(), owner.public_key(), &policy, 1_000).is_err()
        );
        assert!(RecoveryProposal::new(
            owner.public_key(),
            new_owner.public_key(),
            &policy,
            u64::MAX,
        )
        .is_err());
    }

    // ===== - WalletPrivacyConfig (section 10 #5 + view key) =====

    #[test]
    fn d2_privacy_config_defaults_off() {
        let cfg = WalletPrivacyConfig::default();
        assert!(
            !cfg.is_privacy_active(),
            "section 10 #5: OFF by default (opt-in)"
        );
        assert!(!cfg.is_note_privacy_active());
        assert_eq!(cfg.effective_backend(), "none");
        assert!(cfg.view_key.is_none());
        assert!(cfg.export_view_key_for_disclosure().is_none());
    }

    #[test]
    fn d2_privacy_config_user_opt_in_client_first() {
        let cfg = WalletPrivacyConfig::from_user_opt_in(true);
        assert!(cfg.is_privacy_active());
        assert!(cfg.is_note_privacy_active());
        // Client-side TEE preferred (user device / laptop SGX).
        assert_eq!(cfg.effective_backend(), "client");
    }

    #[test]
    fn d2_privacy_config_server_backend_fallback() {
        let mut cfg = WalletPrivacyConfig::from_user_opt_in(true);
        cfg.prefer_client_side_tee = false; // weak device -> server-side
        assert_eq!(cfg.effective_backend(), "server");
    }

    #[test]
    fn d2_note_privacy_only_keeps_tee_off() {
        let cfg = WalletPrivacyConfig::note_privacy_only(true);
        assert!(cfg.is_note_privacy_active());
        assert!(!cfg.is_privacy_active());
        assert_eq!(cfg.effective_backend(), "none");
    }

    #[test]
    fn d2_view_key_derive_export_roundtrip() {
        let seed = [0x42u8; 32];
        let mut cfg = WalletPrivacyConfig::default();
        let vk1 = cfg.ensure_view_key(&seed);
        let vk2 = cfg.ensure_view_key(&seed); // idempotent
        assert_eq!(vk1, vk2);
        let disclosure = cfg.export_view_key_for_disclosure().expect("view-key set");
        assert_eq!(disclosure.version, VIEW_KEY_VERSION);
        assert_eq!(disclosure.view_key, vk1);
        let hex = disclosure.to_hex();
        assert!(hex.starts_with("vk1:1:"));
        let parsed = ViewKeyDisclosure::from_hex(&hex).expect("parse");
        assert_eq!(parsed, disclosure);
    }

    #[test]
    fn d2_view_key_rotation_changes_key() {
        let seed = [0x7u8; 32];
        let mut cfg = WalletPrivacyConfig::default();
        let vk0 = cfg.ensure_view_key(&seed);
        let vk1 = cfg.rotate_view_key(&seed, 1);
        assert_ne!(vk0, vk1);
        // Different seeds → different keys
        let mut other = WalletPrivacyConfig::default();
        let vk_other = other.ensure_view_key(&[0x8u8; 32]);
        assert_ne!(vk0, vk_other);
    }

    #[test]
    fn d2_view_key_rejects_malformed_hex() {
        assert!(ViewKeyDisclosure::from_hex("not-a-key").is_none());
        assert!(ViewKeyDisclosure::from_hex("vk1:2:00").is_none()); // bad version
        assert!(ViewKeyDisclosure::from_hex("vk1:1:abcd").is_none()); // short
    }

    // ===== wallet-bound privacy wire =====

    #[test]
    fn d2_wallet_defaults_privacy_off() {
        let w = Wallet::from_entropy(&[0x11u8; 16]).unwrap();
        assert!(!w.privacy_config().is_note_privacy_active());
        assert!(!w.privacy_config().is_privacy_active());
        assert_eq!(w.tee_backend_kind(), TeeBackendKind::None);
    }

    #[test]
    fn d2_wallet_private_transfer_requires_note_privacy() {
        let w = Wallet::from_entropy(&[0x22u8; 16]).unwrap();
        let inp = PrivateNoteInput {
            amount: 100,
            recipient_tag: 1,
            blinding: 2,
            spend_secret: 3,
        };
        let req = PrivateTransferRequest {
            input: inp,
            to: [9u8; 32],
            send_amount: 100,
            output_blinding: 5,
            change_recipient_tag: None,
            change_blinding: None,
        };
        let rt = w.default_tee_runtime();
        let err = w.build_private_transfer(req, &rt).unwrap_err();
        assert!(matches!(err, WalletError::NotePrivacyDisabled));
    }

    /// Two notes that share a blinding share a commitment: an observer learns
    /// they carry the same amount and the nullifier set rejects the second
    /// spend. The caller picks the counter, so the wallet has to be the one
    /// that refuses a counter it already handed out.
    #[test]
    fn a_reused_blinding_counter_is_refused() {
        let mut w = Wallet::from_entropy(&[0x33u8; 16]).unwrap();
        w.set_privacy_config(WalletPrivacyConfig::note_privacy_only(true));
        let first = w.prepare_receive_note(100, 7).unwrap();
        let err = w.prepare_receive_note(100, 7).unwrap_err();
        assert!(
            matches!(err, WalletError::InvalidPrivateTransfer(_)),
            "reusing a blinding counter must be refused, got ok with blinding {}",
            first.0
        );
        // A fresh counter still works, and it gives a different blinding.
        let second = w.prepare_receive_note(100, 8).unwrap();
        assert_ne!(
            first.0, second.0,
            "different counters must derive different blindings"
        );
    }

    #[test]
    fn d2_wallet_private_transfer_1in_1out_signs() {
        let mut w = Wallet::from_entropy(&[0x33u8; 16]).unwrap();
        w.set_privacy_config(WalletPrivacyConfig::note_privacy_only(true));
        let (blinding, _c, _) = w.prepare_receive_note(100, 0).unwrap();
        let input = w.note_input_from_receive(100, blinding).unwrap();
        let req = PrivateTransferRequest {
            input,
            to: [0xABu8; 32],
            send_amount: 100,
            output_blinding: derive_blinding(w.seed(), 1),
            change_recipient_tag: None,
            change_blinding: None,
        };
        let rt = w.default_tee_runtime();
        let intent = w.build_private_transfer(req, &rt).unwrap();
        assert_eq!(intent.sum_in, intent.sum_out);
        assert_eq!(intent.sum_in, 100);
        assert_eq!(intent.nullifiers.len(), 1);
        assert_eq!(intent.output_commitments.len(), 1);
        assert!(Wallet::verify(
            &w.public_key(),
            &intent.public_digest,
            &intent.authorization_sig
        ));
    }

    #[test]
    fn d2_wallet_private_transfer_with_change() {
        let mut w = Wallet::from_entropy(&[0x44u8; 16]).unwrap();
        w.set_note_privacy_enabled(true);
        let (blinding, _, _) = w.prepare_receive_note(100, 0).unwrap();
        let input = w.note_input_from_receive(100, blinding).unwrap();
        let change_tag = address_to_recipient_tag(&w.address());
        let req = PrivateTransferRequest {
            input,
            to: [0xCDu8; 32],
            send_amount: 60,
            output_blinding: 11,
            change_recipient_tag: Some(change_tag),
            change_blinding: Some(12),
        };
        let intent = w
            .build_private_transfer(req, &w.default_tee_runtime())
            .unwrap();
        assert_eq!(intent.output_commitments.len(), 2);
        assert_eq!(intent.sum_out, 100);
    }

    #[test]
    fn d2_wallet_tee_enabled_fail_closed_without_runtime() {
        let mut w = Wallet::from_entropy(&[0x55u8; 16]).unwrap();
        w.set_privacy_config(WalletPrivacyConfig::from_user_opt_in(true));
        assert!(w.privacy_config().tee_enabled);
        let rt = w.default_tee_runtime();
        let err = w
            .sign_with_privacy(b"hello", &rt, &UnavailableTeeQuoteVerifier)
            .unwrap_err();
        assert!(matches!(err, WalletError::TeeUnavailable(_)));

        let (blinding, _, _) = w.prepare_receive_note(10, 0).unwrap();
        let input = w.note_input_from_receive(10, blinding).unwrap();
        let req = PrivateTransferRequest {
            input,
            to: [1u8; 32],
            send_amount: 10,
            output_blinding: 1,
            change_recipient_tag: None,
            change_blinding: None,
        };
        let err = w.build_private_transfer(req, &rt).unwrap_err();
        assert!(matches!(err, WalletError::TeeUnavailable(_)));
    }

    #[test]
    fn d2_wallet_tee_ready_mock_allows_sign() {
        let rt = crate::tee::mock::MockTeeRuntime::new(TeeBackendKind::ClientSgx);
        let verifier = crate::tee::mock::MockQuoteVerifier::default();
        let mut w = Wallet::from_entropy(&[0x66u8; 16]).unwrap();
        w.set_tee_enabled(true);
        // Enrol the measurement the mock attests with; without this the
        // wallet would refuse any attestation, self-attested or not.
        w.set_trusted_tee_measurement(crate::tee::mock::MOCK_MEASUREMENT);
        let sig = w.sign_with_privacy(b"hello", &rt, &verifier).unwrap();
        // Signature is over sealed bytes + measurement, not raw message.
        assert!(!Wallet::verify(&w.public_key(), b"hello", &sig));
        let sealed = rt.seal_private_intent(b"hello").unwrap();
        let mut to_sign = sealed.clone();
        to_sign.extend_from_slice(&crate::tee::mock::MOCK_MEASUREMENT);
        assert!(Wallet::verify(&w.public_key(), &to_sign, &sig));
    }

    #[test]
    fn d2_wallet_tee_requires_enrolled_measurement() {
        // The runtime produces a quote and the verifier validates it, but the
        // wallet has not enrolled any measurement, so it must refuse to sign
        // rather than trust the runtime's own claim (Strix MEDIUM, CWE-347,
        // follow-up work).
        let rt = crate::tee::mock::MockTeeRuntime::new(TeeBackendKind::ClientSgx);
        let verifier = crate::tee::mock::MockQuoteVerifier::default();
        let mut w = Wallet::from_entropy(&[0x6Au8; 16]).unwrap();
        w.set_tee_enabled(true);
        let err = w.sign_with_privacy(b"hello", &rt, &verifier).unwrap_err();
        assert!(matches!(err, WalletError::TeeUnavailable(_)));
    }

    #[test]
    fn d2_wallet_tee_rejects_foreign_measurement() {
        // The quote is valid and the verifier recognizes the enclave, but the
        // enclave is not the one this wallet deployed: the enrolled
        // measurement differs, so the wallet must not sign for it.
        let rt = crate::tee::mock::MockTeeRuntime::new(TeeBackendKind::ClientSgx);
        let foreign = [0xEE; 32];
        let verifier = crate::tee::mock::MockQuoteVerifier {
            recognized_measurements: vec![foreign],
        };
        let mut w = Wallet::from_entropy(&[0x6Bu8; 16]).unwrap();
        w.set_tee_enabled(true);
        w.set_trusted_tee_measurement(crate::tee::mock::MOCK_MEASUREMENT);
        let err = w.sign_with_privacy(b"hello", &rt, &verifier).unwrap_err();
        assert!(matches!(err, WalletError::TeeUnavailable(_)));
    }

    #[test]
    fn d2_wallet_tee_rejects_wrong_backend() {
        // Same measurement, wrong backend: the wallet prefers client-side
        // SGX by default, and an attestation claiming a Nitro enclave the
        // user did not opt into must not satisfy it.
        let rt = crate::tee::mock::MockTeeRuntime::new(TeeBackendKind::ServerNitro);
        let verifier = crate::tee::mock::MockQuoteVerifier::default();
        let mut w = Wallet::from_entropy(&[0x6Cu8; 16]).unwrap();
        w.set_tee_enabled(true);
        w.set_trusted_tee_measurement(crate::tee::mock::MOCK_MEASUREMENT);
        let err = w.sign_with_privacy(b"hello", &rt, &verifier).unwrap_err();
        assert!(matches!(err, WalletError::TeeUnavailable(_)));
    }

    #[test]
    fn d2_wallet_tee_rejects_forged_quote() {
        // The runtime hands the wallet raw bytes. If those bytes are not a
        // valid quote for the verifier's root of trust, the wallet refuses
        // even though the runtime produced them itself: the runtime can
        // never supply a parsed attestation (Strix MEDIUM, CWE-347).
        let verifier = crate::tee::mock::MockQuoteVerifier::default();
        struct ForgingRuntime;
        impl TeeRuntime for ForgingRuntime {
            fn status(&self) -> TeeRuntimeStatus {
                TeeRuntimeStatus {
                    kind: TeeBackendKind::ClientSgx,
                    available: true,
                    detail: "forging".into(),
                }
            }
            fn seal_private_intent(&self, plaintext: &[u8]) -> Result<Vec<u8>, WalletError> {
                let mut out = b"FORGED:".to_vec();
                out.extend_from_slice(plaintext);
                Ok(out)
            }
        }
        impl TeeQuoter for ForgingRuntime {
            fn quote(&self, report_data: [u8; 32]) -> Result<Vec<u8>, WalletError> {
                // Try to hand the wallet a self-asserted "attestation"
                // instead of a verifiable quote.
                let mut fake = vec![0xFFu8; 77];
                fake[36..68].copy_from_slice(&report_data);
                Ok(fake)
            }
        }
        let mut w = Wallet::from_entropy(&[0x6Du8; 16]).unwrap();
        w.set_tee_enabled(true);
        w.set_trusted_tee_measurement(crate::tee::mock::MOCK_MEASUREMENT);
        let err = w
            .sign_with_privacy(b"hello", &ForgingRuntime, &verifier)
            .unwrap_err();
        assert!(matches!(err, WalletError::TeeUnavailable(_)));
    }

    #[test]
    fn d2_wallet_view_key_bound_to_seed() {
        let mut w = Wallet::from_entropy(&[0x77u8; 16]).unwrap();
        let vk = w.ensure_view_key();
        let again = w.ensure_view_key();
        assert_eq!(vk, again);
        let disc = w.export_view_key_for_disclosure().unwrap();
        assert_eq!(disc.view_key, vk);
    }

    #[test]
    fn d2_wallet_overspend_rejected() {
        let mut w = Wallet::from_entropy(&[0x88u8; 16]).unwrap();
        w.set_note_privacy_enabled(true);
        let (blinding, _, _) = w.prepare_receive_note(50, 0).unwrap();
        let input = w.note_input_from_receive(50, blinding).unwrap();
        let req = PrivateTransferRequest {
            input,
            to: [2u8; 32],
            send_amount: 51,
            output_blinding: 1,
            change_recipient_tag: None,
            change_blinding: None,
        };
        let err = w
            .build_private_transfer(req, &w.default_tee_runtime())
            .unwrap_err();
        assert!(matches!(err, WalletError::InvalidPrivateTransfer(_)));
    }
}
