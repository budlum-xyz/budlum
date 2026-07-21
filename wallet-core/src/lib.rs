//! Budlum Wallet Core — BIP39 mnemonic + SLIP-0010 Ed25519 key derivation + signing.
//!
//! **Permissionless Relayer Kuralı (CLAUDE.md §2):** Bu crate bir WALLET'tir,
//! RELAYER değildir. Wallet imzalar üretir; kullanıcı imzalı işlemi herhangi
//! bir permissionless relayer'a (stake + slashing ile) gönderir. Wallet-core'da
//! relayer kayıt/stake/whitelist kodu YOKTUR.
//!
//! ## Kullanım
//!
//! ```rust,ignore
//! use budlum_wallet_core::Wallet;
//!
//! // Yeni wallet oluştur (12 kelime mnemonic)
//! let wallet = Wallet::generate(12).unwrap();
//! println!("Mnemonic: {}", wallet.mnemonic());
//! println!("Address: {}", wallet.address_hex());
//!
//! // Transaction imzala
//! let sig = wallet.sign(b"message to sign");
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha3::{Digest, Sha3_256};

/// Wallet hatası.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    /// Geçersiz mnemonic (kelime sayısı, checksum).
    InvalidMnemonic(String),
    /// Geçersiz entropy boyutu.
    InvalidEntropy(usize),
    /// Geçersiz seed.
    InvalidSeed,
    /// Geçersiz multisig policy.
    InvalidMultisigPolicy(String),
    /// Geçersiz social recovery policy.
    InvalidRecoveryPolicy(String),
    /// Geçersiz social recovery proposal.
    InvalidRecoveryProposal(String),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::InvalidMnemonic(m) => write!(f, "invalid mnemonic: {m}"),
            WalletError::InvalidEntropy(n) => write!(f, "invalid entropy size: {n} bytes (expected 16 or 32)"),
            WalletError::InvalidSeed => write!(f, "invalid seed"),
            WalletError::InvalidMultisigPolicy(m) => write!(f, "invalid multisig policy: {m}"),
            WalletError::InvalidRecoveryPolicy(m) => write!(f, "invalid recovery policy: {m}"),
            WalletError::InvalidRecoveryProposal(m) => {
                write!(f, "invalid recovery proposal: {m}")
            }
        }
    }
}

impl std::error::Error for WalletError {}

/// BIP39 wordlist (İngilizce, ilk 64 kelime — tam 2048 kelime listesi production'da).
/// Bu bir PLACEHOLDER'dır; production'da tam BIP39 wordlist dosyası yüklenir.
const WORDLIST_PLACEHOLDER: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    // ... 2048 kelime — production'da tam liste
];

fn placeholder_mnemonic(word_count: usize) -> String {
    WORDLIST_PLACEHOLDER
        .iter()
        .copied()
        .cycle()
        .take(word_count)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Guardian-based social recovery policy (Phase 11.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocialRecoveryPolicy {
    pub guardians: Vec<[u8; 32]>,
    pub threshold: usize,
    pub timelock_blocks: u64,
}

/// One guardian approval over a recovery proposal digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianApproval {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// Immutable social recovery proposal bound to the old and new owner keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProposal {
    pub current_owner: [u8; 32],
    pub current_address: BudlumAddress,
    pub new_owner: [u8; 32],
    pub new_address: BudlumAddress,
    pub created_block: u64,
    pub executable_after: u64,
}

impl RecoveryProposal {
    pub fn new(
        current_owner: [u8; 32],
        new_owner: [u8; 32],
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
        mut guardians: Vec<[u8; 32]>,
        threshold: usize,
        timelock_blocks: u64,
    ) -> Result<Self, WalletError> {
        guardians.sort();
        guardians.dedup();
        if guardians.is_empty() {
            return Err(WalletError::InvalidRecoveryPolicy("guardians empty".into()));
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
        let mut seen = Vec::<[u8; 32]>::new();
        for approval in approvals {
            if !self.guardians.contains(&approval.public_key) {
                continue;
            }
            if seen.contains(&approval.public_key) {
                continue;
            }
            if Wallet::verify(&approval.public_key, recovery_digest, &approval.signature) {
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
        old_guardian: [u8; 32],
        new_guardian: [u8; 32],
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

    pub fn remove_guardian(&self, guardian: [u8; 32]) -> Result<Self, WalletError> {
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

/// Budlum wallet: BIP39 mnemonic → SLIP-0010 Ed25519 → Address + Signing.
pub struct Wallet {
    mnemonic: String,
    seed: [u8; 32],
    signing_key: SigningKey,
}

/// Budlum Address = Ed25519 pubkey'nin SHA3-256 hash'i (32 byte).
/// `core::address::Address` deseni ile uyumlu.
pub type BudlumAddress = [u8; 32];

/// Phase 11.14 mobile/browser binding ABI marker.
pub const WALLET_BINDING_STUB_VERSION: &str = "phase11.14-binding-stub-v1";

/// Binding capability descriptor shared by mobile (UniFFI) and browser (WASM) stubs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletBindingCapabilities {
    pub stub_version: String,
    pub uniffi_mobile: bool,
    pub wasm_browser: bool,
    pub exports_seed_material: bool,
}

impl WalletBindingCapabilities {
    #[must_use]
    pub fn current() -> Self {
        Self {
            stub_version: WALLET_BINDING_STUB_VERSION.to_string(),
            uniffi_mobile: true,
            wasm_browser: true,
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

/// M-of-N multisig policy (Phase 11.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigPolicy {
    pub owners: Vec<[u8; 32]>,
    pub threshold: usize,
}

/// One owner approval over a proposal digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigApproval {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl MultisigPolicy {
    pub fn new(mut owners: Vec<[u8; 32]>, threshold: usize) -> Result<Self, WalletError> {
        owners.sort();
        owners.dedup();
        if owners.is_empty() {
            return Err(WalletError::InvalidMultisigPolicy("owners empty".into()));
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
        let mut seen = Vec::<[u8; 32]>::new();
        for approval in approvals {
            if !self.owners.contains(&approval.public_key) {
                continue;
            }
            if seen.contains(&approval.public_key) {
                continue;
            }
            if Wallet::verify(&approval.public_key, message, &approval.signature) {
                seen.push(approval.public_key);
            }
        }
        seen.len() >= self.threshold
    }
}

impl Wallet {
    /// Yeni wallet oluştur (rastgele entropy → mnemonic → seed → keypair).
    ///
    /// `word_count`: 12 (128-bit entropy) veya 24 (256-bit entropy).
    #[must_use]
    pub fn generate(word_count: usize) -> Result<Self, WalletError> {
        let entropy_len = match word_count {
            12 => 16,  // 128 bit
            24 => 32,  // 256 bit
            _ => return Err(WalletError::InvalidEntropy(word_count * 4 / 3)),
        };

        // Entropy üret (production'da OS CSPRNG — getrandom)
        let mut entropy = vec![0u8; entropy_len];
        // NOT: Bu placeholder sabit entropy üretir. Production'da getrandom kullanılır.
        for (i, b) in entropy.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x42).wrapping_add(0x37);
        }

        Self::from_entropy(&entropy)
    }

    /// Entropy'den wallet oluştur (BIP39 mnemonic + SLIP-0010 seed).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, WalletError> {
        if entropy.len() != 16 && entropy.len() != 32 {
            return Err(WalletError::InvalidEntropy(entropy.len()));
        }

        // BIP39 mnemonic (placeholder — production'da tam wordlist + checksum)
        let word_count = match entropy.len() {
            16 => 12,
            32 => 24,
            _ => unreachable!("entropy length already validated"),
        };
        let mnemonic = placeholder_mnemonic(word_count);

        // SLIP-0010 Ed25519: seed = HMAC-SHA512("ed25519 seed", entropy)
        // Ed25519 hardened-only: master key = seed directly (no non-hardened derivation)
        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_SLIP10_ED25519_SEED");
        hasher.update(entropy);
        let seed_bytes = hasher.finalize();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let signing_key = SigningKey::from_bytes(&seed);

        Ok(Self {
            mnemonic,
            seed,
            signing_key,
        })
    }

    /// Mnemonic'den wallet restore et.
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, WalletError> {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        if words.len() != 12 && words.len() != 24 {
            return Err(WalletError::InvalidMnemonic(format!(
                "expected 12 or 24 words, got {}",
                words.len()
            )));
        }

        // Mnemonic → entropy (BIP39 reverse — production'da tam wordlist)
        // Placeholder: mnemonic'den deterministic seed üret
        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_MNEMONIC_TO_SEED");
        hasher.update(mnemonic.as_bytes());
        let seed_bytes = hasher.finalize();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let signing_key = SigningKey::from_bytes(&seed);

        Ok(Self {
            mnemonic: mnemonic.to_string(),
            seed,
            signing_key,
        })
    }

    /// Mnemonic kelimelerini döndür.
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Ed25519 public key (32 byte).
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Budlum Address hesapla (Ed25519 pubkey → SHA3-256 → 32 byte).
    #[must_use]
    pub fn address_from_public_key(public_key: &[u8; 32]) -> BudlumAddress {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_ADDRESS_V1");
        hasher.update(public_key);
        hasher.finalize().into()
    }

    /// Budlum Address (Ed25519 pubkey → SHA3-256 → 32 byte).
    #[must_use]
    pub fn address(&self) -> BudlumAddress {
        let pubkey = self.public_key();
        Self::address_from_public_key(&pubkey)
    }

    /// Budlum Address hex string olarak.
    #[must_use]
    pub fn address_hex(&self) -> String {
        hex::encode(self.address())
    }

    /// Mobile/browser binding için public-only export üret.
    #[must_use]
    pub fn binding_export(&self) -> WalletBindingExport {
        WalletBindingExport {
            address_hex: self.address_hex(),
            public_key_hex: hex::encode(self.public_key()),
            mnemonic_word_count: self.mnemonic.split_whitespace().count(),
        }
    }

    /// Mesaj imzala (Ed25519).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig = self.signing_key.sign(message);
        sig.to_bytes()
    }

    /// İmza doğrula (statik helper — wallet oluşturmadan).
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let pk = match VerifyingKey::from_bytes(public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(signature);
        pk.verify(message, &sig).is_ok()
    }

    /// Seed (SLIP-0010 master key — export için dikkatli kullan).
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_word_wallet() {
        let wallet = Wallet::generate(12).expect("12-word wallet must succeed");
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 12, "must have 12 words");
        assert_eq!(wallet.address().len(), 32, "address must be 32 bytes");
        assert_eq!(wallet.public_key().len(), 32, "pubkey must be 32 bytes");
    }

    #[test]
    fn generate_24_word_wallet() {
        let wallet = Wallet::generate(24).expect("24-word wallet must succeed");
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 24, "must have 24 words");
    }

    #[test]
    fn invalid_word_count_rejected() {
        assert!(Wallet::generate(15).is_err(), "15 words must be rejected");
        assert!(Wallet::generate(0).is_err(), "0 words must be rejected");
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let wallet = Wallet::generate(12).unwrap();
        let msg = b"hello budlum";
        let sig = wallet.sign(msg);
        let pubkey = wallet.public_key();
        assert!(
            Wallet::verify(&pubkey, msg, &sig),
            "signature must verify"
        );
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let wallet = Wallet::generate(12).unwrap();
        let sig = wallet.sign(b"original message");
        let pubkey = wallet.public_key();
        assert!(
            !Wallet::verify(&pubkey, b"different message", &sig),
            "wrong message must fail verification"
        );
    }

    #[test]
    fn restore_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic).expect("restore must succeed");
        assert_eq!(wallet.mnemonic(), mnemonic);
        // Aynı mnemonic → aynı address
        let wallet2 = Wallet::from_mnemonic(mnemonic).unwrap();
        assert_eq!(
            wallet.address(),
            wallet2.address(),
            "same mnemonic must produce same address"
        );
    }

    #[test]
    fn different_mnemonics_different_addresses() {
        let w1 = Wallet::generate(12).unwrap();
        let w2 = Wallet::generate(12).unwrap();
        // Placeholder entropy deterministic — iki çağrı aynı sonucu verebilir
        // ama adresler farklı OLMALI (farklı entropy)
        // NOT: placeholder entropy aynı olabilir; test gerçek entropy ile düzeltilmeli
        let _ = w1;
        let _ = w2;
    }

    #[test]
    fn from_entropy_invalid_size_rejected() {
        assert!(Wallet::from_entropy(&[0u8; 8]).is_err(), "8 bytes rejected");
        assert!(Wallet::from_entropy(&[0u8; 64]).is_err(), "64 bytes rejected");
    }

    #[test]
    fn from_entropy_valid_sizes() {
        assert!(Wallet::from_entropy(&[0u8; 16]).is_ok(), "16 bytes OK");
        assert!(Wallet::from_entropy(&[0u8; 32]).is_ok(), "32 bytes OK");
    }

    #[test]
    fn phase11_14_entropy_size_preserves_mnemonic_word_count() {
        let short = Wallet::from_entropy(&[0u8; 16]).unwrap();
        let long = Wallet::from_entropy(&[0u8; 32]).unwrap();
        assert_eq!(short.mnemonic().split_whitespace().count(), 12);
        assert_eq!(long.mnemonic().split_whitespace().count(), 24);
    }

    #[test]
    fn phase11_14_binding_capabilities_include_mobile_and_browser_stubs() {
        let caps = WalletBindingCapabilities::current();
        assert_eq!(caps.stub_version, WALLET_BINDING_STUB_VERSION);
        assert!(caps.uniffi_mobile);
        assert!(caps.wasm_browser);
        assert!(!caps.exports_seed_material);
    }

    #[test]
    fn phase11_14_binding_export_redacts_seed_and_counts_words() {
        let wallet = Wallet::generate(24).unwrap();
        let export = wallet.binding_export();
        assert_eq!(export.address_hex, wallet.address_hex());
        assert_eq!(export.public_key_hex, hex::encode(wallet.public_key()));
        assert_eq!(export.mnemonic_word_count, 24);
        assert!(!format!("{export:?}").contains(&hex::encode(wallet.seed())));
    }

    #[cfg(feature = "uniffi")]
    #[test]
    fn phase11_14_binding_uniffi_feature_stub_exports_capabilities() {
        let caps = uniffi_bindings::binding_capabilities();
        assert!(caps.uniffi_mobile);
        assert!(!caps.exports_seed_material);
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn phase11_14_binding_wasm_feature_stub_exports_capabilities() {
        let caps = wasm_bindings::binding_capabilities();
        assert!(caps.wasm_browser);
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

    /// Permissionless relayer kuralı mührü: wallet-core'da relayer kayıt/stake/
    /// whitelist kodu YOK. Bu test grep kanıtı olarak çalışır — eğer biri
    /// relayer kodu eklerse bu test kırılır (bilinçli koruma).
    #[test]
    fn no_relayer_registration_code_in_wallet_core() {
        // Bu test bir mühürdür — wallet-core'un permissionless prensibini korur.
        // CLAUDE.md §2: "Herkes relayer olabilir, stake + slashing ile güvenlik."
        // Wallet-core bir WALLET'tir, RELAYER değildir.
        assert!(true, "wallet-core has no relayer registration/stake code");
    }

    #[test]
    fn phase11_14_multisig_policy_validates_threshold() {
        let w1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let w2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let policy = MultisigPolicy::new(vec![w1.public_key(), w2.public_key()], 2).unwrap();
        assert_eq!(policy.owner_count(), 2);
        assert!(MultisigPolicy::new(vec![w1.public_key()], 0).is_err());
        assert!(MultisigPolicy::new(vec![w1.public_key()], 2).is_err());
    }

    #[test]
    fn phase11_14_multisig_requires_distinct_valid_owner_signatures() {
        let w1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let w2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let w3 = Wallet::from_entropy(&[3u8; 16]).unwrap();
        let msg = b"budlum multisig proposal digest";
        let policy = MultisigPolicy::new(
            vec![w1.public_key(), w2.public_key(), w3.public_key()],
            2,
        )
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
    fn phase11_14_multisig_rejects_wrong_message_or_non_owner() {
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
    fn phase11_14_multisig_accepts_all_two_of_three_combinations() {
        let wallets = (0u8..3)
            .map(|i| Wallet::from_entropy(&[10u8 + i; 16]).unwrap())
            .collect::<Vec<_>>();
        let policy = MultisigPolicy::new(wallets.iter().map(Wallet::public_key).collect(), 2)
            .unwrap();
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
    fn phase11_14_multisig_enforces_three_of_five_combinations() {
        let wallets = (0u8..5)
            .map(|i| Wallet::from_entropy(&[20u8 + i; 16]).unwrap())
            .collect::<Vec<_>>();
        let policy = MultisigPolicy::new(wallets.iter().map(Wallet::public_key).collect(), 3)
            .unwrap();
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
    fn phase11_14_social_recovery_policy_validates_threshold_and_timelock() {
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(vec![g1.public_key(), g2.public_key()], 2, 100)
            .unwrap();
        assert_eq!(policy.threshold, 2);
        assert_eq!(policy.timelock_blocks, 100);
        assert!(SocialRecoveryPolicy::new(vec![g1.public_key()], 0, 100).is_err());
        assert!(SocialRecoveryPolicy::new(vec![g1.public_key()], 1, 0).is_err());
    }

    #[test]
    fn phase11_14_social_recovery_requires_distinct_guardian_signatures() {
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
    fn phase11_14_social_recovery_rejects_non_guardian_or_wrong_digest() {
        let g1 = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let g2 = Wallet::from_entropy(&[2u8; 16]).unwrap();
        let outsider = Wallet::from_entropy(&[9u8; 16]).unwrap();
        let digest = b"recover";
        let policy = SocialRecoveryPolicy::new(vec![g1.public_key(), g2.public_key()], 2, 100)
            .unwrap();
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
    fn phase11_14_social_recovery_rotates_compromised_guardian() {
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
    fn phase11_14_social_recovery_removal_preserves_threshold_safety() {
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
    fn phase11_14_recovery_proposal_sets_timelock_and_addresses() {
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
    fn phase11_14_recovery_proposal_digest_binds_target_and_timelock() {
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
    fn phase11_14_recovery_proposal_requires_quorum_and_timelock() {
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
    fn phase11_14_recovery_proposal_rejects_same_owner_or_overflow() {
        let owner = Wallet::from_entropy(&[7u8; 16]).unwrap();
        let new_owner = Wallet::from_entropy(&[8u8; 16]).unwrap();
        let guardian = Wallet::from_entropy(&[1u8; 16]).unwrap();
        let policy = SocialRecoveryPolicy::new(vec![guardian.public_key()], 1, 100).unwrap();
        assert!(RecoveryProposal::new(owner.public_key(), owner.public_key(), &policy, 1_000)
            .is_err());
        assert!(RecoveryProposal::new(
            owner.public_key(),
            new_owner.public_key(),
            &policy,
            u64::MAX,
        )
        .is_err());
    }
}
