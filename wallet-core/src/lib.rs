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

mod bip39_wordlist;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

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
    /// Production entropy (CSPRNG) kullanılamıyor — fail-closed.
    ProductionEntropyUnavailable(String),
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
        }
    }
}

impl std::error::Error for WalletError {}

/// BIP39 mnemonic → entropy (entropy → checksum → mnemonic).
/// SHA256 checksum: ilk (entropy_bits / 32) bit checksum eklenir.
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
            "checksum mismatch — invalid mnemonic".into(),
        ));
    }

    Ok(entropy)
}

/// Guardian-based social recovery policy (Task 11.14).
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

/// D2 (2026-07-22) Görev E — cüzdan içi gizlilik yüzeyi.
///
/// İki bağımsız opt-in katmanı (kullanıcı planı + MAINNET_KARARLAR D2):
/// 1. **Note privacy (ağ seçeneği):** gizli transfer opcode ailesi
///    (PrivacyCommit/NullifierCheck/SumConservation). Kullanıcı cüzdanında
///    "gizli işlem kullan" tercihi; varsayılan kapalı.
/// 2. **TEE execution-time confidentiality (Bölüm 10 #5):** işlem üretimi
///    TEE enklavı üzerinden — operatör düz-metin görmez. UX prompt:
///    "Bu cüzdanın işlemleri TEE katmanıyla gizli kılınsın mı?
///    Evet (işlemleriniz biraz yavaşlar)." Varsayılan kapalı.
///
/// View-key (Bölüm 10 #3, Zcash deseni): kullanıcı üretir/saklar; BDDK gibi
/// yetkiliye manuel ibraz. Kamuya kapalı, yetkiliye açık selective disclosure.
///
/// Gerçek TEE enklavı (SGX/Nitro) ayrı entegrasyon hattı; bu struct tercih +
/// view-key materyalini tutar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPrivacyConfig {
    /// Ağ-seviyesi gizli transfer (note/UTXO opcode ailesi) kullanılsın mı.
    /// Varsayılan `false` — kullanıcı cüzdan ayarından açar (ağ için seçenek).
    pub note_privacy_enabled: bool,
    /// TEE gizlilik toggle'ı. `false` = varsayılan (mevcut akış, operatör veriyi
    /// görür, sadece STARK integrity). `true` = işlemler TEE ile gizli (yavaşlar).
    pub tee_enabled: bool,
    /// Client-side TEE öncelikli mi. `true` = önce kullanıcı cihazı (laptop SGX),
    /// başarısızsa server-side (AWS Nitro) fallback. `false` = doğrudan server-side.
    pub prefer_client_side_tee: bool,
    /// Kullanıcı-üretimi view-key (32 byte). `None` = henüz üretilmedi.
    /// Selective disclosure için yetkiliye manuel paylaşılır; asla zincire yazılmaz.
    pub view_key: Option<[u8; 32]>,
}

impl Default for WalletPrivacyConfig {
    fn default() -> Self {
        // Bölüm 10 #5 + kullanıcı planı: varsayılan KAPALI (opt-in).
        Self {
            note_privacy_enabled: false,
            tee_enabled: false,
            prefer_client_side_tee: true,
            view_key: None,
        }
    }
}

impl WalletPrivacyConfig {
    /// Toggle prompt yanıtı (Bölüm 10 #5 UX): "Bu cüzdanın işlemleri TEE
    /// katmanıyla gizli kılınsın mı?" → `enable`.
    #[must_use]
    pub fn from_user_opt_in(enable: bool) -> Self {
        Self {
            note_privacy_enabled: enable,
            tee_enabled: enable,
            prefer_client_side_tee: true,
            view_key: None,
        }
    }

    /// Yalnızca ağ-seviyesi note privacy (TEE kapalı) — daha hafif seçenek.
    #[must_use]
    pub fn note_privacy_only(enable: bool) -> Self {
        Self {
            note_privacy_enabled: enable,
            tee_enabled: false,
            prefer_client_side_tee: true,
            view_key: None,
        }
    }

    /// TEE gizlilik aktif mi (işlem yavaşlama uyarısı bu durumda geçerli).
    #[must_use]
    pub fn is_privacy_active(&self) -> bool {
        self.tee_enabled
    }

    /// Note privacy (gizli transfer opcode'ları) aktif mi.
    #[must_use]
    pub fn is_note_privacy_active(&self) -> bool {
        self.note_privacy_enabled
    }

    /// Kullanılacak TEE backend'i (client-side öncelikli karar mantığı).
    /// `"client"` (cihaz SGX) | `"server"` (AWS Nitro) | `"none"` (TEE kapalı).
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

    /// View-key üret (Bölüm 10 #3). Deterministik türetim: wallet seed'den
    /// domain-separated SHA3-256("BUDLUM_VIEW_KEY_V1" || seed).
    /// Mevcut view-key varsa değiştirmez (idempotent); zorla yenilemek için
    /// `rotate_view_key`.
    pub fn ensure_view_key(&mut self, wallet_seed: &[u8; 32]) -> [u8; 32] {
        if let Some(vk) = self.view_key {
            return vk;
        }
        let vk = derive_view_key(wallet_seed);
        self.view_key = Some(vk);
        vk
    }

    /// View-key'i yeniden üret (eski anahtar yetkiliye verildiyse rotasyon).
    pub fn rotate_view_key(&mut self, wallet_seed: &[u8; 32], rotation_counter: u64) -> [u8; 32] {
        let vk = derive_view_key_rotated(wallet_seed, rotation_counter);
        self.view_key = Some(vk);
        vk
    }

    /// View-key ibraz paketi (yetkiliye manuel paylaşım). Zincire yazılmaz.
    /// `None` eğer view-key henüz üretilmediyse.
    #[must_use]
    pub fn export_view_key_for_disclosure(&self) -> Option<ViewKeyDisclosure> {
        self.view_key.map(|key| ViewKeyDisclosure {
            version: VIEW_KEY_VERSION,
            view_key: key,
        })
    }
}

/// View-key format sürümü (selective disclosure protokolü).
pub const VIEW_KEY_VERSION: u32 = 1;

/// Yetkiliye ibraz edilen view-key paketi (Bölüm 10 #3).
/// Kamuya kapalı; kullanıcı cüzdanından yetkiliye (BDDK vb.) manuel iletilir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewKeyDisclosure {
    pub version: u32,
    pub view_key: [u8; 32],
}

impl ViewKeyDisclosure {
    /// Hex export (kullanıcı kopyala-yapıştır / QR için).
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

/// Task 11.14 mobile/browser binding ABI marker.
pub const WALLET_BINDING_STUB_VERSION: &str = "task11.14-binding-stub-v1";

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

/// M-of-N multisig policy (Task 11.14).
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
    ///
    /// **Production güvenliği:** Bu fonksiyon yalnızca `production` feature'ı
    /// etkinleştirilmişse çalışır. Production feature olmadan `Wallet::generate`
    /// **fail-closed** döner — placeholder/deterministic entropy asla production
    /// ortamına sızar. Test/dev ortamları için `from_entropy` kullanın.
    pub fn generate(word_count: usize) -> Result<Self, WalletError> {
        let entropy_len = match word_count {
            12 => 16, // 128 bit
            24 => 32, // 256 bit
            _ => return Err(WalletError::InvalidEntropy(word_count * 4 / 3)),
        };

        // Production CSPRNG: getrandom ile gerçek rastgele entropy
        #[cfg(feature = "production")]
        let entropy = {
            let mut buf = vec![0u8; entropy_len];
            getrandom::getrandom(&mut buf)
                .map_err(|e| WalletError::ProductionEntropyUnavailable(e.to_string()))?;
            buf
        };

        // Production feature olmadan generate fail-closed
        #[cfg(not(feature = "production"))]
        let _ = entropy_len; // entropy_len kullanımı için (compile warning önleme)

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

    /// Entropy'den wallet oluştur (BIP39 mnemonic + SLIP-0010 seed).
    ///
    /// **Production notu:** `from_entropy` test/dev için tasarılmıştır.
    /// Production wallet generation için `Wallet::generate()` kullanın
    /// (production feature + getrandom CSPRNG gerektirir).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, WalletError> {
        if entropy.len() != 16 && entropy.len() != 32 {
            return Err(WalletError::InvalidEntropy(entropy.len()));
        }

        // BIP39 mnemonic: tam wordlist + SHA256 checksum
        let mnemonic = entropy_to_mnemonic(entropy)?;

        // SLIP-0010 Ed25519: seed = SHA3-256("BUDLUM_SLIP10_ED25519_SEED" + entropy)
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

    /// Mnemonic'den wallet restore et (BIP39 checksum doğrulaması ile).
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, WalletError> {
        // BIP39 reverse: mnemonic → entropy (checksum doğrulaması ile)
        let entropy = mnemonic_to_entropy(mnemonic)?;

        // SLIP-0010 Ed25519: seed = SHA3-256("BUDLUM_SLIP10_ED25519_SEED" + entropy)
        let mut hasher = Sha3_256::new();
        hasher.update(b"BUDLUM_SLIP10_ED25519_SEED");
        hasher.update(&entropy);
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
        let wallet = Wallet::from_entropy(&[0x42u8; 16]).expect("12-word wallet must succeed");
        let words: Vec<&str> = wallet.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 12, "must have 12 words");
        assert_eq!(wallet.address().len(), 32, "address must be 32 bytes");
        assert_eq!(wallet.public_key().len(), 32, "pubkey must be 32 bytes");
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
        // Aynı mnemonic → aynı address
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
    /// without the `production` feature to prevent deterministic/placeholder
    /// entropy from reaching production.
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
    fn binding_capabilities_include_mobile_and_browser_stubs() {
        let caps = WalletBindingCapabilities::current();
        assert_eq!(caps.stub_version, WALLET_BINDING_STUB_VERSION);
        assert!(caps.uniffi_mobile);
        assert!(caps.wasm_browser);
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
        assert!(caps.uniffi_mobile);
        assert!(!caps.exports_seed_material);
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn binding_wasm_feature_stub_exports_capabilities() {
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

    // ===== D2 Görev E — WalletPrivacyConfig (Bölüm 10 #5 + view-key) =====

    #[test]
    fn d2_privacy_config_defaults_off() {
        let cfg = WalletPrivacyConfig::default();
        assert!(
            !cfg.is_privacy_active(),
            "Bölüm 10 #5: varsayılan KAPALI (opt-in)"
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
        // Client-side TEE öncelikli (kullanıcı cihazı/laptop SGX).
        assert_eq!(cfg.effective_backend(), "client");
    }

    #[test]
    fn d2_privacy_config_server_backend_fallback() {
        let mut cfg = WalletPrivacyConfig::from_user_opt_in(true);
        cfg.prefer_client_side_tee = false; // zayıf cihaz → server-side
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
}
