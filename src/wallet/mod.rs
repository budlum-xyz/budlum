//! The command-line wallet.
//!
//! A new key file is version 2: its address is the Address V3 of account 0,
//! index 0 and it signs V7 composite
//! transactions. A version 1 file (the V5, ML-DSA-87 only address) is still
//! opened for devnet and cannot sign on mainnet. The text below describes the
//! entropy and the key file, which both versions share; the ML-DSA-87 seed
//! rule it names is the version 1 (V5) derivation.
//!
//! - A 24-word BIP39 mnemonic (256 bits of entropy). A 12-word phrase is
//!   refused here as on mainnet: the testnet is the mainnet rehearsal
//!   (decision A-07).
//! - The ML-DSA-87 key is derived from the entropy exactly as
//!   `crates/wallet-core` derives it: `SHA3-256("BUDLUM_MLDSA87_SEED_V1" ‖
//!   entropy)` is the FIPS 204 `KeyGen_internal` seed
//!   ([`WalletKeyPair::from_seed`]). The BIP39 word list is wallet-core's own
//!   file, so a phrase made by either opens the same account in the other.
//! - The key file holds the entropy sealed with a password: PBKDF2-HMAC-SHA256
//!   derives the key, XChaCha20-Poly1305 seals. A wrong password fails the
//!   authentication tag; nothing is ever written in the clear.

use crate::core::address::Address;
use crate::crypto::primitives::WalletKeyPair;
use serde::{Deserialize, Serialize};

#[path = "../../crates/wallet-core/src/bip39_wordlist.rs"]
mod bip39_wordlist;

/// Words in a mnemonic: 256 bits of entropy and an 8-bit checksum.
/// exposed for: wallet surface - the grant/reveal doors' readers land with the custody wave.
pub const MNEMONIC_WORDS: usize = 24;
/// PBKDF2 iterations for a new key file (OWASP 2023 figure for SHA-256).
pub const DEFAULT_KDF_ITERATIONS: u32 = 600_000;
/// The key-file format this module writes: the address is the Address V3 of
/// account 0, index 0, derived from the entropy with an empty
/// derivation password.
const KEY_FILE_VERSION: u32 = 2;
/// The earlier format, whose address is the V5 (ML-DSA-87 only) address. It is
/// still opened so a devnet wallet keeps working; it cannot sign on mainnet.
const LEGACY_KEY_FILE_VERSION: u32 = 1;
const KDF_NAME: &str = "pbkdf2-hmac-sha256";
const CIPHER_NAME: &str = "xchacha20poly1305";

/// Why a wallet operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletError {
    #[error("a mnemonic has 24 words; this one has {0} (12-word phrases are refused)")]
    WordCount(usize),
    #[error("'{0}' is not a BIP39 English word")]
    UnknownWord(String),
    #[error("the mnemonic checksum does not match: a word is wrong or out of order")]
    Checksum,
    #[error(
        "the key file is not a version {KEY_FILE_VERSION} {KDF_NAME}/{CIPHER_NAME} wallet: {0}"
    )]
    Format(String),
    #[error("the password does not open this key file")]
    WrongPassword,
    #[error("the key file names address {0}, but its key derives another")]
    AddressMismatch(String),
}

/// SHA-256 of the concatenated parts.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// HMAC-SHA256 (RFC 2104) over the concatenated parts.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    let hashed;
    let key = if key.len() > BLOCK {
        hashed = sha256(&[key]);
        hashed.as_slice()
    } else {
        key
    };
    for (slot, byte) in block.iter_mut().zip(key) {
        *slot = *byte;
    }
    let ipad = block.map(|b| b ^ 0x36);
    let opad = block.map(|b| b ^ 0x5c);
    let mut inner_parts: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
    inner_parts.push(&ipad);
    inner_parts.extend_from_slice(parts);
    let inner = sha256(&inner_parts);
    sha256(&[&opad, &inner])
}

/// PBKDF2-HMAC-SHA256 (RFC 8018) with a 32-byte output (one block).
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut u = hmac_sha256(password, &[salt, &1u32.to_be_bytes()]);
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &[&u]);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// The 24 words of `entropy`.
#[must_use]
pub fn mnemonic_from_entropy(entropy: &[u8; 32]) -> String {
    let [checksum, ..] = sha256(&[entropy]);
    // 264 bits: the entropy, then the checksum byte (8 bits for 256 bits).
    let mut bits = Vec::with_capacity(264);
    for byte in entropy.iter().chain(std::iter::once(&checksum)) {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    bits.chunks(11)
        .map(|chunk| {
            let index = chunk
                .iter()
                .fold(0usize, |acc, bit| (acc << 1) | usize::from(*bit));
            bip39_wordlist::index_to_word(index).unwrap_or("?")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The entropy of a 24-word mnemonic, checksum verified.
///
/// # Errors
///
/// Another word count (12-word phrases included), an unknown word, or a
/// checksum mismatch.
pub fn entropy_from_mnemonic(mnemonic: &str) -> Result<[u8; 32], WalletError> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.len() != MNEMONIC_WORDS {
        return Err(WalletError::WordCount(words.len()));
    }
    let mut bits = Vec::with_capacity(264);
    for word in &words {
        let index = bip39_wordlist::word_to_index(&word.to_ascii_lowercase())
            .ok_or_else(|| WalletError::UnknownWord((*word).to_string()))?;
        for shift in (0..11).rev() {
            bits.push(u8::from((index >> shift) & 1 == 1));
        }
    }
    let mut bytes = [0u8; 33];
    for (byte, chunk) in bytes.iter_mut().zip(bits.chunks(8)) {
        *byte = chunk.iter().fold(0u8, |acc, bit| (acc << 1) | bit);
    }
    let [entropy @ .., checksum] = bytes;
    let [expected, ..] = sha256(&[&entropy]);
    if expected != checksum {
        return Err(WalletError::Checksum);
    }
    Ok(entropy)
}

/// The ML-DSA-87 key of `entropy`, as wallet-core derives it.
#[must_use]
/// exposed for: wallet surface - the grant/reveal doors' readers land with the custody wave.
pub fn keypair_from_entropy(entropy: &[u8; 32]) -> WalletKeyPair {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"BUDLUM_MLDSA87_SEED_V1");
    hasher.update(entropy);
    let digest = hasher.finalize();
    // The derived seed is wiped when it goes out of scope.
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&digest);
    WalletKeyPair::from_seed(&seed)
}

/// The V3 account `(account, index)` of `entropy` with an empty derivation
/// password: the composite keys, the recovery seed and the Address V3.
///
/// # Errors
///
/// [`WalletError::Format`] when a key component cannot be derived.
/// exposed for: wallet surface - the grant/reveal doors' readers land with the custody wave.
pub fn user_account_from_entropy(
    entropy: &[u8; 32],
    account: u32,
    index: u32,
) -> Result<crate::crypto::key_derivation::UserAccount, WalletError> {
    crate::crypto::key_derivation::RootSecret::derive(entropy, "")
        .and_then(|root| root.user_account(account, index))
        .map_err(|e| WalletError::Format(format!("key derivation: {e}")))
}

/// Fresh entropy from the operating system's generator.
#[must_use]
pub fn generate_entropy() -> [u8; 32] {
    use rand::Rng;
    let mut entropy = [0u8; 32];
    rand::rng().fill_bytes(&mut entropy);
    entropy
}

/// Open a sealed key file the way every command-line tool does: the
/// password from the first line of `password_file` (which must not be
/// readable by others) or else from `BUD_WALLET_PASSWORD`. A password never
/// travels on the command line.
///
/// # Errors
///
/// An unreadable or malformed file, a missing or short password, or a wrong
/// password.
pub fn open_key_file(
    key_file: &std::path::Path,
    password_file: Option<&std::path::Path>,
) -> Result<SigningKey, String> {
    let password = match password_file {
        Some(path) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)
                    .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?
                    .permissions()
                    .mode();
                if mode & 0o077 != 0 {
                    return Err(format!(
                        "{} has mode {:03o}; use chmod 600",
                        path.display(),
                        mode & 0o777
                    ));
                }
            }
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        }
        None => std::env::var("BUD_WALLET_PASSWORD").map_err(|_| {
            String::from(
                "no wallet password: pass --password-file <path> or set BUD_WALLET_PASSWORD",
            )
        })?,
    };
    if password.chars().count() < 8 {
        return Err("the wallet password must have at least 8 characters".into());
    }
    let raw = std::fs::read_to_string(key_file)
        .map_err(|e| format!("cannot read {}: {e}", key_file.display()))?;
    let file: KeyFile = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not a wallet key file: {e}", key_file.display()))?;
    let entropy = file.open(&password).map_err(|e| e.to_string())?;
    SigningKey::from_entropy(&entropy, file.is_legacy()).map_err(|e| e.to_string())
}

/// The key a tool signs its transactions with.
///
/// A V3 wallet signs V7 composite transactions, the only user form a
/// mainnet node admits. A legacy file opens to the V5 ML-DSA-87 key,
/// which devnet and testnet still accept.
pub enum SigningKey {
    /// A V3 account (V7 composite).
    V3(Box<crate::crypto::key_derivation::UserAccount>),
    /// A legacy V5 key.
    V5(WalletKeyPair),
}

impl SigningKey {
    /// The key of `entropy`: the V3 account `(0, 0)`, or the V5 key when the
    /// file is a legacy one.
    ///
    /// # Errors
    ///
    /// [`WalletError::Format`] when a V3 key component cannot be derived.
    pub fn from_entropy(entropy: &[u8; 32], legacy: bool) -> Result<Self, WalletError> {
        if legacy {
            return Ok(Self::V5(keypair_from_entropy(entropy)));
        }
        Ok(Self::V3(Box::new(user_account_from_entropy(
            entropy, 0, 0,
        )?)))
    }

    /// The sender address the key signs for.
    #[must_use]
    pub fn address(&self) -> Address {
        match self {
            Self::V3(account) => Address::from(account.address),
            Self::V5(key) => key.address(),
        }
    }

    /// Sign `tx` as its sender: V7 for a V3 account, V5 for a legacy key.
    ///
    /// # Errors
    ///
    /// The composite signer's refusal (a scheme the registry does not allow).
    pub fn sign(&self, tx: &mut crate::core::transaction::Transaction) -> Result<(), String> {
        match self {
            Self::V3(account) => {
                use rand::Rng;
                let mut rnd = [0u8; 32];
                rand::rng().fill_bytes(&mut rnd);
                tx.sign_v7(
                    &crate::crypto::scheme::SchemeStatusRegistry::genesis(),
                    &account.signing,
                    &account.recovery_public_key,
                    &rnd,
                )
            }
            Self::V5(key) => {
                tx.sign_v5(key);
                Ok(())
            }
        }
    }
}

/// A password-sealed wallet on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFile {
    pub version: u32,
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
    /// The account the sealed key opens, so a reader can show it without
    /// the password. Checked against the key on every open.
    pub address: String,
}

impl KeyFile {
    /// Seal `entropy` under `password`.
    ///
    /// # Errors
    ///
    /// Only if the cipher refuses its own key, which it does not for a
    /// 32-byte key.
    pub fn seal(entropy: &[u8; 32], password: &str, iterations: u32) -> Result<Self, WalletError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        {
            use rand::Rng;
            let mut rng = rand::rng();
            rng.fill_bytes(&mut salt);
            rng.fill_bytes(&mut nonce);
        }
        let key = pbkdf2_sha256(password.as_bytes(), &salt, iterations.max(1));
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| WalletError::Format("cipher key".into()))?;
        let nonce_value =
            XNonce::try_from(nonce.as_slice()).map_err(|_| WalletError::Format("nonce".into()))?;
        let ciphertext = cipher
            .encrypt(&nonce_value, entropy.as_slice())
            .map_err(|_| WalletError::Format("encryption".into()))?;
        Ok(Self {
            version: KEY_FILE_VERSION,
            kdf: KDF_NAME.into(),
            iterations: iterations.max(1),
            salt: hex::encode(salt),
            cipher: CIPHER_NAME.into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
            address: Address::from(user_account_from_entropy(entropy, 0, 0)?.address).to_hex(),
        })
    }

    /// Whether this file holds a legacy V5 wallet (address of the ML-DSA-87
    /// key alone) rather than a V3 wallet.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.version == LEGACY_KEY_FILE_VERSION
    }

    /// Open the key file with `password` and return its entropy.
    ///
    /// # Errors
    ///
    /// A file of another format, a wrong password, or an address that the
    /// sealed key does not derive.
    pub fn open(&self, password: &str) -> Result<[u8; 32], WalletError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};
        if (self.version != KEY_FILE_VERSION && self.version != LEGACY_KEY_FILE_VERSION)
            || self.kdf != KDF_NAME
            || self.cipher != CIPHER_NAME
        {
            return Err(WalletError::Format(format!(
                "version {} {}/{}",
                self.version, self.kdf, self.cipher
            )));
        }
        let decode = |field: &str, text: &str| {
            hex::decode(text).map_err(|_| WalletError::Format(format!("{field} is not hex")))
        };
        let salt = decode("salt", &self.salt)?;
        let nonce = decode("nonce", &self.nonce)?;
        let ciphertext = decode("ciphertext", &self.ciphertext)?;
        let key = pbkdf2_sha256(password.as_bytes(), &salt, self.iterations.max(1));
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| WalletError::Format("cipher key".into()))?;
        let nonce_value = XNonce::try_from(nonce.as_slice())
            .map_err(|_| WalletError::Format("nonce length".into()))?;
        let plain = cipher
            .decrypt(&nonce_value, ciphertext.as_slice())
            .map_err(|_| WalletError::WrongPassword)?;
        let entropy = <[u8; 32]>::try_from(plain.as_slice())
            .map_err(|_| WalletError::Format("sealed entropy length".into()))?;
        let address = if self.is_legacy() {
            keypair_from_entropy(&entropy).address()
        } else {
            Address::from(user_account_from_entropy(&entropy, 0, 0)?.address)
        };
        if Address::from_hex(&self.address).ok() != Some(address) {
            return Err(WalletError::AddressMismatch(self.address.clone()));
        }
        Ok(entropy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_and_pbkdf2_match_their_published_vectors() {
        // RFC 4231 test case 2.
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"])),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // PBKDF2-HMAC-SHA256 ("password", "salt"), 1 and 2 iterations.
        assert_eq!(
            hex::encode(pbkdf2_sha256(b"password", b"salt", 1)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            hex::encode(pbkdf2_sha256(b"password", b"salt", 2)),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn mnemonics_match_the_bip39_vectors_and_round_trip() {
        let zero = [0u8; 32];
        let phrase = mnemonic_from_entropy(&zero);
        assert_eq!(phrase, format!("{}art", "abandon ".repeat(23)));
        assert_eq!(entropy_from_mnemonic(&phrase), Ok(zero));
        let legal = [0x7f; 32];
        assert_eq!(
            mnemonic_from_entropy(&legal),
            "legal winner thank year wave sausage worth useful legal winner thank year wave \
             sausage worth useful legal winner thank year wave sausage worth title"
        );
        let random = generate_entropy();
        assert_eq!(
            entropy_from_mnemonic(&mnemonic_from_entropy(&random)),
            Ok(random)
        );
    }

    #[test]
    fn a_twelve_word_or_damaged_phrase_is_refused() {
        let twelve = format!("{}about", "abandon ".repeat(11));
        assert_eq!(
            entropy_from_mnemonic(&twelve),
            Err(WalletError::WordCount(12))
        );
        let swapped = format!("art {}", "abandon ".repeat(23));
        assert_eq!(
            entropy_from_mnemonic(swapped.trim()),
            Err(WalletError::Checksum)
        );
        let unknown = format!("{}zzzz", "abandon ".repeat(23));
        assert!(matches!(
            entropy_from_mnemonic(&unknown),
            Err(WalletError::UnknownWord(_))
        ));
    }

    #[test]
    fn a_key_file_opens_with_its_password_only() {
        let entropy = generate_entropy();
        let file = KeyFile::seal(&entropy, "correct horse", 2).expect("seals");
        assert_eq!(file.open("correct horse"), Ok(entropy));
        assert_eq!(file.open("wrong"), Err(WalletError::WrongPassword));
        assert_eq!(
            Address::from_hex(&file.address).ok(),
            Some(Address::from(
                user_account_from_entropy(&entropy, 0, 0)
                    .expect("derives")
                    .address
            ))
        );
        assert!(!file.is_legacy());
        let mut tampered = file.clone();
        tampered.address = "11".repeat(32);
        assert!(matches!(
            tampered.open("correct horse"),
            Err(WalletError::AddressMismatch(_))
        ));
        assert!(!serde_json::to_string(&file)
            .expect("serializes")
            .contains(&hex::encode(entropy)));
    }

    /// The V5 transfer signing hash, pinned. `crates/wallet-core`
    /// (`transfer::UnsignedTransfer`) asserts the same value, so the browser
    /// and mobile wallets sign exactly what the node verifies.
    #[test]
    fn the_v5_transfer_signing_hash_matches_the_published_vector() {
        use crate::core::transaction::{Transaction, TransactionType, SIGNATURE_VERSION_V5};
        let mut tx = Transaction::new_with_chain_id(
            Address::from([0x11; 32]),
            Address::from([0x22; 32]),
            1_000_000,
            1_000,
            3,
            Vec::new(),
            45_261,
            TransactionType::Transfer,
        );
        tx.max_fee = 1_000;
        tx.priority_fee = 0;
        tx.timestamp = 1_800_000_000_000;
        tx.signature_version = SIGNATURE_VERSION_V5;
        tx.authorization = None;
        assert_eq!(
            hex::encode(tx.signing_hash()),
            "fb982bceadd9bbd150970eda0e6103abcbba874b3d3622452d8e6a0bb1c22d8e"
        );
    }

    /// The V7 composite transfer signing hash, pinned. `crates/wallet-core`
    /// asserts the same value (`the_v7_signing_hash_matches_the_node_vector`).
    #[test]
    fn the_v7_transfer_signing_hash_matches_the_published_vector() {
        use crate::core::transaction::{Transaction, TransactionType, SIGNATURE_VERSION_V7};
        let mut tx = Transaction::new_with_chain_id(
            Address::from([0x11; 32]),
            Address::from([0x22; 32]),
            1_000_000,
            1_000,
            3,
            Vec::new(),
            45_261,
            TransactionType::Transfer,
        );
        tx.max_fee = 1_000;
        tx.priority_fee = 0;
        tx.timestamp = 1_800_000_000_000;
        tx.signature_version = SIGNATURE_VERSION_V7;
        tx.authorization = None;
        assert_eq!(
            hex::encode(tx.signing_hash()),
            "616f18ed47f2a635b224c368855a4e21a8fe6231b7353c6465ac32ce964de3f7"
        );
    }

    #[test]
    fn a_signed_v5_transfer_verifies() {
        use crate::core::transaction::{Transaction, TransactionType};
        let key = keypair_from_entropy(&[7u8; 32]);
        let mut tx = Transaction::new_with_chain_id(
            key.address(),
            Address::from([2u8; 32]),
            5,
            1,
            0,
            Vec::new(),
            45261,
            TransactionType::Transfer,
        );
        tx.sign_v5(&key);
        assert!(tx.verify());
    }
}
