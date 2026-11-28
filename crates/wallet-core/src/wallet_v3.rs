//! The V3 wallet.
//!
//! A V3 wallet is 24 words (256 bits of entropy) and an optional password. The
//! root secret and every key branch come from `crypto::key_derivation`, the
//! same file the node mounts. Twelve words are refused: the derivation has no
//! 128-bit path, so a 12 word phrase cannot reach a V3 address.
//!
//! A watch-only wallet holds no secret and derives no public key; it keeps the
//! address list this wallet exports with [`WalletV3::address_list`].
//! WIRING: unwired - the v3 wallet surface belongs to the custody path; in-tree readers land with it (the crate binary and SDK callers are not wired yet).

use crate::crypto::key_derivation::{RootSecret, UserAccount, ENTROPY_LEN};
use crate::{entropy_to_mnemonic, mnemonic_to_entropy, normalize_mnemonic_nfkd, WalletError};
use zeroize::Zeroizing;

/// The word count of a V3 wallet.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
pub const WORD_COUNT: usize = 24;

/// Maximum addresses exported in a single watch-only [`WalletV3::address_list`] call.
const MAX_ADDRESS_LIST_COUNT: u32 = 256;

/// Maximum UTF-8 byte length accepted for a V3 wallet password before NFKD expansion.
const MAX_PASSWORD_BYTES: usize = 4_096;

#[cfg(any(feature = "production", test))]
fn validate_generated_entropy(entropy: &[u8; ENTROPY_LEN]) -> Result<(), WalletError> {
    let first = entropy[0];
    if entropy.iter().all(|&b| b == first) {
        return Err(WalletError::ProductionEntropyUnavailable(
            "OS CSPRNG returned degenerate all-identical entropy".into(),
        ));
    }
    Ok(())
}

/// A V3 wallet: the mnemonic and the root secret, both wiped on drop.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
pub struct WalletV3 {
    mnemonic: Zeroizing<String>,
    root: RootSecret,
}

impl std::fmt::Debug for WalletV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletV3")
            .field("mnemonic", &"[redacted]")
            .field("root", &"[redacted]")
            .finish()
    }
}

impl WalletV3 {
    /// Build a wallet from 32 bytes of entropy and a password (empty for none).
    ///
    /// # Errors
    ///
    /// [`WalletError::InvalidEntropy`] unless the entropy is 32 bytes, or
    /// [`WalletError::InvalidSeed`] if the password exceeds the safety bound.
    pub fn from_entropy(entropy: &[u8], password: &str) -> Result<Self, WalletError> {
        if entropy.len() != ENTROPY_LEN {
            return Err(WalletError::InvalidEntropy(entropy.len()));
        }
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(WalletError::InvalidSeed);
        }
        let mnemonic = Zeroizing::new(entropy_to_mnemonic(entropy)?);
        let root = RootSecret::derive(entropy, password)
            .map_err(|_| WalletError::InvalidEntropy(entropy.len()))?;
        Ok(Self { mnemonic, root })
    }

    /// Generate a wallet from OS entropy. Needs the `production` feature, like
    /// [`crate::Wallet::generate`]: without it the call fails closed.
    ///
    /// # Errors
    ///
    /// [`WalletError::ProductionEntropyUnavailable`] when no CSPRNG is built in,
    /// it fails, or it returns degenerate all-identical bytes.
    pub fn generate(password: &str) -> Result<Self, WalletError> {
        #[cfg(feature = "production")]
        {
            let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
            getrandom::getrandom(entropy.as_mut_slice())
                .map_err(|e| WalletError::ProductionEntropyUnavailable(e.to_string()))?;
            validate_generated_entropy(&entropy)?;
            Self::from_entropy(entropy.as_slice(), password)
        }
        #[cfg(not(feature = "production"))]
        {
            let _ = password;
            Err(WalletError::ProductionEntropyUnavailable(
                "WalletV3::generate requires the 'production' feature".into(),
            ))
        }
    }

    /// Restore from a 24 word mnemonic and a password.
    ///
    /// # Errors
    ///
    /// [`WalletError::InvalidWordCount`] for any count but 24 (12 words are
    /// refused), [`WalletError::InvalidMnemonic`] for a bad checksum, or
    /// [`WalletError::InvalidSeed`] for an oversized password.
    /// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
    pub fn from_mnemonic(mnemonic: &str, password: &str) -> Result<Self, WalletError> {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(WalletError::InvalidSeed);
        }
        let normalized = Zeroizing::new(normalize_mnemonic_nfkd(mnemonic));
        let words = normalized.split_whitespace().count();
        if words != WORD_COUNT {
            return Err(WalletError::InvalidWordCount(words));
        }
        let entropy = Zeroizing::new(mnemonic_to_entropy(&normalized)?);
        Self::from_entropy(entropy.as_slice(), password)
    }

    /// The mnemonic, for display at creation and for backup.
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// The keys and address of `(account, index)`.
    ///
    /// # Errors
    ///
    /// [`WalletError::InvalidSeed`] when a component cannot be derived.
    pub fn account(&self, account: u32, index: u32) -> Result<UserAccount, WalletError> {
        self.root
            .user_account(account, index)
            .map_err(|_| WalletError::InvalidSeed)
    }

    /// The addresses of `count` indices of one account: the export a
    /// watch-only wallet imports. It carries no key material.
    ///
    /// # Errors
    ///
    /// [`WalletError::InvalidSeed`] when `count` exceeds the export bound or a
    /// component cannot be derived.
    /// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring.
    pub fn address_list(&self, account: u32, count: u32) -> Result<Vec<[u8; 32]>, WalletError> {
        if count > MAX_ADDRESS_LIST_COUNT {
            return Err(WalletError::InvalidSeed);
        }
        (0..count)
            .map(|index| self.account(account, index).map(|a| a.address))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_24_word_wallet_restores_to_the_same_addresses() {
        let wallet = WalletV3::from_entropy(&[9u8; 32], "").unwrap();
        assert_eq!(wallet.mnemonic().split_whitespace().count(), 24);
        let again = WalletV3::from_mnemonic(wallet.mnemonic(), "").unwrap();
        assert_eq!(
            wallet.address_list(0, 2).unwrap(),
            again.address_list(0, 2).unwrap()
        );
        let with_password = WalletV3::from_mnemonic(wallet.mnemonic(), "pw").unwrap();
        assert_ne!(
            wallet.account(0, 0).unwrap().address,
            with_password.account(0, 0).unwrap().address
        );
    }

    #[test]
    fn twelve_words_are_refused() {
        let twelve = entropy_to_mnemonic(&[1u8; 16]).unwrap();
        assert!(matches!(
            WalletV3::from_mnemonic(&twelve, ""),
            Err(WalletError::InvalidWordCount(12))
        ));
        assert!(matches!(
            WalletV3::from_entropy(&[1u8; 16], ""),
            Err(WalletError::InvalidEntropy(16))
        ));
    }

    #[test]
    fn the_address_list_holds_no_key_material() {
        let wallet = WalletV3::from_entropy(&[9u8; 32], "").unwrap();
        let list = wallet.address_list(3, 3).unwrap();
        assert_eq!(list.len(), 3);
        assert_ne!(list[0], list[1]);
        assert_eq!(list[1], wallet.account(3, 1).unwrap().address);
    }

    #[test]
    fn walcore05_wallet_v3_rejects_oversized_password_degenerate_rng_unbounded_list_and_redacts_debug(
    ) {
        // 1. Oversized password must be refused before NFKD expansion on both entry points.
        let huge_pw = "x".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(
            matches!(
                WalletV3::from_entropy(&[9u8; 32], &huge_pw),
                Err(WalletError::InvalidSeed)
            ),
            "oversized password in from_entropy must be refused"
        );
        let wallet = WalletV3::from_entropy(&[9u8; 32], "").unwrap();
        assert!(
            matches!(
                WalletV3::from_mnemonic(wallet.mnemonic(), &huge_pw),
                Err(WalletError::InvalidSeed)
            ),
            "oversized password in from_mnemonic must be refused"
        );
        // Exact boundary password length must succeed.
        let boundary_pw = "x".repeat(MAX_PASSWORD_BYTES);
        assert!(WalletV3::from_entropy(&[9u8; 32], &boundary_pw).is_ok());

        // 2. Generated OS CSPRNG entropy must reject degenerate all-identical buffers.
        assert!(matches!(
            validate_generated_entropy(&[0u8; ENTROPY_LEN]),
            Err(WalletError::ProductionEntropyUnavailable(_))
        ));
        assert!(matches!(
            validate_generated_entropy(&[0xFFu8; ENTROPY_LEN]),
            Err(WalletError::ProductionEntropyUnavailable(_))
        ));
        let mut non_degenerate = [0u8; ENTROPY_LEN];
        non_degenerate[31] = 1;
        assert!(validate_generated_entropy(&non_degenerate).is_ok());

        // 3. Unbounded address_list count must fail closed immediately instead of OOM/CPU DoS.
        assert!(
            matches!(
                wallet.address_list(0, MAX_ADDRESS_LIST_COUNT + 1),
                Err(WalletError::InvalidSeed)
            ),
            "address_list count above bound must be refused"
        );
        assert!(wallet.address_list(0, 0).unwrap().is_empty());

        // 4. Debug output must redact the mnemonic and root secret.
        let dbg = format!("{wallet:?}");
        assert!(dbg.contains("[redacted]"));
        for word in wallet.mnemonic().split_whitespace() {
            assert!(
                !dbg.contains(word),
                "Debug leaked mnemonic word '{word}': {dbg}"
            );
        }
    }
}
