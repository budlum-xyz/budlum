//! The V3 wallet.
//!
//! A V3 wallet is 24 words (256 bits of entropy) and an optional password. The
//! root secret and every key branch come from `crypto::key_derivation`, the
//! same file the node mounts. Twelve words are refused: the derivation has no
//! 128-bit path, so a 12 word phrase cannot reach a V3 address.
//!
//! A watch-only wallet holds no secret and derives no public key; it keeps the
//! address list this wallet exports with [`WalletV3::address_list`].

use crate::crypto::key_derivation::{RootSecret, UserAccount, ENTROPY_LEN};
use crate::{entropy_to_mnemonic, mnemonic_to_entropy, WalletError};
use zeroize::{Zeroize, Zeroizing};

/// The word count of a V3 wallet.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring wave.
pub const WORD_COUNT: usize = 24;

/// A V3 wallet: the mnemonic and the root secret, both wiped on drop.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring wave.
pub struct WalletV3 {
    mnemonic: Zeroizing<String>,
    root: RootSecret,
}

impl WalletV3 {
    /// Build a wallet from 32 bytes of entropy and a password (empty for none).
    ///
    /// # Errors
    ///
    /// [`WalletError::InvalidEntropy`] unless the entropy is 32 bytes.
    pub fn from_entropy(entropy: &[u8], password: &str) -> Result<Self, WalletError> {
        if entropy.len() != ENTROPY_LEN {
            return Err(WalletError::InvalidEntropy(entropy.len()));
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
    /// [`WalletError::ProductionEntropyUnavailable`] when no CSPRNG is built in
    /// or it fails.
    pub fn generate(password: &str) -> Result<Self, WalletError> {
        #[cfg(feature = "production")]
        {
            let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
            getrandom::getrandom(entropy.as_mut_slice())
                .map_err(|e| WalletError::ProductionEntropyUnavailable(e.to_string()))?;
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
    /// refused), [`WalletError::InvalidMnemonic`] for a bad checksum.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring wave.
    pub fn from_mnemonic(mnemonic: &str, password: &str) -> Result<Self, WalletError> {
        let words = mnemonic.split_whitespace().count();
        if words != WORD_COUNT {
            return Err(WalletError::InvalidWordCount(words));
        }
        let mut entropy = mnemonic_to_entropy(mnemonic)?;
        let wallet = Self::from_entropy(&entropy, password);
        entropy.zeroize();
        wallet
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
    /// [`WalletError::InvalidSeed`] when a component cannot be derived.
/// exposed for: the wallet crate's SDK surface - in-tree readers land with the wallet wiring wave.
    pub fn address_list(&self, account: u32, count: u32) -> Result<Vec<[u8; 32]>, WalletError> {
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
}
