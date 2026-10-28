//! Key derivation.
//!
//! A wallet holds 256 bits of entropy (24 words) and an optional password. One
//! root secret is derived from both, and every key branch is derived from the
//! root with SHAKE256 under its own tag:
//!
//! ```text
//! E                = SHAKE256("BDLM_KDF_ROOT_V1"       || entropy || NFKD(password), 64)
//! xi_mldsa87(a, i) = SHAKE256("BDLM_KDF_MLDSA87_V1"    || E || u32 a || u32 i, 32)
//! seed_ed(a, i)    = SHAKE256("BDLM_KDF_ED25519_V1"    || E || u32 a || u32 i, 32)
//! seed_slh(a, i)   = SHAKE256("BDLM_KDF_SLHDSA256S_V1" || E || u32 a || u32 i, 96)
//! seed_xwing(a, i) = SHAKE256("BDLM_KDF_XWING_V1"      || E || u32 a || u32 i, 32)
//! ```
//!
//! `a` is the account and `i` the index (both `u32`, big endian). No branch is
//! derived from the secret key of another branch, so one leaked branch seed
//! does not reveal a sibling. Entropy is exactly 32 bytes: the preimage has no
//! length field, and a 12 word phrase (16 bytes) has no derivation here, which
//! is how the mainnet rule "12 words are rejected" is enforced. The password
//! is NFKD normalized and defaults to empty.
//!
//! A watch-only wallet derives no public key: it exports an address list.
//!
//! This file has no dependency on the rest of the node. `crates/wallet-core`
//! mounts the same source.

use super::address_v3::{self, AddressV3Error};
use super::composite::{CompositeError, CompositeKeypair, CompositePublicKey, ED25519_SEED_LEN};
use super::pq::{self, PqError};
use super::scheme::{SchemeId, SuiteId};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The entropy length of a V3 wallet: 24 words.
pub const ENTROPY_LEN: usize = 32;

/// The length of the root secret `E`.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const ROOT_LEN: usize = 64;

/// The SLH-DSA-SHAKE-256s seed length (three `n = 32` values).
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const SLH_SEED_LEN: usize = 96;

/// Tag of the root secret.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const ROOT_TAG: &[u8] = b"BDLM_KDF_ROOT_V1";
/// Tag of the ML-DSA-87 branch.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const MLDSA87_TAG: &[u8] = b"BDLM_KDF_MLDSA87_V1";
/// Tag of the Ed25519 branch.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const ED25519_TAG: &[u8] = b"BDLM_KDF_ED25519_V1";
/// Tag of the SLH-DSA-SHAKE-256s branch.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const SLHDSA256S_TAG: &[u8] = b"BDLM_KDF_SLHDSA256S_V1";
/// Tag of the X-Wing branch.
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub const XWING_TAG: &[u8] = b"BDLM_KDF_XWING_V1";

/// Why a derivation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub enum KdfError {
    /// The entropy is not 32 bytes (24 words).
    EntropyLength(usize),
    /// The suite is not one a user can own (it needs a recovery scheme).
    Suite(SuiteId),
    /// A post-quantum component failed.
    Pq(PqError),
    /// The composite key pair failed.
    Composite(CompositeError),
    /// The address derivation failed.
    Address(AddressV3Error),
}

impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EntropyLength(n) => {
                write!(f, "entropy must be {ENTROPY_LEN} bytes (24 words), got {n}")
            }
            Self::Suite(s) => write!(f, "suite {:#06x} is not a user suite", s.0),
            Self::Pq(e) => write!(f, "{e}"),
            Self::Composite(e) => write!(f, "{e}"),
            Self::Address(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KdfError {}

impl From<PqError> for KdfError {
    fn from(e: PqError) -> Self {
        Self::Pq(e)
    }
}
impl From<CompositeError> for KdfError {
    fn from(e: CompositeError) -> Self {
        Self::Composite(e)
    }
}
impl From<AddressV3Error> for KdfError {
    fn from(e: AddressV3Error) -> Self {
        Self::Address(e)
    }
}

/// The root secret `E`, wiped on drop.
pub struct RootSecret(Zeroizing<[u8; ROOT_LEN]>);

fn shake<const N: usize>(parts: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let mut xof = Shake256::default();
    for part in parts {
        xof.update(part);
    }
    let mut out = Zeroizing::new([0u8; N]);
    xof.finalize_xof().read(out.as_mut_slice());
    out
}

impl RootSecret {
    /// Derive `E` from the entropy and the (possibly empty) password.
    ///
    /// # Errors
    ///
    /// [`KdfError::EntropyLength`] unless the entropy is 32 bytes.
    pub fn derive(entropy: &[u8], password: &str) -> Result<Self, KdfError> {
        if entropy.len() != ENTROPY_LEN {
            return Err(KdfError::EntropyLength(entropy.len()));
        }
        let normalized: Zeroizing<String> = Zeroizing::new(password.nfkd().collect());
        Ok(Self(shake::<ROOT_LEN>(&[
            ROOT_TAG,
            entropy,
            normalized.as_bytes(),
        ])))
    }

    /// The raw root bytes (wallet storage and tests only).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ROOT_LEN] {
        &self.0
    }

    fn branch<const N: usize>(&self, tag: &[u8], account: u32, index: u32) -> Zeroizing<[u8; N]> {
        shake::<N>(&[
            tag,
            self.0.as_slice(),
            &account.to_be_bytes(),
            &index.to_be_bytes(),
        ])
    }

    /// The ML-DSA-87 seed `xi` of `(account, index)`.
    #[must_use]
    /// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn xi_mldsa87(&self, account: u32, index: u32) -> Zeroizing<[u8; 32]> {
        self.branch::<32>(MLDSA87_TAG, account, index)
    }

    /// The Ed25519 seed of `(account, index)`.
    #[must_use]
    /// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn seed_ed25519(&self, account: u32, index: u32) -> Zeroizing<[u8; ED25519_SEED_LEN]> {
        self.branch::<ED25519_SEED_LEN>(ED25519_TAG, account, index)
    }

    /// The SLH-DSA-SHAKE-256s seed of `(account, index)`.
    #[must_use]
    /// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn seed_slh_dsa_256s(&self, account: u32, index: u32) -> Zeroizing<[u8; SLH_SEED_LEN]> {
        self.branch::<SLH_SEED_LEN>(SLHDSA256S_TAG, account, index)
    }

    /// The X-Wing seed of `(account, index)`.
    #[must_use]
    /// exposed for: the crypto/key registry's public labels and shapes — production readers land with the anchor-ceremony and key-config doors (wiring pending).
    pub fn seed_xwing(&self, account: u32, index: u32) -> Zeroizing<[u8; 32]> {
        self.branch::<32>(XWING_TAG, account, index)
    }

    /// The signing key pair, the recovery seed and the address of `(account,
    /// index)` under the user suite.
    ///
    /// # Errors
    ///
    /// [`KdfError`] when a component cannot be derived.
    pub fn user_account(&self, account: u32, index: u32) -> Result<UserAccount, KdfError> {
        let suite = SuiteId::USER;
        let signing = CompositeKeypair::from_seeds(
            suite,
            self.xi_mldsa87(account, index).as_slice(),
            &self.seed_ed25519(account, index),
        )?;
        let recovery_seed = self.seed_slh_dsa_256s(account, index);
        let public = signing.public_key()?;
        let recovery_public_key =
            pq::slh_dsa_public_key(SchemeId::SLH_DSA_SHAKE_256S, recovery_seed.as_slice())?;
        let address = address_v3::address_v3(suite, &public.pq, &public.ed, &recovery_public_key)?;
        Ok(UserAccount {
            account,
            index,
            signing,
            public,
            recovery_seed,
            recovery_public_key,
            address,
        })
    }
}

/// The keys and the address of one `(account, index)`.
pub struct UserAccount {
    /// The account number `a`.
    pub account: u32,
    /// The index `i`.
    pub index: u32,
    /// The composite signing key pair (ML-DSA-87 and Ed25519).
    pub signing: CompositeKeypair,
    /// The composite public key.
    pub public: CompositePublicKey,
    /// The SLH-DSA-SHAKE-256s recovery seed. Kept cold: it signs only in the
    /// recovery path.
    pub recovery_seed: Zeroizing<[u8; SLH_SEED_LEN]>,
    /// The recovery public key.
    pub recovery_public_key: Vec<u8>,
    /// The V3 address.
    pub address: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(password: &str) -> RootSecret {
        RootSecret::derive(&[0x42; 32], password).unwrap()
    }

    #[test]
    fn root_is_the_documented_shake256() {
        let mut xof = Shake256::default();
        xof.update(b"BDLM_KDF_ROOT_V1");
        xof.update(&[0x42; 32]);
        xof.update(b"pw");
        let mut expected = [0u8; 64];
        xof.finalize_xof().read(&mut expected);
        assert_eq!(root("pw").as_bytes(), &expected);
    }

    #[test]
    fn branches_follow_the_documented_layout() {
        let r = root("");
        let mut xof = Shake256::default();
        xof.update(b"BDLM_KDF_SLHDSA256S_V1");
        xof.update(r.as_bytes());
        xof.update(&3u32.to_be_bytes());
        xof.update(&9u32.to_be_bytes());
        let mut expected = [0u8; 96];
        xof.finalize_xof().read(&mut expected);
        assert_eq!(*r.seed_slh_dsa_256s(3, 9), expected);
    }

    #[test]
    fn branches_account_and_index_are_separated() {
        let r = root("");
        let all = [
            r.xi_mldsa87(0, 0).to_vec(),
            r.seed_ed25519(0, 0).to_vec(),
            r.seed_xwing(0, 0).to_vec(),
            r.seed_slh_dsa_256s(0, 0)[..32].to_vec(),
            r.xi_mldsa87(1, 0).to_vec(),
            r.xi_mldsa87(0, 1).to_vec(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn password_changes_everything_and_is_nfkd_normalized() {
        assert_ne!(root("").as_bytes(), root("x").as_bytes());
        // U+00EF and "i" + U+0308 are canonically equivalent; U+FB01 (fi
        // ligature) decomposes under NFKD only.
        assert_eq!(
            root("na\u{ef}ve").as_bytes(),
            root("nai\u{308}ve").as_bytes()
        );
        assert_eq!(root("\u{fb01}").as_bytes(), root("fi").as_bytes());
    }

    #[test]
    fn only_256_bit_entropy_derives() {
        for n in [0usize, 16, 24, 31, 33, 64] {
            assert_eq!(
                RootSecret::derive(&vec![1; n], "").err(),
                Some(KdfError::EntropyLength(n))
            );
        }
    }

    #[test]
    fn user_account_is_deterministic_and_matches_the_address_rule() {
        let r = root("");
        let a = r.user_account(0, 0).unwrap();
        let b = r.user_account(0, 0).unwrap();
        assert_eq!(a.address, b.address);
        assert_eq!(a.public, b.public);
        assert_eq!(
            a.address,
            address_v3::address_v3(
                SuiteId::USER,
                &a.public.pq,
                &a.public.ed,
                &a.recovery_public_key
            )
            .unwrap()
        );
        assert_ne!(a.address, r.user_account(0, 1).unwrap().address);
        assert_ne!(a.address, r.user_account(1, 0).unwrap().address);
        assert_ne!(a.address, root("pw").user_account(0, 0).unwrap().address);
    }
}
