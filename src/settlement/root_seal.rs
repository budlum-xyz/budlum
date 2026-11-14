//! The Root Seal.
//!
//! Every 3,600 blocks (about one hour) a SLH-DSA-SHAKE-256s key signs the
//! Merkle root of the PQ anchors of that period. The seal is the hash-only
//! rung of the seal layer: its security rests on SHAKE-256 alone, so it stays
//! valid when the lattice family falls. Seals are kept forever and chain to
//! each other by hash, so one seal vouches for every earlier one.
//!
//! WIRING: the seal is built and verified by the anchor driver of the node
//! (`Blockchain::emit_anchor_for` in `src/chain/blockchain.rs`) and its
//! latest verified instance is the Polyp source of `PqCanonicalSource`
//! (`src/domain/regen_health.rs`). The rules are pinned by this file's tests.
//!
//! # What a seal signs
//!
//! `BDLM_ROOT_SEAL_V1 || chain_id || seal_height || anchors_root ||
//! anchor_count || previous_seal || key_epoch || key_index`, all fixed width.
//! The signature carries the FIPS 205 context `BDLM/SEAL/V1`. The key epoch
//! and the key index are inside the payload for the same reason they are in
//! the anchor payload: a rotated-out key, or the wrong slot of the ledger,
//! must not produce bytes that still verify as current.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use super::pq_anchor::{AnchorError, AnchorSignatureAlgorithm, PqAnchor, SignerBackend};
use super::pq_anchor_verify::verify_in_context;
use crate::consensus::merkle_tree::{combine_sha3, merkle_root, promote_sha3};
use crate::core::hash::hash_fields_bytes;
use crate::crypto::pq;
use crate::crypto::scheme::SchemeId;

/// Blocks between two Root Seals: one per hour at the 1 second block
/// time.
pub const ROOT_SEAL_INTERVAL: u64 = 3_600;

/// The most seals a node keeps in memory. Older seals stay committed through
/// the `previous_seal` hash chain; archive nodes keep them all on disk.
pub const MAX_RETAINED_SEALS: usize = 4_096;

/// The most anchors one seal may cover. A period holds ten (one per 360
/// blocks); the bound keeps a hostile list from costing a large tree.
pub const MAX_SEAL_ANCHORS: usize = 64;

/// The all-zero link of the first seal.
pub const GENESIS_SEAL_LINK: [u8; 32] = [0u8; 32];

/// A Root Seal: one SLH-DSA-SHAKE-256s signature over one period of anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSeal {
    /// The chain the seal belongs to.
    pub chain_id: u64,
    /// The height at the end of the period. A positive multiple of
    /// [`ROOT_SEAL_INTERVAL`].
    pub seal_height: u64,
    /// The Merkle root over the digests of the period's anchors.
    pub anchors_root: [u8; 32],
    /// How many anchors the root covers.
    pub anchor_count: u32,
    /// The digest of the previous seal, [`GENESIS_SEAL_LINK`] for the first.
    pub previous_seal: [u8; 32],
    /// The key epoch the seal is signed under.
    pub key_epoch: u32,
    /// The slot of the signing key in the ledger's seal keys.
    pub key_index: u8,
    /// The SLH-DSA-SHAKE-256s signature (29,792 bytes).
    pub signature: Vec<u8>,
}

/// Why a seal operation refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The height is not a positive multiple of [`ROOT_SEAL_INTERVAL`].
    HeightNotOnBoundary { height: u64 },
    /// A seal covers at least one anchor.
    NoAnchors,
    /// More anchors than [`MAX_SEAL_ANCHORS`].
    TooManyAnchors { max: usize, presented: usize },
    /// An anchor lies outside the period the seal covers.
    AnchorOutsidePeriod {
        anchor_height: u64,
        seal_height: u64,
    },
    /// Anchor heights are not strictly ascending.
    AnchorsNotAscending { anchor_height: u64 },
    /// The seal commits a different anchor set than the one presented.
    AnchorsMismatch,
    /// The seal belongs to another chain.
    WrongChain { expected: u64, got: u64 },
    /// The seal is signed under a key epoch other than the current one.
    StaleKeyEpoch { seal_epoch: u32, current_epoch: u32 },
    /// The key slot does not exist in the ledger.
    UnknownKeyIndex { index: u8 },
    /// The key epoch of that slot is suspended by equivocation evidence.
    KeySuspended { index: u8, key_epoch: u32 },
    /// The signature did not verify.
    InvalidSignature,
    /// The seal does not extend the chain of earlier seals.
    BrokenLink,
    /// The seal is not newer than the latest accepted one.
    NotNewer { seal_height: u64, latest: u64 },
    /// The signing backend refused.
    Signing(AnchorError),
}

impl SealError {
    /// A stable label.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::HeightNotOnBoundary { .. } => "seal-height-not-on-boundary",
            Self::NoAnchors => "seal-no-anchors",
            Self::TooManyAnchors { .. } => "seal-too-many-anchors",
            Self::AnchorOutsidePeriod { .. } => "seal-anchor-outside-period",
            Self::AnchorsNotAscending { .. } => "seal-anchors-not-ascending",
            Self::AnchorsMismatch => "seal-anchors-mismatch",
            Self::WrongChain { .. } => "seal-wrong-chain",
            Self::StaleKeyEpoch { .. } => "seal-stale-key-epoch",
            Self::UnknownKeyIndex { .. } => "seal-unknown-key-index",
            Self::KeySuspended { .. } => "seal-key-suspended",
            Self::InvalidSignature => "seal-invalid-signature",
            Self::BrokenLink => "seal-broken-link",
            Self::NotNewer { .. } => "seal-not-newer",
            Self::Signing(_) => "seal-signing",
        }
    }
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeightNotOnBoundary { height } => write!(
                f,
                "root seal height {height} is not a positive multiple of {ROOT_SEAL_INTERVAL}"
            ),
            Self::NoAnchors => write!(f, "a root seal covers at least one anchor"),
            Self::TooManyAnchors { max, presented } => {
                write!(f, "root seal covers {presented} anchors, at most {max}")
            }
            Self::AnchorOutsidePeriod {
                anchor_height,
                seal_height,
            } => write!(
                f,
                "anchor at height {anchor_height} is outside the period ending at {seal_height}"
            ),
            Self::AnchorsNotAscending { anchor_height } => {
                write!(f, "anchor at height {anchor_height} is out of order")
            }
            Self::AnchorsMismatch => write!(f, "root seal commits another anchor set"),
            Self::WrongChain { expected, got } => {
                write!(f, "root seal is for chain {got}, this is chain {expected}")
            }
            Self::StaleKeyEpoch {
                seal_epoch,
                current_epoch,
            } => write!(
                f,
                "root seal key epoch {seal_epoch} is stale (current {current_epoch})"
            ),
            Self::UnknownKeyIndex { index } => write!(f, "root seal key slot {index} is unknown"),
            Self::KeySuspended { index, key_epoch } => write!(
                f,
                "root seal key slot {index} is suspended for epoch {key_epoch}"
            ),
            Self::InvalidSignature => write!(f, "root seal signature failed verification"),
            Self::BrokenLink => write!(f, "root seal does not extend the seal chain"),
            Self::NotNewer {
                seal_height,
                latest,
            } => write!(
                f,
                "root seal at {seal_height} is not newer than the latest at {latest}"
            ),
            Self::Signing(err) => write!(f, "root seal signing: {err}"),
        }
    }
}

impl std::error::Error for SealError {}

/// Whether a Root Seal is due at `height`: a positive multiple of
/// [`ROOT_SEAL_INTERVAL`].
#[must_use]
pub fn seal_due(height: u64) -> bool {
    height > 0 && height.is_multiple_of(ROOT_SEAL_INTERVAL)
}

/// The digest of one anchor as a leaf of the seal tree:
/// `SHA3-256(BDLM_ROOT_SEAL_LEAF_V1 || len || payload)`.
fn anchor_leaf(anchor: &PqAnchor) -> [u8; 32] {
    let payload = anchor.payload();
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_ROOT_SEAL_LEAF_V1");
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(&payload);
    hasher.finalize().into()
}

/// The Merkle root over the anchors of the period ending at `seal_height`.
///
/// # Errors
///
/// [`SealError`] when the height is off the boundary, the list is empty or too
/// long, an anchor lies outside `(seal_height - ROOT_SEAL_INTERVAL,
/// seal_height]`, or the heights are not strictly ascending.
pub fn period_anchors_root(
    seal_height: u64,
    anchors: &[PqAnchor],
) -> Result<([u8; 32], u32), SealError> {
    if !seal_due(seal_height) {
        return Err(SealError::HeightNotOnBoundary {
            height: seal_height,
        });
    }
    if anchors.is_empty() {
        return Err(SealError::NoAnchors);
    }
    if anchors.len() > MAX_SEAL_ANCHORS {
        return Err(SealError::TooManyAnchors {
            max: MAX_SEAL_ANCHORS,
            presented: anchors.len(),
        });
    }
    let period_start = seal_height - ROOT_SEAL_INTERVAL;
    let mut previous: Option<u64> = None;
    let mut leaves = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        if anchor.height <= period_start || anchor.height > seal_height {
            return Err(SealError::AnchorOutsidePeriod {
                anchor_height: anchor.height,
                seal_height,
            });
        }
        if previous.is_some_and(|p| anchor.height <= p) {
            return Err(SealError::AnchorsNotAscending {
                anchor_height: anchor.height,
            });
        }
        previous = Some(anchor.height);
        leaves.push(anchor_leaf(anchor));
    }
    let count = u32::try_from(anchors.len()).unwrap_or(u32::MAX);
    Ok((merkle_root(&leaves, combine_sha3, promote_sha3), count))
}

impl RootSeal {
    /// The bytes the SLH-DSA key signs.
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        root_seal_payload(
            self.chain_id,
            self.seal_height,
            &self.anchors_root,
            self.anchor_count,
            &self.previous_seal,
            self.key_epoch,
            self.key_index,
        )
    }

    /// The digest the next seal links to: it covers the signature too, so a
    /// link cannot be satisfied by a different signature over the same payload.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        hash_fields_bytes(&[b"BDLM_ROOT_SEAL_LINK_V1", &self.payload(), &self.signature])
    }
}

/// The canonical payload of a Root Seal.
#[must_use]
pub fn root_seal_payload(
    chain_id: u64,
    seal_height: u64,
    anchors_root: &[u8; 32],
    anchor_count: u32,
    previous_seal: &[u8; 32],
    key_epoch: u32,
    key_index: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + 8 + 8 + 32 + 4 + 32 + 4 + 1);
    out.extend_from_slice(b"BDLM_ROOT_SEAL_V1");
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&seal_height.to_le_bytes());
    out.extend_from_slice(anchors_root);
    out.extend_from_slice(&anchor_count.to_le_bytes());
    out.extend_from_slice(previous_seal);
    out.extend_from_slice(&key_epoch.to_le_bytes());
    out.push(key_index);
    out
}

/// Who signs Root Seals. A trait for the same reason [`super::pq_anchor::AnchorSigner`]
/// is one: a software key now, an HSM behind PKCS#11 in production.
pub trait SealSigner {
    /// Where the key lives. Production mode refuses anything but
    /// [`SignerBackend::Hsm`].
    fn backend(&self) -> SignerBackend;
    /// The raw SLH-DSA-SHAKE-256s public key (64 bytes).
    fn public_key(&self) -> Vec<u8>;
    /// Sign the canonical payload under `BDLM/SEAL/V1`.
    ///
    /// # Errors
    ///
    /// Any backend refusal. Never substituted output.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError>;
}

/// A software SLH-DSA-SHAKE-256s signer over a 96 byte seed, wiped on drop.
///
/// Devnet and tests only: a production seal key lives in an HSM.
pub struct SoftwareSealSigner {
    seed: Zeroizing<Vec<u8>>,
}

impl SoftwareSealSigner {
    /// Build a signer from its seed (`sk_seed || sk_prf || pk_seed`, 96 bytes).
    ///
    /// # Errors
    ///
    /// [`AnchorError::InvalidSignature`] when the seed has the wrong length.
    pub fn from_seed(seed: &[u8]) -> Result<Self, AnchorError> {
        let expected = pq::slh_dsa_seed_len(SchemeId::SLH_DSA_SHAKE_256S)
            .map_err(|_| AnchorError::InvalidSignature)?;
        if seed.len() != expected {
            return Err(AnchorError::InvalidSignature);
        }
        Ok(Self {
            seed: Zeroizing::new(seed.to_vec()),
        })
    }

    /// A fresh random key.
    ///
    /// # Errors
    ///
    /// [`AnchorError::SigningBackendUnavailable`] when the OS rng is dead.
    pub fn generate() -> Result<Self, AnchorError> {
        let len = pq::slh_dsa_seed_len(SchemeId::SLH_DSA_SHAKE_256S)
            .map_err(|_| AnchorError::InvalidSignature)?;
        let mut seed = Zeroizing::new(vec![0u8; len]);
        rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, seed.as_mut_slice())
            .map_err(|_| AnchorError::SigningBackendUnavailable("os-rng"))?;
        Ok(Self { seed })
    }
}

impl SealSigner for SoftwareSealSigner {
    fn backend(&self) -> SignerBackend {
        SignerBackend::Software
    }

    fn public_key(&self) -> Vec<u8> {
        pq::slh_dsa_public_key(SchemeId::SLH_DSA_SHAKE_256S, &self.seed).unwrap_or_default()
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        // Hedged: the randomizer is `n` = 32 fresh bytes.
        let mut rnd = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, rnd.as_mut_slice())
            .map_err(|_| AnchorError::SigningBackendUnavailable("os-rng"))?;
        pq::slh_dsa_sign(
            SchemeId::SLH_DSA_SHAKE_256S,
            &self.seed,
            payload,
            crate::crypto::ctx::SEAL_V1,
            Some(rnd.as_slice()),
        )
        .map_err(|_| AnchorError::InvalidSignature)
    }
}

/// Build and sign the Root Seal of the period ending at `seal_height`.
///
/// # Errors
///
/// The period checks of [`period_anchors_root`], or the signer's refusal.
pub fn build_root_seal(
    chain_id: u64,
    seal_height: u64,
    period_anchors: &[PqAnchor],
    previous: Option<&RootSeal>,
    key_epoch: u32,
    key_index: u8,
    signer: &dyn SealSigner,
) -> Result<RootSeal, SealError> {
    let (anchors_root, anchor_count) = period_anchors_root(seal_height, period_anchors)?;
    let previous_seal = previous.map_or(GENESIS_SEAL_LINK, RootSeal::digest);
    let payload = root_seal_payload(
        chain_id,
        seal_height,
        &anchors_root,
        anchor_count,
        &previous_seal,
        key_epoch,
        key_index,
    );
    let signature = signer.sign(&payload).map_err(SealError::Signing)?;
    Ok(RootSeal {
        chain_id,
        seal_height,
        anchors_root,
        anchor_count,
        previous_seal,
        key_epoch,
        key_index,
        signature,
    })
}

/// The keys a seal may be signed under: one SLH-DSA-SHAKE-256s public key per
/// slot, with the slots a key epoch suspends. The anchor key ledger
/// (`anchor_ledger`) implements it.
pub trait SealKeys {
    /// The public key of slot `index`, `None` when the slot does not exist.
    fn seal_key(&self, index: u8) -> Option<&[u8]>;
    /// Whether the slot is suspended for `key_epoch`.
    fn seal_key_suspended(&self, index: u8, key_epoch: u32) -> bool;
}

/// Verify one Root Seal against the seal keys of the ledger.
///
/// The check order is cheap before expensive: chain, boundary and key epoch,
/// the slot, then the signature. When `anchors` is given, the seal must
/// commit exactly that anchor set.
///
/// # Errors
///
/// The first [`SealError`] that applies.
pub fn verify_root_seal(
    seal: &RootSeal,
    chain_id: u64,
    keys: &dyn SealKeys,
    current_key_epoch: u32,
    anchors: Option<&[PqAnchor]>,
) -> Result<(), SealError> {
    if seal.chain_id != chain_id {
        return Err(SealError::WrongChain {
            expected: chain_id,
            got: seal.chain_id,
        });
    }
    if !seal_due(seal.seal_height) {
        return Err(SealError::HeightNotOnBoundary {
            height: seal.seal_height,
        });
    }
    if seal.key_epoch != current_key_epoch {
        return Err(SealError::StaleKeyEpoch {
            seal_epoch: seal.key_epoch,
            current_epoch: current_key_epoch,
        });
    }
    let Some(public_key) = keys.seal_key(seal.key_index) else {
        return Err(SealError::UnknownKeyIndex {
            index: seal.key_index,
        });
    };
    if keys.seal_key_suspended(seal.key_index, seal.key_epoch) {
        return Err(SealError::KeySuspended {
            index: seal.key_index,
            key_epoch: seal.key_epoch,
        });
    }
    if let Some(anchors) = anchors {
        let (root, count) = period_anchors_root(seal.seal_height, anchors)?;
        if root != seal.anchors_root || count != seal.anchor_count {
            return Err(SealError::AnchorsMismatch);
        }
    }
    verify_in_context(
        AnchorSignatureAlgorithm::SlhDsaShake256s,
        public_key,
        &seal.payload(),
        crate::crypto::ctx::SEAL_V1,
        &seal.signature,
    )
    .map_err(|_| SealError::InvalidSignature)
}

/// The seals a node has verified, oldest first, chained by hash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSealLog {
    seals: std::collections::VecDeque<RootSeal>,
}

impl RootSealLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The latest accepted seal.
    #[must_use]
    pub fn latest(&self) -> Option<&RootSeal> {
        self.seals.back()
    }

    /// How many seals are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seals.len()
    }

    /// Whether no seal is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seals.is_empty()
    }

    /// The seal at `seal_height`, if held.
    #[must_use]
    pub fn at(&self, seal_height: u64) -> Option<&RootSeal> {
        self.seals.iter().find(|s| s.seal_height == seal_height)
    }

    /// Verify a seal against the keys and append it.
    ///
    /// The first seal links to [`GENESIS_SEAL_LINK`]; every later one must be
    /// newer than the latest and link to its digest.
    ///
    /// # Errors
    ///
    /// The refusal of [`verify_root_seal`], [`SealError::NotNewer`] or
    /// [`SealError::BrokenLink`].
    pub fn accept(
        &mut self,
        seal: RootSeal,
        chain_id: u64,
        keys: &dyn SealKeys,
        current_key_epoch: u32,
        anchors: Option<&[PqAnchor]>,
    ) -> Result<(), SealError> {
        if let Some(latest) = self.seals.back() {
            if seal.seal_height <= latest.seal_height {
                return Err(SealError::NotNewer {
                    seal_height: seal.seal_height,
                    latest: latest.seal_height,
                });
            }
            if seal.previous_seal != latest.digest() {
                return Err(SealError::BrokenLink);
            }
        } else if seal.previous_seal != GENESIS_SEAL_LINK {
            // A node that starts from a checkpoint seeds the log with
            // `adopt`; an empty log only takes the genesis link.
            return Err(SealError::BrokenLink);
        }
        verify_root_seal(&seal, chain_id, keys, current_key_epoch, anchors)?;
        self.seals.push_back(seal);
        while self.seals.len() > MAX_RETAINED_SEALS {
            self.seals.pop_front();
        }
        Ok(())
    }

    /// Seed an empty log with a seal verified out of band (a checkpoint sync).
    /// The caller has verified it with [`verify_root_seal`].
    pub fn adopt(&mut self, seal: RootSeal) {
        if self.seals.is_empty() {
            self.seals.push_back(seal);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: u64 = 7;

    struct OneKey {
        key: Vec<u8>,
        suspended: Option<(u8, u32)>,
    }

    impl SealKeys for OneKey {
        fn seal_key(&self, index: u8) -> Option<&[u8]> {
            (index == 0).then_some(self.key.as_slice())
        }
        fn seal_key_suspended(&self, index: u8, key_epoch: u32) -> bool {
            self.suspended == Some((index, key_epoch))
        }
    }

    fn anchor(height: u64) -> PqAnchor {
        PqAnchor {
            chain_id: CHAIN,
            height,
            aggregate_root: [height as u8; 32],
            stark_root: None,
            crossdomain_root: None,
            key_epoch: 1,
            signatures: Vec::new(),
        }
    }

    fn period(seal_height: u64) -> Vec<PqAnchor> {
        (1..=10)
            .map(|i| anchor(seal_height - ROOT_SEAL_INTERVAL + i * 360))
            .collect()
    }

    /// One signer, its public key and the first seal, built once per process:
    /// SLH-DSA-SHAKE-256s key generation and signing are millions of hash
    /// calls and the tests below only need the bytes.
    fn fixture() -> &'static (SoftwareSealSigner, Vec<u8>, RootSeal) {
        static FIXTURE: std::sync::OnceLock<(SoftwareSealSigner, Vec<u8>, RootSeal)> =
            std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            let signer = SoftwareSealSigner::from_seed(&[1u8; 96]).expect("96 byte seed");
            let key = signer.public_key();
            let first = build_root_seal(CHAIN, 3_600, &period(3_600), None, 1, 0, &signer)
                .expect("first seal");
            (signer, key, first)
        })
    }

    fn keys() -> OneKey {
        OneKey {
            key: fixture().1.clone(),
            suspended: None,
        }
    }

    #[test]
    fn a_seal_is_due_on_every_3600th_block_and_nowhere_else() {
        assert!(!seal_due(0));
        assert!(!seal_due(3_599));
        assert!(seal_due(3_600));
        assert!(!seal_due(3_601));
        assert!(seal_due(7_200));
    }

    #[test]
    fn a_seal_verifies_and_a_wrong_one_is_refused() {
        let seal = fixture().2.clone();
        let anchors = period(3_600);
        assert_eq!(seal.signature.len(), 29_792);
        assert_eq!(seal.previous_seal, GENESIS_SEAL_LINK);
        verify_root_seal(&seal, CHAIN, &keys(), 1, Some(&anchors)).expect("the seal verifies");

        // A tampered anchor root.
        let mut forged = seal.clone();
        forged.anchors_root[0] ^= 1;
        let err = verify_root_seal(&forged, CHAIN, &keys(), 1, None).unwrap_err();
        assert_eq!(err.kind(), "seal-invalid-signature");

        // A flipped signature bit.
        let mut flipped = seal.clone();
        flipped.signature[100] ^= 0x80;
        let err = verify_root_seal(&flipped, CHAIN, &keys(), 1, None).unwrap_err();
        assert_eq!(err.kind(), "seal-invalid-signature");

        // A seal under a stranger's key.
        let stranger = OneKey {
            key: vec![0x11; 64],
            suspended: None,
        };
        let err = verify_root_seal(&seal, CHAIN, &stranger, 1, None).unwrap_err();
        assert_eq!(err.kind(), "seal-invalid-signature");
    }

    #[test]
    fn a_seal_is_bound_to_chain_epoch_slot_and_anchor_set() {
        let seal = fixture().2.clone();
        let anchors = period(3_600);
        assert_eq!(
            verify_root_seal(&seal, 8, &keys(), 1, None)
                .unwrap_err()
                .kind(),
            "seal-wrong-chain"
        );
        assert_eq!(
            verify_root_seal(&seal, CHAIN, &keys(), 2, None)
                .unwrap_err()
                .kind(),
            "seal-stale-key-epoch"
        );
        let mut other_slot = seal.clone();
        other_slot.key_index = 3;
        assert_eq!(
            verify_root_seal(&other_slot, CHAIN, &keys(), 1, None)
                .unwrap_err()
                .kind(),
            "seal-unknown-key-index"
        );
        let mut fewer = anchors;
        fewer.pop();
        assert_eq!(
            verify_root_seal(&seal, CHAIN, &keys(), 1, Some(&fewer))
                .unwrap_err()
                .kind(),
            "seal-anchors-mismatch"
        );
        let suspended = OneKey {
            key: fixture().1.clone(),
            suspended: Some((0, 1)),
        };
        assert_eq!(
            verify_root_seal(&seal, CHAIN, &suspended, 1, None)
                .unwrap_err()
                .kind(),
            "seal-key-suspended"
        );
    }

    #[test]
    fn the_period_rules_refuse_empty_foreign_and_unordered_anchors() {
        assert_eq!(
            period_anchors_root(3_600, &[]).unwrap_err().kind(),
            "seal-no-anchors"
        );
        assert_eq!(
            period_anchors_root(3_599, &[anchor(10)])
                .unwrap_err()
                .kind(),
            "seal-height-not-on-boundary"
        );
        assert_eq!(
            period_anchors_root(3_600, &[anchor(3_601)])
                .unwrap_err()
                .kind(),
            "seal-anchor-outside-period"
        );
        assert_eq!(
            period_anchors_root(7_200, &[anchor(3_600)])
                .unwrap_err()
                .kind(),
            "seal-anchor-outside-period"
        );
        assert_eq!(
            period_anchors_root(3_600, &[anchor(720), anchor(360)])
                .unwrap_err()
                .kind(),
            "seal-anchors-not-ascending"
        );
        let many: Vec<PqAnchor> = (0..=MAX_SEAL_ANCHORS as u64)
            .map(|i| anchor(1 + i))
            .collect();
        assert_eq!(
            period_anchors_root(3_600, &many).unwrap_err().kind(),
            "seal-too-many-anchors"
        );
    }

    #[test]
    fn seals_chain_by_digest_and_the_log_refuses_a_break() {
        let (signer, _, first) = fixture();
        let mut log = RootSealLog::new();
        log.accept(first.clone(), CHAIN, &keys(), 1, None)
            .expect("the first seal links to genesis");
        let second = build_root_seal(CHAIN, 7_200, &period(7_200), Some(first), 1, 0, signer)
            .expect("second seal");
        assert_eq!(second.previous_seal, first.digest());
        // A seal that skips the chain: built without the previous seal.
        let orphan =
            build_root_seal(CHAIN, 7_200, &period(7_200), None, 1, 0, signer).expect("orphan");
        assert_eq!(
            log.accept(orphan, CHAIN, &keys(), 1, None)
                .unwrap_err()
                .kind(),
            "seal-broken-link"
        );
        log.accept(second, CHAIN, &keys(), 1, None)
            .expect("the second seal extends the chain");
        assert_eq!(log.len(), 2);
        assert_eq!(log.latest().map(|s| s.seal_height), Some(7_200));
        // Replaying an old seal is not newer.
        assert_eq!(
            log.accept(first.clone(), CHAIN, &keys(), 1, None)
                .unwrap_err()
                .kind(),
            "seal-not-newer"
        );
    }

    #[test]
    fn a_first_seal_must_link_to_genesis() {
        let mut stray = fixture().2.clone();
        stray.previous_seal = [3u8; 32];
        let mut log = RootSealLog::new();
        assert_eq!(
            log.accept(stray, CHAIN, &keys(), 1, None)
                .unwrap_err()
                .kind(),
            "seal-broken-link"
        );
        assert!(log.is_empty());
    }

    #[test]
    fn the_seal_payload_binds_every_field() {
        let base = root_seal_payload(1, 3_600, &[1u8; 32], 10, &[2u8; 32], 1, 0);
        assert!(base.starts_with(b"BDLM_ROOT_SEAL_V1"));
        assert_eq!(base.len(), 17 + 8 + 8 + 32 + 4 + 32 + 4 + 1);
        for other in [
            root_seal_payload(2, 3_600, &[1u8; 32], 10, &[2u8; 32], 1, 0),
            root_seal_payload(1, 7_200, &[1u8; 32], 10, &[2u8; 32], 1, 0),
            root_seal_payload(1, 3_600, &[9u8; 32], 10, &[2u8; 32], 1, 0),
            root_seal_payload(1, 3_600, &[1u8; 32], 9, &[2u8; 32], 1, 0),
            root_seal_payload(1, 3_600, &[1u8; 32], 10, &[9u8; 32], 1, 0),
            root_seal_payload(1, 3_600, &[1u8; 32], 10, &[2u8; 32], 2, 0),
            root_seal_payload(1, 3_600, &[1u8; 32], 10, &[2u8; 32], 1, 1),
        ] {
            assert_ne!(base, other);
        }
    }
}
