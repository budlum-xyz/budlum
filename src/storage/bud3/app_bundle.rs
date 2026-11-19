//! BUD-APP-1: verifiable application bundles and storage mirror attestations.
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.
//!
//! A `.bud` name resolves to a B.U.D. 3.0 content reference, and a browser is
//! handed that reference with no way to check it. [`AppBundle`] is the envelope
//! that closes that gap: one signed-shaped value that binds a name leaf, the
//! object manifest, an isolation policy, and the BNS state root it came from,
//! so a client can check the whole path offline against a root it already
//! trusts.
//!
//! The name half re-uses the canonical sparse Merkle tree: the leaf is the
//! [`Bud3NameBinding`] digest (`BDLM_BUD3_BNS_BINDING_V2`) and the proof is
//! folded with [`crate::bns::smt::root_of_path`], so a bundle cannot invent a
//! second name-hashing rule. The policy half is committed by
//! [`AppIsolationPolicy::digest`] under `BDLM_BUD_APP_POLICY_V1`, so the
//! origins, quota and RPC allowlist an app was verified with cannot be swapped
//! after the fact.
//!
//! [`StorageMirrorAttestation`] is the other half of "verifiable": the object
//! the bundle names is also held outside the chain (IPFS, Arweave) and the
//! mirror's claim to hold it is checked, not believed. The mirror answers one
//! drawn sub-block with the same two-path custody proof the audit path uses
//! ([`CustodyProof::verify`] under `BDLM_BUD3_SYMBOLS_V1`), and the verifier's
//! nonce is bound into the attestation, so a replay for another draw fails.
//!
//! Neither type consults chain state. The caller passes the root it trusts and
//! gets a verdict; that is what makes the check usable offline and in a light
//! client.

use serde::{Deserialize, Serialize};

use super::content_id::{ContentId, ContentIdKind};
use super::content_ref::{ContentRef, ContentRefError};
use super::custody::{Audit, CustodyProof, ProofContext, ProofError};
use crate::bns::bud3::Bud3NameBinding;
use crate::bns::smt::{self, Path, Terminal};
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;

/// Bundle format version this node writes and accepts.
pub const APP_BUNDLE_VERSION: u16 = 1;
/// Domain tag of the bundle digest.
pub const BUNDLE_TAG: &[u8] = b"BDLM_BUD_APP_BUNDLE_V1";
/// Domain tag of the isolation policy digest.
pub const POLICY_TAG: &[u8] = b"BDLM_BUD_APP_POLICY_V1";
/// Domain tag of a storage mirror attestation.
pub const MIRROR_TAG: &[u8] = b"BDLM_STORAGE_MIRROR_V1";

/// The most frame ancestors a policy may allow.
pub const MAX_ORIGINS: usize = 16;
/// The longest allowed origin string.
pub const MAX_ORIGIN_LEN: usize = 128;
/// The largest `storage_quota_bytes` a policy may ask for (1 TiB).
pub const MAX_QUOTA_BYTES: u64 = 1 << 40;
/// The longest name a bundle may bind.
pub const MAX_NAME_LEN: usize = 63;
/// The longest policy RPC allowlist.
pub const MAX_POLICY_METHODS: usize = 64;
/// The longest validity window a bundle may ask for, in epochs.
pub const MAX_LIFETIME_EPOCHS: u64 = 1_000_000;
/// The largest symbol count a mirror attestation may claim (2^24).
pub const MAX_MIRROR_SYMBOLS: u64 = 1 << 24;
/// The largest sub-block count a mirror attestation may claim.
pub const MAX_MIRROR_SUB_BLOCKS: u64 = 4096;

/// Why a bundle or a mirror attestation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The bundle was written by another format version.
    WrongVersion(u16),
    /// The manifest and the envelope disagree about the hash suite.
    HashSuiteMismatch,
    /// The name is empty, too long, or not a lowercase `.bud` label.
    InvalidName,
    /// The manifest commits to another object than the envelope.
    ManifestObjectMismatch,
    /// The manifest carries an unset commitment.
    ManifestUnset,
    /// The content reference is structurally invalid.
    InvalidContentRef(ContentRefError),
    /// The reference names a sealed object without the NFT grant it needs.
    SealedWithoutNft,
    /// The isolation policy is malformed; carries the reason.
    Policy(&'static str),
    /// The state root the proof is folded against is unset.
    UnsetStateRoot,
    /// The name proof does not fold to the state root for this name.
    NameNotInState,
    /// The name proof's terminal leaf is another value than the binding.
    NameLeafMismatch,
    /// `issued_epoch` is after `expires_epoch`.
    EpochOrder,
    /// The validity window is longer than [`MAX_LIFETIME_EPOCHS`].
    LifetimeTooLong,
    /// The bundle had expired at the epoch it was checked at.
    Expired {
        /// Epoch the bundle expired at.
        expires_epoch: u64,
        /// Epoch it was checked at.
        at_epoch: u64,
    },
    /// The mirror locator is unset or names an unknown mirror kind.
    BadLocator,
    /// The mirror challenge is out of range for the claimed root.
    BadChallenge,
    /// The attestation answers another nonce than the one drawn.
    WrongNonce,
    /// The mirror proof answers another challenge than the one recorded.
    ProofMismatch,
    /// The mirror proof does not fold to the claimed symbol root.
    ProofPath,
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongVersion(v) => write!(f, "bundle version {v} is not {APP_BUNDLE_VERSION}"),
            Self::HashSuiteMismatch => f.write_str("manifest and bundle disagree on the hash suite"),
            Self::InvalidName => f.write_str("the bound name is not a .bud label"),
            Self::ManifestObjectMismatch => f.write_str("the manifest commits to another object"),
            Self::ManifestUnset => f.write_str("the manifest carries an unset commitment"),
            Self::InvalidContentRef(e) => write!(f, "content reference: {e:?}"),
            Self::SealedWithoutNft => f.write_str("a sealed reference needs an NFT grant"),
            Self::Policy(reason) => write!(f, "isolation policy: {reason}"),
            Self::UnsetStateRoot => f.write_str("the bundle carries no BNS state root"),
            Self::NameNotInState => f.write_str("the name proof does not fold to the state root"),
            Self::NameLeafMismatch => f.write_str("the name proof carries another leaf"),
            Self::EpochOrder => f.write_str("issued_epoch is after expires_epoch"),
            Self::LifetimeTooLong => f.write_str("the validity window is longer than allowed"),
            Self::Expired {
                expires_epoch,
                at_epoch,
            } => write!(f, "expired at epoch {expires_epoch}, checked at {at_epoch}"),
            Self::BadLocator => f.write_str("the mirror locator is unset"),
            Self::BadChallenge => f.write_str("the mirror challenge is out of range"),
            Self::WrongNonce => f.write_str("the attestation answers another nonce"),
            Self::ProofMismatch => f.write_str("the mirror proof answers another challenge"),
            Self::ProofPath => f.write_str("the mirror proof does not fold to the symbol root"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<ContentRefError> for BundleError {
    fn from(e: ContentRefError) -> Self {
        Self::InvalidContentRef(e)
    }
}

/// The isolation an app runs under, committed by [`Self::digest`].
///
/// The fields are the ones a browser actually enforces: which origins may
/// frame the app, how much B.U.D. 3.0 quota it may spend, which RPC methods it
/// may call, and whether worker scripts and direct network access are allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIsolationPolicy {
    /// Origins allowed to frame the app; `self` or an `https://` origin.
    pub allowed_origins: Vec<String>,
    /// Storage quota the app may spend, in bytes.
    pub storage_quota_bytes: u64,
    /// RPC methods the app may call, as `bud_*` prefixes.
    pub rpc_methods: Vec<String>,
    /// Whether the app may install worker scripts.
    pub worker_scripts_allowed: bool,
    /// Whether the app may open sockets to hosts outside `allowed_origins`.
    pub network_access: bool,
    /// The largest single frame the app may publish.
    pub max_frame_bytes: u32,
}

impl AppIsolationPolicy {
    /// The commitment the bundle carries for this policy.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let flags = [
            u8::from(self.worker_scripts_allowed),
            u8::from(self.network_access),
        ];
        let quota = self.storage_quota_bytes.to_le_bytes();
        let frame = u64::from(self.max_frame_bytes).to_le_bytes();
        let origins = self.allowed_origins.join("\u{1f}");
        let methods = self.rpc_methods.join("\u{1f}");
        hash_fields_bytes(&[
            POLICY_TAG,
            &flags,
            &quota,
            &frame,
            origins.as_bytes(),
            methods.as_bytes(),
        ])
    }

    /// Check the policy a bundle carries.
    ///
    /// # Errors
    ///
    /// [`BundleError::Policy`] naming the first field that is out of range or
    /// not in the canonical form the digest expects (sorted, no duplicates).
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.allowed_origins.len() > MAX_ORIGINS {
            return Err(BundleError::Policy("too many origins"));
        }
        if self.allowed_origins.iter().any(|o| {
            o.len() > MAX_ORIGIN_LEN
                || o.is_empty()
                || o.chars().any(|c| c.is_whitespace())
                || o.chars().any(|c| c.is_uppercase())
        }) {
            return Err(BundleError::Policy("origin is not lowercase without spaces"));
        }
        if self.allowed_origins.iter().any(|o| {
            o.as_str() != "self" && !o.starts_with("https://") && !o.starts_with("http://localhost")
        }) {
            return Err(BundleError::Policy("origin is not self, https, or localhost"));
        }
        let mut sorted = self.allowed_origins.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != self.allowed_origins {
            return Err(BundleError::Policy("origins are not sorted and unique"));
        }
        if self.storage_quota_bytes == 0 || self.storage_quota_bytes > MAX_QUOTA_BYTES {
            return Err(BundleError::Policy("quota is out of range"));
        }
        if self.rpc_methods.len() > MAX_POLICY_METHODS || self.rpc_methods.is_empty() {
            return Err(BundleError::Policy("the RPC allowlist is empty or too long"));
        }
        if self.rpc_methods.iter().any(|m| !m.starts_with("bud_")) {
            return Err(BundleError::Policy("an allowed method is not a bud_* name"));
        }
        if self.max_frame_bytes == 0
            || u64::from(self.max_frame_bytes) > self.storage_quota_bytes
        {
            return Err(BundleError::Policy("the frame cap is out of range"));
        }
        Ok(())
    }

    /// Whether the policy lets the app call `method`.
    ///
    /// A policy entry is a prefix, so `bud_storage` allows
    /// `bud_storageMayView` and `bud_storageGetObject`.
    #[must_use]
    pub fn allows_method(&self, method: &str) -> bool {
        self.rpc_methods
            .iter()
            .any(|allowed| method.starts_with(allowed.as_str()))
    }
}

/// A serialisable form of [`crate::bns::smt::Path`].
///
/// The tree's own path type carries no serde derive, so the bundle holds this
/// and folds it back into [`Path`] before checking. The terminal kind is a
/// byte: `0` leaf, `1` empty, `2` another key's leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameInclusionProof {
    /// `0` leaf, `1` empty, `2` another key's leaf.
    pub terminal_kind: u8,
    /// The leaf value, or the other key's value.
    pub terminal_value: [u8; 32],
    /// The other key, for kind `2`; zero otherwise.
    pub terminal_key: [u8; 32],
    /// Sibling digests from the terminal node up to the root.
    pub siblings: Vec<[u8; 32]>,
}

impl NameInclusionProof {
    /// Capture a path the tree produced.
    #[must_use]
    pub fn from_path(path: &Path) -> Self {
        let (terminal_kind, terminal_value, terminal_key) = match path.terminal {
            Terminal::Leaf(value) => (0u8, value, [0u8; 32]),
            Terminal::Empty => (1u8, [0u8; 32], [0u8; 32]),
            Terminal::Other(key, value) => (2u8, value, key),
        };
        Self {
            terminal_kind,
            terminal_value,
            terminal_key,
            siblings: path.siblings.clone(),
        }
    }

    /// Fold this back into the tree's own path, or `None` for an unknown kind.
    #[must_use]
    pub fn to_path(&self) -> Option<Path> {
        let terminal = match self.terminal_kind {
            0 => Terminal::Leaf(self.terminal_value),
            1 => Terminal::Empty,
            2 => Terminal::Other(self.terminal_key, self.terminal_value),
            _ => return None,
        };
        Some(Path {
            terminal,
            siblings: self.siblings.clone(),
        })
    }

    /// Whether this proof shows `expected_leaf` at `name` under `state_root`.
    #[must_use]
    pub fn verify(&self, name: &str, expected_leaf: [u8; 32], state_root: [u8; 32]) -> bool {
        if state_root == [0u8; 32] {
            return false;
        }
        let Some(path) = self.to_path() else {
            return false;
        };
        match path.terminal {
            Terminal::Leaf(value) if value != expected_leaf => return false,
            Terminal::Leaf(_) => {}
            // A key that is not in the tree proves nothing about a name that is.
            Terminal::Empty | Terminal::Other(_, _) => return false,
        }
        smt::root_of_path(&smt::key_of(name), &path).is_ok_and(|root| root == state_root)
    }

    /// The commitment the bundle digest binds for this proof.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let kind = [self.terminal_kind];
        let mut owned: Vec<Vec<u8>> = vec![kind.to_vec()];
        owned.push(self.terminal_value.to_vec());
        owned.push(self.terminal_key.to_vec());
        for sibling in &self.siblings {
            owned.push(sibling.to_vec());
        }
        let fields: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        hash_fields_bytes(&fields)
    }
}

/// A `.bud` application as a client may verify it offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBundle {
    /// Format version; must be [`APP_BUNDLE_VERSION`].
    pub version: u16,
    /// Hash suite of the manifest this bundle binds.
    pub hash_suite: u8,
    /// The bound name, without the trailing `.bud`.
    pub name: String,
    /// The name owner the binding leaf commits to.
    pub owner: Address,
    /// The content id the name points at.
    pub content_id: ContentId,
    /// The object commitment the name points at.
    pub object_commitment: [u8; 32],
    /// The NFT grant a sealed reference needs.
    pub nft_id: Option<[u8; 32]>,
    /// The manifest of the app's entry object.
    pub manifest: SealedObjectManifestBytes,
    /// The isolation policy the app runs under.
    pub policy: AppIsolationPolicy,
    /// The BNS state root the name proof folds to.
    pub bns_state_root: [u8; 32],
    /// The inclusion proof of the name leaf in that root.
    pub name_proof: NameInclusionProof,
    /// Epoch the bundle was issued at.
    pub issued_epoch: u64,
    /// Epoch the bundle expires at.
    pub expires_epoch: u64,
}

/// The manifest fields a bundle needs, in a serde-stable shape.
///
/// The full [`crate::storage::bud3::seal::SealedObjectManifest`] carries the
/// same commitments; this narrow copy exists so a bundle can be checked without
/// the cipher profile and padding bookkeeping, which no verifier needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedObjectManifestBytes {
    /// Manifest format version (`1`).
    pub version: u16,
    /// Hash suite identifier (see the manifest).
    pub hash_suite: u8,
    /// Commitment over the outer sealed payload.
    pub ciphertext_root: [u8; 32],
    /// Commitment over the canonical plaintext.
    pub plaintext_root: [u8; 32],
    /// Commitment over the object content key.
    pub key_commitment: [u8; 32],
    /// Keyed object commitment.
    pub object_commitment: [u8; 32],
    /// Visibility class of the object.
    pub visibility: SealedObjectVisibilityBytes,
}

impl SealedObjectManifestBytes {
    /// Whether every commitment the bundle will rely on is set.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.ciphertext_root != [0u8; 32]
            && self.plaintext_root != [0u8; 32]
            && self.key_commitment != [0u8; 32]
            && self.object_commitment != [0u8; 32]
    }
}

impl AppBundle {
    /// The name binding the leaf must carry.
    ///
    /// # Errors
    ///
    /// [`BundleError::InvalidContentRef`] for a structurally invalid reference
    /// and [`BundleError::SealedWithoutNft`] for a sealed reference with no
    /// NFT grant.
    pub fn binding(&self) -> Result<Bud3NameBinding, BundleError> {
        let content_ref = ContentRef::new(self.content_id, self.object_commitment, self.nft_id)?;
        if content_ref.content_id.kind == ContentIdKind::Sealed && content_ref.nft_id.is_none() {
            return Err(BundleError::SealedWithoutNft);
        }
        Ok(Bud3NameBinding {
            name: self.name.clone(),
            owner: self.owner,
            content_ref,
        })
    }

    /// The commitment a client signs or compares.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let kind_byte = [match self.content_id.kind {
            ContentIdKind::Public => 0u8,
            ContentIdKind::Sealed => 1u8,
        }];
        let nft_flag = [u8::from(self.nft_id.is_some())];
        let nft_bytes = self.nft_id.unwrap_or([0u8; 32]);
        let policy = self.policy.digest();
        let proof = self.name_proof.digest();
        let version = self.version.to_le_bytes();
        let issued = self.issued_epoch.to_le_bytes();
        let expires = self.expires_epoch.to_le_bytes();
        hash_fields_bytes(&[
            BUNDLE_TAG,
            &version,
            &[self.hash_suite],
            self.name.as_bytes(),
            self.owner.as_bytes(),
            &kind_byte,
            &self.content_id.digest,
            &self.content_id.len.to_le_bytes(),
            &self.object_commitment,
            &nft_flag,
            &nft_bytes,
            &self.manifest.ciphertext_root,
            &self.manifest.plaintext_root,
            &self.manifest.key_commitment,
            &policy,
            &self.bns_state_root,
            &proof,
            &issued,
            &expires,
        ])
    }

    /// Check the bundle against the epoch it is being used at.
    ///
    /// # Errors
    ///
    /// The first [`BundleError`] the bundle trips, in this order: version, hash
    /// suite, name shape, manifest commitments, content reference, policy,
    /// state root, name proof, and the validity window.
    pub fn verify(&self, at_epoch: u64) -> Result<(), BundleError> {
        if self.version != APP_BUNDLE_VERSION {
            return Err(BundleError::WrongVersion(self.version));
        }
        if self.hash_suite != self.manifest.hash_suite {
            return Err(BundleError::HashSuiteMismatch);
        }
        if self.name.is_empty()
            || self.name.len() > MAX_NAME_LEN
            || !self.name.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'
            })
        {
            return Err(BundleError::InvalidName);
        }
        if !self.manifest.is_set() {
            return Err(BundleError::ManifestUnset);
        }
        if self.manifest.object_commitment != self.object_commitment {
            return Err(BundleError::ManifestObjectMismatch);
        }
        let binding = self.binding()?;
        self.policy.validate()?;
        if self.bns_state_root == [0u8; 32] {
            return Err(BundleError::UnsetStateRoot);
        }
        let leaf = binding.digest();
        match self.name_proof.to_path().map(|p| p.terminal) {
            Some(Terminal::Leaf(value)) if value != leaf => {
                return Err(BundleError::NameLeafMismatch);
            }
            Some(Terminal::Leaf(_)) => {}
            _ => return Err(BundleError::NameNotInState),
        }
        if !self
            .name_proof
            .verify(&self.name, leaf, self.bns_state_root)
        {
            return Err(BundleError::NameNotInState);
        }
        if self.issued_epoch > self.expires_epoch {
            return Err(BundleError::EpochOrder);
        }
        if self.expires_epoch - self.issued_epoch > MAX_LIFETIME_EPOCHS {
            return Err(BundleError::LifetimeTooLong);
        }
        if at_epoch >= self.expires_epoch {
            return Err(BundleError::Expired {
                expires_epoch: self.expires_epoch,
                at_epoch,
            });
        }
        Ok(())
    }
}

/// The outside store a mirror attestation is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MirrorKind {
    /// An IPFS CIDv1 payload digest.
    Ipfs = 1,
    /// An Arweave transaction id.
    Arweave = 2,
}

impl MirrorKind {
    /// The tag the locator digest binds.
    #[must_use]
    pub fn tag(self) -> &'static [u8] {
        match self {
            Self::Ipfs => b"BDLM_MIRROR_IPFS_V1",
            Self::Arweave => b"BDLM_MIRROR_ARWEAVE_V1",
        }
    }

    /// Read a mirror kind from its byte, or `None`.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Ipfs),
            2 => Some(Self::Arweave),
            _ => None,
        }
    }
}

/// Where a mirror says the object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorLocator {
    /// Which outside store this is.
    pub kind: MirrorKind,
    /// The locator digest: CIDv1 multihash digest, or Arweave tx id bytes.
    pub digest: [u8; 32],
}

/// The draw a mirror answer is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorChallenge {
    /// Segment index the draw is taken from.
    pub segment: u64,
    /// Position of the drawn symbol in the symbol root.
    pub position: u64,
    /// Sub-block index inside the drawn symbol.
    pub sub_block: u64,
    /// The verifier's nonce, so an old answer cannot be replayed.
    pub nonce: [u8; 32],
}

/// A mirror's claim to hold an object, checked rather than believed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMirrorAttestation {
    /// Format version; must be [`APP_BUNDLE_VERSION`].
    pub version: u16,
    /// The object commitment the mirror claims to hold.
    pub object_commitment: [u8; 32],
    /// The symbol root of the placement the draw is taken from.
    pub symbols_root: [u8; 32],
    /// Number of symbols under that root.
    pub symbol_count: u64,
    /// Sub-blocks per symbol.
    pub sub_blocks: u64,
    /// Where the mirror says the object lives.
    pub locator: MirrorLocator,
    /// The draw the answer is bound to.
    pub challenge: MirrorChallenge,
    /// The two-path custody proof of the drawn sub-block.
    pub proof: CustodyProof,
    /// Epoch the mirror answered at.
    pub attested_epoch: u64,
    /// Epoch the answer stops counting.
    pub expires_epoch: u64,
}

impl StorageMirrorAttestation {
    /// The commitment a client compares across mirrors.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let version = self.version.to_le_bytes();
        let count = self.symbol_count.to_le_bytes();
        let subs = self.sub_blocks.to_le_bytes();
        let segment = self.challenge.segment.to_le_bytes();
        let position = self.challenge.position.to_le_bytes();
        let sub_block = self.challenge.sub_block.to_le_bytes();
        let esi = [self.proof.esi as u8];
        let attested = self.attested_epoch.to_le_bytes();
        let expires = self.expires_epoch.to_le_bytes();
        let mut owned: Vec<Vec<u8>> = vec![
            MIRROR_TAG.to_vec(),
            version.to_vec(),
            self.object_commitment.to_vec(),
            self.symbols_root.to_vec(),
            count.to_vec(),
            subs.to_vec(),
            self.locator.kind.tag().to_vec(),
            self.locator.digest.to_vec(),
            segment.to_vec(),
            position.to_vec(),
            sub_block.to_vec(),
            self.challenge.nonce.to_vec(),
            esi.to_vec(),
            self.proof.bytes.to_vec(),
            attested.to_vec(),
            expires.to_vec(),
        ];
        for step in self
            .proof
            .symbol_path
            .iter()
            .chain(self.proof.root_path.iter())
        {
            // A step with no sibling is marked, so a short path cannot be
            // confused with a longer one.
            owned.push(match step {
                Some(sibling) => sibling.to_vec(),
                None => vec![0u8],
            });
        }
        let fields: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        hash_fields_bytes(&fields)
    }

    /// Check the attestation against the nonce the verifier drew.
    ///
    /// # Errors
    ///
    /// [`BundleError::WrongVersion`], [`BundleError::BadLocator`],
    /// [`BundleError::BadChallenge`], [`BundleError::WrongNonce`],
    /// [`BundleError::ProofMismatch`], [`BundleError::ProofPath`],
    /// [`BundleError::EpochOrder`] or [`BundleError::Expired`].
    pub fn verify(&self, expected_nonce: &[u8; 32], at_epoch: u64) -> Result<(), BundleError> {
        if self.version != APP_BUNDLE_VERSION {
            return Err(BundleError::WrongVersion(self.version));
        }
        if self.locator.digest == [0u8; 32] || self.object_commitment == [0u8; 32] {
            return Err(BundleError::BadLocator);
        }
        if self.symbols_root == [0u8; 32]
            || self.symbol_count == 0
            || self.symbol_count > MAX_MIRROR_SYMBOLS
            || self.sub_blocks == 0
            || self.sub_blocks > MAX_MIRROR_SUB_BLOCKS
        {
            return Err(BundleError::BadChallenge);
        }
        if self.challenge.position >= self.symbol_count
            || self.challenge.sub_block >= self.sub_blocks
            || self.challenge.nonce != *expected_nonce
        {
            return Err(BundleError::WrongNonce);
        }
        if self.attested_epoch > self.expires_epoch {
            return Err(BundleError::EpochOrder);
        }
        if at_epoch >= self.expires_epoch {
            return Err(BundleError::Expired {
                expires_epoch: self.expires_epoch,
                at_epoch,
            });
        }
        let audit = Audit {
            segment: self.challenge.segment,
            position: self.challenge.position,
            sub_block: self.challenge.sub_block,
        };
        let ctx = ProofContext {
            symbol_root: self.symbols_root,
            symbol_count: self.symbol_count,
            sub_blocks: self.sub_blocks,
        };
        match self.proof.verify(&audit, &ctx) {
            Ok(()) => Ok(()),
            Err(ProofError::WrongChallenge) => Err(BundleError::ProofMismatch),
            Err(ProofError::BadPath) => Err(BundleError::ProofPath),
        }
    }
}

/// The visibility class a bundle records, in a serde-stable byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealedObjectVisibilityBytes {
    /// Sealed, grants hidden.
    Sealed = 0,
    /// Sealed with consent proofs.
    Consented = 1,
    /// Publicly readable.
    Public = 2,
}

impl SealedObjectVisibilityBytes {
    /// Whether the object is readable without a grant.
    #[must_use]
    pub fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }

    /// Read the class from the manifest's own enum.
    #[must_use]
    pub fn from_manifest(visibility: super::seal::ObjectVisibility) -> Self {
        match visibility {
            super::seal::ObjectVisibility::Sealed => Self::Sealed,
            super::seal::ObjectVisibility::Consented => Self::Consented,
            super::seal::ObjectVisibility::Public => Self::Public,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bns::smt;
    use crate::storage::bud3::custody;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn content_id(byte: u8) -> ContentId {
        ContentId {
            kind: ContentIdKind::Public,
            digest: [byte; 32],
            len: 4_096,
        }
    }

    fn manifest(object: [u8; 32]) -> SealedObjectManifestBytes {
        SealedObjectManifestBytes {
            version: 1,
            hash_suite: 1,
            ciphertext_root: [0xa1; 32],
            plaintext_root: [0xb1; 32],
            key_commitment: [0xc1; 32],
            object_commitment: object,
            visibility: SealedObjectVisibilityBytes::Public,
        }
    }

    fn policy() -> AppIsolationPolicy {
        AppIsolationPolicy {
            allowed_origins: vec!["https://app.bud".to_string(), "self".to_string()],
            storage_quota_bytes: 1 << 30,
            rpc_methods: vec!["bud_storage".to_string()],
            worker_scripts_allowed: false,
            network_access: false,
            max_frame_bytes: 1 << 20,
        }
    }

    /// A tree holding one name, and the bundle that proves it.
    fn fixture() -> (AppBundle, [u8; 32]) {
        let name = "alice";
        let owner = addr(1);
        let cid = content_id(9);
        let object = [0x77; 32];
        let binding = Bud3NameBinding {
            name: name.to_string(),
            owner,
            content_ref: ContentRef::new(cid, object, None).expect("content ref"),
        };
        let mut tree = smt::Tree::default();
        tree.insert(smt::key_of(name), binding.digest());
        let root = tree.root();
        let proof = NameInclusionProof::from_path(&tree.prove(&smt::key_of(name)));
        let bundle = AppBundle {
            version: APP_BUNDLE_VERSION,
            hash_suite: 1,
            name: name.to_string(),
            owner,
            content_id: cid,
            object_commitment: object,
            nft_id: None,
            manifest: manifest(object),
            policy: policy(),
            bns_state_root: root,
            name_proof: proof,
            issued_epoch: 10,
            expires_epoch: 100,
        };
        (bundle, root)
    }

    #[test]
    fn a_bundle_folds_to_the_state_root_it_carries() {
        let (bundle, root) = fixture();
        assert_eq!(bundle.bns_state_root, root);
        assert_eq!(bundle.verify(50), Ok(()));
        assert_eq!(bundle.binding().expect("binding").name, "alice");
        assert_ne!(bundle.digest(), [0u8; 32]);
    }

    #[test]
    fn a_name_proved_against_another_state_root_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.bns_state_root = [0x11; 32];
        assert_eq!(bundle.verify(50), Err(BundleError::NameNotInState));
    }

    #[test]
    fn a_bundle_whose_owner_moved_after_the_proof_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.owner = addr(2);
        assert_eq!(bundle.verify(50), Err(BundleError::NameLeafMismatch));
    }

    #[test]
    fn a_name_the_tree_does_not_hold_is_refused() {
        let (mut bundle, _) = fixture();
        let other = "bob";
        let mut tree = smt::Tree::default();
        let owner = bundle.owner;
        let binding = Bud3NameBinding {
            name: other.to_string(),
            owner,
            content_ref: ContentRef::new(bundle.content_id, bundle.object_commitment, None)
                .expect("content ref"),
        };
        tree.insert(smt::key_of(other), binding.digest());
        bundle.bns_state_root = tree.root();
        bundle.name_proof = NameInclusionProof::from_path(&tree.prove(&smt::key_of("alice")));
        assert_eq!(bundle.verify(50), Err(BundleError::NameNotInState));
    }

    #[test]
    fn an_expired_bundle_is_refused_with_the_epochs_it_names() {
        let (bundle, _) = fixture();
        assert_eq!(
            bundle.verify(100),
            Err(BundleError::Expired {
                expires_epoch: 100,
                at_epoch: 100
            })
        );
    }

    #[test]
    fn a_bundle_validity_window_longer_than_the_cap_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.expires_epoch = bundle.issued_epoch + MAX_LIFETIME_EPOCHS + 1;
        assert_eq!(bundle.verify(50), Err(BundleError::LifetimeTooLong));
    }

    #[test]
    fn a_manifest_committing_to_another_object_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.manifest.object_commitment = [0x99; 32];
        assert_eq!(bundle.verify(50), Err(BundleError::ManifestObjectMismatch));
    }

    #[test]
    fn an_unset_manifest_commitment_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.manifest.plaintext_root = [0u8; 32];
        assert_eq!(bundle.verify(50), Err(BundleError::ManifestUnset));
    }

    #[test]
    fn a_sealed_reference_without_the_nft_grant_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.content_id.kind = ContentIdKind::Sealed;
        // The reference is checked before the name proof, which is the order
        // `verify` documents: a sealed content id with no NFT grant can never
        // be a valid binding, whatever the leaf says.
        assert_eq!(bundle.verify(50), Err(BundleError::SealedWithoutNft));
        assert_eq!(bundle.binding(), Err(BundleError::SealedWithoutNft));
        // With a grant the reference passes and the leaf check runs again.
        let mut granted = bundle;
        granted.nft_id = Some([0x3c; 32]);
        assert_eq!(granted.verify(50), Err(BundleError::NameLeafMismatch));
    }

    #[test]
    fn a_policy_with_unsorted_origins_is_refused() {
        let (mut bundle, _) = fixture();
        // "self" sorts after "https://app.bud", so this order is not canonical.
        bundle.policy.allowed_origins = vec![
            "self".to_string(),
            "https://app.bud".to_string(),
        ];
        assert_eq!(
            bundle.verify(50),
            Err(BundleError::Policy("origins are not sorted and unique"))
        );
    }

    #[test]
    fn a_policy_quota_over_the_cap_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.policy.storage_quota_bytes = MAX_QUOTA_BYTES + 1;
        assert_eq!(
            bundle.verify(50),
            Err(BundleError::Policy("quota is out of range"))
        );
    }

    #[test]
    fn a_policy_frame_cap_over_its_quota_is_refused() {
        let (mut bundle, _) = fixture();
        bundle.policy.storage_quota_bytes = 1 << 10;
        bundle.policy.max_frame_bytes = 1 << 20;
        assert_eq!(
            bundle.verify(50),
            Err(BundleError::Policy("the frame cap is out of range"))
        );
    }

    #[test]
    fn the_policy_digest_follows_every_field() {
        let base = policy();
        let mut wider = base.clone();
        wider.storage_quota_bytes += 1;
        let mut opened = base.clone();
        opened.network_access = true;
        let mut method = base.clone();
        method.rpc_methods = vec!["bud_storageMayView".to_string()];
        assert_ne!(base.digest(), wider.digest());
        assert_ne!(base.digest(), opened.digest());
        assert_ne!(base.digest(), method.digest());
        assert!(base.allows_method("bud_storageMayView"));
        assert!(!base.allows_method("bud_mint"));
    }

    #[test]
    fn the_bundle_digest_follows_the_policy_and_the_epochs() {
        let (bundle, _) = fixture();
        let mut other = bundle.clone();
        other.policy.rpc_methods = vec!["bud_mine".to_string()];
        assert_ne!(bundle.digest(), other.digest());
        let mut later = bundle.clone();
        later.expires_epoch += 1;
        assert_ne!(bundle.digest(), later.digest());
    }

    fn mirror_fixture() -> (StorageMirrorAttestation, [u8; 32]) {
        let symbol: Vec<u8> = (0..custody::SUB_BLOCK * 4).map(|i| i as u8).collect();
        let leaf = custody::symbol_leaf(&symbol);
        let placed = vec![(0u32, leaf)];
        let proof = custody::prove(0, &placed, 0, &symbol, 3).expect("custody proof");
        let root = custody::symbol_root(&placed);
        let attestation = StorageMirrorAttestation {
            version: APP_BUNDLE_VERSION,
            object_commitment: [0x77; 32],
            symbols_root: root,
            symbol_count: 1,
            sub_blocks: 4,
            locator: MirrorLocator {
                kind: MirrorKind::Ipfs,
                digest: [0x5a; 32],
            },
            challenge: MirrorChallenge {
                segment: 0,
                position: 0,
                sub_block: 3,
                nonce: [0x2b; 32],
            },
            proof,
            attested_epoch: 10,
            expires_epoch: 40,
        };
        (attestation, root)
    }

    #[test]
    fn a_mirror_answer_folds_to_the_symbol_root_it_claims() {
        let (attestation, root) = mirror_fixture();
        assert_eq!(attestation.symbols_root, root);
        assert_eq!(attestation.verify(&[0x2b; 32], 20), Ok(()));
        assert_ne!(attestation.digest(), [0u8; 32]);
    }

    #[test]
    fn a_mirror_answer_to_another_nonce_is_refused() {
        let (attestation, _) = mirror_fixture();
        assert_eq!(
            attestation.verify(&[0x2c; 32], 20),
            Err(BundleError::WrongNonce)
        );
    }

    #[test]
    fn a_mirror_answer_drawn_from_another_position_is_refused() {
        let (mut attestation, _) = mirror_fixture();
        attestation.challenge.position = 1;
        assert_eq!(
            attestation.verify(&[0x2b; 32], 20),
            Err(BundleError::WrongNonce)
        );
    }

    #[test]
    fn a_mirror_answer_with_tampered_bytes_is_refused() {
        let (mut attestation, _) = mirror_fixture();
        attestation.proof.bytes[0] ^= 0xff;
        assert_eq!(
            attestation.verify(&[0x2b; 32], 20),
            Err(BundleError::ProofPath)
        );
    }

    #[test]
    fn an_expired_mirror_answer_is_refused() {
        let (attestation, _) = mirror_fixture();
        assert_eq!(
            attestation.verify(&[0x2b; 32], 40),
            Err(BundleError::Expired {
                expires_epoch: 40,
                at_epoch: 40
            })
        );
    }

    #[test]
    fn a_mirror_answer_with_an_unset_locator_is_refused() {
        let (mut attestation, _) = mirror_fixture();
        attestation.locator.digest = [0u8; 32];
        assert_eq!(
            attestation.verify(&[0x2b; 32], 20),
            Err(BundleError::BadLocator)
        );
    }

    #[test]
    fn a_mirror_answer_claiming_more_symbols_than_the_cap_is_refused() {
        let (mut attestation, _) = mirror_fixture();
        attestation.symbol_count = MAX_MIRROR_SYMBOLS + 1;
        assert_eq!(
            attestation.verify(&[0x2b; 32], 20),
            Err(BundleError::BadChallenge)
        );
    }
}
