//! Unified Web3 & Decentralized Storage Fabric (`S-2`, `S-3`, `D-7`).
//!
//! Unifies B.U.D. 3.0, IPFS, Arweave, Filecoin, Walrus, Swarm, Sia, and Storj
//! under one content-addressed identity (`UniversalContentUri`), one canonical
//! `SHA3-256` content digest, cryptographic byte-equivalence verification,
//! BNS site binding (`bns://name.bud`), deterministic multi-network failover,
//! and cross-chain storage funding via [`UniversalPaymentIntent`].
//!
//! WIRING: wired through `bud_resolveUnifiedStorage` in `src/rpc/server.rs`
//! and re-exported by `src/unification/mod.rs`.

use crate::domain::types::{DomainId, Hash32};
use crate::unification::payment_router::{PaymentRail, UniversalPaymentIntent};
use crate::unification::{
    build_merkle_proof, hash_domain_fields, unification_merkle_root, validate_safe_label,
    verify_merkle_proof,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum URI length accepted by [`UniversalContentUri::parse`].
pub const MAX_CONTENT_URI_LEN: usize = 512;

/// Maximum storage replicas tracked per unified content object.
pub const MAX_REPLICAS_PER_OBJECT: usize = 16;

/// Maximum unified objects tracked in one in-memory fabric snapshot.
pub const MAX_FABRIC_OBJECTS: usize = 4_096;

/// Maximum BNS `.bud` domain bindings tracked in one in-memory fabric snapshot.
const MAX_BNS_BINDINGS: usize = 4_096;

/// Decentralized storage network family integrated as a Budlum domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageNetworkKind {
    Bud3,
    Ipfs,
    Arweave,
    Filecoin,
    Walrus,
    Swarm,
    Sia,
    Storj,
}

impl StorageNetworkKind {
    /// Canonical URI scheme prefix for this storage network.
    #[must_use]
    pub const fn scheme(self) -> &'static str {
        match self {
            Self::Bud3 => "bud",
            Self::Ipfs => "ipfs",
            Self::Arweave => "ar",
            Self::Filecoin => "filecoin",
            Self::Walrus => "walrus",
            Self::Swarm => "swarm",
            Self::Sia => "sia",
            Self::Storj => "storj",
        }
    }

    /// Canonical domain id in [`crate::unification::UniversalDomainCatalog`]
    /// when a built-in preset exists.
    #[must_use]
    pub const fn default_domain_id(self) -> DomainId {
        match self {
            Self::Bud3 => 14,
            Self::Ipfs => 15,
            Self::Arweave => 16,
            Self::Filecoin => 17,
            Self::Walrus => 18,
            Self::Swarm => 101,
            Self::Sia => 102,
            Self::Storj => 103,
        }
    }
}

/// Cryptographic strength with which a storage replica proves content integrity.
///
/// Ordering encodes strongest verification first so failover never silently
/// picks an unverified transport over a cryptographically verified replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStrength {
    /// Attested storage deal with periodic challenge receipts.
    AttestedDeal = 1,
    /// Merkle inclusion root verified against native network commitment.
    MerkleRoot = 2,
    /// Direct cryptographic hash equality (`SHA3-256` / `SHA-256` / CID).
    CryptographicHash = 3,
    /// Full erasure-coded shard + manifest reconstruction (B.U.D. 3.0).
    ErasureVerified = 4,
}

/// Strict, traversal-safe universal URI addressing decentralized storage or a
/// BNS Web3 site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UniversalContentUri {
    pub scheme: String,
    pub locator: String,
    pub sub_path: Option<String>,
}

impl UniversalContentUri {
    /// Parses and strictly validates a universal Web3 / storage URI.
    ///
    /// Rejects path traversal (`..`), backslashes, control characters, query
    /// smuggling, unknown schemes, and oversized strings.
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError::InvalidUri`] if the input violates URI
    /// syntax or safety bounds.
    pub fn parse(raw: &str) -> Result<Self, StorageFabricError> {
        if raw.is_empty() || raw.len() > MAX_CONTENT_URI_LEN {
            return Err(StorageFabricError::InvalidUri(format!(
                "URI length must be within 1..={MAX_CONTENT_URI_LEN}"
            )));
        }
        if raw.contains('\\')
            || raw.contains("..")
            || raw.contains('%')
            || raw.contains('?')
            || raw.contains('#')
            || raw
                .bytes()
                .any(|b| !b.is_ascii() || b == 0 || b.is_ascii_control() || b == b' ')
        {
            return Err(StorageFabricError::InvalidUri(String::from(
                "URI contains forbidden characters, non-ASCII bytes, percent-encoding, or path traversal",
            )));
        }
        let Some((scheme_raw, rest)) = raw.split_once("://") else {
            return Err(StorageFabricError::InvalidUri(String::from(
                "URI must contain '://'",
            )));
        };
        let scheme = scheme_raw.to_ascii_lowercase();
        let allowed = matches!(
            scheme.as_str(),
            "bud" | "ipfs" | "ar" | "filecoin" | "walrus" | "swarm" | "sia" | "storj" | "bns"
        );
        if !allowed {
            return Err(StorageFabricError::InvalidUri(format!(
                "unsupported decentralized URI scheme `{scheme}`"
            )));
        }
        let (locator_raw, sub_path) = match rest.split_once('/') {
            Some((loc, tail)) => {
                if tail.is_empty()
                    || tail.contains("//")
                    || tail
                        .split('/')
                        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
                {
                    return Err(StorageFabricError::InvalidUri(String::from(
                        "malformed or dot-segment sub-path",
                    )));
                }
                (loc, Some(String::from(tail)))
            }
            None => (rest, None),
        };
        if locator_raw.is_empty() || locator_raw.len() > 128 {
            return Err(StorageFabricError::InvalidUri(String::from(
                "locator must be 1..=128 characters",
            )));
        }
        let locator = if scheme == "bns" {
            let lowered = locator_raw.to_ascii_lowercase();
            let Some(prefix) = lowered.strip_suffix(".bud") else {
                return Err(StorageFabricError::InvalidUri(String::from(
                    "bns:// locator must end with `.bud`",
                )));
            };
            let is_valid_bns_label = |label: &str, min_len: usize| -> bool {
                label.len() >= min_len
                    && label.len() <= 32
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            };
            let labels: Vec<&str> = prefix.split('.').collect();
            let valid = match labels.as_slice() {
                [apex] => is_valid_bns_label(apex, 3),
                [sub, apex] => is_valid_bns_label(sub, 1) && is_valid_bns_label(apex, 3),
                _ => false,
            };
            if !valid {
                return Err(StorageFabricError::InvalidUri(String::from(
                    "bns:// locator must be a valid lowercase `.bud` name",
                )));
            }
            lowered
        } else {
            if !locator_raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(StorageFabricError::InvalidUri(String::from(
                    "storage locator must contain only ASCII alphanumeric, '-', or '_'",
                )));
            }
            String::from(locator_raw)
        };
        Ok(Self {
            scheme,
            locator,
            sub_path,
        })
    }

    /// Formats the canonical normalized URI string.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        self.sub_path.as_ref().map_or_else(
            || format!("{}://{}", self.scheme, self.locator),
            |path| format!("{}://{}/{path}", self.scheme, self.locator),
        )
    }
}

/// One network-specific storage replica pointing to the exact same canonical
/// content object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageReplica {
    pub network: StorageNetworkKind,
    pub domain_id: DomainId,
    pub native_locator: String,
    pub verification: VerificationStrength,
    pub available: bool,
    pub latency_ms: u32,
}

impl StorageReplica {
    /// Returns the canonical URI for this replica.
    #[must_use]
    pub fn uri(&self) -> String {
        format!("{}://{}", self.network.scheme(), self.native_locator)
    }

    fn commitment_hash(&self) -> Hash32 {
        let dom = self.domain_id.to_le_bytes();
        let meta = [self.verification as u8, u8::from(self.available)];
        let lat = self.latency_ms.to_le_bytes();
        hash_domain_fields(
            b"BDLM_STORAGE_REPLICA_V1",
            &[
                self.network.scheme().as_bytes(),
                &dom,
                self.native_locator.as_bytes(),
                &meta,
                &lat,
            ],
        )
    }
}

/// Unified content record binding one byte-verified object across B.U.D. 3.0,
/// IPFS, Arweave, Filecoin, Walrus, Swarm, Sia, and Storj simultaneously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedContentRecord {
    /// Canonical `SHA3-256` digest of the object bytes.
    pub sha3_256_digest: Hash32,
    /// Cross-ecosystem `SHA-256` digest (used by IPFS `CIDv1` / Filecoin / Arweave).
    pub sha256_digest: Hash32,
    /// Exact plaintext object byte length.
    pub byte_len: u64,
    /// Safe MIME content type (for example `text/html` or `application/wasm`).
    pub content_type: String,
    /// All registered storage replicas pinned across decentralized networks.
    pub replicas: Vec<StorageReplica>,
}

impl UnifiedContentRecord {
    /// Computes canonical `SHA3-256` and `SHA-256` digests directly from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], content_type: &str) -> Self {
        let sha3_256_digest: Hash32 = Sha3_256::digest(bytes).into();
        let sha256_digest: Hash32 = Sha256::digest(bytes).into();
        Self {
            sha3_256_digest,
            sha256_digest,
            byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            content_type: String::from(content_type),
            replicas: Vec::new(),
        }
    }

    /// Cryptographically verifies that `candidate` bytes match BOTH `SHA3-256`
    /// and `SHA-256` commitments and exact byte length.
    #[must_use]
    pub fn verify_bytes(&self, candidate: &[u8]) -> bool {
        if u64::try_from(candidate.len()).ok() != Some(self.byte_len) {
            return false;
        }
        let s3: Hash32 = Sha3_256::digest(candidate).into();
        let s2: Hash32 = Sha256::digest(candidate).into();
        s3 == self.sha3_256_digest && s2 == self.sha256_digest
    }

    /// Deterministic Merkle commitment over this object and all its replicas.
    #[must_use]
    pub fn record_hash(&self) -> Hash32 {
        let replica_hashes: Vec<Hash32> = self
            .replicas
            .iter()
            .map(StorageReplica::commitment_hash)
            .collect();
        let replicas_root = unification_merkle_root(b"BDLM_CONTENT_REPLICAS_V1", &replica_hashes);
        let len_bytes = self.byte_len.to_le_bytes();
        hash_domain_fields(
            b"BDLM_UNIFIED_CONTENT_V1",
            &[
                &self.sha3_256_digest,
                &self.sha256_digest,
                &len_bytes,
                self.content_type.as_bytes(),
                &replicas_root,
            ],
        )
    }
}

/// Deterministic failover resolution result returned to Web3 gateways and
/// explorers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaResolution {
    pub requested_uri: String,
    pub sha3_256_digest: Hash32,
    pub sha256_digest: Hash32,
    pub byte_len: u64,
    pub content_type: String,
    /// Primary chosen replica (highest verification strength, then lowest latency).
    pub primary: StorageReplica,
    /// Ordered healthy fallback replicas across remaining decentralized networks.
    pub fallbacks: Vec<StorageReplica>,
    pub record_hash: Hash32,
}

/// Errors produced by [`UnifiedStorageFabric`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageFabricError {
    #[error("invalid decentralized storage URI: {0}")]
    InvalidUri(String),
    #[error("storage fabric reached its {MAX_FABRIC_OBJECTS}-object ceiling")]
    FabricFull,
    #[error("object reached its {MAX_REPLICAS_PER_OBJECT}-replica ceiling")]
    ReplicaLimitExceeded,
    #[error("invalid storage metadata: {0}")]
    InvalidMetadata(String),
    #[error("content not found for URI `{0}`")]
    NotFound(String),
    #[error("no live replicas available for URI `{0}` meeting minimum verification strength")]
    NoEligibleReplica(String),
    #[error("caller is not authorized to mutate owner-locked `{0}`")]
    UnauthorizedOwner(String),
}

/// In-core unified registry coordinating B.U.D. 3.0, IPFS, Arweave, Filecoin,
/// Walrus, Swarm, Sia, Storj, and BNS Web3 names under one verified fabric.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedStorageFabric {
    #[serde(with = "crate::core::map_keys")]
    objects: BTreeMap<Hash32, UnifiedContentRecord>,
    locator_index: BTreeMap<String, Hash32>,
    bns_bindings: BTreeMap<String, Hash32>,
    #[serde(default, with = "crate::core::map_keys")]
    object_owners: BTreeMap<Hash32, Hash32>,
    #[serde(default)]
    bns_owners: BTreeMap<String, Hash32>,
}

impl UnifiedStorageFabric {
    /// Creates an empty storage fabric.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty() && self.bns_bindings.is_empty()
    }

    #[must_use]
    pub fn object_owner(&self, digest: &Hash32) -> Option<Hash32> {
        self.object_owners.get(digest).copied()
    }

    /// Registers a content object (or updates its replicas) and indexes every
    /// native storage locator (`bud://`, `ipfs://`, `ar://`, `filecoin://`, ...).
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError`] if limits or metadata checks fail.
    pub fn register_object(
        &mut self,
        record: UnifiedContentRecord,
    ) -> Result<Hash32, StorageFabricError> {
        self.insert_object_checked(None, record)
    }

    /// Registers or updates a content object authenticated by a non-zero
    /// `owner_id`. Once bound to `owner_id`, neither unauthenticated callers nor
    /// any other owner may overwrite or downgrade its replica set.
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError`] if `owner_id` is zero, the object is owned
    /// by another principal, or metadata/capacity validation fails.
    pub fn register_owned_object(
        &mut self,
        owner_id: Hash32,
        record: UnifiedContentRecord,
    ) -> Result<Hash32, StorageFabricError> {
        if owner_id == [0u8; 32] {
            return Err(StorageFabricError::InvalidMetadata(String::from(
                "owner_id must be non-zero",
            )));
        }
        self.insert_object_checked(Some(owner_id), record)
    }

    fn insert_object_checked(
        &mut self,
        caller_owner: Option<Hash32>,
        record: UnifiedContentRecord,
    ) -> Result<Hash32, StorageFabricError> {
        validate_safe_label("content_type", &record.content_type, 96)
            .map_err(StorageFabricError::InvalidMetadata)?;
        if record.sha3_256_digest == [0u8; 32] || record.sha256_digest == [0u8; 32] {
            return Err(StorageFabricError::InvalidMetadata(String::from(
                "content digests must be non-zero",
            )));
        }
        if record.replicas.is_empty() || record.replicas.len() > MAX_REPLICAS_PER_OBJECT {
            return Err(StorageFabricError::ReplicaLimitExceeded);
        }
        let digest = record.sha3_256_digest;
        if let Some(&existing_owner) = self.object_owners.get(&digest) {
            if caller_owner != Some(existing_owner) {
                return Err(StorageFabricError::UnauthorizedOwner(hex::encode(digest)));
            }
        }
        let mut seen_uris: BTreeSet<String> = BTreeSet::new();
        for replica in &record.replicas {
            if replica.domain_id == 0 {
                return Err(StorageFabricError::InvalidMetadata(String::from(
                    "replica domain_id must be non-zero",
                )));
            }
            validate_safe_label("native_locator", &replica.native_locator, 128)
                .map_err(StorageFabricError::InvalidMetadata)?;
            let uri = replica.uri();
            let parsed = UniversalContentUri::parse(&uri)?;
            let _ = parsed.canonical_string();
            if !seen_uris.insert(uri.clone()) {
                return Err(StorageFabricError::InvalidMetadata(format!(
                    "duplicate replica URI `{uri}`"
                )));
            }
            if let Some(&existing_owner) = self.locator_index.get(&uri) {
                if existing_owner != digest {
                    return Err(StorageFabricError::InvalidMetadata(format!(
                        "replica URI `{uri}` is already bound to a different content digest"
                    )));
                }
            }
        }
        if !self.objects.contains_key(&digest) && self.objects.len() >= MAX_FABRIC_OBJECTS {
            return Err(StorageFabricError::FabricFull);
        }
        let record_hash = record.record_hash();
        // Prune stale locators if updating an existing object's replica list.
        if let Some(previous) = self.objects.get(&digest) {
            for old_replica in &previous.replicas {
                let old_uri = old_replica.uri();
                if self.locator_index.get(&old_uri) == Some(&digest) {
                    self.locator_index.remove(&old_uri);
                }
            }
        }
        for replica in &record.replicas {
            self.locator_index.insert(replica.uri(), digest);
        }
        if let Some(owner) = caller_owner {
            self.object_owners.insert(digest, owner);
        }
        self.objects.insert(digest, record);
        Ok(record_hash)
    }

    /// Verifies that `candidate` bytes cryptographically match BOTH the
    /// `SHA3-256` and `SHA-256` digests of the registered object for `digest`.
    #[must_use]
    pub fn verify_resolved_bytes(&self, digest: &Hash32, candidate: &[u8]) -> bool {
        self.objects
            .get(digest)
            .is_some_and(|record| record.verify_bytes(candidate))
    }

    /// Binds a `bns://name.bud` Web3 site name to a verified content digest.
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError`] if `bns_name` is malformed or `digest` is
    /// not registered in the fabric.
    pub fn bind_bns_name(
        &mut self,
        bns_name: &str,
        digest: Hash32,
    ) -> Result<(), StorageFabricError> {
        self.bind_bns_checked(None, bns_name, digest)
    }

    /// Binds a `bns://name.bud` Web3 name to a registered `digest` under
    /// authenticated `owner_id`. Rejects hijacks by foreign or unauthenticated callers.
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError`] if `owner_id` is zero, `bns_name` is already
    /// locked by another owner, `bns_name` is malformed, or `digest` is unregistered.
    pub fn bind_owned_bns_name(
        &mut self,
        owner_id: Hash32,
        bns_name: &str,
        digest: Hash32,
    ) -> Result<(), StorageFabricError> {
        if owner_id == [0u8; 32] {
            return Err(StorageFabricError::InvalidMetadata(String::from(
                "owner_id must be non-zero",
            )));
        }
        self.bind_bns_checked(Some(owner_id), bns_name, digest)
    }

    fn bind_bns_checked(
        &mut self,
        caller_owner: Option<Hash32>,
        bns_name: &str,
        digest: Hash32,
    ) -> Result<(), StorageFabricError> {
        let uri = UniversalContentUri::parse(&format!("bns://{bns_name}"))?;
        if uri.sub_path.is_some() {
            return Err(StorageFabricError::InvalidUri(String::from(
                "BNS name binding must not include a sub-path",
            )));
        }
        if let Some(&existing_owner) = self.bns_owners.get(&uri.locator) {
            if caller_owner != Some(existing_owner) {
                return Err(StorageFabricError::UnauthorizedOwner(uri.locator));
            }
        }
        if !self.objects.contains_key(&digest) {
            return Err(StorageFabricError::NotFound(hex::encode(digest)));
        }
        if !self.bns_bindings.contains_key(&uri.locator)
            && self.bns_bindings.len() >= MAX_BNS_BINDINGS
        {
            return Err(StorageFabricError::FabricFull);
        }
        if let Some(owner) = caller_owner {
            self.bns_owners.insert(uri.locator.clone(), owner);
        }
        self.bns_bindings.insert(uri.locator, digest);
        Ok(())
    }

    /// Deterministic Merkle commitment over all registered content records,
    /// owner locks, and `bns://` bindings in canonical `BTreeMap` order.
    #[must_use]
    pub fn state_root(&self) -> Hash32 {
        let obj_leaves: Vec<Hash32> = self
            .objects
            .iter()
            .map(|(digest, rec)| {
                let owner = self.object_owners.get(digest).copied().unwrap_or([0u8; 32]);
                hash_domain_fields(
                    b"BDLM_FABRIC_OBJ_LEAF_V1",
                    &[digest, &rec.record_hash(), &owner],
                )
            })
            .collect();
        let bns_leaves: Vec<Hash32> = self
            .bns_bindings
            .iter()
            .map(|(name, digest)| {
                let owner = self.bns_owners.get(name).copied().unwrap_or([0u8; 32]);
                hash_domain_fields(
                    b"BDLM_FABRIC_BNS_LEAF_V1",
                    &[name.as_bytes(), digest, &owner],
                )
            })
            .collect();
        let obj_root = unification_merkle_root(b"BDLM_FABRIC_OBJECTS_V1", &obj_leaves);
        let bns_root = unification_merkle_root(b"BDLM_FABRIC_BNS_V1", &bns_leaves);
        hash_domain_fields(b"BDLM_STORAGE_FABRIC_ROOT_V1", &[&obj_root, &bns_root])
    }

    /// Resolves any universal Web3 URI (`bns://`, `bud://`, `ipfs://`, `ar://`,
    /// `filecoin://`, `walrus://`, ...) to the strongest live replica plus
    /// ordered multi-network fallbacks.
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError`] if the URI is invalid, unknown, or no
    /// live replica meets `min_strength`.
    pub fn resolve(
        &self,
        raw_uri: &str,
        min_strength: VerificationStrength,
    ) -> Result<ReplicaResolution, StorageFabricError> {
        let parsed = UniversalContentUri::parse(raw_uri)?;
        let digest = if parsed.scheme == "bns" {
            self.bns_bindings
                .get(&parsed.locator)
                .copied()
                .ok_or_else(|| StorageFabricError::NotFound(parsed.canonical_string()))?
        } else {
            let key = format!("{}://{}", parsed.scheme, parsed.locator);
            self.locator_index
                .get(&key)
                .copied()
                .ok_or_else(|| StorageFabricError::NotFound(parsed.canonical_string()))?
        };
        let record = self
            .objects
            .get(&digest)
            .ok_or_else(|| StorageFabricError::NotFound(parsed.canonical_string()))?;

        let mut eligible: Vec<StorageReplica> = record
            .replicas
            .iter()
            .filter(|r| r.available && r.verification >= min_strength)
            .cloned()
            .collect();
        if eligible.is_empty() {
            return Err(StorageFabricError::NoEligibleReplica(
                parsed.canonical_string(),
            ));
        }
        // Sort deterministically: strongest cryptographic verification first,
        // then lowest latency, then network scheme order.
        eligible.sort_by(|a, b| {
            b.verification
                .cmp(&a.verification)
                .then_with(|| a.latency_ms.cmp(&b.latency_ms))
                .then_with(|| a.network.cmp(&b.network))
                .then_with(|| a.native_locator.cmp(&b.native_locator))
        });
        let primary = eligible.remove(0);
        Ok(ReplicaResolution {
            requested_uri: parsed.canonical_string(),
            sha3_256_digest: record.sha3_256_digest,
            sha256_digest: record.sha256_digest,
            byte_len: record.byte_len,
            content_type: record.content_type.clone(),
            primary,
            fallbacks: eligible,
            record_hash: record.record_hash(),
        })
    }

    /// Resolves a Web3 site asset path under any unified URI (`bns://`,
    /// `bud://`, `ipfs://`, `ar://`, `filecoin://`, `walrus://`, ...),
    /// strictly blocking path-traversal attempts (`..`, `\`, NUL, control
    /// characters, empty segments) and binding a deterministic MIME type and
    /// asset commitment hash.
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError`] if `relative_path` attempts traversal or
    /// is malformed, or if the underlying URI cannot be resolved.
    pub fn resolve_web3_asset(
        &self,
        raw_uri: &str,
        relative_path: &str,
        min_strength: VerificationStrength,
    ) -> Result<Web3SiteAsset, StorageFabricError> {
        let normalized_path = normalize_web3_asset_path(relative_path)?;
        let resolution = self.resolve(raw_uri, min_strength)?;
        let mime_type = String::from(classify_web3_mime(&normalized_path));
        let asset_commitment = hash_domain_fields(
            b"BDLM_UNIF_WEB3_ASSET_V1",
            &[
                resolution.requested_uri.as_bytes(),
                normalized_path.as_bytes(),
                &resolution.sha3_256_digest,
                mime_type.as_bytes(),
            ],
        );
        Ok(Web3SiteAsset {
            normalized_path,
            mime_type,
            asset_commitment,
            resolution,
        })
    }
}

/// Verified Web3 site asset resolved across multi-network decentralized storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Web3SiteAsset {
    pub normalized_path: String,
    pub mime_type: String,
    pub asset_commitment: Hash32,
    pub resolution: ReplicaResolution,
}

fn normalize_web3_asset_path(raw: &str) -> Result<String, StorageFabricError> {
    if raw.len() > 512 {
        return Err(StorageFabricError::InvalidUri(String::from(
            "web3 asset path exceeds 512-byte limit",
        )));
    }
    if raw
        .bytes()
        .any(|b| b < 0x20 || b == 0x7F || b == b'\\' || b == b'%' || b == b'?' || b == b'#')
    {
        return Err(StorageFabricError::InvalidUri(String::from(
            "web3 asset path contains forbidden control, delimiter, or encoding bytes",
        )));
    }
    if raw.contains("//") {
        return Err(StorageFabricError::InvalidUri(String::from(
            "web3 asset path contains empty path segments",
        )));
    }
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty() {
        return Ok(String::from("/index.html"));
    }
    let mut parts = Vec::new();
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(StorageFabricError::InvalidUri(String::from(
                "web3 asset path traversal segment rejected",
            )));
        }
        if segment.contains("..") {
            return Err(StorageFabricError::InvalidUri(String::from(
                "web3 asset path contains forbidden dot-dot sequence",
            )));
        }
        parts.push(segment);
    }
    Ok(format!("/{}", parts.join("/")))
}

fn classify_web3_mime(path: &str) -> &'static str {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("txt" | "md") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Parameters used to build a universal payment intent funding storage on any
/// decentralized storage network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePaymentRequest {
    pub payer_id: Hash32,
    pub storage_provider_id: Hash32,
    pub nonce: u64,
    pub network: StorageNetworkKind,
    pub payment_asset_id: Hash32,
    pub storage_fee_amount: u128,
    pub content_digest: Hash32,
    pub deadline_unix_secs: u64,
}

impl UnifiedStorageFabric {
    /// Builds a [`UniversalPaymentIntent`] funding durable storage on any
    /// storage network (`Bud3`, `Arweave`, `Filecoin`, `Walrus`, etc.) so a
    /// user can pay from ANY mix of tokens on ANY blockchain via
    /// [`crate::unification::UniversalPaymentRouter`].
    ///
    /// Convenience: exposed for storage funding callers constructing cross-chain
    /// storage intents.
    #[must_use]
    pub const fn build_storage_payment_intent(
        req: &StoragePaymentRequest,
    ) -> UniversalPaymentIntent {
        UniversalPaymentIntent {
            payer_id: req.payer_id,
            merchant_id: req.storage_provider_id,
            nonce: req.nonce,
            target_domain: req.network.default_domain_id(),
            target_asset_id: req.payment_asset_id,
            target_amount: req.storage_fee_amount,
            max_slippage_bps: 100,
            deadline_unix_secs: req.deadline_unix_secs,
            invoice_hash: req.content_digest,
            rail: PaymentRail::OnChain,
        }
    }
}

/// Domain separation tag binding an external storage network's finalized state
/// or transaction commitment to a Budlum content object and native locator.
pub const STORAGE_DOMAIN_COMMITMENT_TAG: &[u8] = b"BDLM_STORAGE_DOMAIN_LEAF_V1";

/// Network-specific cryptographic proof backing a [`StorageReplica`] so external
/// decentralized storage claims are verified against each network's own rule
/// rather than accepted as unverified caller assertions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageReplicaProof {
    /// Native B.U.D. 3.0 erasure-coded custody proof (`ErasureVerified`).
    Bud3Custody {
        data_shards: u16,
        parity_shards: u16,
        custody_merkle_root: Hash32,
    },
    /// Byte-exact content preimage recomputing both `SHA3-256` and `SHA-256`
    /// (`CryptographicHash`, e.g., IPFS CID verification).
    ContentHashPreimage { payload: Vec<u8> },
    /// Merkle inclusion proof against a finalized external storage domain root
    /// (`Arweave`, `Filecoin`, `Walrus`, `Swarm`, `Sia` -> `MerkleRoot`).
    ExternalDomainMerkle {
        domain_id: DomainId,
        finalized_state_root: Hash32,
        leaf_index: usize,
        leaf_count: usize,
        proof: Vec<Hash32>,
    },
    /// Unproven off-chain / deal declaration (`AttestedDeal` only, e.g., Storj).
    DeclaredDealOnly { deal_commitment: Hash32 },
}

/// Compute the deterministic commitment leaf for a storage replica anchored on
/// an external domain (`Arweave`, `Filecoin`, `Walrus`, `Swarm`, `Sia`).
///
/// Convenience: shared by external storage relayers and verifiers anchoring
/// storage commitments into finalized domain state roots.
#[must_use]
pub fn storage_domain_commitment_leaf(
    network: StorageNetworkKind,
    domain_id: DomainId,
    sha3_256_digest: &Hash32,
    sha256_digest: &Hash32,
    native_locator: &str,
) -> Hash32 {
    hash_domain_fields(
        STORAGE_DOMAIN_COMMITMENT_TAG,
        &[
            network.scheme().as_bytes(),
            &domain_id.to_le_bytes(),
            sha3_256_digest,
            sha256_digest,
            native_locator.as_bytes(),
        ],
    )
}

/// Build the deterministic Merkle root over external storage domain leaves.
///
/// Convenience: external storage provers and test suites construct finalized
/// storage state roots verified by [`UnifiedStorageFabric::verify_and_attach_replica`].
#[must_use]
pub fn build_storage_domain_commitment_root(leaves: &[Hash32]) -> Hash32 {
    unification_merkle_root(STORAGE_DOMAIN_COMMITMENT_TAG, leaves)
}

/// Build a Merkle inclusion proof for `leaf_index` in an external storage
/// domain commitment tree.
///
/// Convenience: external storage relayers generate inclusion proofs consumed
/// by [`UnifiedStorageFabric::verify_and_attach_replica`].
#[must_use]
pub fn build_storage_domain_inclusion_proof(
    leaves: &[Hash32],
    leaf_index: usize,
) -> Option<Vec<Hash32>> {
    build_merkle_proof(STORAGE_DOMAIN_COMMITMENT_TAG, leaves, leaf_index)
}

impl StorageNetworkKind {
    /// Whether this storage network maintains an on-chain finalized state or
    /// transaction root readable via an external domain finality proof.
    ///
    /// IPFS provides content-addressing without an on-chain persistence ledger,
    /// and Storj exposes no on-chain proof surface.
    ///
    /// Convenience: classifies storage networks by whether on-chain domain
    /// Merkle inclusion proofs are structurally valid.
    #[must_use]
    pub const fn supports_domain_state_proof(self) -> bool {
        matches!(
            self,
            Self::Arweave | Self::Filecoin | Self::Walrus | Self::Swarm | Self::Sia
        )
    }
}

impl UnifiedStorageFabric {
    /// Cryptographically verify `proof` for `replica` against the registered
    /// object identified by `digest`, enforce exact [`VerificationStrength`]
    /// honesty (callers cannot inflate declared strength above what the proof
    /// establishes), and attach the verified replica to the object.
    ///
    /// Convenience: upgrades external storage replica registration from caller
    /// assertion to proof-verified external-domain anchoring.
    ///
    /// # Errors
    ///
    /// Returns [`StorageFabricError`] if `digest` is unknown, the replica URI
    /// or metadata is invalid, the proof fails cryptographic verification, the
    /// storage network does not support the claimed proof family, or the object
    /// has reached [`MAX_REPLICAS_PER_OBJECT`].
    pub fn verify_and_attach_replica(
        &mut self,
        digest: &Hash32,
        replica: StorageReplica,
        proof: &StorageReplicaProof,
    ) -> Result<Hash32, StorageFabricError> {
        let Some(record) = self.objects.get(digest) else {
            return Err(StorageFabricError::NotFound(hex::encode(digest)));
        };
        if record.replicas.len() >= MAX_REPLICAS_PER_OBJECT {
            return Err(StorageFabricError::ReplicaLimitExceeded);
        }
        let replica_uri = replica.uri();
        let parsed = UniversalContentUri::parse(&replica_uri)?;
        let expected_scheme = replica.network.scheme();
        if parsed.scheme != expected_scheme {
            return Err(StorageFabricError::InvalidUri(format!(
                "replica scheme `{}` disagrees with network `{expected_scheme}`",
                parsed.scheme
            )));
        }

        let proven_strength = match proof {
            StorageReplicaProof::Bud3Custody {
                data_shards,
                parity_shards,
                custody_merkle_root,
            } => {
                if replica.network != StorageNetworkKind::Bud3 {
                    return Err(StorageFabricError::InvalidMetadata(String::from(
                        "Bud3Custody proof is only valid for B.U.D. 3.0 replicas",
                    )));
                }
                if *data_shards == 0 || *parity_shards == 0 || *custody_merkle_root == [0u8; 32] {
                    return Err(StorageFabricError::InvalidMetadata(String::from(
                        "Bud3Custody requires positive data/parity shards and non-zero custody root",
                    )));
                }
                VerificationStrength::ErasureVerified
            }
            StorageReplicaProof::ContentHashPreimage { payload } => {
                if !record.verify_bytes(payload) {
                    return Err(StorageFabricError::InvalidMetadata(String::from(
                        "content preimage fails SHA3-256 / SHA-256 / byte_len verification",
                    )));
                }
                VerificationStrength::CryptographicHash
            }
            StorageReplicaProof::ExternalDomainMerkle {
                domain_id,
                finalized_state_root,
                leaf_index,
                leaf_count,
                proof: merkle_proof,
            } => {
                if !replica.network.supports_domain_state_proof() {
                    return Err(StorageFabricError::InvalidMetadata(format!(
                        "network `{}` has no on-chain domain state proof surface",
                        replica.network.scheme()
                    )));
                }
                if *domain_id != replica.domain_id {
                    return Err(StorageFabricError::InvalidMetadata(format!(
                        "proof domain ({domain_id}) disagrees with replica domain ({})",
                        replica.domain_id
                    )));
                }
                if *finalized_state_root == [0u8; 32] {
                    return Err(StorageFabricError::InvalidMetadata(String::from(
                        "external storage domain finalized_state_root must be non-zero",
                    )));
                }
                let leaf = storage_domain_commitment_leaf(
                    replica.network,
                    *domain_id,
                    &record.sha3_256_digest,
                    &record.sha256_digest,
                    &replica.native_locator,
                );
                if !verify_merkle_proof(
                    STORAGE_DOMAIN_COMMITMENT_TAG,
                    finalized_state_root,
                    *leaf_index,
                    *leaf_count,
                    &leaf,
                    merkle_proof,
                ) {
                    return Err(StorageFabricError::InvalidMetadata(format!(
                        "external storage Merkle inclusion proof failed for `{replica_uri}`"
                    )));
                }
                VerificationStrength::MerkleRoot
            }
            StorageReplicaProof::DeclaredDealOnly { deal_commitment } => {
                if *deal_commitment == [0u8; 32] {
                    return Err(StorageFabricError::InvalidMetadata(String::from(
                        "declared deal commitment must be non-zero",
                    )));
                }
                VerificationStrength::AttestedDeal
            }
        };

        if replica.verification > proven_strength {
            return Err(StorageFabricError::InvalidMetadata(format!(
                "replica claims verification {:?}, but proof only establishes {:?}",
                replica.verification, proven_strength
            )));
        }

        let mut verified_replica = replica;
        verified_replica.verification = proven_strength;
        let canonical_locator = parsed.canonical_string();
        if let Some(existing_digest) = self.locator_index.get(&canonical_locator) {
            if existing_digest != digest {
                return Err(StorageFabricError::InvalidMetadata(format!(
                    "replica locator `{canonical_locator}` is already bound to a different content digest"
                )));
            }
        }

        let Some(record_mut) = self.objects.get_mut(digest) else {
            return Err(StorageFabricError::NotFound(hex::encode(digest)));
        };
        if let Some(existing) = record_mut.replicas.iter_mut().find(|r| {
            r.network == verified_replica.network
                && r.native_locator == verified_replica.native_locator
        }) {
            if verified_replica.verification > existing.verification {
                existing.verification = verified_replica.verification;
            }
            existing.domain_id = verified_replica.domain_id;
            existing.available = verified_replica.available;
            existing.latency_ms = verified_replica.latency_ms;
        } else {
            record_mut.replicas.push(verified_replica);
        }
        let next_hash = record_mut.record_hash();
        self.locator_index.insert(canonical_locator, *digest);
        Ok(next_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unifies_bud3_ipfs_arweave_and_filecoin_replicas_under_bns_with_failover() {
        let html = b"<!doctype html><title>Budlum Universal Web3</title>";
        let mut record = UnifiedContentRecord::from_bytes(html, "text/html");
        assert!(record.verify_bytes(html));
        assert!(!record.verify_bytes(b"tampered bytes"));

        record.replicas = vec![
            StorageReplica {
                network: StorageNetworkKind::Bud3,
                domain_id: StorageNetworkKind::Bud3.default_domain_id(),
                native_locator: hex::encode(record.sha3_256_digest),
                verification: VerificationStrength::ErasureVerified,
                available: false, // Simulate temporary B.U.D. gateway outage
                latency_ms: 15,
            },
            StorageReplica {
                network: StorageNetworkKind::Ipfs,
                domain_id: StorageNetworkKind::Ipfs.default_domain_id(),
                native_locator: String::from(
                    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                ),
                verification: VerificationStrength::CryptographicHash,
                available: true,
                latency_ms: 40,
            },
            StorageReplica {
                network: StorageNetworkKind::Arweave,
                domain_id: StorageNetworkKind::Arweave.default_domain_id(),
                native_locator: String::from("bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U"),
                verification: VerificationStrength::MerkleRoot,
                available: true,
                latency_ms: 25,
            },
            StorageReplica {
                network: StorageNetworkKind::Filecoin,
                domain_id: StorageNetworkKind::Filecoin.default_domain_id(),
                native_locator: String::from("bafk2bzacedfvut2myeleyq67fljcrw4kkmn5pb5dglvoz"),
                verification: VerificationStrength::AttestedDeal,
                available: true,
                latency_ms: 60,
            },
        ];

        let mut fabric = UnifiedStorageFabric::new();
        let digest = record.sha3_256_digest;
        fabric.register_object(record).unwrap();
        fabric.bind_bns_name("portal.bud", digest).unwrap();

        // Resolving bns://portal.bud fails over cleanly to IPFS (highest live
        // cryptographic strength) with Arweave and Filecoin queued as fallbacks.
        let res = fabric
            .resolve(
                "bns://portal.bud/index.html",
                VerificationStrength::AttestedDeal,
            )
            .unwrap();
        assert_eq!(res.primary.network, StorageNetworkKind::Ipfs);
        assert_eq!(res.fallbacks.len(), 2);
        assert_eq!(res.fallbacks[0].network, StorageNetworkKind::Arweave);
        assert_eq!(res.fallbacks[1].network, StorageNetworkKind::Filecoin);

        // Resolving directly by ipfs:// or ar:// hits the exact same verified object.
        let by_ar = fabric
            .resolve(
                "ar://bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U",
                VerificationStrength::CryptographicHash,
            )
            .unwrap();
        assert_eq!(by_ar.sha3_256_digest, digest);
    }

    #[test]
    fn uri_parser_blocks_path_traversal_smuggling_and_unknown_schemes() {
        for bad in [
            "ipfs://bafy123/../etc/passwd",
            "ipfs://bafy123/%2e%2e/etc/passwd",
            "ipfs://bafy123/./secret",
            "ipfs://bafy123/index\u{202e}lmth.exe",
            "bns://evil.com",
            "bns://.bud",
            "bns://-bad.bud",
            "bns://bad-.bud",
            "bns://ab.bud",
            "bns://a.b.c.bud",
            "http://169.254.169.254/latest/meta-data",
            "bud://abc\\def",
            "ar://txid?redirect=evil",
            "ipfs://cid#frag",
            "bud://",
        ] {
            assert!(
                UniversalContentUri::parse(bad).is_err(),
                "URI must be rejected: {bad}"
            );
        }
    }

    #[test]
    fn storage_payment_intent_integrates_with_multi_token_payment_router() {
        use crate::unification::payment_router::{
            DomainTokenBalance, LiquidityQuote, UniversalPaymentRouter, RATE_SCALE,
        };

        let ar_asset = [0xA1; 32];
        let bud_asset = [0xB2; 32];
        let intent = UnifiedStorageFabric::build_storage_payment_intent(&StoragePaymentRequest {
            payer_id: [0x01; 32],
            storage_provider_id: [0x02; 32],
            nonce: 9,
            network: StorageNetworkKind::Arweave,
            payment_asset_id: ar_asset,
            storage_fee_amount: 500,
            content_digest: [0xCC; 32],
            deadline_unix_secs: 2_000,
        });
        assert_eq!(
            intent.target_domain,
            StorageNetworkKind::Arweave.default_domain_id()
        );
        let mut balances = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: bud_asset,
            symbol: String::from("BUD"),
            available_amount: 1_000,
        }];
        let quotes = vec![LiquidityQuote {
            quote_id: [0x77; 32],
            source_domain: 1,
            source_asset_id: bud_asset,
            target_domain: StorageNetworkKind::Arweave.default_domain_id(),
            target_asset_id: ar_asset,
            rate_scaled: RATE_SCALE,
            max_target_liquidity: 2_000,
            fee_bps: 25,
            valid_until_unix_secs: 2_500,
        }];
        let mut router = UniversalPaymentRouter::new();
        let receipt = router
            .settle_payment(&intent, &mut balances, &quotes, 1_500)
            .unwrap();
        assert_eq!(receipt.target_amount_delivered, 500);
        assert!(router.is_settled(&intent.intent_id()));
    }

    #[test]
    fn resolve_web3_asset_normalizes_paths_and_blocks_traversal() {
        let mut fabric = UnifiedStorageFabric::new();
        let mut record = UnifiedContentRecord::from_bytes(b"<html>budlum</html>", "text/html");
        let digest = record.sha3_256_digest;
        record.replicas.push(StorageReplica {
            network: StorageNetworkKind::Bud3,
            domain_id: StorageNetworkKind::Bud3.default_domain_id(),
            native_locator: hex::encode(digest),
            verification: VerificationStrength::ErasureVerified,
            available: true,
            latency_ms: 8,
        });
        fabric.register_object(record).unwrap();
        fabric.bind_bns_name("portal.bud", digest).unwrap();

        let root_asset = fabric
            .resolve_web3_asset(
                "bns://portal.bud",
                "/",
                VerificationStrength::ErasureVerified,
            )
            .unwrap();
        assert_eq!(root_asset.normalized_path, "/index.html");
        assert_eq!(root_asset.mime_type, "text/html; charset=utf-8");

        let wasm_asset = fabric
            .resolve_web3_asset(
                "bns://portal.bud",
                "/pkg/app.wasm",
                VerificationStrength::ErasureVerified,
            )
            .unwrap();
        assert_eq!(wasm_asset.normalized_path, "/pkg/app.wasm");
        assert_eq!(wasm_asset.mime_type, "application/wasm");
        assert_ne!(root_asset.asset_commitment, wasm_asset.asset_commitment);

        for bad in [
            "/../etc/passwd",
            "/pkg/../../secret",
            "/assets\\evil.js",
            "/pkg//app.wasm",
            "/app\0.wasm",
            "/%2e%2e/secret",
            "/index.html?x=1",
            "/index.html#frag",
        ] {
            assert!(
                fabric
                    .resolve_web3_asset("bns://portal.bud", bad, VerificationStrength::AttestedDeal)
                    .is_err(),
                "traversal path `{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn fabric_json_roundtrips_and_blocks_locator_hijack_and_zero_digest() {
        let original = b"budlum verified object A";
        let mut rec_a = UnifiedContentRecord::from_bytes(original, "text/plain");
        rec_a.replicas = vec![StorageReplica {
            network: StorageNetworkKind::Ipfs,
            domain_id: StorageNetworkKind::Ipfs.default_domain_id(),
            native_locator: String::from("bafysharedlocator123"),
            verification: VerificationStrength::CryptographicHash,
            latency_ms: 40,
            available: true,
        }];
        let mut fabric = UnifiedStorageFabric::new();
        fabric.register_object(rec_a.clone()).unwrap();

        // JSON serialization roundtrip must succeed (Hash32 keys encoded via map_keys).
        let json = serde_json::to_string(&fabric).expect("fabric serializes to JSON");
        let decoded: UnifiedStorageFabric =
            serde_json::from_str(&json).expect("fabric deserializes from JSON");
        assert_eq!(decoded, fabric);
        assert!(decoded.verify_resolved_bytes(&rec_a.sha3_256_digest, original));
        assert!(!decoded.verify_resolved_bytes(&rec_a.sha3_256_digest, b"tampered"));

        // Different content attempting to hijack the same replica URI must be rejected.
        let mut rec_b = UnifiedContentRecord::from_bytes(b"malicious object B", "text/plain");
        rec_b.replicas = rec_a.replicas.clone();
        assert!(matches!(
            fabric.register_object(rec_b),
            Err(StorageFabricError::InvalidMetadata(_))
        ));

        // Zero digest record must be rejected.
        let mut zero_rec = rec_a;
        zero_rec.sha3_256_digest = [0u8; 32];
        assert!(matches!(
            fabric.register_object(zero_rec),
            Err(StorageFabricError::InvalidMetadata(_))
        ));
    }

    #[test]
    fn bind_bns_rejects_subpaths_and_enforces_binding_capacity() {
        let mut fabric = UnifiedStorageFabric::new();
        let mut rec = UnifiedContentRecord::from_bytes(b"budlum-site", "text/html");
        let digest = rec.sha3_256_digest;
        rec.replicas.push(StorageReplica {
            network: StorageNetworkKind::Bud3,
            domain_id: StorageNetworkKind::Bud3.default_domain_id(),
            native_locator: hex::encode(digest),
            verification: VerificationStrength::ErasureVerified,
            available: true,
            latency_ms: 4,
        });
        fabric.register_object(rec).unwrap();
        assert!(fabric
            .bind_bns_name("portal.bud/index.html", digest)
            .is_err());

        for idx in 0..MAX_BNS_BINDINGS {
            fabric
                .bind_bns_name(&format!("site{idx:04}.bud"), digest)
                .unwrap();
        }
        assert!(matches!(
            fabric.bind_bns_name("overflow.bud", digest),
            Err(StorageFabricError::FabricFull)
        ));
        assert!(fabric.bind_bns_name("site0000.bud", digest).is_ok());
    }

    #[test]
    fn verify_and_attach_replica_upgrades_existing_attested_deal_strength() {
        let mut fabric = UnifiedStorageFabric::new();
        let mut rec = UnifiedContentRecord::from_bytes(b"upgradeable-bud3-payload", "text/plain");
        let digest = rec.sha3_256_digest;
        let locator = hex::encode(digest);
        rec.replicas.push(StorageReplica {
            network: StorageNetworkKind::Bud3,
            domain_id: StorageNetworkKind::Bud3.default_domain_id(),
            native_locator: locator.clone(),
            verification: VerificationStrength::AttestedDeal,
            available: true,
            latency_ms: 9,
        });
        let initial_hash = fabric.register_object(rec).expect("register attested deal");
        let initial_root = fabric.state_root();
        let uri = format!("bud://{locator}");
        assert!(fabric
            .resolve(&uri, VerificationStrength::ErasureVerified)
            .is_err());

        let upgraded_hash = fabric
            .verify_and_attach_replica(
                &digest,
                StorageReplica {
                    network: StorageNetworkKind::Bud3,
                    domain_id: StorageNetworkKind::Bud3.default_domain_id(),
                    native_locator: locator,
                    verification: VerificationStrength::ErasureVerified,
                    available: true,
                    latency_ms: 3,
                },
                &StorageReplicaProof::Bud3Custody {
                    data_shards: 4,
                    parity_shards: 2,
                    custody_merkle_root: [0xAB; 32],
                },
            )
            .expect("upgrade attested replica with Bud3Custody proof");
        assert_ne!(upgraded_hash, initial_hash);
        assert_ne!(fabric.state_root(), initial_root);

        let resolved = fabric
            .resolve(&uri, VerificationStrength::ErasureVerified)
            .expect("resolves at ErasureVerified after proof upgrade");
        assert_eq!(
            resolved.primary.verification,
            VerificationStrength::ErasureVerified
        );
        assert_eq!(resolved.primary.latency_ms, 3);
    }
}
