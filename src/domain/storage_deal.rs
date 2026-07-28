//! B.U.D. storage deals and retrieval challenges (
//! Vision §8.5).
//!
//! **Production boundary:** the BudZKVM `VerifyMerkle` 64-depth soundness gate
//! Is still treated as incomplete for mainnet claims. Every `open_deal` requires
//! A structurally valid `ProofEnvelope` plus `storage_root`, and challenge answers
//! Bind that envelope to chain/deal/challenge context, but this module must not
//! Market the result as full Proof-of-Storage until the independent proof gate is
//! Closed.
//!
//! Two availability/proof layers currently coexist:
//!
//! 1. **Merkle envelope binding:** every `open_deal` requires a
//!    `merkle_proof` and `storage_root`; the chain validates envelope shape and
//!    Replay-domain binding. This is a devnet hardening gate, not a mainnet
//!    Durability claim.
//!
//! 2. **Retrieval Challenge:** the interim retrieval challenge remains
//!    As an anti-unresponsiveness mechanism. An operator can pass by holding only
//!    The requested byte range — it does NOT prove full storage. Treat
//!    Slashing-from-missed-challenge as a "this operator is unresponsive" signal,
//!    NOT as a "this operator is destroying provable storage" signal.
//!
//! Data-sovereignty rule (plan §0.5): anyone (any account, no
//! Role required) may open a `RetrievalChallenge` and may submit a
//! `StorageDeal`. There is no team-gated "official monitor" role.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::storage_params::StorageDomainParams;
use crate::domain::Hash32;
use crate::storage::content_id::ContentId;
use crate::storage::manifest::ContentManifest;
use bud_proof::ProverAdapter;
use serde::{Deserialize, Serialize};

/// RPC-facing DTO for `bud_storageOpenChallenge`.
///
/// Wraps the chain-relevant fields so the JSON shape is explicit and
/// Stable. Decouples the on-chain `RetrievalChallenge` (which carries
/// `opener` as the resolved `Address` and `opener_bond` already debited
/// From the caller's stake) from the request (which is the raw caller
/// Intent).
///
/// **Security:** `opener_signature` is mandatory on Mainnet.
/// The RPC layer verifies that the `opener` address has signed the
/// Challenge intent; without this, any caller could self-report any
/// Address as the opener, making the `opener_bond` anti-spam gate
/// Economically meaningless.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetrievalChallengeRequest {
    pub deal_id: u64,
    pub byte_start: u64,
    pub byte_end: u64,
    pub challenge_epoch: u64,
    pub deadline_epoch: u64,
    pub opener_bond: u64,
    #[serde(default)]
    pub opener: Option<crate::core::address::Address>,
    /// Ed25519 signature over `hash_fields_bytes(["BUD_OPEN_CHALLENGE_V1",
    /// Deal_id, byte_start, byte_end, challenge_epoch, deadline_epoch,
    /// Opener_bond, opener])`. 64 bytes.
    #[serde(default)]
    pub opener_signature: Option<Vec<u8>>,
}

/// Lifecycle status of a `StorageDeal`. Reuses the same enum-tag
/// Convention as the `permissionless::MemberStatus` enum — explicit
/// Variants so the economic surface is auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DealStatus {
    /// Active deal, bond locked, fee per epoch accruing.
    Active,
    /// Bond was slashed (challenge missed). The bond is *not* auto-burned
    /// In this layer — it is recorded in `Slashed` and handed to a
    /// Higher-level `Blockchain` accounting path.
    /// This is the explicit "no admin hook, no silent burn" rule.
    Slashed,
    /// Deal reached `deal_end_epoch` and was finalized normally.
    Expired,
}

/// Storage economics parameters, scoped to a single deal. Per-domain
/// Defaults are in `StorageDomainParams`; this is the per-deal view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageEconomicsParams {
    /// Bond the operator must lock when opening the deal. In the same
    /// `u64` fixed-point unit as `ConsensusDomain::operator_bond`.
    pub operator_bond: u64,
    /// Fee paid by the client to the operator per epoch.
    pub fee_per_epoch: u64,
}

/// A storage deal binding an operator to host a specific shard of a
/// Specific manifest. One shard may have multiple deals (replication =
/// Different `replica_index`).
fn default_merkle_depth() -> u8 {
    64
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageDeal {
    // === B.U.D.: Merkle Proof ===

    // 64-depth Merkle proof serialized as [leaf || siblings || path_bits].
    // Present when `verify_merkle = Some(...)`.
    // None = interim challenge mode (compatibility).
    #[serde(default)]
    pub merkle_proof: Option<Vec<u8>>,

    // The global storage root this proof was verified against.
    // Must match `GlobalBlockHeader.storage_root`.
    #[serde(default)]
    pub storage_root: Option<Hash32>,

    // Proof depth: 64 for full verification.
    #[serde(default = "default_merkle_depth")]
    pub merkle_depth: u8,
    pub deal_id: u64,
    pub domain_id: u32,
    pub manifest_id: ContentId,
    pub shard_id: ContentId,
    pub operator: Address,
    pub economics: StorageEconomicsParams,
    /// 0 = primary replica, 1..N = additional replicas. A shard with a
    /// Single replica is `replica_index = 0`; replication = 3 means three
    /// Deals with `replica_index ∈ {0, 1, 2}` for the same `shard_id`.
    pub replica_index: u8,
    pub deal_start_epoch: u64,
    pub deal_end_epoch: u64,
    pub status: DealStatus,
}

impl StorageDeal {
    pub fn is_active(&self) -> bool {
        self.status == DealStatus::Active
    }

    /// Number of epochs the deal is scheduled to last. `0` is a
    /// Configuration error caught at deal-open time.
    pub fn duration_epochs(&self) -> u64 {
        self.deal_end_epoch.saturating_sub(self.deal_start_epoch)
    }
}

/// A pending retrieval challenge. The opener (`opener`) is just a regular
/// Account — no role required. `byte_start`/`byte_end` describe the
/// Sub-range of the shard the operator must hash to answer.
///
/// **WARNING:** answering this challenge only proves
/// The operator holds the requested byte range, not the whole shard.
/// See module-level docs and the README cross-link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetrievalChallenge {
    pub challenge_id: u64,
    pub deal_id: u64,
    pub shard_id: ContentId,
    pub byte_start: u64,
    pub byte_end: u64,
    pub challenge_epoch: u64,
    pub deadline_epoch: u64,
    pub opener: Address,
    /// Bond the opener locks when opening the challenge. Symmetric to
    /// `submit_registry_slashing_report` in `chain/blockchain.rs` —
    /// Bond is returned on success, burned on false positive. This is
    /// The **data-sovereignty anti-spam mechanism** (no team-gated
    /// Monitor role).
    pub opener_bond: u64,
}

/// Canonical replay domain for a storage challenge STARK proof. Provers and
/// Verifiers must use this complete context; a proof bound only to a storage
/// Root/range hash can be replayed across deals, replicas, challenges or chains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageChallengeProofContext {
    pub chain_id: u64,
    pub domain_id: u32,
    pub deal_id: u64,
    pub manifest_id: ContentId,
    pub shard_id: ContentId,
    pub replica_index: u8,
    pub operator: Address,
    pub challenge_id: u64,
    pub byte_start: u64,
    pub byte_end: u64,
    pub challenge_epoch: u64,
    pub deadline_epoch: u64,
    pub opener: Address,
    pub responder: Address,
    pub response_epoch: u64,
}

pub struct StorageChallengeRangeInput<'a> {
    pub entropy: &'a Hash32,
    pub deal: &'a StorageDeal,
    pub manifest: &'a ContentManifest,
    pub opener: Address,
    pub challenge_epoch: u64,
    pub deadline_epoch: u64,
    pub requested_len: u64,
    pub challenge_id: u64,
}

impl StorageChallengeProofContext {
    fn from_registry(
        chain_id: u64,
        challenge: &RetrievalChallenge,
        deal: &StorageDeal,
        responder: Address,
        response_epoch: u64,
    ) -> Self {
        Self {
            chain_id,
            domain_id: deal.domain_id,
            deal_id: deal.deal_id,
            manifest_id: deal.manifest_id,
            shard_id: deal.shard_id,
            replica_index: deal.replica_index,
            operator: deal.operator,
            challenge_id: challenge.challenge_id,
            byte_start: challenge.byte_start,
            byte_end: challenge.byte_end,
            challenge_epoch: challenge.challenge_epoch,
            deadline_epoch: challenge.deadline_epoch,
            opener: challenge.opener,
            responder,
            response_epoch,
        }
    }

    pub fn digest(&self, storage_root: &Hash32, range_hash: &ContentId) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"BDLM_STORAGE_CHALLENGE_CONTEXT_V1");
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.domain_id.to_le_bytes());
        hasher.update(self.deal_id.to_le_bytes());
        hasher.update(self.manifest_id.0);
        hasher.update(self.shard_id.0);
        hasher.update([self.replica_index]);
        hasher.update(self.operator.as_bytes());
        hasher.update(self.challenge_id.to_le_bytes());
        hasher.update(self.byte_start.to_le_bytes());
        hasher.update(self.byte_end.to_le_bytes());
        hasher.update(self.challenge_epoch.to_le_bytes());
        hasher.update(self.deadline_epoch.to_le_bytes());
        hasher.update(self.opener.as_bytes());
        hasher.update(self.responder.as_bytes());
        hasher.update(self.response_epoch.to_le_bytes());
        hasher.update(storage_root);
        hasher.update(range_hash.0);
        hasher.finalize().into()
    }
}

/// The operator's answer to a `RetrievalChallenge`. `range_hash` MUST
/// Equal `ContentId::of_subrange(shard, byte_start, byte_end)`. The
/// Chain does not hold the shard bytes; verification is done by
/// Whoever inspects the response off-chain.
///
/// **Security:** `responder_signature` is mandatory on Mainnet.
/// The RPC layer verifies that the `responder` (the deal's operator)
/// Has signed the response intent; without this, any caller could
/// Self-report the operator address and answer a challenge on their
/// Behalf, bypassing the `NotTheOperator` registry check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetrievalResponse {
    pub challenge_id: u64,
    pub _range_hash: ContentId,
    pub responder: Address,
    pub response_epoch: u64,
    /// Ed25519 signature over `hash_fields_bytes(["BUD_ANSWER_CHALLENGE_V1",
    /// Challenge_id, range_hash, responder, response_epoch])`. 64 bytes.
    #[serde(default)]
    pub responder_signature: Option<Vec<u8>>,
    /// ZK proof bytes (ProofEnvelope) certifying the correct challenge answer
    #[serde(default)]
    pub proof_bytes: Option<Vec<u8>>,
}

/// The outcome of a finalized challenge. `Missed` is the only path that
/// Can transition a deal to `Slashed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeOutcome {
    /// Operator answered on time with a hash that matches the requested
    /// Sub-range. Opener bond returned, deal stays `Active`.
    Answered,
    /// Operator answered on time but the hash was wrong. Opener bond
    /// Returned (correct call), operator bond slashed.
    Mismatched,
    /// Deadline elapsed without a response. Operator bond slashed.
    Missed,
}

/// A finalized challenge with its outcome and the slash amount (if any)
/// To make the economic accounting auditable. `slashed_bond` is a *record*
/// The actual burn is performed by the `Blockchain` accounting path
///, never silently in this layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeResult {
    pub challenge_id: u64,
    pub deal_id: u64,
    pub outcome: ChallengeOutcome,
    pub finalized_epoch: u64,
    /// Total bond burned if any. 0 for `Answered`.
    pub slashed_bond: u64,
}

/// Fixed devnet/testnet replication target selected for Tur 14.5 hardening.
/// A missed challenge creates a reallocation ticket for the failed replica slot
/// So independent nodes can observe and repair under-replication without an
/// Off-chain team-operated scheduler. Mainnet storage remains fail-closed until
/// This policy is externally audited and economically approved.
pub const STORAGE_REPLICATION_TARGET: u8 = 3;
pub const REALLOCATION_ACCEPTANCE_EPOCHS: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReallocationStatus {
    Pending,
    ActiveReplacement,
    UnderReplicated,
    EscalatedFault,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageReallocationTicket {
    pub ticket_id: u64,
    pub failed_deal_id: u64,
    pub replacement_deal_id: Option<u64>,
    pub domain_id: u32,
    pub manifest_id: ContentId,
    pub shard_id: ContentId,
    pub replica_index: u8,
    pub slashed_operator: Address,
    pub opened_epoch: u64,
    pub deadline_epoch: u64,
    pub status: ReallocationStatus,
}

/// On-chain, in-memory registry of all `StorageDeal`s, `RetrievalChallenge`s,
/// And `ChallengeResult`s for a single storage domain. Backed by
/// `BTreeMap` (the same primitive `permissionless::PermissionlessRegistry`
/// Uses) so the registry is deterministic, cloneable, and
/// `bincode`-serializable for sled storage (vision §8.4 atomic
/// Persistence).
///
/// **No admin hook**, no `pause_all`, no `freeze`, no team-only method
/// (data-sovereignty rule). All state transitions are either
/// Permissionless (anyone can open a deal / challenge) or are computed
/// From the on-chain data (epoch deadline elapses → `Missed`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageRegistry {
    /// Next `deal_id` to assign.
    next_deal_id: u64,
    /// Next `challenge_id` to assign.
    next_challenge_id: u64,
    /// Next reallocation ticket id.
    #[serde(default)]
    next_reallocation_id: u64,
    deals: BTreeMap<u64, StorageDeal>,
    /// Index by `(manifest_id, shard_id)` for `bud_storageGetDealsByShard`
    /// And `bud_storageGetDealsByManifest`. `(deal_id)` is the value
    /// So the index is deterministic and small.
    deals_by_shard: BTreeMap<(ContentId, ContentId), Vec<u64>>,
    challenges: BTreeMap<u64, RetrievalChallenge>,
    results: BTreeMap<u64, ChallengeResult>,
    #[serde(default)]
    reallocations: BTreeMap<u64, StorageReallocationTicket>,
    #[serde(default)]
    pub manifests: BTreeMap<ContentId, ContentManifest>,
}

use std::collections::BTreeMap;

/// Errors emitted by the registry. Enum-tagged for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Caller asked to open a deal for a shard that does not exist in the
    /// Referenced manifest. (We can't know this without the manifest; we
    /// Pass the manifest in for validation.)
    UnknownShard {
        manifest_id: ContentId,
        shard_id: ContentId,
    },
    /// Deal end epoch must be strictly after start epoch.
    InvalidEpochRange {
        start: u64,
        end: u64,
    },
    /// Operator bond is below the per-domain minimum.
    InsufficientBond {
        required: u64,
        provided: u64,
    },
    /// Opener bond is 0 (would let anyone spam challenges for free).
    ZeroOpenerBond,
    /// Opener bond does not cover the I/O the operator must spend to answer.
    ///
    /// The bond is refunded when the operator answers correctly, so an
    /// attacker who only wants to burn the operator's disk bandwidth pays
    /// nothing. Requiring the bond to scale with the challenged range makes
    /// the griefer's capital scale with the damage, even though it is
    /// eventually returned.
    OpenerBondBelowRangeCost {
        range_len: u64,
        required: u64,
        provided: u64,
    },
    /// Caller referenced a deal that does not exist.
    UnknownDeal(u64),
    /// Caller referenced a challenge that does not exist.
    UnknownChallenge(u64),
    /// Caller referenced a deal that is not `Active` (e.g. tried to
    /// Answer a challenge on a `Slashed` deal).
    DealNotActive(u64),
    /// Caller tried to answer a challenge with the wrong operator
    /// Address (anyone can open; only the deal's operator can answer).
    NotTheOperator {
        expected: Address,
        provided: Address,
    },
    /// Challenge deadline has already passed at response time.
    DeadlineElapsed {
        deadline_epoch: u64,
        now_epoch: u64,
    },
    /// Challenge has already been answered / finalized.
    ChallengeAlreadyResolved(u64),
    /// Manifest with the given `manifest_id` is not registered in the
    /// Storage domain.
    UnknownManifest(ContentId),
    /// B.U.D.: merkle_proof and storage_root are mandatory
    /// Now that VerifyMerkle production gate is open.
    MerkleProofRequired,
    /// B.U.D.: the provided merkle proof failed format validation
    /// Or STARK verification. The proof must be a valid ProofEnvelope.
    InvalidMerkleProof(String),
    /// Too many concurrent open challenges for a single deal.
    TooManyOpenChallenges {
        deal_id: u64,
        max: usize,
    },
    /// A recently challenged operator/manifest pair cannot be challenged again
    /// Until the canonical epoch shown here. This prevents cheap repeated
    /// Retrieval probes that let an operator retain only the last requested
    /// Range.
    ChallengeRateLimited {
        operator: Address,
        manifest_id: ContentId,
        minimum_next_epoch: u64,
    },
    UnknownReallocationTicket(u64),
    ReallocationNotPending(u64),
    ReplacementOperatorMatchesSlashed(Address),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::UnknownShard {
                manifest_id,
                shard_id,
            } => write!(f, "shard {} not in manifest {}", shard_id, manifest_id),
            StorageError::InvalidEpochRange { start, end } => {
                write!(f, "deal epoch range {start}..{end} invalid")
            }
            StorageError::InsufficientBond { required, provided } => {
                write!(f, "operator bond {provided} below required {required}")
            }
            StorageError::ZeroOpenerBond => write!(f, "opener_bond must be > 0"),
            StorageError::OpenerBondBelowRangeCost {
                range_len,
                required,
                provided,
            } => write!(
                f,
                "opener_bond {provided} below {required} required for a \
                 {range_len}-byte challenge range"
            ),
            StorageError::UnknownDeal(id) => write!(f, "unknown deal {id}"),
            StorageError::UnknownChallenge(id) => write!(f, "unknown challenge {id}"),
            StorageError::DealNotActive(id) => write!(f, "deal {id} is not Active"),
            StorageError::NotTheOperator { expected, provided } => {
                write!(
                    f,
                    "response signed by {provided} but deal operator is {expected}"
                )
            }
            StorageError::DeadlineElapsed {
                deadline_epoch,
                now_epoch,
            } => write!(
                f,
                "challenge deadline {deadline_epoch} elapsed at epoch {now_epoch}"
            ),
            StorageError::ChallengeAlreadyResolved(id) => {
                write!(f, "challenge {id} already resolved")
            }
            StorageError::UnknownManifest(id) => write!(f, "unknown manifest {id}"),
            StorageError::MerkleProofRequired => write!(
                f,
                "merkle_proof and storage_root are mandatory (VerifyMerkle gate open)"
            ),
            StorageError::InvalidMerkleProof(ref reason) => {
                write!(f, "invalid merkle proof — {reason}")
            }
            StorageError::TooManyOpenChallenges { deal_id, max } => {
                write!(f, "too many open challenges for deal {deal_id} (max {max})")
            }
            StorageError::ChallengeRateLimited {
                operator,
                manifest_id,
                minimum_next_epoch,
            } => write!(
                f,
                "operator {operator} was recently challenged for manifest {manifest_id}; retry at epoch {minimum_next_epoch}"
            ),
            StorageError::UnknownReallocationTicket(id) => {
                write!(f, "unknown storage reallocation ticket {id}")
            }
            StorageError::ReallocationNotPending(id) => {
                write!(f, "storage reallocation ticket {id} is not pending")
            }
            StorageError::ReplacementOperatorMatchesSlashed(operator) => write!(
                f,
                "replacement operator {operator} matches the slashed operator"
            ),
        }
    }
}

impl std::error::Error for StorageError {}

impl StorageRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.next_deal_id == 0
            && self.next_challenge_id == 0
            && self.next_reallocation_id == 0
            && self.deals.is_empty()
            && self.deals_by_shard.is_empty()
            && self.challenges.is_empty()
            && self.results.is_empty()
            && self.reallocations.is_empty()
            && self.manifests.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_STORAGE_REGISTRY_V1");
        hasher.update(self.next_deal_id.to_le_bytes());
        hasher.update(self.next_challenge_id.to_le_bytes());
        hasher.update(self.next_reallocation_id.to_le_bytes());
        for deal in self.deals.values() {
            hasher.update(
                bincode::serialize(deal)
                    .expect("StorageDeal must serialize for storage registry root"),
            );
        }
        for ((manifest_id, shard_id), deal_ids) in &self.deals_by_shard {
            hasher.update(manifest_id.0);
            hasher.update(shard_id.0);
            for deal_id in deal_ids {
                hasher.update(deal_id.to_le_bytes());
            }
        }
        for challenge in self.challenges.values() {
            hasher.update(
                bincode::serialize(challenge)
                    .expect("RetrievalChallenge must serialize for storage registry root"),
            );
        }
        for result in self.results.values() {
            hasher.update(
                bincode::serialize(result)
                    .expect("ChallengeResult must serialize for storage registry root"),
            );
        }
        for ticket in self.reallocations.values() {
            hasher.update(
                bincode::serialize(ticket)
                    .expect("StorageReallocationTicket must serialize for storage registry root"),
            );
        }
        for manifest in self.manifests.values() {
            hasher.update(
                bincode::serialize(manifest)
                    .expect("ContentManifest must serialize for storage registry root"),
            );
        }
        hasher.finalize().into()
    }

    /// Register a manifest so subsequent deal-opens can validate
    /// `(manifest_id, shard_id)` membership. Idempotent — re-registering
    /// The same `manifest_id` is a no-op (per the chain-only rule: the
    /// Canonical manifest lives in `ContentManifest`; this index only
    /// Tracks "is this manifest known to the storage domain?").
    pub fn register_manifest(&mut self, manifest: &ContentManifest) {
        self.manifests
            .entry(manifest.manifest_id)
            .or_insert_with(|| manifest.clone());
    }

    pub fn get_manifest(&self, manifest_id: &ContentId) -> Option<&ContentManifest> {
        self.manifests.get(manifest_id)
    }

    /// Validate that `shard_id` is a member of `manifest`. Used by
    /// `open_deal`; exposed so the E2E test can exercise the failure
    /// Path.
    pub fn validate_shard_membership(
        &self,
        manifest: &ContentManifest,
        shard_id: &ContentId,
    ) -> Result<(), StorageError> {
        if manifest.shard(shard_id).is_some() {
            Ok(())
        } else {
            Err(StorageError::UnknownShard {
                manifest_id: manifest.manifest_id,
                shard_id: *shard_id,
            })
        }
    }

    /// Open a new `StorageDeal`. The caller supplies the
    /// `ContentManifest` so we can validate shard membership on-chain
    /// (no off-chain indexer dependency).
    #[allow(clippy::too_many_arguments)]
    pub fn open_deal(
        &mut self,
        domain_id: u32,
        manifest: &ContentManifest,
        shard_id: ContentId,
        operator: Address,
        replica_index: u8,
        start_epoch: u64,
        end_epoch: u64,
        economics: StorageEconomicsParams,
        domain_params: &StorageDomainParams,
        // === B.U.D.: Merkle Proof ===
        // Optional (interim); required once VerifyMerkle gate opens.
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<Hash32>,
    ) -> Result<u64, StorageError> {
        // === B.U.D.: Merkle envelope MANDATORY + VALIDATE ===
        // Mainnet Proof-of-Storage claims remain fail-closed until the
        // 64-depth VerifyMerkle soundness gate is complete. The devnet gate
        // Still requires a proof envelope plus storage_root so later full
        // Verification has a transaction-bound witness to consume.
        let proof_bytes = merkle_proof
            .as_ref()
            .ok_or(StorageError::MerkleProofRequired)?;
        let root = storage_root.ok_or(StorageError::MerkleProofRequired)?;

        // Validate proof format: must deserialize as a valid ProofEnvelope.
        // Full STARK verification deferred to nodes with prover capability;
        // The chain validates structural integrity at deal-open time.
        Self::validate_merkle_proof_format(proof_bytes, &root)?;
        if start_epoch >= end_epoch {
            return Err(StorageError::InvalidEpochRange {
                start: start_epoch,
                end: end_epoch,
            });
        }
        if (economics.operator_bond as u128) < (domain_params.min_operator_bond as u128) {
            return Err(StorageError::InsufficientBond {
                required: domain_params.min_operator_bond,
                provided: economics.operator_bond,
            });
        }
        self.validate_shard_membership(manifest, &shard_id)?;
        self.register_manifest(manifest);

        let deal_id = self.next_deal_id;
        self.next_deal_id += 1;

        let deal = StorageDeal {
            deal_id,
            domain_id,
            manifest_id: manifest.manifest_id,
            shard_id,
            operator,
            economics,
            replica_index,
            deal_start_epoch: start_epoch,
            deal_end_epoch: end_epoch,
            status: DealStatus::Active,
            merkle_proof,
            storage_root,
            merkle_depth: 64,
        };

        self.deals.insert(deal_id, deal);
        self.deals_by_shard
            .entry((manifest.manifest_id, shard_id))
            .or_default()
            .push(deal_id);
        Ok(deal_id)
    }

    /// Open a retrieval challenge. Anyone can call this (no role
    /// Required) — the opener_bond is the anti-spam mechanism.
    #[allow(clippy::too_many_arguments)]
    /// Maximum concurrent open challenges per deal.
    /// Prevents spam attacks where a single deal gets unlimited challenges,
    /// Growing the StorageRegistry's challenge BTreeMap without bound.
    const MAX_OPEN_CHALLENGES_PER_DEAL: usize = 10;

    /// Opener bond charged per KiB of the challenged byte range.
    ///
    /// A challenge costs the operator a read plus a hash over the range. On
    /// commodity NVMe that is roughly 20 ms for the 16 MiB maximum chunk and
    /// 0.3 ms for the 256 KiB default — small individually, but the rate limit
    /// is keyed on `(operator, manifest)`, so an operator serving 1000
    /// manifests can be made to spend seconds of I/O per epoch by an attacker
    /// who pays nothing: the bond is refunded whenever the operator answers.
    ///
    /// Tying the bond to the range does not make griefing expensive in the
    /// long run — the capital comes back — but it makes it *capital-bound*:
    /// sustaining the attack requires locking stake proportional to the
    /// damage, in parallel, for the whole challenge window.
    pub const OPENER_BOND_PER_KIB: u64 = 1;

    /// Floor applied on top of `OPENER_BOND_PER_KIB` so sub-KiB ranges are
    /// not free.
    pub const MIN_OPENER_BOND: u64 = 1;

    /// Bond required to challenge `range_len` bytes.
    ///
    /// Rounds the range up to whole KiB so a 1-byte challenge costs the same
    /// as a 1 KiB one; the operator's seek dominates at that size anyway.
    pub fn required_opener_bond(range_len: u64) -> u64 {
        let kib = range_len.div_ceil(1024);
        Self::MIN_OPENER_BOND.max(kib.saturating_mul(Self::OPENER_BOND_PER_KIB))
    }
    /// Devnet hardening policy selected for Tur 14.5: a given operator and
    /// Manifest can receive at most one retrieval challenge every four
    /// Canonical epochs, including challenges opened through distinct deals.
    pub(crate) const MIN_OPERATOR_MANIFEST_CHALLENGE_EPOCHS: u64 = 4;

    pub fn open_challenge_with_entropy(
        &mut self,
        request: &RetrievalChallengeRequest,
        opener: Address,
        challenge_entropy: &Hash32,
    ) -> Result<u64, StorageError> {
        if request.byte_start >= request.byte_end {
            return Err(StorageError::InvalidEpochRange {
                start: request.byte_start,
                end: request.byte_end,
            });
        }
        let requested_len = request.byte_end - request.byte_start;
        let deal = self
            .deals
            .get(&request.deal_id)
            .ok_or(StorageError::UnknownDeal(request.deal_id))?;
        let manifest = self
            .manifests
            .get(&deal.manifest_id)
            .ok_or(StorageError::UnknownManifest(deal.manifest_id))?;
        let (byte_start, byte_end) = Self::derive_challenge_range(StorageChallengeRangeInput {
            entropy: challenge_entropy,
            deal,
            manifest,
            opener,
            challenge_epoch: request.challenge_epoch,
            deadline_epoch: request.deadline_epoch,
            requested_len,
            challenge_id: self.next_challenge_id,
        })?;
        self.open_challenge(
            request.deal_id,
            byte_start,
            byte_end,
            request.challenge_epoch,
            request.deadline_epoch,
            opener,
            request.opener_bond,
        )
    }

    pub fn derive_challenge_range(
        input: StorageChallengeRangeInput<'_>,
    ) -> Result<(u64, u64), StorageError> {
        if input.requested_len == 0 {
            return Err(StorageError::InvalidEpochRange { start: 0, end: 0 });
        }
        let shard =
            input
                .manifest
                .shard(&input.deal.shard_id)
                .ok_or(StorageError::UnknownShard {
                    manifest_id: input.manifest.manifest_id,
                    shard_id: input.deal.shard_id,
                })?;
        let shard_size = u64::from(shard.size);
        let range_len = input.requested_len.min(shard_size);
        let range_count = shard_size
            .checked_sub(range_len)
            .and_then(|last_start| last_start.checked_add(1))
            .ok_or(StorageError::InvalidEpochRange {
                start: 0,
                end: shard_size,
            })?;
        let digest = hash_fields_bytes(&[
            b"BDLM_STORAGE_RANDOM_CHALLENGE_RANGE_V1",
            input.entropy,
            &input.deal.deal_id.to_le_bytes(),
            &input.deal.domain_id.to_le_bytes(),
            input.deal.manifest_id.as_bytes(),
            input.deal.shard_id.as_bytes(),
            &[input.deal.replica_index],
            input.deal.operator.as_bytes(),
            input.opener.as_bytes(),
            &input.challenge_epoch.to_le_bytes(),
            &input.deadline_epoch.to_le_bytes(),
            &input.requested_len.to_le_bytes(),
            &input.challenge_id.to_le_bytes(),
        ]);
        let offset = u64::from_le_bytes(
            digest[..8]
                .try_into()
                .expect("32-byte challenge digest has an 8-byte prefix"),
        ) % range_count;
        Ok((offset, offset + range_len))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_challenge(
        &mut self,
        deal_id: u64,
        byte_start: u64,
        byte_end: u64,
        challenge_epoch: u64,
        deadline_epoch: u64,
        opener: Address,
        opener_bond: u64,
    ) -> Result<u64, StorageError> {
        if opener_bond == 0 {
            return Err(StorageError::ZeroOpenerBond);
        }
        if byte_start >= byte_end {
            return Err(StorageError::InvalidEpochRange {
                start: byte_start,
                end: byte_end,
            });
        }
        // The bond must scale with the work the operator is being asked to do.
        // Without this a 1-unit bond buys a 16 MiB read-and-hash, and the bond
        // comes back when the operator answers.
        let range_len = byte_end - byte_start;
        let required = Self::required_opener_bond(range_len);
        if opener_bond < required {
            return Err(StorageError::OpenerBondBelowRangeCost {
                range_len,
                required,
                provided: opener_bond,
            });
        }
        if challenge_epoch >= deadline_epoch {
            return Err(StorageError::InvalidEpochRange {
                start: challenge_epoch,
                end: deadline_epoch,
            });
        }
        let deal = self
            .deals
            .get(&deal_id)
            .ok_or(StorageError::UnknownDeal(deal_id))?;
        if !deal.is_active() {
            return Err(StorageError::DealNotActive(deal_id));
        }

        let operator = deal.operator;
        let manifest_id = deal.manifest_id;
        let shard_id = deal.shard_id;
        let minimum_next_epoch = self
            .challenges
            .values()
            .filter_map(|challenge| {
                let challenged_deal = self.deals.get(&challenge.deal_id)?;
                (challenged_deal.operator == operator && challenged_deal.manifest_id == manifest_id)
                    .then_some(
                        challenge
                            .challenge_epoch
                            .saturating_add(Self::MIN_OPERATOR_MANIFEST_CHALLENGE_EPOCHS),
                    )
            })
            .max();
        if let Some(minimum_next_epoch) = minimum_next_epoch {
            if challenge_epoch < minimum_next_epoch {
                return Err(StorageError::ChallengeRateLimited {
                    operator,
                    manifest_id,
                    minimum_next_epoch,
                });
            }
        }

        // Limit concurrent open challenges per deal.
        // Count challenges for this deal that haven't been resolved yet.
        let open_count = self
            .challenges
            .values()
            .filter(|c| c.deal_id == deal_id && !self.results.contains_key(&c.challenge_id))
            .count();
        if open_count >= Self::MAX_OPEN_CHALLENGES_PER_DEAL {
            return Err(StorageError::TooManyOpenChallenges {
                deal_id,
                max: Self::MAX_OPEN_CHALLENGES_PER_DEAL,
            });
        }

        let challenge_id = self.next_challenge_id;
        self.next_challenge_id += 1;
        let challenge = RetrievalChallenge {
            challenge_id,
            deal_id,
            shard_id,
            byte_start,
            byte_end,
            challenge_epoch,
            deadline_epoch,
            opener,
            opener_bond,
        };
        self.challenges.insert(challenge_id, challenge);
        Ok(challenge_id)
    }

    /// Operator answers a challenge. `range_hash` MUST equal
    /// `ContentId::of_subrange(shard_bytes, byte_start, byte_end)`. The
    /// Bytes themselves are not on-chain; the chain records only the
    /// Hash and trusts off-chain verifiers to confirm it. This is
    /// The documented interim-challenge limitation.
    ///
    /// Range_hash must be non-zero (empty hash = invalid response).
    /// Full hash verification deferred to ZK proof integration.
    pub fn answer_challenge(
        &mut self,
        challenge_id: u64,
        range_hash: ContentId,
        responder: Address,
        response_epoch: u64,
        proof_bytes: Option<&[u8]>,
    ) -> Result<ChallengeResult, StorageError> {
        self.answer_challenge_with_chain_id(
            crate::core::transaction::DEFAULT_CHAIN_ID,
            challenge_id,
            range_hash,
            responder,
            response_epoch,
            proof_bytes,
        )
    }

    pub fn answer_challenge_with_chain_id(
        &mut self,
        chain_id: u64,
        challenge_id: u64,
        range_hash: ContentId,
        responder: Address,
        response_epoch: u64,
        proof_bytes: Option<&[u8]>,
    ) -> Result<ChallengeResult, StorageError> {
        // Reject empty/zero range_hash — operator must provide a real hash
        if range_hash == ContentId([0u8; 32]) {
            return Err(StorageError::InvalidMerkleProof(
                "range_hash must be non-zero (empty hash rejected)".into(),
            ));
        }

        if self.results.contains_key(&challenge_id) {
            return Err(StorageError::ChallengeAlreadyResolved(challenge_id));
        }
        let challenge = self
            .challenges
            .get(&challenge_id)
            .ok_or(StorageError::UnknownChallenge(challenge_id))?;
        let deal = self
            .deals
            .get(&challenge.deal_id)
            .ok_or(StorageError::UnknownDeal(challenge.deal_id))?;
        if !deal.is_active() {
            return Err(StorageError::DealNotActive(deal.deal_id));
        }
        if responder != deal.operator {
            return Err(StorageError::NotTheOperator {
                expected: deal.operator,
                provided: responder,
            });
        }
        if response_epoch > challenge.deadline_epoch {
            return Err(StorageError::DeadlineElapsed {
                deadline_epoch: challenge.deadline_epoch,
                now_epoch: response_epoch,
            });
        }

        // === B.U.D.: full STARK proof verification ===
        if let Some(root) = deal.storage_root {
            if let Some(proof) = proof_bytes {
                let context = StorageChallengeProofContext::from_registry(
                    chain_id,
                    challenge,
                    deal,
                    responder,
                    response_epoch,
                );
                Self::verify_answer_challenge_zk_proof_for_chain(
                    &context,
                    &root,
                    &range_hash,
                    proof,
                )?;
            } else {
                return Err(StorageError::InvalidMerkleProof(
                    "ZK proof (ProofEnvelope) is mandatory for storage challenge verification"
                        .into(),
                ));
            }
        }

        let result = ChallengeResult {
            challenge_id,
            deal_id: deal.deal_id,
            outcome: ChallengeOutcome::Answered,
            finalized_epoch: response_epoch,
            slashed_bond: 0,
        };
        self.results.insert(challenge_id, result.clone());
        Ok(result)
    }

    /// Context-free verification is intentionally disabled. A Merkle proof that
    /// Is not bound to its deal/challenge/response context is replayable across
    /// Storage deals and networks. Callers must use `answer_challenge`, which
    /// Reconstructs the complete canonical context from registry state.
    pub fn verify_answer_challenge_zk_proof(
        _storage_root: &Hash32,
        _range_hash: &ContentId,
        _proof_bytes: &[u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::InvalidMerkleProof(
            "context-free storage challenge verification is disabled".into(),
        ))
    }

    fn verify_answer_challenge_zk_proof_for_chain(
        context: &StorageChallengeProofContext,
        storage_root: &Hash32,
        range_hash: &ContentId,
        proof_bytes: &[u8],
    ) -> Result<(), StorageError> {
        // For testing/mocking to keep tests fast:
        if cfg!(test) && proof_bytes == b"test-mock-proof" {
            return Ok(());
        }

        let envelope =
            bincode::deserialize::<bud_proof::ProofEnvelope>(proof_bytes).map_err(|e| {
                StorageError::InvalidMerkleProof(format!(
                    "failed to deserialize ProofEnvelope: {e}"
                ))
            })?;

        let (program, expected_inputs) =
            Self::storage_challenge_expected_program_and_inputs(context, storage_root, range_hash);

        bud_proof::DefaultAdapter::verify(&envelope, &expected_inputs, &program).map_err(|e| {
            StorageError::InvalidMerkleProof(format!("STARK proof verification failed: {e:?}"))
        })?;

        Ok(())
    }

    fn storage_challenge_expected_program_and_inputs(
        context: &StorageChallengeProofContext,
        storage_root: &Hash32,
        range_hash: &ContentId,
    ) -> (Vec<u64>, bud_proof::ExecutionPublicInputs) {
        use bud_isa::{Instruction, Opcode};
        use sha3::{Digest, Keccak256};

        let program = vec![
            Instruction {
                opcode: Opcode::VerifyMerkle,
                rd: 1,
                rs1: 2,
                rs2: 3,
                imm: 256,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        ];

        let mut program_bytes = Vec::with_capacity(program.len() * std::mem::size_of::<u64>());
        for &inst in &program {
            program_bytes.extend_from_slice(&inst.to_le_bytes());
        }
        let mut program_hasher = Keccak256::new();
        program_hasher.update(&program_bytes);
        let program_hash: [u8; 32] = program_hasher.finalize().into();

        // Bind every replay-relevant registry field. Roots alone are not enough:
        // The same shard proof must not answer another deal, replica, range,
        // Challenge, deadline, responder, epoch, domain, or L1 network.
        let context_digest = context.digest(storage_root, range_hash);

        let mut sender_bytes = [0u8; 8];
        sender_bytes.copy_from_slice(&context.responder.as_bytes()[..8]);
        let expected_inputs = bud_proof::ExecutionPublicInputs {
            chain_id: context.chain_id,
            program_hash,
            initial_state_root: *storage_root,
            final_state_root: range_hash.0,
            sender: u64::from_le_bytes(sender_bytes),
            nonce: context.challenge_id,
            block_height: context.response_epoch,
            gas_limit: 1_000_000,
            gas_used: 0,
            exit_code: 0,
            trace_len: 66,
            event_digest: context_digest,
        };

        (program, expected_inputs)
    }

    /// Finalize a challenge whose deadline has elapsed without a
    /// Response. The deal transitions to `Slashed` and the operator
    /// Bond is *recorded* as slashed (not burned — burning is a
    /// Higher-layer `Blockchain` accounting decision).
    pub fn finalize_missed_challenge(
        &mut self,
        challenge_id: u64,
        now_epoch: u64,
    ) -> Result<ChallengeResult, StorageError> {
        if self.results.contains_key(&challenge_id) {
            return Err(StorageError::ChallengeAlreadyResolved(challenge_id));
        }
        let challenge = self
            .challenges
            .get(&challenge_id)
            .ok_or(StorageError::UnknownChallenge(challenge_id))?;
        if now_epoch <= challenge.deadline_epoch {
            return Err(StorageError::InvalidEpochRange {
                start: now_epoch,
                end: challenge.deadline_epoch,
            });
        }
        let deal_id = challenge.deal_id;
        let (slash_amount, ticket) = {
            let deal = self
                .deals
                .get_mut(&deal_id)
                .ok_or(StorageError::UnknownDeal(deal_id))?;
            let slash_amount = deal.economics.operator_bond;
            deal.status = DealStatus::Slashed;
            let existing_ticket = self
                .reallocations
                .values()
                .any(|ticket| ticket.failed_deal_id == deal_id);
            let ticket = (!existing_ticket).then(|| {
                let ticket_id = self.next_reallocation_id;
                self.next_reallocation_id = self.next_reallocation_id.saturating_add(1);
                StorageReallocationTicket {
                    ticket_id,
                    failed_deal_id: deal_id,
                    replacement_deal_id: None,
                    domain_id: deal.domain_id,
                    manifest_id: deal.manifest_id,
                    shard_id: deal.shard_id,
                    replica_index: deal.replica_index,
                    slashed_operator: deal.operator,
                    opened_epoch: now_epoch,
                    deadline_epoch: now_epoch.saturating_add(REALLOCATION_ACCEPTANCE_EPOCHS),
                    status: ReallocationStatus::Pending,
                }
            });
            (slash_amount, ticket)
        };
        if let Some(ticket) = ticket {
            self.reallocations.insert(ticket.ticket_id, ticket);
        }

        let result = ChallengeResult {
            challenge_id,
            deal_id,
            outcome: ChallengeOutcome::Missed,
            finalized_epoch: now_epoch,
            slashed_bond: slash_amount,
        };
        self.results.insert(challenge_id, result.clone());
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_reallocation_ticket(
        &mut self,
        ticket_id: u64,
        replacement_operator: Address,
        start_epoch: u64,
        end_epoch: u64,
        economics: StorageEconomicsParams,
        domain_params: &StorageDomainParams,
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<Hash32>,
    ) -> Result<u64, StorageError> {
        let ticket = self
            .reallocations
            .get(&ticket_id)
            .cloned()
            .ok_or(StorageError::UnknownReallocationTicket(ticket_id))?;
        if !matches!(
            ticket.status,
            ReallocationStatus::Pending | ReallocationStatus::UnderReplicated
        ) {
            return Err(StorageError::ReallocationNotPending(ticket_id));
        }
        if replacement_operator == ticket.slashed_operator {
            return Err(StorageError::ReplacementOperatorMatchesSlashed(
                replacement_operator,
            ));
        }
        let manifest = self
            .manifests
            .get(&ticket.manifest_id)
            .cloned()
            .ok_or(StorageError::UnknownManifest(ticket.manifest_id))?;
        let replacement_deal_id = self.open_deal(
            ticket.domain_id,
            &manifest,
            ticket.shard_id,
            replacement_operator,
            ticket.replica_index,
            start_epoch,
            end_epoch,
            economics,
            domain_params,
            merkle_proof,
            storage_root,
        )?;
        if let Some(ticket) = self.reallocations.get_mut(&ticket_id) {
            ticket.status = ReallocationStatus::ActiveReplacement;
            ticket.replacement_deal_id = Some(replacement_deal_id);
        }
        Ok(replacement_deal_id)
    }

    pub fn mark_overdue_reallocations_under_replicated(&mut self, now_epoch: u64) -> usize {
        let mut changed = 0;
        for ticket in self.reallocations.values_mut() {
            if ticket.status == ReallocationStatus::Pending && now_epoch > ticket.deadline_epoch {
                ticket.status = ReallocationStatus::UnderReplicated;
                changed += 1;
            }
        }
        changed
    }

    pub fn all_reallocation_tickets(&self) -> Vec<&StorageReallocationTicket> {
        self.reallocations.values().collect()
    }

    pub fn get_reallocation_ticket(&self, ticket_id: u64) -> Option<&StorageReallocationTicket> {
        self.reallocations.get(&ticket_id)
    }

    /// Expire a deal that reached its `deal_end_epoch` without
    /// Being slashed.
    /// Expire a deal that reached its `deal_end_epoch` without
    /// Being slashed. Returns the operator bond amount to be refunded
    /// By the blockchain accounting layer.
    pub fn expire_deal(&mut self, deal_id: u64, now_epoch: u64) -> Result<u64, StorageError> {
        let deal = self
            .deals
            .get_mut(&deal_id)
            .ok_or(StorageError::UnknownDeal(deal_id))?;
        if now_epoch < deal.deal_end_epoch {
            return Err(StorageError::InvalidEpochRange {
                start: now_epoch,
                end: deal.deal_end_epoch,
            });
        }
        if deal.status == DealStatus::Active {
            let bond = deal.economics.operator_bond;
            deal.status = DealStatus::Expired;
            Ok(bond)
        } else {
            Ok(0)
        }
    }

    /// B.U.D.: validate merkle proof format.
    /// Checks that proof_bytes deserializes to a valid ProofEnvelope.
    /// Full STARK verification (Plonky3Adapter::verify) is deferred to
    /// Nodes with the bud-proof crate and prover capability.
    pub fn validate_merkle_proof_format(
        proof_bytes: &[u8],
        storage_root: &Hash32,
    ) -> Result<(), StorageError> {
        // Format validation: proof must be non-empty and at least
        // Contain a minimal ProofEnvelope header (version + backend + proof_bytes).
        if proof_bytes.len() < 64 {
            return Err(StorageError::InvalidMerkleProof(
                "proof too short (< 64 bytes)".into(),
            ));
        }
        // Try deserializing as ProofEnvelope via bincode.
        // The ProofEnvelope has: proof_format_version(u32), backend(String),
        // P3_version(String), fri_params_id(String), public_inputs_hash([u8;32]),
        // proof_bytes(Vec<u8>), degree_bits(u32).
        match bincode::deserialize::<bud_proof::ProofEnvelope>(proof_bytes) {
            Ok(envelope) => {
                // Minimal sanity: proof_bytes inside envelope must not be empty.
                if envelope.proof_bytes.is_empty() {
                    return Err(StorageError::InvalidMerkleProof(
                        "ProofEnvelope.proof_bytes is empty".into(),
                    ));
                }
                // Log the proof acceptance (storage_root validated off-chain).
                let _ = storage_root;
                Ok(())
            }
            Err(e) => Err(StorageError::InvalidMerkleProof(format!(
                "failed to deserialize ProofEnvelope: {e}"
            ))),
        }
    }

    // ---- Queries (all read-only, no state change) --------------------

    pub fn get_deal(&self, deal_id: u64) -> Option<&StorageDeal> {
        self.deals.get(&deal_id)
    }

    pub fn get_challenge(&self, challenge_id: u64) -> Option<&RetrievalChallenge> {
        self.challenges.get(&challenge_id)
    }

    pub fn get_result(&self, challenge_id: u64) -> Option<&ChallengeResult> {
        self.results.get(&challenge_id)
    }

    /// Read-only projection into the spec lifecycle state machine.
    ///
    /// This does not mutate existing deal/challenge accounting. It lets RPC,
    /// Tests, and later pruning/archive logic reason about the richer lifecycle
    /// Vocabulary without changing the currently stable `DealStatus` storage
    /// Format in one step.
    pub fn lifecycle_state(&self, deal_id: u64) -> Option<crate::storage::StorageLifecycleState> {
        let deal = self.deals.get(&deal_id)?;
        match deal.status {
            DealStatus::Slashed => {
                let ticket = self
                    .reallocations
                    .values()
                    .find(|ticket| ticket.failed_deal_id == deal_id);
                match ticket.map(|ticket| ticket.status) {
                    Some(ReallocationStatus::Pending) => {
                        Some(crate::storage::StorageLifecycleState::ReallocationPending)
                    }
                    Some(ReallocationStatus::UnderReplicated) => {
                        Some(crate::storage::StorageLifecycleState::UnderReplicated)
                    }
                    Some(ReallocationStatus::EscalatedFault) => {
                        Some(crate::storage::StorageLifecycleState::EscalatedFault)
                    }
                    _ => Some(crate::storage::StorageLifecycleState::Slashed),
                }
            }
            DealStatus::Expired => Some(crate::storage::StorageLifecycleState::Expired),
            DealStatus::Active => {
                let is_active_replacement = self.reallocations.values().any(|ticket| {
                    ticket.replacement_deal_id == Some(deal_id)
                        && ticket.status == ReallocationStatus::ActiveReplacement
                });
                if is_active_replacement {
                    return Some(crate::storage::StorageLifecycleState::ActiveReplacement);
                }
                let has_open_challenge = self
                    .challenges
                    .values()
                    .any(|c| c.deal_id == deal_id && !self.results.contains_key(&c.challenge_id));
                if has_open_challenge {
                    Some(crate::storage::StorageLifecycleState::Challenged)
                } else if deal.merkle_proof.is_some() || deal.storage_root.is_some() {
                    Some(crate::storage::StorageLifecycleState::Proving)
                } else {
                    Some(crate::storage::StorageLifecycleState::Open)
                }
            }
        }
    }

    pub fn deals_for_shard(
        &self,
        manifest_id: &ContentId,
        shard_id: &ContentId,
    ) -> Vec<&StorageDeal> {
        self.deals_by_shard
            .get(&(*manifest_id, *shard_id))
            .map(|ids| ids.iter().filter_map(|id| self.deals.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn deals_for_manifest(&self, manifest_id: &ContentId) -> Vec<&StorageDeal> {
        self.deals
            .values()
            .filter(|d| &d.manifest_id == manifest_id)
            .collect()
    }

    pub fn all_deals(&self) -> Vec<&StorageDeal> {
        self.deals.values().collect()
    }

    pub fn all_challenges(&self) -> Vec<&RetrievalChallenge> {
        self.challenges.values().collect()
    }

    pub fn all_results(&self) -> Vec<&ChallengeResult> {
        self.results.values().collect()
    }

    pub fn active_replica_count(&self, manifest_id: &ContentId, shard_id: &ContentId) -> usize {
        self.deals_for_shard(manifest_id, shard_id)
            .into_iter()
            .filter(|deal| deal.is_active())
            .count()
    }

    pub fn under_replicated_shards(&self) -> Vec<(ContentId, ContentId, usize)> {
        self.deals_by_shard
            .keys()
            .filter_map(|(manifest_id, shard_id)| {
                let active = self.active_replica_count(manifest_id, shard_id);
                (active < usize::from(STORAGE_REPLICATION_TARGET)).then_some((
                    *manifest_id,
                    *shard_id,
                    active,
                ))
            })
            .collect()
    }

    /// Force-prune all storage content associated with a manifest CID.
    /// Called when an NFT is burned (Constitution §1: "NFT yakılırsa veri
    /// B.U.D. storage'dan fiziksel silinir").
    ///
    /// Expires all active deals for this manifest and removes the manifest
    /// From the registry. Deals that are already Slashed or Expired are
    /// Left as-is (audit trail).
    ///
    /// Returns the number of active deals that were expired by this prune.
    pub fn prune_content(&mut self, manifest_id: &ContentId, _now_epoch: u64) -> u64 {
        let deal_ids: Vec<u64> = self
            .deals_for_manifest(manifest_id)
            .iter()
            .filter(|d| d.is_active())
            .map(|d| d.deal_id)
            .collect();

        let pruned = deal_ids.len() as u64;
        for deal_id in deal_ids {
            if let Some(deal) = self.deals.get_mut(&deal_id) {
                deal.status = DealStatus::Expired;
            }
        }

        // Remove the manifest entry so it can no longer be referenced.
        self.manifests.remove(manifest_id);

        pruned
    }
}

/// Canonical, domain-tagged byte encoding of a `StorageDeal`. Used in
/// Audit logs and the (future) `GlobalBlockHeader.storage_root` aggregation
/// (vision §8.4).
pub fn storage_deal_leaf_hash(deal: &StorageDeal) -> Hash32 {
    hash_fields_bytes(&[
        b"BDLM_STORAGE_DEAL_V1",
        &deal.deal_id.to_le_bytes(),
        &deal.domain_id.to_le_bytes(),
        &deal.manifest_id.0,
        &deal.shard_id.0,
        deal.operator.as_bytes(),
        &deal.economics.operator_bond.to_le_bytes(),
        &deal.economics.fee_per_epoch.to_le_bytes(),
        &[deal.replica_index],
        &deal.deal_start_epoch.to_le_bytes(),
        &deal.deal_end_epoch.to_le_bytes(),
        &[match deal.status {
            DealStatus::Active => 0,
            DealStatus::Slashed => 1,
            DealStatus::Expired => 2,
        }],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::domain::storage_params::StorageDomainParams;

    fn params() -> StorageDomainParams {
        StorageDomainParams {
            chunk_size: 256,
            max_committed_chunks: 1000,
            challenge_interval: 10,
            min_operator_bond: 1_000_000,
        }
    }
    fn operator() -> Address {
        Address::from([1u8; 32])
    }
    fn opener() -> Address {
        Address::from([2u8; 32])
    }
    fn replacement_operator() -> Address {
        Address::from([3u8; 32])
    }

    fn good_manifest() -> ContentManifest {
        ContentManifest::from_bytes_sliced(b"some test content for the deal", 8).unwrap()
    }

    fn good_econ() -> StorageEconomicsParams {
        StorageEconomicsParams {
            operator_bond: 5_000_000,
            fee_per_epoch: 100,
        }
    }

    /// Format-gecerli test zarfi (durust
    /// Marker — GERCEK STARK kaniti degil; bincode-deserialize olabilen minimal
    /// ProofEnvelope). NOT: a0671c4'teki inline 78-baytlık diziler tip hatasi
    /// (E0308) veriyordu ve niyeti gizliyordu; helper geri yuklendi.
    fn valid_merkle_proof() -> Vec<u8> {
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        bincode::serialize(&envelope).expect("test envelope serialize")
    }

    fn open_one(reg: &mut StorageRegistry, m: &ContentManifest) -> (u64, ContentId) {
        let shard_id = m.shards[0].shard_id;
        let id = reg
            .open_deal(
                42,
                m,
                shard_id,
                operator(),
                0,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();
        (id, shard_id)
    }

    #[test]
    fn deal_open_rejects_unregistered_shard() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let bogus = ContentId([0xFFu8; 32]);
        let err = reg
            .open_deal(
                42,
                &m,
                bogus,
                operator(),
                0,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::UnknownShard { .. }));
    }

    #[test]
    fn deal_open_rejects_invalid_epoch_range() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let shard_id = m.shards[0].shard_id;
        let err = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                0,
                200,
                100,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidEpochRange { .. }));
    }

    #[test]
    fn deal_open_rejects_insufficient_bond() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let shard_id = m.shards[0].shard_id;
        let mut econ = good_econ();
        econ.operator_bond = 1; // way below min_operator_bond
        let err = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                0,
                100,
                200,
                econ,
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::InsufficientBond { .. }));
    }

    #[test]
    fn deal_open_assigns_unique_ids_and_indexes_by_shard() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let shard_id = m.shards[0].shard_id;
        let id1 = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                0,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();
        let id2 = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                1,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();
        assert_ne!(id1, id2);

        // Test with merkle proof (mode)
        let shard_id = m.shards[0].shard_id;
        let id3 = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                2,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]), // storage_root
            )
            .unwrap();
        assert_ne!(id2, id3);

        // Verify merkle proof is stored
        let deal3 = reg.get_deal(id3).unwrap();
        assert!(deal3.merkle_proof.is_some());
        assert!(deal3.storage_root.is_some());
        assert_eq!(deal3.merkle_depth, 64);
        assert_eq!(reg.deals_for_shard(&m.manifest_id, &shard_id).len(), 3);
        assert_eq!(reg.deals_for_manifest(&m.manifest_id).len(), 3);
    }

    #[test]
    fn challenge_open_rejects_zero_bond_and_bad_ranges() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        assert!(matches!(
            reg.open_challenge(deal_id, 0, 1, 1, 2, opener(), 0),
            Err(StorageError::ZeroOpenerBond)
        ));
        assert!(matches!(
            reg.open_challenge(deal_id, 5, 1, 1, 2, opener(), 100),
            Err(StorageError::InvalidEpochRange { .. })
        ));
        assert!(matches!(
            reg.open_challenge(deal_id, 0, 1, 5, 2, opener(), 100),
            Err(StorageError::InvalidEpochRange { .. })
        ));
    }

    #[test]
    fn challenge_open_rejects_unknown_or_inactive_deal() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        // Unknown deal:
        assert!(matches!(
            reg.open_challenge(9999, 0, 1, 1, 2, opener(), 100),
            Err(StorageError::UnknownDeal(9999))
        ));
        // Open one, then expire it, then try to challenge.
        let (deal_id, _) = open_one(&mut reg, &m);
        reg.expire_deal(deal_id, 1000).unwrap();
        assert!(matches!(
            reg.open_challenge(deal_id, 0, 1, 1, 2, opener(), 100),
            Err(StorageError::DealNotActive(_))
        ));
    }

    #[test]
    fn challenge_answered_on_time_records_answer_with_zero_slash() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let res = reg
            .answer_challenge(
                cid,
                ContentId([1u8; 32]),
                operator(),
                115,
                Some(b"test-mock-proof"),
            )
            .unwrap();
        assert_eq!(res.outcome, ChallengeOutcome::Answered);
        assert_eq!(res.slashed_bond, 0);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Active);
    }

    #[test]
    fn challenge_answer_after_deadline_rejected() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let err = reg
            .answer_challenge(cid, ContentId([1u8; 32]), operator(), 200, None)
            .unwrap_err();
        assert!(matches!(err, StorageError::DeadlineElapsed { .. }));
    }

    #[test]
    fn challenge_answer_by_non_operator_rejected() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let err = reg
            .answer_challenge(cid, ContentId([1u8; 32]), opener(), 115, None)
            .unwrap_err();
        assert!(matches!(err, StorageError::NotTheOperator { .. }));
    }

    #[test]
    fn missed_challenge_slashes_deal_and_records_bond() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let res = reg.finalize_missed_challenge(cid, 150).unwrap();
        assert_eq!(res.outcome, ChallengeOutcome::Missed);
        assert_eq!(res.slashed_bond, 5_000_000);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);
    }

    #[test]
    fn missed_challenge_creates_reallocation_ticket_and_accepts_replacement() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, shard_id) = open_one(&mut reg, &m);
        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();

        let result = reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        assert_eq!(result.outcome, ChallengeOutcome::Missed);
        assert_eq!(
            reg.lifecycle_state(deal_id),
            Some(crate::storage::StorageLifecycleState::ReallocationPending)
        );
        let ticket = reg
            .all_reallocation_tickets()
            .first()
            .copied()
            .cloned()
            .unwrap();
        assert_eq!(ticket.failed_deal_id, deal_id);
        assert_eq!(ticket.shard_id, shard_id);
        assert_eq!(ticket.replica_index, 0);
        assert_eq!(ticket.status, ReallocationStatus::Pending);

        let same_operator_err = reg
            .accept_reallocation_ticket(
                ticket.ticket_id,
                operator(),
                151,
                250,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap_err();
        assert!(matches!(
            same_operator_err,
            StorageError::ReplacementOperatorMatchesSlashed(_)
        ));

        let replacement = reg
            .accept_reallocation_ticket(
                ticket.ticket_id,
                replacement_operator(),
                151,
                250,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();
        assert_eq!(
            reg.lifecycle_state(replacement),
            Some(crate::storage::StorageLifecycleState::ActiveReplacement)
        );
        assert_eq!(
            reg.get_reallocation_ticket(ticket.ticket_id)
                .unwrap()
                .replacement_deal_id,
            Some(replacement)
        );
    }

    #[test]
    fn overdue_reallocation_marks_under_replicated() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        assert_eq!(reg.mark_overdue_reallocations_under_replicated(153), 0);
        assert_eq!(reg.mark_overdue_reallocations_under_replicated(155), 1);
        assert_eq!(
            reg.lifecycle_state(deal_id),
            Some(crate::storage::StorageLifecycleState::UnderReplicated)
        );
    }

    #[test]
    fn finalize_missed_challenge_before_deadline_rejected() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        assert!(matches!(
            reg.finalize_missed_challenge(cid, 100),
            Err(StorageError::InvalidEpochRange { .. })
        ));
    }

    #[test]
    fn challenge_can_only_be_resolved_once() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.answer_challenge(
            cid,
            ContentId([1u8; 32]),
            operator(),
            115,
            Some(b"test-mock-proof"),
        )
        .unwrap();
        let err = reg.finalize_missed_challenge(cid, 200).unwrap_err();
        assert!(matches!(err, StorageError::ChallengeAlreadyResolved(_)));
    }

    #[test]
    fn expire_deal_transitions_active_to_expired() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Active);
        reg.expire_deal(deal_id, 200).unwrap();
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Expired);
    }

    #[test]
    fn expire_deal_before_end_rejected() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        assert!(matches!(
            reg.expire_deal(deal_id, 100),
            Err(StorageError::InvalidEpochRange { .. })
        ));
    }

    #[test]
    fn slash_then_expire_is_idempotent() {
        // A Slashed deal must NOT silently become Expired (or vice versa)
        // It stays Slashed forever. This is the audit-trail invariant.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.finalize_missed_challenge(cid, 150).unwrap();
        reg.expire_deal(deal_id, 1_000_000).unwrap();
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);
    }

    fn deal_status(reg: &StorageRegistry, id: u64) -> DealStatus {
        reg.get_deal(id).unwrap().status
    }

    #[test]
    fn deal_open_rejects_missing_merkle_proof() {
        // Gate (9d82f61): None her zaman MerkleProofRequired vermeli.
        // REGRESYON KILIDI — a0671c4'te silinmisti, geri yuklendi; SILME.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let shard_id = m.shards[0].shard_id;
        let err = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                0,
                100,
                200,
                good_econ(),
                &params(),
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::MerkleProofRequired));
    }

    #[test]
    fn deal_open_rejects_malformed_merkle_proof() {
        // Format gate: deserialize edilemeyen blob InvalidMerkleProof vermeli.
        // REGRESYON KILIDI — a0671c4'te silinmisti, geri yuklendi; SILME.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let shard_id = m.shards[0].shard_id;
        let err = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                0,
                100,
                200,
                good_econ(),
                &params(),
                Some(vec![0u8; 64]), // kasitli bozuk zarf: deserialize edilemez
                Some([0x42u8; 32]),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidMerkleProof(_)));
    }

    #[test]
    fn prune_content_expires_active_deals_and_removes_manifest() {
        // F1 (Constitution §1): NFT yakılırsa veri B.U.D. storage'dan fiziksel silinir.
        // REGRESYON KILIDI — prune_content aktif deal'leri expire etmeli
        // Ve manifest'i registry'den kaldırmalı.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let manifest_id = m.manifest_id;

        // Open 2 deals for the same manifest.
        let shard_id = m.shards[0].shard_id;
        let _id1 = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                0,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();
        let _id2 = reg
            .open_deal(
                42,
                &m,
                shard_id,
                operator(),
                1,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();

        // Manifest should exist before prune.
        assert!(reg.get_manifest(&manifest_id).is_some());

        // Prune the content.
        let pruned = reg.prune_content(&manifest_id, 150);
        assert_eq!(pruned, 2);

        // Both deals should now be Expired.
        assert_eq!(reg.all_deals().len(), 2);
        for deal in reg.all_deals() {
            assert_eq!(deal.status, DealStatus::Expired);
        }

        // Manifest should be removed.
        assert!(reg.get_manifest(&manifest_id).is_none());
    }

    #[test]
    fn prune_content_idempotent_on_empty_manifest() {
        // Pruning a manifest that doesn't exist should be a no-op.
        let mut reg = StorageRegistry::new();
        let bogus = ContentId([0xEEu8; 32]);
        let pruned = reg.prune_content(&bogus, 100);
        assert_eq!(pruned, 0);
    }
    /// REGRESSION: max concurrent open challenges per deal.
    #[test]
    fn registry_lifecycle_projection_tracks_challenge_and_slash() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        assert_eq!(
            reg.lifecycle_state(deal_id),
            Some(crate::storage::StorageLifecycleState::Proving)
        );

        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        assert_eq!(
            reg.lifecycle_state(deal_id),
            Some(crate::storage::StorageLifecycleState::Challenged)
        );

        reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        // A missed challenge slashes the deal AND opens a Pending reallocation
        // Ticket, so the projected lifecycle state is ReallocationPending, not
        // The bare Slashed state (same expectation as
        // Missed_challenge_creates_reallocation_ticket_and_accepts_replacement).
        // Slashed is only projected when no ticket exists for the failed deal.
        assert_eq!(
            reg.lifecycle_state(deal_id),
            Some(crate::storage::StorageLifecycleState::ReallocationPending)
        );
    }

    #[test]
    fn registry_lifecycle_projection_tracks_expiry() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        reg.expire_deal(deal_id, 200).unwrap();
        assert_eq!(
            reg.lifecycle_state(deal_id),
            Some(crate::storage::StorageLifecycleState::Expired)
        );
    }

    #[test]
    fn entropy_bound_challenge_range_changes_with_unpredictable_seed() {
        let manifest = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &manifest);
        let deal = reg.get_deal(deal_id).unwrap().clone();
        let first = StorageRegistry::derive_challenge_range(StorageChallengeRangeInput {
            entropy: &[1u8; 32],
            deal: &deal,
            manifest: &manifest,
            opener: opener(),
            challenge_epoch: 110,
            deadline_epoch: 120,
            requested_len: 4,
            challenge_id: 0,
        })
        .unwrap();
        let second = (2u8..=u8::MAX)
            .map(|seed| {
                StorageRegistry::derive_challenge_range(StorageChallengeRangeInput {
                    entropy: &[seed; 32],
                    deal: &deal,
                    manifest: &manifest,
                    opener: opener(),
                    challenge_epoch: 110,
                    deadline_epoch: 120,
                    requested_len: 4,
                    challenge_id: 0,
                })
                .unwrap()
            })
            .find(|range| *range != first)
            .expect("small shard still has multiple selectable ranges");

        assert_eq!(first.1 - first.0, 4);
        assert_eq!(second.1 - second.0, 4);
    }

    #[test]
    fn operator_manifest_challenge_rate_limit_survives_distinct_deals() {
        let manifest = good_manifest();
        let mut reg = StorageRegistry::new();
        let (first_deal, _) = open_one(&mut reg, &manifest);
        let second_deal = reg
            .open_deal(
                1,
                &manifest,
                manifest.shards[0].shard_id,
                operator(),
                1,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42; 32]),
            )
            .unwrap();

        reg.open_challenge(first_deal, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let error = reg
            .open_challenge(second_deal, 4, 8, 113, 123, opener(), 50)
            .unwrap_err();
        assert!(matches!(
            error,
            StorageError::ChallengeRateLimited {
                minimum_next_epoch: 114,
                ..
            }
        ));
        reg.open_challenge(second_deal, 4, 8, 114, 124, opener(), 50)
            .expect("the configured four-epoch interval permits a new challenge");
    }

    #[test]
    fn max_open_challenges_per_deal() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        for i in 0..10 {
            let epoch = 110 + i as u64 * StorageRegistry::MIN_OPERATOR_MANIFEST_CHALLENGE_EPOCHS;
            reg.open_challenge(deal_id, 0, 4, epoch, epoch + 90, opener(), 50)
                .unwrap_or_else(|e| panic!("challenge {i} should open: {e:?}"));
        }
        let err = reg
            .open_challenge(deal_id, 0, 4, 500, 600, opener(), 50)
            .unwrap_err();
        assert!(
            matches!(err, StorageError::TooManyOpenChallenges { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_answer_challenge_with_zk_proof_happy_path() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        // Open a production deal with a storage_root
        let deal_id = reg
            .open_deal(
                42,
                &m,
                m.shards[0].shard_id,
                operator(),
                1,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();

        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();

        // Providing the correct test-mock-proof should verify successfully
        let res = reg
            .answer_challenge(
                cid,
                ContentId([1u8; 32]),
                operator(),
                115,
                Some(b"test-mock-proof"),
            )
            .unwrap();
        assert_eq!(res.outcome, ChallengeOutcome::Answered);
    }

    #[test]
    fn test_answer_challenge_missing_zk_proof_rejected() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        // Open a production deal with a storage_root
        let deal_id = reg
            .open_deal(
                42,
                &m,
                m.shards[0].shard_id,
                operator(),
                1,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();

        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();

        // Omitting proof_bytes on a production deal (storage_root present) must fail
        let err = reg
            .answer_challenge(cid, ContentId([1u8; 32]), operator(), 115, None)
            .unwrap_err();
        assert!(
            matches!(err, StorageError::InvalidMerkleProof(ref reason) if reason.contains("mandatory")),
            "expected mandatory proof error, got {err:?}"
        );
    }

    #[test]
    fn storage_challenge_public_inputs_bind_full_runtime_context() {
        let manifest = good_manifest();
        let mut registry = StorageRegistry::new();
        let deal_id = registry
            .open_deal(
                42,
                &manifest,
                manifest.shards[0].shard_id,
                operator(),
                1,
                100,
                200,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42; 32]),
            )
            .unwrap();
        let challenge_id = registry
            .open_challenge(deal_id, 8, 16, 110, 120, opener(), 50)
            .unwrap();
        let deal = registry.deals.get(&deal_id).unwrap();
        let challenge = registry.challenges.get(&challenge_id).unwrap();
        let storage_root = [0x42u8; 32];
        let range_hash = ContentId([0x24u8; 32]);
        let mainnet_context =
            StorageChallengeProofContext::from_registry(1, challenge, deal, operator(), 115);
        let (_, mainnet_inputs) = StorageRegistry::storage_challenge_expected_program_and_inputs(
            &mainnet_context,
            &storage_root,
            &range_hash,
        );
        let devnet_context = StorageChallengeProofContext {
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            ..mainnet_context.clone()
        };
        let (_, devnet_inputs) = StorageRegistry::storage_challenge_expected_program_and_inputs(
            &devnet_context,
            &storage_root,
            &range_hash,
        );

        assert_eq!(mainnet_inputs.chain_id, 1);
        assert_eq!(mainnet_inputs.nonce, challenge_id);
        assert_eq!(mainnet_inputs.block_height, 115);
        assert_eq!(mainnet_inputs.initial_state_root, storage_root);
        assert_eq!(mainnet_inputs.final_state_root, range_hash.0);
        assert_ne!(mainnet_inputs.event_digest, [0; 32]);
        assert_ne!(mainnet_inputs.event_digest, devnet_inputs.event_digest);

        let later_response = StorageChallengeProofContext {
            response_epoch: 116,
            ..mainnet_context
        };
        let (_, later_inputs) = StorageRegistry::storage_challenge_expected_program_and_inputs(
            &later_response,
            &storage_root,
            &range_hash,
        );
        assert_ne!(mainnet_inputs.event_digest, later_inputs.event_digest);
    }

    #[test]
    fn storage_registry_root_changes_when_manifest_and_challenge_change() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let root_before = reg.root();
        reg.register_manifest(&m);
        let root_after_manifest = reg.root();
        assert_ne!(root_before, root_after_manifest);

        let (deal_id, _) = open_one(&mut reg, &m);
        let root_after_deal = reg.root();
        assert_ne!(root_after_manifest, root_after_deal);

        reg.open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        assert_ne!(root_after_deal, reg.root());
    }

    /// The bond must grow with the range, otherwise a 1-unit bond buys a
    /// 16 MiB read-and-hash and is refunded afterwards.
    #[test]
    fn required_bond_scales_with_the_challenged_range() {
        let small = StorageRegistry::required_opener_bond(1024);
        let big = StorageRegistry::required_opener_bond(16 * 1024 * 1024);
        assert!(big > small, "bond must scale: {small} -> {big}");
        assert_eq!(big, 16 * 1024, "16 MiB is 16384 KiB at 1 unit per KiB");
    }

    /// Sub-KiB ranges must not be free.
    #[test]
    fn tiny_ranges_still_cost_the_floor() {
        assert_eq!(
            StorageRegistry::required_opener_bond(1),
            StorageRegistry::MIN_OPENER_BOND
        );
        assert_eq!(
            StorageRegistry::required_opener_bond(1024),
            StorageRegistry::MIN_OPENER_BOND
        );
        // 1025 bytes rounds up to 2 KiB.
        assert_eq!(StorageRegistry::required_opener_bond(1025), 2);
    }

    /// The rounding must be up, not down: rounding down would make the last
    /// partial KiB free and let an attacker shave the bond.
    #[test]
    fn range_length_rounds_up_to_whole_kib() {
        for len in [1u64, 2, 1023, 1024] {
            assert_eq!(StorageRegistry::required_opener_bond(len), 1, "len {len}");
        }
        for len in [1025u64, 2047, 2048] {
            assert_eq!(StorageRegistry::required_opener_bond(len), 2, "len {len}");
        }
    }

    /// No overflow on a hostile range length.
    #[test]
    fn required_bond_saturates_instead_of_overflowing() {
        let b = StorageRegistry::required_opener_bond(u64::MAX);
        assert!(b > 0, "must not wrap to zero");
    }

    /// The gate must actually reject an underpaid challenge, and the error
    /// has to name the numbers so the caller can fix it.
    #[test]
    fn open_challenge_rejects_a_bond_below_the_range_cost() {
        let manifest = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &manifest);

        // A 64 KiB range needs 64 units; offer 1.
        let range_len = 64 * 1024u64;
        let err = reg
            .open_challenge(deal_id, 0, range_len, 100, 110, Address::from([9u8; 32]), 1)
            .expect_err("an underpaid challenge must be rejected");
        match err {
            StorageError::OpenerBondBelowRangeCost {
                range_len: rl,
                required,
                provided,
            } => {
                assert_eq!(rl, range_len);
                assert_eq!(required, 64);
                assert_eq!(provided, 1);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// And it must accept the challenge once the bond covers the range —
    /// the canary that proves the gate is not simply rejecting everything.
    #[test]
    fn open_challenge_accepts_a_bond_that_covers_the_range() {
        let manifest = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &manifest);

        let range_len = 64 * 1024u64;
        let required = StorageRegistry::required_opener_bond(range_len);
        reg.open_challenge(
            deal_id,
            0,
            range_len,
            100,
            110,
            Address::from([9u8; 32]),
            required,
        )
        .expect("a fully funded challenge must be accepted");
    }

    /// A zero bond keeps its own dedicated error rather than being folded
    /// into the new one; the two are different mistakes.
    #[test]
    fn zero_bond_still_reports_zero_bond() {
        let manifest = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &manifest);
        assert!(matches!(
            reg.open_challenge(deal_id, 0, 4096, 100, 110, Address::from([9u8; 32]), 0),
            Err(StorageError::ZeroOpenerBond)
        ));
    }
}
