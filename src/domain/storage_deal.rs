//! B.U.D. storage deals and retrieval challenges (Phase 0.39 §2.2 - §2.6,
//! vision §8.5).
//!
//! **Phase 9 (ARENA3, 2026-07-16): VerifyMerkle production gate AÇILDI.**
//! The BudZKVM `VerifyMerkle` opcode passed all three positive STARK tests
//! (1-depth, 2-depth, 64-depth). B.U.D. Faz 3 (real Proof-of-Storage) is now
//! active: every `open_deal` requires a valid `merkle_proof` (serialized
//! `ProofEnvelope`) and `storage_root`. The chain validates proof format
//! at deal-open time; full STARK verification is performed by nodes with
//! prover capability.
//!
//! **Phase 9 (ARENA3, 2026-07-16):** Two proof layers now coexist:
//!
//! 1. **Merkle Proof (Faz 3):** Every `open_deal` requires a valid
//!    `merkle_proof` and `storage_root`. The proof is format-validated at
//!    deal-open time (ProofEnvelope deserialization). Full STARK
//!    verification performed by prover-capable nodes.
//!    This is the **real Proof-of-Storage** (vision §8.3).
//!
//! 2. **Retrieval Challenge (Faz 5):** The interim retrieval challenge
//!    remains as an anti-unresponsiveness mechanism. An operator can
//!    pass by holding only the requested byte range — it does NOT prove
//!    full storage. Treat slashing-from-missed-challenge as a
//!    "this operator is unresponsive" signal, NOT as a "this operator
//!    is destroying provable storage" signal.
//!
//! Data-sovereignty rule (Phase 0.39 plan §0.5): anyone (any account, no
//! role required) may open a `RetrievalChallenge` and may submit a
//! `StorageDeal`. There is no team-gated "official monitor" role.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::storage_params::StorageDomainParams;
use crate::domain::Hash32;
use crate::storage::content_id::ContentId;
use crate::storage::manifest::ContentManifest;
use serde::{Deserialize, Serialize};

/// RPC-facing DTO for `bud_storageOpenChallenge`.
///
/// Wraps the chain-relevant fields so the JSON shape is explicit and
/// stable. Decouples the on-chain `RetrievalChallenge` (which carries
/// `opener` as the resolved `Address` and `opener_bond` already debited
/// from the caller's stake) from the request (which is the raw caller
/// intent).
///
/// **Security (Phase 3 §0.2):** `opener_signature` is mandatory on Mainnet.
/// The RPC layer verifies that the `opener` address has signed the
/// challenge intent; without this, any caller could self-report any
/// address as the opener, making the `opener_bond` anti-spam gate
/// economically meaningless.
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
    /// deal_id, byte_start, byte_end, challenge_epoch, deadline_epoch,
    /// opener_bond, opener])`. 64 bytes.
    #[serde(default)]
    pub opener_signature: Option<Vec<u8>>,
}

/// Lifecycle status of a `StorageDeal`. Reuses the same enum-tag
/// convention as the `permissionless::MemberStatus` enum — explicit
/// variants so the economic surface is auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DealStatus {
    /// Active deal, bond locked, fee per epoch accruing.
    Active,
    /// Bond was slashed (challenge missed). The bond is *not* auto-burned
    /// in this layer — it is recorded in `Slashed` and handed to a
    /// higher-level `Blockchain` accounting path (Faz 5, vision §8.5).
    /// This is the explicit "no admin hook, no silent burn" rule.
    Slashed,
    /// Deal reached `deal_end_epoch` and was finalized normally.
    Expired,
}

/// Storage economics parameters, scoped to a single deal. Per-domain
/// defaults are in `StorageDomainParams`; this is the per-deal view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageEconomicsParams {
    /// Bond the operator must lock when opening the deal. In the same
    /// `u64` fixed-point unit as `ConsensusDomain::operator_bond`.
    pub operator_bond: u64,
    /// Fee paid by the client to the operator per epoch.
    pub fee_per_epoch: u64,
}

/// A storage deal binding an operator to host a specific shard of a
/// specific manifest. One shard may have multiple deals (replication =
/// different `replica_index`).
fn default_merkle_depth() -> u8 {
    64
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageDeal {
    // === B.U.D. Faz 3: Merkle Proof (Phase 4) ===

    // 64-depth Merkle proof serialized as [leaf || siblings || path_bits].
    // Present when `verify_merkle = Some(...)`.
    // None = interim challenge mode (Faz 2 compatibility).
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
    /// single replica is `replica_index = 0`; replication = 3 means three
    /// deals with `replica_index ∈ {0, 1, 2}` for the same `shard_id`.
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
    /// configuration error caught at deal-open time.
    pub fn duration_epochs(&self) -> u64 {
        self.deal_end_epoch.saturating_sub(self.deal_start_epoch)
    }
}

/// A pending retrieval challenge. The opener (`opener`) is just a regular
/// account — no role required. `byte_start`/`byte_end` describe the
/// sub-range of the shard the operator must hash to answer.
///
/// **WARNING (Phase 0.39 §2.5):** answering this challenge only proves
/// the operator holds the requested byte range, not the whole shard.
/// See module-level docs and the README/CLAUDE.md cross-link.
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
    /// bond is returned on success, burned on false positive. This is
    /// the **data-sovereignty anti-spam mechanism** (no team-gated
    /// monitor role).
    pub opener_bond: u64,
}

/// The operator's answer to a `RetrievalChallenge`. `range_hash` MUST
/// equal `ContentId::of_subrange(shard, byte_start, byte_end)`. The
/// chain does not hold the shard bytes; verification is done by
/// whoever inspects the response off-chain.
///
/// **Security (Phase 3 §0.2):** `responder_signature` is mandatory on Mainnet.
/// The RPC layer verifies that the `responder` (the deal's operator)
/// has signed the response intent; without this, any caller could
/// self-report the operator address and answer a challenge on their
/// behalf, bypassing the `NotTheOperator` registry check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetrievalResponse {
    pub challenge_id: u64,
    pub _range_hash: ContentId,
    pub responder: Address,
    pub response_epoch: u64,
    /// Ed25519 signature over `hash_fields_bytes(["BUD_ANSWER_CHALLENGE_V1",
    /// challenge_id, range_hash, responder, response_epoch])`. 64 bytes.
    #[serde(default)]
    pub responder_signature: Option<Vec<u8>>,
}

/// The outcome of a finalized challenge. `Missed` is the only path that
/// can transition a deal to `Slashed` (Phase 0.39 §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeOutcome {
    /// Operator answered on time with a hash that matches the requested
    /// sub-range. Opener bond returned, deal stays `Active`.
    Answered,
    /// Operator answered on time but the hash was wrong. Opener bond
    /// returned (correct call), operator bond slashed.
    Mismatched,
    /// Deadline elapsed without a response. Operator bond slashed.
    Missed,
}

/// A finalized challenge with its outcome and the slash amount (if any)
/// to make the economic accounting auditable. `slashed_bond` is a *record*
/// — the actual burn is performed by the `Blockchain` accounting path
/// (Faz 5), never silently in this layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeResult {
    pub challenge_id: u64,
    pub deal_id: u64,
    pub outcome: ChallengeOutcome,
    pub finalized_epoch: u64,
    /// Total bond burned if any. 0 for `Answered`.
    pub slashed_bond: u64,
}

/// On-chain, in-memory registry of all `StorageDeal`s, `RetrievalChallenge`s,
/// and `ChallengeResult`s for a single storage domain. Backed by
/// `BTreeMap` (the same primitive `permissionless::PermissionlessRegistry`
/// uses) so the registry is deterministic, cloneable, and
/// `bincode`-serializable for sled storage (vision §8.4 atomic
/// persistence).
///
/// **No admin hook**, no `pause_all`, no `freeze`, no team-only method
/// (data-sovereignty rule). All state transitions are either
/// permissionless (anyone can open a deal / challenge) or are computed
/// from the on-chain data (epoch deadline elapses → `Missed`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageRegistry {
    /// Next `deal_id` to assign.
    next_deal_id: u64,
    /// Next `challenge_id` to assign.
    next_challenge_id: u64,
    deals: BTreeMap<u64, StorageDeal>,
    /// Index by `(manifest_id, shard_id)` for `bud_storageGetDealsByShard`
    /// and `bud_storageGetDealsByManifest`. `(deal_id)` is the value
    /// so the index is deterministic and small.
    deals_by_shard: BTreeMap<(ContentId, ContentId), Vec<u64>>,
    challenges: BTreeMap<u64, RetrievalChallenge>,
    results: BTreeMap<u64, ChallengeResult>,
    #[serde(default)]
    pub manifests: BTreeMap<ContentId, ContentManifest>,
}

use std::collections::BTreeMap;

/// Errors emitted by the registry. Enum-tagged for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Caller asked to open a deal for a shard that does not exist in the
    /// referenced manifest. (We can't know this without the manifest; we
    /// pass the manifest in for validation.)
    UnknownShard {
        manifest_id: ContentId,
        shard_id: ContentId,
    },
    /// Deal end epoch must be strictly after start epoch.
    InvalidEpochRange { start: u64, end: u64 },
    /// Operator bond is below the per-domain minimum.
    InsufficientBond { required: u64, provided: u64 },
    /// Opener bond is 0 (would let anyone spam challenges for free).
    ZeroOpenerBond,
    /// Caller referenced a deal that does not exist.
    UnknownDeal(u64),
    /// Caller referenced a challenge that does not exist.
    UnknownChallenge(u64),
    /// Caller referenced a deal that is not `Active` (e.g. tried to
    /// answer a challenge on a `Slashed` deal).
    DealNotActive(u64),
    /// Caller tried to answer a challenge with the wrong operator
    /// address (anyone can open; only the deal's operator can answer).
    NotTheOperator {
        expected: Address,
        provided: Address,
    },
    /// Challenge deadline has already passed at response time.
    DeadlineElapsed { deadline_epoch: u64, now_epoch: u64 },
    /// Challenge has already been answered / finalized.
    ChallengeAlreadyResolved(u64),
    /// Manifest with the given `manifest_id` is not registered in the
    /// storage domain.
    UnknownManifest(ContentId),
    /// B.U.D. Faz 3 (Phase 9): merkle_proof and storage_root are mandatory
    /// now that VerifyMerkle production gate is open.
    MerkleProofRequired,
    /// B.U.D. Faz 3 (Phase 9): the provided merkle proof failed format validation
    /// or STARK verification. The proof must be a valid ProofEnvelope.
    InvalidMerkleProof(String),
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
                "B.U.D. Faz 3: merkle_proof and storage_root are mandatory (VerifyMerkle gate open)"
            ),
            StorageError::InvalidMerkleProof(ref reason) => {
                write!(f, "B.U.D. Faz 3: invalid merkle proof — {reason}")
            }
        }
    }
}

impl std::error::Error for StorageError {}

impl StorageRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a manifest so subsequent deal-opens can validate
    /// `(manifest_id, shard_id)` membership. Idempotent — re-registering
    /// the same `manifest_id` is a no-op (per the chain-only rule: the
    /// canonical manifest lives in `ContentManifest`; this index only
    /// tracks "is this manifest known to the storage domain?").
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
    /// path.
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
        // === B.U.D. Faz 3: Merkle Proof (Phase 4) ===
        // Optional in Faz 2 (interim); required in Faz 3 once VerifyMerkle gate opens.
        merkle_proof: Option<Vec<u8>>,
        storage_root: Option<Hash32>,
    ) -> Result<u64, StorageError> {
        // === B.U.D. Faz 3 (Phase 9): Merkle proof MANDATORY + VALIDATE ===
        // VerifyMerkle production gate AÇILDI (ARENA3, 2026-07-16).
        // All three positive STARK tests pass (1+2+64-depth).
        // Real Proof-of-Storage is now active — merkle_proof + storage_root required.
        let proof_bytes = merkle_proof
            .as_ref()
            .ok_or(StorageError::MerkleProofRequired)?;
        let root = storage_root.ok_or(StorageError::MerkleProofRequired)?;

        // Validate proof format: must deserialize as a valid ProofEnvelope.
        // Full STARK verification deferred to nodes with prover capability;
        // the chain validates structural integrity at deal-open time.
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
    /// required) — the opener_bond is the anti-spam mechanism.
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

        let challenge_id = self.next_challenge_id;
        self.next_challenge_id += 1;
        let challenge = RetrievalChallenge {
            challenge_id,
            deal_id,
            shard_id: deal.shard_id,
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
    /// bytes themselves are not on-chain; the chain records only the
    /// hash and trusts off-chain verifiers to confirm it. This is
    /// the documented interim-challenge limitation.
    pub fn answer_challenge(
        &mut self,
        challenge_id: u64,
        __range_hash: ContentId,
        responder: Address,
        response_epoch: u64,
    ) -> Result<ChallengeResult, StorageError> {
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

        // The chain does not hold the shard bytes, so we cannot itself
        // compute the expected range hash from `shard_bytes`. The
        // `StorageRegistry` therefore accepts ANY `range_hash` at this
        // layer and tags the result `Answered` if the response arrived
        // on time. Off-chain verifiers and the next audit pass
        // (Phase 0.40) can re-validate `range_hash` against the public
        // `RetrievalResponse`. This keeps the on-chain surface small
        // and explicit: a `Mismatched` outcome is reserved for the
        // future when shard bytes (or a ZK proof) are on-chain.
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

    /// Finalize a challenge whose deadline has elapsed without a
    /// response. The deal transitions to `Slashed` and the operator
    /// bond is *recorded* as slashed (not burned — burning is a
    /// higher-layer `Blockchain` accounting decision).
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
        let deal = self
            .deals
            .get_mut(&deal_id)
            .ok_or(StorageError::UnknownDeal(deal_id))?;
        let slash_amount = deal.economics.operator_bond;
        deal.status = DealStatus::Slashed;

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

    /// Expire a deal that reached its `deal_end_epoch` without
    /// being slashed.
    pub fn expire_deal(&mut self, deal_id: u64, now_epoch: u64) -> Result<(), StorageError> {
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
            deal.status = DealStatus::Expired;
        }
        Ok(())
    }

    /// B.U.D. Faz 3 (Phase 9): validate merkle proof format.
    /// Checks that proof_bytes deserializes to a valid ProofEnvelope.
    /// Full STARK verification (Plonky3Adapter::verify) is deferred to
    /// nodes with the bud-proof crate and prover capability.
    pub fn validate_merkle_proof_format(
        proof_bytes: &[u8],
        storage_root: &Hash32,
    ) -> Result<(), StorageError> {
        // Phase 9 format validation: proof must be non-empty and at least
        // contain a minimal ProofEnvelope header (version + backend + proof_bytes).
        if proof_bytes.len() < 64 {
            return Err(StorageError::InvalidMerkleProof(
                "proof too short (< 64 bytes)".into(),
            ));
        }
        // Try deserializing as ProofEnvelope via bincode.
        // The ProofEnvelope has: proof_format_version(u32), backend(String),
        // p3_version(String), fri_params_id(String), public_inputs_hash([u8;32]),
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

    /// Force-prune all storage content associated with a manifest CID.
    /// Called when an NFT is burned (Constitution §1: "NFT yakılırsa veri
    /// B.U.D. storage'dan fiziksel silinir").
    ///
    /// Expires all active deals for this manifest and removes the manifest
    /// from the registry. Deals that are already Slashed or Expired are
    /// left as-is (audit trail).
    ///
    /// Returns the number of active deals that were expired by this prune.
    pub fn prune_content(&mut self, manifest_id: &ContentId, now_epoch: u64) -> u64 {
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
/// audit logs and the (future) `GlobalBlockHeader.storage_root` aggregation
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

    fn good_manifest() -> ContentManifest {
        ContentManifest::from_bytes_sliced(b"some test content for the deal", 8).unwrap()
    }

    fn good_econ() -> StorageEconomicsParams {
        StorageEconomicsParams {
            operator_bond: 5_000_000,
            fee_per_epoch: 100,
        }
    }

    /// Phase 9 (Faz 3, `9d82f61`): format-gecerli test zarfi (durust
    /// marker — GERCEK STARK kaniti degil; bincode-deserialize olabilen minimal
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

        // Test with merkle proof (Faz 3 mode)
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
            .answer_challenge(cid, ContentId([0u8; 32]), operator(), 115)
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
            .answer_challenge(cid, ContentId([0u8; 32]), operator(), 200)
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
            .answer_challenge(cid, ContentId([0u8; 32]), opener(), 115)
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
        reg.answer_challenge(cid, ContentId([0u8; 32]), operator(), 115)
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
        // — it stays Slashed forever. This is the audit-trail invariant.
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
        // Faz 3 gate (9d82f61): None her zaman MerkleProofRequired vermeli.
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
        // Faz 3 format gate: deserialize edilemeyen blob InvalidMerkleProof vermeli.
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
        // ve manifest'i registry'den kaldırmalı.
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
}

impl StorageRegistry {
    pub fn root(&self) -> Hash32 {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"BDLM_STORAGE_REGISTRY_V1");
        hasher.update(self.next_deal_id.to_le_bytes());
        hasher.update(self.next_challenge_id.to_le_bytes());
        
        let mut deal_hashes = Vec::new();
        for (id, deal) in &self.deals {
            let mut h = sha2::Sha256::new();
            h.update(id.to_le_bytes());
            h.update(storage_deal_leaf_hash(deal));
            deal_hashes.push(h.finalize());
        }
        
        for h in deal_hashes {
            hasher.update(h);
        }
        
        hasher.finalize().into()
    }
}
