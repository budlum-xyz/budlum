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
//!    The requested byte range - it does NOT prove full storage. Treat
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
/// Convention as the `permissionless::MemberStatus` enum, explicit
/// Variants so the economic surface is auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DealStatus {
    /// Active deal, bond locked, fee per epoch accruing.
    Active,
    /// Bond was slashed (challenge missed). The bond is *not* auto-burned
    /// In this layer - it is recorded in `Slashed` and handed to a
    /// Higher-level `Blockchain` accounting path.
    /// This is the explicit "no admin hook, no silent burn" rule.
    Slashed,
    /// Deal reached `deal_end_epoch` and was finalized normally.
    Expired,
}

/// How long an operator that lost a challenge stays out of the storage
/// business, in seconds.
///
/// Six hours. The number is in seconds rather than epochs on purpose: an
/// epoch is `slot_duration_secs * epoch_length_slots`, both governance
/// parameters, so a cooldown written as "67 epochs" would silently become
/// four hours or twelve the next time either is tuned. A punishment whose
/// severity depends on an unrelated timing knob is not a punishment anyone
/// can reason about.
///
/// Six hours is long enough that a machine flapping in and out costs its
/// operator real income, and short enough that a genuine outage does not end
/// a business. Storj measures downtime in days before suspension, but Storj
/// suspends on a rolling *score*; this is a single missed challenge, which is
/// a sharper signal and deserves a lighter, immediate response.
///
/// # What a block producer can do to this clock
///
/// The cooldown is measured against block timestamps, and a producer chooses
/// the timestamp of the block it makes. Consensus bounds that choice: a block
/// dated further ahead than `MAX_FUTURE_BLOCK_TIME_MS` is rejected. So the
/// worst a producer can do is move the chain's clock forward by that drift
/// and shorten someone's cooldown by the same amount.
///
/// Six hours is chosen partly because it dwarfs that window. A punishment
/// measured in seconds would be worth manipulating a timestamp for; one
/// measured in hours is not, and the producer would have to keep doing it
/// block after block while every other node watched the clock run ahead.
pub const MISSED_CHALLENGE_COOLDOWN_SECS: u64 = 6 * 60 * 60;

/// What kind of machine an operator says it is.
///
/// The chain cannot verify this, and does not try. What it can do is hold the
/// operator to the class it claimed: a phone that says it is a phone accepts
/// the phone rules, and a phone that lies its way into a primary replica
/// carries a server's obligations and loses its bond when it sleeps.
///
/// The distinction exists because the two are not interchangeable. A phone is
/// online when its owner happens to be using it. Putting the only copy of
/// something there is not redundancy, it is a coin flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OperatorClass {
    /// Continuously powered, on mains and a fixed connection.
    #[default]
    AlwaysOn,
    /// A phone, tablet or laptop: online opportunistically, on battery, often
    /// on a metered link.
    Mobile,
}

impl OperatorClass {
    /// Whether this class may hold `replica_index = 0`.
    ///
    /// The primary is the copy a reader reaches for first and the one a repair
    /// rebuilds from when the others are gone. A device that is online when
    /// its owner is awake cannot be that.
    #[must_use]
    pub const fn may_hold_primary(self) -> bool {
        matches!(self, Self::AlwaysOn)
    }
}

/// Storage economics parameters, scoped to a single deal. Per-domain
/// Defaults are in `StorageDomainParams`; this is the per-deal view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageEconomicsParams {
    /// Bond the operator must lock when opening the deal. In the same
    /// `u64` fixed-point unit as `ConsensusDomain::operator_bond`.
    pub operator_bond: u64,
    /// Price of storing one byte for one epoch, in base units scaled by
    /// [`FEE_RATE_SCALE`].
    ///
    /// This used to be `fee_per_byte_epoch`, a flat price for the deal no matter
    /// how large the shard was. A 1 KiB shard and a 16 MiB shard cost the
    /// same, so the client picked the size and the operator carried it. The
    /// deal already receives the manifest and looks the shard up in it, so
    /// the byte count was available at every call site that computed a price
    /// and simply went unread.
    ///
    /// Scaling exists because a useful per-byte-epoch price is far below one
    /// base unit: at [`FEE_RATE_SCALE`] = 1e9, a rate of `1` prices a 1 GiB
    /// shard at roughly one base unit per epoch. Integer division truncates,
    /// so [`StorageEconomicsParams::total_fee`] multiplies by size and by
    /// epochs before it divides, and never the other way round.
    pub fee_per_byte_epoch: u64,
}

/// Fixed-point denominator for [`StorageEconomicsParams::fee_per_byte_epoch`].
///
/// A price per byte per epoch is a small number. Without a scale the only
/// expressible rates are zero and "one base unit per byte per epoch", and the
/// second is absurd: it charges a gigabyte more per epoch than the total
/// supply. Every arithmetic path divides by this exactly once, at the end.
pub const FEE_RATE_SCALE: u128 = 1_000_000_000;

impl StorageEconomicsParams {
    /// Total client fee for storing `shard_bytes` for `epochs` epochs.
    ///
    /// Multiplication happens in `u128` and before the single division, so a
    /// rate worth less than one base unit per byte per epoch still adds up
    /// over a large shard or a long deal instead of truncating on every term.
    ///
    /// The result is rounded **up**. Truncation is what made the flat price
    /// wrong in the first place, and it comes back in a smaller form here:
    /// integer division sends any deal whose true price is under one base
    /// unit to zero, and a zero fee is free storage that an operator is still
    /// obliged to serve and answer challenges for. Rounding up means a priced
    /// deal always costs something. A deal that is genuinely free is written
    /// as `fee_per_byte_epoch: 0`, which stays zero and says so.
    ///
    /// Saturates rather than wrapping. A deal priced beyond `u64` cannot be
    /// escrowed anyway, and the caller checks the payer balance against the
    /// value returned here, so a saturated total is refused at that check
    /// rather than silently becoming a small number.
    pub fn total_fee(&self, shard_bytes: u64, epochs: u64) -> u64 {
        let scaled = (self.fee_per_byte_epoch as u128)
            .saturating_mul(shard_bytes as u128)
            .saturating_mul(epochs as u128);
        u64::try_from(scaled.div_ceil(FEE_RATE_SCALE)).unwrap_or(u64::MAX)
    }
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
    /// Size of the shard this deal covers, in bytes, copied from the
    /// manifest at open time.
    ///
    /// The deal is the thing that gets paid, challenged and slashed, and it
    /// outlives the caller's copy of the manifest, so the number the price
    /// was computed from has to travel with it. Reading the manifest again
    /// later would price the deal against whatever the registry holds then,
    /// not against what the payer agreed to.
    ///
    /// `0` is how deals written before per-byte pricing deserialize. Those
    /// were priced flat, and [`StorageDeal::total_fee`] keeps charging them
    /// nothing extra rather than repricing an agreement after the fact.
    #[serde(default)]
    pub shard_bytes: u64,
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

    /// Client fee owed for `epochs` epochs of this deal.
    ///
    /// Reads `shard_bytes` recorded at open time rather than looking the
    /// manifest up again, so the price cannot move under an agreement that
    /// has already been escrowed.
    pub fn total_fee(&self, epochs: u64) -> u64 {
        self.economics.total_fee(self.shard_bytes, epochs)
    }

    /// Number of epochs the deal is scheduled to last. `0` is a
    /// Configuration error caught at deal-open time.
    pub fn duration_epochs(&self) -> u64 {
        self.deal_end_epoch.saturating_sub(self.deal_start_epoch)
    }
}

/// A pending retrieval challenge. The opener (`opener`) is just a regular
/// Account - no role required. `byte_start`/`byte_end` describe the
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
    /// `submit_registry_slashing_report` in `chain/blockchain.rs` -
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

/// What a coding audit asks about: one parity shard, one byte column.
///
/// Deliberately not a stored type. It is derived from entropy and the
/// manifest whenever an audit is opened, so there is no second copy of the
/// selection that could drift from the one the verifier recomputes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingAudit {
    pub manifest_id: ContentId,
    /// Counts parity shards from zero, so 0 is generator row `k`.
    pub parity_index: u32,
    /// Byte offset within the shard, the same for every shard in the code
    /// word because Reed-Solomon works symbol-wise across equal-length
    /// shards.
    pub column: u64,
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
    /// What each owner declared about content they intend to self-host.
    ///
    /// `MobileSelfContentPolicy` lets an owner mark content critical and name
    /// how many paid replicas it needs. The type existed, was tested, and no
    /// deal path read it, so a phone could take the only copy of something its
    /// owner had already declared too important for a phone.
    ///
    /// Keyed by content, because the declaration is about the content rather
    /// than about the device: the same phone may self-host a holiday photo and
    /// be refused a legal document.
    #[serde(default)]
    pub self_host_policies: BTreeMap<ContentId, crate::storage::MobileSelfContentPolicy>,
    /// When each operator that missed a challenge may take storage work
    /// again, as a unix timestamp.
    ///
    /// Losing the bond is a one-off cost an operator can price in: fail,
    /// pay, re-register, fail again. The cooldown is what makes flapping
    /// expensive in the dimension that actually hurts, which is time on the
    /// network earning fees. An entry is kept until it expires and is then
    /// pruned, so the map stays proportional to recent failures rather than
    /// to history.
    #[serde(default)]
    operator_cooldowns: BTreeMap<Address, u64>,
    /// What each operator declared itself to be.
    ///
    /// Absent means [`OperatorClass::AlwaysOn`], which is what every operator
    /// registered before this field was implicitly claiming by taking primary
    /// replicas.
    #[serde(default)]
    operator_classes: BTreeMap<Address, OperatorClass>,
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
    /// The manifest's `manifest_id` does not derive from its own contents,
    /// so the caller either built it wrong or chose the id deliberately.
    InvalidManifest {
        reason: String,
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
    /// A self-hosting device was offered content its own declared profile
    /// says it cannot carry alone.
    ///
    /// `MobileSelfContentPolicy` lets an owner mark content critical and name
    /// how many paid replicas it needs. The rule existed and nothing read it,
    /// so a phone could accept the only copy of something its owner had
    /// already declared too important for a phone.
    SelfHostRefusedByPolicy {
        content_id: ContentId,
        reason: String,
    },
    /// A coding audit was opened against an object with no parity shards.
    ///
    /// There is no relationship to check: under plain replication every
    /// shard is data, and `XOR_j coeff(i, j) * data_j[c]` has no `i` to
    /// range over. Refusing is the honest answer. Returning "correct" would
    /// report a passing audit on an object that was never audited.
    NoParityToAudit {
        manifest_id: ContentId,
    },
    /// The audit's answer did not satisfy the coding relationship.
    ///
    /// Column `column` of parity shard `parity_index` is not what the
    /// generator says it must be, given the data bytes at that column. The
    /// operator either miscomputed the parity or is serving bytes that are
    /// not the parity it was paid to hold.
    ParityColumnMismatch {
        manifest_id: ContentId,
        parity_index: u32,
        column: u64,
    },
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
    /// The operator lost a challenge recently and is serving its cooldown.
    ///
    /// Carries the timestamp it may open deals again, so the caller can say
    /// how long is left rather than only that the door is shut.
    OperatorInCooldown {
        operator: Address,
        until_unix_secs: u64,
    },
    /// A mobile operator asked for `replica_index = 0`.
    ///
    /// The primary is the copy a reader reaches first and a repair rebuilds
    /// from. A device that is online when its owner is awake cannot be it.
    MobileOperatorCannotHoldPrimary(Address),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::UnknownShard {
                manifest_id,
                shard_id,
            } => write!(f, "shard {} not in manifest {}", shard_id, manifest_id),
            StorageError::InvalidManifest { reason } => {
                write!(f, "manifest rejected: {reason}")
            }
            StorageError::InvalidEpochRange { start, end } => {
                write!(f, "deal epoch range {start}..{end} invalid")
            }
            StorageError::InsufficientBond { required, provided } => {
                write!(f, "operator bond {provided} below required {required}")
            }
            StorageError::OperatorInCooldown {
                operator,
                until_unix_secs,
            } => write!(
                f,
                "operator {operator} missed a challenge and cannot take storage \
                 work until unix {until_unix_secs}"
            ),
            StorageError::MobileOperatorCannotHoldPrimary(operator) => write!(
                f,
                "operator {operator} is registered as mobile and cannot hold \
                 replica_index 0; a phone is online when its owner is, which \
                 is not what a primary copy means"
            ),
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
            StorageError::SelfHostRefusedByPolicy { content_id, reason } => write!(
                f,
                "self-hosting {content_id} refused by the owner's own policy: {reason}"
            ),
            StorageError::NoParityToAudit { manifest_id } => write!(
                f,
                "manifest {manifest_id} has no parity shards, so there is no \
                 coding relationship to audit"
            ),
            StorageError::ParityColumnMismatch {
                manifest_id,
                parity_index,
                column,
            } => write!(
                f,
                "parity shard {parity_index} of manifest {manifest_id} is not \
                 the parity the generator requires at column {column}"
            ),
            StorageError::MerkleProofRequired => write!(
                f,
                "merkle_proof and storage_root are mandatory (VerifyMerkle gate open)"
            ),
            StorageError::InvalidMerkleProof(ref reason) => {
                write!(f, "invalid merkle proof - {reason}")
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
            && self.operator_cooldowns.is_empty()
            && self.operator_classes.is_empty()
            && self.manifests.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_STORAGE_REGISTRY_V1");
        hasher.update(self.next_deal_id.to_le_bytes());
        hasher.update(self.next_challenge_id.to_le_bytes());
        hasher.update(self.next_reallocation_id.to_le_bytes());
        // Cooldowns and declared classes decide who may open a deal, so two
        // nodes that disagree about them would accept different blocks. Both
        // maps are `BTreeMap`, so iteration order is the key order and every
        // node hashes the same bytes.
        for (operator, until) in &self.operator_cooldowns {
            hasher.update(operator.as_bytes());
            hasher.update(until.to_le_bytes());
        }
        for (operator, class) in &self.operator_classes {
            hasher.update(operator.as_bytes());
            hasher.update([match class {
                OperatorClass::AlwaysOn => 0u8,
                OperatorClass::Mobile => 1u8,
            }]);
        }
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
    /// `(manifest_id, shard_id)` membership. Idempotent, re-registering
    /// The same `manifest_id` is a no-op (per the chain-only rule: the
    /// Canonical manifest lives in `ContentManifest`; this index only
    /// Tracks "is this manifest known to the storage domain?").
    /// Record what an owner declared about content they intend to self-host.
    ///
    /// The declaration is validated against the device profile that made it,
    /// so a policy naming a different owner, or marking content critical while
    /// asking for no paid replicas, is refused at the door rather than stored
    /// and read later by something that trusts it.
    ///
    /// # Errors
    ///
    /// [`StorageError::SelfHostRefusedByPolicy`] when the policy and the
    /// profile disagree, carrying the reason so the caller can show it.
    pub fn declare_self_host_policy(
        &mut self,
        policy: crate::storage::MobileSelfContentPolicy,
        profile: &crate::storage::MobileSelfProfile,
    ) -> Result<(), StorageError> {
        policy.validate_against_profile(profile).map_err(|reason| {
            StorageError::SelfHostRefusedByPolicy {
                content_id: policy.content_id,
                reason,
            }
        })?;
        self.self_host_policies.insert(policy.content_id, policy);
        Ok(())
    }

    /// Whether this content may sit on a self-hosting device with the paid
    /// replicas currently open for it.
    ///
    /// Returns `Ok(())` when no policy was declared, because content nobody
    /// said anything about is not content anybody restricted. What it refuses
    /// is the case the type was written for: an owner marked something
    /// critical, asked for `n` paid replicas, and fewer than `n` exist.
    ///
    /// # Errors
    ///
    /// [`StorageError::SelfHostRefusedByPolicy`] when self-hosting is off for
    /// this content, or when the paid replicas the owner asked for are not
    /// there.
    pub fn check_self_host_allowed(
        &self,
        manifest_id: &ContentId,
        content_id: &ContentId,
    ) -> Result<(), StorageError> {
        let Some(policy) = self.self_host_policies.get(content_id) else {
            return Ok(());
        };
        if !policy.self_host_allowed {
            return Err(StorageError::SelfHostRefusedByPolicy {
                content_id: *content_id,
                reason: "the owner turned self-hosting off for this content".into(),
            });
        }
        let paid = self.active_replica_count(manifest_id, content_id);
        let required = usize::from(policy.required_paid_replicas);
        if paid < required {
            return Err(StorageError::SelfHostRefusedByPolicy {
                content_id: *content_id,
                reason: format!(
                    "the owner asked for {required} paid replica(s) before \
                     self-hosting and {paid} are open"
                ),
            });
        }
        Ok(())
    }

    /// Record that `operator` may not take storage work until
    /// `now_unix_secs + MISSED_CHALLENGE_COOLDOWN_SECS`.
    ///
    /// Idempotent in the direction that matters: a second failure extends the
    /// cooldown, it never shortens one already running. An operator failing
    /// twice in an hour should not find its second failure resetting the
    /// clock to a shorter remaining time than its first.
    pub fn begin_operator_cooldown(&mut self, operator: Address, now_unix_secs: u64) -> u64 {
        let until = now_unix_secs.saturating_add(MISSED_CHALLENGE_COOLDOWN_SECS);
        let entry = self.operator_cooldowns.entry(operator).or_insert(until);
        *entry = (*entry).max(until);
        *entry
    }

    /// When `operator` may take work again, or `None` if it is free now.
    ///
    /// Reads without mutating so a query path can call it. Expired entries
    /// are reported as free here and removed by
    /// [`StorageRegistry::prune_expired_cooldowns`].
    #[must_use]
    pub fn operator_cooldown_until(&self, operator: &Address, now_unix_secs: u64) -> Option<u64> {
        self.operator_cooldowns
            .get(operator)
            .copied()
            .filter(|until| *until > now_unix_secs)
    }

    /// Drop cooldowns that have run out. Returns how many were removed.
    ///
    /// Without this the map grows with every failure the network ever saw,
    /// and it is hashed into the state root, so it would cost every node
    /// storage and bandwidth forever to remember a six-hour punishment.
    pub fn prune_expired_cooldowns(&mut self, now_unix_secs: u64) -> usize {
        let before = self.operator_cooldowns.len();
        self.operator_cooldowns
            .retain(|_, until| *until > now_unix_secs);
        before - self.operator_cooldowns.len()
    }

    /// Declare what kind of machine an operator runs.
    ///
    /// Self-reported and unverifiable, which is fine: the chain holds the
    /// operator to the class it claimed rather than trying to detect a lie.
    /// Claiming `AlwaysOn` to reach a primary replica means accepting a
    /// primary's obligations, and the bond answers for them.
    ///
    /// No production path calls this yet, so today every operator is
    /// `AlwaysOn` and the primary rule refuses nobody. The rule itself is
    /// live in `open_deal`; what is missing is the way an operator says it is
    /// a phone. That needs a signed transaction, because otherwise anyone
    /// could reclassify anyone else and lock them out of primary replicas,
    /// and a signed transaction type is its own change. Recorded here rather
    /// than left for a reader to discover: the enforcement is real and the
    /// declaration is not there yet.
    pub fn set_operator_class(&mut self, operator: Address, class: OperatorClass) {
        self.operator_classes.insert(operator, class);
    }

    /// What `operator` declared. Defaults to [`OperatorClass::AlwaysOn`],
    /// which is what every operator registered before this existed was
    /// implicitly claiming by taking primary replicas.
    #[must_use]
    pub fn operator_class(&self, operator: &Address) -> OperatorClass {
        self.operator_classes
            .get(operator)
            .copied()
            .unwrap_or_default()
    }

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
        // A mobile operator may hold a second or third copy and never the
        // first. The primary is what a reader reaches for and what a repair
        // rebuilds from; a device that is online when its owner is awake
        // cannot be that, and putting the only copy there is a coin flip
        // dressed as redundancy.
        //
        // The class is self-reported and the chain does not try to detect a
        // lie. It holds the operator to the class it claimed: an operator
        // that says `AlwaysOn` to reach a primary accepts a primary's
        // obligations, and the bond answers for them when it sleeps.
        if replica_index == 0 && !self.operator_class(&operator).may_hold_primary() {
            return Err(StorageError::MobileOperatorCannotHoldPrimary(operator));
        }
        // The owner's own declaration about this content, asked here because
        // this is the only place a replica is actually placed.
        //
        // `MobileSelfContentPolicy` lets an owner say "this is critical, do
        // not put it on a phone until `n` paid replicas exist".
        // `check_self_host_allowed` was written to enforce that and tested
        // six ways, and nothing in production called it: the policy could be
        // declared, stored, hashed into the state root, and then ignored by
        // the one path it was meant to govern. A rule nothing reads is not a
        // rule.
        //
        // Asked only for a mobile operator, because that is what the policy
        // is about. An always-on operator taking a replica is the case the
        // owner was trying to get more of.
        //
        // Honest about the half that is still missing: `check` is wired here,
        // but `declare_self_host_policy` has no transaction behind it yet, so
        // `self_host_policies` is empty on a live chain and this call returns
        // `Ok(())` every time. What it buys today is that the check runs on
        // the placement path, so the day a declaration can reach the chain it
        // is already being read. Wiring the declaration needs a transaction
        // type, which is a consensus-surface decision.
        if self.operator_class(&operator) == OperatorClass::Mobile {
            self.check_self_host_allowed(&manifest.manifest_id, &shard_id)?;
        }
        // A deal-open carries its own copy of the manifest, and
        // `register_manifest` is first-writer-wins, so this path can seed the
        // registry just as `RegisterStorageManifest` can. It has to apply the
        // same check that entry point does.
        //
        // It used to call `verify_id` alone, which only proves the id was
        // derived from the fields present, not that those fields agree with
        // each other. `manifest_id` covers `k` and `n`, so an author who wants
        // a false redundancy claim simply computes the id over the claim it
        // wants: three data shards with no parity, declared `(k=1, n=3)`,
        // hashes consistently and reports a loss tolerance of two. A repair
        // trigger reads that and concludes the object survives two failures
        // when it survives none.
        //
        // `validate_untrusted` is the check that catches it, by requiring the
        // data-shard count to equal `k` and the parity count to equal `n - k`.
        // `RegisterStorageManifest` already ran it; this path did not, and
        // it is the one that also opens a paid deal against the manifest.
        manifest
            .validate_untrusted()
            .map_err(|reason| StorageError::InvalidManifest { reason })?;
        self.validate_shard_membership(manifest, &shard_id)?;
        // Membership was just checked, so the shard is present; take its size
        // while the manifest is still in hand. Pricing reads this and not the
        // registry copy, which a later manifest write could move.
        let shard_bytes = u64::from(
            manifest
                .shard(&shard_id)
                .ok_or(StorageError::UnknownShard {
                    manifest_id: manifest.manifest_id,
                    shard_id,
                })?
                .size,
        );
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
            shard_bytes,
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
    /// Required) - the opener_bond is the anti-spam mechanism.
    #[allow(clippy::too_many_arguments)]
    /// Maximum concurrent open challenges per deal.
    /// Prevents spam attacks where a single deal gets unlimited challenges,
    /// Growing the StorageRegistry's challenge BTreeMap without bound.
    const MAX_OPEN_CHALLENGES_PER_DEAL: usize = 10;

    /// Opener bond charged per KiB of the challenged byte range.
    ///
    /// A challenge costs the operator a read plus a hash over the range. On
    /// commodity NVMe that is roughly 20 ms for the 16 MiB maximum chunk and
    /// 0.3 ms for the 256 KiB default - small individually, but the rate limit
    /// is keyed on `(operator, manifest)`, so an operator serving 1000
    /// manifests can be made to spend seconds of I/O per epoch by an attacker
    /// who pays nothing: the bond is refunded whenever the operator answers.
    ///
    /// Tying the bond to the range does not make griefing expensive in the
    /// long run - the capital comes back - but it makes it *capital-bound*:
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

    /// Which parity shard and which byte column a coding audit should ask
    /// about, derived from entropy the opener cannot choose.
    ///
    /// The retrieval challenge asks "do you still have these bytes". This
    /// asks a different question: "are the parity bytes you hold actually
    /// parity". An operator can pass the first while failing the second, by
    /// storing whatever it likes under the parity shard's `ContentId`. It
    /// would only be discovered during a repair, which is the one moment the
    /// object cannot afford it.
    ///
    /// Reed-Solomon works symbol-wise, so one byte column is a complete,
    /// self-contained instance of the relationship: parity byte `c` of shard
    /// `i` is `XOR_j coeff(i, j) * data_j[c]`. That makes an audit cost `k`
    /// data bytes plus one parity byte no matter how large the object is,
    /// against a full check that would read every data shard end to end.
    ///
    /// Selection is derived from `entropy` rather than chosen by the opener,
    /// for the reason the retrieval range already is: an opener who picks the
    /// column picks one the operator has, and an operator who knows the
    /// column in advance stores only that column.
    ///
    /// # Errors
    ///
    /// [`StorageError::NoParityToAudit`] when the object is replicated. There
    /// is no `i` to range over, and reporting a pass would report an audit
    /// that never happened.
    pub fn derive_coding_audit(
        entropy: &Hash32,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        let parity_count = manifest.erasure.parity_count();
        if parity_count == 0 {
            return Err(StorageError::NoParityToAudit {
                manifest_id: manifest.manifest_id,
            });
        }
        // Every shard in a code word is the padded stripe length, so any
        // shard's size is the column count. Taking the minimum rather than
        // the first is defensive: a manifest that passed `validate_untrusted`
        // has equal-length shards, but this reads sizes from an untrusted
        // structure and a short shard would make a column index out of range
        // for the operator holding it.
        let columns = manifest
            .shards
            .iter()
            .map(|s| u64::from(s.size))
            .min()
            .unwrap_or(0);
        if columns == 0 {
            return Err(StorageError::NoParityToAudit {
                manifest_id: manifest.manifest_id,
            });
        }
        let digest = hash_fields_bytes(&[
            b"BDLM_STORAGE_CODING_AUDIT_V1",
            entropy,
            manifest.manifest_id.as_bytes(),
            &challenge_id.to_le_bytes(),
            &manifest.erasure.k.to_le_bytes(),
            &manifest.erasure.n.to_le_bytes(),
        ]);
        let parity_index = u32::try_from(
            u64::from_le_bytes(
                digest[..8]
                    .try_into()
                    .expect("32-byte digest has an 8-byte prefix"),
            ) % u64::from(parity_count),
        )
        .expect("a value reduced modulo a u32 fits in u32");
        let column = u64::from_le_bytes(
            digest[8..16]
                .try_into()
                .expect("32-byte digest has a second 8-byte word"),
        ) % columns;
        Ok(CodingAudit {
            manifest_id: manifest.manifest_id,
            parity_index,
            column,
        })
    }

    /// Check an answered coding audit against the generator.
    ///
    /// `data_column` is byte `audit.column` of each data shard in shard
    /// order; `parity_byte` is the same column of parity shard
    /// `audit.parity_index`.
    ///
    /// # What a pass means
    ///
    /// That the relationship holds at that column, and nothing wider. An
    /// operator who miscomputed a fraction `f` of columns fails a uniformly
    /// random one with probability `f`, so `r` audits leave a cheat standing
    /// with probability `(1 - f)^r`. Ateniese's provable-data-possession
    /// paper measured the same trade at 460 sampled blocks out of 10,000
    /// detecting a 1% deletion with 99% confidence. This is a probabilistic
    /// instrument and calling it anything else would be a false claim.
    ///
    /// It says nothing about whether the operator *stores* the shard. That
    /// is the retrieval challenge's question. An operator can hold bytes that
    /// are not valid parity, and can compute valid parity on demand while
    /// holding nothing.
    ///
    /// # Errors
    ///
    /// [`StorageError::UnknownManifest`] if the audit names a manifest this
    /// registry does not hold, [`StorageError::NoParityToAudit`] if the
    /// object is replicated or the indices fall outside the scheme, and
    /// [`StorageError::ParityColumnMismatch`] when the answer does not
    /// satisfy the relationship.
    pub fn verify_coding_audit(
        &self,
        audit: &CodingAudit,
        data_column: &[u8],
        parity_byte: u8,
    ) -> Result<(), StorageError> {
        let manifest = self
            .manifests
            .get(&audit.manifest_id)
            .ok_or(StorageError::UnknownManifest(audit.manifest_id))?;
        let coder = crate::storage::ReedSolomon::for_scheme(&manifest.erasure).map_err(|_| {
            StorageError::NoParityToAudit {
                manifest_id: audit.manifest_id,
            }
        })?;
        let parity_index = audit.parity_index as usize;
        if coder.parity_coefficient(parity_index, 0).is_none() {
            return Err(StorageError::NoParityToAudit {
                manifest_id: audit.manifest_id,
            });
        }
        if coder.column_is_correctly_encoded(parity_index, data_column, parity_byte) {
            Ok(())
        } else {
            Err(StorageError::ParityColumnMismatch {
                manifest_id: audit.manifest_id,
                parity_index: audit.parity_index,
                column: audit.column,
            })
        }
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
        // Reject empty/zero range_hash - operator must provide a real hash
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
        //
        // A proof that fails to verify is not a malformed request, it is a
        // wrong answer from the operator who is being challenged. Returning
        // `Err` here would leave the challenge unresolved: nothing lands in
        // `self.results`, no bond moves, and the operator is free to answer
        // wrongly again. That made a wrong answer strictly cheaper than
        // silence, since only silence reaches `finalize_missed_challenge`.
        //
        // `Mismatched` exists for exactly this case and was never produced
        // anywhere in the tree. It is produced here now: the operator bond is
        // recorded as slashed on the same terms as `Missed`, and the deal
        // leaves `Active`.
        //
        // Errors raised *before* this point stay errors - they mean the
        // caller addressed the wrong deal, missed the deadline, or is not the
        // operator, none of which is evidence about stored bytes.
        let verification: Result<(), StorageError> = match (deal.storage_root, proof_bytes) {
            // The verifier cannot state what an honest proof looks like, so
            // its rejection is not evidence about the operator. Accepting the
            // answer without moving the bond is the same position the chain
            // held before challenge proofs existed; slashing on it would take
            // bonds from operators doing their job. See
            // `storage_challenge_proofs_are_checkable`.
            (Some(_), Some(_)) if !Self::storage_challenge_proofs_are_checkable() => Ok(()),
            (Some(root), Some(proof)) => {
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
                )
            }
            (Some(_), None) => Err(StorageError::InvalidMerkleProof(
                "ZK proof (ProofEnvelope) is mandatory for storage challenge verification".into(),
            )),
            // No `storage_root` on the deal means there is nothing to verify
            // against. `open_deal` requires one, so this is unreachable for
            // deals opened through the supported path; it is not treated as a
            // slashable wrong answer, because absence of a commitment is the
            // registry's gap, not the operator's fault.
            (None, _) => Ok(()),
        };

        let deal_id = deal.deal_id;
        let result = match verification {
            Ok(()) => ChallengeResult {
                challenge_id,
                deal_id,
                outcome: ChallengeOutcome::Answered,
                finalized_epoch: response_epoch,
                slashed_bond: 0,
            },
            Err(reason) => {
                tracing::warn!(
                    challenge_id,
                    deal_id,
                    operator = %responder,
                    %reason,
                    "storage challenge answered with a proof that does not verify; \
                     slashing the operator bond"
                );
                let deal = self
                    .deals
                    .get_mut(&deal_id)
                    .ok_or(StorageError::UnknownDeal(deal_id))?;
                let slashed_bond = deal.economics.operator_bond;
                deal.status = DealStatus::Slashed;
                ChallengeResult {
                    challenge_id,
                    deal_id,
                    outcome: ChallengeOutcome::Mismatched,
                    finalized_epoch: response_epoch,
                    slashed_bond,
                }
            }
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

    /// Whether this build can state, and therefore check, what an honest
    /// storage challenge proof looks like.
    ///
    /// It cannot, and the honest answer is a constant rather than a silent
    /// gap. Three of the public inputs
    /// `storage_challenge_expected_program_and_inputs` names are values the
    /// AIR does not produce for the program it names, so
    /// `DefaultAdapter::verify` rejects every proof put through this path,
    /// including a correct one:
    ///
    ///   * `initial_state_root` is given the storage root. Since the
    ///     initial-image commitment landed, that field is the fold of the
    ///     memory and register words a program reads before anything writes
    ///     them. The program here reads 65 words from the path buffer, the key
    ///     at `imm` and 64 siblings, plus two seeded registers. A storage root
    ///     is none of those. `bud-cli` had the same mistake and it was fixed
    ///     when the commitment landed; this caller was missed because no test
    ///     ever ran a real proof through it.
    ///   * `event_digest` is given the context digest. The AIR builds that
    ///     field by summing the `rs1` of every `Log` row and this program has
    ///     no `Log`, so the only value it accepts is zero.
    ///   * `gas_used` is given 0. `VerifyMerkle` costs 10.
    ///
    /// Correcting those three is not enough, which is why this is a flag and
    /// not a patch. To state the initial-image commitment the verifier needs
    /// the 65 path words and the two seeded registers, and it holds none of
    /// them: `answer_challenge` receives a `storage_root` and a `range_hash`,
    /// and the `merkle_proof` stored on the deal is a `ProofEnvelope`, not the
    /// `[leaf || siblings || path_bits]` its comment describes. Beyond that,
    /// `storage_root` is 32 bytes while the VM's notion of a Merkle root is a
    /// single 64-bit Goldilocks element, and no conversion between them is
    /// defined anywhere in the tree.
    ///
    /// Deciding how the path reaches the verifier is a consensus-visible
    /// change with several defensible answers, so it is not made here.
    ///
    /// What is fixed here is the damage. A verifier that rejects everything
    /// was wired to a caller that treats rejection as a wrong answer and
    /// slashes the operator's bond, so an operator storing the bytes
    /// faithfully and answering correctly loses its bond. Until the path is
    /// designed, this returns `false` and the challenge is answered without a
    /// bond movement, which is the same position the chain was in before
    /// challenge proofs existed.
    ///
    /// The flag is deliberately not configurable. An operator that could turn
    /// it on would be turning on a verifier that rejects honest work.
    pub(crate) fn storage_challenge_proofs_are_checkable() -> bool {
        false
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
    /// Bond is *recorded* as slashed (not burned - burning is a
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

    /// How many of an object's distinct shards still have an active deal.
    ///
    /// This is the number erasure coding cares about, and it is not the one
    /// `under_replicated_shards` computes. That function asks, per shard,
    /// whether it has fewer than `STORAGE_REPLICATION_TARGET` copies, the
    /// right question when every shard is a whole copy of the object. Under a
    /// `(k, n)` code each shard is a distinct piece, and what decides whether
    /// the object survives is how many *different* pieces are left, compared
    /// against `k`.
    ///
    /// The two disagree in both directions. A `(4,6)` object with all six
    /// shards held once is fully recoverable, yet every shard is "under
    /// replicated" at 1 < 3. The same object down to three shards, each held
    /// three times, looks healthy shard-by-shard and is already unrecoverable.
    pub fn live_shard_count(&self, manifest_id: &ContentId) -> u32 {
        let Some(manifest) = self.manifests.get(manifest_id) else {
            return 0;
        };
        manifest
            .shards
            .iter()
            .filter(|shard| self.active_replica_count(manifest_id, &shard.shard_id) > 0)
            .count() as u32
    }

    /// Objects whose surviving shard count has fallen into the repair band.
    ///
    /// Returns `(manifest_id, live, k)` for each object where
    /// `k <= live < k + margin`. Repair has to start with headroom: waiting
    /// until `live == k` means the next loss is fatal with nothing in flight.
    ///
    /// Objects already below `k` are excluded - [`ContentManifest::needs_repair`]
    /// returns false there, because there is nothing left to reconstruct from
    /// and a repair deal opened then would only burn an operator bond. Use
    /// [`StorageRegistry::unrecoverable_objects`] to see those; they need an
    /// operator alarm, not a repair.
    pub fn objects_needing_repair(&self, margin: u32) -> Vec<(ContentId, u32, u32)> {
        self.manifests
            .iter()
            .filter_map(|(manifest_id, manifest)| {
                let live = self.live_shard_count(manifest_id);
                manifest.needs_repair(live, margin).then_some((
                    *manifest_id,
                    live,
                    manifest.erasure.k,
                ))
            })
            .collect()
    }

    /// Objects that can no longer be reconstructed: fewer than `k` distinct
    /// shards still have an active deal.
    ///
    /// Separate from [`StorageRegistry::objects_needing_repair`] because the
    /// response is different. A repairable object gets a replacement deal; an
    /// unrecoverable one has already lost data, and opening deals for it
    /// accomplishes nothing. Surfacing the two together would let the second
    /// hide inside the first.
    pub fn unrecoverable_objects(&self) -> Vec<(ContentId, u32, u32)> {
        self.manifests
            .iter()
            .filter_map(|(manifest_id, manifest)| {
                let live = self.live_shard_count(manifest_id);
                (!manifest.is_recoverable(live)).then_some((*manifest_id, live, manifest.erasure.k))
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
        &deal.economics.fee_per_byte_epoch.to_le_bytes(),
        &deal.shard_bytes.to_le_bytes(),
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
            fee_per_byte_epoch: 100,
        }
    }

    // === B64: storage is priced by the bytes it holds =====================

    /// The regression this pricing replaced. `total_fee` used to be
    /// `epochs * fee_per_epoch`, so a shard a thousand times larger cost the
    /// same to store for the same time, and the client chose the size.
    #[test]
    fn a_larger_shard_costs_more_for_the_same_duration() {
        let econ = StorageEconomicsParams {
            operator_bond: 0,
            fee_per_byte_epoch: FEE_RATE_SCALE as u64,
        };
        let small = econ.total_fee(1_024, 10);
        let large = econ.total_fee(1_024 * 1_000, 10);
        assert!(
            large > small,
            "a 1000x larger shard must not cost the same: {small} vs {large}"
        );
        assert_eq!(large, small * 1_000, "price must be linear in size");
    }

    #[test]
    fn a_longer_deal_costs_more_for_the_same_shard() {
        let econ = StorageEconomicsParams {
            operator_bond: 0,
            fee_per_byte_epoch: FEE_RATE_SCALE as u64,
        };
        assert_eq!(econ.total_fee(4_096, 20), econ.total_fee(4_096, 10) * 2);
    }

    /// Truncation is what made the flat price wrong; it must not return in a
    /// smaller form. A priced deal always costs something, however small.
    #[test]
    fn a_priced_deal_is_never_free_through_rounding() {
        let econ = StorageEconomicsParams {
            operator_bond: 0,
            // Far below one base unit per byte per epoch.
            fee_per_byte_epoch: 1,
        };
        assert_eq!(
            econ.total_fee(1, 1),
            1,
            "a one-byte, one-epoch priced deal must still cost a unit"
        );
    }

    /// A deal that is genuinely free says so with a zero rate, and that stays
    /// zero. Otherwise rounding up would invent a charge nobody agreed to.
    #[test]
    fn a_zero_rate_stays_free() {
        let econ = StorageEconomicsParams {
            operator_bond: 0,
            fee_per_byte_epoch: 0,
        };
        assert_eq!(econ.total_fee(u64::MAX, u64::MAX), 0);
    }

    /// The product overflows `u64` long before it overflows the `u128` the
    /// arithmetic runs in. Saturating keeps the caller's balance check
    /// meaningful; wrapping would turn an unpayable deal into a cheap one.
    #[test]
    fn an_unpayable_deal_saturates_rather_than_wrapping() {
        let econ = StorageEconomicsParams {
            operator_bond: 0,
            fee_per_byte_epoch: u64::MAX,
        };
        assert_eq!(econ.total_fee(u64::MAX, u64::MAX), u64::MAX);
    }

    /// The deal carries the size it was priced at. Reading the manifest again
    /// later would price an agreement against whatever the registry holds
    /// then, not against what the payer escrowed.
    #[test]
    fn opening_a_deal_records_the_shard_size_it_was_priced_at() {
        let mut reg = StorageRegistry::new();
        let m = good_manifest();
        let shard = &m.shards[0];
        let id = reg
            .open_deal(
                42,
                &m,
                shard.shard_id,
                operator(),
                0,
                10,
                20,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .expect("deal opens");
        let deal = reg.get_deal(id).expect("deal exists");
        assert_eq!(
            deal.shard_bytes,
            u64::from(shard.size),
            "the deal must record the size it was priced at"
        );
        assert_eq!(
            deal.total_fee(10),
            good_econ().total_fee(u64::from(shard.size), 10),
            "the deal must price itself from its own recorded size"
        );
    }

    // === B72: a deal-open must not accept a false redundancy claim ========

    /// `manifest_id` covers `k` and `n`, so an author who wants a false
    /// redundancy claim computes the id over the claim it wants and
    /// `verify_id` passes. Three data shards with no parity, declared
    /// `(k=1, n=3)`, reports a loss tolerance of two and survives none. The
    /// deal-open path checked only the id, and it is the path that also takes
    /// the payer's money and seeds the registry.
    #[test]
    fn a_deal_open_refuses_a_manifest_claiming_parity_it_does_not_have() {
        let mut reg = StorageRegistry::new();
        let honest = good_manifest();
        let shard_id = honest.shards[0].shard_id;

        // Same shards, all Data, but claiming one of three reconstructs.
        let mut liar = honest.clone();
        liar.erasure = crate::storage::ErasureScheme {
            k: 1,
            n: liar.shard_count,
        };
        liar.manifest_id =
            crate::storage::manifest_id_from_parts(&liar.shards, &liar.erasure, &liar.encryption);
        assert!(
            liar.verify_id().is_ok(),
            "the fixture must pass the weaker check, or it tests nothing"
        );
        assert!(
            liar.erasure.loss_tolerance() > 0,
            "the fixture must actually claim a tolerance it cannot deliver"
        );

        let err = reg
            .open_deal(
                42,
                &liar,
                shard_id,
                operator(),
                0,
                10,
                20,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .expect_err("a false redundancy claim must not open a deal");
        assert!(
            matches!(err, StorageError::InvalidManifest { .. }),
            "expected InvalidManifest, got {err:?}"
        );
        assert!(
            reg.get_manifest(&liar.manifest_id).is_none(),
            "a refused manifest must not reach the registry"
        );
    }

    /// The honest manifest still opens. A check that refuses everything is
    /// not a check.
    #[test]
    fn a_deal_open_still_accepts_a_coherent_manifest() {
        let mut reg = StorageRegistry::new();
        let m = good_manifest();
        reg.open_deal(
            42,
            &m,
            m.shards[0].shard_id,
            operator(),
            0,
            10,
            20,
            good_econ(),
            &params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("a coherent manifest must still open a deal");
    }

    // === B75: a missed challenge costs six hours, not just the bond =======

    /// The bond alone is a one-off cost an operator can price in. The
    /// cooldown is the part that makes flapping expensive.
    #[test]
    fn a_missed_challenge_locks_the_operator_out_for_six_hours() {
        let mut reg = StorageRegistry::new();
        let now = 1_000_000u64;
        let until = reg.begin_operator_cooldown(operator(), now);
        assert_eq!(until, now + MISSED_CHALLENGE_COOLDOWN_SECS);
        assert_eq!(MISSED_CHALLENGE_COOLDOWN_SECS, 21_600, "six hours");
        assert_eq!(reg.operator_cooldown_until(&operator(), now), Some(until));
    }

    /// The clock has to actually run out. A cooldown that never lifts is a
    /// ban, and this is not one.
    #[test]
    fn the_cooldown_lifts_when_it_expires() {
        let mut reg = StorageRegistry::new();
        let now = 1_000_000u64;
        let until = reg.begin_operator_cooldown(operator(), now);
        assert!(reg
            .operator_cooldown_until(&operator(), until - 1)
            .is_some());
        assert!(reg.operator_cooldown_until(&operator(), until).is_none());
        assert!(reg
            .operator_cooldown_until(&operator(), until + 1)
            .is_none());
    }

    /// A second failure extends the cooldown and never shortens it. Failing
    /// twice must not leave less time to serve than failing once.
    #[test]
    fn a_second_failure_never_shortens_a_running_cooldown() {
        let mut reg = StorageRegistry::new();
        let first = reg.begin_operator_cooldown(operator(), 1_000_000);
        // A failure recorded with an earlier timestamp, which is what a
        // reordered or replayed event looks like.
        let second = reg.begin_operator_cooldown(operator(), 999_000);
        assert_eq!(second, first, "an earlier failure must not pull it in");
        let third = reg.begin_operator_cooldown(operator(), 1_010_000);
        assert!(third > first, "a later failure extends it");
    }

    /// The map is hashed into the state root, so it cannot grow with every
    /// failure the network ever saw.
    #[test]
    fn expired_cooldowns_are_pruned() {
        let mut reg = StorageRegistry::new();
        let until = reg.begin_operator_cooldown(operator(), 1_000);
        reg.begin_operator_cooldown(opener(), 1_000_000);
        assert_eq!(reg.prune_expired_cooldowns(until), 1);
        assert!(reg.operator_cooldown_until(&operator(), until).is_none());
        assert!(reg.operator_cooldown_until(&opener(), 1_000_001).is_some());
    }

    /// Cooldowns decide who may open a deal, so two nodes disagreeing about
    /// them would accept different blocks.
    #[test]
    fn a_cooldown_changes_the_registry_root() {
        let mut reg = StorageRegistry::new();
        let before = reg.root();
        reg.begin_operator_cooldown(operator(), 1_000);
        assert_ne!(before, reg.root(), "the cooldown must reach the root");
    }

    // === B76: a phone may hold a copy, never the only one =================

    /// The primary is what a reader reaches for and a repair rebuilds from.
    #[test]
    fn a_mobile_operator_cannot_take_the_primary_replica() {
        let mut reg = StorageRegistry::new();
        reg.set_operator_class(operator(), OperatorClass::Mobile);
        let m = good_manifest();
        let err = reg
            .open_deal(
                42,
                &m,
                m.shards[0].shard_id,
                operator(),
                0, // primary
                10,
                20,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .expect_err("a phone must not hold the only copy");
        assert!(
            matches!(err, StorageError::MobileOperatorCannotHoldPrimary(_)),
            "expected MobileOperatorCannotHoldPrimary, got {err:?}"
        );
    }

    /// It may hold a second or third copy. A rule that refuses everything is
    /// not a rule, it is a ban on mobile storage.
    #[test]
    fn a_mobile_operator_may_take_a_secondary_replica() {
        let mut reg = StorageRegistry::new();
        reg.set_operator_class(operator(), OperatorClass::Mobile);
        let m = good_manifest();
        reg.open_deal(
            42,
            &m,
            m.shards[0].shard_id,
            operator(),
            1, // secondary
            10,
            20,
            good_econ(),
            &params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("a phone may hold a secondary copy");
    }

    /// An operator that declared nothing is `AlwaysOn`, which is what every
    /// operator registered before this field was implicitly claiming.
    #[test]
    fn an_undeclared_operator_defaults_to_always_on() {
        let reg = StorageRegistry::new();
        assert_eq!(reg.operator_class(&operator()), OperatorClass::AlwaysOn);
        assert!(OperatorClass::AlwaysOn.may_hold_primary());
        assert!(!OperatorClass::Mobile.may_hold_primary());
    }

    /// The declared class decides who may hold a primary, so it belongs in
    /// the root for the same reason the cooldown does.
    #[test]
    fn a_declared_class_changes_the_registry_root() {
        let mut reg = StorageRegistry::new();
        let before = reg.root();
        reg.set_operator_class(operator(), OperatorClass::Mobile);
        assert_ne!(before, reg.root());
    }

    /// Two deals over shards of different sizes must not hash alike. The size
    /// is what the price is computed from, so leaving it out of the leaf lets
    /// the number the payer agreed to move without the commitment noticing.
    #[test]
    fn the_deal_leaf_commits_to_the_shard_size() {
        let mut a = StorageDeal {
            deal_id: 1,
            domain_id: 42,
            manifest_id: ContentId([7u8; 32]),
            shard_id: ContentId([8u8; 32]),
            operator: operator(),
            economics: good_econ(),
            shard_bytes: 1_024,
            replica_index: 0,
            deal_start_epoch: 10,
            deal_end_epoch: 20,
            status: DealStatus::Active,
            merkle_proof: None,
            storage_root: None,
            merkle_depth: 64,
        };
        let before = storage_deal_leaf_hash(&a);
        a.shard_bytes = 1_048_576;
        assert_ne!(
            before,
            storage_deal_leaf_hash(&a),
            "the leaf must change when the priced size changes"
        );
    }

    /// Format-gecerli test zarfi (durust
    /// Marker - GERCEK STARK kaniti degil; bincode-deserialize olabilen minimal
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

    /// A wrong answer used to be cheaper than no answer at all.
    ///
    /// When the proof failed to verify, `answer_challenge` returned `Err`.
    /// Nothing landed in `results`, no bond moved, the deal stayed `Active`,
    /// and the operator could try again. Only silence reached
    /// `finalize_missed_challenge` and got slashed, so an operator that had
    /// discarded the data was better off answering wrongly, forever, than
    /// staying quiet once.
    ///
    /// `Mismatched` was declared for this case and produced nowhere in the
    /// tree. These tests hold it on the same economic terms as `Missed`.
    #[test]
    fn an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        // Answering with a proof exercises the STARK verifier, and this build
        // cannot state what an honest proof looks like, so its rejection is
        // not evidence about the operator. See
        // `storage_challenge_proofs_are_checkable`. The bond stays put; the
        // no-proof case below is the one that still slashes, because a missing
        // proof is a fact about the answer rather than a limitation of ours.
        assert!(
            !StorageRegistry::storage_challenge_proofs_are_checkable(),
            "if the verifier can state an honest proof, this test must go back \
             to asserting Mismatched"
        );
        let res = reg
            .answer_challenge(
                cid,
                ContentId([1u8; 32]),
                operator(),
                115,
                Some(&valid_merkle_proof()),
            )
            .expect("a wrong answer must resolve the challenge, not error out");
        assert_eq!(res.outcome, ChallengeOutcome::Answered);
        assert_eq!(res.slashed_bond, 0);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Active);
    }

    /// The containment above must not reach the case it was not written for.
    ///
    /// An answer with no proof at all is a fact about the answer, not a
    /// limitation of the verifier, so it still costs the bond. Without this
    /// the flag would quietly turn every wrong answer free.
    #[test]
    fn the_unverifiable_proof_carve_out_does_not_cover_a_missing_proof() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let res = reg
            .answer_challenge(cid, ContentId([1u8; 32]), operator(), 115, None)
            .expect("an answer with no proof resolves as mismatched");
        assert_eq!(res.outcome, ChallengeOutcome::Mismatched);
        assert_eq!(res.slashed_bond, good_econ().operator_bond);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);
    }

    /// A mismatched answer costs the same as silence.
    ///
    /// The point of producing `Mismatched` at all: before it, a wrong answer
    /// returned `Err`, left the challenge unresolved and moved no bond, so it
    /// was strictly cheaper than staying quiet.
    #[test]
    fn a_mismatched_answer_slashes_the_full_bond_like_a_missed_deadline() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let res = reg
            .answer_challenge(cid, ContentId([1u8; 32]), operator(), 115, None)
            .unwrap();
        assert_eq!(res.outcome, ChallengeOutcome::Mismatched);
        assert_eq!(
            res.slashed_bond,
            good_econ().operator_bond,
            "a mismatched answer slashes the full operator bond, as Missed does"
        );
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);
    }

    /// One answer per challenge, whatever the answer was.
    ///
    /// The retry loop is the point: before `Mismatched` existed, a wrong
    /// answer returned `Err`, recorded nothing, and let the operator keep
    /// guessing. What must hold is that the first answer resolves the
    /// challenge, not what the first answer resolved to.
    ///
    /// The outcome is asserted through `results` rather than through
    /// `deal_status`, because the two are not the same claim. The deal is only
    /// slashed when the answer was wrong, and while
    /// `storage_challenge_proofs_are_checkable` reports false a proof-carrying
    /// answer is not treated as wrong; that half is held by
    /// `an_answer_carrying_a_proof_does_not_cost_the_bond_while_proofs_are_uncheckable`.
    #[test]
    fn a_mismatched_answer_resolves_the_challenge_so_it_cannot_be_retried() {
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
            Some(&valid_merkle_proof()),
        )
        .expect("first answer resolves");

        let err = reg
            .answer_challenge(
                cid,
                ContentId([2u8; 32]),
                operator(),
                116,
                Some(b"test-mock-proof"),
            )
            .expect_err("a resolved challenge must not accept a second answer");
        assert!(matches!(err, StorageError::ChallengeAlreadyResolved(_)));
        assert!(
            reg.results.contains_key(&cid),
            "the first answer must land in results, otherwise the challenge is \
             still open and the operator can keep guessing"
        );
    }

    #[test]
    fn a_missing_proof_still_slashes_rather_than_leaving_the_challenge_open() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        // Answering in time but with no proof at all is a wrong answer, not a
        // malformed request: the deal carries a storage_root, so a proof was
        // owed.
        let res = reg
            .answer_challenge(cid, ContentId([1u8; 32]), operator(), 115, None)
            .expect("an answer with no proof resolves as mismatched");
        assert_eq!(res.outcome, ChallengeOutcome::Mismatched);
        assert_eq!(res.slashed_bond, good_econ().operator_bond);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);
    }

    #[test]
    fn addressing_errors_are_still_errors_not_slashes() {
        // Only claims about stored bytes are slashable. Getting the deal, the
        // deadline or the identity wrong says nothing about whether the
        // operator kept the data, so those must not burn a bond.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();

        assert!(matches!(
            reg.answer_challenge(cid, ContentId([1u8; 32]), opener(), 115, None),
            Err(StorageError::NotTheOperator { .. })
        ));
        assert!(matches!(
            reg.answer_challenge(cid, ContentId([1u8; 32]), operator(), 200, None),
            Err(StorageError::DeadlineElapsed { .. })
        ));
        assert!(matches!(
            reg.answer_challenge(cid, ContentId([0u8; 32]), operator(), 115, None),
            Err(StorageError::InvalidMerkleProof(_))
        ));
        assert!(matches!(
            reg.answer_challenge(9_999, ContentId([1u8; 32]), operator(), 115, None),
            Err(StorageError::UnknownChallenge(_))
        ));

        assert_eq!(
            deal_status(&reg, deal_id),
            DealStatus::Active,
            "no addressing error may slash the deal"
        );
        assert!(
            reg.get_result(cid).is_none(),
            "an addressing error must leave the challenge open for a real answer"
        );
    }

    #[test]
    fn a_correct_answer_is_still_accepted_after_the_mismatch_path_exists() {
        // The slash path is only meaningful if the honest path still works.
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
            .expect("an honest answer must pass");
        assert_eq!(res.outcome, ChallengeOutcome::Answered);
        assert_eq!(res.slashed_bond, 0);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Active);
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
        // REGRESYON KILIDI - a0671c4'te silinmisti, geri yuklendi; SILME.
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
        // REGRESYON KILIDI - a0671c4'te silinmisti, geri yuklendi; SILME.
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
        // REGRESYON KILIDI - prune_content aktif deal'leri expire etmeli
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

        // Omitting proof_bytes on a production deal (storage_root present)
        // must not pass. It used to surface as `Err(InvalidMerkleProof)`,
        // which left the challenge unresolved and the operator free to retry;
        // it is now a `Mismatched` answer that slashes, on the same terms as
        // a missed deadline. The property under test is unchanged, a
        // production deal cannot be answered without a proof, but the
        // consequence is no longer cheaper than staying silent.
        let res = reg
            .answer_challenge(cid, ContentId([1u8; 32]), operator(), 115, None)
            .expect("a proofless answer resolves the challenge rather than erroring");
        assert_eq!(res.outcome, ChallengeOutcome::Mismatched);
        assert_eq!(res.slashed_bond, good_econ().operator_bond);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);
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

    /// And it must accept the challenge once the bond covers the range,
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
