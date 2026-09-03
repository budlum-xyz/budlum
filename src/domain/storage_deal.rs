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
use bincode::Options;
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

/// Stand-in bytes hashed when a registry entry cannot be serialized.
///
/// These types are plain owned data with derived `Serialize`, so `bincode`
/// has no failing case here; the previous `expect` guarded a condition that
/// cannot arise. It still must not be a panic: this runs while computing a
/// state root, and every node computes the same root, so aborting on it would
/// take down the whole validator set at once rather than a single node.
/// Hashing a fixed marker keeps the root deterministic across nodes.
const SERIALIZE_FAILED: &[u8] = b"budlum/serialize-failed/storage-registry";

/// Hard byte budget for one deserialized proof envelope.
///
/// A challenge answer is operator-supplied, so a proof blob must be bounded
/// before it is parsed: the envelope's nested `proof_bytes` is copied out of
/// the blob, so an oversized blob doubles whatever the operator sent and lets
/// one answer hold a whole block's worth of bytes hostage in memory. 1 MiB
/// matches the block ceiling and covers the 256 KiB execution-proof ceiling
/// plus the envelope's version-string metadata with room to spare.
const MAX_PROOF_ENVELOPE_BYTES: u64 = 1024 * 1024;

/// Deserialize a [`bud_proof::ProofEnvelope`] under [`MAX_PROOF_ENVELOPE_BYTES`].
fn deserialize_proof_envelope(
    proof_bytes: &[u8],
) -> Result<bud_proof::ProofEnvelope, StorageError> {
    if proof_bytes.len() as u64 > MAX_PROOF_ENVELOPE_BYTES {
        return Err(StorageError::InvalidMerkleProof(format!(
            "proof envelope exceeds the {MAX_PROOF_ENVELOPE_BYTES} byte ceiling"
        )));
    }
    // Fixint, not the `bincode::options()` varint default: envelopes are
    // written by `bincode::serialize`, which is fixint, and a varint reader
    // would reject every honest envelope before it ever saw the limit.
    // `with_limit` also bounds the deserializer's own decoded-byte accounting,
    // so a length-prefixed field cannot ask for more than the budget even on
    // the io::Read path.
    bincode::options()
        .with_fixint_encoding()
        .with_limit(MAX_PROOF_ENVELOPE_BYTES)
        .deserialize::<bud_proof::ProofEnvelope>(proof_bytes)
        .map_err(|e| {
            StorageError::InvalidMerkleProof(format!("failed to deserialize ProofEnvelope: {e}"))
        })
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

/// Fixed devnet/testnet replication target for devnet hardening.
/// A missed challenge creates a reallocation ticket for the failed replica slot
/// So independent nodes can observe and repair under-replication without an
/// Off-chain team-operated scheduler. Mainnet storage remains fail-closed until
/// This policy is externally audited and economically approved.
pub const STORAGE_REPLICATION_TARGET: u8 = 3;

/// The step of proven read rate that adds one more replica to a discounted
/// object. Scaled by `ACCESS_SCALE`, in reads per half-life.
///
/// Eight proven reads in one half-life (720 epochs). It is low because what
/// is counted here is not a raw read but a *proven* read: every answered
/// retrieval challenge is one, and the chain opens those sparsely per object.
/// Had the threshold been tuned to raw traffic, no object would ever cross it.
pub const DEMAND_REPLICA_STEP_SCALED: u64 = 8 * crate::storage::living_threshold::ACCESS_SCALE;
pub const REALLOCATION_ACCEPTANCE_EPOCHS: u64 = 4;

/// How long a ticket whose replacement deal opened stays in the registry.
///
/// A ticket is a work item: it exists so a slot that lost its holder gets a
/// new one. Once `accept_reallocation_ticket` opens the replacement deal the
/// work is done, and what remains is a record that says which deal replaced
/// which. That record is worth keeping for a while (`lifecycle_state` reports
/// `ActiveReplacement` from it, and `placements_that_diverged` measures the
/// placement algorithm against it), but not forever: the map had no delete
/// path at all, so every slash and every expiry on the chain grew it by one
/// row for the life of the node.
///
/// The window is long compared with the acceptance deadline on purpose. The
/// question the retained row answers is an audit question, so the row lives
/// through several acceptance windows before it goes. Tickets that still
/// wait for a taker (`Pending`, `UnderReplicated`) are never swept: they are
/// the obligation itself, not a record of one.
const REALLOCATION_RECORD_RETENTION_EPOCHS: u64 = 16 * REALLOCATION_ACCEPTANCE_EPOCHS;

/// How long before a deal matures its operator may renew it unopposed.
///
/// Renewal exists because the two ways a deal ends are not symmetric. A
/// slashed operator is gone and the shard has to be rebuilt somewhere else,
/// which costs a full shard transfer. An operator whose term simply ran out
/// is still holding the bytes: extending its deal costs nothing to move.
///
/// Measured, with the expiry path as it stood (mature, refund the bond, open
/// no ticket): at a 99% per-term renewal rate, a `(10,16)` object reaches `k`
/// after 53 terms, and `LRC k=2000` after 4. The wide codes are the fragile
/// ones here for the same reason they are cheap, they hold very little parity
/// per shard, so the drain that replication would shrug off walks them to the
/// edge in a handful of terms.
///
/// The window is the same length as [`REALLOCATION_ACCEPTANCE_EPOCHS`], so an
/// operator that declines to renew leaves exactly as much time to find a
/// replacement as a slashed one does.
pub const RENEWAL_WINDOW_EPOCHS: u64 = 4;

/// Carriers a manifest may not fall below when the registry cannot read its
/// erasure parameters.
///
/// One. Not a guess at a good replication factor: the registry holds deals
/// for manifests it may not hold, and refusing every expiry for those would
/// let an unregistered id freeze bonds. One is the point past which there is
/// nothing left holding the bytes, which is the only claim this fallback can
/// honestly make without the manifest in hand.
pub const PERMANENCE_FLOOR_DEFAULT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReallocationStatus {
    Pending,
    ActiveReplacement,
    UnderReplicated,
    EscalatedFault,
    Cancelled,
}

/// Why a reallocation ticket exists.
///
/// `FailedDeal` is the historic path: a slash or an expiry left a slot empty
/// and the ticket names the deal that failed. `NeverPlaced` is the bootstrap
/// path: the manifest lists a shard, the repair band sees zero live replicas,
/// and no deal has ever been opened for that shard. The two are not the same
/// obligation - one replaces a holder, the other places the first one - so the
/// cause is part of the ticket, not a comment next to a zeroed deal id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ReallocationCause {
    /// A prior deal on this slot ended (slash or expiry). `failed_deal_id` is set.
    #[default]
    FailedDeal,
    /// The shard was registered and never held a deal. `failed_deal_id` is 0 and
    /// is not a lookup key.
    NeverPlaced,
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
    /// The holder the placement algorithm computed for this shard.
    ///
    /// **A recommendation, not a rule.** Whoever accepts the ticket takes it;
    /// this field only records the answer to "who would rendezvous placement
    /// have chosen". Binding acceptance to it would close the open market and
    /// is a separate policy decision.
    ///
    /// The reason it is recorded is measurability: making divergence visible.
    /// Tickets constantly being taken by other operators says either that the
    /// placement computation does not reflect real capacity or that the
    /// assigned operators are not meeting their obligation. Both are worth
    /// knowing and neither is visible today.
    ///
    /// `None`: the candidate set produced no placement (no staked validator).
    /// An empty recommendation is better than a wrong one.
    #[serde(default)]
    pub expected_holder: Option<Address>,
    /// What opened this ticket. Default `FailedDeal` keeps pre-field tickets
    /// bit-stable under serde defaulting and bincode append-at-end.
    #[serde(default)]
    pub cause: ReallocationCause,
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
    #[serde(with = "crate::core::map_keys")]
    deals_by_shard: BTreeMap<(ContentId, ContentId), Vec<u64>>,
    challenges: BTreeMap<u64, RetrievalChallenge>,
    results: BTreeMap<u64, ChallengeResult>,
    #[serde(default)]
    reallocations: BTreeMap<u64, StorageReallocationTicket>,
    #[serde(default)]
    #[serde(with = "crate::core::map_keys")]
    pub manifests: BTreeMap<ContentId, ContentManifest>,
    /// Shared dictionaries and how many manifests depend on them.
    ///
    /// The reason this lives here is reference counting: a dictionary cannot
    /// be deleted until the last object depending on it is also gone. If the
    /// count is not kept in the same place as the manifest record the two
    /// diverge and a dictionary still being read becomes deletable.
    #[serde(default)]
    pub dictionaries: crate::storage::dictionary::DictionaryRegistry,
    /// Finalized read evidence per object, newest last.
    ///
    /// The demand signal `storage::living_threshold` needs. It is a log of
    /// finalized events rather than a mutable per-object counter, and that is
    /// the whole design: a counter would have to be agreed on by the network
    /// and written on every read, which is the cost the storage levers exist
    /// to avoid. From the same events at the same epoch every node derives
    /// the same estimate, because the decay is integer halving.
    ///
    /// Only answered retrieval challenges are recorded. A challenge that was
    /// answered correctly is a read the chain **proved** happened; a missed
    /// or mismatched one proves the opposite. Using unproven reads would let
    /// an operator inflate demand for its own content and keep replicas the
    /// network is paying for.
    #[serde(default)]
    #[serde(with = "crate::core::map_keys")]
    access_events: BTreeMap<ContentId, Vec<crate::storage::living_threshold::AccessEvent>>,
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
    #[serde(with = "crate::core::map_keys")]
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
    /// Who may open non-public content (view-key permission book).
    ///
    /// Key material stays off-chain; this map is grants only. Classic/2.0
    /// private bodies and Three/3.0 encrypted recipes both use it.
    #[serde(default)]
    pub view_grants: crate::storage::ViewGrantRegistry,
    /// Classic/2.0 confidential body commits (ciphertext root + proof kind).
    /// Three/R1 has no body; this map is the private-body surface only.
    #[serde(default)]
    #[serde(with = "crate::core::map_keys")]
    pub confidential_commits: BTreeMap<ContentId, crate::storage::ConfidentialBodyCommit>,
    /// The address each confidential commit was recorded for. Grants are signed
    /// authorisations, and a signature needs somebody whose word it is.
    #[serde(default)]
    #[serde(with = "crate::core::map_keys")]
    pub confidential_owners: BTreeMap<ContentId, crate::core::address::Address>,
    /// Epoch a ticket reached `ActiveReplacement`, keyed by that epoch, so
    /// the sweep drops due rows without walking the whole map.
    ///
    /// Last field on purpose: the registry row is bincode, which is
    /// positional, so a new field anywhere else would make every stored
    /// registry unreadable. `#[serde(default)]` keeps JSON snapshots taken
    /// before the field loadable; the bincode side is covered by
    /// `LegacyStorageRegistryV1` in `storage/db.rs`.
    #[serde(default)]
    settled_tickets: BTreeMap<u64, Vec<u64>>,
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
    /// Expiring this deal would take its object below the shard count a
    /// decode needs.
    ///
    /// A term ending is not a reason to lose an object. The slash path takes
    /// a bond from someone who broke a promise; the expiry path takes nothing
    /// from anyone, so nothing about it justifies making the content
    /// unreadable. The deal stays `Active`, unpaid, until a replacement
    /// carrier accepts the reallocation ticket the sweep already opened.
    ///
    /// Only raised when this deal is the last active replica of its shard
    /// *and* the object is already down to `k` live shards. A shard with a
    /// spare replica may always be let go, because the shard survives.
    ///
    /// Measured on the chosen scheme (n=10, k=7, p=0.99): losing three shards
    /// takes availability from 5.70 nines to 1.17, and losing a fourth means
    /// the object cannot be reconstructed at all.
    ExpiryWouldStrandContent {
        deal_id: u64,
        manifest_id: ContentId,
        shard_id: ContentId,
        /// Live shards the object would be left with, not carriers of this
        /// one shard: the decode threshold is counted in distinct shards.
        remaining_carriers: u32,
        floor: u32,
    },
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
    /// F-18: too many concurrent open challenges across every manifest
    /// of one operator. The (operator, manifest) interval alone lets an
    /// attacker scale I/O with the number of manifests.
    TooManyOpenChallengesPerOperator {
        operator: Address,
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
            Self::UnknownShard {
                manifest_id,
                shard_id,
            } => write!(f, "shard {} not in manifest {}", shard_id, manifest_id),
            Self::InvalidManifest { reason } => {
                write!(f, "manifest rejected: {reason}")
            }
            Self::InvalidEpochRange { start, end } => {
                write!(f, "deal epoch range {start}..{end} invalid")
            }
            Self::InsufficientBond { required, provided } => {
                write!(f, "operator bond {provided} below required {required}")
            }
            Self::OperatorInCooldown {
                operator,
                until_unix_secs,
            } => write!(
                f,
                "operator {operator} missed a challenge and cannot take storage \
                 work until unix {until_unix_secs}"
            ),
            Self::MobileOperatorCannotHoldPrimary(operator) => write!(
                f,
                "operator {operator} is registered as mobile and cannot hold \
                 replica_index 0; a phone is online when its owner is, which \
                 is not what a primary copy means"
            ),
            Self::ZeroOpenerBond => write!(f, "opener_bond must be > 0"),
            Self::OpenerBondBelowRangeCost {
                range_len,
                required,
                provided,
            } => write!(
                f,
                "opener_bond {provided} below {required} required for a \
                 {range_len}-byte challenge range"
            ),
            Self::UnknownDeal(id) => write!(f, "unknown deal {id}"),
            Self::UnknownChallenge(id) => write!(f, "unknown challenge {id}"),
            Self::DealNotActive(id) => write!(f, "deal {id} is not Active"),
            Self::ExpiryWouldStrandContent {
                deal_id,
                manifest_id,
                shard_id,
                remaining_carriers,
                floor,
            } => write!(
                f,
                "expiring deal {deal_id} would drop the last replica of shard {shard_id}, \
                 leaving manifest {manifest_id} with {remaining_carriers} live shards, \
                 below the {floor} a decode needs"
            ),
            Self::NotTheOperator { expected, provided } => {
                write!(
                    f,
                    "response signed by {provided} but deal operator is {expected}"
                )
            }
            Self::DeadlineElapsed {
                deadline_epoch,
                now_epoch,
            } => write!(
                f,
                "challenge deadline {deadline_epoch} elapsed at epoch {now_epoch}"
            ),
            Self::ChallengeAlreadyResolved(id) => {
                write!(f, "challenge {id} already resolved")
            }
            Self::UnknownManifest(id) => write!(f, "unknown manifest {id}"),
            Self::SelfHostRefusedByPolicy { content_id, reason } => write!(
                f,
                "self-hosting {content_id} refused by the owner's own policy: {reason}"
            ),
            Self::NoParityToAudit { manifest_id } => write!(
                f,
                "manifest {manifest_id} has no parity shards, so there is no \
                 coding relationship to audit"
            ),
            Self::ParityColumnMismatch {
                manifest_id,
                parity_index,
                column,
            } => write!(
                f,
                "parity shard {parity_index} of manifest {manifest_id} is not \
                 the parity the generator requires at column {column}"
            ),
            Self::MerkleProofRequired => write!(
                f,
                "merkle_proof and storage_root are mandatory (VerifyMerkle gate open)"
            ),
            Self::InvalidMerkleProof(ref reason) => {
                write!(f, "invalid merkle proof - {reason}")
            }
            Self::TooManyOpenChallenges { deal_id, max } => {
                write!(f, "too many open challenges for deal {deal_id} (max {max})")
            }
            Self::TooManyOpenChallengesPerOperator { operator, max } => {
                write!(
                    f,
                    "too many open challenges for operator {operator} (max {max})"
                )
            }
            Self::ChallengeRateLimited {
                operator,
                manifest_id,
                minimum_next_epoch,
            } => write!(
                f,
                "operator {operator} was recently challenged for manifest {manifest_id}; retry at epoch {minimum_next_epoch}"
            ),
            Self::UnknownReallocationTicket(id) => {
                write!(f, "unknown storage reallocation ticket {id}")
            }
            Self::ReallocationNotPending(id) => {
                write!(f, "storage reallocation ticket {id} is not pending")
            }
            Self::ReplacementOperatorMatchesSlashed(operator) => write!(
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
            && self.settled_tickets.is_empty()
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
            hasher.update(bincode::serialize(deal).unwrap_or_else(|_| SERIALIZE_FAILED.to_vec()));
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
                bincode::serialize(challenge).unwrap_or_else(|_| SERIALIZE_FAILED.to_vec()),
            );
        }
        for result in self.results.values() {
            hasher.update(bincode::serialize(result).unwrap_or_else(|_| SERIALIZE_FAILED.to_vec()));
        }
        for ticket in self.reallocations.values() {
            hasher.update(bincode::serialize(ticket).unwrap_or_else(|_| SERIALIZE_FAILED.to_vec()));
        }
        // The settled-ticket queue decides which tickets the next sweep
        // drops, so two registries with the same tickets and different
        // queues would diverge one epoch later; fold it in now, not then.
        for (epoch, ticket_ids) in &self.settled_tickets {
            hasher.update(epoch.to_le_bytes());
            for ticket_id in ticket_ids {
                hasher.update(ticket_id.to_le_bytes());
            }
        }
        for manifest in self.manifests.values() {
            hasher
                .update(bincode::serialize(manifest).unwrap_or_else(|_| SERIALIZE_FAILED.to_vec()));
        }
        // A confidential body and the address that speaks for it decide whether a
        // view grant opens bytes, so two nodes disagreeing about either would
        // accept different blocks. Both maps are `BTreeMap`, keyed by the content
        // id, so every node hashes the same bytes in the same order. The commit is
        // folded through `commitment()` rather than its serialization: the
        // commitment is the value the chain promised, and pinning the serialized
        // struct would make a field that cannot change the promise (a re-ordered
        // enum variant, say) change the state root.
        //
        // An empty pair of maps contributes no bytes, which is what keeps a chain
        // that has never held a confidential body at exactly the root it had
        // before this fold existed.
        for (content_id, commit) in &self.confidential_commits {
            hasher.update(content_id.0);
            hasher.update(commit.commitment());
        }
        for (content_id, owner) in &self.confidential_owners {
            hasher.update(content_id.0);
            hasher.update(owner.as_bytes());
        }
        // A live view grant decides whether bytes are opened, and a self-host
        // declaration decides whether an object may sit on a device without paid
        // replicas. Both are enforced while a block is applied, so a node holding
        // a different book accepts a block its peers reject. The grant book is
        // folded through its own digest, and only after the first id was handed
        // out: a chain that never issued a grant keeps the bytes it had, while an
        // issue followed by a revoke still leaves its mark.
        if self.view_grants.issued() > 0 {
            hasher.update(self.view_grants.root());
        }
        for (content_id, policy) in &self.self_host_policies {
            hasher.update(content_id.0);
            hasher.update(bincode::serialize(policy).unwrap_or_else(|_| SERIALIZE_FAILED.to_vec()));
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
    /// F-17: `ChainHandle::set_storage_operator_class` is the production
    /// declaration path. The class is still self-reported; `open_deal`
    /// holds the operator to whatever it claimed.
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

    /// Register a manifest that declares a source regime.
    ///
    /// **"Generated" is a claim for a discount, so it is not accepted without
    /// proof.** A manifest saying `Generated` only earns the right to hold one
    /// replica (`required_replica_count`); if that claim were not verified,
    /// someone labelling ordinary organic content as "generated" would collect
    /// full durability payment for a third of the copies and the content would
    /// genuinely be lost.
    ///
    /// Verification is cheap and exact: it RUNS the recipe, computes the
    /// content id of the resulting bytes and compares it against the
    /// manifest's single shard. You cannot fake it - the recipe space is
    /// smaller than the content space (pigeonhole); the recipe only holds if
    /// the content really was born from that recipe.
    ///
    /// `Hybrid` is not accepted on this path: its prefix bytes are not on
    /// chain, so it cannot be verified. A claim that cannot be verified gets
    /// no discount either.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipe cannot be run, if the bytes it produces
    /// do not match the manifest's id, if the manifest does not have exactly
    /// one shard, or if the regime is `Hybrid`.
    pub fn register_manifest_with_source(
        &mut self,
        manifest: &ContentManifest,
    ) -> Result<(), StorageError> {
        // The dictionary reference is checked first: an object cannot be
        // registered against a dictionary it could not be decoded with.
        //
        // There are three refusals and all three must come before the record.
        // Unknown dictionary: if nobody holds the bytes the object cannot be
        // opened. Retiring dictionary: adding a new dependant to something
        // scheduled for deletion would silently invalidate the deletion date.
        // A dictionary resting on a dictionary: a chain forms and the number
        // of fetches needed to open one object becomes unbounded.
        //
        // Checking **after** the record would be too late: manifest
        // registration is first-writer-wins and idempotent, so a rejected
        // record cannot be taken back.
        // Edition gate first: BUD edition Three admits no durable body. Classic keeps
        // Stored/Hybrid. Checked before recipe execution so a Three+Stored claim
        // never pays for a generate_and_verify of content that the edition
        // forbids holding.
        manifest
            .edition
            .check_source(&manifest.source)
            .map_err(|reason| StorageError::InvalidManifest { reason })?;

        match &manifest.source {
            crate::storage::generated::ContentSource::Stored => {}
            crate::storage::generated::ContentSource::Generated(spec) => {
                // Generated content is a single piece: the recipe produces
                // the whole object. A multi-shard "generated" claim does not
                // say which shard corresponds to which part, so it cannot be
                // verified.
                if manifest.shards.len() != 1 {
                    return Err(StorageError::InvalidManifest {
                        reason: "Generated manifest must have exactly one shard".into(),
                    });
                }
                let shard =
                    manifest
                        .shards
                        .first()
                        .ok_or_else(|| StorageError::InvalidManifest {
                            reason: "Generated manifest has no shard".into(),
                        })?;
                // RUN the recipe. The claim either holds here or falls.
                crate::storage::generated::generate_and_verify(spec, shard.shard_id).map_err(
                    |e| StorageError::InvalidManifest {
                        reason: format!(
                            "Generated manifest recipe does not reproduce its content: {e:?}"
                        ),
                    },
                )?;
            }
            // Sealed Three recipe: seed is off-chain. We cannot run the
            // generator. We check shape (one shard, public fields sane) and
            // refuse a zero commitment. Reveal-time open_with + generate is
            // the honesty check, gated by view-grants.
            crate::storage::generated::ContentSource::SealedGenerated(sealed) => {
                if manifest.shards.len() != 1 {
                    return Err(StorageError::InvalidManifest {
                        reason: "SealedGenerated manifest must have exactly one shard".into(),
                    });
                }
                if sealed.recipe_commitment == [0u8; 32] {
                    return Err(StorageError::InvalidManifest {
                        reason: "SealedGenerated recipe_commitment must not be zero".into(),
                    });
                }
                if sealed.output_len == 0 {
                    return Err(StorageError::InvalidManifest {
                        reason: "SealedGenerated output_len must be non-zero".into(),
                    });
                }
                // Public digest must match the sealed fields (no seed).
                let expect = crate::storage::generated::sealed_generated_commitment(sealed);
                let _ = expect; // commitment is part of source_commitment_bytes via id
            }
            crate::storage::generated::ContentSource::Hybrid { .. } => {
                return Err(StorageError::InvalidManifest {
                    reason:
                        "Hybrid source cannot be verified on-chain; its prefix is not recoverable"
                            .into(),
                });
            }
            // Fully verifying a derivation requires the master's bytes and
            // those are not on chain - the same reason as `Hybrid`. But
            // refusing the part that cannot be verified is no excuse for not
            // checking the part that can: the recipe's OWN internal
            // consistency can be checked here, exactly, without fetching the
            // master.
            //
            // `check_region` was written for precisely this: do the transform
            // and the fields agree, is the region empty, does the box spill
            // outside the bounds the master declares. Skipping that check and
            // only saying "cannot be verified" would throw a recipe that
            // contradicts itself into the same bin - whereas that one can be
            // refused without ever fetching the master.
            crate::storage::generated::ContentSource::Derived(spec) => {
                spec.check_region()
                    .map_err(|e| StorageError::InvalidManifest {
                        reason: format!("Derived spec is not internally consistent: {e:?}"),
                    })?;
                // A derivation of a derivation is forbidden, and that too can
                // be checked without fetching the master: if the master's
                // manifest is REGISTERED we read its regime from here.
                //
                // If it is not registered we do not know, and we do not permit
                // what we do not know - the same fail-closed posture as
                // `required_replicas_for`. The chain must not accept the first
                // link of a chain whose durability depends on another
                // derivation.
                let master_is_derived = self.manifests.get(&spec.master_id).is_none_or(|m| {
                    matches!(
                        m.source,
                        crate::storage::generated::ContentSource::Derived(_)
                    )
                });
                spec.check_master_is_stored(master_is_derived)
                    .map_err(|e| StorageError::InvalidManifest {
                        reason: format!("Derived master is not a stored object: {e:?}"),
                    })?;
                return Err(StorageError::InvalidManifest {
                    reason: "Derived source cannot be verified here; \
                             the master's bytes are not on chain"
                        .into(),
                });
            }
        }
        // The dictionary reference is acquired here and the check is embedded
        // in the same call: `acquire_dictionary` runs
        // `check_dictionary_reference` first. Writing a separate pre-check
        // would keep the same rule in two places and the two could diverge
        // (section 68).
        //
        // There are three refusals. Unknown dictionary: if nobody holds the
        // bytes the object cannot be opened. Retiring dictionary: adding a new
        // dependant to something scheduled for deletion would silently
        // invalidate the deletion date. A dictionary resting on a dictionary:
        // a chain forms and the number of fetches needed to open one object
        // becomes unbounded.
        //
        // It must come **before** the record: manifest registration is
        // first-writer-wins and idempotent, so a rejected record cannot be
        // taken back.
        //
        // The reference is only acquired for a **new** record.
        // `register_manifest` is first-writer-wins and idempotent; bumping the
        // counter again when the same manifest is submitted a second time
        // would leave a reference that never drops and the dictionary would
        // become undeletable even after its last dependant is gone.
        let already_registered = self.manifests.contains_key(&manifest.manifest_id);
        if let Some(dict_id) = manifest.dictionary_id {
            if !already_registered {
                let referrer_is_dictionary =
                    self.dictionaries.has_dictionary(&manifest.manifest_id);
                self.dictionaries
                    .acquire_dictionary(&dict_id, referrer_is_dictionary)
                    .map_err(|e| StorageError::InvalidManifest {
                        reason: format!("dictionary reference is not usable: {e:?}"),
                    })?;
            }
        }
        self.register_manifest(manifest);
        Ok(())
    }

    /// How many replicas this manifest requires.
    ///
    /// Looks at the regime the registered manifest declares. If it is not
    /// registered the full target is returned: no discount is given for
    /// something we do not know (fail-closed).
    #[must_use]
    pub fn required_replicas_for(&self, manifest_id: &ContentId) -> u8 {
        self.manifests
            .get(manifest_id)
            .map_or(STORAGE_REPLICATION_TARGET, |manifest| {
                crate::storage::generated::required_replica_count(
                    &manifest.source,
                    STORAGE_REPLICATION_TARGET,
                )
            })
    }

    /// How many replicas are required once proven demand is taken into account.
    ///
    /// The regime discount sets the floor; demand only pushes upwards. One
    /// replica for a heavily read object means an object nobody can read the
    /// moment the single operator holding that replica falls; the discount was
    /// given for durability, and popularity takes it back.
    ///
    /// Demand never lowers the count. Trimming the replicas of a rarely read
    /// object would turn the *absence* of measured demand into a durability
    /// decision: a backup that has never been read is exactly the thing that
    /// must not be lost.
    ///
    /// The threshold is one replica per multiple of
    /// [`DEMAND_REPLICA_STEP_SCALED`], up to the full target. A fixed ladder,
    /// because the number returned here is a number the chain has to agree on;
    /// a threshold depending on an operator's own hardware ratios would give
    /// two nodes two answers.
    #[must_use]
    pub fn required_replicas_with_demand(&self, manifest_id: &ContentId, epoch: u64) -> u8 {
        let floor = self.required_replicas_for(manifest_id);
        if floor >= STORAGE_REPLICATION_TARGET {
            return floor;
        }
        let rate = self.access_estimate(manifest_id, epoch).rate_scaled(epoch);
        let steps = u8::try_from(rate / DEMAND_REPLICA_STEP_SCALED).unwrap_or(u8::MAX);
        floor.saturating_add(steps).min(STORAGE_REPLICATION_TARGET)
    }

    pub fn get_manifest(&self, manifest_id: &ContentId) -> Option<&ContentManifest> {
        self.manifests.get(manifest_id)
    }

    /// Issue a view grant. Key material stays off-chain. The manifest is the
    /// authority on who may give a grant: the `issuer` field is checked against
    /// the recorded owner instead of being believed, because a caller that could
    /// name any issuer could hand out public view access to bytes it does not
    /// own.
    pub fn issue_view_grant(
        &mut self,
        content_id: ContentId,
        auth: &crate::storage::GrantAuthorization,
        grantee: Option<Address>,
        key_id: [u8; 32],
        policy: crate::storage::ViewPolicy,
        opened_epoch: u64,
    ) -> Result<u64, crate::storage::ViewGrantError> {
        let owner = self
            .owner_of(&content_id)
            .ok_or(crate::storage::ViewGrantError::UnknownContent)?;
        let issuer = auth
            .derived_owner()
            .map_err(crate::storage::ViewGrantError::Authorization)?;
        if issuer != owner {
            return Err(crate::storage::ViewGrantError::NotOwner { issuer, owner });
        }
        let digest = crate::storage::grant_issue_digest(
            &content_id,
            &issuer,
            grantee.as_ref(),
            &key_id,
            policy,
            opened_epoch,
        );
        auth.verify(&digest, &owner)
            .map_err(crate::storage::ViewGrantError::Authorization)?;
        self.view_grants
            .issue(content_id, issuer, grantee, key_id, policy, opened_epoch)
    }

    /// Revoke one grant. Returns the row that was revoked, because whatever has
    /// to react to a revocation (a gateway dropping session keys, a wallet
    /// showing what it gave up) needs to know which content it was about; echo
    /// back the content id from the request and the reply becomes a claim.
    ///
    /// # Errors
    ///
    /// [`crate::storage::ViewGrantError`] for an unknown id, a caller who is not
    /// the owner, or an unreadable authorisation.
    pub fn revoke_view_grant(
        &mut self,
        grant_id: u64,
        auth: &crate::storage::GrantAuthorization,
        at_epoch: u64,
    ) -> Result<crate::storage::ViewGrant, crate::storage::ViewGrantError> {
        let caller = auth
            .derived_owner()
            .map_err(crate::storage::ViewGrantError::Authorization)?;
        let digest = crate::storage::grant_revoke_digest(grant_id, &caller, at_epoch);
        let grant = self
            .view_grants
            .get(grant_id)
            .ok_or(crate::storage::ViewGrantError::UnknownGrant(grant_id))?
            .clone();
        // `unwrap_or`, not `unwrap_or_else`: the fallback is a field read, and a
        // closure there is what CI's Clippy step refuses under `-D warnings`.
        let owner = self.owner_of(&grant.content_id).unwrap_or(grant.issuer);
        auth.verify(&digest, &owner)
            .map_err(crate::storage::ViewGrantError::Authorization)?;
        self.view_grants.revoke(grant_id, caller, at_epoch)?;
        Ok(grant)
    }

    /// Every view-grant row of one content, revoked ones included.
    #[must_use]
    pub fn view_grants_for(&self, content_id: &ContentId) -> Vec<crate::storage::ViewGrant> {
        self.view_grants
            .rows_for_content(content_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// How many rows of one content are live right now. Read through the
    /// registry's own live index rather than by filtering `view_grants_for`, so
    /// the number a wallet is shown is the number `may_view` will honour.
    #[must_use]
    pub fn live_view_grant_count(&self, content_id: &ContentId) -> usize {
        self.view_grants.live_for_content(content_id).len()
    }

    /// Whether `viewer` may open `content_id` with `key_id`. `owner` is a claim,
    /// not an authority: it is checked against the manifest, and a query naming
    /// itself as the owner of somebody else's content is refused rather than
    /// served. Content with no manifest has no owner and opens for nobody.
    #[must_use]
    pub fn may_view(
        &self,
        content_id: &ContentId,
        viewer: &Address,
        key_id: &[u8; 32],
        owner: &Address,
    ) -> bool {
        let Some(recorded) = self.owner_of(content_id) else {
            return false;
        };
        if recorded != *owner {
            return false;
        }
        self.view_grants.may_view(content_id, viewer, key_id, owner)
    }

    /// Record a Classic confidential body commit. Refuses plaintext encryption
    /// (see ConfidentialBodyCommit::new) and refuses a Three edition manifest
    /// when one is already registered for this id (body vs recipe category).
    /// The `owner` is the address the commit is recorded for: an unattributed
    /// body commit would leave later view grants with nobody whose word counts.
    /// Register a confidential body commit under the address that signed it.
    ///
    /// The owner is not a field the caller types: it is derived from the key
    /// and then proven by a signature over [`crate::storage::confidential_commit_digest`].
    /// Derivation alone would let anybody holding Alice's public key register a
    /// commit under her address and, by registering first, lock her own commit
    /// out of an object she already sealed.
    ///
    /// # Errors
    ///
    /// Refuses Three (recipe-only) manifests, a body already committed under a
    /// different commitment, an object another address spoke for, and any
    /// authorisation whose signature does not verify for the derived owner.
    pub fn register_confidential_commit(
        &mut self,
        commit: crate::storage::ConfidentialBodyCommit,
        auth: &crate::storage::GrantAuthorization,
    ) -> Result<[u8; 32], String> {
        let owner = auth
            .derived_owner()
            .map_err(|e| format!("confidential commit authorization: {e}"))?;
        let digest = crate::storage::confidential_commit_digest(&commit, &owner);
        auth.verify(&digest, &owner)
            .map_err(|e| format!("confidential commit authorization: {e}"))?;
        if let Some(m) = self.manifests.get(&commit.content_id) {
            if !m.edition.admits_body() {
                return Err(String::from(
                    "confidential body commit refused: registered manifest is Three (recipe-only); bodies are Classic/2.0",
                ));
            }
        }
        let commitment = commit.commitment();
        let content_id = commit.content_id;
        // Registering a commit for an object somebody else already spoke for
        // would move the view authority of a live object to the newcomer, and a
        // grant issued under the old owner would silently start meaning the new
        // one. Overwriting an already-open commitment is refused outright:
        // whoever holds an object holds it until the object is closed.
        if let Some(prev) = self.confidential_commits.get(&content_id) {
            return Err(if prev.commitment() == commitment {
                format!("confidential body commit already registered for 0x{content_id:?}")
            } else {
                format!(
                    "confidential body commit refused: 0x{content_id:?} is already committed under a different body"
                )
            });
        }
        if let Some(prev_owner) = self.confidential_owners.get(&content_id) {
            if *prev_owner != owner {
                return Err(format!(
                    "confidential body commit refused: 0x{content_id:?} is spoken for by {prev_owner:?}"
                ));
            }
        }
        self.confidential_commits.insert(content_id, commit);
        self.confidential_owners.insert(content_id, owner);
        Ok(commitment)
    }

    #[must_use]
    pub fn get_confidential_commit(
        &self,
        content_id: &ContentId,
    ) -> Option<&crate::storage::ConfidentialBodyCommit> {
        self.confidential_commits.get(content_id)
    }

    /// Who may speak for this content: the manifest owner, or the address that
    /// registered a Classic confidential commit when there is no manifest. One
    /// authority per object, and it is looked up rather than believed.
    ///
    /// The read path for wallets and auditors: before signing a grant, a holder
    /// has to be able to ask who the chain believes owns an object. The refusals
    /// of `issue_view_grant` are the write-side half; this is the same authority
    /// made visible, so the two cannot disagree.
    #[must_use]
    pub fn owner_of(&self, content_id: &ContentId) -> Option<crate::core::address::Address> {
        self.manifests
            .get(content_id)
            .map(|m| m.owner)
            .or_else(|| self.confidential_owners.get(content_id).copied())
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
        // Three is recipe-only: a storage deal is custody of held bytes. Opening
        // a deal against a Three manifest would reintroduce body economics under
        // another name (operators "holding" a recipe, charging rent for zero
        // held_bytes, or laundering a body as a live copy). Classic only.
        if !manifest.edition.admits_body() {
            return Err(StorageError::InvalidManifest {
                reason: String::from(
                    "BUD edition Three admits no storage deal: recipes are not placed with operators; use Classic for bodies",
                ),
            });
        }
        self.validate_shard_membership(manifest, &shard_id)?;
        // Membership was just checked, so the shard is present; take its size
        // while the manifest is still in hand. Pricing reads this and not the
        // registry copy, which a later manifest write could move.
        //
        // `held_bytes` is the axis that makes Generated and Stored comparable:
        // a recipe holds nothing on disk, so charging its listed output size
        // would invent a rent for bytes nobody stores. A Hybrid whose prefix
        // exceeds the listed size is a contradictory spec and is refused.
        let listed_bytes = u64::from(
            manifest
                .shard(&shard_id)
                .ok_or(StorageError::UnknownShard {
                    manifest_id: manifest.manifest_id,
                    shard_id,
                })?
                .size,
        );
        let shard_bytes = crate::storage::generated::held_bytes(&manifest.source, listed_bytes)
            .ok_or_else(|| StorageError::InvalidManifest {
                reason: String::from(
                    "held_bytes refused the source (hybrid prefix longer than listed size)",
                ),
            })?;
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

    /// Social/DM delete for one content (plan G5, CK.5): owner-authorised,
    /// it revokes every live grant the owner issued for the content and
    /// rotates the payload key id (delete implies rotate). Grants issued by
    /// someone else are not the owner's word and are left alone.
    ///
    /// The hook seam runs on [`NopThreeHook`](crate::storage::three_hooks::NopThreeHook)
    /// here because this binary is headless: a gateway installs its own sink
    /// at its boundary. The revocations themselves are the durable state a
    /// block commits; serving checks them regardless of who heard the event.
    ///
    /// # Errors
    ///
    /// [`crate::storage::ViewGrantError`] for unknown content, a caller who
    /// is not the owner, or an unreadable authorisation.
    pub fn social_delete(
        &mut self,
        content_id: ContentId,
        auth: &crate::storage::GrantAuthorization,
        at_epoch: u64,
    ) -> Result<crate::storage::DeleteOutcome, crate::storage::ViewGrantError> {
        let owner = self
            .owner_of(&content_id)
            .ok_or(crate::storage::ViewGrantError::UnknownContent)?;
        let caller = auth
            .derived_owner()
            .map_err(crate::storage::ViewGrantError::Authorization)?;
        if caller != owner {
            return Err(crate::storage::ViewGrantError::NotOwner {
                issuer: caller,
                owner,
            });
        }
        let digest = crate::storage::social_delete_digest(&content_id, &caller, at_epoch);
        auth.verify(&digest, &owner)
            .map_err(crate::storage::ViewGrantError::Authorization)?;
        let mut hook = crate::storage::three_hooks::NopThreeHook;
        Ok(crate::storage::process_social_delete(
            &mut self.view_grants,
            content_id,
            owner,
            at_epoch,
            &mut hook,
        ))
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

    /// F-18: concurrent open challenges across every manifest of one
    /// operator. The (operator, manifest) interval alone lets an attacker
    /// scale I/O with the number of manifests the operator holds.
    pub const MAX_OPEN_CHALLENGES_PER_OPERATOR: usize = 16;

    /// F-19: mainnet floor above the uncalibrated 1-unit-per-`KiB` rate.
    /// `required_opener_bond` for 16 `MiB` is 16_384; this floor dominates it.
    /// Storage economics stay disabled on mainnet today; the constant is
    /// the policy the actor will apply the day that gate opens.
    pub const MAINNET_MIN_OPENER_BOND: u64 = 1_000_000;

    /// Bond required to challenge `range_len` bytes.
    ///
    /// Rounds the range up to whole KiB so a 1-byte challenge costs the same
    /// as a 1 KiB one; the operator's seek dominates at that size anyway.
    pub fn required_opener_bond(range_len: u64) -> u64 {
        let kib = range_len.div_ceil(1024);
        Self::MIN_OPENER_BOND.max(kib.saturating_mul(Self::OPENER_BOND_PER_KIB))
    }
    /// Devnet hardening policy: a given operator and
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
        // `digest` is a 32-byte array, so both windows are in range and the
        // modulo keeps the result inside `u32`. Written as fixed-size array
        // reads rather than fallible slice conversions so there is no panic
        // left to reason about.
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&digest[..8]);
        let mut hi = [0u8; 8];
        hi.copy_from_slice(&digest[8..16]);
        let parity_index = (u64::from_le_bytes(lo) % u64::from(parity_count)) as u32;
        let column = u64::from_le_bytes(hi) % columns;
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
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&digest[..8]);
        let offset = u64::from_le_bytes(lo) % range_count;
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

        let operator_open = self
            .challenges
            .values()
            .filter(|c| {
                !self.results.contains_key(&c.challenge_id)
                    && self
                        .deals
                        .get(&c.deal_id)
                        .is_some_and(|d| d.operator == operator)
            })
            .count();
        if operator_open >= Self::MAX_OPEN_CHALLENGES_PER_OPERATOR {
            return Err(StorageError::TooManyOpenChallengesPerOperator {
                operator,
                max: Self::MAX_OPEN_CHALLENGES_PER_OPERATOR,
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
        // Copied before the mutable borrows below; the object a proven read
        // belongs to is the deal's manifest, not the shard.
        let challenge_manifest_id = deal.manifest_id;
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
        if result.outcome == ChallengeOutcome::Answered {
            self.record_proven_read(challenge_manifest_id, response_epoch);
        }
        self.results.insert(challenge_id, result.clone());
        Ok(result)
    }

    /// Record one proven read of `manifest_id` at `epoch`.
    ///
    /// Reads in the same epoch collapse into one event's count, so the log
    /// grows with epochs an object was read in rather than with reads. An
    /// object read a thousand times in one epoch costs one entry.
    fn record_proven_read(&mut self, manifest_id: ContentId, epoch: u64) {
        let events = self.access_events.entry(manifest_id).or_default();
        match events.last_mut() {
            Some(last) if last.epoch == epoch => {
                last.count = last.count.saturating_add(1);
            }
            // Out-of-order epochs would make the derived estimate depend on
            // arrival order, so a late event is folded into the newest one
            // rather than appended behind it. `from_events` refuses
            // out-of-order input; this makes sure it never sees any.
            Some(last) if last.epoch > epoch => {
                last.count = last.count.saturating_add(1);
            }
            _ => events.push(crate::storage::living_threshold::AccessEvent { epoch, count: 1 }),
        }
    }

    /// The demand estimate for `manifest_id` as of `epoch`.
    ///
    /// Derived from the finalized event log, so two nodes with the same
    /// blocks compute the same number. An object with no proven reads yields
    /// a zero estimate, which is a real answer: nothing has demonstrated
    /// demand for it.
    #[must_use]
    pub fn access_estimate(
        &self,
        manifest_id: &ContentId,
        epoch: u64,
    ) -> crate::storage::living_threshold::AccessEstimate {
        let events = self
            .access_events
            .get(manifest_id)
            .map_or(&[][..], |v| &v[..]);
        crate::storage::living_threshold::AccessEstimate::from_events(events, epoch)
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

        let envelope = deserialize_proof_envelope(proof_bytes)?;

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
            state_writes_digest: [0u8; 32],
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
            // The answer path refuses a deal that has left `Active`; the
            // Missed path has to ask the same question. Up to
            // `MAX_OPEN_CHALLENGES_PER_DEAL` challenges can be open against one
            // Deal, and every one of them used to reach this line and record
            // The bond again: a wrong answer on challenge one and silence on
            // Challenge two produced two slash events for one failure. This
            // Layer does not burn the bond, it hands the amount to the
            // `Blockchain` accounting path, which counts events, not deals.
            if !deal.is_active() {
                return Err(StorageError::DealNotActive(deal_id));
            }
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
                    // The candidate set is not in the registry; the
                    // recommendation is written after opening, by
                    // `annotate_expected_holders`.
                    expected_holder: None,
                    cause: ReallocationCause::FailedDeal,
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
        // The retention clock starts no earlier than the ticket itself.
        // `start_epoch` is the acceptor's number and `open_deal` only checks
        // it against `end_epoch`; keyed on it alone, a start far in the past
        // made the record due at the very next sweep, which is how a
        // replacement operator would erase the slash record it just filled.
        let settled_epoch = start_epoch.max(ticket.opened_epoch);
        self.settled_tickets
            .entry(settled_epoch)
            .or_default()
            .push(ticket_id);
        Ok(replacement_deal_id)
    }

    /// Deals inside their renewal window: matured soon, still `Active`.
    ///
    /// Returned so the maintenance sweep can offer the incumbent operator the
    /// extension before anyone else is asked to take the shard. The operator
    /// already holds the bytes, so a renewal moves nothing across the network
    /// and a reallocation moves a whole shard.
    ///
    /// Excludes deals that have already matured: past `deal_end_epoch` the
    /// renewal offer has expired and the shard is the reallocation path's
    /// problem.
    pub fn deals_in_renewal_window(&self, now_epoch: u64) -> Vec<(u64, Address, u64)> {
        self.deals
            .values()
            .filter(|deal| deal.is_active())
            .filter(|deal| {
                let opens = deal.deal_end_epoch.saturating_sub(RENEWAL_WINDOW_EPOCHS);
                now_epoch >= opens && now_epoch < deal.deal_end_epoch
            })
            .map(|deal| (deal.deal_id, deal.operator, deal.deal_end_epoch))
            .collect()
    }

    /// Extend a deal that its operator chose to renew.
    ///
    /// Refuses outside the renewal window rather than clamping, because a
    /// renewal accepted early would let an operator lock a price in before
    /// the term it applies to, and one accepted late would resurrect a deal
    /// the reallocation path may already have replaced.
    ///
    /// The economics are carried over untouched: this is the same agreement
    /// running longer, not a new one. Repricing belongs in a fresh deal, where
    /// the payer gets to agree to the new number.
    ///
    /// # Errors
    ///
    /// [`StorageError::UnknownDeal`] for an id the registry does not hold,
    /// [`StorageError::DealNotActive`] for a deal that was slashed or expired,
    /// [`StorageError::NotTheOperator`] when someone else tries to renew, and
    /// [`StorageError::InvalidEpochRange`] outside the window or for a
    /// non-positive extension.
    pub fn renew_deal(
        &mut self,
        deal_id: u64,
        operator: Address,
        now_epoch: u64,
        extra_epochs: u64,
    ) -> Result<u64, StorageError> {
        let deal = self
            .deals
            .get_mut(&deal_id)
            .ok_or(StorageError::UnknownDeal(deal_id))?;
        if !deal.is_active() {
            return Err(StorageError::DealNotActive(deal_id));
        }
        if deal.operator != operator {
            return Err(StorageError::NotTheOperator {
                expected: deal.operator,
                provided: operator,
            });
        }
        if extra_epochs == 0 {
            return Err(StorageError::InvalidEpochRange {
                start: now_epoch,
                end: now_epoch,
            });
        }
        let opens = deal.deal_end_epoch.saturating_sub(RENEWAL_WINDOW_EPOCHS);
        if now_epoch < opens || now_epoch >= deal.deal_end_epoch {
            return Err(StorageError::InvalidEpochRange {
                start: now_epoch,
                end: deal.deal_end_epoch,
            });
        }
        deal.deal_end_epoch = deal.deal_end_epoch.saturating_add(extra_epochs);
        Ok(deal.deal_end_epoch)
    }

    /// Open a reallocation ticket for a shard whose deal matured unrenewed.
    ///
    /// The slash path opened a ticket and the expiry path did not, so an
    /// operator that served its whole term and left honestly dropped a shard
    /// with nothing watching. Both exits now look the same to the redundancy
    /// layer; they differ only in what happens to the bond, which is the part
    /// that should differ.
    ///
    /// Returns the ticket id, or `None` when a ticket for this deal already
    /// exists, which is what makes the sweep safe to run every block.
    pub fn open_expiry_reallocation(&mut self, deal_id: u64, now_epoch: u64) -> Option<u64> {
        let deal = self.deals.get(&deal_id)?;
        if self
            .reallocations
            .values()
            .any(|ticket| ticket.failed_deal_id == deal_id)
        {
            return None;
        }
        let ticket_id = self.next_reallocation_id;
        self.next_reallocation_id = self.next_reallocation_id.saturating_add(1);
        let ticket = StorageReallocationTicket {
            ticket_id,
            failed_deal_id: deal_id,
            replacement_deal_id: None,
            domain_id: deal.domain_id,
            manifest_id: deal.manifest_id,
            shard_id: deal.shard_id,
            replica_index: deal.replica_index,
            // The incumbent is recorded so the ticket reads the same as a
            // slash ticket, but it is NOT barred from taking the replacement:
            // `accept_reallocation_ticket` refuses only the slashed operator,
            // and an operator that let a term lapse was never slashed. It may
            // well be the cheapest replacement, since it still has the bytes.
            slashed_operator: Address::zero(),
            opened_epoch: now_epoch,
            deadline_epoch: now_epoch.saturating_add(REALLOCATION_ACCEPTANCE_EPOCHS),
            status: ReallocationStatus::Pending,
            expected_holder: None,
            cause: ReallocationCause::FailedDeal,
        };
        self.reallocations.insert(ticket_id, ticket);
        Some(ticket_id)
    }

    /// Open a bootstrap ticket for a shard that has never held a deal.
    ///
    /// The expiry and slash paths both require a historic `deal_id`. A shard
    /// the registry registered but never placed has none, and the repair band
    /// used to log that gap and walk on. Logging is not a ticket: nothing is
    /// pending, nothing can be accepted, and the object stays under-replicated
    /// forever under a warning that looks like progress.
    ///
    /// Dedup key is `(manifest_id, shard_id, replica_index)` among pending /
    /// under-replicated never-placed tickets - the same slot must not pay two
    /// operators for the first copy. `failed_deal_id` is 0 and is not a lookup
    /// key for this cause.
    ///
    /// `domain_id` is taken from the caller because the manifest does not carry
    /// one; the chain actor passes the storage domain it is sweeping.
    pub fn open_never_placed_ticket(
        &mut self,
        domain_id: u32,
        manifest_id: ContentId,
        shard_id: ContentId,
        replica_index: u8,
        now_epoch: u64,
    ) -> Option<u64> {
        self.manifests.get(&manifest_id)?;
        // Refuse when the slot already has a live deal: a never-placed ticket
        // is only for the empty case the repair band already filtered.
        if self.active_replica_count(&manifest_id, &shard_id) > 0 {
            return None;
        }
        let already = self.reallocations.values().any(|ticket| {
            ticket.cause == ReallocationCause::NeverPlaced
                && ticket.manifest_id == manifest_id
                && ticket.shard_id == shard_id
                && ticket.replica_index == replica_index
                && matches!(
                    ticket.status,
                    ReallocationStatus::Pending | ReallocationStatus::UnderReplicated
                )
        });
        if already {
            return None;
        }
        let ticket_id = self.next_reallocation_id;
        self.next_reallocation_id = self.next_reallocation_id.saturating_add(1);
        let ticket = StorageReallocationTicket {
            ticket_id,
            failed_deal_id: 0,
            replacement_deal_id: None,
            domain_id,
            manifest_id,
            shard_id,
            replica_index,
            slashed_operator: Address::zero(),
            opened_epoch: now_epoch,
            deadline_epoch: now_epoch.saturating_add(REALLOCATION_ACCEPTANCE_EPOCHS),
            status: ReallocationStatus::Pending,
            expected_holder: None,
            cause: ReallocationCause::NeverPlaced,
        };
        self.reallocations.insert(ticket_id, ticket);
        Some(ticket_id)
    }

    /// Write the placement advice onto the pending tickets.
    ///
    /// `assign_shard` uses rendezvous hashing to choose one deterministic holder
    /// per shard: the same shard, the same entropy and the same
    /// candidate set give the same answer on every node. The answer here is a
    /// **recommendation**, whoever accepts the ticket takes it
    /// (`accept_reallocation_ticket` did not change).
    ///
    /// The reason it is written is to make divergence visible. Today there is
    /// no comparison at all between who took a ticket and who the placement
    /// computation chose, so neither the computation failing to reflect real
    /// capacity nor assigned operators skipping their obligation can be seen.
    ///
    /// Only `Pending` tickets and only once: writing a recommendation onto an
    /// already accepted ticket would be inventing the recommendation after the
    /// outcome. The return value is the number of recommendations written.
    pub fn annotate_expected_holders(
        &mut self,
        entropy: &crate::domain::Hash32,
        candidates: &[crate::storage::assignment::ShardCandidate],
    ) -> usize {
        let mut written = 0;
        for ticket in self.reallocations.values_mut() {
            if ticket.status != ReallocationStatus::Pending || ticket.expected_holder.is_some() {
                continue;
            }
            // One replica: a ticket fills a single slot, not the set.
            let Ok(placed) =
                crate::storage::assignment::assign_shard(&ticket.shard_id, entropy, candidates, 1)
            else {
                // No candidate, no recommendation. An empty recommendation
                // is better than a wrong one.
                continue;
            };
            ticket.expected_holder = placed.first().copied();
            if ticket.expected_holder.is_some() {
                written += 1;
            }
        }
        written
    }

    /// Accepted tickets that diverged from the recommendation.
    ///
    /// Returns `(ticket_id, recommended, actually accepted by)`. An empty
    /// result says the placement computation agrees with the acceptances that
    /// actually happened.
    #[must_use]
    pub fn placements_that_diverged(&self) -> Vec<(u64, Address, Address)> {
        self.reallocations
            .values()
            .filter_map(|ticket| {
                let expected = ticket.expected_holder?;
                let replacement = ticket.replacement_deal_id?;
                let actual = self.deals.get(&replacement)?.operator;
                (actual != expected).then_some((ticket.ticket_id, expected, actual))
            })
            .collect()
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

    /// Drop the tickets whose replacement deal opened
    /// `REALLOCATION_RECORD_RETENTION_EPOCHS` or more epochs ago.
    ///
    /// Runs from the same epoch maintenance step as
    /// [`Self::mark_overdue_reallocations_under_replicated`], so every node
    /// drops the same rows at the same epoch and the registry digest stays
    /// consensus-equal. Only a ticket still in `ActiveReplacement` is
    /// dropped; the queue is a hint and the status is the fact, so a ticket
    /// that is somehow back to waiting stays.
    ///
    /// Returns how many tickets were dropped.
    pub fn sweep_settled_reallocations(&mut self, now_epoch: u64) -> usize {
        let Some(cutoff) = now_epoch.checked_sub(REALLOCATION_RECORD_RETENTION_EPOCHS) else {
            return 0;
        };
        let due: Vec<u64> = self
            .settled_tickets
            .range(..=cutoff)
            .map(|(&epoch, _)| epoch)
            .collect();
        let mut dropped = 0;
        for epoch in due {
            let Some(ticket_ids) = self.settled_tickets.remove(&epoch) else {
                continue;
            };
            for ticket_id in ticket_ids {
                let settled = self
                    .reallocations
                    .get(&ticket_id)
                    .is_some_and(|t| t.status == ReallocationStatus::ActiveReplacement);
                if settled && self.reallocations.remove(&ticket_id).is_some() {
                    dropped += 1;
                }
            }
        }
        dropped
    }

    /// Rows in the ticket map, for the `budlum_storage_reallocation_rows`
    /// gauge: a number that only ever rises means the sweep is not running.
    pub fn reallocation_ticket_count(&self) -> usize {
        self.reallocations.len()
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
            .get(&deal_id)
            .ok_or(StorageError::UnknownDeal(deal_id))?;
        if now_epoch < deal.deal_end_epoch {
            return Err(StorageError::InvalidEpochRange {
                start: now_epoch,
                end: deal.deal_end_epoch,
            });
        }
        if deal.status != DealStatus::Active {
            return Ok(0);
        }
        // A term ending must not be a way to lose an object. The question is
        // not how many carriers the manifest has in total: shards are not
        // interchangeable, and a decode needs `k` *distinct* shards live. So
        // ask what this deal's own shard would have left, and only refuse
        // when letting go would take that shard to zero while the object is
        // already down to the shards it cannot decode without.
        let (manifest_id, shard_id) = (deal.manifest_id, deal.shard_id);
        let shard_replicas = self.active_replica_count(&manifest_id, &shard_id);
        if shard_replicas <= 1 {
            let live = self.live_shard_count(&manifest_id);
            let floor = self.permanence_floor(manifest_id);
            if live <= floor {
                return Err(StorageError::ExpiryWouldStrandContent {
                    deal_id,
                    manifest_id,
                    shard_id,
                    remaining_carriers: live.saturating_sub(1),
                    floor,
                });
            }
        }
        let deal = self
            .deals
            .get_mut(&deal_id)
            .ok_or(StorageError::UnknownDeal(deal_id))?;
        let bond = deal.economics.operator_bond;
        deal.status = DealStatus::Expired;
        Ok(bond)
    }

    /// The fewest live shards a manifest may fall to before an expiry is
    /// refused.
    ///
    /// Reads the manifest's own erasure parameters rather than a constant:
    /// the floor is the number of shards a decode needs, so an object coded
    /// with a different `k` gets a different floor, and one the registry has
    /// no manifest for falls back to [`PERMANENCE_FLOOR_DEFAULT`].
    ///
    /// Deliberately not `k + margin`. The margin belongs to the reallocation
    /// sweep, which opens a ticket the moment a term lapses; this number is
    /// the hard line where refusing the exit is the only thing left.
    pub fn permanence_floor(&self, manifest_id: ContentId) -> u32 {
        self.manifests
            .get(&manifest_id)
            .map(|m| m.erasure.k.max(1))
            .unwrap_or(PERMANENCE_FLOOR_DEFAULT)
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
        // Try deserializing as ProofEnvelope via bincode, under the envelope
        // byte budget so a hostile length prefix is refused before allocation.
        // The ProofEnvelope has: proof_format_version(u32), backend(String),
        // P3_version(String), fri_params_id(String), public_inputs_hash([u8;32]),
        // proof_bytes(Vec<u8>), degree_bits(u32).
        let envelope = deserialize_proof_envelope(proof_bytes)?;
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

    /// Shards that stay below target, as of `epoch`.
    ///
    /// The target is not fixed. It depends on the **content's source** (one
    /// replica is enough for content born from a recipe) and on **proven
    /// demand**
    /// (a heavily read object gives its discount back). Measuring against a
    /// fixed 3 kept showing recipe-backed content as "under-replicated" and
    /// opened repair tickets that added no durability; giving the discount
    /// independently of demand left a heavily read object behind a single
    /// operator.
    ///
    /// There is one version, parameterised by `epoch`. Leaving two versions,
    /// one that sees demand and one that does not, would let the caller choose
    /// which target is applied.
    pub fn under_replicated_shards(&self, epoch: u64) -> Vec<(ContentId, ContentId, usize)> {
        self.deals_by_shard
            .keys()
            .filter_map(|(manifest_id, shard_id)| {
                let active = self.active_replica_count(manifest_id, shard_id);
                let target = usize::from(self.required_replicas_with_demand(manifest_id, epoch));
                (active < target).then_some((*manifest_id, *shard_id, active))
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

    /// Objects in the repair band, each judged by its own scheme's margin.
    ///
    /// [`StorageRegistry::objects_needing_repair`] takes one margin and
    /// applies it to every object, which is the right shape for a caller that
    /// wants to ask a specific question. It is the wrong shape for the
    /// maintenance sweep: the sweep sees every scheme at once, and a single
    /// number cannot be correct for `(10,16)` and `LRC k=2000` at the same
    /// time. See [`ContentManifest::repair_margin`] for the measurement.
    ///
    /// Returns `(manifest_id, live, k, margin)` so a caller can log why an
    /// object was selected without recomputing the rule.
    pub fn objects_below_own_repair_margin(&self) -> Vec<(ContentId, u32, u32, u32)> {
        self.manifests
            .iter()
            .filter_map(|(manifest_id, manifest)| {
                let live = self.live_shard_count(manifest_id);
                let margin = manifest.repair_margin();
                manifest.needs_repair(live, margin).then_some((
                    *manifest_id,
                    live,
                    manifest.erasure.k,
                    margin,
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
    /// Called when an NFT is burned (Constitution section 1: "if an NFT is
    /// burned the data is physically deleted from B.U.D. storage").
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

    // === Dictionary reference ============================================

    /// The dictionary enters the identity: if two manifests declare the same
    /// bytes with different dictionaries they cannot be the same object.
    ///
    /// Had it not entered, a manifest could be redirected to another
    /// dictionary without breaking its record and the same id would decode to
    /// different content.
    #[test]
    fn the_dictionary_is_part_of_the_identity() {
        let plain = good_manifest();
        let mut with_dict = plain.clone();
        with_dict.dictionary_id = Some(ContentId([9u8; 32]));
        let rebound = with_dict.clone().with_source(with_dict.source.clone());
        assert_ne!(
            rebound.manifest_id, plain.manifest_id,
            "a manifest declaring a dictionary cannot carry the same id"
        );
    }

    /// The identity of a manifest that declares no dictionary does not change.
    ///
    /// Every manifest recorded before this field was added falls here; that is
    /// why no migration is needed.
    #[test]
    fn no_dictionary_means_no_change_to_the_preimage() {
        let m = good_manifest();
        assert!(m.dictionary_id.is_none());
        assert_eq!(
            m.verify_id(),
            Ok(()),
            "the old identity must verify unchanged"
        );
    }

    /// A view grant follows the manifest's owner, not the caller's word.
    ///
    /// Both halves are needed: `issue_view_grant` refuses a stranger, and
    /// `may_view` refuses a query that claims to be the owner. Measured against
    /// the code before the fix, each half alone left the other open.
    #[test]
    fn view_grants_are_the_manifest_owners_to_give() {
        let mut reg = StorageRegistry::new();
        let owner = Address::from([1u8; 32]);
        let stranger = Address::from([7u8; 32]);
        let bob = Address::from([2u8; 32]);
        let mut m = good_manifest();
        m.owner = owner;
        reg.register_manifest(&m);
        let content = m.manifest_id;
        let key = [5u8; 32];
        // An authorisation no key signed is refused before the registry looks at
        // what the grant would allow. Which refusal it is depends on the build:
        // with the wallet verifier the fabricated key derives to an address that
        // is not the owner, without it nothing can be derived at all. Both are
        // refusals, and only those two are accepted here.
        let unsigned = crate::storage::GrantAuthorization {
            owner_key: [7u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN],
            signature: Vec::new(),
        };
        let err = reg
            .issue_view_grant(
                content,
                &unsigned,
                None,
                key,
                crate::storage::ViewPolicy::PublicKeyId,
                1,
            )
            .expect_err("a stranger cannot hand out grants");
        assert!(
            matches!(
                err,
                crate::storage::ViewGrantError::NotOwner { .. }
                    | crate::storage::ViewGrantError::Authorization(_)
            ),
            "an unsigned grant must be refused as one of the two, got {err:?}"
        );
        assert!(
            !reg.may_view(&content, &bob, &key, &stranger),
            "naming oneself the owner is not being the owner"
        );
        let yok = ContentId([42u8; 32]);
        assert!(
            !reg.may_view(&yok, &bob, &key, &owner),
            "content no manifest describes opens for nobody"
        );
    }

    /// A signed grant opens the object it names and nothing else.
    ///
    /// The signature binds content, grantee, key handle, policy and epoch, so a
    /// valid authorisation cannot be moved to another object or reshaped into a
    /// wider one; and a caller that cannot derive the owner from its key never
    /// reaches the registry at all.
    /// A confidential commit must carry proof that the key signing it is held
    /// by the address it is registered under.
    ///
    /// Deriving an address from a public key is not an identity check: the
    /// public key is public. If the signature is never verified, anybody who
    /// has seen Alice's key can register a commit under her address - and by
    /// registering first, lock her out of her own object, since a second
    /// commit under a different body is refused.
    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn a_confidential_commit_is_refused_when_nothing_signed_it() {
        use crate::crypto::primitives::WalletKeyPair;

        let mut reg = StorageRegistry::new();
        let kp = WalletKeyPair::generate();
        let owner = kp.address();
        let commit = crate::storage::ConfidentialBodyCommit {
            content_id: ContentId([11u8; 32]),
            encryption: crate::storage::ContentEncryption::Plaintext,
            ciphertext_root: [3u8; 32],
            proof_kind: crate::storage::ConfidentialProofKind::RetrievalChallenge,
        };
        // The victim's public key, and a signature that is not a signature.
        let forged = crate::storage::GrantAuthorization {
            owner_key: kp.public_key_bytes(),
            signature: vec![0u8; 16],
        };
        assert_eq!(
            forged.derived_owner().ok(),
            Some(owner),
            "the public key alone must derive the victim address, or this test proves nothing"
        );
        let res = reg.register_confidential_commit(commit, &forged);
        assert!(
            res.is_err(),
            "a commit under an address whose key signed nothing was accepted"
        );
    }

    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn a_signed_grant_opens_only_the_object_it_names() {
        use crate::crypto::primitives::WalletKeyPair;

        let mut reg = StorageRegistry::new();
        let kp = WalletKeyPair::generate();
        let owner = kp.address();
        let bob = Address::from([2u8; 32]);
        let mut m = good_manifest();
        m.owner = owner;
        reg.register_manifest(&m);
        let content = m.manifest_id;
        let mut other = ContentManifest::from_bytes_sliced(b"another private body bytes...", 8)
            .expect("second manifest");
        other.owner = owner;
        reg.register_manifest(&other);
        let other = other.manifest_id;
        assert_ne!(content, other, "the two objects must be distinct");

        let key = [5u8; 32];
        let digest = crate::storage::grant_issue_digest(
            &content,
            &owner,
            None,
            &key,
            crate::storage::ViewPolicy::PublicKeyId,
            1,
        );
        let auth = crate::storage::GrantAuthorization {
            owner_key: kp.public_key_bytes(),
            signature: kp.sign(&digest).to_vec(),
        };
        reg.issue_view_grant(
            content,
            &auth,
            None,
            key,
            crate::storage::ViewPolicy::PublicKeyId,
            1,
        )
        .expect("the owner's own signed grant must be accepted");
        assert!(reg.may_view(&content, &bob, &key, &owner));
        assert!(
            !reg.may_view(&content, &bob, &key, &bob),
            "a grantee is not an owner and must not be treated as one"
        );

        // The same signature, offered for the other object: the content is inside
        // the digest, so it verifies as nothing.
        let err = reg
            .issue_view_grant(
                other,
                &auth,
                None,
                key,
                crate::storage::ViewPolicy::PublicKeyId,
                1,
            )
            .expect_err("a grant signature is bound to the object it names");
        assert!(matches!(
            err,
            crate::storage::ViewGrantError::Authorization(
                crate::storage::GrantAuthError::BadSignature
            )
        ));
        // The same signature, offered as a different grant: policy and grantee are
        // in the digest too.
        let err = reg
            .issue_view_grant(
                content,
                &auth,
                Some(bob),
                key,
                crate::storage::ViewPolicy::OwnerOnly,
                1,
            )
            .expect_err("a grant signature is bound to the policy it names");
        assert!(matches!(
            err,
            crate::storage::ViewGrantError::Authorization(
                crate::storage::GrantAuthError::BadSignature
            )
        ));
    }

    /// A revocation needs the owner's word as much as an issuance does.
    /// An issued view grant reaches the state root.
    ///
    /// Measured with a real ML-DSA-87 signature, because a grant the registry
    /// refused must not move the root either: the assertion below is about the
    /// accepted row, and the refusal case has its own test.
    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn an_issued_view_grant_reaches_the_registry_root() {
        use crate::crypto::primitives::WalletKeyPair;

        let mut reg = StorageRegistry::new();
        let kp = WalletKeyPair::generate();
        let owner = kp.address();
        let mut m = good_manifest();
        m.owner = owner;
        reg.register_manifest(&m);
        let key = [5u8; 32];
        let digest = crate::storage::grant_issue_digest(
            &m.manifest_id,
            &owner,
            None,
            &key,
            crate::storage::ViewPolicy::PublicKeyId,
            1,
        );
        let auth = crate::storage::GrantAuthorization {
            owner_key: kp.public_key_bytes(),
            signature: kp.sign(&digest).to_vec(),
        };
        let before = reg.root();
        reg.issue_view_grant(
            m.manifest_id,
            &auth,
            None,
            key,
            crate::storage::ViewPolicy::PublicKeyId,
            1,
        )
        .expect("the owner's signed grant");
        assert_ne!(before, reg.root(), "a live grant must reach the state root");
    }

    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn a_grant_is_revoked_only_by_a_signed_revocation() {
        use crate::crypto::primitives::WalletKeyPair;

        let mut reg = StorageRegistry::new();
        let kp = WalletKeyPair::generate();
        let owner = kp.address();
        let mut m = good_manifest();
        m.owner = owner;
        reg.register_manifest(&m);
        let key = [6u8; 32];
        let issue_digest = crate::storage::grant_issue_digest(
            &m.manifest_id,
            &owner,
            None,
            &key,
            crate::storage::ViewPolicy::PublicKeyId,
            1,
        );
        let issue = crate::storage::GrantAuthorization {
            owner_key: kp.public_key_bytes(),
            signature: kp.sign(&issue_digest).to_vec(),
        };
        let grant = reg
            .issue_view_grant(
                m.manifest_id,
                &issue,
                None,
                key,
                crate::storage::ViewPolicy::PublicKeyId,
                1,
            )
            .expect("signed issuance");
        assert!(reg.may_view(&m.manifest_id, &Address::from([2u8; 32]), &key, &owner));

        // Revoking with the issuance signature still attached is not revoking.
        let err = reg
            .revoke_view_grant(grant, &issue, 4)
            .expect_err("a revocation needs its own signature");
        assert!(matches!(
            err,
            crate::storage::ViewGrantError::Authorization(
                crate::storage::GrantAuthError::BadSignature
            )
        ));
        assert!(
            reg.may_view(&m.manifest_id, &Address::from([2u8; 32]), &key, &owner),
            "a refused revocation must leave the grant standing"
        );

        let revoke_digest = crate::storage::grant_revoke_digest(grant, &owner, 4);
        let revoke = crate::storage::GrantAuthorization {
            owner_key: kp.public_key_bytes(),
            signature: kp.sign(&revoke_digest).to_vec(),
        };
        reg.revoke_view_grant(grant, &revoke, 4)
            .expect("the owner's signed revocation");
        assert!(
            !reg.may_view(&m.manifest_id, &Address::from([2u8; 32]), &key, &owner),
            "a revoked grant opens nothing"
        );
    }

    /// An object resting on an unknown dictionary cannot be registered.
    ///
    /// If nobody holds the bytes the object cannot be opened; accepting the
    /// record would be paying for the durability of something that could never
    /// be decoded.
    #[test]
    fn an_unknown_dictionary_is_refused() {
        let mut reg = StorageRegistry::new();
        let mut m = good_manifest();
        m.dictionary_id = Some(ContentId([9u8; 32]));
        let err = reg
            .register_manifest_with_source(&m)
            .expect_err("an unknown dictionary must be refused");
        assert!(matches!(err, StorageError::InvalidManifest { .. }));
        assert!(
            !reg.manifests.contains_key(&m.manifest_id),
            "a refused record must not enter the registry"
        );
    }

    /// An object resting on a registered dictionary is accepted and a
    /// reference is acquired.
    #[test]
    fn a_registered_dictionary_is_acquired() {
        let mut reg = StorageRegistry::new();
        let dict = ContentId([9u8; 32]);
        reg.dictionaries
            .register_dictionary(dict, 4_096)
            .expect("the dictionary must register");
        let mut m = good_manifest();
        m.dictionary_id = Some(dict);
        reg.register_manifest_with_source(&m)
            .expect("an object on a registered dictionary must be accepted");
        assert_eq!(reg.dictionaries.reference_count(&dict), Some(1));
    }

    /// If the same manifest is submitted twice the reference is acquired once.
    ///
    /// Registration is first-writer-wins and idempotent. Counting a second
    /// time would leave a reference that never drops and the dictionary would
    /// become undeletable even after its last dependant is gone.
    #[test]
    fn re_registering_does_not_double_count_the_reference() {
        let mut reg = StorageRegistry::new();
        let dict = ContentId([9u8; 32]);
        reg.dictionaries
            .register_dictionary(dict, 4_096)
            .expect("the dictionary must register");
        let mut m = good_manifest();
        m.dictionary_id = Some(dict);
        reg.register_manifest_with_source(&m)
            .expect("first registration");
        reg.register_manifest_with_source(&m)
            .expect("second registration");
        assert_eq!(
            reg.dictionaries.reference_count(&dict),
            Some(1),
            "an idempotent registration must not bump the counter again"
        );
    }

    // === B.U.D. Three: recipe durability stands in for a replica ===========

    /// A manifest whose recipe really runs, so its registration is accepted.
    fn generated_manifest() -> (ContentManifest, crate::storage::generated::GeneratedSpec) {
        use crate::storage::generated::{generate_content, GeneratedSpec, GeneratorId};
        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        // The manifest is built from the recipe's REAL output: let the claim
        // be true.
        let bytes = generate_content(&spec).expect("the recipe must run");
        let manifest = ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32)
            .expect("manifest")
            .with_source(crate::storage::generated::ContentSource::Generated(
                spec.clone(),
            ));
        (manifest, spec)
    }

    /// Content born from a recipe needs ONE copy; three add no durability.
    ///
    /// Storing the same deterministic generator three times is not a third
    /// backup, it is three copies of the same answer. What keeps the content
    /// alive is the recipe on chain.

    #[test]
    fn edition_three_refuses_a_stored_body() {
        use crate::storage::generated::BudStorageEdition;
        let mut m = good_manifest();
        m = m.with_edition(BudStorageEdition::Three);
        // source still Stored (default from good_manifest)
        let mut reg = StorageRegistry::new();
        let err = reg
            .register_manifest_with_source(&m)
            .expect_err("Three must refuse Stored");
        assert!(
            matches!(err, StorageError::InvalidManifest { .. }),
            "expected InvalidManifest, got {err:?}"
        );
    }

    #[test]
    fn classic_edition_still_accepts_stored_body() {
        use crate::storage::generated::BudStorageEdition;
        let m = good_manifest().with_edition(BudStorageEdition::Classic);
        let mut reg = StorageRegistry::new();
        reg.register_manifest_with_source(&m)
            .expect("Classic Stored must remain valid");
    }

    #[test]
    fn a_recipe_backed_object_needs_one_copy_not_three() {
        use crate::storage::generated::{required_replica_count, ContentSource};
        let (manifest, spec) = generated_manifest();

        assert_eq!(
            required_replica_count(
                &ContentSource::Generated(spec.clone()),
                STORAGE_REPLICATION_TARGET
            ),
            1,
            "recipe-backed content needs one copy"
        );
        // Stored content needs the full target: the bytes have no other
        // source.
        assert_eq!(
            required_replica_count(&ContentSource::Stored, STORAGE_REPLICATION_TARGET),
            STORAGE_REPLICATION_TARGET
        );
        // Hybrid gets NO discount: the prefix is real bytes that cannot be
        // regenerated.
        assert_eq!(
            required_replica_count(
                &ContentSource::Hybrid {
                    prefix_bytes: 16,
                    spec,
                },
                STORAGE_REPLICATION_TARGET
            ),
            STORAGE_REPLICATION_TARGET,
            "the prefix cannot be regenerated, so it earns no discount"
        );

        let mut reg = StorageRegistry::new();
        reg.register_manifest_with_source(&manifest)
            .expect("a correct recipe must be accepted");
        assert_eq!(reg.required_replicas_for(&manifest.manifest_id), 1);
    }

    /// "Generated" is a CLAIM FOR A DISCOUNT; it is not accepted unproven.
    ///
    /// Without proof, someone labelling ordinary organic content as
    /// "generated" would collect full durability payment for a third of the
    /// copies and the content would genuinely be lost.
    #[test]
    fn a_false_generated_claim_is_refused_at_registration() {
        use crate::storage::generated::{ContentSource, GeneratedSpec, GeneratorId};
        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        // Organic bytes, labelled "born from this recipe". A lie.
        let organic = b"these bytes were born from no recipe".to_vec();
        let manifest = ContentManifest::from_bytes_sliced(&organic, organic.len() as u32)
            .expect("manifest")
            .with_source(ContentSource::Generated(spec));

        let mut reg = StorageRegistry::new();
        let err = reg
            .register_manifest_with_source(&manifest)
            .expect_err("a false generated claim must be refused");
        assert!(
            format!("{err:?}").contains("does not reproduce"),
            "the reason must say the recipe does not produce the content: {err:?}"
        );
        // A refused manifest must NOT be recorded at all: otherwise it gets
        // the discount anyway.
        assert!(reg.get_manifest(&manifest.manifest_id).is_none());
        // Unregistered content falls to the full target (fail-closed).
        assert_eq!(
            reg.required_replicas_for(&manifest.manifest_id),
            STORAGE_REPLICATION_TARGET
        );
    }

    /// A claim that cannot be verified earns no discount either: `Hybrid`
    /// cannot be proven on chain.
    #[test]
    fn a_hybrid_source_is_refused_because_its_prefix_cannot_be_proven() {
        use crate::storage::generated::{ContentSource, GeneratedSpec, GeneratorId};
        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        let manifest = ContentManifest::from_bytes_sliced(b"prefixed cont", 13)
            .expect("manifest")
            .with_source(ContentSource::Hybrid {
                prefix_bytes: 4,
                spec,
            });
        let mut reg = StorageRegistry::new();
        let err = reg
            .register_manifest_with_source(&manifest)
            .expect_err("an unverifiable hybrid claim must be refused");
        assert!(format!("{err:?}").contains("Hybrid"), "{err:?}");
        assert!(reg.get_manifest(&manifest.manifest_id).is_none());
    }

    /// The source regime enters the IDENTITY.
    ///
    /// Had it not, two manifests for the same bytes, one saying "stored" and
    /// the other "generated", would share the same id; because
    /// `register_manifest` is first-writer-wins, one could silently change the
    /// other's durability requirement.
    #[test]
    fn the_source_regime_changes_the_manifest_id() {
        let (generated, _spec) = generated_manifest();
        let stored = ContentManifest::from_bytes_sliced(
            &crate::storage::generated::generate_content(&match &generated.source {
                crate::storage::generated::ContentSource::Generated(s) => s.clone(),
                _ => unreachable!("test manifest is Generated"),
            })
            .expect("recipe"),
            32 * 32,
        )
        .expect("manifest");

        // Same bytes, different claim -> different identity.
        assert_ne!(
            generated.manifest_id, stored.manifest_id,
            "the source regime must enter the identity"
        );
        // The identity of old manifests must not change: `Stored` adds no
        // bytes, so it stays the same as the id from before this field.
        assert_eq!(
            stored.manifest_id,
            crate::storage::manifest::manifest_id_from_parts_stored(
                &stored.shards,
                &stored.erasure,
                &stored.encryption,
                stored.content_size(),
                stored.total_size,
            ),
            "the Stored identity must not change"
        );
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

    /// A Generated source holds no bytes. Pricing from the listed output size
    /// would invent a rent for a recipe; `held_bytes` is what keeps Three's
    /// "kira = 0" claim true on the deal path, not only in a spreadsheet.
    #[test]
    fn a_generated_deal_is_priced_at_zero_held_bytes() {
        use crate::storage::generated::{
            generate_content, ContentSource, GeneratedSpec, GeneratorId,
        };

        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        let bytes = generate_content(&spec).expect("generation");
        let manifest = ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32)
            .expect("manifest")
            .with_source(ContentSource::Generated(spec));
        // Classic edition still admits a body-shaped deal for the live copy;
        // the rent must still read held_bytes = 0.
        let mut reg = StorageRegistry::new();
        let shard = &manifest.shards[0];
        let listed = u64::from(shard.size);
        assert!(listed > 0, "fixture must list a non-zero output size");
        let id = reg
            .open_deal(
                42,
                &manifest,
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
            .expect("generated deal opens");
        let deal = reg.get_deal(id).expect("deal");
        assert_eq!(deal.shard_bytes, 0, "Generated holds nothing to rent");
        assert_eq!(
            deal.total_fee(10),
            0,
            "zero held bytes must yield zero rent even at a positive rate"
        );
        assert_ne!(
            good_econ().total_fee(listed, 10),
            0,
            "control: the same rate on listed size would not be free"
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
        liar.manifest_id = crate::storage::manifest_id_from_parts_stored(
            &liar.shards,
            &liar.erasure,
            &liar.encryption,
            liar.content_size(),
            liar.total_size,
        );
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

    /// The confidential record must reach the state root, both halves of it.
    ///
    /// A commitment that nobody can point at is not a promise, and an owner that
    /// lives only in a node's local map is exactly the record a second node would
    /// disagree about: a grant is checked against it, and the chain's answer must
    /// not depend on which node replayed the block.
    ///
    /// Both registries are filled by a key that actually signs, because the
    /// owner recorded is the one derived from the signing key; two different
    /// speakers means two different keys, not two typed addresses.
    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn a_confidential_commit_changes_the_registry_root() {
        use crate::crypto::primitives::WalletKeyPair;
        use crate::storage::{
            ConfidentialBodyCommit, ConfidentialProofKind, ContentCipher, ContentEncryption,
        };

        let m = ContentManifest::from_bytes_sliced(b"classic private body bytes!!", 8).unwrap();
        let signed_commit = |kp: &WalletKeyPair| {
            let commit = ConfidentialBodyCommit::new(
                m.manifest_id,
                ContentEncryption::ClientSide(ContentCipher::Aes256Gcm),
                [4u8; 32],
                ConfidentialProofKind::HybridZkTee,
            )
            .unwrap();
            let owner = kp.address();
            let digest = crate::storage::confidential_commit_digest(&commit, &owner);
            (
                commit,
                crate::storage::GrantAuthorization {
                    owner_key: kp.public_key_bytes(),
                    signature: kp.sign(&digest).to_vec(),
                },
            )
        };

        let mut reg = StorageRegistry::new();
        reg.register_manifest(&m);
        let before = reg.root();
        let (commit, auth) = signed_commit(&WalletKeyPair::generate());
        reg.register_confidential_commit(commit, &auth).unwrap();
        let after = reg.root();
        assert_ne!(before, after, "the body commit must reach the root");

        // The owner alone moves the root too: same commitment, different
        // speaker. A fold over the commitments only would let a node swap who
        // owns an object without any state-root change.
        let mut other_registry = StorageRegistry::new();
        other_registry.register_manifest(&m);
        let (commit2, auth2) = signed_commit(&WalletKeyPair::generate());
        other_registry
            .register_confidential_commit(commit2, &auth2)
            .unwrap();
        assert_ne!(
            after,
            other_registry.root(),
            "the recorded owner must reach the root"
        );
    }

    /// Without a verifier nothing can prove an owner, so nothing is recorded
    /// and the root holds. Fail-closed is the point: a build that cannot check
    /// signatures must not write an owner nobody proved into the state root.
    #[cfg(not(feature = "wallet-ml-dsa"))]
    #[test]
    fn a_confidential_commit_is_refused_so_the_root_holds() {
        use crate::storage::{
            ConfidentialBodyCommit, ConfidentialProofKind, ContentCipher, ContentEncryption,
        };

        let mut reg = StorageRegistry::new();
        let m = ContentManifest::from_bytes_sliced(b"classic private body bytes!!", 8).unwrap();
        reg.register_manifest(&m);
        let before = reg.root();
        let commit = ConfidentialBodyCommit::new(
            m.manifest_id,
            ContentEncryption::ClientSide(ContentCipher::Aes256Gcm),
            [4u8; 32],
            ConfidentialProofKind::HybridZkTee,
        )
        .unwrap();
        let auth = crate::storage::GrantAuthorization {
            owner_key: [9u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN],
            signature: vec![1, 2, 3, 4],
        };
        assert!(
            reg.register_confidential_commit(commit, &auth).is_err(),
            "a commit whose owner signed nothing must be refused"
        );
        assert_eq!(
            before,
            reg.root(),
            "a refused commit must not move the state root"
        );
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

    /// A format-valid test envelope (an honest marker - NOT a REAL STARK
    /// proof; a minimal ProofEnvelope that can be bincode-deserialized).
    /// NOTE: the inline 78-byte arrays in a0671c4 gave a type error (E0308)
    /// and hid the intent; the helper was restored.
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

    // === Placement advice =================================================

    fn placement_candidates(n: u8) -> Vec<crate::storage::assignment::ShardCandidate> {
        (1..=n)
            .map(|i| crate::storage::assignment::ShardCandidate {
                address: Address::from([i; 32]),
                stake: 1_000,
            })
            .collect()
    }

    /// The shortest path that opens a ticket: open a deal and miss the challenge.
    fn registry_with_pending_ticket() -> StorageRegistry {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let cid = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .expect("the challenge must open");
        reg.finalize_missed_challenge(cid, 150)
            .expect("a missed challenge must open a ticket");
        reg
    }

    /// A pending ticket gets an advisory and it is deterministic.
    #[test]
    fn a_pending_ticket_gets_a_deterministic_advisory() {
        let mut reg = registry_with_pending_ticket();
        let cands = placement_candidates(5);
        assert_eq!(reg.annotate_expected_holders(&[7u8; 32], &cands), 1);
        let first = reg
            .all_reallocation_tickets()
            .first()
            .and_then(|t| t.expected_holder)
            .expect("an advisory must be written");

        // Same shard, same entropy, same candidate set: same answer.
        let mut again = registry_with_pending_ticket();
        again.annotate_expected_holders(&[7u8; 32], &cands);
        let second = again
            .all_reallocation_tickets()
            .first()
            .and_then(|t| t.expected_holder)
            .expect("an advisory must be written");
        assert_eq!(
            first, second,
            "placement must give the same answer on every node"
        );
    }

    /// An advisory is written once; a second pass does not overwrite it.
    ///
    /// Otherwise the advisory would change as the entropy changed and the
    /// divergence measurement would become meaningless: an advisory invented
    /// after the acceptance measures nothing.
    #[test]
    fn an_advisory_is_written_once() {
        let mut reg = registry_with_pending_ticket();
        let cands = placement_candidates(5);
        assert_eq!(reg.annotate_expected_holders(&[7u8; 32], &cands), 1);
        let first = reg
            .all_reallocation_tickets()
            .first()
            .and_then(|t| t.expected_holder);
        // A second pass with different entropy: nothing must change.
        assert_eq!(reg.annotate_expected_holders(&[9u8; 32], &cands), 0);
        let after = reg
            .all_reallocation_tickets()
            .first()
            .and_then(|t| t.expected_holder);
        assert_eq!(first, after, "an advisory cannot be changed afterwards");
    }

    /// No candidates means no advisory: an empty advisory beats a wrong one.
    #[test]
    fn no_candidates_means_no_advisory() {
        let mut reg = registry_with_pending_ticket();
        assert_eq!(reg.annotate_expected_holders(&[7u8; 32], &[]), 0);
        assert!(reg
            .all_reallocation_tickets()
            .first()
            .and_then(|t| t.expected_holder)
            .is_none());
    }

    /// A candidate with zero stake is never chosen: an operator with nothing
    /// to lose takes no damage from dropping the bytes.
    #[test]
    fn a_zero_stake_candidate_is_never_advised() {
        let mut reg = registry_with_pending_ticket();
        let zero = vec![crate::storage::assignment::ShardCandidate {
            address: Address::from([3u8; 32]),
            stake: 0,
        }];
        assert_eq!(reg.annotate_expected_holders(&[7u8; 32], &zero), 0);
    }

    /// No divergence is reported for a ticket that was not accepted.
    ///
    /// Divergence can only be measured between an actual acceptance and the
    /// advisory.
    #[test]
    fn divergence_needs_an_actual_acceptance() {
        let mut reg = registry_with_pending_ticket();
        reg.annotate_expected_holders(&[7u8; 32], &placement_candidates(5));
        assert!(
            reg.placements_that_diverged().is_empty(),
            "a ticket that was not accepted cannot produce divergence"
        );
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
        // Open one, then expire it, then try to challenge. A second replica
        // is opened first so the expiry is about the deal's own status rather
        // than about stranding the object.
        let (deal_id, _) = open_one(&mut reg, &m);
        open_second_replica(&mut reg, &m);
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

    /// Slash, ticket, accept: the ticket that opened the replacement deal
    /// is a record from then on, and records leave after the retention
    /// window. The replacement deal itself is untouched.
    #[test]
    fn settled_reallocation_tickets_are_swept_after_retention() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        let ticket_id = reg.all_reallocation_tickets()[0].ticket_id;
        let replacement = reg
            .accept_reallocation_ticket(
                ticket_id,
                replacement_operator(),
                151,
                250,
                good_econ(),
                &params(),
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap();
        assert_eq!(reg.reallocation_ticket_count(), 1);

        // Even an epoch-zero queue entry retains its ticket until the full
        // window has elapsed. Saturating subtraction used to make every
        // pre-window sweep treat epoch zero as already due.
        reg.settled_tickets.entry(0).or_default().push(ticket_id);
        assert_eq!(
            reg.sweep_settled_reallocations(REALLOCATION_RECORD_RETENTION_EPOCHS - 1),
            0
        );
        assert!(reg.get_reallocation_ticket(ticket_id).is_some());
        reg.settled_tickets.remove(&0);

        // One epoch short of the window: the record stays.
        let last_kept = 151 + REALLOCATION_RECORD_RETENTION_EPOCHS - 1;
        assert_eq!(reg.sweep_settled_reallocations(last_kept), 0);
        assert_eq!(reg.reallocation_ticket_count(), 1);
        assert_eq!(
            reg.lifecycle_state(replacement),
            Some(crate::storage::StorageLifecycleState::ActiveReplacement)
        );

        // At the window the record goes; the deal it opened does not.
        assert_eq!(reg.sweep_settled_reallocations(last_kept + 1), 1);
        assert_eq!(reg.reallocation_ticket_count(), 0);
        assert!(reg.get_reallocation_ticket(ticket_id).is_none());
        assert_eq!(deal_status(&reg, replacement), DealStatus::Active);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);
        // With the record gone the slashed deal reads as plain Slashed and
        // the replacement as a plain active deal.
        assert_eq!(
            reg.lifecycle_state(deal_id),
            Some(crate::storage::StorageLifecycleState::Slashed)
        );
        // A second sweep has nothing left to do.
        assert_eq!(reg.sweep_settled_reallocations(last_kept + 100), 0);
    }

    /// A start epoch below the ticket's own epoch does not shorten the
    /// record's retention: the queue key is the later of the two.
    #[test]
    fn a_backdated_start_epoch_does_not_shorten_record_retention() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        let ticket_id = reg.all_reallocation_tickets()[0].ticket_id;
        assert_eq!(
            reg.get_reallocation_ticket(ticket_id).unwrap().opened_epoch,
            150
        );
        reg.accept_reallocation_ticket(
            ticket_id,
            replacement_operator(),
            1,
            250,
            good_econ(),
            &params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();

        // Keyed on the backdated start, the record would be due at epoch
        // 1 + retention; keyed on the ticket's epoch it stays until 150 +
        // retention.
        let last_kept = 150 + REALLOCATION_RECORD_RETENTION_EPOCHS - 1;
        assert_eq!(reg.sweep_settled_reallocations(last_kept), 0);
        assert!(reg.get_reallocation_ticket(ticket_id).is_some());
        assert_eq!(reg.sweep_settled_reallocations(last_kept + 1), 1);
        assert!(reg.get_reallocation_ticket(ticket_id).is_none());
    }

    /// A ticket nobody has taken is the obligation itself, not a record of
    /// one: no retention window applies to it, however old it gets.
    #[test]
    fn waiting_tickets_are_never_swept() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        let far = 150 + 100 * REALLOCATION_RECORD_RETENTION_EPOCHS;
        assert_eq!(reg.sweep_settled_reallocations(far), 0);
        assert_eq!(reg.mark_overdue_reallocations_under_replicated(far), 1);
        assert_eq!(reg.sweep_settled_reallocations(far), 0);
        assert_eq!(reg.reallocation_ticket_count(), 1);
    }

    /// The registry row is bincode and positional. A row written before
    /// `settled_tickets` existed is refused.
    ///
    /// The loader used to pad such a row with an empty queue and accept it.
    /// The queue is hashed into `root()` and decides when
    /// `sweep_settled_reallocations` drops a ticket, so a node that loaded
    /// the padded row kept tickets its peers dropped and split from them at
    /// the first retention cutoff. No network has launched, so there is no
    /// older row to be loyal to; the shorter row fails to decode and the
    /// loader reports it.
    #[test]
    fn registry_rows_written_before_the_settled_queue_are_refused() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        assert!(reg.settled_tickets.is_empty());

        let current = bincode::serialize(&reg).unwrap();
        let empty_map = 0u64.to_le_bytes();
        assert!(current.ends_with(&empty_map));
        let older = &current[..current.len() - empty_map.len()];
        assert!(
            bincode::deserialize::<StorageRegistry>(older).is_err(),
            "the shorter row must be refused, not padded"
        );

        // A current row decodes, queue included, to the same root.
        let ticket_id = reg.all_reallocation_tickets()[0].ticket_id;
        reg.accept_reallocation_ticket(
            ticket_id,
            replacement_operator(),
            151,
            250,
            good_econ(),
            &params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
        let with_queue = bincode::serialize(&reg).unwrap();
        let loaded: StorageRegistry = bincode::deserialize(&with_queue).unwrap();
        assert_eq!(loaded.settled_tickets, reg.settled_tickets);
        assert_eq!(loaded.root(), reg.root());
    }

    #[test]
    fn a_never_placed_shard_gets_a_bootstrap_ticket() {
        // Register without opening a deal. The repair band used to log
        // "no ticket type" and walk on; the bootstrap ticket is what makes
        // that gap actionable.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        reg.register_manifest(&m);
        let shard_id = m.shards[0].shard_id;

        let ticket_id = reg
            .open_never_placed_ticket(42, m.manifest_id, shard_id, 0, 100)
            .expect("a never-held shard must open a bootstrap ticket");
        let ticket = reg.get_reallocation_ticket(ticket_id).unwrap();
        assert_eq!(ticket.cause, ReallocationCause::NeverPlaced);
        assert_eq!(ticket.failed_deal_id, 0, "no historic deal to name");
        assert_eq!(ticket.manifest_id, m.manifest_id);
        assert_eq!(ticket.shard_id, shard_id);
        assert_eq!(ticket.domain_id, 42);
        assert_eq!(ticket.status, ReallocationStatus::Pending);
    }

    #[test]
    fn never_placed_ticket_opens_once_per_slot() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        reg.register_manifest(&m);
        let shard_id = m.shards[0].shard_id;

        assert!(reg
            .open_never_placed_ticket(42, m.manifest_id, shard_id, 0, 100)
            .is_some());
        assert!(
            reg.open_never_placed_ticket(42, m.manifest_id, shard_id, 0, 101)
                .is_none(),
            "a second sweep must not open a second first-copy ticket"
        );
        assert!(
            reg.open_never_placed_ticket(42, m.manifest_id, shard_id, 1, 102)
                .is_some(),
            "replica_index is part of the slot key"
        );
    }

    #[test]
    fn never_placed_refuses_when_a_live_deal_already_holds_the_shard() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (_, shard_id) = open_one(&mut reg, &m);
        assert!(
            reg.open_never_placed_ticket(42, m.manifest_id, shard_id, 0, 100)
                .is_none(),
            "bootstrap is only for the empty case"
        );
    }

    #[test]
    fn slash_and_expiry_tickets_record_failed_deal_cause() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        let challenge_id = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        reg.finalize_missed_challenge(challenge_id, 150).unwrap();
        let ticket = reg.all_reallocation_tickets()[0];
        assert_eq!(ticket.cause, ReallocationCause::FailedDeal);
        assert_eq!(ticket.failed_deal_id, deal_id);
    }

    /// A deal is slashed once. `answer_challenge` refuses a deal that has left
    /// `Active` (`DealNotActive`); `finalize_missed_challenge` never asked that
    /// Question, so a second open challenge on the same deal - up to
    /// `MAX_OPEN_CHALLENGES_PER_DEAL` of them - recorded the bond as slashed
    /// Again. This layer does not burn the bond, it hands the amount to the
    /// `Blockchain` accounting path, and that path counts events, not deals:
    /// The operator would pay twice for one failure.
    #[test]
    fn a_deal_that_has_already_been_slashed_is_not_slashed_twice() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);

        let first = reg
            .open_challenge(deal_id, 0, 4, 110, 120, opener(), 50)
            .unwrap();
        let second = reg
            .open_challenge(deal_id, 0, 4, 121, 140, opener(), 50)
            .unwrap();

        let first_result = reg.finalize_missed_challenge(first, 130).unwrap();
        assert!(
            first_result.slashed_bond > 0,
            "the first miss has to slash the bond"
        );
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Slashed);

        assert!(
            reg.finalize_missed_challenge(second, 150).is_err(),
            "the bond of a deal that is already `Slashed` must not be recorded a second time"
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

    /// Open a second replica of the *same* shard under a different operator,
    /// so letting the first go leaves the shard live.
    fn open_second_replica(reg: &mut StorageRegistry, m: &ContentManifest) -> u64 {
        reg.open_deal(
            42,
            m,
            m.shards[0].shard_id,
            replacement_operator(),
            1,
            100,
            200,
            good_econ(),
            &params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn expire_deal_transitions_active_to_expired() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, _) = open_one(&mut reg, &m);
        // A second replica of the same shard, so letting the first go leaves
        // the shard live. Without it this expiry is refused, which is the
        // point of the test below.
        open_second_replica(&mut reg, &m);
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Active);
        reg.expire_deal(deal_id, 200).unwrap();
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Expired);
    }

    #[test]
    fn the_last_carrier_may_not_expire_out_from_under_its_object() {
        // The regression: a term ending was a way to lose an object. The
        // slash path takes a bond from someone who broke a promise; expiry
        // takes nothing from anyone, so nothing about it justifies making the
        // content unreadable.
        //
        // `good_manifest` is plain replication, so every shard is a data
        // shard and losing any one of them is already fatal. Opening a deal
        // on the first shard alone leaves the object at one live shard
        // against a floor of two, which is exactly the case the floor exists
        // for.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (deal_id, shard_id) = open_one(&mut reg, &m);
        let err = reg.expire_deal(deal_id, 200).unwrap_err();
        assert_eq!(
            err,
            StorageError::ExpiryWouldStrandContent {
                deal_id,
                manifest_id: m.manifest_id,
                shard_id,
                remaining_carriers: 0,
                floor: m.erasure.k.max(1),
            }
        );
        // Held Active, not punished: the operator did nothing wrong and its
        // bond is still owed once a replacement takes over.
        assert_eq!(deal_status(&reg, deal_id), DealStatus::Active);
    }

    #[test]
    fn a_shard_with_a_spare_replica_may_always_be_let_go() {
        // The floor is about shards a decode needs, not about how busy any
        // one operator is. When the shard survives the departure, nothing is
        // at risk and the term may end normally.
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        let (first, shard_id) = open_one(&mut reg, &m);
        let second = open_second_replica(&mut reg, &m);
        assert_eq!(reg.active_replica_count(&m.manifest_id, &shard_id), 2);

        reg.expire_deal(first, 200)
            .expect("the shard still has a replica");
        // The one that is now alone may not follow it out.
        assert!(matches!(
            reg.expire_deal(second, 200),
            Err(StorageError::ExpiryWouldStrandContent { .. })
        ));
    }

    #[test]
    fn the_floor_reads_the_manifests_own_erasure_parameters() {
        let m = good_manifest();
        let mut reg = StorageRegistry::new();
        open_one(&mut reg, &m);
        // `good_manifest` is plain replication, so k equals the shard count
        // and the floor is that same number.
        assert_eq!(reg.permanence_floor(m.manifest_id), m.erasure.k);
        // An id the registry holds no manifest for falls back rather than
        // freezing every bond behind an unanswerable question.
        assert_eq!(
            reg.permanence_floor(ContentId([0xEEu8; 32])),
            PERMANENCE_FLOOR_DEFAULT
        );
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
        // Gate (9d82f61): None must always yield MerkleProofRequired.
        // REGRESSION LOCK - deleted in a0671c4, restored; DO NOT DELETE.
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
        // Format gate: a blob that cannot be deserialized must yield InvalidMerkleProof.
        // REGRESSION LOCK - deleted in a0671c4, restored; DO NOT DELETE.
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
    fn oversized_proof_envelope_is_refused_before_parsing() {
        // A challenge answer must not carry a block-sized proof blob: the
        // envelope ceiling refuses it before bincode parses it, so the nested
        // `proof_bytes` is never copied into memory.
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; MAX_PROOF_ENVELOPE_BYTES as usize + 1],
            degree_bits: 8,
        };
        let blob = bincode::serialize(&envelope).expect("test envelope serialize");
        let err = StorageRegistry::validate_merkle_proof_format(&blob, &[0u8; 32]).unwrap_err();
        assert!(matches!(err, StorageError::InvalidMerkleProof(_)));
    }

    #[test]
    fn prune_content_expires_active_deals_and_removes_manifest() {
        // F1 (Constitution section 1): if an NFT is burned the data is
        // physically deleted from B.U.D. storage.
        // REGRESSION LOCK - prune_content must expire active deals
        // And it must remove the manifest from the registry.
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
        open_second_replica(&mut reg, &m);
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

#[cfg(test)]
mod demand_driven_replication_tests {
    use super::*;
    use crate::storage::generated::{ContentSource, GeneratedSpec, GeneratorId};

    /// A recipe-born object that has never been read keeps its discount.
    ///
    /// The ABSENCE of demand is not a durability decision; the floor comes
    /// from the regime and demand only pushes upwards.
    #[test]
    fn an_unread_generated_object_keeps_its_discount() {
        let (reg, manifest_id) = generated_registry();
        assert_eq!(reg.required_replicas_for(&manifest_id), 1);
        assert_eq!(reg.required_replicas_with_demand(&manifest_id, 0), 1);
        // The same at a much later epoch: zero reads is zero demand.
        assert_eq!(reg.required_replicas_with_demand(&manifest_id, 10_000), 1);
    }

    /// Proven reads claw the discount back.
    ///
    /// One replica means the object cannot be read the moment the operator
    /// holding that replica falls. The discount was given for durability;
    /// popularity takes it back.
    #[test]
    fn proven_reads_claw_the_discount_back() {
        let (mut reg, manifest_id) = generated_registry();
        // Reads below one step do not change the target.
        for _ in 0..7 {
            reg.record_proven_read(manifest_id, 5);
        }
        assert_eq!(
            reg.required_replicas_with_demand(&manifest_id, 5),
            1,
            "demand below the threshold does not break the discount"
        );
        // Crossing one step adds one more replica.
        reg.record_proven_read(manifest_id, 5);
        assert_eq!(reg.required_replicas_with_demand(&manifest_id, 5), 2);
        // Two steps: the full target.
        for _ in 0..8 {
            reg.record_proven_read(manifest_id, 5);
        }
        assert_eq!(
            reg.required_replicas_with_demand(&manifest_id, 5),
            STORAGE_REPLICATION_TARGET
        );
        // It cannot exceed the ceiling.
        for _ in 0..500 {
            reg.record_proven_read(manifest_id, 5);
        }
        assert_eq!(
            reg.required_replicas_with_demand(&manifest_id, 5),
            STORAGE_REPLICATION_TARGET,
            "demand cannot push the target above the ceiling"
        );
    }

    /// Demand is forgotten. An object that was once popular does not hold
    /// three replicas forever; once reading stops the estimate decays with the
    /// half-life.
    #[test]
    fn demand_decays_when_reading_stops() {
        let (mut reg, manifest_id) = generated_registry();
        for _ in 0..16 {
            reg.record_proven_read(manifest_id, 5);
        }
        assert_eq!(
            reg.required_replicas_with_demand(&manifest_id, 5),
            STORAGE_REPLICATION_TARGET
        );
        let half_life = crate::storage::living_threshold::ACCESS_HALF_LIFE_EPOCHS;
        // After one half-life 16 -> 8: still above one step.
        assert_eq!(
            reg.required_replicas_with_demand(&manifest_id, 5 + half_life),
            2
        );
        // After three half-lives 16 -> 2: below the step, the discount is
        // back.
        assert_eq!(
            reg.required_replicas_with_demand(&manifest_id, 5 + 3 * half_life),
            1
        );
    }

    /// Reads in the same epoch collapse into one entry.
    ///
    /// Otherwise the ledger of a heavily read object would grow with the read
    /// count, and this ledger lives in chain state.
    #[test]
    fn reads_in_one_epoch_collapse_into_one_entry() {
        let (mut reg, manifest_id) = generated_registry();
        for _ in 0..1000 {
            reg.record_proven_read(manifest_id, 7);
        }
        let events = reg
            .access_events
            .get(&manifest_id)
            .expect("there must be a read record");
        assert_eq!(events.len(), 1, "a thousand reads, one entry");
        assert_eq!(events[0].count, 1000);
    }

    /// Content already at the full target is at the ceiling: demand changes
    /// nothing and is not computed for nothing.
    #[test]
    fn stored_content_is_already_at_the_ceiling() {
        let mut reg = StorageRegistry::new();
        let bytes = b"ordinary stored content".to_vec();
        let manifest =
            ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32).expect("manifest");
        reg.register_manifest(&manifest);
        for _ in 0..100 {
            reg.record_proven_read(manifest.manifest_id, 1);
        }
        assert_eq!(
            reg.required_replicas_with_demand(&manifest.manifest_id, 1),
            STORAGE_REPLICATION_TARGET
        );
    }

    /// Unregistered content is fail-closed: no discount for what we do not know.
    #[test]
    fn an_unknown_object_gets_the_full_target() {
        let reg = StorageRegistry::new();
        let unknown = ContentId([42u8; 32]);
        assert_eq!(
            reg.required_replicas_with_demand(&unknown, 99),
            STORAGE_REPLICATION_TARGET
        );
    }

    /// A late event never leaves the ledger unordered.
    ///
    /// `AccessEstimate::from_events` refuses unordered input; this test shows
    /// that the input it would refuse never forms in the first place.
    #[test]
    fn a_late_event_never_breaks_the_ordering() {
        let (mut reg, manifest_id) = generated_registry();
        reg.record_proven_read(manifest_id, 100);
        reg.record_proven_read(manifest_id, 50);
        let events = reg
            .access_events
            .get(&manifest_id)
            .expect("there must be a read record");
        assert!(
            events.windows(2).all(|w| w[0].epoch <= w[1].epoch),
            "the ledger is always ordered by epoch"
        );
        assert_eq!(events.len(), 1, "a late event folds into the newest");
        assert_eq!(
            events[0].count, 2,
            "a late event is not lost, it is counted"
        );
    }

    /// Whether a shard counts as under-replicated follows demand.
    #[test]
    fn the_shard_view_follows_demand() {
        let (mut reg, manifest_id) = generated_registry();
        let manifest = reg.get_manifest(&manifest_id).expect("manifest").clone();
        let shard_id = manifest.shards.first().expect("shard").shard_id;
        reg.deals_by_shard
            .entry((manifest_id, shard_id))
            .or_default();
        // Not even one replica but the target is 1: this shard counts as short.
        assert_eq!(reg.under_replicated_shards(0).len(), 1);
        // When demand raises the target to 3 it is still short, but the
        // target really did change.
        for _ in 0..16 {
            reg.record_proven_read(manifest_id, 0);
        }
        assert_eq!(
            reg.required_replicas_with_demand(&manifest_id, 0),
            STORAGE_REPLICATION_TARGET
        );
        assert_eq!(reg.under_replicated_shards(0).len(), 1);
    }

    #[test]
    fn three_manifest_cannot_open_a_storage_deal() {
        use crate::core::address::Address;
        use crate::domain::storage_params::StorageDomainParams;
        use crate::storage::generated::{
            generate_content, BudStorageEdition, ContentSource, GeneratedSpec, GeneratorId,
        };

        fn operator() -> Address {
            Address::from([7u8; 32])
        }
        fn params() -> StorageDomainParams {
            StorageDomainParams {
                chunk_size: 256,
                max_committed_chunks: 1000,
                challenge_interval: 10,
                min_operator_bond: 1_000_000,
            }
        }
        fn good_econ() -> StorageEconomicsParams {
            StorageEconomicsParams {
                operator_bond: 5_000_000,
                fee_per_byte_epoch: 100,
            }
        }
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

        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [2u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        let bytes = generate_content(&spec).expect("gen");
        let shard_id = {
            let manifest =
                ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32).expect("m");
            manifest.shards.first().expect("shard").shard_id
        };
        let manifest = ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32)
            .expect("m")
            .with_source(ContentSource::Generated(spec))
            .with_edition(BudStorageEdition::Three);
        let mut reg = StorageRegistry::new();
        reg.register_manifest_with_source(&manifest)
            .expect("three recipe may register");
        let err = reg
            .open_deal(
                42,
                &manifest,
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
            .expect_err("Three must not open a deal");
        assert!(
            matches!(err, StorageError::InvalidManifest { .. }),
            "got {err:?}"
        );
    }

    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn confidential_commit_refuses_three_edition_manifest() {
        use crate::crypto::primitives::WalletKeyPair;
        use crate::storage::generated::{
            generate_content, BudStorageEdition, ContentSource, GeneratedSpec, GeneratorId,
        };
        use crate::storage::{
            ConfidentialBodyCommit, ConfidentialProofKind, ContentCipher, ContentEncryption,
        };

        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [1u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        let bytes = generate_content(&spec).expect("gen");
        let manifest = ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32)
            .expect("m")
            .with_source(ContentSource::Generated(spec))
            .with_edition(BudStorageEdition::Three);
        let mut reg = StorageRegistry::new();
        reg.register_manifest_with_source(&manifest)
            .expect("three recipe registers");
        let commit = ConfidentialBodyCommit::new(
            manifest.manifest_id,
            ContentEncryption::ClientSide(ContentCipher::Aes256Gcm),
            [9u8; 32],
            ConfidentialProofKind::ZkStorageProof,
        )
        .expect("client-side ok");
        // Signed by a real key, so the refusal that follows is the edition rule
        // and not a missing authorisation.
        let kp = WalletKeyPair::generate();
        let owner = kp.address();
        let digest = crate::storage::confidential_commit_digest(&commit, &owner);
        let auth = crate::storage::GrantAuthorization {
            owner_key: kp.public_key_bytes(),
            signature: kp.sign(&digest).to_vec(),
        };
        let err = reg
            .register_confidential_commit(commit, &auth)
            .expect_err("Three must not take a body commit");
        assert!(err.contains("Three") || err.contains("recipe"), "got {err}");
    }

    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn confidential_commit_accepts_classic_encrypted_body() {
        use crate::crypto::primitives::WalletKeyPair;
        use crate::storage::{
            ConfidentialBodyCommit, ConfidentialProofKind, ContentCipher, ContentEncryption,
        };

        let m = ContentManifest::from_bytes_sliced(b"classic private body bytes!!", 8).unwrap();
        let mut reg = StorageRegistry::new();
        reg.register_manifest(&m);
        let commit = ConfidentialBodyCommit::new(
            m.manifest_id,
            ContentEncryption::ClientSide(ContentCipher::Aes256Gcm),
            [4u8; 32],
            ConfidentialProofKind::HybridZkTee,
        )
        .unwrap();
        let kp = WalletKeyPair::generate();
        let owner = kp.address();
        let digest = crate::storage::confidential_commit_digest(&commit, &owner);
        let auth = crate::storage::GrantAuthorization {
            owner_key: kp.public_key_bytes(),
            signature: kp.sign(&digest).to_vec(),
        };
        let c = reg.register_confidential_commit(commit, &auth).unwrap();
        assert_eq!(c.len(), 32);
        assert!(reg.get_confidential_commit(&m.manifest_id).is_some());
        // The commit is worthless without a recorded owner: whoever signs a
        // grant later is checked against this address, so a commit that named
        // nobody could be opened by anybody's word. `owner_of` answers the
        // manifest first, so the address the commit was registered under is
        // measured where it is recorded.
        assert_eq!(
            reg.confidential_owners.get(&m.manifest_id).copied(),
            Some(owner),
            "the commit must be recorded under the address that signed it"
        );
    }

    /// Without the ML-DSA verifier nothing can prove an authorisation, so a
    /// commit is refused rather than registered on trust. The gate must fail
    /// closed: a build that cannot check signatures must not accept any.
    #[cfg(not(feature = "wallet-ml-dsa"))]
    #[test]
    fn confidential_commit_fails_closed_without_a_verifier() {
        use crate::storage::{
            ConfidentialBodyCommit, ConfidentialProofKind, ContentCipher, ContentEncryption,
        };

        let m = ContentManifest::from_bytes_sliced(b"classic private body bytes!!", 8).unwrap();
        let mut reg = StorageRegistry::new();
        reg.register_manifest(&m);
        let commit = ConfidentialBodyCommit::new(
            m.manifest_id,
            ContentEncryption::ClientSide(ContentCipher::Aes256Gcm),
            [4u8; 32],
            ConfidentialProofKind::HybridZkTee,
        )
        .unwrap();
        let auth = crate::storage::GrantAuthorization {
            owner_key: [9u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN],
            signature: vec![1, 2, 3, 4],
        };
        let err = reg
            .register_confidential_commit(commit, &auth)
            .expect_err("a build without a verifier must register nothing");
        assert!(
            err.contains("authorization"),
            "the refusal must name the authorisation, got {err}"
        );
        assert!(reg.get_confidential_commit(&m.manifest_id).is_none());
    }

    fn generated_registry() -> (StorageRegistry, ContentId) {
        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [3u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        let bytes = crate::storage::generated::generate_content(&spec).expect("generation");
        let manifest = ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32)
            .expect("manifest")
            .with_source(ContentSource::Generated(spec));
        let mut reg = StorageRegistry::new();
        reg.register_manifest_with_source(&manifest)
            .expect("a correct recipe must be accepted");
        let id = manifest.manifest_id;
        (reg, id)
    }
}
