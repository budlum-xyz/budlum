//! Tendermint and CometBFT commit finality: the adapter for the family whose
//! finality is a signed commit.
//!
//! # What this adapter verifies, and what it refuses to assume
//!
//! A Tendermint commit is a set of Ed25519 precommits over a canonical vote:
//! `(type, height, round, block id, timestamp, chain id)`. Finality is
//! *protocol* finality - once two thirds of the voting power by consensus has
//! precommitted a block, no conflicting block can be committed at that height
//! without at least a third of the power equivocating, which is slashable
//! evidence in the target chain's own rules.
//!
//! This adapter recomputes that claim from the evidence alone:
//!
//! 1. It re-encodes the canonical vote bytes for every signature from the
//!    header fields it was handed - not from a hash the submitter supplied.
//! 2. It checks every Ed25519 signature against the public key the *validator
//!    set* binds to the signing address, and it checks that binding itself
//!    (`address = SHA256(public_key)[..20]`).
//! 3. It sums the voting power of the distinct signers and requires at least
//!    `2 * total / 3 + 1`, the threshold CometBFT itself uses.
//! 4. It refuses duplicate signers, signers outside the set, a zero or
//!    mismatched chain id, a mismatched declared height or state root, and
//!    anything it cannot decode in full.
//!
//! Nothing here trusts a length. A commit full of well-formed signatures that
//! do not verify attests nothing, and the adapter says so instead of counting
//! them.
//!
//! # The canonical encoding
//!
//! Sign bytes are `protoio.MarshalDelimited(CanonicalVote)`: the length of the
//! message as a varint, then the message itself. Two details decide whether a
//! real mainnet commit verifies at all, and both were confirmed against
//! CometBFT's `proto/tendermint/types/canonical.proto` and against live
//! `noble-1` and `cosmoshub-4` commits:
//!
//! - `CanonicalBlockID.part_set_header` carries the **part-set hash**, not only
//!   the part count. A commit that drops it re-encodes different bytes and
//!   every signature fails, which is the correct outcome: the parts are part of
//!   what the validator signed.
//! - Protobuf3 omits scalar fields whose value is zero. A commit at round 0
//!   has **no round field at all** in its sign bytes. An encoder that always
//!   emits `round = 0` produces bytes nobody ever signed.
//!
//! # What this adapter does not do
//!
//! - No light-client skip. `required_depth` is one: a single verified commit is
//!   finality for a BFT chain, and pretending otherwise would be theatre.
//! - No unbonding-period validation, no validator-set chaining
//!   (`next_validators_hash` continuity between heights). Those are light-client
//!   properties, not single-commit properties, and claiming them here would be
//!   the overclaim this repository's boundary documents forbid. A caller that
//!   needs them needs a light client, and this adapter does not pretend to be
//!   one.
//! - No post-quantum half. The backing is Ed25519 only, so
//!   [`TendermintFinalityAdapter::is_classical_only_quorum`] is `true` and the
//!   settlement layer's mainnet gate
//!   (`refuse_classical_only_quorum_on_mainnet`) applies to a Budlum quorum
//!   built on it. That is stated here so it cannot be discovered later.
//!
//! # WIRING
//!
//! WIRING: `AdapterSpec::TendermintCommit` in
//! [`crate::cross_domain::external::intake`] constructs this adapter, so a
//! registered domain reaches it through the same `register_domain` /
//! `submit_evidence` path every other external domain uses.

use crate::cross_domain::external::selftest::{
    BytePatch, ExpectedRefusal, FaultProbe, RefusalKind,
};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};
use crate::crypto::facts::ObservedScheme;
use crate::crypto::primitives::verify_signature;
use crate::crypto::scheme::SchemeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The evidence version this adapter reads.
pub const EVIDENCE_VERSION: u32 = 1;

/// A ceiling on the encoded payload, checked before deserialization.
///
/// A mainnet commit with a thousand validators is roughly 100 KiB. The cap is
/// generous enough for that and small enough that a hostile payload cannot ask
/// the decoder for more memory than the node has.
pub const MAX_PAYLOAD_BYTES: usize = 512 * 1024;

/// A commit is finality by itself for a BFT chain: one verified commit is the
/// depth. Declared so a consumer reads the number instead of assuming one.
pub const REQUIRED_DEPTH: u64 = 1;

/// A bound on the validator set size, so a payload cannot make the verifier
/// iterate an unbounded list.
pub const MAX_VALIDATORS: usize = 10_000;

/// A bound on the number of commit signatures, for the same reason.
pub const MAX_SIGNATURES: usize = 10_000;

/// Ed25519 public keys are 32 bytes on the wire, signatures 64.
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Tendermint validator addresses are the first 20 bytes of
/// `SHA256(public_key)`.
pub const ADDRESS_LEN: usize = 20;

/// `SignedMsgType.SIGNED_MSG_TYPE_PRECOMMIT`, the only vote type a commit
/// carries.
const PRECOMMIT_TYPE: u64 = 2;

const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Maximum future skew accepted between a commit's timestamp and `policy.now`
/// when freshness enforcement (`policy.max_age != 0`) is active (2 hours).
const MAX_FUTURE_SECONDS: u64 = 7_200;

/// Maximum divergence allowed between the envelope's `commit_time` and the
/// voting-power-weighted median of the verified precommit vote timestamps.
const MAX_COMMIT_TIME_SKEW_SECONDS: u64 = 600;

/// Governance-pinned Tendermint commit anchor binding both `chain_id` and the
/// canonical validator-set digest ([`validator_set_commitment`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedTendermintAnchor {
    pub chain_id: String,
    pub validator_set_hash: [u8; 32],
}

/// Canonical domain-separated commitment over a Tendermint validator set,
/// sorted by validator address so ordering permutations produce one digest.
#[must_use]
pub fn validator_set_commitment(validators: &[TendermintValidator]) -> [u8; 32] {
    let mut ordered = validators.to_vec();
    ordered.sort_by_key(|v| v.address);
    let count_le = (ordered.len() as u64).to_le_bytes();
    let mut flat = Vec::with_capacity(
        ordered
            .len()
            .saturating_mul(ADDRESS_LEN + PUBLIC_KEY_LEN + 8),
    );
    for v in &ordered {
        flat.extend_from_slice(&v.address);
        flat.extend_from_slice(&v.public_key);
        flat.extend_from_slice(&v.voting_power.to_le_bytes());
    }
    crate::core::hash::hash_fields_bytes(&[b"BDLM_TM_COMMIT_VALSET_V1", &count_le, &flat])
}

/// One validator of the set the commit is verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TendermintValidator {
    /// The 20-byte address the commit refers to signers by.
    pub address: [u8; ADDRESS_LEN],
    /// The Ed25519 key that address is bound to.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// Consensus voting power. Not a token amount: it is whatever the target
    /// chain's `MaxTotalVotingPower` arithmetic produced, and the threshold is
    /// computed over it as the target does.
    pub voting_power: u64,
}

/// One commit signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TendermintSignature {
    pub address: [u8; ADDRESS_LEN],
    /// The vote's own timestamp, seconds since the Unix epoch. Each validator
    /// stamps its own vote, so this is per-signature and part of the sign bytes.
    pub timestamp_seconds: i64,
    pub timestamp_nanos: u32,
    /// 64 bytes of Ed25519. Kept as a `Vec` so the decoder can refuse a wrong
    /// length explicitly rather than failing inside the deserializer.
    pub signature: Vec<u8>,
}

/// The wire shape of one Tendermint commit.
///
/// Everything the verification needs is carried: the header fields that are
/// signed, the validator set the signers are resolved against, and the
/// signatures themselves. In particular the *validator set travels with the
/// commit* rather than being looked up from "the latest set", because the set
/// is height-scoped in Tendermint and a commit must be checked against the set
/// for its own height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TendermintCommitEvidence {
    /// The chain id, part of every sign byte.
    pub chain_id: String,
    pub height: u64,
    pub round: i64,
    /// The block hash the commit is over.
    pub block_hash: [u8; 32],
    pub parts_total: u32,
    /// The part-set hash. Signed, so it must be present and exact.
    pub parts_hash: [u8; 32],
    /// The application state root committed at this height. This is what the
    /// attestation hands out as `state_root`.
    pub app_hash: [u8; 32],
    /// The commit time in seconds since the Unix epoch, from the header. Used
    /// for the attestation's `finalized_at` and for staleness, and never
    /// compared to the individual vote timestamps: those legitimately spread
    /// over the round.
    pub commit_time: u64,
    pub validators: Vec<TendermintValidator>,
    pub signatures: Vec<TendermintSignature>,
}

/// Byte offsets inside an encoded commit, for admission probes.
///
/// `None` means the field is absent in this payload (an empty vector has no
/// first element) and a probe built on it would be a lie about what it tests.
///
/// Deliberately not `pub`: this is how [`TendermintFinalityAdapter::fault_probes`]
/// locates the bytes it corrupts, and nothing outside this module has any
/// business depending on the wire layout. A `pub` accessor would also be a
/// second, test-shaped description of the encoding that could drift from the
/// probes that actually use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldOffsets {
    /// Offset of the `validators` length prefix (u64).
    pub validators_len_at: usize,
    /// Offset of the first validator's `voting_power` (u64), when one exists.
    pub first_validator_power_at: Option<usize>,
    /// Offset of the `signatures` length prefix (u64).
    pub signatures_len_at: usize,
    /// Offset of the first signature's `address` (20 bytes), when one exists.
    pub first_signature_address_at: Option<usize>,
    /// Offset of the first signature's `signature` length prefix (u64).
    pub first_signature_len_at: Option<usize>,
}

impl TendermintCommitEvidence {
    /// Decodes a payload.
    ///
    /// # Errors
    ///
    /// [`AdapterError::Malformed`] for an over-long or non-decoding payload.
    /// The payload cap is checked first, so a length prefix cannot be used to
    /// ask the decoder itself for memory.
    pub fn decode(payload: &[u8]) -> Result<Self, AdapterError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::Malformed {
                offset: payload.len(),
                reason: format!(
                    "payload is {} bytes, above the {MAX_PAYLOAD_BYTES}-byte cap",
                    payload.len()
                ),
            });
        }
        use bincode::Options;
        let byte_limit = u64::try_from(payload.len()).unwrap_or(MAX_PAYLOAD_BYTES as u64);
        let decoded: Self = bincode::options()
            .with_fixint_encoding()
            .with_limit(byte_limit)
            .reject_trailing_bytes()
            .deserialize(payload)
            .map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: format!("payload does not decode: {e}"),
            })?;
        Ok(decoded)
    }

    /// Encodes. Used by callers that hold the parts and need the payload.
    ///
    /// # Errors
    ///
    /// A serialization failure, which for this type means the encoder's own
    /// limits were exceeded.
    pub fn encode(&self) -> Result<Vec<u8>, AdapterError> {
        bincode::serialize(self).map_err(|e| AdapterError::Malformed {
            offset: 0,
            reason: format!("payload does not encode: {e}"),
        })
    }

    /// Byte offsets of the fields an admission probe needs to reach.
    ///
    /// Admission proves an adapter refuses the faults its author thought of.
    /// The probes that matter for this adapter are the ones that keep a
    /// forged quorum from reaching the power sum: a duplicated signer, a
    /// zero-power validator, a duplicated set entry. All three live inside
    /// the bincode payload, so a probe needs the offset of the field it
    /// corrupts.
    ///
    /// The offsets are DERIVED, not typed in: this method walks the same
    /// header the encoder writes and stops at the field asked for, so a
    /// field added to the wire shape moves these with it instead of leaving
    /// a probe pointing at the middle of the wrong integer. No offset is
    /// returned when the field is absent (an empty set has no first entry),
    /// and the caller must then skip the probe rather than guess.
    #[must_use]
    fn field_offsets(&self) -> FieldOffsets {
        // Fixed-width header: chain_id (u64 len + bytes), height (u64),
        // round (i64), block_hash (32), parts_total (u32), parts_hash (32),
        // app_hash (32), commit_time (u64), then Vec<T> length prefixes.
        let mut at = 8usize.saturating_add(self.chain_id.len());
        at += 8; // height
        at += 8; // round
        at += 32; // block_hash
        at += 4; // parts_total
        at += 32; // parts_hash
        at += 32; // app_hash
        at += 8; // commit_time
        let validators_len_at = at;
        at += 8; // validators length prefix
        let first_validator_at = at;
        // TendermintValidator: address (20) + public_key (32) + power (u64).
        let first_validator_power_at = first_validator_at + ADDRESS_LEN + PUBLIC_KEY_LEN;
        let validators_bytes_at = at.saturating_add(
            self.validators
                .len()
                .saturating_mul(ADDRESS_LEN + PUBLIC_KEY_LEN + 8),
        );
        let signatures_len_at = validators_bytes_at;
        let signatures_bytes_at = signatures_len_at + 8;
        // TendermintSignature: address (20) + seconds (i64) + nanos (u32) +
        // signature (u64 len + bytes). Only the first entry's offsets are
        // needed: no probe reaches past it.
        let first_signature_address_at =
            (!self.signatures.is_empty()).then_some(signatures_bytes_at);
        let first_signature_len_at = first_signature_address_at.map(|at| at + ADDRESS_LEN + 8 + 4);
        FieldOffsets {
            validators_len_at,
            first_validator_power_at: (!self.validators.is_empty())
                .then_some(first_validator_power_at),
            signatures_len_at,
            first_signature_address_at,
            first_signature_len_at,
        }
    }

    /// Shape checks, all of them independent of any signature.
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] naming the rule that failed.
    pub fn validate_shape(&self) -> Result<(), AdapterError> {
        if self.chain_id.is_empty() {
            return Err(rule("the commit carries an empty chain id"));
        }
        if self.height == 0 {
            return Err(rule("height 0 is not a committed height in Tendermint"));
        }
        if self.round < 0 {
            return Err(rule("a negative round is not a Tendermint round"));
        }
        if self.parts_total == 0 {
            return Err(rule(
                "a commit with a zero part-set header total cannot be the block's block id",
            ));
        }
        if self.block_hash.iter().all(|b| *b == 0) {
            return Err(rule("the commit's block hash is all zeroes"));
        }
        if self.validators.is_empty() {
            return Err(rule(
                "no validator set supplied, so no signature can be resolved to a key",
            ));
        }
        if self.validators.len() > MAX_VALIDATORS {
            return Err(rule(format!(
                "the validator set has {} entries, above the {MAX_VALIDATORS} cap",
                self.validators.len()
            )));
        }
        if self.signatures.is_empty() {
            return Err(rule("the commit carries no signatures"));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(rule(format!(
                "the commit carries {} signatures, above the {MAX_SIGNATURES} cap",
                self.signatures.len()
            )));
        }
        let mut seen_validators: std::collections::BTreeSet<[u8; ADDRESS_LEN]> =
            std::collections::BTreeSet::new();
        let mut total_power = 0u128;
        // CometBFT protocol ceiling (`types.MaxTotalVotingPower = MaxInt64 / 8`).
        let max_total_voting_power = (i64::MAX as u128) / 8;
        for (index, validator) in self.validators.iter().enumerate() {
            if validator.voting_power == 0 {
                return Err(rule(format!(
                    "validator {} has zero voting power and cannot contribute to a quorum",
                    hex::encode(validator.address)
                )));
            }
            if validator.address != validator_address_of(&validator.public_key) {
                return Err(rule(format!(
                    "validator entry {index} carries address {} which is not SHA256 of its public key",
                    hex::encode(validator.address)
                )));
            }
            if !seen_validators.insert(validator.address) {
                return Err(rule(format!(
                    "validator {} appears twice in the set, which would let one key count twice",
                    hex::encode(validator.address)
                )));
            }
            total_power = total_power.saturating_add(u128::from(validator.voting_power));
            if total_power > max_total_voting_power {
                return Err(rule(format!(
                    "total voting power {total_power} exceeds CometBFT ceiling {max_total_voting_power}"
                )));
            }
        }
        let mut seen_signers: std::collections::BTreeSet<[u8; ADDRESS_LEN]> =
            std::collections::BTreeSet::new();
        for (index, signature) in self.signatures.iter().enumerate() {
            if signature.signature.len() != SIGNATURE_LEN {
                return Err(rule(format!(
                    "commit signature {index} is {} bytes, not the {SIGNATURE_LEN} bytes of Ed25519",
                    signature.signature.len()
                )));
            }
            if signature.timestamp_nanos >= NANOS_PER_SECOND {
                return Err(rule(format!(
                    "commit signature {index} carries {} nanoseconds, which is not a timestamp",
                    signature.timestamp_nanos
                )));
            }
            if !seen_signers.insert(signature.address) {
                return Err(rule(format!(
                    "validator {} signed twice; a duplicated signature must not add power twice",
                    hex::encode(signature.address)
                )));
            }
        }
        Ok(())
    }

    /// Total voting power of the supplied set.
    #[must_use]
    pub fn total_voting_power(&self) -> u128 {
        self.validators
            .iter()
            .map(|v| u128::from(v.voting_power))
            .sum()
    }

    /// The quorum this commit must reach: `2 * total / 3 + 1`, the same
    /// threshold CometBFT uses. Integer arithmetic, no float, no rounding
    /// direction to get wrong.
    #[must_use]
    pub fn quorum_threshold(&self) -> u128 {
        quorum_threshold(self.total_voting_power())
    }

    /// The canonical vote bytes for one signature: exactly what the validator
    /// signed, re-encoded from the header fields.
    #[must_use]
    pub fn canonical_vote_bytes(&self, signature: &TendermintSignature) -> Vec<u8> {
        vote_sign_bytes(
            &self.chain_id,
            self.height,
            self.round,
            &self.block_hash,
            self.parts_total,
            &self.parts_hash,
            (signature.timestamp_seconds, signature.timestamp_nanos),
        )
    }
}

/// `2 * total / 3 + 1`, in integer arithmetic.
#[must_use]
pub fn quorum_threshold(total_voting_power: u128) -> u128 {
    total_voting_power * 2 / 3 + 1
}

/// `SHA256(public_key)[..20]`, the Tendermint validator address derivation.
///
/// Named `validator_address_of` so it does not share a bare identifier with the
/// tokenomics allocation helper: the dead-API gate counts names rather than
/// paths, and two same-named functions hide whichever of them is dead.
#[must_use]
pub fn validator_address_of(public_key: &[u8; PUBLIC_KEY_LEN]) -> [u8; ADDRESS_LEN] {
    let digest = Sha256::digest(public_key);
    let mut address = [0u8; ADDRESS_LEN];
    for (dst, src) in address.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    address
}

/// Maximum RFC-6962 Merkle branch depth accepted for CometBFT header proofs.
const MAX_RFC6962_DEPTH: usize = 32;
/// CometBFT `Header` field index of `next_validators_hash` (0-based across 14 fields).
pub const COMETBFT_HEADER_NEXT_VALIDATORS_INDEX: usize = 8;
/// CometBFT `Header` field index of `app_hash` (0-based across 14 fields).
pub const COMETBFT_HEADER_APP_HASH_INDEX: usize = 10;
/// Total canonical leaf count of a CometBFT `Header` RFC-6962 Merkle tree.
pub const COMETBFT_HEADER_TOTAL_LEAVES: usize = 14;

/// RFC-6962 binary Merkle inclusion proof used by CometBFT `Header.Hash()` and IBC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc6962Proof {
    /// Zero-based leaf position inside the tree.
    pub index: usize,
    /// Total number of leaves committed in the tree.
    pub total: usize,
    /// Sibling ("aunt") hashes ordered from leaf level to root.
    pub aunts: Vec<[u8; 32]>,
}

fn rfc6962_leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn rfc6962_inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Largest power of two strictly less than `n` (for `n >= 2`), matching
/// CometBFT `crypto/merkle::getSplitPoint`.
const fn rfc6962_split_point(n: usize) -> usize {
    let bitlen = (usize::BITS - n.leading_zeros()) as usize;
    let k = 1usize << (bitlen - 1);
    if k == n {
        k >> 1
    } else {
        k
    }
}

fn rfc6962_root_from_aunts(
    index: usize,
    total: usize,
    leaf_hash: [u8; 32],
    aunts: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if total == 0 || index >= total || aunts.len() > MAX_RFC6962_DEPTH {
        return None;
    }
    if total == 1 {
        return aunts.is_empty().then_some(leaf_hash);
    }
    let (&top_aunt, sub_aunts) = aunts.split_last()?;
    let k = rfc6962_split_point(total);
    if index < k {
        let left = rfc6962_root_from_aunts(index, k, leaf_hash, sub_aunts)?;
        Some(rfc6962_inner_hash(&left, &top_aunt))
    } else {
        let right = rfc6962_root_from_aunts(index - k, total - k, leaf_hash, sub_aunts)?;
        Some(rfc6962_inner_hash(&top_aunt, &right))
    }
}

/// Verify an RFC-6962 inclusion proof for `leaf` against CometBFT `expected_root`
/// (e.g. proving `AppHash` or `NextValidatorsHash` inside validator-signed `block_hash`).
/// WIRING: Tendermint/IBC header-field verification consumed by [`verify_skipping_commit`].
#[must_use]
pub fn verify_rfc6962_inclusion(
    leaf: &[u8],
    proof: &Rfc6962Proof,
    expected_root: &[u8; 32],
) -> bool {
    if *expected_root == [0u8; 32] {
        return false;
    }
    let Some(computed) = rfc6962_root_from_aunts(
        proof.index,
        proof.total,
        rfc6962_leaf_hash(leaf),
        &proof.aunts,
    ) else {
        return false;
    };
    bool::from(subtle::ConstantTimeEq::ct_eq(
        computed.as_slice(),
        expected_root.as_slice(),
    ))
}

/// Trusted light-client checkpoint for Tendermint/IBC skipping verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedTendermintState {
    pub chain_id: String,
    pub height: u64,
    pub time_secs: u64,
    pub trusting_period_secs: u64,
    pub validators: Vec<TendermintValidator>,
    pub next_validators_hash: [u8; 32],
}

/// Verified state produced by advancing a [`TrustedTendermintState`] to a newer commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTendermintSkip {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub app_hash: [u8; 32],
    pub validator_set_hash: [u8; 32],
    pub next_validators_hash: Option<[u8; 32]>,
    pub median_time_secs: u64,
    pub trusted_overlap_power: u128,
    pub target_signed_power: u128,
}

/// Verify a Tendermint/IBC light-client transition from `trusted` to `target`
/// under the Amintoosi-Buchman-Kwon skipping theorem:
///
/// - Adjacent transition (`target.height == trusted.height + 1` with matching
///   `trusted.next_validators_hash`): accepts on `>= 2/3 + 1` target voting power.
/// - Non-adjacent skipping transition (`target.height > trusted.height`): requires
///   BOTH strictly `> 1/3` of `trusted.validators` voting power (cross-checked by
///   exact Ed25519 public key) AND `>= 2/3 + 1` of `target.validators` power within
///   `trusted.trusting_period_secs`.
/// - When `app_hash_proof` is supplied, cryptographically proves `target.app_hash`
///   at [`COMETBFT_HEADER_APP_HASH_INDEX`] inside signed `target.block_hash`;
///   otherwise fails closed unless `target.app_hash == target.block_hash`.
/// - When `next_validators` is supplied, proves the rotated `next_validators_hash`
///   at [`COMETBFT_HEADER_NEXT_VALIDATORS_INDEX`] inside signed `target.block_hash`.
///
/// # Errors
///
/// Returns [`AdapterError`] if the trusted checkpoint expired, timestamps regress,
/// signatures fail, trusted overlap is `<= 1/3`, target quorum is `< 2/3 + 1`, or
/// an RFC-6962 header inclusion proof fails.
///
/// WIRING: Tendermint/IBC dynamic validator-set rotation and AppHash light-client verifier.
pub fn verify_skipping_commit(
    trusted: &TrustedTendermintState,
    target: &TendermintCommitEvidence,
    app_hash_proof: Option<&Rfc6962Proof>,
    next_validators: Option<([u8; 32], &Rfc6962Proof)>,
    now_secs: u64,
) -> Result<VerifiedTendermintSkip, AdapterError> {
    target.validate_shape()?;
    if trusted.chain_id.is_empty() || target.chain_id != trusted.chain_id {
        return Err(rule(
            "target commit chain_id mismatches trusted light-client state",
        ));
    }
    if target.height <= trusted.height {
        return Err(rule(
            "target commit height does not advance past trusted height",
        ));
    }
    if trusted.trusting_period_secs == 0 {
        return Err(rule(
            "trusted light-client state carries zero trusting_period_secs",
        ));
    }
    if now_secs.saturating_sub(trusted.time_secs) >= trusted.trusting_period_secs {
        return Err(AdapterError::Stale {
            age: now_secs.saturating_sub(trusted.time_secs),
            max_age: trusted.trusting_period_secs,
        });
    }
    if trusted.validators.is_empty() || trusted.validators.len() > MAX_VALIDATORS {
        return Err(rule("trusted validator set size outside valid bounds"));
    }

    // Build deduplicated trusted validator map and total trusted voting power.
    let mut trusted_map: std::collections::BTreeMap<[u8; ADDRESS_LEN], &TendermintValidator> =
        std::collections::BTreeMap::new();
    let mut trusted_total = 0u128;
    for v in &trusted.validators {
        if v.voting_power == 0 || v.address != address_of(&v.public_key) {
            return Err(rule("trusted validator entry invalid or zero power"));
        }
        if trusted_map.insert(v.address, v).is_some() {
            return Err(rule("duplicate validator in trusted Tendermint state"));
        }
        trusted_total = trusted_total.saturating_add(u128::from(v.voting_power));
    }

    let target_map: std::collections::BTreeMap<[u8; ADDRESS_LEN], &TendermintValidator> =
        target.validators.iter().map(|v| (v.address, v)).collect();
    let target_total = target.total_voting_power();
    let target_required = quorum_threshold(target_total);

    // Cryptographically verify every signature, accumulating target power and
    // trusted-set overlap power (measured strictly in `trusted` weights).
    let mut target_signed = 0u128;
    let mut trusted_overlap = 0u128;
    let mut signed_times: Vec<(u64, u128)> = Vec::with_capacity(target.signatures.len());

    for sig in &target.signatures {
        let vote_ts = u64::try_from(sig.timestamp_seconds)
            .map_err(|_| rule("precommit carries negative timestamp"))?;
        let sign_bytes = target.canonical_vote_bytes(sig);
        let mut verified_key: Option<[u8; PUBLIC_KEY_LEN]> = None;

        if let Some(tv) = target_map.get(&sig.address) {
            verify_signature(&sign_bytes, &sig.signature, &tv.public_key).map_err(|_| {
                AdapterError::Crypto {
                    what: "invalid Ed25519 precommit signature in target set".into(),
                }
            })?;
            let p = u128::from(tv.voting_power);
            target_signed = target_signed.saturating_add(p);
            signed_times.push((vote_ts, p));
            verified_key = Some(tv.public_key);
        }
        if let Some(old_v) = trusted_map.get(&sig.address) {
            match verified_key {
                Some(pk) if pk != old_v.public_key => {
                    return Err(rule("validator address collided with distinct public key"));
                }
                Some(_) => {}
                None => {
                    verify_signature(&sign_bytes, &sig.signature, &old_v.public_key).map_err(
                        |_| AdapterError::Crypto {
                            what: "invalid Ed25519 precommit signature in trusted overlap".into(),
                        },
                    )?;
                }
            }
            trusted_overlap = trusted_overlap.saturating_add(u128::from(old_v.voting_power));
        }
        if verified_key.is_none() && !trusted_map.contains_key(&sig.address) {
            return Err(rule(
                "precommit signer belongs to neither target nor trusted set",
            ));
        }
    }

    if target_signed < target_required {
        return Err(rule(format!(
            "target signed power {target_signed}/{target_total} below 2/3+1 quorum {target_required}"
        )));
    }

    let target_set_hash = validator_set_commitment(&target.validators);
    let is_committed_adjacent = Some(target.height) == trusted.height.checked_add(1)
        && trusted.next_validators_hash != [0u8; 32]
        && bool::from(subtle::ConstantTimeEq::ct_eq(
            target_set_hash.as_slice(),
            trusted.next_validators_hash.as_slice(),
        ));
    if !is_committed_adjacent && trusted_overlap.saturating_mul(3) <= trusted_total {
        return Err(rule(format!(
            "skipping trust level failed: trusted overlap {trusted_overlap}/{trusted_total} does not exceed 1/3"
        )));
    }

    // Enforce BFT median-time monotonicity and future-clock drift bound.
    signed_times.sort_by_key(|(ts, _)| *ts);
    let half = target_signed / 2;
    let mut acc = 0u128;
    let mut median_ts = target.commit_time;
    for (ts, power) in &signed_times {
        acc = acc.saturating_add(*power);
        if acc > half {
            median_ts = *ts;
            break;
        }
    }
    if target.commit_time.abs_diff(median_ts) > MAX_COMMIT_TIME_SKEW_SECONDS {
        return Err(rule(
            "target commit_time diverges from signed precommit median",
        ));
    }
    if median_ts <= trusted.time_secs {
        return Err(rule(
            "target commit BFT time does not strictly advance past trusted time",
        ));
    }
    if median_ts > now_secs.saturating_add(MAX_FUTURE_SECONDS) {
        return Err(rule(
            "target commit BFT time exceeds future clock drift bound",
        ));
    }

    // Bind `app_hash` to validator-signed `block_hash` via CometBFT RFC-6962 proof.
    let verified_app_hash = if let Some(proof) = app_hash_proof {
        if proof.index != COMETBFT_HEADER_APP_HASH_INDEX
            || proof.total != COMETBFT_HEADER_TOTAL_LEAVES
            || !verify_rfc6962_inclusion(&target.app_hash, proof, &target.block_hash)
        {
            return Err(rule(
                "RFC-6962 proof fails to bind app_hash into signed CometBFT block_hash",
            ));
        }
        target.app_hash
    } else if bool::from(subtle::ConstantTimeEq::ct_eq(
        target.app_hash.as_slice(),
        target.block_hash.as_slice(),
    )) {
        target.block_hash
    } else {
        return Err(rule(
            "skipping commit with distinct app_hash requires a valid RFC-6962 header proof",
        ));
    };

    let verified_next = if let Some((next_hash, proof)) = next_validators {
        if next_hash == [0u8; 32]
            || proof.index != COMETBFT_HEADER_NEXT_VALIDATORS_INDEX
            || proof.total != COMETBFT_HEADER_TOTAL_LEAVES
            || !verify_rfc6962_inclusion(&next_hash, proof, &target.block_hash)
        {
            return Err(rule(
                "RFC-6962 proof fails to bind next_validators_hash into signed block_hash",
            ));
        }
        Some(next_hash)
    } else {
        None
    };

    Ok(VerifiedTendermintSkip {
        height: target.height,
        block_hash: target.block_hash,
        app_hash: verified_app_hash,
        validator_set_hash: target_set_hash,
        next_validators_hash: verified_next,
        median_time_secs: median_ts,
        trusted_overlap_power: trusted_overlap,
        target_signed_power: target_signed,
    })
}

fn rule(reason: impl Into<String>) -> AdapterError {
    AdapterError::ConsensusRule {
        rule: reason.into(),
    }
}

// ---------------------------------------------------------------------------
// The canonical encoding
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// A varint field: wire type 0. Proto3 drops the field entirely when the value
/// is zero, and so does this encoder - that omission is what a real commit at
/// round 0 signs.
fn put_scalar(out: &mut Vec<u8>, field: u8, value: u64) {
    if value == 0 {
        return;
    }
    out.push(field << 3);
    put_varint(out, value);
}

/// A fixed 64-bit field: wire type 1, little endian. `sfixed64` on the wire.
fn put_fixed64(out: &mut Vec<u8>, field: u8, value: u64) {
    if value == 0 {
        return;
    }
    out.push((field << 3) | 1);
    out.extend_from_slice(&value.to_le_bytes());
}

/// A length-delimited field: wire type 2. Emitted even when empty, because the
/// callers below only use it for embedded messages and byte strings that are
/// structurally present.
fn put_bytes(out: &mut Vec<u8>, field: u8, body: &[u8]) {
    out.push((field << 3) | 2);
    put_varint(out, body.len() as u64);
    out.extend_from_slice(body);
}

/// The sign bytes of one precommit: `MarshalDelimited(CanonicalVote)`.
///
/// Field numbers and types follow CometBFT's
/// `proto/tendermint/types/canonical.proto`:
///
/// ```text
/// CanonicalVote          field 1 type (varint), field 2 height (sfixed64),
///                        field 3 round (sfixed64), field 4 block_id,
///                        field 5 timestamp, field 6 chain identifier
/// CanonicalBlockID       hash = 1, part_set_header = 2
/// CanonicalPartSetHeader total = 1, hash = 2
/// Timestamp              seconds = 1, nanos = 2
/// ```
#[must_use]
pub fn vote_sign_bytes(
    chain_id: &str,
    height: u64,
    round: i64,
    block_hash: &[u8; 32],
    parts_total: u32,
    parts_hash: &[u8; 32],
    (seconds, nanos): (i64, u32),
) -> Vec<u8> {
    let mut part_set_header = Vec::new();
    put_scalar(&mut part_set_header, 1, u64::from(parts_total));
    put_bytes(&mut part_set_header, 2, parts_hash);

    let mut block_id = Vec::new();
    put_bytes(&mut block_id, 1, block_hash);
    put_bytes(&mut block_id, 2, &part_set_header);

    let mut timestamp = Vec::new();
    put_scalar(&mut timestamp, 1, seconds as u64);
    put_scalar(&mut timestamp, 2, u64::from(nanos));

    let mut body = Vec::new();
    put_scalar(&mut body, 1, PRECOMMIT_TYPE);
    put_fixed64(&mut body, 2, height);
    put_fixed64(&mut body, 3, round as u64);
    put_bytes(&mut body, 4, &block_id);
    put_bytes(&mut body, 5, &timestamp);
    if !chain_id.is_empty() {
        put_bytes(&mut body, 6, chain_id.as_bytes());
    }

    let mut out = Vec::new();
    put_varint(&mut out, body.len() as u64);
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// Commit finality for one Tendermint/CometBFT chain.
#[derive(Debug, Clone)]
pub struct TendermintFinalityAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    chain_id: String,
    /// When constructed through consensus intake (`new_pinned`), requires the
    /// commit's validator set to hash to this pinned digest and restricts the
    /// attested root to the validator-signed `block_hash` (preventing unpinned
    /// validator-set forgery and unsigned `app_hash` substitution).
    pinned_validator_set: Option<[u8; 32]>,
    require_pinned_set: bool,
    golden: Option<RawConsensusEvidence>,
}

impl TendermintFinalityAdapter {
    /// Pins the adapter to one network label and one chain id (for standalone
    /// self-test and fixture verification).
    #[must_use]
    pub fn new(network: &str, chain_id: &str) -> Self {
        let name = format!("tendermint-commit-{network}");
        Self {
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(&name),
                name,
                adapter_version: 1,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "tendermint-bft".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: REQUIRED_DEPTH,
                time_unit: TimeUnit::UnixSeconds,
                trust_model: TrustModel::HonestMajority { set_size: 0 },
            },
            network: network.to_string(),
            chain_id: chain_id.to_string(),
            pinned_validator_set: None,
            require_pinned_set: false,
            golden: None,
        }
    }

    /// Consensus-intake constructor: enforces a governance-pinned validator-set
    /// commitment and requires the attested root to match the signed `block_hash`
    /// (fails closed with `AdapterError::Unavailable` if `validator_set_hash` is
    /// absent or zero).
    #[must_use]
    pub fn new_pinned(network: &str, chain_id: &str, validator_set_hash: Option<[u8; 32]>) -> Self {
        let mut adapter = Self::new(network, chain_id);
        adapter.pinned_validator_set = validator_set_hash.filter(|h| *h != [0u8; 32]);
        adapter.require_pinned_set = true;
        adapter
    }

    /// The chain id this adapter will only ever attest.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Attach the known-good evidence sample admission verifies against.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    /// The backing is Ed25519 only: no post-quantum half yet.
    ///
    /// Returned as a method rather than left implicit because the settlement
    /// layer refuses a classical-only quorum on mainnet
    /// (`settlement::domains::refuse_classical_only_quorum_on_mainnet`), and a
    /// caller building a Budlum quorum out of this attestation has to know
    /// that gate applies to them.
    #[must_use]
    pub const fn is_classical_only_quorum(&self) -> bool {
        true
    }
}

impl ExternalFinalityAdapter for TendermintFinalityAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: "another adapter".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        // One commit is the depth. A caller asking for more is asking for
        // something a single commit cannot give, and is told so rather than
        // handed an attestation that silently lacks it.
        if policy.min_depth > REQUIRED_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: REQUIRED_DEPTH,
                required: policy.min_depth,
            });
        }

        let decoded = TendermintCommitEvidence::decode(&evidence.payload)?;
        decoded.validate_shape()?;

        // The chain id is inside every sign byte, so this check is not a
        // substitute for the signature check: it is the check that the
        // signatures are being verified against the right chain at all.
        if decoded.chain_id != self.chain_id {
            return Err(rule(format!(
                "commit chain id {} is not the pinned chain id {}",
                decoded.chain_id, self.chain_id
            )));
        }

        // Consensus-admitted domains must verify against a governance-pinned
        // validator set so a submitter cannot fabricate a private Ed25519 set,
        // and must bind the attested root to the validator-signed `block_hash`
        // because CometBFT `CanonicalVote` signs `block_id.hash`, not `app_hash`.
        let attested_root = if self.require_pinned_set {
            let Some(expected_set) = self.pinned_validator_set else {
                return Err(AdapterError::Unavailable {
                    reason: "no Tendermint validator set is pinned for this domain".to_string(),
                });
            };
            let observed_set = validator_set_commitment(&decoded.validators);
            if observed_set != expected_set {
                return Err(rule(
                    "commit validator set does not match the governance-pinned validator_set_hash",
                ));
            }
            if decoded.app_hash != decoded.block_hash {
                return Err(rule(
                    "consensus-pinned single commit binds block_hash only; unproved app_hash refused",
                ));
            }
            decoded.block_hash
        } else {
            decoded.app_hash
        };

        if policy.require_declared_match {
            if evidence.declared_height != decoded.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != attested_root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }

        let validator_map: std::collections::BTreeMap<[u8; ADDRESS_LEN], &TendermintValidator> =
            decoded.validators.iter().map(|v| (v.address, v)).collect();
        let total = decoded.total_voting_power();
        let required = quorum_threshold(total);
        let mut signed: u128 = 0;
        let mut signers: u64 = 0;
        let mut signed_times: Vec<(u64, u128)> = Vec::with_capacity(decoded.signatures.len());
        for signature in &decoded.signatures {
            let validator = validator_map
                .get(&signature.address)
                .copied()
                .ok_or_else(|| {
                    rule(format!(
                        "the commit carries a signature from {} which is not in the supplied validator set",
                        hex::encode(signature.address)
                    ))
                })?;
            let vote_ts = u64::try_from(signature.timestamp_seconds)
                .map_err(|_| rule("precommit carries a pre-epoch negative timestamp"))?;
            let sign_bytes = decoded.canonical_vote_bytes(signature);
            verify_signature(&sign_bytes, &signature.signature, &validator.public_key).map_err(
                |_| AdapterError::Crypto {
                    what: format!(
                        "validator {} did not sign the canonical precommit for height {} round {}",
                        hex::encode(signature.address),
                        decoded.height,
                        decoded.round
                    ),
                },
            )?;
            let power = u128::from(validator.voting_power);
            signed += power;
            signers += 1;
            signed_times.push((vote_ts, power));
        }

        if signed < required {
            return Err(rule(format!(
                "signed voting power {signed} is below the two-thirds-plus-one threshold {required} of {total}"
            )));
        }

        // Cross-check the unsigned `commit_time` header field against the
        // stake-weighted median of the verified vote timestamps so an ancient
        // commit cannot bypass `policy.max_age` by rewriting `commit_time`.
        signed_times.sort_by_key(|(ts, _)| *ts);
        let half = signed / 2;
        let mut acc_power: u128 = 0;
        let mut median_vote_time = decoded.commit_time;
        for (ts, power) in &signed_times {
            acc_power += *power;
            if acc_power > half {
                median_vote_time = *ts;
                break;
            }
        }
        if decoded.commit_time.abs_diff(median_vote_time) > MAX_COMMIT_TIME_SKEW_SECONDS {
            return Err(rule(format!(
                "commit_time {} diverges from signed precommit median {} by more than {}s",
                decoded.commit_time, median_vote_time, MAX_COMMIT_TIME_SKEW_SECONDS
            )));
        }

        // CometBFT commits are slashable: a validator that double-signs at one
        // height is provably byzantine and loses its bond on the target chain.
        // There is therefore nothing to refuse when the caller requires
        // slashable backing - the backing is. It is stated in `security`
        // below so the caller reads it rather than assumes it.
        if policy.require_slashable && !BACKING_SLASHABLE {
            return Err(AdapterError::UnslashableBacking);
        }

        if policy.max_age != 0 {
            if decoded.commit_time > policy.now.saturating_add(MAX_FUTURE_SECONDS) {
                return Err(rule(format!(
                    "commit timestamp {} exceeds policy clock {} by more than {}s",
                    decoded.commit_time, policy.now, MAX_FUTURE_SECONDS
                )));
            }
            let age = policy.now.saturating_sub(decoded.commit_time);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height: decoded.height,
            state_root: attested_root,
            finalized_at: decoded.commit_time,
            time_unit: TimeUnit::UnixSeconds,
            security: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                signers,
                required: u64::try_from(required).map_err(|_| rule("quorum above u64"))?,
                total_weight: total,
                slashable: BACKING_SLASHABLE,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(decoded.block_hash),
            attested_event_root: None,
            attested_tx_root: None,
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let golden_height = self
            .golden
            .as_ref()
            .and_then(|golden| TendermintCommitEvidence::decode(&golden.payload).ok())
            .map(|decoded| decoded.height)
            .unwrap_or(1);

        let mut probes = vec![
            FaultProbe {
                name: "a declared state root the payload does not carry is a mismatch".to_string(),
                patch: BytePatch::DeclaredRoot { value: [0u8; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "an envelope height the payload does not have is a declaration mismatch"
                    .to_string(),
                patch: BytePatch::DeclaredHeight {
                    value: golden_height.wrapping_add(1),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "a truncated payload must be a refusal, not a partial parse".to_string(),
                patch: BytePatch::TruncatePayload { keep: 16 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "an evidence version the adapter does not read must be refused".to_string(),
                patch: BytePatch::EvidenceVersion {
                    value: EVIDENCE_VERSION + 1,
                },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "the same adapter must not attest a different network".to_string(),
                patch: BytePatch::Network {
                    value: "not-the-pinned-network".to_string(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::WrongAdapter),
            },
        ];

        // A payload-level signature corruption, only when a golden sample is
        // attached. The offset is found by searching the encoded payload for
        // the signature's own bytes, so the probe follows the encoding instead
        // of hard-coding an offset that a field change would silently move.
        if let Some(golden) = &self.golden {
            if let Ok(decoded) = TendermintCommitEvidence::decode(&golden.payload) {
                if let Some(first) = decoded.signatures.first() {
                    if let (Some(prefix), Some(&first_byte)) =
                        (first.signature.get(..8), first.signature.first())
                    {
                        if first.signature.len() == SIGNATURE_LEN {
                            if let Some(offset) = golden
                                .payload
                                .windows(8)
                                .position(|window| window == prefix)
                            {
                                let replacement = if first_byte == 0 { 1 } else { 0 };
                                probes.push(FaultProbe {
                                    name:
                                        "one bit of one signature must be refused as a crypto failure"
                                            .to_string(),
                                    patch: BytePatch::InPayload {
                                        offset,
                                        bytes: vec![replacement],
                                    },
                                    expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Three attacks on the quorum itself, built from the payload's own
        // field offsets. Each is a fault an adapter that counts what it was
        // handed (instead of what it verified) would accept: the offsets are
        // derived by `field_offsets`, so a wire change moves the probe with
        // the field instead of leaving it pointed at the wrong integer.
        if let Some(golden) = &self.golden {
            if let Ok(decoded) = TendermintCommitEvidence::decode(&golden.payload) {
                let offsets = decoded.field_offsets();

                // A. One validator with zero power. The adapter must refuse
                //    the set, not silently count a member that cannot sign.
                if let Some(at) = offsets.first_validator_power_at {
                    probes.push(FaultProbe {
                        name: "a zero-power validator must be refused, not counted".to_string(),
                        patch: BytePatch::InPayload {
                            offset: at,
                            bytes: 0u64.to_le_bytes().to_vec(),
                        },
                        expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
                    });
                }

                // B. The same validator twice in the set. Two entries for one
                //    key is how a commit buys a quorum with one signature.
                if decoded.validators.len() >= 2 {
                    let entry_bytes = ADDRESS_LEN + PUBLIC_KEY_LEN + 8;
                    let first_at = offsets.validators_len_at.saturating_add(8);
                    let second_at = first_at.saturating_add(entry_bytes);
                    if let Some(first) = golden.payload.get(first_at..second_at) {
                        probes.push(FaultProbe {
                            name: "a duplicated validator entry must be refused".to_string(),
                            patch: BytePatch::InPayload {
                                offset: second_at,
                                bytes: first.to_vec(),
                            },
                            expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
                        });
                    }
                }

                // C. The same signature twice. A duplicated precommit must
                //    not add its power a second time.
                if decoded.signatures.len() >= 2 {
                    if let (Some(first_at), Some(len_at)) = (
                        offsets.first_signature_address_at,
                        offsets.first_signature_len_at,
                    ) {
                        let first_len = decoded.signatures.first().map_or(0, |s| s.signature.len());
                        let end = len_at.saturating_add(8).saturating_add(first_len);
                        // `get` rather than `[]`: a slice that does not fit is
                        // a probe that cannot be built, and this function
                        // reports that by not emitting the probe - it must not
                        // panic on a golden sample whose encoding disagrees
                        // with the offsets derived from it.
                        if let Some(first) = golden.payload.get(first_at..end) {
                            let second_entry_bytes = ADDRESS_LEN + 8 + 4 + 8 + first_len;
                            probes.push(FaultProbe {
                                name: "a duplicated signature must not add power twice".to_string(),
                                patch: BytePatch::InPayload {
                                    offset: first_at.saturating_add(second_entry_bytes),
                                    bytes: first.to_vec(),
                                },
                                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
                            });
                        }
                    }
                }
            }
        }

        // Two attacks that change what the commit *means* rather than what it
        // contains: a set that can no longer reach the threshold, and a commit
        // signed for a different chain. Both are reachable by rewriting one
        // integer or one byte of the payload, which is exactly the kind of
        // forgery a submitter controls the bytes for.
        if let Some(golden) = &self.golden {
            if let Ok(decoded) = TendermintCommitEvidence::decode(&golden.payload) {
                let offsets = decoded.field_offsets();

                // D. Raise a NON-signing validator's power. Total (and so the
                //    threshold) goes up while signed power does not, so the
                //    commit becomes sub-threshold with every signature still
                //    valid. Lowering a signer's power would move `signed` and
                //    `total` together and might leave the ratio satisfied.
                if decoded.validators.len() >= 2 {
                    let signed: std::collections::BTreeSet<[u8; ADDRESS_LEN]> =
                        decoded.signatures.iter().map(|s| s.address).collect();
                    let entry_bytes = ADDRESS_LEN + PUBLIC_KEY_LEN + 8;
                    let first_at = offsets.validators_len_at.saturating_add(8);
                    if let Some(index) = decoded
                        .validators
                        .iter()
                        .position(|v| !signed.contains(&v.address))
                    {
                        let offset = first_at.saturating_add(index.saturating_mul(entry_bytes))
                            + ADDRESS_LEN
                            + PUBLIC_KEY_LEN;
                        probes.push(FaultProbe {
                            name: "a set that cannot reach the threshold must be refused"
                                .to_string(),
                            patch: BytePatch::InPayload {
                                offset,
                                bytes: u64::MAX.to_le_bytes().to_vec(),
                            },
                            expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
                        });
                    }
                }

                // E. One byte of the chain id, so the commit claims a chain the
                //    adapter was not pinned to. The byte is derived from the
                //    payload's own chain id rather than assumed ASCII.
                if let Some(first) = decoded.chain_id.bytes().next() {
                    let flipped = if first == 0 { 1 } else { first.wrapping_sub(1) };
                    probes.push(FaultProbe {
                        name: "a commit for another chain id must be refused".to_string(),
                        patch: BytePatch::InPayload {
                            offset: 8,
                            bytes: vec![flipped],
                        },
                        expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
                    });
                }
            }
        }

        probes
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

/// Whether a Tendermint commit's backing is slashable on the target chain.
/// It is: equivocation at one height is provable from two signed commits.
pub const BACKING_SLASHABLE: bool = true;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::{admit, ProbeOutcome};
    use crate::crypto::primitives::KeyPair;

    /// A real `noble-1` commit at height 64239414, captured from a public
    /// CometBFT RPC (`/commit` and `/validators?height=64239414`) and reduced
    /// to the fields this adapter reads. The validator addresses are the
    /// `SHA256(public_key)[..20]` of the keys in the same capture, and all
    /// five signatures in it verify against those keys under the canonical
    /// encoding below - that is what makes this a golden sample rather than a
    /// transcript.
    ///
    /// `timestamp_seconds` and `timestamp_nanos` are the RPC's RFC3339 vote
    /// timestamps, which were e.g. `2026-11-18T07:18:55.949535266Z` for the
    /// first signer. They are carried numerically because the adapter's wire
    /// shape is numeric; nothing here parses calendar text.
    const NOBLE_COMMIT_JSON: &str = r#"{"chain_id":"noble-1","height":64239414,"round":0,"block_hash":"8B3E0A7F14EF04EC5A3DE98CE214249D9F49711DAACD2BAB433BA9785583F394","parts_total":1,"app_hash":"789D3D6D36565DDA8721303A0CC1067E1D34F5A67800FB941ACB077382F3BED2","commit_time_seconds":1794986334,"validators":[{"address":"417E75EF24DE0207B9BFD235331F4897AD28738A","public_key":"233B590A7507763A0583CE319077EE0AE134F7148091C25B25E814ED5A058D7E","voting_power":1},{"address":"4E4BF0D6B90FCEC903166CA9909EDA38871BC7C5","public_key":"41B7B382A21E603DE1309C95449F2DEA84A1ED7F9649840FE8DA6D0D7447BDDB","voting_power":1},{"address":"7259FA8ABEE6365224E8917262A077D8F21C215E","public_key":"A93CEEDCBB78EFBB56EBBC0962929D9D93F5DFCF0AC8AED7DA922334C1E791D3","voting_power":1},{"address":"913A87C9053EE31DC75DBC0711499841F4FE41D2","public_key":"C3FA937121CB48D92607E2813C9E11E664C5B25D4808C00A2FACA8D77887C279","voting_power":1},{"address":"9814A41D7ADECFC8686C1B551CFE12A5529CCF47","public_key":"EAC07122ADBDDEF6FE94FD95172E3189C30085D499645D9BABA6AD00FF01B4A3","voting_power":1},{"address":"D1AD8B58C084D0E6014ACEADD5B44E9458F11A58","public_key":"BF8F447AF3D9BE00578A370D001F843C89782025F886482751A2832E5320AEFF","voting_power":1},{"address":"F21F8BD8AB575EC5D5B3B691080830CCEC51BD1D","public_key":"49A8CD065495568AE199F166CF8F7F3170D0D036E8E9CEA8A2C869F79F1F3403","voting_power":1}],"signatures":[{"validator_address":"4E4BF0D6B90FCEC903166CA9909EDA38871BC7C5","timestamp":"2026-11-18T07:18:55.949535266Z","signature":"FA5C29908B26F44BEF52173B81F681D08681BE67044D30B7B6EA316B06DB665C82E26C656C275839A15DDBCD137F7430B5529545A75A5DABA4FACB42980DF407","timestamp_seconds":1794986335,"timestamp_nanos":949535266},{"validator_address":"7259FA8ABEE6365224E8917262A077D8F21C215E","timestamp":"2026-11-18T07:18:55.91613621Z","signature":"5CC6DDE372ECD598B1A2919CE182F837ED077F46FFD9729CC4E0E90649EADE070B4CD8E982F9BEEE4FF943AF66F55F4398414FEC0032160E13567A03153FF302","timestamp_seconds":1794986335,"timestamp_nanos":916136210},{"validator_address":"913A87C9053EE31DC75DBC0711499841F4FE41D2","timestamp":"2026-11-18T07:18:55.972621579Z","signature":"0DB93F558994717907001F0CDFFFBB774C09B136A67FCE121D711532DA87D45C4665D6C89011268EE0AE7C125A31893AC28E8B7EE2835C82E50B27166583310D","timestamp_seconds":1794986335,"timestamp_nanos":972621579},{"validator_address":"D1AD8B58C084D0E6014ACEADD5B44E9458F11A58","timestamp":"2026-11-18T07:18:55.975841154Z","signature":"BFC42102253DC47C97B1C3BE0978574C95AE0251B585083EA1B4501FC263A3AF34CA091914DB18FA816AB392CEF15C781E8B45482BA58D79B06C3F5BF596A703","timestamp_seconds":1794986335,"timestamp_nanos":975841154},{"validator_address":"F21F8BD8AB575EC5D5B3B691080830CCEC51BD1D","timestamp":"2026-11-18T07:18:55.920354751Z","signature":"A60C0AD32F60BA0B4D6923A0A39DDD4768AB6127415D601DFF56228CBD606264605B9946272E24ADFFA76DFD4F344EB981308A95925B262926A793160609A503","timestamp_seconds":1794986335,"timestamp_nanos":920354751}],"parts_hash":"8C02B74E3120E2416FD0016D96242719486ED754BF350E378ABD11751ABDB1DC"}"#;

    /// The canonical precommit sign bytes for the noble commit's first
    /// signature, computed independently and checked against the live
    /// signature. Pinned so a refactor of the encoder cannot silently change
    /// the bytes - which would be invisible, because a wrong encoder simply
    /// refuses every real commit.
    ///
    /// Decoded by hand, it is: `0x6C` (message length 108), `08 02` (precommit
    /// type), `11` + 8 bytes (sfixed64 height 64239414), `22 48` (block id, 72
    /// bytes: hash + part-set header with total 1 and the real part-set hash),
    /// `2A 0C` (timestamp), `32 07 "noble-1"`. There is no round field: proto3
    /// omits a zero round, which is exactly what a round-0 commit signs.
    const NOBLE_FIRST_SIGN_BYTES_HEX: &str = "6C0802113637D4030000000022480A208B3E0A7F14EF04EC5A3DE98CE214249D9F49711DAACD2BAB433BA9785583F3941224080112208C02B74E3120E2416FD0016D96242719486ED754BF350E378ABD11751ABDB1DC2A0C08DFA2F5D70610A284E3C40332076E6F626C652D31";

    #[derive(serde::Deserialize)]
    struct Fixture {
        chain_id: String,
        height: u64,
        round: i64,
        block_hash: String,
        parts_total: u32,
        parts_hash: String,
        app_hash: String,
        commit_time_seconds: u64,
        validators: Vec<FixtureValidator>,
        signatures: Vec<FixtureSignature>,
    }

    #[derive(serde::Deserialize)]
    struct FixtureValidator {
        address: String,
        public_key: String,
        voting_power: u64,
    }

    #[derive(serde::Deserialize)]
    struct FixtureSignature {
        validator_address: String,
        timestamp_seconds: i64,
        timestamp_nanos: u32,
        signature: String,
    }

    fn fixed<const N: usize>(hex_text: &str) -> [u8; N] {
        let bytes = hex::decode(hex_text).expect("fixture hex decodes");
        assert_eq!(bytes.len(), N, "fixture field width");
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn noble_commit() -> TendermintCommitEvidence {
        let fixture: Fixture =
            serde_json::from_str(NOBLE_COMMIT_JSON).expect("golden fixture parses");
        TendermintCommitEvidence {
            chain_id: fixture.chain_id,
            height: fixture.height,
            round: fixture.round,
            block_hash: fixed(&fixture.block_hash),
            parts_total: fixture.parts_total,
            parts_hash: fixed(&fixture.parts_hash),
            app_hash: fixed(&fixture.app_hash),
            commit_time: fixture.commit_time_seconds,
            validators: fixture
                .validators
                .iter()
                .map(|v| TendermintValidator {
                    address: fixed(&v.address),
                    public_key: fixed(&v.public_key),
                    voting_power: v.voting_power,
                })
                .collect(),
            signatures: fixture
                .signatures
                .iter()
                .map(|s| TendermintSignature {
                    address: fixed(&s.validator_address),
                    timestamp_seconds: s.timestamp_seconds,
                    timestamp_nanos: s.timestamp_nanos,
                    signature: hex::decode(&s.signature).expect("signature hex"),
                })
                .collect(),
        }
    }

    fn adapter() -> TendermintFinalityAdapter {
        TendermintFinalityAdapter::new("noble", "noble-1")
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy::strict(1_794_986_334)
    }

    fn evidence_for(
        adapter: &TendermintFinalityAdapter,
        commit: &TendermintCommitEvidence,
    ) -> RawConsensusEvidence {
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "noble".to_string(),
            payload: commit.encode().expect("payload encodes"),
            declared_height: commit.height,
            declared_root: commit.app_hash,
            submitter: Address([7u8; 32]),
        }
    }

    /// Re-signs every signature of `commit` with the key that owns its address,
    /// so a test can build a commit that is wrong in exactly one respect and
    /// still carries valid signatures - the only way to test what happens
    /// *after* the signature check.
    fn resign(commit: &mut TendermintCommitEvidence, keys: &[KeyPair]) {
        let messages: Vec<Vec<u8>> = commit
            .signatures
            .iter()
            .map(|signature| commit.canonical_vote_bytes(signature))
            .collect();
        for (signature, message) in commit.signatures.iter_mut().zip(messages) {
            let key = keys
                .iter()
                .find(|key| validator_address_of(&key.public_key_bytes()) == signature.address)
                .expect("a key for every signer");
            signature.signature = key.sign(&message).to_vec();
        }
    }

    fn keys(count: usize) -> Vec<KeyPair> {
        (0..count)
            .map(|index| {
                // Fixed seeds, so a failing test names the same key on every
                // run and every machine.
                let mut seed = [0u8; 32]; // ed25519 seed width, `KeyPair::from_seed`
                seed[0] = index as u8 + 1;
                seed[seed.len() - 1] = 0x5A;
                KeyPair::from_seed(&seed).expect("deterministic test key")
            })
            .collect()
    }

    /// A synthetic commit over `keys` with the given powers and the first
    /// `signers` keys signing. Round 1 on purpose: the real golden sample is a
    /// round-0 commit, where the round field is omitted from the sign bytes,
    /// so only a non-zero round exercises its encoding.
    fn synthetic_commit(powers: &[u64], signers: usize) -> TendermintCommitEvidence {
        let keyring = keys(powers.len());
        let validators: Vec<TendermintValidator> = keyring
            .iter()
            .zip(powers)
            .map(|(key, power)| TendermintValidator {
                address: validator_address_of(&key.public_key_bytes()),
                public_key: key.public_key_bytes(),
                voting_power: *power,
            })
            .collect();
        let signatures = validators
            .iter()
            .take(signers)
            .map(|validator| TendermintSignature {
                address: validator.address,
                timestamp_seconds: 1_700_000_000,
                timestamp_nanos: 7,
                signature: vec![0u8; SIGNATURE_LEN],
            })
            .collect();
        let mut commit = TendermintCommitEvidence {
            chain_id: "noble-1".to_string(),
            height: 900,
            round: 1,
            block_hash: [0x11; 32],
            parts_total: 3,
            parts_hash: [0x22; 32],
            app_hash: [0x33; 32],
            commit_time: 1_700_000_000,
            validators,
            signatures,
        };
        resign(&mut commit, &keyring);
        commit
    }

    #[test]
    fn a_real_noble_commit_verifies_and_attests_its_block() {
        let adapter = adapter();
        let commit = noble_commit();
        let attestation = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect("the real mainnet commit verifies");

        assert_eq!(attestation.height, 64_239_414);
        assert_eq!(attestation.finalized_at, 1_794_986_334);
        assert_eq!(attestation.time_unit, TimeUnit::UnixSeconds);
        assert_eq!(attestation.state_root, commit.app_hash);
        assert_eq!(attestation.attested_block_hash, Some(commit.block_hash));
        assert_eq!(attestation.adapter, adapter.descriptor().id);
        assert_eq!(attestation.evidence_version, EVIDENCE_VERSION);

        match attestation.security {
            SecurityBacking::SignatureSet {
                scheme,
                signers,
                required,
                total_weight,
                slashable,
            } => {
                assert_eq!(scheme, ObservedScheme::Scheme(SchemeId::ED25519));
                assert_eq!(signers, 5, "five of the seven validators signed");
                assert_eq!(required, 5, "2 * 7 / 3 + 1");
                assert_eq!(total_weight, 7);
                assert!(slashable, "a CometBFT commit is slashable evidence");
            }
            other => panic!("expected a signature-set backing, got {other:?}"),
        }
    }

    #[test]
    fn the_descriptor_declares_protocol_finality_at_depth_one() {
        let descriptor = adapter().descriptor();
        assert_eq!(descriptor.finality_kind, FinalityKind::ProtocolFinality);
        assert_eq!(descriptor.required_depth, 1);
        assert_eq!(descriptor.time_unit, TimeUnit::UnixSeconds);
        assert_eq!(
            descriptor.accepted_evidence_versions,
            vec![EVIDENCE_VERSION]
        );
        assert!(matches!(
            descriptor.trust_model,
            TrustModel::HonestMajority { .. }
        ));
        assert!(adapter().is_classical_only_quorum());
    }

    #[test]
    fn the_sign_bytes_are_pinned_to_the_verified_canonical_encoding() {
        let commit = noble_commit();
        let bytes = commit.canonical_vote_bytes(&commit.signatures[0]);
        assert_eq!(hex::encode_upper(&bytes), NOBLE_FIRST_SIGN_BYTES_HEX);
        // A round-0 commit has no round field in its sign bytes, so the
        // encoding is exactly the pinned 109 bytes: one varint length prefix
        // and a 108-byte message. The pinned hex above is the check; the
        // length is asserted too so a future field insertion shows up as a
        // length change rather than only as a hex diff.
        assert_eq!(commit.round, 0);
        assert_eq!(bytes.len(), 109);
        assert_eq!(usize::from(bytes[0]) + 1, bytes.len());
        assert_eq!(&bytes[bytes.len() - 8..], b"\x07noble-1");
    }

    #[test]
    fn the_quorum_threshold_is_two_thirds_plus_one() {
        // (total, threshold) pairs computed by hand from CometBFT's rule.
        let cases = [
            (0u128, 1u128),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 3),
            (7, 5),
            (10, 7),
            (21, 15),
            (100, 67),
            (180, 121),
        ];
        for (total, expected) in cases {
            assert_eq!(quorum_threshold(total), expected, "total power {total}");
        }
        // Two thirds exactly is not a quorum: a third of the power must be
        // unable to commit, so the threshold is strictly above two thirds.
        assert!(quorum_threshold(3) > 2);
        assert!(quorum_threshold(100) > 66);
    }

    #[test]
    fn a_flipped_signature_byte_is_refused_as_a_crypto_failure() {
        let adapter = adapter();
        let mut commit = noble_commit();
        commit.signatures[0].signature[0] ^= 0x01;
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("a forged signature must not verify");
        assert!(
            matches!(error, AdapterError::Crypto { .. }),
            "expected a crypto refusal, got {error:?}"
        );
    }

    #[test]
    fn dropping_a_signature_drops_below_the_quorum() {
        let adapter = adapter();
        let mut commit = noble_commit();
        commit.signatures.pop();
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("four of seven is below two thirds plus one");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(
                    rule.contains("below the two-thirds-plus-one threshold"),
                    "{rule}"
                );
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicated_signature_does_not_count_twice() {
        let adapter = adapter();
        let mut commit = noble_commit();
        let duplicate = commit.signatures[0].clone();
        commit.signatures.push(duplicate);
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("one validator cannot sign twice in one commit");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("signed twice"), "{rule}");
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_signer_outside_the_supplied_validator_set_is_refused() {
        let adapter = adapter();
        let mut commit = noble_commit();
        commit.signatures[0].address = [0xAB; ADDRESS_LEN];
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("an unknown signer cannot contribute power");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("not in the supplied validator set"), "{rule}");
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_validator_address_that_is_not_the_hash_of_its_key_is_refused() {
        let adapter = adapter();
        let mut commit = noble_commit();
        commit.validators[0].address = [0xCD; ADDRESS_LEN];
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("an address must be bound to its key");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("not SHA256 of its public key"), "{rule}");
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicated_validator_entry_is_refused() {
        let adapter = adapter();
        let mut commit = noble_commit();
        let duplicate = commit.validators[0];
        commit.validators.push(duplicate);
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("a doubled validator entry would double its power");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("appears twice"), "{rule}");
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_commit_from_another_chain_is_refused_even_with_valid_signatures() {
        let adapter = adapter();
        let keyring = keys(4);
        let mut commit = synthetic_commit(&[3, 3, 2, 2], 3);
        commit.chain_id = "osmosis-1".to_string();
        resign(&mut commit, &keyring);
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("another chain's commit is not this chain's finality");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("is not the pinned chain id"), "{rule}");
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_round_is_part_of_what_was_signed() {
        let adapter = adapter();
        let mut commit = synthetic_commit(&[3, 3, 2, 2], 3);
        commit.round = 2;
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("changing the round changes the sign bytes");
        assert!(
            matches!(error, AdapterError::Crypto { .. }),
            "expected a crypto refusal, got {error:?}"
        );
    }

    #[test]
    fn the_block_hash_is_part_of_what_was_signed() {
        let adapter = adapter();
        let mut commit = synthetic_commit(&[3, 3, 2, 2], 3);
        commit.block_hash = [0x44; 32];
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("changing the block id changes the sign bytes");
        assert!(
            matches!(error, AdapterError::Crypto { .. }),
            "expected a crypto refusal, got {error:?}"
        );
    }

    #[test]
    fn the_part_set_hash_is_part_of_what_was_signed() {
        let adapter = adapter();
        let mut commit = synthetic_commit(&[3, 3, 2, 2], 3);
        commit.parts_hash = [0x55; 32];
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("the part-set hash is signed, not decoration");
        assert!(
            matches!(error, AdapterError::Crypto { .. }),
            "expected a crypto refusal, got {error:?}"
        );
    }

    #[test]
    fn a_sub_threshold_commit_is_refused_even_with_valid_signatures() {
        let adapter = adapter();
        // Powers 3, 3, 2, 2 total 10, so the threshold is 7. The two signers
        // hold 3 + 3 = 6 power and every one of their signatures is genuine.
        let commit = synthetic_commit(&[3, 3, 2, 2], 2);
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("half the power is not a quorum");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(
                    rule.contains("below the two-thirds-plus-one threshold"),
                    "{rule}"
                );
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_exactly_two_thirds_commit_is_still_refused() {
        let adapter = adapter();
        // Powers 3, 3, 3: total 9, threshold 7. Two signers hold 6 = exactly
        // two thirds, which is not more than two thirds.
        let commit = synthetic_commit(&[3, 3, 3], 2);
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("exactly two thirds cannot commit a block");
        assert!(
            matches!(error, AdapterError::ConsensusRule { .. }),
            "expected a consensus-rule refusal, got {error:?}"
        );
    }

    #[test]
    fn a_state_root_the_payload_does_not_carry_is_a_declaration_mismatch() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut evidence = evidence_for(&adapter, &commit);
        evidence.declared_root = [0x99; 32];
        let error = adapter
            .verify(&evidence, &policy())
            .expect_err("the envelope must not claim a root the payload lacks");
        assert!(
            matches!(
                error,
                AdapterError::DeclarationMismatch {
                    field: "state_root"
                }
            ),
            "expected a state-root declaration mismatch, got {error:?}"
        );
    }

    #[test]
    fn a_height_the_payload_does_not_carry_is_a_declaration_mismatch() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut evidence = evidence_for(&adapter, &commit);
        evidence.declared_height += 1;
        let error = adapter
            .verify(&evidence, &policy())
            .expect_err("the envelope must not claim a height the payload lacks");
        assert!(
            matches!(error, AdapterError::DeclarationMismatch { field: "height" }),
            "expected a height declaration mismatch, got {error:?}"
        );
    }

    #[test]
    fn a_stale_commit_is_refused_when_the_caller_sets_a_max_age() {
        let adapter = adapter();
        let commit = noble_commit();
        let evidence = evidence_for(&adapter, &commit);
        let mut strict = policy();
        strict.max_age = 60;
        strict.now = commit.commit_time + 3_600;
        let error = adapter
            .verify(&evidence, &strict)
            .expect_err("an hour old and a one minute budget");
        assert!(
            matches!(
                error,
                AdapterError::Stale {
                    age: 3_600,
                    max_age: 60
                }
            ),
            "expected a staleness refusal, got {error:?}"
        );
        // The same commit is fresh inside the window.
        strict.now = commit.commit_time + 59;
        assert!(adapter.verify(&evidence, &strict).is_ok());
    }

    #[test]
    fn a_depth_requirement_above_one_is_refused_rather_than_ignored() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut demanding = policy();
        demanding.min_depth = 2;
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &demanding)
            .expect_err("one commit is the depth a commit can give");
        assert!(
            matches!(
                error,
                AdapterError::InsufficientDepth {
                    observed: 1,
                    required: 2
                }
            ),
            "expected an insufficient-depth refusal, got {error:?}"
        );
    }

    #[test]
    fn a_different_network_label_is_refused() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut evidence = evidence_for(&adapter, &commit);
        evidence.network = "cosmoshub".to_string();
        let error = adapter
            .verify(&evidence, &policy())
            .expect_err("one adapter binary must not attest another network");
        assert!(
            matches!(error, AdapterError::WrongAdapter { .. }),
            "expected a wrong-adapter refusal, got {error:?}"
        );
    }

    #[test]
    fn an_unread_evidence_version_is_refused() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut evidence = evidence_for(&adapter, &commit);
        evidence.evidence_version = EVIDENCE_VERSION + 1;
        let error = adapter
            .verify(&evidence, &policy())
            .expect_err("the version is declared, never sniffed");
        assert!(
            matches!(
                error,
                AdapterError::UnsupportedEvidenceVersion { version: 2, .. }
            ),
            "expected an unsupported-version refusal, got {error:?}"
        );
    }

    #[test]
    fn another_adapters_evidence_is_refused() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut evidence = evidence_for(&adapter, &commit);
        evidence.adapter = AdapterId::from_name("some-other-adapter");
        let error = adapter
            .verify(&evidence, &policy())
            .expect_err("evidence is addressed to an adapter, and this is not it");
        assert!(
            matches!(error, AdapterError::WrongAdapter { .. }),
            "expected a wrong-adapter refusal, got {error:?}"
        );
    }

    #[test]
    fn a_truncated_payload_is_malformed_not_partially_read() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut evidence = evidence_for(&adapter, &commit);
        evidence.payload.truncate(evidence.payload.len() / 2);
        let error = adapter
            .verify(&evidence, &policy())
            .expect_err("a short read is a refusal");
        assert!(
            matches!(error, AdapterError::Malformed { .. }),
            "expected a malformed refusal, got {error:?}"
        );
    }

    #[test]
    fn a_payload_above_the_cap_is_refused_before_decoding() {
        let adapter = adapter();
        let commit = noble_commit();
        let mut evidence = evidence_for(&adapter, &commit);
        evidence.payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let error = adapter
            .verify(&evidence, &policy())
            .expect_err("an oversized payload is refused before interpretation");
        match error {
            AdapterError::Malformed { reason, .. } => {
                assert!(reason.contains("above the"), "{reason}");
            }
            other => panic!("expected a malformed refusal, got {other:?}"),
        }
    }

    #[test]
    fn zero_power_validators_are_refused() {
        let adapter = adapter();
        let mut commit = noble_commit();
        commit.validators[0].voting_power = 0;
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("a zero-power validator cannot contribute");
        assert!(
            matches!(error, AdapterError::ConsensusRule { .. }),
            "expected a consensus-rule refusal, got {error:?}"
        );
    }

    #[test]
    fn a_wrong_signature_width_is_refused() {
        let adapter = adapter();
        let mut commit = noble_commit();
        commit.signatures[0].signature.truncate(SIGNATURE_LEN - 1);
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("a 63-byte signature is not an Ed25519 signature");
        assert!(
            matches!(error, AdapterError::ConsensusRule { .. }),
            "expected a consensus-rule refusal, got {error:?}"
        );
    }

    #[test]
    fn admission_accepts_the_golden_and_refuses_every_probe() {
        let adapter = adapter();
        let commit = noble_commit();
        let golden = evidence_for(&adapter, &commit);
        let adapter = adapter.with_golden(golden.clone());
        let report = admit(&adapter, &policy());
        assert!(report.golden_verified, "golden refused: {report:?}");
        assert_eq!(report.evidence_version, EVIDENCE_VERSION);
        for (name, outcome) in &report.probes {
            assert!(
                matches!(outcome, ProbeOutcome::Refused { .. }),
                "probe {name:?} was not refused as expected: {outcome:?}"
            );
        }
        assert!(
            report.admitted,
            "admission refused with {} probes: {report:?}",
            report.probes.len()
        );
        // The probe set must actually attack the signature check, not only the
        // envelope: without that, an adapter that never verifies a signature
        // would still pass admission.
        assert!(
            report.probes.len() >= 11,
            "expected the signature-level and quorum-level probes (11+), got {}: {report:?}",
            report.probes.len()
        );
        // Every probe the adapter declares must be a probe it can build from
        // its own golden sample. A probe whose patch does not apply is a probe
        // that proves nothing, and `admit` would still count it as passed.
        for (name, outcome) in &report.probes {
            assert!(
                !matches!(outcome, ProbeOutcome::NotApplicable { .. }),
                "probe {name:?} could not be applied to the golden sample: {outcome:?}"
            );
        }
    }

    /// `field_offsets` must name the bytes it claims to name. This is the test
    /// that keeps the three quorum probes honest: an offset that drifts by one
    /// still "applies" and still produces a refusal - just of something else.
    #[test]
    fn field_offsets_point_at_the_fields_they_name() {
        let commit = synthetic_commit(&[10, 10, 10], 3);
        let payload = commit.encode().expect("payload encodes");
        let offsets = commit.field_offsets();

        // validators length prefix reads back as the validator count.
        let declared = u64::from_le_bytes(
            payload[offsets.validators_len_at..offsets.validators_len_at + 8]
                .try_into()
                .expect("8 bytes"),
        );
        assert_eq!(declared as usize, commit.validators.len());

        // The first validator's power reads back as that validator's power.
        let at = offsets.first_validator_power_at.expect("a first validator");
        let power = u64::from_le_bytes(payload[at..at + 8].try_into().expect("8 bytes"));
        assert_eq!(power, commit.validators[0].voting_power);

        // The first signature's address reads back as that signer's address.
        let at = offsets
            .first_signature_address_at
            .expect("a first signature");
        assert_eq!(
            &payload[at..at + ADDRESS_LEN],
            &commit.signatures[0].address
        );

        // The signature length prefix reads back as the signature width.
        let at = offsets.first_signature_len_at.expect("a first signature");
        let len = u64::from_le_bytes(payload[at..at + 8].try_into().expect("8 bytes"));
        assert_eq!(len as usize, commit.signatures[0].signature.len());
    }

    /// The three quorum-level attacks must be refused by the adapter itself,
    /// not only counted as malformed by the decoder. Each payload is built by
    /// patching the encoded bytes at a derived offset, so this test fails if
    /// either the check or the offset regresses.
    #[test]
    fn quorum_level_faults_are_refused_by_the_adapter() {
        let adapter = adapter();
        let keyring = keys(4);
        let mut commit = synthetic_commit(&[10, 10, 10, 10], 4);
        // Powers 10,10,10,10 -> threshold 2*40/3+1 = 27; three signers reach
        // 30, so a duplicated entry or signature would be enough to pass if
        // the adapter counted what it was handed.
        //
        // The freshness window is computed from the commit's own time, not
        // from `policy()`'s fixed `now`: a synthetic commit is dated in 2023
        // and `policy()` in 2026, so the staleness rule would refuse the
        // *untouched* commit and every probe would "pass" for the wrong
        // reason. A test that cannot show the clean payload being accepted
        // proves nothing about the corrupted ones.
        resign(&mut commit, &keyring);
        let untouched = evidence_for(&adapter, &commit);
        let mut fresh = policy();
        fresh.now = commit.commit_time;
        let clean = adapter.verify(&untouched, &fresh);
        assert!(
            clean.is_ok(),
            "the untouched commit must verify before it is corrupted: {clean:?}"
        );

        let offsets = commit.field_offsets();
        let payload = commit.encode().expect("payload encodes");

        // A. zero power on the first validator
        let at = offsets.first_validator_power_at.expect("a first validator");
        let mut corrupted = untouched.clone();
        corrupted.payload[at..at + 8].copy_from_slice(&0u64.to_le_bytes());
        let error = adapter
            .verify(&corrupted, &fresh)
            .expect_err("a zero-power validator cannot carry a quorum");
        assert!(
            matches!(error, AdapterError::ConsensusRule { .. }),
            "{error:?}"
        );

        // B. duplicated validator entry
        let entry = ADDRESS_LEN + PUBLIC_KEY_LEN + 8;
        let first_start = offsets.validators_len_at + 8;
        let mut corrupted = untouched.clone();
        corrupted.payload[first_start + entry..first_start + 2 * entry]
            .copy_from_slice(&payload[first_start..first_start + entry]);
        let error = adapter
            .verify(&corrupted, &fresh)
            .expect_err("one key cannot hold two seats");
        assert!(
            matches!(error, AdapterError::ConsensusRule { .. }),
            "{error:?}"
        );

        // C. duplicated signature
        let first_at = offsets
            .first_signature_address_at
            .expect("a first signature");
        let len_at = offsets.first_signature_len_at.expect("a first signature");
        let sig_len = commit.signatures[0].signature.len();
        let end = len_at + 8 + sig_len;
        let second = first_at + (ADDRESS_LEN + 8 + 4 + 8 + sig_len);
        let mut corrupted = untouched.clone();
        corrupted.payload[second..second + (end - first_at)]
            .copy_from_slice(&payload[first_at..end]);
        let error = adapter
            .verify(&corrupted, &fresh)
            .expect_err("one validator cannot sign twice");
        assert!(
            matches!(error, AdapterError::ConsensusRule { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_commit_signed_by_an_unpinned_key_is_refused() {
        let adapter = adapter();
        // The evidence's own keys are honest, the addresses bind, the quorum is
        // met - but the chain id says this is not the pinned chain's commit.
        let keyring = keys(4);
        let mut commit = synthetic_commit(&[1, 1, 1, 1], 3);
        commit.chain_id = "noble-2".to_string();
        resign(&mut commit, &keyring);
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("a different chain id is a different chain");
        assert!(
            matches!(error, AdapterError::ConsensusRule { .. }),
            "expected a consensus-rule refusal, got {error:?}"
        );
    }

    #[test]
    fn consensus_pinned_tendermint_refuses_self_signed_validator_set_forged_app_hash_and_stale_clock_spoof(
    ) {
        // 1. Pinned Noble validator set refuses an attacker's self-signed
        //    validator set even when `chain_id == "noble-1"` and 3/4 quorum holds.
        let honest_noble = noble_commit();
        let pinned_hash = validator_set_commitment(&honest_noble.validators);
        let pinned = TendermintFinalityAdapter::new_pinned("noble", "noble-1", Some(pinned_hash));

        let attacker_keys = keys(4);
        let mut forged = synthetic_commit(&[1, 1, 1, 1], 3);
        forged.chain_id = "noble-1".to_string();
        forged.app_hash = forged.block_hash;
        resign(&mut forged, &attacker_keys);
        let err = pinned
            .verify(&evidence_for(&pinned, &forged), &policy())
            .expect_err("self-generated validator set must be refused under consensus pin");
        assert!(matches!(err, AdapterError::ConsensusRule { .. }));

        // 2. Unsigned `app_hash != block_hash` on a genuine Noble commit is
        //    refused on the consensus-pinned path, while binding `app_hash` and
        //    `declared_root` to the validator-signed `block_hash` succeeds.
        let mut swapped_app = honest_noble.clone();
        swapped_app.app_hash = [0xde; 32];
        let err = pinned
            .verify(&evidence_for(&pinned, &swapped_app), &policy())
            .expect_err("unsigned app_hash substitution must be refused");
        assert!(matches!(err, AdapterError::ConsensusRule { .. }));

        let mut block_bound = honest_noble.clone();
        block_bound.app_hash = block_bound.block_hash;
        let att = pinned
            .verify(&evidence_for(&pinned, &block_bound), &policy())
            .expect("pinned Noble commit bound to signed block_hash verifies");
        assert_eq!(att.state_root, honest_noble.block_hash);

        // 3. Rewriting `commit_time` far from the signed vote timestamps or
        //    into the far future (`u64::MAX`) is refused.
        let mut spoofed_time = honest_noble.clone();
        spoofed_time.commit_time += 86_400;
        let err = adapter()
            .verify(&evidence_for(&adapter(), &spoofed_time), &policy())
            .expect_err("spoofed commit_time outside signed vote median must fail");
        assert!(matches!(err, AdapterError::ConsensusRule { .. }));

        let mut future_policy = policy();
        future_policy.max_age = 300;
        future_policy.now = honest_noble
            .commit_time
            .saturating_sub(MAX_FUTURE_SECONDS + 60);
        let err = adapter()
            .verify(&evidence_for(&adapter(), &honest_noble), &future_policy)
            .expect_err("far-future commit must fail closed under max_age");
        assert!(matches!(err, AdapterError::ConsensusRule { .. }));
    }

    // -------------------------------------------------------------------
    // Registration, admission, and the bridge
    // -------------------------------------------------------------------
    //
    // The tests above prove the adapter reads a commit correctly. They do not
    // prove the family is reachable from the production doors: that a
    // permissionless registrant can register it, that admission runs its probe
    // suite, that the stored spec rebuilds an adapter which still verifies, and
    // that the bridge finalizes a commitment whose roots the attestation binds.
    // The Bitcoin SPV family has that integration; this one did not. These are
    // it, and the golden sample is the same real `noble-1` commit.

    use crate::cross_domain::external::{
        decode_external_evidence, encode_external_evidence, AdapterSpec, IntakeState,
        RegistrationRequest, VersionPolicy, EXTERNAL_DOMAIN_FINALITY_ADAPTER,
    };
    use crate::domain::finality_adapter::{DomainFinalityAdapter, FinalityStatus};
    use crate::domain::types::{
        ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
    };

    /// A commit a consensus-pinned registration can admit: the pinned adapter
    /// binds the validator-signed `block_hash`, so `app_hash` must equal it.
    fn pinned_golden_commit() -> TendermintCommitEvidence {
        // All three sign: two of three is 10 of 15, below the +2/3+1 threshold
        // of 11, so a two-signer golden would be refused for the wrong reason.
        let mut commit = synthetic_commit(&[5, 5, 5], 3);
        commit.app_hash = commit.block_hash;
        commit
    }

    fn registration_request(set_hash: [u8; 32]) -> RegistrationRequest {
        let adapter = adapter();
        let golden = evidence_for(&adapter, &pinned_golden_commit());
        let economics = IntakeState::conservative_economics(1_000_000);
        RegistrationRequest {
            spec: AdapterSpec::TendermintCommit {
                network: "noble".to_string(),
                chain_id: "noble-1".to_string(),
                validator_set_hash: Some(set_hash),
            },
            policy: admission_policy(),
            economics,
            versions: VersionPolicy::single(adapter.descriptor().id, 1, 0),
            bond_atoms: economics.required_bond_atoms(),
            poster: Address([9u8; 32]),
            golden,
        }
    }

    fn pinned_intake(commit: &TendermintCommitEvidence) -> IntakeState {
        let mut state = IntakeState::new();
        state.pin_tendermint_anchor(
            "noble",
            PinnedTendermintAnchor {
                chain_id: commit.chain_id.clone(),
                validator_set_hash: validator_set_commitment(&commit.validators),
            },
        );
        state
    }

    /// The clock admission measures freshness against. The golden commit is
    /// from 2026, so a registration must supply a `now` at or after its
    /// `commit_time`, exactly as `IntakeState::submit_evidence` does with the
    /// live clock. A frozen 2026-11-04 would make the golden stale and refuse
    /// it for the wrong reason.
    fn admission_policy() -> VerificationPolicy {
        let mut policy = policy();
        // Just after the synthetic commit's own `commit_time` (1_700_000_000),
        // so the golden is neither stale nor in the future.
        policy.now = 1_700_000_100;
        policy
    }

    /// A pinned Tendermint domain registers, passes admission, and the stored
    /// spec rebuilds an adapter that still verifies the golden.
    #[test]
    fn a_tendermint_domain_registers_and_passes_admission() {
        let commit = pinned_golden_commit();
        let mut state = pinned_intake(&commit);
        let key = state
            .register_domain(
                registration_request(validator_set_commitment(&commit.validators)),
                None,
            )
            .expect("a pinned Tendermint domain registers end to end");
        let entry = state.entries.get(&key).expect("entry is stored");
        assert!(entry.admission.admitted, "report: {:?}", entry.admission);
        assert!(entry.admission.golden_verified);

        let rebuilt = entry.spec.build(None, Some(entry.golden.clone()));
        assert!(rebuilt.verify(&entry.golden, &entry.policy).is_ok());
    }

    /// A registration without a governance-pinned validator set is refused at
    /// the door: the chain id alone does not stop an attacker self-signing a
    /// commit with freshly generated keys.
    #[test]
    fn an_unpinned_tendermint_validator_set_is_refused_at_registration() {
        let mut state = IntakeState::new();
        let commit = pinned_golden_commit();
        assert!(matches!(
            state.register_domain(
                registration_request(validator_set_commitment(&commit.validators)),
                None,
            ),
            Err(crate::cross_domain::external::IntakeError::CommitteeNotPinned)
        ));
    }

    /// A registration whose pinned set hash disagrees with the governance
    /// anchor is refused, so a registrant cannot name its own set.
    #[test]
    fn a_tendermint_set_hash_that_disagrees_with_the_anchor_is_refused() {
        let commit = pinned_golden_commit();
        let mut state = pinned_intake(&commit);
        let mut wrong = validator_set_commitment(&commit.validators);
        wrong[0] ^= 0xff;
        assert!(matches!(
            state.register_domain(registration_request(wrong), None),
            Err(crate::cross_domain::external::IntakeError::CommitteeNotPinned)
        ));
    }

    /// The bridge finalizes a commitment built from the attestation's own
    /// roots, and a corrupted signature does not reach consensus.
    #[test]
    fn the_bridge_finalizes_a_tendermint_commitment() {
        let adapter = adapter();
        let commit = noble_commit();
        let evidence = evidence_for(&adapter, &commit);
        let attestation = adapter
            .verify(&evidence, &policy())
            .expect("the real noble commit verifies");
        let proof = encode_external_evidence(&evidence).expect("evidence encodes");

        let domain = ConsensusDomain {
            id: 8,
            kind: ConsensusKind::Custom("tendermint-bft".to_string()),
            status: DomainStatus::Active,
            domain_chain_id: 88,
            operator: Some(Address([4u8; 32])),
            operator_bond: 1_000_000,
            config_hash: [0; 32],
            validator_set_hash: [0; 32],
            finality_adapter: EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string(),
            min_confirmations: 1,
            bridge_enabled: true,
            block_hash_scheme: RootScheme::Sha256,
            state_root_scheme: RootScheme::Sha256,
            tx_root_scheme: RootScheme::Sha256,
            last_committed_height: commit.height,
            last_committed_hash: commit.block_hash,
            pow_parameters: None,
            zk_program_allowlist: Vec::new(),
            plugin_code_hash: None,
            genesis_state_root: [0; 32],
        };
        let commitment = DomainCommitment {
            domain_id: 8,
            domain_height: attestation.height,
            // The attestation's `state_root` is the app hash and its
            // `attested_block_hash` is the block hash, so each commitment field
            // takes the value the adapter actually attests.
            domain_block_hash: attestation
                .attested_block_hash
                .unwrap_or(attestation.state_root),
            parent_domain_block_hash: [0; 32],
            state_root: attestation.state_root,
            tx_root: [0; 32],
            event_root: [0; 32],
            finality_proof_hash: crate::domain::hash_finality_proof(&proof).expect("hashes"),
            consensus_kind: domain.kind.clone(),
            validator_set_hash: [0; 32],
            timestamp_ms: 0,
            sequence: 1,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        };

        let decoded = decode_external_evidence(&proof).expect("carrier round trips");
        assert_eq!(decoded, evidence);
        let bridge = crate::cross_domain::external::ExternalDomainFinalityBridge::new(
            Box::new(adapter.clone()),
            policy(),
        );
        assert_eq!(
            bridge
                .verify_finality(&domain, &commitment, &proof)
                .expect("the bridge finalizes the commit"),
            FinalityStatus::Finalized
        );

        // A forged signature must not finalize: the bridge reads the same
        // adapter, so the crypto refusal surfaces as an error rather than a
        // commitment anchored on a signature nobody made.
        let mut forged = evidence.clone();
        let offsets = commit.field_offsets();
        if let Some(at) = offsets.first_signature_len_at {
            let start = at + 8;
            if let Some(byte) = forged.payload.get_mut(start) {
                *byte ^= 0xff;
            }
        }
        let forged_proof = encode_external_evidence(&forged).expect("forged encodes");
        let result = bridge.verify_finality(&domain, &commitment, &forged_proof);
        assert!(
            result.is_err(),
            "a forged signature must not finalize: {result:?}"
        );
    fn build_rfc6962_tree_and_proof(
        leaves: &[Vec<u8>],
        target_idx: usize,
    ) -> ([u8; 32], Rfc6962Proof) {
        fn rec(slice: &[Vec<u8>], idx: Option<usize>, aunts: &mut Vec<[u8; 32]>) -> [u8; 32] {
            if slice.len() == 1 {
                return rfc6962_leaf_hash(&slice[0]);
            }
            let k = rfc6962_split_point(slice.len());
            let (left_s, right_s) = slice.split_at(k);
            match idx {
                Some(i) if i < k => {
                    let l = rec(left_s, Some(i), aunts);
                    let r = rec(right_s, None, aunts);
                    aunts.push(r);
                    rfc6962_inner_hash(&l, &r)
                }
                Some(i) => {
                    let l = rec(left_s, None, aunts);
                    let r = rec(right_s, Some(i - k), aunts);
                    aunts.push(l);
                    rfc6962_inner_hash(&l, &r)
                }
                None => {
                    let l = rec(left_s, None, aunts);
                    let r = rec(right_s, None, aunts);
                    rfc6962_inner_hash(&l, &r)
                }
            }
        }
        let mut aunts = Vec::new();
        let root = rec(leaves, Some(target_idx), &mut aunts);
        (
            root,
            Rfc6962Proof {
                index: target_idx,
                total: leaves.len(),
                aunts,
            },
        )
    }

    #[test]
    fn tendermint_skipping_light_client_verifies_rotation_and_rfc6962_app_hash_and_refuses_forgery()
    {
        use crate::crypto::primitives::KeyPair;

        let chain_id = "cosmoshub-4";
        let keys: Vec<KeyPair> = (0..6).map(|_| KeyPair::generate().expect("kp")).collect();
        let make_val = |kp: &KeyPair, power: u64| {
            let public_key = kp.public_key_bytes();
            TendermintValidator {
                address: address_of(&public_key),
                public_key,
                voting_power: power,
            }
        };

        // Trusted validator set at height 100: keys[0..4], 100 power each (total 400).
        let trusted_vals = vec![
            make_val(&keys[0], 100),
            make_val(&keys[1], 100),
            make_val(&keys[2], 100),
            make_val(&keys[3], 100),
        ];
        // Rotated validator set at non-adjacent height 250: keys[0], keys[1] stay (200/400 = 50% > 1/3),
        // keys[4], keys[5] join (total target power 400; keys[0,1,4] sign = 300 >= 267).
        let target_vals = vec![
            make_val(&keys[0], 100),
            make_val(&keys[1], 100),
            make_val(&keys[4], 100),
            make_val(&keys[5], 100),
        ];
        let next_vals_hash = [0x77; 32];
        let app_hash = [0x99; 32];

        // Build exact 14-leaf CometBFT Header RFC-6962 tree committing both next_validators_hash (8) and app_hash (10).
        let mut header_leaves: Vec<Vec<u8>> = (0..COMETBFT_HEADER_TOTAL_LEAVES)
            .map(|i| vec![i as u8; 32])
            .collect();
        header_leaves[COMETBFT_HEADER_NEXT_VALIDATORS_INDEX] = next_vals_hash.to_vec();
        header_leaves[COMETBFT_HEADER_APP_HASH_INDEX] = app_hash.to_vec();
        let (block_hash, app_proof) =
            build_rfc6962_tree_and_proof(&header_leaves, COMETBFT_HEADER_APP_HASH_INDEX);
        let (block_hash_chk, next_proof) =
            build_rfc6962_tree_and_proof(&header_leaves, COMETBFT_HEADER_NEXT_VALIDATORS_INDEX);
        assert_eq!(block_hash, block_hash_chk);

        let parts_hash = [0x55; 32];
        let vote_ts = 1_750_010_000i64;
        let sign_commit = |signer_indices: &[usize]| -> TendermintCommitEvidence {
            let signatures = signer_indices
                .iter()
                .map(|&idx| {
                    let msg = vote_sign_bytes(
                        chain_id,
                        250,
                        0,
                        &block_hash,
                        1,
                        &parts_hash,
                        (vote_ts, 0),
                    );
                    let pk = keys[idx].public_key_bytes();
                    TendermintSignature {
                        address: address_of(&pk),
                        timestamp_seconds: vote_ts,
                        timestamp_nanos: 0,
                        signature: keys[idx].sign(&msg).to_vec(),
                    }
                })
                .collect();
            TendermintCommitEvidence {
                chain_id: chain_id.to_string(),
                height: 250,
                round: 0,
                block_hash,
                parts_total: 1,
                parts_hash,
                app_hash,
                commit_time: vote_ts as u64,
                validators: target_vals.clone(),
                signatures,
            }
        };

        let trusted = TrustedTendermintState {
            chain_id: chain_id.to_string(),
            height: 100,
            time_secs: 1_750_000_000,
            trusting_period_secs: 86_400,
            validators: trusted_vals,
            next_validators_hash: [0x12; 32],
        };
        let valid_skip = sign_commit(&[0, 1, 4]);
        let verified = verify_skipping_commit(
            &trusted,
            &valid_skip,
            Some(&app_proof),
            Some((next_vals_hash, &next_proof)),
            1_750_010_010,
        )
        .expect("50% trusted overlap + 75% target quorum + RFC-6962 proofs verify");
        assert_eq!(verified.height, 250);
        assert_eq!(verified.app_hash, app_hash);
        assert_eq!(verified.next_validators_hash, Some(next_vals_hash));
        assert_eq!(verified.trusted_overlap_power, 200);
        assert_eq!(verified.target_signed_power, 300);

        // 1. Forgery: signers [0, 4, 5] reach 300/400 (75% > 2/3) of target set,
        //    but only 100/400 (25% <= 1/3) of trusted set -> refused!
        let low_overlap = sign_commit(&[0, 4, 5]);
        assert!(matches!(
            verify_skipping_commit(
                &trusted,
                &low_overlap,
                Some(&app_proof),
                None,
                1_750_010_010
            ),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 2. Forgery: substituted app_hash fails RFC-6962 header proof against signed block_hash.
        let mut forged_app = valid_skip.clone();
        forged_app.app_hash = [0xEE; 32];
        assert!(matches!(
            verify_skipping_commit(&trusted, &forged_app, Some(&app_proof), None, 1_750_010_010),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 3. Expired trusting period must fail closed with AdapterError::Stale.
        assert!(matches!(
            verify_skipping_commit(&trusted, &valid_skip, Some(&app_proof), None, 1_750_100_000),
            Err(AdapterError::Stale { .. })
        ));
    }
}
