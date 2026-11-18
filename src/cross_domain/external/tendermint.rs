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
//! # The block hash is recomputed, because the header is what was signed
//!
//! A commit signs a `block_id`, not a header. Everything else in the evidence -
//! `app_hash`, `validators_hash`, `next_validators_hash`, the commit time - is
//! a field somebody typed into a payload. An adapter that reports `app_hash` as
//! the attested state root, without tying it to the signed `block_id.hash`, is
//! reporting an unauthenticated number with a signature's authority.
//!
//! So the header travels with the evidence and is rehashed here, with
//! CometBFT's own rule (`types/block.go`, `Header.Hash()`): a Merkle tree over
//! fourteen leaves, each leaf being the protobuf encoding of a wrapper -
//! `StringValue` for the chain id, `Int64Value` for the height, `BytesValue`
//! for each hash and the proposer address - with the version, the timestamp and
//! the last block id as their own messages, and the empty-tree/half-split rules
//! of RFC-6962. The rule reproduces the live `noble-1` block hash
//! `8B3E0A7F...5583F394` byte for byte, and that is a test here.
//!
//! With the header hash equal to the signed `block_id.hash`, `app_hash` and
//! `validators_hash` stop being claims and become commitments: they are leaves
//! of the tree the validators signed.

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
///
/// Version 2 is the version that carries the header. Version 1 carried a block
/// hash, an app hash and a validator set and no header at all; that layout
/// cannot prove what it attested (see the module note on the header hash), so
/// those payloads are refused as an unread version instead of being
/// reinterpreted. The layout is a bincode struct, so a v1 payload does not
/// decode as a v2 one either - both paths fail closed.
pub const EVIDENCE_VERSION: u32 = 2;

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

/// CometBFT's `ValidatorSet.Hash()`, recomputed from the set.
///
/// The rule, from `types/validator.go` and `crypto/merkle`: each validator is a
/// `SimpleValidator{pub_key, voting_power}` protobuf, leaves are ordered by
/// address, and the tree is RFC-6962. Using the chain's own rule rather than a
/// Budlum-specific digest matters twice over: the value is the one the header
/// commits to in `validators_hash`, so an operator can pin it straight off any
/// explorer, and the adapter can check the set against the header instead of
/// only against its own arithmetic.
#[must_use]
pub fn validator_set_hash(validators: &[TendermintValidator]) -> [u8; 32] {
    let mut ordered: Vec<TendermintValidator> = validators.to_vec();
    ordered.sort_by_key(|v| v.address);
    let leaves: Vec<Vec<u8>> = ordered.iter().map(simple_validator_bytes).collect();
    merkle_root(&leaves)
}

/// The `SimpleValidator` protobuf bytes one leaf commits to.
fn simple_validator_bytes(validator: &TendermintValidator) -> Vec<u8> {
    let mut public_key = Vec::with_capacity(2 + PUBLIC_KEY_LEN);
    // PublicKey.ed25519 = field 1, wire type 2.
    public_key.push((1 << 3) | 2);
    public_key.push(PUBLIC_KEY_LEN as u8);
    public_key.extend_from_slice(&validator.public_key);

    let mut out = Vec::with_capacity(4 + public_key.len() + 10);
    out.push((1 << 3) | 2);
    put_varint(&mut out, public_key.len() as u64);
    out.extend_from_slice(&public_key);
    put_scalar(&mut out, 2, validator.voting_power);
    out
}

fn merkle_leaf(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0u8]);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn merkle_inner(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn merkle_root(items: &[Vec<u8>]) -> [u8; 32] {
    match items.len() {
        0 => Sha256::digest([]).into(),
        1 => merkle_leaf(&items[0]),
        len => {
            let split = split_point(len);
            merkle_inner(&merkle_root(&items[..split]), &merkle_root(&items[split..]))
        }
    }
}

/// The largest power of two strictly below `len`, CometBFT's split point.
fn split_point(len: usize) -> usize {
    let highest = 1usize << (usize::BITS - 1 - len.leading_zeros());
    if highest == len {
        highest >> 1
    } else {
        highest
    }
}

/// `google.protobuf.StringValue`.
fn proto_string_value(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    put_bytes(&mut out, 1, value.as_bytes());
    out
}

/// `google.protobuf.Int64Value`.
fn proto_int64_value(value: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    put_scalar(&mut out, 1, value as u64);
    out
}

/// `google.protobuf.BytesValue`, the wrapper `cdcEncode` uses for header hashes.
fn proto_bytes_value(value: &[u8]) -> Vec<u8> {
    // `cdcEncode` returns nil for an empty item and proto3 omits an empty
    // bytes field, so an empty header hash contributes an empty leaf - not a
    // `0A 00` that would hash to something else.
    let mut out = Vec::with_capacity(2 + value.len());
    if !value.is_empty() {
        put_bytes(&mut out, 1, value);
    }
    out
}

/// Alias of [`validator_set_hash`], kept for the name this module's first cut
/// used and for the callers that pinned it.
///
/// The original implementation was a Budlum-domain-separated digest. That was
/// the wrong artefact to pin: it could not be read off the chain, and it could
/// not be checked against the header's own `validators_hash`. A day of history
/// is the only reason the old name survives; both names now mean "the chain's
/// `ValidatorSet.Hash()`", and no stored registration exists that pinned the
/// old bytes.
#[must_use]
pub fn validator_set_commitment(validators: &[TendermintValidator]) -> [u8; 32] {
    validator_set_hash(validators)
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
    /// The header's version block (the `block` field of `Version`).
    pub version_block: u64,
    /// The parent block's id, as the header carries it.
    pub last_block_hash: [u8; 32],
    pub last_parts_total: u32,
    pub last_parts_hash: [u8; 32],
    /// The remaining header hashes. They are leaves of the header hash, so they
    /// are as authenticated as the block id itself.
    pub last_commit_hash: [u8; 32],
    pub data_hash: [u8; 32],
    /// The header's validator-set root, `ValidatorSet.Hash()`. Countersigned
    /// twice over: it is inside the header hash, and it is recomputed from
    /// `validators` in [`TendermintCommitEvidence::validate_shape`]'s caller.
    pub validators_hash: [u8; 32],
    pub next_validators_hash: [u8; 32],
    pub consensus_hash: [u8; 32],
    /// The application state root committed at this height. Inside the header
    /// hash, so this - and only this - is what the attestation may report.
    pub app_hash: [u8; 32],
    pub last_results_hash: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub proposer_address: [u8; ADDRESS_LEN],
    /// The commit time in seconds since the Unix epoch, from the header. Used
    /// for the attestation's `finalized_at` and for staleness.
    pub commit_time: u64,
    /// The header time's sub-second part. Signed through the header hash, and
    /// carried because the hash covers it.
    pub commit_time_nanos: u32,
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
        // The bincode layout, in declaration order. It is arithmetic rather than
        // a scheme because the probes it serves corrupt exactly one field each:
        // an offset that drifts by a byte still applies and still produces a
        // refusal - of something else - so `field_offsets_point_at_the_fields_they_name`
        // reads every offset back out of a real encoding. Adding a field to the
        // evidence means adding its width here *before* the fields below it stop
        // being where this says they are, and that test is what says so.
        let mut at = 8usize.saturating_add(self.chain_id.len()); // chain_id
        at += 8; // height
        at += 8; // round
        at += 32; // block_hash
        at += 4; // parts_total
        at += 32; // parts_hash
        at += 8; // version_block
        at += 32; // last_block_hash
        at += 4; // last_parts_total
        at += 32; // last_parts_hash
        at += 32; // last_commit_hash
        at += 32; // data_hash
        at += 32; // validators_hash
        at += 32; // next_validators_hash
        at += 32; // consensus_hash
        at += 32; // app_hash
        at += 32; // last_results_hash
        at += 32; // evidence_hash
        at += ADDRESS_LEN; // proposer_address
        at += 8; // commit_time
        at += 4; // commit_time_nanos
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
        }
        // The set must be the one the header commits to. Deliberately checked
        // after the per-entry rules: an entry whose address is not its key, or a
        // doubled entry, is a more precise diagnosis than "the root disagrees",
        // and both are the same bug seen from two angles.
        if self.commit_time_nanos >= NANOS_PER_SECOND {
            return Err(rule(format!(
                "commit_time carries {} nanoseconds, which is not a timestamp",
                self.commit_time_nanos
            )));
        }
        let set_hash = validator_set_hash(&self.validators);
        if set_hash != self.validators_hash {
            return Err(rule(format!(
                "the supplied validator set hashes to {} but the header's validator-set root is {}",
                hex::encode(set_hash),
                hex::encode(self.validators_hash)
            )));
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

    /// The block hash implied by the header fields, `Header.Hash()`.
    ///
    /// Fourteen leaves, RFC-6962, exactly as CometBFT builds it. Equal to the
    /// commit's `block_hash` means the header in this payload is the header the
    /// validators signed - which is what makes `app_hash` and `validators_hash`
    /// attestable at all.
    #[must_use]
    pub fn header_hash(&self) -> [u8; 32] {
        let mut version = Vec::new();
        put_scalar(&mut version, 1, self.version_block);

        let mut timestamp = Vec::new();
        put_scalar(&mut timestamp, 1, self.commit_time);
        put_scalar(&mut timestamp, 2, u64::from(self.commit_time_nanos));

        let mut last_part_set = Vec::new();
        put_scalar(&mut last_part_set, 1, u64::from(self.last_parts_total));
        put_bytes(&mut last_part_set, 2, &self.last_parts_hash);

        let mut last_block_id = Vec::new();
        put_bytes(&mut last_block_id, 1, &self.last_block_hash);
        put_bytes(&mut last_block_id, 2, &last_part_set);

        let leaves = vec![
            version,
            proto_string_value(&self.chain_id),
            proto_int64_value(self.height as i64),
            timestamp,
            last_block_id,
            proto_bytes_value(&self.last_commit_hash),
            proto_bytes_value(&self.data_hash),
            proto_bytes_value(&self.validators_hash),
            proto_bytes_value(&self.next_validators_hash),
            proto_bytes_value(&self.consensus_hash),
            proto_bytes_value(&self.app_hash),
            proto_bytes_value(&self.last_results_hash),
            proto_bytes_value(&self.evidence_hash),
            proto_bytes_value(&self.proposer_address),
        ];
        merkle_root(&leaves)
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

    /// Consensus-intake constructor: enforces a governance-pinned validator
    /// set, given as the chain's own `ValidatorSet.Hash()` - the value the
    /// header carries in its `validators_hash` field, so an operator can copy
    /// it off any explorer rather than computing a Budlum-specific digest.
    /// Fails closed with [`AdapterError::Unavailable`] when no pin is given.
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
    ///
    /// The sample also fixes the profile's committee size. A BFT adapter that
    /// declares `HonestMajority { set_size: 0 }` is declaring that no party has
    /// to be honest, which is the one thing this chain never says; the number a
    /// reader needs is how many validators the pinned set has, and the admitted
    /// sample is the evidence that says so (it verified against the pin, so its
    /// set *is* the pinned set). Without a sample the constructor cannot know,
    /// and the field stays 0 - so a descriptor taken from a sample-less adapter
    /// is honest about being uninformative rather than guessing.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        if let Ok(decoded) = TendermintCommitEvidence::decode(&golden.payload) {
            if decoded.chain_id == self.chain_id {
                if let Ok(set_size) = u64::try_from(decoded.validators.len()) {
                    self.descriptor.trust_model = TrustModel::HonestMajority { set_size };
                }
            }
        }
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

        // The header is what the commit signed, so the header is recomputed.
        // Without this line every other header field - the app hash, the
        // validator-set root, the commit time - is a number the submitter typed
        // next to a real signature.
        let observed_block_hash = decoded.header_hash();
        if observed_block_hash != decoded.block_hash {
            return Err(rule(format!(
                "the header hashes to {} but the commit signed block id {}: the payload's header is not the header that was signed",
                hex::encode(observed_block_hash),
                hex::encode(decoded.block_hash)
            )));
        }

        // With the header hash bound, `app_hash` is a leaf of the tree the
        // validators signed and can be attested directly. Consensus-admitted
        // domains still must match a governance-pinned validator set, which the
        // header's own `validators_hash` ties to the set supplied here.
        let attested_root = if self.require_pinned_set {
            let Some(expected_set) = self.pinned_validator_set else {
                return Err(AdapterError::Unavailable {
                    reason: "no Tendermint validator set is pinned for this domain".to_string(),
                });
            };
            let observed_set = validator_set_hash(&decoded.validators);
            if observed_set != expected_set {
                return Err(rule(
                    "commit validator set does not match the governance-pinned validator-set root",
                ));
            }
            if decoded.validators_hash != expected_set {
                return Err(rule(
                    "the header's validator-set root is not the pinned set, so the commit is not signed by the pinned validators",
                ));
            }
            decoded.app_hash
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
    const NOBLE_COMMIT_JSON: &str = r#"{"chain_id":"noble-1","height":64239414,"round":0,"block_hash":"8B3E0A7F14EF04EC5A3DE98CE214249D9F49711DAACD2BAB433BA9785583F394","parts_total":1,"app_hash":"789D3D6D36565DDA8721303A0CC1067E1D34F5A67800FB941ACB077382F3BED2","commit_time_seconds":1794986334,"commit_time_nanos":763902047,"version_block":11,"validators_hash":"963D149C5AE6A27D84F5CCC474C87BF7B6692AB343D30498A6AA57B05C4BA9F3","next_validators_hash":"963D149C5AE6A27D84F5CCC474C87BF7B6692AB343D30498A6AA57B05C4BA9F3","consensus_hash":"BF63703F8272504006C3E6DC34173DF3837F2ABA15DB8F50500A36E4AF2EAC0E","last_commit_hash":"11EECF9A418C2B6FDC0F3CB5D123002DB35BE55DF99C93D55917BE5FA87DA90E","data_hash":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855","last_results_hash":"098E3F4771A7E13B1A823EAA8C3957D749D63B0B4FAACCAB1B70708FC3A5FF0F","evidence_hash":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855","proposer_address":"417E75EF24DE0207B9BFD235331F4897AD28738A","last_block_hash":"84749CA34E94DC82F5E9AFFD2DF8144EF036BAC79732246361B3CCC19C1DB56B","last_parts_total":1,"last_parts_hash":"30BEB5B9E10138A3E46B706C50184D741447BCB0D35519FCDD8E38DD6264FDAC","validators":[{"address":"417E75EF24DE0207B9BFD235331F4897AD28738A","public_key":"233B590A7507763A0583CE319077EE0AE134F7148091C25B25E814ED5A058D7E","voting_power":1},{"address":"4E4BF0D6B90FCEC903166CA9909EDA38871BC7C5","public_key":"41B7B382A21E603DE1309C95449F2DEA84A1ED7F9649840FE8DA6D0D7447BDDB","voting_power":1},{"address":"7259FA8ABEE6365224E8917262A077D8F21C215E","public_key":"A93CEEDCBB78EFBB56EBBC0962929D9D93F5DFCF0AC8AED7DA922334C1E791D3","voting_power":1},{"address":"913A87C9053EE31DC75DBC0711499841F4FE41D2","public_key":"C3FA937121CB48D92607E2813C9E11E664C5B25D4808C00A2FACA8D77887C279","voting_power":1},{"address":"9814A41D7ADECFC8686C1B551CFE12A5529CCF47","public_key":"EAC07122ADBDDEF6FE94FD95172E3189C30085D499645D9BABA6AD00FF01B4A3","voting_power":1},{"address":"D1AD8B58C084D0E6014ACEADD5B44E9458F11A58","public_key":"BF8F447AF3D9BE00578A370D001F843C89782025F886482751A2832E5320AEFF","voting_power":1},{"address":"F21F8BD8AB575EC5D5B3B691080830CCEC51BD1D","public_key":"49A8CD065495568AE199F166CF8F7F3170D0D036E8E9CEA8A2C869F79F1F3403","voting_power":1}],"signatures":[{"validator_address":"4E4BF0D6B90FCEC903166CA9909EDA38871BC7C5","timestamp":"2026-11-18T07:18:55.949535266Z","signature":"FA5C29908B26F44BEF52173B81F681D08681BE67044D30B7B6EA316B06DB665C82E26C656C275839A15DDBCD137F7430B5529545A75A5DABA4FACB42980DF407","timestamp_seconds":1794986335,"timestamp_nanos":949535266},{"validator_address":"7259FA8ABEE6365224E8917262A077D8F21C215E","timestamp":"2026-11-18T07:18:55.91613621Z","signature":"5CC6DDE372ECD598B1A2919CE182F837ED077F46FFD9729CC4E0E90649EADE070B4CD8E982F9BEEE4FF943AF66F55F4398414FEC0032160E13567A03153FF302","timestamp_seconds":1794986335,"timestamp_nanos":916136210},{"validator_address":"913A87C9053EE31DC75DBC0711499841F4FE41D2","timestamp":"2026-11-18T07:18:55.972621579Z","signature":"0DB93F558994717907001F0CDFFFBB774C09B136A67FCE121D711532DA87D45C4665D6C89011268EE0AE7C125A31893AC28E8B7EE2835C82E50B27166583310D","timestamp_seconds":1794986335,"timestamp_nanos":972621579},{"validator_address":"D1AD8B58C084D0E6014ACEADD5B44E9458F11A58","timestamp":"2026-11-18T07:18:55.975841154Z","signature":"BFC42102253DC47C97B1C3BE0978574C95AE0251B585083EA1B4501FC263A3AF34CA091914DB18FA816AB392CEF15C781E8B45482BA58D79B06C3F5BF596A703","timestamp_seconds":1794986335,"timestamp_nanos":975841154},{"validator_address":"F21F8BD8AB575EC5D5B3B691080830CCEC51BD1D","timestamp":"2026-11-18T07:18:55.920354751Z","signature":"A60C0AD32F60BA0B4D6923A0A39DDD4768AB6127415D601DFF56228CBD606264605B9946272E24ADFFA76DFD4F344EB981308A95925B262926A793160609A503","timestamp_seconds":1794986335,"timestamp_nanos":920354751}],"parts_hash":"8C02B74E3120E2416FD0016D96242719486ED754BF350E378ABD11751ABDB1DC"}"#;

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
        commit_time_nanos: u32,
        version_block: u64,
        validators_hash: String,
        next_validators_hash: String,
        consensus_hash: String,
        last_commit_hash: String,
        data_hash: String,
        last_results_hash: String,
        evidence_hash: String,
        proposer_address: String,
        last_block_hash: String,
        last_parts_total: u32,
        last_parts_hash: String,
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
            version_block: fixture.version_block,
            last_block_hash: fixed(&fixture.last_block_hash),
            last_parts_total: fixture.last_parts_total,
            last_parts_hash: fixed(&fixture.last_parts_hash),
            last_commit_hash: fixed(&fixture.last_commit_hash),
            data_hash: fixed(&fixture.data_hash),
            validators_hash: fixed(&fixture.validators_hash),
            next_validators_hash: fixed(&fixture.next_validators_hash),
            consensus_hash: fixed(&fixture.consensus_hash),
            app_hash: fixed(&fixture.app_hash),
            last_results_hash: fixed(&fixture.last_results_hash),
            evidence_hash: fixed(&fixture.evidence_hash),
            proposer_address: fixed(&fixture.proposer_address),
            commit_time: fixture.commit_time_seconds,
            commit_time_nanos: fixture.commit_time_nanos,
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
            height: 64_239_500,
            round: 1,
            block_hash: [0u8; 32],
            parts_total: 3,
            parts_hash: [0x22; 32],
            version_block: 11,
            last_block_hash: [0x44; 32],
            last_parts_total: 1,
            last_parts_hash: [0x45; 32],
            last_commit_hash: [0x46; 32],
            data_hash: [0x47; 32],
            validators_hash: validator_set_hash(&validators),
            next_validators_hash: validator_set_hash(&validators),
            consensus_hash: [0x48; 32],
            app_hash: [0x33; 32],
            last_results_hash: [0x49; 32],
            evidence_hash: [0x4A; 32],
            proposer_address: [0x4B; 20],
            commit_time: 1_700_000_000,
            commit_time_nanos: 0,
            validators,
            signatures,
        };
        // Seal the header the way a producer does: the block id is the header's
        // own hash, so the payload is internally consistent before any negative
        // test touches one field of it.
        commit.block_hash = commit.header_hash();
        resign(&mut commit, &keyring);
        commit
    }

    #[test]
    fn the_header_hash_reproduces_the_real_noble_block_hash() {
        // The commit's `block_id.hash` is `Header.Hash()`. The rule here -
        // fourteen protobuf-wrapped leaves, RFC-6962 - has to produce it from
        // the header fields alone, or nothing else in this file means anything:
        // an adapter that cannot rebuild the signed object is verifying a
        // signature over bytes it invented.
        let commit = noble_commit();
        assert_eq!(
            hex::encode_upper(commit.header_hash()),
            "8B3E0A7F14EF04EC5A3DE98CE214249D9F49711DAACD2BAB433BA9785583F394"
        );
        assert_eq!(commit.header_hash(), commit.block_hash);
    }

    /// One real block from one real chain: the header fields, and the block id
    /// the chain's validators signed over them.
    struct KnownHeader {
        chain_id: &'static str,
        height: u64,
        version_block: u64,
        commit_time: u64,
        commit_time_nanos: u32,
        last_block_hash: &'static str,
        last_parts_total: u32,
        last_parts_hash: &'static str,
        last_commit_hash: &'static str,
        data_hash: &'static str,
        validators_hash: &'static str,
        next_validators_hash: &'static str,
        consensus_hash: &'static str,
        app_hash: &'static str,
        last_results_hash: &'static str,
        evidence_hash: &'static str,
        proposer_address: &'static str,
        block_hash: &'static str,
    }

    /// Three chains, three eras of header, one rule.
    ///
    /// `noble-1` is the small case. `cosmoshub-4` and `osmosis-1` are the
    /// adversarial ones: a hundred validators rather than seven, a chain id of a
    /// different length, and sub-second timestamps that are not the noble one.
    /// An encoder that happened to fit the first chain would not fit these, and
    /// an encoder that fits all three is the encoder CometBFT has.
    const KNOWN_HEADERS: &[KnownHeader] = &[
        KnownHeader {
            chain_id: "cosmoshub-4",
            height: 33_936_991,
            version_block: 11,
            commit_time: 1_795_016_072,
            commit_time_nanos: 558_441_864,
            last_block_hash: "3FDAADF5E8572B7DC7D6C88D6E481922D1772EDE08F3D0C65D0FE3EE7C16E571",
            last_parts_total: 1,
            last_parts_hash: "37EEE86227C256297D04EE82472CC8D9647DAE7FF01BFDBF7CA9FCA73820473A",
            last_commit_hash: "602436BBD52533E93A01AA3195C50CBBE6C004B8DD83B347A5F2944F9155E530",
            data_hash: "FED88B2A455A8550D5B14A7B6CB10CE260751CEBACE81F1D444A84CEAE88B679",
            validators_hash: "ADAE13380ABD71F125A337AF16E06270E61B325F5945404A17324E62503B95C9",
            next_validators_hash: "ADAE13380ABD71F125A337AF16E06270E61B325F5945404A17324E62503B95C9",
            consensus_hash: "20CA5E3F42E07A0CDB7BD986EFF1947A23FC27FF47204303E082BC44BB348E0B",
            app_hash: "B40E784CD0CC424FFA157D9C93FEDD47843D0A6D33C7B82515BFADE91444B069",
            last_results_hash: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            evidence_hash: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            proposer_address: "2199EAE894CA391FA82F01C2C614BFEB103D056C",
            block_hash: "F5C757B2219B47E20F0B04FEA489B56891CD43EFB28D21F9937949C89A8CF5E7",
        },
        KnownHeader {
            chain_id: "osmosis-1",
            height: 75_461_800,
            version_block: 11,
            commit_time: 1_795_016_006,
            commit_time_nanos: 643_242_144,
            last_block_hash: "3E6B89EE84B3CFA9AED58DDCE4DE89E5533E20DC8B3BA2D595E9FDD2A08F310C",
            last_parts_total: 1,
            last_parts_hash: "67DBFA2B599957889E91E720E3B50BB9FB3DD81ED7461F09DF88A6A7FEB7E73F",
            last_commit_hash: "A64C9820783852B09A3FF14D668FDC1F7DE11DC37C27E2492F15866E5D8EF843",
            data_hash: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            validators_hash: "E01ED3ED9D6434ECB8C36C5013560BF5D691F970C70A62EAFC1B3BBC438ACEF2",
            next_validators_hash: "E01ED3ED9D6434ECB8C36C5013560BF5D691F970C70A62EAFC1B3BBC438ACEF2",
            consensus_hash: "2484BBA8B99E531E1A3F6422362E7D3EEB99A8325119968A355F05C09EEDD40B",
            app_hash: "AF5A1A6496C699BA1AD4A1618DF86A8002CF67B3B4BD82F7E83D1D382D73D4F9",
            last_results_hash: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            evidence_hash: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            proposer_address: "66B69666EBF776E7EBCBE197ABA466A712E27076",
            block_hash: "96F5721360C82B3FB9113584BB55623576C6A5BA63EBF8FA0CD40A2BED3C335C",
        },
    ];

    fn header_only(header: &KnownHeader) -> TendermintCommitEvidence {
        let bytes32 = |text: &str| -> [u8; 32] {
            let raw = hex::decode(text).expect("32-byte hex");
            <[u8; 32]>::try_from(raw.as_slice()).expect("32 bytes")
        };
        let proposer = hex::decode(header.proposer_address).expect("address hex");
        TendermintCommitEvidence {
            chain_id: header.chain_id.to_string(),
            height: header.height,
            round: 0,
            block_hash: bytes32(header.block_hash),
            parts_total: 1,
            parts_hash: [0u8; 32],
            version_block: header.version_block,
            last_block_hash: bytes32(header.last_block_hash),
            last_parts_total: header.last_parts_total,
            last_parts_hash: bytes32(header.last_parts_hash),
            last_commit_hash: bytes32(header.last_commit_hash),
            data_hash: bytes32(header.data_hash),
            validators_hash: bytes32(header.validators_hash),
            next_validators_hash: bytes32(header.next_validators_hash),
            consensus_hash: bytes32(header.consensus_hash),
            app_hash: bytes32(header.app_hash),
            last_results_hash: bytes32(header.last_results_hash),
            evidence_hash: bytes32(header.evidence_hash),
            proposer_address: <[u8; ADDRESS_LEN]>::try_from(proposer.as_slice())
                .expect("20-byte address"),
            commit_time: header.commit_time,
            commit_time_nanos: header.commit_time_nanos,
            validators: Vec::new(),
            signatures: Vec::new(),
        }
    }

    #[test]
    fn the_header_hash_rule_reproduces_three_live_chains_not_one() {
        for header in KNOWN_HEADERS {
            let computed = header_only(header).header_hash();
            assert_eq!(
                hex::encode_upper(computed),
                header.block_hash,
                "{} at {} did not reproduce its own block id",
                header.chain_id,
                header.height
            );
        }
    }

    #[test]
    fn every_header_field_is_covered_by_the_block_id() {
        let commit = noble_commit();
        let original = commit.header_hash();
        let mutations: Vec<(&str, Box<dyn Fn(&mut TendermintCommitEvidence)>)> = vec![
            ("chain_id", Box::new(|c: &mut TendermintCommitEvidence| c.chain_id = "noble-2".to_string())),
            ("height", Box::new(|c: &mut TendermintCommitEvidence| c.height += 1)),
            ("version", Box::new(|c: &mut TendermintCommitEvidence| c.version_block += 1)),
            ("commit_time", Box::new(|c: &mut TendermintCommitEvidence| c.commit_time += 1)),
            (
                "commit_time_nanos",
                Box::new(|c: &mut TendermintCommitEvidence| c.commit_time_nanos += 1),
            ),
            ("last_block_hash", Box::new(|c: &mut TendermintCommitEvidence| c.last_block_hash = [0xA1; 32])),
            ("last_parts_total", Box::new(|c: &mut TendermintCommitEvidence| c.last_parts_total += 1)),
            (
                "last_parts_hash",
                Box::new(|c: &mut TendermintCommitEvidence| c.last_parts_hash = [0xA2; 32]),
            ),
            (
                "last_commit_hash",
                Box::new(|c: &mut TendermintCommitEvidence| c.last_commit_hash = [0xA3; 32]),
            ),
            ("data_hash", Box::new(|c: &mut TendermintCommitEvidence| c.data_hash = [0xA4; 32])),
            (
                "next_validators_hash",
                Box::new(|c: &mut TendermintCommitEvidence| c.next_validators_hash = [0xA5; 32]),
            ),
            (
                "consensus_hash",
                Box::new(|c: &mut TendermintCommitEvidence| c.consensus_hash = [0xA6; 32]),
            ),
            ("app_hash", Box::new(|c: &mut TendermintCommitEvidence| c.app_hash = [0xA7; 32])),
            (
                "last_results_hash",
                Box::new(|c: &mut TendermintCommitEvidence| c.last_results_hash = [0xA8; 32]),
            ),
            (
                "evidence_hash",
                Box::new(|c: &mut TendermintCommitEvidence| c.evidence_hash = [0xA9; 32]),
            ),
            (
                "proposer_address",
                Box::new(|c: &mut TendermintCommitEvidence| c.proposer_address = [0xAA; 20]),
            ),
        ];
        for (name, mutate) in mutations {
            let mut tampered = commit.clone();
            mutate(&mut tampered);
            assert_ne!(
                tampered.header_hash(),
                original,
                "mutating {name} left the header hash unchanged, so it is not covered"
            );
            // And the adapter refuses it: the payload's header is then not the
            // header the validators signed.
            let adapter = adapter();
            let error = adapter
                .verify(&evidence_for(&adapter, &tampered), &policy())
                .expect_err("a header that does not hash to the block id is not the signed header");
            assert!(
                matches!(error, AdapterError::ConsensusRule { .. }),
                "{name}: expected a consensus-rule refusal, got {error:?}"
            );
        }
    }

    #[test]
    fn a_validator_set_that_is_not_the_headers_is_refused() {
        let adapter = adapter();
        let mut commit = noble_commit();
        // A different set with a matching quorum, and a header that still claims
        // the original root.
        commit.validators[0].voting_power = 5;
        let error = adapter
            .verify(&evidence_for(&adapter, &commit), &policy())
            .expect_err("a set that does not hash to the header's root is not the set");
        match error {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("validator-set root"), "{rule}");
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_pinned_digest_is_the_chains_own_validator_set_root() {
        // A pin an operator cannot read off the chain is a pin they will get
        // wrong. `validator_set_commitment` and `validator_set_hash` are the
        // same function, and its output is the header's `validators_hash`.
        let commit = noble_commit();
        assert_eq!(
            validator_set_hash(&commit.validators),
            commit.validators_hash
        );
        assert_eq!(
            validator_set_commitment(&commit.validators),
            commit.validators_hash
        );
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
    fn the_profile_counts_the_pinned_set_instead_of_declaring_zero() {
        // `HonestMajority { set_size: 0 }` reads as "trust nobody in
        // particular", which for a commit adapter is meaningless: the number is
        // the one thing a consumer weighing this domain needs. The admitted
        // sample verified against the pin, so its seven validators are the
        // pinned set's seven validators.
        let unpinned_size = |adapter: &TendermintFinalityAdapter| match adapter.descriptor().trust_model
        {
            TrustModel::HonestMajority { set_size } => Some(set_size),
            _ => None,
        };
        assert_eq!(unpinned_size(&adapter()), Some(0));

        let commit = noble_commit();
        let golden = evidence_for(&adapter(), &commit);
        let admitted = adapter().with_golden(golden.clone());
        assert_eq!(unpinned_size(&admitted), Some(7));

        // A sample from another chain does not get to describe this one.
        let mut other_chain = commit.clone();
        other_chain.chain_id = "osmosis-1".to_string();
        other_chain.block_hash = other_chain.header_hash();
        let foreign = adapter().with_golden(evidence_for(&adapter(), &other_chain));
        assert_eq!(unpinned_size(&foreign), Some(0));
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
        // A header an attacker can seal but not re-sign: change a header field,
        // recompute the header hash into `block_hash`, and leave the signatures
        // where they are. The block id is inside every sign byte, so they fall.
        commit.app_hash = [0x5A; 32];
        commit.block_hash = commit.header_hash();
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
                AdapterError::UnsupportedEvidenceVersion {
                    version,
                    ..
                } if version == EVIDENCE_VERSION + 1
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

        // 2. The header is recomputed, so the app hash is no longer an
        //    unsigned claim: the genuine commit attests it directly.
        let att = pinned
            .verify(&evidence_for(&pinned, &honest_noble), &policy())
            .expect("the genuine pinned Noble commit verifies");
        assert_eq!(att.state_root, honest_noble.app_hash);
        assert_eq!(att.attested_block_hash, Some(honest_noble.block_hash));

        // 2b. Swapping the app hash while leaving the rest of the header alone
        //     breaks the header hash, which no longer matches the block id the
        //     validators signed. That is the refusal this adapter wants: the
        //     substitution is not "trusted", it is impossible.
        let mut swapped_app = honest_noble.clone();
        swapped_app.app_hash = [0xde; 32];
        let err = pinned
            .verify(&evidence_for(&pinned, &swapped_app), &policy())
            .expect_err("a swapped app hash must not survive the header hash");
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("the header hashes to"), "{rule}");
            }
            other => panic!("expected a consensus-rule refusal, got {other:?}"),
        }

        // 3. Rewriting `commit_time` is refused for the same reason: it is a
        //    leaf of the signed header. The stake-weighted median check below
        //    stays as belt and braces for a payload that re-seals and re-signs
        //    an entire header - which is a different block, not a lie about
        //    this one.
        let mut spoofed_time = honest_noble.clone();
        spoofed_time.commit_time += 86_400;
        let err = adapter()
            .verify(&evidence_for(&adapter(), &spoofed_time), &policy())
            .expect_err("spoofed commit_time must fail the header hash");
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
}
