//! The bridge dependent modules use while the B.U.D. 3.0 content flow is
//! being rebuilt. This file is permanent: it is the one place the content
//! reference and the storage error live once the old storage stack is gone.
//!
//! Every content-registering operation refuses with
//! [`StorageError::Bud3NotReady`] until the content flow merges; dependents
//! carry [`ContentRef`] and nothing else.

use super::content_id::ContentId;
use crate::core::address::Address;

/// A reference to content, the only storage handle a dependent module keeps
/// during the rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRef {
    /// The content identifier.
    pub content_id: ContentId,
}

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
    /// A registry id counter reached `u64::MAX`; no further id can be issued.
    IdSpaceExhausted,
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
    /// A deal reached its term while a retrieval challenge was still open on
    /// it.
    ///
    /// The missed-challenge slash settles only an `Active` deal, so letting
    /// the term pass under an open challenge is how an unanswered challenge
    /// stops being slashed: the row leaves `Active`, `finalize_missed_challenge`
    /// refuses with `DealNotActive`, and the opener's bond stays locked. The
    /// deal is held `Active` until the challenge closes and the next sweep
    /// expires it.
    OpenChallengeBlocksExpiry {
        deal_id: u64,
        open_challenges: u32,
    },
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
    /// A declared self-hosting policy lets an owner mark content critical
    /// and name how many paid replicas it needs. The rule existed and nothing read it,
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
    /// Nobody holds the parity shard an audit selected.
    ///
    /// No deal for that shard is `Active`, so there is no operator to ask.
    /// Not the same as an operator failing: no audit is opened.
    NoActiveParityDeal {
        manifest_id: ContentId,
        parity_index: u32,
    },
    /// Caller referenced a coding audit that does not exist.
    UnknownCodingAudit(u64),
    /// The coding audit already has an outcome. Answers are accepted once.
    CodingAuditNotOpen(u64),
    /// Someone other than the audited operator tried to answer.
    CodingAuditWrongResponder {
        audit_id: u64,
    },
    /// The selected deal already has an `Open` coding audit.
    CodingAuditAlreadyOpen {
        deal_id: u64,
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
    /// The manifest carries a column commitment for the audited parity shard
    /// and the answer did not prove its byte against it.
    ///
    /// This is a FAILED audit, not a refused answer: the operator was asked for
    /// a byte of a shard it claims to hold, and could not show that the byte is
    /// part of that shard. A memorised column of some other codeword is exactly
    /// what this refusal exists to catch.
    CodingAuditColumnProofRejected {
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
    /// The replica index is not below [`STORAGE_REPLICATION_TARGET`]. No
    /// object has more replica slots than that, so a larger index names a
    /// slot that does not exist.
    ReplicaIndexOutOfRange {
        replica_index: u8,
        max: u8,
    },
    /// Too many concurrent open challenges for a single deal.
    TooManyOpenChallenges {
        deal_id: u64,
        max: usize,
    },
    /// Too many concurrent open challenges across every manifest
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

    /// The B.U.D. 3.0 content flow is not merged yet: a content-registering
    /// operation refuses rather than half-serves. Removed when the content
    /// flow lands.
    Bud3NotReady,

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownShard {
                manifest_id,
                shard_id,
            } => write!(f, "shard {shard_id} not in manifest {manifest_id}"),
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
            Self::IdSpaceExhausted => write!(f, "registry id counter is exhausted"),
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
            Self::OpenChallengeBlocksExpiry {
                deal_id,
                open_challenges,
            } => write!(
                f,
                "deal {deal_id} reached its term with {open_challenges} challenge(s) still open: \
                 a missed answer could never be slashed under an expired deal"
            ),
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
            Self::NoActiveParityDeal {
                manifest_id,
                parity_index,
            } => write!(
                f,
                "no active deal holds parity shard {parity_index} of manifest {manifest_id}"
            ),
            Self::UnknownCodingAudit(id) => write!(f, "unknown coding audit {id}"),
            Self::CodingAuditNotOpen(id) => {
                write!(f, "coding audit {id} already has an outcome")
            }
            Self::CodingAuditWrongResponder { audit_id } => write!(
                f,
                "coding audit {audit_id} was not addressed to this responder"
            ),
            Self::CodingAuditAlreadyOpen { deal_id } => {
                write!(f, "deal {deal_id} already has an open coding audit")
            }
            Self::CodingAuditColumnProofRejected {
                manifest_id,
                parity_index,
                column,
            } => write!(
                f,
                "the coding audit answer for manifest {} parity {parity_index} column {column} \
                 did not prove its byte against the shard's column commitment",
                hex::encode(manifest_id.0)
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
            Self::ReplicaIndexOutOfRange { replica_index, max } => {
                write!(f, "replica index {replica_index} is not below {max}")
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

/// The temporary content-registration door for dependent modules.
///
/// The B.U.D. 3.0 content flow is not merged yet, so every content-registering
/// operation refuses with [`StorageError::Bud3NotReady`] instead of
/// half-serving. The refusal is removed when the content flow lands.
///
/// # Errors
///
/// Always [`StorageError::Bud3NotReady`].
pub fn register_content(_content: &[u8]) -> Result<ContentRef, StorageError> {
    Err(StorageError::Bud3NotReady)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Content registration refuses until the content flow is ready, and it
    /// refuses with the readiness error rather than another reason.
    #[test]
    fn content_registration_refused_until_bud3_ready() {
        let err = register_content(b"not yet").expect_err("the flow is not merged");
        assert_eq!(err, StorageError::Bud3NotReady);
    }
}
