//! Polkadot / Substrate `GRANDPA` (`GHOST`-based Recursive Ancestor Deriving
//! Prefix Agreement, Stewart et al. 2020) external finality adapter.
//!
//! Unlike per-block BFT protocols (`Tendermint`, `HotStuff`) that lock a single
//! block height at a time, or fixed-interval checkpoint gadgets (`Casper FFG`),
//! `GRANDPA` decouples block production from finality across arbitrary chain
//! prefixes: each authority casts weighted precommits on the deepest valid fork
//! head it observes, and a single justification finalizes the highest common
//! ancestor `target_header` once strictly more than `2/3` of total authority-set
//! weight precommits to `target_header` or verified descendants in
//! `votes_ancestries`.
//!
//! This adapter enforces seven deterministic soundness invariants:
//!
//! 1. **Self-derived header commitment**: every [`GrandpaHeader`] (`target_header`
//!    and every entry in `votes_ancestries`) recomputes
//!    [`compute_grandpa_header_hash`] over `(network, number, parent_hash,
//!    state_root, extrinsics_root, timestamp_ms, scheduled_change)` and compares
//!    `block_hash` in constant time, refusing zero `state_root` or `block_hash`.
//! 2. **Bounded prefix ancestry DAG verification**: `votes_ancestries` is bounded
//!    (`<= 512` headers), duplicate-free, strictly above `target_header.number`,
//!    and every precommit target must walk parent-by-parent with unit-decrementing
//!    block numbers and non-regressing timestamps back to `target_header.block_hash`.
//!    Votes on sibling forks or disconnected ancestors never contribute weight.
//! 3. **Overflow-free strict `> 2/3` supermajority**: authority weights sum in
//!    checked `u128`, duplicate or unknown authority keys fail closed, and quorum
//!    requires `signed_weight * 3 > total_weight * 2` via division-based `u128`
//!    arithmetic that cannot overflow at any bound.
//! 4. **Hybrid post-quantum non-downgrade**: every authority with a registered
//!    NIST FIPS 204 `ML-DSA-65` `pq_pubkey` must supply both a valid `Ed25519`
//!    signature and a valid `ML-DSA-65` co-signature bound to
//!    [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//! 5. **Parent-hash ancestry binding**: [`ExternalFinalityAdapter::attested_parent`]
//!    authenticates `target_header` before returning `Some(target_header.parent_hash)`,
//!    enabling cross-slot ancestry refutation without trusting envelope metadata.
//! 6. **Scheduled authority-set handoff**: [`advance_grandpa_authority_set`]
//!    rotates `set_id -> set_id + 1` only when a verified justification finalizes
//!    a header carrying a matching [`GrandpaScheduledChange`] digest.
//! 7. **Double-precommit equivocation slashing**: [`adjudicate_grandpa_equivocation`]
//!    verifies conflicting signed precommits by the same pinned authority in an
//!    identical `(set_id, round)` pair.
//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`
//! admission, prefix-justification verification, authority-set rotation, and
//! equivocation adjudication; `AdapterSpec` tag append joins `intake.rs`.

use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for Polkadot / Substrate GRANDPA finality.
///
/// WIRING: exposed for external domain registration and adapter descriptor derivation.
pub const ADAPTER_NAME: &str = "polkadot-grandpa-v1";
/// Adapter implementation version.
///
/// WIRING: exposed for `AdapterDescriptor` and attestation version pinning.
pub const ADAPTER_VERSION: u32 = 1;
/// Accepted wire evidence format version.
///
/// WIRING: exposed for `RawConsensusEvidence` construction and self-test probes.
pub const EVIDENCE_VERSION: u32 = 1;
/// Maximum authorities allowed in a single pinned GRANDPA voter set.
///
/// WIRING: exposed for caller-side authority-set sizing checks.
pub const MAX_GRANDPA_AUTHORITIES: usize = 1_024;
/// Maximum descendant headers allowed in `votes_ancestries` per justification.
///
/// WIRING: exposed for relayer justification builder bounds.
pub const MAX_GRANDPA_ANCESTRY_HEADERS: usize = 512;

const PAYLOAD_MAGIC: &[u8; 8] = b"DOTGRPV1";
const FIXED_WIRE_PREFIX_LEN: usize = 32;
const MAX_GRANDPA_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_AUTHORITY_ID_BYTES: usize = 128;
const ED25519_SIG_LEN: usize = 64;
const GRANDPA_PRECOMMIT_STAGE_BYTE: u8 = 0x01;

const SET_HASH_TAG: &[u8] = b"bud-grandpa-authority-set-v1";
const HEADER_HASH_TAG: &[u8] = b"bud-grandpa-header-v1";
const PRECOMMIT_SIGN_TAG: &[u8] = b"bud-grandpa-precommit-v1";

/// One weighted GRANDPA voter in an active authority set.
///
/// WIRING: carried in `PinnedGrandpaSet` for external domain anchor registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrandpaAuthority {
    /// Human-readable SS58 or validator label (`1..=128` bytes).
    pub authority_id: String,
    /// Canonical 32-byte Ed25519 GRANDPA session public key.
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero GRANDPA voting weight.
    pub weight: u64,
    /// Optional NIST FIPS 204 ML-DSA-65 public key; mandatory co-sig when non-empty.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Pinned GRANDPA authority set (`set_id` + weighted voters).
///
/// WIRING: passed to `PolkadotGrandpaAdapter::new` and rotated by `advance_grandpa_authority_set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedGrandpaSet {
    /// Monotonic GRANDPA authority-set counter (`set_id`).
    pub set_id: u64,
    /// Active weighted GRANDPA authorities for `set_id`.
    pub authorities: Vec<GrandpaAuthority>,
    /// Whether verified equivocations on this domain are backed by slashable collateral.
    pub has_slashable_bond_escrow: bool,
}

/// Consensus-digest scheduled authority-set transition committed inside a finalized header.
///
/// WIRING: embedded in `GrandpaHeader` to authenticate `advance_grandpa_authority_set` rotations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrandpaScheduledChange {
    /// Next sequential authority set identifier (`current_set_id + 1`).
    pub next_set_id: u64,
    /// Commitment digest `compute_grandpa_authority_set_hash(next_set_id, &next_authorities)`.
    pub next_authorities_hash: Hash32,
}

/// Canonical Substrate / Polkadot block header projection authenticated by GRANDPA.
///
/// WIRING: carried in justification payloads as `target_header` and `votes_ancestries`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrandpaHeader {
    /// Block height (`BlockNumber`).
    pub number: u64,
    /// Parent block hash.
    pub parent_hash: Hash32,
    /// Post-execution state trie root.
    pub state_root: Hash32,
    /// Extrinsics Merkle root.
    pub extrinsics_root: Hash32,
    /// Slot / aura / babe timestamp in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Optional scheduled authority-set rotation digest committed in this header.
    pub scheduled_change: Option<GrandpaScheduledChange>,
    /// Canonical header hash matching [`compute_grandpa_header_hash`].
    pub block_hash: Hash32,
}

/// One authority's signed GRANDPA precommit vote inside a justification.
///
/// WIRING: carried in `GrandpaJustification` and `GrandpaEquivocationProof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrandpaSignedPrecommit {
    /// Voted block hash (`target_header` or a strict descendant in `votes_ancestries`).
    pub target_hash: Hash32,
    /// Voted block number.
    pub target_number: u64,
    /// Signing authority's 32-byte Ed25519 public key.
    pub authority_pubkey: [u8; 32],
    /// 64-byte Ed25519 signature over [`grandpa_precommit_sign_bytes`].
    pub ed25519_sig: Vec<u8>,
    /// Optional NIST ML-DSA-65 co-signature under `CROSS_DOMAIN_V1`.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Non-interactive double-precommit equivocation proof within a single `(set_id, round)`.
///
/// WIRING: consumed by `adjudicate_grandpa_equivocation` for slashing adjudication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrandpaEquivocationProof {
    /// Authority set identifier under which both precommits were cast.
    pub set_id: u64,
    /// GRANDPA voting round in which the authority double-voted.
    pub round: u64,
    /// First signed precommit.
    pub first: GrandpaSignedPrecommit,
    /// Second conflicting signed precommit in the same `(set_id, round)`.
    pub second: GrandpaSignedPrecommit,
}

/// Verified outcome of adjudicating a [`GrandpaEquivocationProof`].
///
/// WIRING: returned by `adjudicate_grandpa_equivocation` to freeze/slash offending weight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrandpaSlashedAuthority {
    /// Offending authority's Ed25519 public key.
    pub authority_pubkey: [u8; 32],
    /// Authority-set ID where the equivocation occurred.
    pub set_id: u64,
    /// GRANDPA round where the equivocation occurred.
    pub round: u64,
    /// Voting weight of the slashed authority in `PinnedGrandpaSet`.
    pub slashed_weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GrandpaJustificationWire {
    set_id: u64,
    round: u64,
    target_header: GrandpaHeader,
    votes_ancestries: Vec<GrandpaHeader>,
    precommits: Vec<GrandpaSignedPrecommit>,
}

/// Compute the canonical header hash for a [`GrandpaHeader`] bound to `network`.
///
/// WIRING: exposed for relayers, justification builders, and header verification.
#[must_use]
pub fn compute_grandpa_header_hash(
    network: &str,
    number: u64,
    parent_hash: &Hash32,
    state_root: &Hash32,
    extrinsics_root: &Hash32,
    timestamp_ms: u64,
    scheduled_change: Option<&GrandpaScheduledChange>,
) -> Hash32 {
    let mut change_buf = [0u8; 41];
    if let Some(ch) = scheduled_change {
        if let Some((tag, rest)) = change_buf.split_first_mut() {
            *tag = 1;
            if let Some((id_bytes, hash_bytes)) = rest.split_at_mut_checked(8) {
                id_bytes.copy_from_slice(&ch.next_set_id.to_le_bytes());
                hash_bytes.copy_from_slice(&ch.next_authorities_hash);
            }
        }
    }
    crate::core::hash::hash_fields_bytes(&[
        HEADER_HASH_TAG,
        network.as_bytes(),
        &number.to_le_bytes(),
        parent_hash,
        state_root,
        extrinsics_root,
        &timestamp_ms.to_le_bytes(),
        &change_buf,
    ])
}

/// Compute the canonical GRANDPA localized precommit signing payload.
///
/// Matches Polkadot Host Spec section 5.5 localized message structure
/// `(stage = 0x01 Precommit, target_hash, target_number, round, set_id)`
/// domain-separated with `network`.
///
/// WIRING: exposed for GRANDPA precommit signing and equivocation verification.
#[must_use]
pub fn grandpa_precommit_sign_bytes(
    network: &str,
    set_id: u64,
    round: u64,
    target_hash: &Hash32,
    target_number: u64,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        PRECOMMIT_SIGN_TAG,
        &[GRANDPA_PRECOMMIT_STAGE_BYTE],
        network.as_bytes(),
        &set_id.to_le_bytes(),
        &round.to_le_bytes(),
        target_hash,
        &target_number.to_le_bytes(),
    ])
}

fn parse_authority_table(
    authorities: &[GrandpaAuthority],
) -> Result<(BTreeMap<[u8; 32], &GrandpaAuthority>, u128), AdapterError> {
    if authorities.is_empty() || authorities.len() > MAX_GRANDPA_AUTHORITIES {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "GRANDPA authority set size {} outside 1..={MAX_GRANDPA_AUTHORITIES}",
                authorities.len()
            ),
        });
    }
    let mut table = BTreeMap::new();
    let mut total_weight = 0u128;
    for auth in authorities {
        if auth.authority_id.is_empty() || auth.authority_id.len() > MAX_AUTHORITY_ID_BYTES {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA authority_id must be 1..=128 bytes".into(),
            });
        }
        if auth.ed25519_pubkey == [0u8; 32] {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA authority has all-zero Ed25519 public key".into(),
            });
        }
        if auth.weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA authority voting weight must be non-zero".into(),
            });
        }
        if table.insert(auth.ed25519_pubkey, auth).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate Ed25519 public key in GRANDPA authority set".into(),
            });
        }
        total_weight = total_weight
            .checked_add(u128::from(auth.weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "GRANDPA total authority weight overflows u128".into(),
            })?;
    }
    Ok((table, total_weight))
}

/// Compute the deterministic commitment digest of a next GRANDPA authority set.
///
/// WIRING: exposed for scheduled authority-set rotation digest construction.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] if `authorities` violates set bounds,
/// uniqueness, or non-zero weight rules.
pub fn compute_grandpa_authority_set_hash(
    set_id: u64,
    authorities: &[GrandpaAuthority],
) -> Result<Hash32, AdapterError> {
    let (_table, _total) = parse_authority_table(authorities)?;
    let mut rolling = crate::core::hash::hash_fields_bytes(&[
        SET_HASH_TAG,
        &set_id.to_le_bytes(),
        &(authorities.len() as u64).to_le_bytes(),
    ]);
    for auth in authorities {
        rolling = crate::core::hash::hash_fields_bytes(&[
            &rolling,
            auth.authority_id.as_bytes(),
            &auth.ed25519_pubkey,
            &auth.weight.to_le_bytes(),
            &auth.pq_pubkey,
        ]);
    }
    Ok(rolling)
}

/// Encode a canonical GRANDPA justification wire payload.
///
/// Layout:
/// - `0..8`: `DOTGRPV1` magic
/// - `8..16`: `set_id` (`u64` LE)
/// - `16..24`: `round` (`u64` LE)
/// - `24..32`: `target_header.number` (`u64` LE)
/// - `32..`: `postcard`-serialized `GrandpaJustificationWire`
///
/// WIRING: exposed for relayers and admission golden-sample construction.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] if serialization fails or exceeds
/// `MAX_GRANDPA_PAYLOAD_BYTES`.
pub fn encode_grandpa_justification_evidence(
    set_id: u64,
    round: u64,
    target_header: GrandpaHeader,
    votes_ancestries: Vec<GrandpaHeader>,
    precommits: Vec<GrandpaSignedPrecommit>,
) -> Result<Vec<u8>, AdapterError> {
    let wire = GrandpaJustificationWire {
        set_id,
        round,
        target_header,
        votes_ancestries,
        precommits,
    };
    let body = postcard::to_allocvec(&wire).map_err(|e| AdapterError::Malformed {
        offset: FIXED_WIRE_PREFIX_LEN,
        reason: format!("GRANDPA postcard encode failed: {e}"),
    })?;
    let total_len = FIXED_WIRE_PREFIX_LEN
        .checked_add(body.len())
        .ok_or_else(|| AdapterError::Malformed {
            offset: 0,
            reason: "GRANDPA wire payload length overflow".into(),
        })?;
    if total_len > MAX_GRANDPA_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_GRANDPA_PAYLOAD_BYTES,
            reason: format!(
                "GRANDPA wire payload {total_len} bytes exceeds ceiling {MAX_GRANDPA_PAYLOAD_BYTES}"
            ),
        });
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&wire.set_id.to_le_bytes());
    out.extend_from_slice(&wire.round.to_le_bytes());
    out.extend_from_slice(&wire.target_header.number.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Result<u64, AdapterError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| AdapterError::Malformed {
            offset,
            reason: "GRANDPA wire header offset overflow".into(),
        })?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| AdapterError::Malformed {
            offset,
            reason: "truncated GRANDPA wire prefix".into(),
        })?;
    let arr: [u8; 8] = slice.try_into().map_err(|_| AdapterError::Malformed {
        offset,
        reason: "invalid 8-byte integer slice".into(),
    })?;
    Ok(u64::from_le_bytes(arr))
}

fn decode_grandpa_justification_evidence(
    payload: &[u8],
) -> Result<GrandpaJustificationWire, AdapterError> {
    if payload.len() < FIXED_WIRE_PREFIX_LEN {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!("GRANDPA payload shorter than {FIXED_WIRE_PREFIX_LEN}-byte prefix"),
        });
    }
    if payload.len() > MAX_GRANDPA_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_GRANDPA_PAYLOAD_BYTES,
            reason: format!(
                "GRANDPA payload {} bytes exceeds ceiling {MAX_GRANDPA_PAYLOAD_BYTES}",
                payload.len()
            ),
        });
    }
    let magic = payload.get(0..8).ok_or_else(|| AdapterError::Malformed {
        offset: 0,
        reason: "missing GRANDPA magic".into(),
    })?;
    if !bool::from(magic.ct_eq(PAYLOAD_MAGIC.as_slice())) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "invalid DOTGRPV1 payload magic".into(),
        });
    }
    let prefix_set_id = read_le_u64(payload, 8)?;
    let prefix_round = read_le_u64(payload, 16)?;
    let prefix_number = read_le_u64(payload, 24)?;
    let body = payload
        .get(FIXED_WIRE_PREFIX_LEN..)
        .ok_or_else(|| AdapterError::Malformed {
            offset: FIXED_WIRE_PREFIX_LEN,
            reason: "missing GRANDPA postcard body".into(),
        })?;
    let (decoded, trailing) =
        postcard::take_from_bytes::<GrandpaJustificationWire>(body).map_err(|e| {
            AdapterError::Malformed {
                offset: FIXED_WIRE_PREFIX_LEN,
                reason: format!("corrupted GRANDPA postcard body: {e}"),
            }
        })?;
    if !trailing.is_empty() {
        return Err(AdapterError::Malformed {
            offset: payload.len().saturating_sub(trailing.len()),
            reason: format!(
                "GRANDPA payload carries {} unauthenticated trailing bytes",
                trailing.len()
            ),
        });
    }
    if decoded.set_id != prefix_set_id
        || decoded.round != prefix_round
        || decoded.target_header.number != prefix_number
    {
        return Err(AdapterError::ConsensusRule {
            rule: "GRANDPA wire prefix disagrees with serialized justification header".into(),
        });
    }
    Ok(decoded)
}

/// Overflow-free minimum weight strictly exceeding `2/3` of `total_weight`:
/// `floor((2 * total_weight) / 3) + 1`.
fn min_strict_two_thirds_weight(total_weight: u128) -> Option<u128> {
    if total_weight == 0 {
        return None;
    }
    let q = total_weight / 3;
    let r = total_weight % 3;
    let floor_two_thirds = if r == 2 {
        q.checked_mul(2)?.checked_add(1)?
    } else {
        q.checked_mul(2)?
    };
    floor_two_thirds.checked_add(1)
}

fn authenticate_header(network: &str, hdr: &GrandpaHeader, role: &str) -> Result<(), AdapterError> {
    if bool::from(hdr.state_root.ct_eq(&[0u8; 32])) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("GRANDPA {role} carries all-zero state_root"),
        });
    }
    if bool::from(hdr.block_hash.ct_eq(&[0u8; 32])) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("GRANDPA {role} carries all-zero block_hash"),
        });
    }
    let expected = compute_grandpa_header_hash(
        network,
        hdr.number,
        &hdr.parent_hash,
        &hdr.state_root,
        &hdr.extrinsics_root,
        hdr.timestamp_ms,
        hdr.scheduled_change.as_ref(),
    );
    if !bool::from(hdr.block_hash.as_slice().ct_eq(expected.as_slice())) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("GRANDPA {role} block_hash mismatches canonical header digest"),
        });
    }
    Ok(())
}

fn verify_vote_descends_from_target(
    target: &GrandpaHeader,
    ancestry_map: &BTreeMap<Hash32, &GrandpaHeader>,
    vote_hash: &Hash32,
    vote_number: u64,
) -> Result<(), AdapterError> {
    if vote_number == target.number {
        if bool::from(vote_hash.as_slice().ct_eq(target.block_hash.as_slice())) {
            return Ok(());
        }
        return Err(AdapterError::ConsensusRule {
            rule: "GRANDPA precommit at target_number votes for sibling fork hash".into(),
        });
    }
    if vote_number < target.number {
        return Err(AdapterError::ConsensusRule {
            rule: "GRANDPA precommit target_number precedes justification target_header".into(),
        });
    }
    let max_steps = MAX_GRANDPA_ANCESTRY_HEADERS;
    let mut cur_hash = *vote_hash;
    let mut expected_number = vote_number;

    for _ in 0..max_steps {
        let Some(hdr) = ancestry_map.get(&cur_hash).copied() else {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA precommit missing verified header in votes_ancestries".into(),
            });
        };
        if hdr.number != expected_number {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA ancestry header number continuity broken".into(),
            });
        }
        let Some(parent_number) = expected_number.checked_sub(1) else {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA ancestry header number underflows zero".into(),
            });
        };
        if parent_number == target.number {
            if !bool::from(
                hdr.parent_hash
                    .as_slice()
                    .ct_eq(target.block_hash.as_slice()),
            ) {
                return Err(AdapterError::ConsensusRule {
                    rule: "GRANDPA ancestry chain misses target_header at base height".into(),
                });
            }
            if hdr.timestamp_ms < target.timestamp_ms {
                return Err(AdapterError::ConsensusRule {
                    rule: "GRANDPA child header timestamp regresses below target_header".into(),
                });
            }
            return Ok(());
        }
        let Some(parent_hdr) = ancestry_map.get(&hdr.parent_hash).copied() else {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA ancestry chain parent missing before reaching target_header".into(),
            });
        };
        if hdr.timestamp_ms < parent_hdr.timestamp_ms {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA ancestry timestamps regress along descendant branch".into(),
            });
        }
        cur_hash = hdr.parent_hash;
        expected_number = parent_number;
    }

    Err(AdapterError::ConsensusRule {
        rule: "GRANDPA precommit ancestry exceeds maximum allowed depth".into(),
    })
}

fn verify_single_precommit_crypto(
    network: &str,
    set_id: u64,
    round: u64,
    auth: &GrandpaAuthority,
    precommit: &GrandpaSignedPrecommit,
) -> Result<bool, AdapterError> {
    if precommit.ed25519_sig.len() != ED25519_SIG_LEN {
        return Err(AdapterError::Crypto {
            what: format!(
                "GRANDPA Ed25519 signature must be {ED25519_SIG_LEN} bytes, got {}",
                precommit.ed25519_sig.len()
            ),
        });
    }
    let sign_digest = grandpa_precommit_sign_bytes(
        network,
        set_id,
        round,
        &precommit.target_hash,
        precommit.target_number,
    );
    crate::crypto::primitives::verify_signature(
        &sign_digest,
        &precommit.ed25519_sig,
        &auth.ed25519_pubkey,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid Ed25519 signature on GRANDPA precommit".into(),
    })?;

    if auth.pq_pubkey.is_empty() {
        Ok(false)
    } else {
        if precommit.pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: "missing mandatory ML-DSA-65 co-signature for PQ-enrolled GRANDPA authority"
                    .into(),
            });
        }
        crate::crypto::primitives::PqKeyPair::verify(
            &auth.pq_pubkey,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &sign_digest,
            &precommit.pq_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid ML-DSA-65 co-signature on GRANDPA precommit".into(),
        })?;
        Ok(true)
    }
}

struct VerifiedGrandpaJustification {
    round: u64,
    target_header: GrandpaHeader,
    signers_scaled: u64,
    required_scaled: u64,
    total_weight: u128,
    all_pq: bool,
}

fn evaluate_grandpa_justification(
    network: &str,
    pinned: &PinnedGrandpaSet,
    wire: &GrandpaJustificationWire,
) -> Result<VerifiedGrandpaJustification, AdapterError> {
    let (auth_table, total_weight) = parse_authority_table(&pinned.authorities)?;
    if wire.set_id != pinned.set_id {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "GRANDPA justification set_id {} mismatches pinned set_id {}",
                wire.set_id, pinned.set_id
            ),
        });
    }
    if wire.round == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "GRANDPA round 0 cannot carry a precommit justification".into(),
        });
    }
    if wire.votes_ancestries.len() > MAX_GRANDPA_ANCESTRY_HEADERS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "GRANDPA votes_ancestries length {} exceeds {MAX_GRANDPA_ANCESTRY_HEADERS}",
                wire.votes_ancestries.len()
            ),
        });
    }
    if wire.precommits.is_empty() || wire.precommits.len() > MAX_GRANDPA_AUTHORITIES {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "GRANDPA precommit count {} outside 1..={MAX_GRANDPA_AUTHORITIES}",
                wire.precommits.len()
            ),
        });
    }

    authenticate_header(network, &wire.target_header, "target_header")?;

    let mut ancestry_map: BTreeMap<Hash32, &GrandpaHeader> = BTreeMap::new();
    for ancestry_hdr in &wire.votes_ancestries {
        if ancestry_hdr.number <= wire.target_header.number {
            return Err(AdapterError::ConsensusRule {
                rule: "GRANDPA votes_ancestries header number must strictly exceed target_header"
                    .into(),
            });
        }
        authenticate_header(network, ancestry_hdr, "ancestry_header")?;
        if ancestry_map
            .insert(ancestry_hdr.block_hash, ancestry_hdr)
            .is_some()
        {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate block_hash in GRANDPA votes_ancestries".into(),
            });
        }
    }

    let mut seen_signers = BTreeSet::new();
    let mut signed_weight = 0u128;
    let mut all_pq = true;

    for precommit in &wire.precommits {
        if !seen_signers.insert(precommit.authority_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate authority precommit in GRANDPA justification".into(),
            });
        }
        let Some(auth) = auth_table.get(&precommit.authority_pubkey).copied() else {
            return Err(AdapterError::ConsensusRule {
                rule: "unknown authority signed GRANDPA precommit".into(),
            });
        };
        let has_pq =
            verify_single_precommit_crypto(network, pinned.set_id, wire.round, auth, precommit)?;
        if !has_pq {
            all_pq = false;
        }
        verify_vote_descends_from_target(
            &wire.target_header,
            &ancestry_map,
            &precommit.target_hash,
            precommit.target_number,
        )?;
        signed_weight = signed_weight
            .checked_add(u128::from(auth.weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "GRANDPA signed weight overflows u128".into(),
            })?;
    }

    let required_weight =
        min_strict_two_thirds_weight(total_weight).ok_or_else(|| AdapterError::ConsensusRule {
            rule: "GRANDPA total authority weight cannot compute strict 2/3 threshold".into(),
        })?;
    if signed_weight < required_weight {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "GRANDPA signed weight {signed_weight}/{total_weight} below required {required_weight}"
            ),
        });
    }

    let shift = 128u32
        .saturating_sub(total_weight.leading_zeros())
        .saturating_sub(64);
    let signers_scaled = u64::try_from(signed_weight >> shift).unwrap_or(u64::MAX);
    let required_scaled = u64::try_from(required_weight >> shift)
        .unwrap_or(u64::MAX)
        .max(1);

    Ok(VerifiedGrandpaJustification {
        round: wire.round,
        target_header: wire.target_header.clone(),
        signers_scaled,
        required_scaled,
        total_weight,
        all_pq,
    })
}

/// Rotate a [`PinnedGrandpaSet`] from `set_id` to `set_id + 1` using a verified
/// GRANDPA justification whose `target_header` commits a matching
/// [`GrandpaScheduledChange`].
///
/// WIRING: exposed for permissionless authority-set rotation without governance votes.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the justification fails verification, no
/// `scheduled_change` is committed, `next_set_id != current.set_id + 1`, or
/// `proposed_next_authorities` mismatches `next_authorities_hash`.
pub fn advance_grandpa_authority_set(
    network: &str,
    current: &PinnedGrandpaSet,
    justification_payload: &[u8],
    proposed_next_authorities: Vec<GrandpaAuthority>,
    next_has_slashable_bond_escrow: bool,
) -> Result<PinnedGrandpaSet, AdapterError> {
    let wire = decode_grandpa_justification_evidence(justification_payload)?;
    let verified = evaluate_grandpa_justification(network, current, &wire)?;
    let Some(scheduled) = verified.target_header.scheduled_change.as_ref() else {
        return Err(AdapterError::ConsensusRule {
            rule: "finalized GRANDPA target_header carries no scheduled authority change".into(),
        });
    };
    let expected_next_id =
        current
            .set_id
            .checked_add(1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "GRANDPA set_id overflows u64 on rotation".into(),
            })?;
    if scheduled.next_set_id != expected_next_id {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "GRANDPA scheduled next_set_id {} must equal {}",
                scheduled.next_set_id, expected_next_id
            ),
        });
    }
    let computed_hash =
        compute_grandpa_authority_set_hash(expected_next_id, &proposed_next_authorities)?;
    if !bool::from(
        computed_hash
            .as_slice()
            .ct_eq(scheduled.next_authorities_hash.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "proposed GRANDPA authority set hash mismatches finalized scheduled_change"
                .into(),
        });
    }
    Ok(PinnedGrandpaSet {
        set_id: expected_next_id,
        authorities: proposed_next_authorities,
        has_slashable_bond_escrow: next_has_slashable_bond_escrow,
    })
}

/// Adjudicate a non-interactive [`GrandpaEquivocationProof`] showing that one
/// pinned authority signed two distinct precommit targets in the same `(set_id, round)`.
///
/// WIRING: exposed for external domain equivocation challenge doors.
///
/// # Errors
///
/// Returns an [`AdapterError`] if `set_id` mismatches `pinned`, `round == 0`,
/// the two precommits were signed by different keys or vote for identical
/// `(target_hash, target_number)`, the signer is not in `pinned`, or either
/// cryptographic signature is invalid.
pub fn adjudicate_grandpa_equivocation(
    network: &str,
    pinned: &PinnedGrandpaSet,
    proof: &GrandpaEquivocationProof,
) -> Result<GrandpaSlashedAuthority, AdapterError> {
    let (auth_table, _) = parse_authority_table(&pinned.authorities)?;
    if proof.set_id != pinned.set_id {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "GRANDPA equivocation set_id {} mismatches pinned set_id {}",
                proof.set_id, pinned.set_id
            ),
        });
    }
    if proof.round == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "GRANDPA equivocation round must be non-zero".into(),
        });
    }
    if !bool::from(
        proof
            .first
            .authority_pubkey
            .as_slice()
            .ct_eq(proof.second.authority_pubkey.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "GRANDPA equivocation precommits carry distinct authority public keys".into(),
        });
    }
    let same_hash = bool::from(
        proof
            .first
            .target_hash
            .as_slice()
            .ct_eq(proof.second.target_hash.as_slice()),
    );
    if same_hash && proof.first.target_number == proof.second.target_number {
        return Err(AdapterError::ConsensusRule {
            rule: "identical GRANDPA precommits in the same round do not constitute equivocation"
                .into(),
        });
    }
    let Some(auth) = auth_table.get(&proof.first.authority_pubkey).copied() else {
        return Err(AdapterError::ConsensusRule {
            rule: "GRANDPA equivocation signer is not in pinned authority set".into(),
        });
    };
    verify_single_precommit_crypto(network, pinned.set_id, proof.round, auth, &proof.first)?;
    verify_single_precommit_crypto(network, pinned.set_id, proof.round, auth, &proof.second)?;

    Ok(GrandpaSlashedAuthority {
        authority_pubkey: auth.ed25519_pubkey,
        set_id: pinned.set_id,
        round: proof.round,
        slashed_weight: auth.weight,
    })
}

/// External finality adapter for Polkadot / Substrate `GRANDPA` justifications.
///
/// WIRING: implements `ExternalFinalityAdapter` for external domain registry admission.
#[derive(Debug, Clone)]
pub struct PolkadotGrandpaAdapter {
    network: String,
    pinned: Option<PinnedGrandpaSet>,
    descriptor: AdapterDescriptor,
    golden: Option<RawConsensusEvidence>,
}

impl PolkadotGrandpaAdapter {
    /// Construct a [`PolkadotGrandpaAdapter`] bound to `network` and optional `pinned` set.
    ///
    /// WIRING: called when registering or instantiating a Polkadot / Substrate domain.
    #[must_use]
    pub fn new(network: &str, pinned: Option<PinnedGrandpaSet>) -> Self {
        let set_size = pinned.as_ref().map_or(0, |p| {
            u64::try_from(p.authorities.len()).unwrap_or(u64::MAX)
        });
        let descriptor = AdapterDescriptor {
            id: AdapterId::from_name(ADAPTER_NAME),
            name: ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "polkadot-grandpa-bft".to_string(),
            finality_kind: FinalityKind::ProtocolFinality,
            required_depth: 1,
            time_unit: TimeUnit::Round,
            trust_model: TrustModel::HonestMajority { set_size },
        };
        Self {
            network: network.to_string(),
            pinned,
            descriptor,
            golden: None,
        }
    }

    /// Attach a canonical golden evidence sample for self-test admission.
    ///
    /// WIRING: called before `selftest::admit` during external domain registration.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn evaluate_evidence(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: hex::encode(self.descriptor.id.0),
                found: hex::encode(evidence.adapter.0),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "GRANDPA evidence network '{}' mismatches adapter network '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = self.pinned.as_ref() else {
            return Err(AdapterError::Unavailable {
                reason: "no pinned GRANDPA authority set configured".into(),
            });
        };
        if policy.require_slashable && !pinned.has_slashable_bond_escrow {
            return Err(AdapterError::UnslashableBacking);
        }

        let wire = decode_grandpa_justification_evidence(&evidence.payload)?;
        let verified = evaluate_grandpa_justification(&self.network, pinned, &wire)?;

        // Observed depth is 1 + descendant chain span in votes_ancestries.
        let max_descendant = wire
            .votes_ancestries
            .iter()
            .map(|h| h.number)
            .max()
            .unwrap_or(verified.target_header.number);
        let observed_depth = max_descendant
            .saturating_sub(verified.target_header.number)
            .saturating_add(1);
        if observed_depth < policy.min_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: observed_depth,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && policy.now > verified.round {
            let age = policy.now.saturating_sub(verified.round);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }
        if policy.require_declared_match {
            if evidence.declared_height != verified.target_header.number {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(
                evidence
                    .declared_root
                    .as_slice()
                    .ct_eq(verified.target_header.state_root.as_slice()),
            ) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }

        let scheme = if verified.all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height: verified.target_header.number,
            state_root: verified.target_header.state_root,
            finalized_at: verified.round,
            time_unit: TimeUnit::Round,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: verified.signers_scaled,
                required: verified.required_scaled,
                total_weight: verified.total_weight,
                slashable: pinned.has_slashable_bond_escrow,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(verified.target_header.block_hash),
            attested_event_root: None,
            attested_tx_root: Some(verified.target_header.extrinsics_root),
        };
        Ok((attestation, verified.all_pq))
    }

    fn locate_golden_sig_offset(&self) -> usize {
        let Some(g) = self.golden.as_ref() else {
            return FIXED_WIRE_PREFIX_LEN + 64;
        };
        let Ok(wire) = decode_grandpa_justification_evidence(&g.payload) else {
            return g.payload.len().saturating_sub(32);
        };
        if let Some(first) = wire.precommits.first() {
            if first.ed25519_sig.len() == ED25519_SIG_LEN {
                if let Some(pos) = g
                    .payload
                    .windows(ED25519_SIG_LEN)
                    .position(|w| w == first.ed25519_sig.as_slice())
                {
                    return pos;
                }
            }
        }
        g.payload.len().saturating_sub(32)
    }
}

impl ExternalFinalityAdapter for PolkadotGrandpaAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.evaluate_evidence(evidence, policy).map(|(att, _)| att)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (att, all_pq) = self.evaluate_evidence(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_offset = self.locate_golden_sig_offset();
        vec![
            FaultProbe {
                name: "refuses unsupported GRANDPA evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 99 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses mismatched Polkadot network identifier".into(),
                patch: BytePatch::Network {
                    value: "kusama:b0a8d493285c2df73290dfb7e61f870f".into(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted DOTGRPV1 wire magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"NOTDOTGR".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses truncated GRANDPA wire prefix".into(),
                patch: BytePatch::TruncatePayload { keep: 16 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses tampered wire prefix set_id".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xEE; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses lied declared height in envelope".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses lied declared state_root in envelope".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted Ed25519 precommit signature bytes".into(),
                patch: BytePatch::InPayload {
                    offset: sig_offset,
                    bytes: vec![0xAA; 16],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }

    fn attested_parent(&self, evidence: &RawConsensusEvidence) -> Option<[u8; 32]> {
        if evidence.adapter != self.descriptor.id
            || evidence.evidence_version != EVIDENCE_VERSION
            || evidence.network != self.network
        {
            return None;
        }
        let pinned = self.pinned.as_ref()?;
        let wire = decode_grandpa_justification_evidence(&evidence.payload).ok()?;
        let verified = evaluate_grandpa_justification(&self.network, pinned, &wire).ok()?;
        Some(verified.target_header.parent_hash)
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.pinned.is_some()
    }
}
