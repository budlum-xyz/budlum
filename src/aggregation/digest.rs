//! Every digest of the aggregation layer, in one file, with the directive's
//! section 4 as the specification.
//!
//! # The one invariant
//!
//! A digest is a function of a *fixed, explicit* list of fields, each of which
//! is either fixed width or length-prefixed. Two different inputs therefore
//! never share an encoding, and the encoding never depends on a `Display`
//! impl, a `serde` representation or a map iteration order. The length prefix
//! is the same one `crate::core::hash::hash_fields_bytes` uses (u64
//! little-endian before every field), so a tree that wires this module into the
//! core can call the core function and get the same bytes.
//!
//! # Tags
//!
//! Every tag is a `BDLM_*` literal listed in `src/crypto/domain_tags.rs`; the
//! `domain-tags` gate refuses a tag used but unlisted and a tag listed but
//! unused. [`ALL_TAGS`] repeats them so the distinctness and prefix-freeness
//! properties are testable without reading the inventory.

use sha2::{Digest as _, Sha256};

use super::types::{
    Address, AggError, AggParams, Claim, ClaimFrame, DomainId, Envelope, Ext, Hash, ObjectKind,
    Segment,
};

/// `claim_digest = H("BDLM_CLAIM_V1" || domain || kind tag || claim values)`.
pub const TAG_CLAIM: &str = "BDLM_CLAIM_V1";
/// The Merkle leaf and interior prefixes of `claims_root`.
pub const TAG_CLAIM_ROOT: &str = "BDLM_CLAIM_ROOT_V1";
/// `tick_pi = H("BDLM_AGG_TICK_V1" || domain || claims_root || count || aggregator)`.
pub const TAG_TICK: &str = "BDLM_AGG_TICK_V1";
/// `merge_pi = H("BDLM_AGG_MERGE_V1" || left_pi || right_pi)`.
pub const TAG_MERGE: &str = "BDLM_AGG_MERGE_V1";
/// `object_id = H("BDLM_OBJECT_V1" || envelope bytes)`.
pub const TAG_OBJECT: &str = "BDLM_OBJECT_V1";
/// `frame_hash = H("BDLM_FRAME_V1" || master_pi || params_hash || H(proof))`.
pub const TAG_FRAME: &str = "BDLM_FRAME_V1";
/// `AUTH_OK`, the output digest a program account's authority claim names.
pub const TAG_AUTH_OK: &str = "BDLM_AUTH_OK_V1";
/// The policy an adapter answers to, for `FinalityProof` claims (domain
/// adapters bind a claim to the exact verification policy it was checked under).
pub const TAG_BINDING: &str = "BDLM_AGG_BINDING_V1";
/// The digest of an adapter's identity in an aggregation claim.
pub const TAG_ADAPTER: &str = "BDLM_AGG_ADAPTER_V1";
/// The name-derived program hash of the tick AIR (Phase 2).
pub const TAG_PROGRAM_TICK: &str = "BDLM_AGG_PROGRAM_TICK_V1";
/// The name-derived program hash of the merge AIR (Phase 3).
pub const TAG_PROGRAM_MERGE: &str = "BDLM_AGG_PROGRAM_MERGE_V1";
/// A domain finality claim, wrapping a `FinalityProof` digest (Phase 4).
pub const TAG_FINALITY_CLAIM: &str = "BDLM_AGG_FINALITY_CLAIM_V1";
/// The preimage tag of the reference backend's merge proof. Replaced by the
/// `AggMerge` program's public input in Phase 3; kept distinct so a native merge
/// can never be read as a STARK merge.
pub const TAG_NATIVE_MERGE: &str = "BDLM_AGG_NATIVE_MERGE_V1";

/// Every tag this module introduces, for the distinctness property.
pub const ALL_TAGS: [&str; 13] = [
    TAG_CLAIM,
    TAG_CLAIM_ROOT,
    TAG_TICK,
    TAG_MERGE,
    TAG_OBJECT,
    TAG_FRAME,
    TAG_AUTH_OK,
    TAG_BINDING,
    TAG_ADAPTER,
    TAG_PROGRAM_TICK,
    TAG_PROGRAM_MERGE,
    TAG_FINALITY_CLAIM,
    TAG_NATIVE_MERGE,
];

/// The preimage rule of `crate::core::hash::hash_fields_bytes`: a u64
/// little-endian length before every field, then the field.
fn h(tag: &str, fields: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((tag.len() as u64).to_le_bytes());
    hasher.update(tag.as_bytes());
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// The constant, domain-separated program hash of a named program.
///
/// Same derivation as `crate::cross_domain::external::spec::AdapterId::from_name`:
/// the name is the whole input, so anybody can recompute the id from the name
/// and check that the constant means what it says.
fn program_hash_from_name(tag: &str, name: &str) -> Hash {
    h(tag, &[name.as_bytes()])
}

/// `AGG_TICK_PROGRAM_HASH`, the program a single-aggregator frame is proven by.
#[must_use]
pub fn agg_tick_program_hash() -> Hash {
    program_hash_from_name(TAG_PROGRAM_TICK, "budlum/agg/tick/v1")
}

/// `AGG_MERGE_PROGRAM_HASH`, the program a merged frame is proven by.
#[must_use]
pub fn agg_merge_program_hash() -> Hash {
    program_hash_from_name(TAG_PROGRAM_MERGE, "budlum/agg/merge/v1")
}

/// The digest of the consensus fields of `params`. A proof produced under one
/// parameter set is refused under another because this digest enters
/// [`frame_hash`] and the proof commits to the frame hash.
#[must_use]
pub fn params_hash(params: &AggParams) -> Hash {
    h(TAG_BINDING, &[b"params", &params.consensus_bytes()])
}

/// `claim_digest = H("BDLM_CLAIM_V1" || domain || kind tag || claim values)`.
///
/// The domain is inside every claim digest. That is the single most load-bearing
/// line in the module: a claim verified for domain A cannot be replayed into
/// domain B, because the digest the Merkle root commits to would differ.
#[must_use]
pub fn claim_digest(domain: DomainId, claim: &Claim) -> Hash {
    let domain = domain.to_le_bytes();
    match claim {
        Claim::Sig {
            scheme,
            signer,
            msg_hash,
        } => h(
            TAG_CLAIM,
            &[
                &domain,
                &[ObjectKind::Signature.tag()],
                &scheme.to_le_bytes(),
                signer.as_bytes(),
                msg_hash,
            ],
        ),
        Claim::Prog {
            program_hash,
            input_hash,
            output_hash,
        } => h(
            TAG_CLAIM,
            &[
                &domain,
                &[ObjectKind::StarkProof.tag()],
                program_hash,
                input_hash,
                output_hash,
            ],
        ),
        Claim::Poly {
            poly_hash,
            point,
            value,
        } => h(
            TAG_CLAIM,
            &[
                &domain,
                &[ObjectKind::PcsOpening.tag()],
                poly_hash,
                &point.canonical_bytes(),
                &value.canonical_bytes(),
            ],
        ),
    }
}

/// The canonical encoding of an envelope, as hashed into `object_id`.
///
/// Fixed template, length-prefixed payload: `kind(1) || scheme(2 LE) ||
/// payload_len(8 LE) || payload || tx_hash(32) || domain(4 LE)`.
#[must_use]
pub fn envelope_bytes(envelope: &Envelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + 8 + envelope.payload.len() + 32 + 4);
    out.push(envelope.kind.tag());
    out.extend_from_slice(&envelope.scheme.to_le_bytes());
    out.extend_from_slice(&(envelope.payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&envelope.payload);
    out.extend_from_slice(&envelope.tx_hash);
    out.extend_from_slice(&envelope.domain.to_le_bytes());
    out
}

/// `object_id = H("BDLM_OBJECT_V1" || envelope bytes)`.
#[must_use]
pub fn object_id(envelope: &Envelope) -> Hash {
    h(TAG_OBJECT, &[&envelope_bytes(envelope)])
}

/// The Merkle root over `claim_digest`s, in block order.
///
/// Leaf: `H(ROOT_TAG || 0x00 || digest)`. Interior node:
/// `H(ROOT_TAG || 0x01 || left || right)`. An odd node at the end of a level is
/// promoted unchanged, **not** duplicated: promoting is the rule the directive
/// writes down, and it is the one that avoids the CVE-2012-2459 duplicate-leaf
/// shape, where a tree over `[a, b, c]` and a tree over `[a, b, c, c]` collide.
///
/// An empty list is refused: there is no empty root, because an empty root is
/// a value a prover can produce for free.
///
/// # Errors
///
/// [`AggError::Empty`] when `digests` is empty.
pub fn claims_root(digests: &[Hash]) -> Result<Hash, AggError> {
    if digests.is_empty() {
        return Err(AggError::Empty);
    }
    let mut level: Vec<Hash> = digests
        .iter()
        .map(|d| h(TAG_CLAIM_ROOT, &[&[0x00], d]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if let [left, right] = pair {
                next.push(h(TAG_CLAIM_ROOT, &[&[0x01], left, right]));
            } else if let [only] = pair {
                next.push(*only);
            }
        }
        level = next;
    }
    level.first().copied().ok_or(AggError::Empty)
}

/// The claims root of a slice of claims belonging to `domain`.
///
/// # Errors
///
/// Same as [`claims_root`], plus nothing else: this is a total function of the
/// slice.
pub fn claims_root_of(domain: DomainId, claims: &[Claim]) -> Result<Hash, AggError> {
    let digests: Vec<Hash> = claims
        .iter()
        .map(|claim| claim_digest(domain, claim))
        .collect();
    claims_root(&digests)
}

/// `tick_pi = H("BDLM_AGG_TICK_V1" || domain || claims_root || count ||
/// aggregator)`.
#[must_use]
pub fn tick_pi(domain: DomainId, segment: &Segment) -> Hash {
    h(
        TAG_TICK,
        &[
            &domain.to_le_bytes(),
            &segment.claims_root,
            &segment.count.to_le_bytes(),
            segment.aggregator.as_bytes(),
        ],
    )
}

/// `merge_pi = H("BDLM_AGG_MERGE_V1" || left_pi || right_pi)`.
#[must_use]
pub fn merge_pi(left: Hash, right: Hash) -> Hash {
    h(TAG_MERGE, &[&left, &right])
}

/// `frame_hash = H("BDLM_FRAME_V1" || master_pi || params_hash ||
/// H(proof))`.
///
/// The proof is hashed first so that a frame's hash is a fixed 96 bytes of
/// input no matter how large the proof is, and so a header can commit to a
/// proof it does not store.
#[must_use]
pub fn frame_hash(master_pi: Hash, params: &AggParams, proof: &[u8]) -> Hash {
    let proof_hash = h(TAG_FRAME, &[b"proof", proof]);
    h(TAG_FRAME, &[&master_pi, &params_hash(params), &proof_hash])
}

/// `fold_shape`: consume the postfix shape against the segments, left to right.
///
/// `0` pushes the next segment's `tick_pi`; `1` pops two values and pushes
/// their `merge_pi`. The shape is correct when every segment was consumed
/// exactly once and exactly one value is left.
///
/// This is the whole block rule in one function: rules 2 (counts), 3 (roots) and
/// 10 (frame hash) are separate checks, but rule 4 (the shape) is this, and
/// rule 5 (`proof` verifies against `master_pi`) is the backend verifying that
/// `master_pi` is the public input its proof commits to.
///
/// # Errors
///
/// [`AggError::BadShape`] for an operator other than `0`/`1`, a merge with
/// fewer than two operands, a tick with no segment left, unconsumed segments,
/// or a final stack that is not exactly one value. [`AggError::Empty`] when
/// the shape is empty.
pub fn fold_shape(domain: DomainId, segments: &[Segment], shape: &[u8]) -> Result<Hash, AggError> {
    if shape.is_empty() {
        return Err(AggError::Empty);
    }
    let mut stack: Vec<Hash> = Vec::with_capacity(shape.len());
    let mut next = 0usize;
    for op in shape {
        match op {
            0 => {
                let segment = segments.get(next).ok_or(AggError::BadShape)?;
                next += 1;
                stack.push(tick_pi(domain, segment));
            }
            1 => {
                let right = stack.pop().ok_or(AggError::BadShape)?;
                let left = stack.pop().ok_or(AggError::BadShape)?;
                stack.push(merge_pi(left, right));
            }
            _ => return Err(AggError::BadShape),
        }
    }
    if next != segments.len() || stack.len() != 1 {
        return Err(AggError::BadShape);
    }
    stack.pop().ok_or(AggError::BadShape)
}

/// The `master_pi` of a frame: the fold of its shape over its segments.
///
/// # Errors
///
/// Whatever [`fold_shape`] refuses with.
pub fn master_pi(domain: DomainId, frame: &ClaimFrame) -> Result<Hash, AggError> {
    fold_shape(domain, &frame.segments, &frame.shape)
}

/// The digest of the authority a `Sig` claim grants: `AUTH_OK` names the output
/// of a program account's authority program in Phase 4, and here it is the
/// value a program account's claim must carry as `output_hash`.
#[must_use]
pub fn auth_ok() -> Hash {
    h(TAG_AUTH_OK, &[])
}

/// The digest an adapter answers to in a finality claim: the adapter's identity
/// and the version of the evidence format it accepted.
#[must_use]
pub fn adapter_binding(adapter: &str, evidence_version: &str) -> Hash {
    h(
        TAG_ADAPTER,
        &[adapter.as_bytes(), evidence_version.as_bytes()],
    )
}

/// The digest of a finality claim over an opaque proof digest.
#[must_use]
pub fn finality_claim(adapter_binding: Hash, proof_digest: &Hash) -> Hash {
    h(TAG_FINALITY_CLAIM, &[&adapter_binding, proof_digest])
}

/// A helper for callers that hold an `Ext` and want its canonical bytes.
#[must_use]
pub fn ext_bytes(value: Ext) -> [u8; 32] {
    value.canonical_bytes()
}

/// The address of the all-zero key, for tests and for the "no aggregator" case.
#[must_use]
pub fn zero_address() -> Address {
    Address::zero()
}
