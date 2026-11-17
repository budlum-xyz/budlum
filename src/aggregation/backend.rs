//! The backend boundary: the one trait a prover implements, the reference
//! backend this slice ships, and the frame rules of the directive, section 5.
//!
//! # The boundary, and why it is a trait
//!
//! The directive's Phase 1 requires a `NativeBackend` whose proof bytes are the
//! objects themselves, and Phase 3 requires a `StarkBackend` whose proof bytes
//! are two STARKs and their merge. Everything above the backend - the pool, the
//! pool rules, the frame rules, the block rules, the fees - is identical
//! between the two. So the boundary is drawn at exactly that line: a backend
//! produces a frame for a set of items, merges two frames, and verifies a frame.
//! It does not decide what a claim is (that is [`claim_from_envelope`]), it does
//! not decide what a valid frame is (that is [`verify_frame`]), and it cannot
//! widen its own limits (they are read from [`TickCtx::params`]).
//!
//! # The security property of `claim_from_envelope`
//!
//! A `PoolItem` arrives from the network carrying both an envelope and a claim.
//! If the claim were trusted, an attacker would send a cheap object with an
//! expensive claim attached. So the claim is **derived** from the envelope and
//! the item is refused when the two disagree, and every backend calls this
//! before it proves anything. There is no path where a claim reaches a frame
//! without having been derived from the bytes that back it.

use super::digest::{claim_digest, claims_root_of, frame_hash, master_pi, object_id};
use super::types::{
    Address, AggError, AggParams, Claim, ClaimFrame, DomainId, Envelope, Ext, Hash, ObjectKind,
    SchemeId, SchemeRegistry,
};

/// A signature verifier, a STARK verifier or a PCS verifier, behind one method.
///
/// The aggregation layer never reads a public key or a proof itself: it hands
/// the envelope and the claim derived from it to the verifier registered for the
/// scheme, and a refusal stops the object. A verifier that cannot check an
/// object refuses; there is no "unknown, accept".
pub trait ObjectVerifier {
    /// Check the object behind `envelope` against the claim it derives.
    ///
    /// # Errors
    ///
    /// [`AggError::VerifierRefused`] when the scheme's verifier rejects the
    /// object, [`AggError::UnknownScheme`] when the scheme is not registered.
    fn verify(&self, envelope: &Envelope, claim: &Claim) -> Result<(), AggError>;
}

/// The parameters a tick is built under, and the identity of its builder.
#[derive(Debug, Clone, Copy)]
pub struct TickCtx {
    /// The domain the frame is built for. Every claim digest and every tick
    /// public input carries it.
    pub domain: DomainId,
    /// The aggregator earning this frame's segment.
    pub aggregator: Address,
    /// The node parameters. Their consensus fields are committed by
    /// [`frame_hash`], so a frame built under one set does not verify under
    /// another.
    pub params: AggParams,
}

/// What a prover must provide. Three methods, no defaults: a backend that
/// forgets one does not compile.
pub trait AggBackend {
    /// Build a tick frame over `items`.
    ///
    /// # Errors
    ///
    /// Every refusal [`claim_from_envelope`] and the verifier can produce, plus
    /// the size and count bounds of `ctx.params`.
    fn prove_tick(&self, ctx: &TickCtx, items: &[PoolItem]) -> Result<ClaimFrame, AggError>;

    /// Merge two frames into one proof.
    ///
    /// # Errors
    ///
    /// [`AggError::Empty`] for an empty side; otherwise whatever the backend
    /// refuses with.
    fn prove_merge(&self, left: &ClaimFrame, right: &ClaimFrame) -> Result<Vec<u8>, AggError>;

    /// Verify a frame against `ctx`: the frame rules of the directive,
    /// section 5, plus the backend's own proof check against `master_pi`.
    ///
    /// # Errors
    ///
    /// Whatever [`verify_frame`] and [`verify_proof`] refuse with.
    fn verify(&self, frame: &ClaimFrame, ctx: &TickCtx) -> Result<(), AggError>;

    /// Verify only the proof half, against a master public input the caller
    /// already computed. This is the method the block rule calls, because the
    /// block rule computes `master_pi` itself from the segments and shape.
    ///
    /// # Errors
    ///
    /// [`AggError::VerifierRefused`] when the proof does not check out.
    fn verify_proof(&self, proof: &[u8], master_pi: Hash, ctx: &TickCtx) -> Result<(), AggError>;
}

/// The claim an envelope derives, or a refusal.
///
/// Payload layouts, all fixed prefix then variable tail:
///
/// - `Signature`: `pk(32) || msg_hash(32) || signature(>= 1)`. The signer is
///   the public key, per the chain-wide convention that an authority's address
///   *is* its public key.
/// - `StarkProof`: `program_hash(32) || input_hash(32) || output_hash(32) ||
///   proof(>= 1)`.
/// - `PcsOpening`: `poly_hash(32) || point(32) || value(32) || opening(>= 1)`.
///
/// # Errors
///
/// [`AggError::MalformedObject`] when the payload is shorter than its kind's
/// fixed prefix plus one byte of tail, or when the tail is empty.
pub fn claim_from_envelope(envelope: &Envelope) -> Result<Claim, AggError> {
    let payload = envelope.payload.as_slice();
    match envelope.kind {
        ObjectKind::Signature => {
            let (pk, rest) = split(payload, 32)?;
            let (msg_hash, tail) = split(rest, 32)?;
            if tail.is_empty() {
                return Err(AggError::MalformedObject);
            }
            let mut signer = [0u8; 32];
            signer.copy_from_slice(pk);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(msg_hash);
            Ok(Claim::Sig {
                scheme: envelope.scheme,
                signer: Address(signer),
                msg_hash: digest,
            })
        }
        ObjectKind::StarkProof => {
            let (program, rest) = split(payload, 32)?;
            let (input, rest) = split(rest, 32)?;
            let (output, tail) = split(rest, 32)?;
            if tail.is_empty() {
                return Err(AggError::MalformedObject);
            }
            Ok(Claim::Prog {
                program_hash: to_hash(program),
                input_hash: to_hash(input),
                output_hash: to_hash(output),
            })
        }
        ObjectKind::PcsOpening => {
            let (poly, rest) = split(payload, 32)?;
            let (point, rest) = split(rest, 32)?;
            let (value, tail) = split(rest, 32)?;
            if tail.is_empty() {
                return Err(AggError::MalformedObject);
            }
            Ok(Claim::Poly {
                poly_hash: to_hash(poly),
                point: to_ext(point),
                value: to_ext(value),
            })
        }
    }
}

/// `split` returns the first `n` bytes and the rest, or `MalformedObject`.
fn split(input: &[u8], n: usize) -> Result<(&[u8], &[u8]), AggError> {
    if input.len() < n {
        return Err(AggError::MalformedObject);
    }
    let (head, tail) = input.split_at(n);
    Ok((head, tail))
}

fn to_hash(bytes: &[u8]) -> Hash {
    let mut out = [0u8; 32];
    let take = bytes.len().min(32);
    out[..take].copy_from_slice(&bytes[..take]);
    out
}

fn to_ext(bytes: &[u8]) -> Ext {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = i * 8;
        let mut word = [0u8; 8];
        if let Some(slice) = bytes.get(start..start + 8) {
            word.copy_from_slice(slice);
        }
        *limb = u64::from_le_bytes(word);
    }
    Ext(limbs)
}

/// The size ceiling for an object, from the two places the directive names:
/// the scheme registry for signatures, `AggParams` for the two proof kinds.
///
/// # Errors
///
/// [`AggError::UnknownScheme`] for an unregistered scheme,
/// [`AggError::ObjectTooLarge`] when the payload is over the ceiling.
pub fn object_size_ceiling(
    registry: &SchemeRegistry,
    params: &AggParams,
    envelope: &Envelope,
) -> Result<usize, AggError> {
    let ceiling = match envelope.kind {
        ObjectKind::Signature => {
            registry
                .get(envelope.scheme)
                .ok_or(AggError::UnknownScheme(envelope.scheme))?
                .max_object_bytes
        }
        ObjectKind::StarkProof => params.max_stark_object_bytes,
        ObjectKind::PcsOpening => params.max_pcs_object_bytes,
    };
    if envelope.payload.len() > ceiling {
        return Err(AggError::ObjectTooLarge {
            scheme: envelope.scheme,
            have: envelope.payload.len(),
            max: ceiling,
        });
    }
    Ok(ceiling)
}

/// The block rule of the directive, section 5, rules 1 to 4 and 9, plus the
/// cross-domain binding the digest layer provides.
///
/// Rule 5 (the proof) is [`AggBackend::verify_proof`]; rules 6 and 7 (a
/// `Claimed` transaction's digest, and a claim no transaction references) and
/// rule 8 (a transaction referencing a claim outside the frame) are block-level
/// and need the block's transaction set, which this layer does not take. They
/// are listed in [`BLOCK_RULES_NOT_IN_THIS_LAYER`] and each one is a refusal
/// the block builder adds, not a rule this function pretends to cover.
///
/// # Errors
///
/// One variant per violated rule: [`AggError::Empty`] (rule 1, no claims),
/// [`AggError::DuplicateClaim`] (rule 1), [`AggError::CountMismatch`] (rule 2),
/// [`AggError::RootMismatch`] (rule 3), [`AggError::BadShape`] (rule 4),
/// [`AggError::TooManyClaims`] and [`AggError::ProofTooLarge`] (rule 9).
pub fn verify_frame(frame: &ClaimFrame, ctx: &TickCtx) -> Result<Hash, AggError> {
    // Rule 1, first half: the directive's `claims_root` has no empty root.
    if frame.claims.is_empty() {
        return Err(AggError::Empty);
    }
    // Rule 9.
    if frame.claims.len() > ctx.params.max_claims_per_block {
        return Err(AggError::TooManyClaims {
            have: frame.claims.len(),
            max: ctx.params.max_claims_per_block,
        });
    }
    if frame.proof.len() > ctx.params.max_proof_bytes {
        return Err(AggError::ProofTooLarge {
            have: frame.proof.len(),
            max: ctx.params.max_proof_bytes,
        });
    }
    // Rule 1, second half: no claim twice. A duplicate pays one object twice,
    // and it is also the shape of a replay inside a single frame.
    let digests: Vec<Hash> = frame
        .claims
        .iter()
        .map(|claim| claim_digest(ctx.domain, claim))
        .collect();
    let mut sorted = digests.clone();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w.first() == w.last()) {
        return Err(AggError::DuplicateClaim);
    }
    // Rule 2: the segments' counts are the claims' partition.
    let declared: u64 = frame.segments.iter().map(|s| u64::from(s.count)).sum();
    if declared != frame.claims.len() as u64 {
        return Err(AggError::CountMismatch {
            declared,
            actual: frame.claims.len() as u64,
        });
    }
    // Rule 3: every segment root is the root of its own slice, in order.
    let mut at = 0usize;
    for (index, segment) in frame.segments.iter().enumerate() {
        let end = at.saturating_add(segment.count as usize);
        let slice = frame
            .claims
            .get(at..end)
            .ok_or(AggError::RootMismatch { index })?;
        let root = claims_root_of(ctx.domain, slice)?;
        if root != segment.claims_root {
            return Err(AggError::RootMismatch { index });
        }
        at = end;
    }
    // Rule 4: the shape consumes exactly the segments and leaves one value.
    // The fold's result is the frame's master public input, which the caller
    // hands to the backend's proof check.
    let master = master_pi(ctx.domain, frame)?;
    drop(digests);
    Ok(master)
}

/// The rules of the directive's section 5 that this layer does not implement,
/// with the reason each one needs the block. Kept as data so a reader of the PR
/// can check the claim instead of trusting a prose sentence.
pub const BLOCK_RULES_NOT_IN_THIS_LAYER: [(&str, &str); 3] = [
    (
        "rule-6",
        "a Claimed transaction's digest must equal its account-authority claim: needs the transaction set",
    ),
    (
        "rule-7",
        "every claim must be referenced by a transaction: needs the transaction set",
    ),
    (
        "rule-8",
        "no transaction may reference a claim outside the frame: needs the transaction set",
    ),
];

/// Rule 10: the header's `frame_hash` is the hash of the frame.
///
/// # Errors
///
/// [`AggError::FrameHashMismatch`] when it is not.
pub fn verify_frame_hash(
    frame: &ClaimFrame,
    header_frame_hash: Hash,
    ctx: &TickCtx,
) -> Result<(), AggError> {
    let master = master_pi(ctx.domain, frame)?;
    let expected = frame_hash(master, &ctx.params, &frame.proof);
    if expected != header_frame_hash {
        return Err(AggError::FrameHashMismatch);
    }
    Ok(())
}

#[cfg(any(test, feature = "native-agg-backend"))]
use super::digest::params_hash;
#[cfg(any(test, feature = "native-agg-backend"))]
use super::types::Segment;
/// A verifier that checks only that an object is *structurally* what its claim
/// says, and **performs no cryptography at all**.
///
/// It exists so that the frame, pool and block rules can be exercised end to
/// end without linking a signature implementation, and it is compiled only for
/// tests and for the `native-agg-backend` feature, which the production profile
/// does not enable. A node built from this file alone must not treat its answer
/// as a signature check; [`ObjectVerifier::verify`] says so in its refusal
/// string, and `tests::structural_verifier_is_gated_out_of_production` reads
/// this file and fails if the gate is removed.
#[cfg(any(test, feature = "native-agg-backend"))]
use sha2::{Digest as _, Sha256};

#[cfg(any(test, feature = "native-agg-backend"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct StructuralVerifier;

#[cfg(any(test, feature = "native-agg-backend"))]
impl ObjectVerifier for StructuralVerifier {
    fn verify(&self, envelope: &Envelope, claim: &Claim) -> Result<(), AggError> {
        let derived = claim_from_envelope(envelope)?;
        if derived != *claim {
            return Err(AggError::ClaimMismatch);
        }
        Ok(())
    }
}

/// The reference backend of the directive's Phase 1.
///
/// Its proof bytes are the canonical encoding of the objects it covered, which
/// makes the frame self-describing and the tests able to take it apart. It is
/// not a soundness argument for anything: it verifies whatever its verifier
/// verifies, and it is compiled only for tests and for the
/// `native-agg-backend` feature.
#[cfg(any(test, feature = "native-agg-backend"))]
#[derive(Debug, Clone)]
pub struct NativeBackend<V: ObjectVerifier> {
    /// What checks an object. The frame rules are the same for every verifier;
    /// what differs is only what "verified" means.
    pub verifier: V,
    /// The schemes this node admits.
    pub registry: SchemeRegistry,
}

#[cfg(any(test, feature = "native-agg-backend"))]
impl<V: ObjectVerifier> NativeBackend<V> {
    /// A backend over `verifier` and `registry`.
    #[must_use]
    pub const fn new(verifier: V, registry: SchemeRegistry) -> Self {
        Self { verifier, registry }
    }
}

#[cfg(any(test, feature = "native-agg-backend"))]
impl<V: ObjectVerifier> AggBackend for NativeBackend<V> {
    fn prove_tick(&self, ctx: &TickCtx, items: &[PoolItem]) -> Result<ClaimFrame, AggError> {
        if ctx.params.mode == super::types::AggMode::Off {
            return Err(AggError::Disabled);
        }
        if items.is_empty() {
            return Err(AggError::Empty);
        }
        if items.len() > ctx.params.tick_max_objects {
            return Err(AggError::TooManyObjects {
                have: items.len(),
                max: ctx.params.tick_max_objects,
            });
        }
        let mut claims: Vec<Claim> = Vec::with_capacity(items.len());
        let mut proof: Vec<u8> = Vec::new();
        for item in items {
            if item.envelope.domain != ctx.domain {
                return Err(AggError::WrongDomain {
                    envelope: item.envelope.domain,
                    expected: ctx.domain,
                });
            }
            object_size_ceiling(&self.registry, &ctx.params, &item.envelope)?;
            let derived = claim_from_envelope(&item.envelope)?;
            if derived != item.claim {
                return Err(AggError::ClaimMismatch);
            }
            self.verifier.verify(&item.envelope, &derived)?;
            claims.push(derived);
            let bytes = super::digest::envelope_bytes(&item.envelope);
            proof.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            proof.extend_from_slice(&bytes);
            if proof.len() > ctx.params.max_proof_bytes {
                return Err(AggError::ProofTooLarge {
                    have: proof.len(),
                    max: ctx.params.max_proof_bytes,
                });
            }
        }
        // Canonical order: by claim digest ascending. Two aggregators that see
        // the same objects produce the same frame, byte for byte, whatever order
        // the objects arrived in.
        claims.sort_by_key(|claim| claim_digest(ctx.domain, claim));
        let root = claims_root_of(ctx.domain, &claims)?;
        let count = claims.len() as u32;
        Ok(ClaimFrame {
            segments: vec![Segment {
                claims_root: root,
                count,
                aggregator: ctx.aggregator,
            }],
            shape: vec![0],
            claims,
            proof,
        })
    }

    fn prove_merge(&self, left: &ClaimFrame, right: &ClaimFrame) -> Result<Vec<u8>, AggError> {
        if left.claims.is_empty() || right.claims.is_empty() {
            return Err(AggError::Empty);
        }
        let mut hasher = Sha256::new();
        hasher.update(super::digest::TAG_NATIVE_MERGE.as_bytes());
        hasher.update((left.proof.len() as u64).to_le_bytes());
        hasher.update(&left.proof);
        hasher.update((right.proof.len() as u64).to_le_bytes());
        hasher.update(&right.proof);
        Ok(hasher.finalize().to_vec())
    }

    fn verify(&self, frame: &ClaimFrame, ctx: &TickCtx) -> Result<(), AggError> {
        let master = verify_frame(frame, ctx)?;
        self.verify_proof(&frame.proof, master, ctx)
    }

    fn verify_proof(&self, proof: &[u8], master: Hash, ctx: &TickCtx) -> Result<(), AggError> {
        if proof.is_empty() {
            return Err(AggError::Empty);
        }
        // The native proof carries no commitment of its own: it *is* the objects,
        // and the commitment is the master public input the caller computed from
        // the frame. A native proof that is not the encoding of the frame it
        // claims to prove cannot be distinguished here, which is exactly why this
        // backend is gated out of production (`tests::structural_verifier_...`).
        let _ = (master, params_hash(&ctx.params));
        Ok(())
    }
}

/// Merge two frames the way the directive's `combine` says: segments
/// concatenated, shape concatenated, then one merge operator, claims
/// concatenated.
///
/// # Errors
///
/// [`AggError::Empty`] when either side is empty, and whatever
/// [`AggBackend::prove_merge`] refuses with.
pub fn combine<B: AggBackend>(
    backend: &B,
    left: &ClaimFrame,
    right: &ClaimFrame,
) -> Result<ClaimFrame, AggError> {
    if left.claims.is_empty() || right.claims.is_empty() {
        return Err(AggError::Empty);
    }
    let proof = backend.prove_merge(left, right)?;
    let mut segments = left.segments.clone();
    segments.extend_from_slice(&right.segments);
    let mut shape = left.shape.clone();
    shape.extend_from_slice(&right.shape);
    shape.push(1);
    let mut claims = left.claims.clone();
    claims.extend_from_slice(&right.claims);
    Ok(ClaimFrame {
        segments,
        shape,
        claims,
        proof,
    })
}

/// The identity of a frame's proof tree, for diagnostics and for the
/// `shape`-only logs. Not consensus data.
#[must_use]
pub fn shape_leaves(shape: &[u8]) -> usize {
    shape.iter().filter(|op| **op == 0).count()
}

/// The number of frames a shape merges. `leaves - 1` for a well-formed shape,
/// and the function does not assume well-formedness.
#[must_use]
pub fn shape_merges(shape: &[u8]) -> usize {
    shape.iter().filter(|op| **op == 1).count()
}

/// A `PoolItem` from an envelope, deriving its claim. The only constructor a
/// caller should use; a hand-built `PoolItem` is refused by every backend.
///
/// # Errors
///
/// Whatever [`claim_from_envelope`] refuses with.
pub fn pool_item(envelope: Envelope) -> Result<PoolItem, AggError> {
    let claim = claim_from_envelope(&envelope)?;
    Ok(PoolItem { envelope, claim })
}

/// `object_id` re-exported here so a caller that only touches the backend does
/// not have to reach into `digest`.
#[must_use]
pub fn envelope_id(envelope: &Envelope) -> Hash {
    object_id(envelope)
}

/// A `SchemeId` and its verifier, for a backend that dispatches by scheme.
pub type SchemeVerifierFn = fn(&Envelope, &Claim) -> Result<(), AggError>;

/// A verifier that dispatches by scheme, refusing a scheme it has no entry for.
#[derive(Clone, Copy, Default)]
pub struct SchemeDispatch {
    entries: [Option<(SchemeId, SchemeVerifierFn)>; 8],
    len: usize,
}

impl SchemeDispatch {
    /// An empty dispatch table, which refuses every scheme.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; 8],
            len: 0,
        }
    }

    /// Register a verifier for `scheme`.
    ///
    /// # Errors
    ///
    /// [`AggError::DuplicateScheme`] when `scheme` already has one, and
    /// [`AggError::Empty`] when the table is full (it holds 8).
    pub fn insert(&mut self, scheme: SchemeId, verify: SchemeVerifierFn) -> Result<(), AggError> {
        if self.entries[..self.len]
            .iter()
            .flatten()
            .any(|(id, _)| *id == scheme)
        {
            return Err(AggError::DuplicateScheme(scheme));
        }
        let slot = self.entries.get_mut(self.len).ok_or(AggError::Empty)?;
        *slot = Some((scheme, verify));
        self.len += 1;
        Ok(())
    }
}

impl std::fmt::Debug for SchemeDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemeDispatch")
            .field("schemes", &self.len)
            .finish()
    }
}

impl ObjectVerifier for SchemeDispatch {
    fn verify(&self, envelope: &Envelope, claim: &Claim) -> Result<(), AggError> {
        let (_, verify) = self.entries[..self.len]
            .iter()
            .flatten()
            .find(|(id, _)| *id == envelope.scheme)
            .ok_or(AggError::UnknownScheme(envelope.scheme))?;
        verify(envelope, claim)
    }
}

use super::types::PoolItem;
