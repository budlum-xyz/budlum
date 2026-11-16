//! Claim frames: a list of claims and the one proof that covers them.
//!
//! Every proof that travels the network is a [`ClaimFrame`]: a tick proof, a
//! merged proof and the master proof of a block have the same form. The frame
//! of a block is the root of the merge tree.
//!
//! This file holds what can be decided from the frame alone: its canonical
//! bytes, the public input its proof must verify against and the structure
//! rules 1, 2, 3, 4 and 9 of the block rules. Proof verification (rule 5)
//! takes the [`FrameFacts`] this file produces; rules 6, 7, 8 and 10 need the
//! transactions and the header and live with the block.
//!
//! WIRING: [`tick_pi`], [`merge_pi`] and [`fold_shape`] are the public
//! inputs of the `AggTick` and `AggMerge` programs; the STARK backend of
//! Phases 2 and 3 calls them and chooses its verifying key by
//! [`AggProgram`]. [`Segment`] and [`FrameFacts`] reach the node through the
//! frame and its structure check.

use std::collections::BTreeSet;

use super::claim::{Claim, ClaimError};
use super::hash::{h, TAG_AGG_MERGE, TAG_AGG_TICK, TAG_FRAME};
use super::merkle::claims_root;
use super::params::AggParams;
use crate::core::address::Address;
use crate::domain::types::{DomainId, Hash32};

/// Shape op: push the public input of the next segment (a tick proof).
pub const SHAPE_TICK: u8 = 0;
/// Shape op: pop two public inputs and push their merge.
pub const SHAPE_MERGE: u8 = 1;

/// Encoded bytes of a segment: root, count and aggregator.
const SEGMENT_BYTES: usize = 32 + 4 + 32;
/// No encoded claim is shorter than this.
const MIN_CLAIM_BYTES: usize = 64;

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The shape is not one full merge tree over the segments (rule 4).
    BadShape,
    /// A claim appears twice (rule 1).
    DuplicateClaim,
    /// The segment counts do not add up to the number of claims (rule 2).
    CountMismatch,
    /// A segment covers no claim. An empty claim list has no root.
    EmptySegment,
    /// The root of the segment at this index is not the root of its claims
    /// (rule 3).
    ClaimsRootMismatch(usize),
    /// More claims than the limit (rule 9).
    TooManyClaims(usize),
    /// More proof bytes than the limit (rule 9).
    ProofTooLarge(usize),
    /// The bytes end before the frame does.
    Truncated,
    /// Bytes follow the frame.
    TrailingBytes,
    /// A claim inside the frame is malformed.
    Claim(ClaimError),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadShape => write!(f, "the shape is not one merge tree over the segments"),
            Self::DuplicateClaim => write!(f, "a claim appears twice"),
            Self::CountMismatch => write!(f, "segment counts do not add up to the claim count"),
            Self::EmptySegment => write!(f, "a segment covers no claim"),
            Self::ClaimsRootMismatch(at) => write!(f, "claims root of segment {at} does not match"),
            Self::TooManyClaims(n) => write!(f, "{n} claims are over the limit"),
            Self::ProofTooLarge(n) => write!(f, "{n} proof bytes are over the limit"),
            Self::Truncated => write!(f, "frame bytes are truncated"),
            Self::TrailingBytes => write!(f, "bytes follow the frame"),
            Self::Claim(e) => write!(f, "malformed claim: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<ClaimError> for FrameError {
    fn from(e: ClaimError) -> Self {
        Self::Claim(e)
    }
}

/// The claims one tick proof covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Root of the claim tree over the claims of this segment.
    pub claims_root: Hash32,
    /// Number of claims in this segment.
    pub count: u32,
    /// The aggregator that proved the tick and earns its share.
    pub aggregator: Address,
}

/// `tick_pi = H("BDLM_AGG_TICK_V1" || domain || claims_root || count || aggregator)`.
#[must_use]
pub fn tick_pi(domain: DomainId, segment: &Segment) -> Hash32 {
    h(&[
        TAG_AGG_TICK,
        &domain.to_be_bytes(),
        &segment.claims_root,
        &segment.count.to_be_bytes(),
        segment.aggregator.as_bytes(),
    ])
}

/// `merge_pi = H("BDLM_AGG_MERGE_V1" || left_pi || right_pi)`.
#[must_use]
pub fn merge_pi(left: &Hash32, right: &Hash32) -> Hash32 {
    h(&[TAG_AGG_MERGE, left, right])
}

/// `frame_hash = H("BDLM_FRAME_V1" || master_pi || H(proof))`.
#[must_use]
pub fn frame_hash(master_pi: &Hash32, proof: &[u8]) -> Hash32 {
    h(&[TAG_FRAME, master_pi, &h(&[proof])])
}

/// The public input of the proof of a frame: the fold of the postfix `shape`
/// over the segments.
///
/// # Errors
///
/// [`FrameError::BadShape`] when the shape is not exactly one merge tree that
/// uses every segment once, in order.
pub fn fold_shape(
    domain: DomainId,
    segments: &[Segment],
    shape: &[u8],
) -> Result<Hash32, FrameError> {
    let mut stack: Vec<Hash32> = Vec::new();
    let mut unused = segments.iter();
    for op in shape {
        match *op {
            SHAPE_TICK => {
                let segment = unused.next().ok_or(FrameError::BadShape)?;
                stack.push(tick_pi(domain, segment));
            }
            SHAPE_MERGE => {
                let right = stack.pop().ok_or(FrameError::BadShape)?;
                let left = stack.pop().ok_or(FrameError::BadShape)?;
                stack.push(merge_pi(&left, &right));
            }
            _ => return Err(FrameError::BadShape),
        }
    }
    if unused.next().is_some() {
        return Err(FrameError::BadShape);
    }
    match stack.as_slice() {
        [master_pi] => Ok(*master_pi),
        _ => Err(FrameError::BadShape),
    }
}

/// The program whose proof a frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggProgram {
    /// One segment: the proof is a tick proof.
    Tick,
    /// Several segments: the proof is a merge proof.
    Merge,
}

/// The consensus limits of a frame (rule 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    /// Most claims.
    pub max_claims: usize,
    /// Most proof bytes.
    pub max_proof_bytes: usize,
}

impl From<&AggParams> for FrameLimits {
    fn from(params: &AggParams) -> Self {
        Self {
            max_claims: params.max_claims_per_block,
            max_proof_bytes: params.max_proof_bytes,
        }
    }
}

/// What a structurally valid frame commits to. The proof of the frame is
/// checked against `master_pi` under `program`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameFacts {
    /// The public input the proof must verify against.
    pub master_pi: Hash32,
    /// The digest of every claim, in frame order.
    pub claim_digests: Vec<Hash32>,
    /// Which program the proof belongs to.
    pub program: AggProgram,
}

/// A list of claims with the proof that covers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimFrame {
    /// The segments, one per tick proof under this frame.
    pub segments: Vec<Segment>,
    /// The merge tree in postfix order: [`SHAPE_TICK`] and [`SHAPE_MERGE`].
    pub shape: Vec<u8>,
    /// The claims of every segment, in segment order.
    pub claims: Vec<Claim>,
    /// A tick proof, a merged proof or the master proof.
    pub proof: Vec<u8>,
}

fn read<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], FrameError> {
    let (head, tail) = rest.split_first_chunk::<N>().ok_or(FrameError::Truncated)?;
    *rest = tail;
    Ok(*head)
}

fn read_len(rest: &mut &[u8]) -> Result<usize, FrameError> {
    Ok(usize::try_from(u32::from_be_bytes(read(rest)?)).unwrap_or(usize::MAX))
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    // No list of a frame reaches 2^32 entries: the consensus limits are far below.
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
}

impl ClaimFrame {
    /// The frame of one tick: `claims` sorted by digest, one segment owned by
    /// `aggregator`, and the tick proof.
    ///
    /// # Errors
    ///
    /// [`FrameError::EmptySegment`] without claims,
    /// [`FrameError::DuplicateClaim`] when a claim repeats and
    /// [`FrameError::TooManyClaims`] when the count does not fit the segment.
    pub fn tick(
        domain: DomainId,
        aggregator: Address,
        claims: Vec<Claim>,
        proof: Vec<u8>,
    ) -> Result<Self, FrameError> {
        let mut keyed: Vec<(Hash32, Claim)> = claims
            .into_iter()
            .map(|claim| (claim.digest(domain), claim))
            .collect();
        keyed.sort_unstable_by_key(|(digest, _)| *digest);
        if keyed.windows(2).any(|pair| match pair {
            [a, b] => a.0 == b.0,
            _ => false,
        }) {
            return Err(FrameError::DuplicateClaim);
        }
        let digests: Vec<Hash32> = keyed.iter().map(|(digest, _)| *digest).collect();
        let root = claims_root(&digests).map_err(|_| FrameError::EmptySegment)?;
        let count =
            u32::try_from(keyed.len()).map_err(|_| FrameError::TooManyClaims(keyed.len()))?;
        Ok(Self {
            segments: vec![Segment {
                claims_root: root,
                count,
                aggregator,
            }],
            shape: vec![SHAPE_TICK],
            claims: keyed.into_iter().map(|(_, claim)| claim).collect(),
            proof,
        })
    }

    /// The merge of two frames with disjoint claims: the segments, the claims
    /// and the shapes of `left` then `right`, one merge op, and the merge
    /// proof.
    ///
    /// Both frames belong to one domain, so two claims are the same claim
    /// exactly when their canonical bytes are equal. The two frames are not
    /// checked here; the caller merges frames it has verified.
    ///
    /// # Errors
    ///
    /// [`FrameError::DuplicateClaim`] when the frames share a claim.
    pub fn combine(left: &Self, right: &Self, proof: Vec<u8>) -> Result<Self, FrameError> {
        if !left.is_disjoint(right) {
            return Err(FrameError::DuplicateClaim);
        }
        let mut shape = Vec::with_capacity(
            left.shape
                .len()
                .saturating_add(right.shape.len())
                .saturating_add(1),
        );
        shape.extend_from_slice(&left.shape);
        shape.extend_from_slice(&right.shape);
        shape.push(SHAPE_MERGE);
        Ok(Self {
            segments: left
                .segments
                .iter()
                .chain(&right.segments)
                .cloned()
                .collect(),
            shape,
            claims: left.claims.iter().chain(&right.claims).cloned().collect(),
            proof,
        })
    }

    /// Whether the two frames of one domain share no claim and neither
    /// repeats one.
    #[must_use]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        let mut seen = BTreeSet::new();
        self.claims
            .iter()
            .chain(&other.claims)
            .all(|claim| seen.insert(claim.encode()))
    }

    /// Check everything the frame alone decides (block rules 1, 2, 3, 4 and
    /// 9) and return what its proof must verify against.
    ///
    /// # Errors
    ///
    /// The [`FrameError`] of the first rule that fails.
    pub fn check_structure(
        &self,
        domain: DomainId,
        limits: &FrameLimits,
    ) -> Result<FrameFacts, FrameError> {
        // Rule 9 first: nothing below runs on an oversized frame.
        if self.claims.len() > limits.max_claims {
            return Err(FrameError::TooManyClaims(self.claims.len()));
        }
        if self.proof.len() > limits.max_proof_bytes {
            return Err(FrameError::ProofTooLarge(self.proof.len()));
        }
        // Rule 2.
        let mut total: usize = 0;
        for segment in &self.segments {
            if segment.count == 0 {
                return Err(FrameError::EmptySegment);
            }
            let count = usize::try_from(segment.count).map_err(|_| FrameError::CountMismatch)?;
            total = total.checked_add(count).ok_or(FrameError::CountMismatch)?;
        }
        if total != self.claims.len() {
            return Err(FrameError::CountMismatch);
        }
        // Rule 1.
        let claim_digests: Vec<Hash32> = self
            .claims
            .iter()
            .map(|claim| claim.digest(domain))
            .collect();
        let mut seen = BTreeSet::new();
        if !claim_digests.iter().all(|digest| seen.insert(*digest)) {
            return Err(FrameError::DuplicateClaim);
        }
        // Rule 3.
        let mut rest = claim_digests.as_slice();
        for (at, segment) in self.segments.iter().enumerate() {
            let count = usize::try_from(segment.count).map_err(|_| FrameError::CountMismatch)?;
            let (own, tail) = rest
                .split_at_checked(count)
                .ok_or(FrameError::CountMismatch)?;
            rest = tail;
            if claims_root(own) != Ok(segment.claims_root) {
                return Err(FrameError::ClaimsRootMismatch(at));
            }
        }
        // Rule 4.
        let master_pi = fold_shape(domain, &self.segments, &self.shape)?;
        let program = if self.segments.len() == 1 {
            AggProgram::Tick
        } else {
            AggProgram::Merge
        };
        Ok(FrameFacts {
            master_pi,
            claim_digests,
            program,
        })
    }

    /// The frame hash a block header carries (rule 10).
    ///
    /// # Errors
    ///
    /// [`FrameError::BadShape`] when the shape does not fold.
    pub fn hash(&self, domain: DomainId) -> Result<Hash32, FrameError> {
        let master_pi = fold_shape(domain, &self.segments, &self.shape)?;
        Ok(frame_hash(&master_pi, &self.proof))
    }

    /// The canonical encoding: the four lengths (claims, segments, shape,
    /// proof), then the segments, the shape, the claims and the proof.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_len(&mut out, self.claims.len());
        write_len(&mut out, self.segments.len());
        write_len(&mut out, self.shape.len());
        write_len(&mut out, self.proof.len());
        for segment in &self.segments {
            out.extend_from_slice(&segment.claims_root);
            out.extend_from_slice(&segment.count.to_be_bytes());
            out.extend_from_slice(segment.aggregator.as_bytes());
        }
        out.extend_from_slice(&self.shape);
        for claim in &self.claims {
            claim.write(&mut out);
        }
        out.extend_from_slice(&self.proof);
        out
    }

    /// Decode a frame that fills `bytes` exactly. Every length is checked
    /// against `limits` before anything is read for it, so a hostile header
    /// cannot make the node allocate. A frame has at most one segment per
    /// claim and a merge tree over `n` segments has `2n - 1` ops, which bounds
    /// the other two lists.
    ///
    /// Decoding checks the wire form only; [`Self::check_structure`] decides
    /// whether the frame is valid.
    ///
    /// # Errors
    ///
    /// [`FrameError`] when the bytes are malformed or over a limit.
    pub fn decode(bytes: &[u8], limits: &FrameLimits) -> Result<Self, FrameError> {
        let mut rest = bytes;
        let claim_count = read_len(&mut rest)?;
        if claim_count > limits.max_claims {
            return Err(FrameError::TooManyClaims(claim_count));
        }
        let segment_count = read_len(&mut rest)?;
        if segment_count > claim_count {
            return Err(FrameError::EmptySegment);
        }
        let shape_len = read_len(&mut rest)?;
        if shape_len > segment_count.saturating_mul(2) {
            return Err(FrameError::BadShape);
        }
        let proof_len = read_len(&mut rest)?;
        if proof_len > limits.max_proof_bytes {
            return Err(FrameError::ProofTooLarge(proof_len));
        }
        // Capacity follows the bytes that are really there, not the header.
        let mut segments = Vec::with_capacity(segment_count.min(rest.len() / SEGMENT_BYTES));
        for _ in 0..segment_count {
            segments.push(Segment {
                claims_root: read(&mut rest)?,
                count: u32::from_be_bytes(read(&mut rest)?),
                aggregator: Address::from(read::<32>(&mut rest)?),
            });
        }
        let (shape, tail) = rest
            .split_at_checked(shape_len)
            .ok_or(FrameError::Truncated)?;
        rest = tail;
        let mut claims = Vec::with_capacity(claim_count.min(rest.len() / MIN_CLAIM_BYTES));
        for _ in 0..claim_count {
            let (claim, taken) = Claim::decode(rest)?;
            rest = rest.get(taken..).ok_or(FrameError::Truncated)?;
            claims.push(claim);
        }
        match rest.len().cmp(&proof_len) {
            std::cmp::Ordering::Less => return Err(FrameError::Truncated),
            std::cmp::Ordering::Greater => return Err(FrameError::TrailingBytes),
            std::cmp::Ordering::Equal => {}
        }
        Ok(Self {
            segments,
            shape: shape.to_vec(),
            claims,
            proof: rest.to_vec(),
        })
    }
}
