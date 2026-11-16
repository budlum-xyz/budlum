//! The aggregator: it admits objects, proves a tick of them, merges the
//! frames it knows and hands the block producer the frame of a block.
//!
//! A node reaches the aggregator through [`super::node::AggNode`], which
//! adds the transactions the claims stand for: the `agg/object` topic feeds
//! [`Aggregator::on_object`], `agg/frame` feeds [`Aggregator::on_frame`],
//! the tick timer drives [`Aggregator::on_tick`], the block producer asks
//! [`Aggregator::block_frame`] and a committed block reports through
//! [`Aggregator::on_final`].

use std::collections::{BTreeMap, BTreeSet};

use super::backend::{AggBackend, AggError, TickCtx};
use super::envelope::Envelope;
use super::frame::{ClaimFrame, FrameError, FrameLimits};
use super::params::AggParams;
use super::pool::{Admission, ObjectPool, PoolItem, Rejection, TxLookup};
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::Hash32;

/// Frames an aggregator keeps. Past this the frame with the fewest claims is
/// dropped.
const MAX_FRAMES: usize = 1024;

/// What a tick produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TickOutcome {
    /// The frames to publish: the tick frame, then each merged frame.
    pub publish: Vec<ClaimFrame>,
    /// Why the tick was skipped, when proving failed.
    pub error: Option<AggError>,
}

/// An aggregator of one domain.
#[derive(Debug)]
pub struct Aggregator<B> {
    backend: B,
    ctx: TickCtx,
    params: AggParams,
    pool: ObjectPool,
    /// Verified frames, by frame hash.
    frames: BTreeMap<Hash32, ClaimFrame>,
}

impl<B: AggBackend> Aggregator<B> {
    /// An aggregator that proves with `backend` for the domain and the
    /// address of `ctx`.
    #[must_use]
    pub const fn new(backend: B, ctx: TickCtx, params: AggParams) -> Self {
        Self {
            backend,
            ctx,
            params,
            pool: ObjectPool::new(params, ctx.domain),
            frames: BTreeMap::new(),
        }
    }

    /// The object pool.
    #[must_use]
    pub const fn pool(&self) -> &ObjectPool {
        &self.pool
    }

    /// Verified frames the aggregator holds.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// An object arrived on `agg/object`.
    ///
    /// # Errors
    ///
    /// The [`Rejection`] of the admission rule the object broke.
    pub fn on_object(
        &mut self,
        envelope: Envelope,
        txs: &impl TxLookup,
        registry: &SchemeStatusRegistry,
    ) -> Result<Admission, Rejection> {
        self.pool.admit(envelope, txs, registry)
    }

    /// A frame arrived on `agg/frame`. It is verified with the backend; an
    /// invalid frame is dropped. Returns whether the frame is new.
    ///
    /// # Errors
    ///
    /// [`AggError`] when the frame is not valid.
    pub fn on_frame(&mut self, frame: ClaimFrame) -> Result<bool, AggError> {
        let hash = frame.hash(self.ctx.domain)?;
        if self.frames.contains_key(&hash) {
            return Ok(false);
        }
        self.backend.verify(&frame, self.ctx.domain)?;
        self.keep(hash, frame);
        Ok(true)
    }

    fn keep(&mut self, hash: Hash32, frame: ClaimFrame) {
        self.frames.insert(hash, frame);
        while self.frames.len() > MAX_FRAMES {
            let smallest = self
                .frames
                .iter()
                .min_by_key(|(hash, frame)| (frame.claims.len(), **hash))
                .map(|(hash, _)| *hash);
            match smallest {
                Some(hash) => self.frames.remove(&hash),
                None => break,
            };
        }
    }

    /// One tick: prove the next objects of the pool, delete their payload
    /// bytes and merge. When proving fails the tick is skipped, the error is
    /// reported, and an object that failed twice in a row is dropped.
    ///
    /// A frame over the limits of the chain could never go into a block.
    /// When the proof of the chosen objects comes out too large (a backend
    /// whose proof grows with its objects), the tick is tried again over
    /// half of them; the rest wait for the next tick and nothing is counted
    /// as a failure.
    pub fn on_tick(&mut self, txs: &impl TxLookup, registry: &SchemeStatusRegistry) -> TickOutcome {
        let mut outcome = TickOutcome::default();
        self.pool.begin_tick(txs, registry);
        let mut items = self.pool.next_items();
        while !items.is_empty() {
            match self.prove_within_limits(&items) {
                Ok((hash, frame)) => {
                    self.pool.mark_proven(&items);
                    self.keep(hash, frame.clone());
                    outcome.publish.push(frame);
                    break;
                }
                Err(AggError::Frame(
                    FrameError::ProofTooLarge(_) | FrameError::TooManyClaims(_),
                )) if items.len() > 1 => {
                    items.truncate(items.len() / 2);
                }
                Err(e) => {
                    self.pool.mark_failed(&items);
                    outcome.error = Some(e);
                    break;
                }
            }
        }
        outcome.publish.extend(self.merge());
        outcome
    }

    /// Prove one tick over `items` and check the frame against the limits
    /// of the chain: the frame and its hash.
    fn prove_within_limits(&self, items: &[PoolItem]) -> Result<(Hash32, ClaimFrame), AggError> {
        let frame = self.backend.prove_tick(&self.ctx, items)?;
        frame.check_structure(self.ctx.domain, &FrameLimits::from(&self.params))?;
        let hash = frame.hash(self.ctx.domain)?;
        Ok((hash, frame))
    }

    /// Forget one frame: it cannot go into a block as it is. Its parts and
    /// the frames it is a part of stay.
    pub fn forget_frame(&mut self, frame: &ClaimFrame) {
        if let Ok(hash) = frame.hash(self.ctx.domain) {
            self.frames.remove(&hash);
        }
    }

    /// Merge the frames the aggregator holds: starting from the frame with
    /// the most claims, every frame that shares no claim with the result and
    /// fits the claim limit is merged in. The parts stay: a block may carry
    /// only one of them, and the claims of the other must then still be
    /// within reach of a later block. They leave when one of their claims
    /// is final, or as the smallest frames when the store is full.
    fn merge(&mut self) -> Vec<ClaimFrame> {
        let limits = FrameLimits::from(&self.params);
        let mut published = Vec::new();
        loop {
            let mut order: Vec<(&Hash32, &ClaimFrame)> = self.frames.iter().collect();
            order.sort_by_key(|(hash, frame)| (std::cmp::Reverse(frame.claims.len()), **hash));
            let Some(((_, left), others)) = order.split_first() else {
                break;
            };
            let partner = others.iter().find(|(_, right)| {
                left.claims.len().saturating_add(right.claims.len()) <= limits.max_claims
                    && left.is_disjoint(right)
            });
            let Some((_, right)) = partner else {
                break;
            };
            let Ok(proof) = self.backend.prove_merge(left, right) else {
                break;
            };
            if proof.len() > limits.max_proof_bytes {
                break;
            }
            let Ok(merged) = ClaimFrame::combine(left, right, proof) else {
                break;
            };
            let Ok(merged_hash) = merged.hash(self.ctx.domain) else {
                break;
            };
            if self.frames.contains_key(&merged_hash) {
                break;
            }
            self.keep(merged_hash, merged.clone());
            published.push(merged);
        }
        published
    }

    /// The frame of the next block.
    ///
    /// `usable` holds the digests of the claims the transactions of the block
    /// refer to. A frame with a claim outside it is skipped: its transaction
    /// is missing. Frames with disjoint claims are chosen, the one with the
    /// most claims first, up to the claim limit, and merged into one frame.
    /// Returns `None` when no frame is usable.
    #[must_use]
    pub fn block_frame(&self, usable: &BTreeSet<Hash32>) -> Option<ClaimFrame> {
        let limits = FrameLimits::from(&self.params);
        let domain = self.ctx.domain;
        let mut order: Vec<(&Hash32, &ClaimFrame)> = self
            .frames
            .iter()
            .filter(|(_, frame)| {
                frame
                    .claims
                    .iter()
                    .all(|claim| usable.contains(&claim.digest(domain)))
            })
            .collect();
        order.sort_by_key(|(hash, frame)| (std::cmp::Reverse(frame.claims.len()), **hash));
        let mut chosen: Option<ClaimFrame> = None;
        for (_, frame) in order {
            chosen = match chosen {
                None => Some(frame.clone()),
                Some(current) => {
                    let fits = current.claims.len().saturating_add(frame.claims.len())
                        <= limits.max_claims;
                    let merged = if fits && current.is_disjoint(frame) {
                        self.backend
                            .prove_merge(&current, frame)
                            .ok()
                            .filter(|proof| proof.len() <= limits.max_proof_bytes)
                            .and_then(|proof| ClaimFrame::combine(&current, frame, proof).ok())
                    } else {
                        None
                    };
                    Some(merged.unwrap_or(current))
                }
            };
        }
        chosen
    }

    /// The block that carried `frame` is final: its claims leave the pool's
    /// memory and every frame that shares a claim with it is dropped.
    pub fn on_final(&mut self, frame: &ClaimFrame) {
        let domain = self.ctx.domain;
        let digests: Vec<Hash32> = frame.claims.iter().map(|c| c.digest(domain)).collect();
        self.pool.forget_claims(&digests);
        self.frames.retain(|_, kept| kept.is_disjoint(frame));
    }
}
