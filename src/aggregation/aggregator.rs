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
use super::frame::{verify_segment_attestations, ClaimFrame, FrameError, FrameLimits};
use super::params::AggParams;
use super::pool::{Admission, ObjectPool, PoolItem, Rejection, TxLookup};
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::Hash32;

/// Frames an aggregator keeps. Past this the frame with the fewest claims is
/// dropped (peer frames before locally proven/merged frames).
const MAX_FRAMES: usize = 1024;
/// Total encoded frame bytes an aggregator keeps. Bounds resident memory under
/// worst-case wire frames while comfortably fitting 1024-claim merge hierarchies.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
struct StoredFrame {
    frame: ClaimFrame,
    bytes: usize,
    local: bool,
    claim_set: Vec<Hash32>,
}

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
    frames: BTreeMap<Hash32, StoredFrame>,
    /// Total encoded bytes held in `frames`.
    frame_bytes: usize,
    max_frames: usize,
    max_frame_bytes: usize,
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
            frame_bytes: 0,
            max_frames: MAX_FRAMES,
            max_frame_bytes: MAX_FRAME_BYTES,
        }
    }

    /// Test-only bound override for frame-eviction tests without multi-MiB allocations.
    #[cfg(test)]
    pub(super) const fn with_frame_limits(
        mut self,
        max_frames: usize,
        max_frame_bytes: usize,
    ) -> Self {
        self.max_frames = max_frames;
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    /// The object pool.
    #[must_use]
    pub const fn pool(&self) -> &ObjectPool {
        &self.pool
    }

    /// The tick context of this aggregator.
    #[must_use]
    pub const fn ctx(&self) -> &TickCtx {
        &self.ctx
    }

    /// Verified frames the aggregator holds.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Total encoded bytes held across verified frames.
    #[must_use]
    pub const fn frame_bytes(&self) -> usize {
        self.frame_bytes
    }

    /// Whether any verified frame currently held covers `digest`.
    #[must_use]
    pub fn tracks_claim(&self, digest: &Hash32) -> bool {
        self.frames
            .values()
            .any(|entry| entry.claim_set.binary_search(digest).is_ok())
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

    /// A frame arrived on `agg/frame`. It is verified structurally, by
    /// segment ownership attestations, and with the backend; an invalid frame
    /// is dropped. Returns whether the frame was accepted into the store.
    ///
    /// # Errors
    ///
    /// [`AggError`] when the frame is not valid.
    pub fn on_frame(
        &mut self,
        frame: ClaimFrame,
        registry: &SchemeStatusRegistry,
    ) -> Result<bool, AggError> {
        let hash = frame.hash(self.ctx.domain)?;
        if self.frames.contains_key(&hash) {
            return Ok(false);
        }
        frame.check_structure(self.ctx.domain, &FrameLimits::from(&self.params))?;
        verify_segment_attestations(registry, self.ctx.domain, &frame.segments)?;
        self.backend.verify(&frame, self.ctx.domain)?;
        Ok(self.keep(hash, frame, false))
    }

    fn sorted_claim_set(&self, frame: &ClaimFrame) -> Vec<Hash32> {
        let mut claim_set: Vec<Hash32> = frame
            .claims
            .iter()
            .map(|c| c.digest(self.ctx.domain))
            .collect();
        claim_set.sort_unstable();
        claim_set
    }

    fn remove_frame(&mut self, hash: &Hash32) {
        if let Some(removed) = self.frames.remove(hash) {
            self.frame_bytes = self.frame_bytes.saturating_sub(removed.bytes);
        }
    }

    fn retain_frames(&mut self, mut predicate: impl FnMut(&Hash32, &ClaimFrame) -> bool) {
        self.frames
            .retain(|hash, entry| predicate(hash, &entry.frame));
        self.frame_bytes = self.frames.values().map(|entry| entry.bytes).sum();
    }

    fn keep(&mut self, hash: Hash32, frame: ClaimFrame, local: bool) -> bool {
        if self.frames.contains_key(&hash) {
            return false;
        }
        let bytes = frame.encode().len();
        if bytes > self.max_frame_bytes {
            return false;
        }
        let claim_set = self.sorted_claim_set(&frame);

        // Collapse duplicate coverage of the exact same sorted claim set.
        // Local frames always beat peer frames; within the same tier, keep the
        // smaller encoding to avoid churn.
        if let Some((&existing_hash, existing)) = self
            .frames
            .iter()
            .find(|(_, entry)| entry.claim_set == claim_set)
        {
            if !local && existing.local {
                return false;
            }
            if local == existing.local && bytes >= existing.bytes {
                return false;
            }
            if self
                .frame_bytes
                .saturating_sub(existing.bytes)
                .saturating_add(bytes)
                > self.max_frame_bytes
            {
                return false;
            }
            self.remove_frame(&existing_hash);
            self.frame_bytes = self.frame_bytes.saturating_add(bytes);
            self.frames.insert(
                hash,
                StoredFrame {
                    frame,
                    bytes,
                    local,
                    claim_set,
                },
            );
            return true;
        }

        if !local {
            // Peer frames may only evict strictly lower-priority peer frames
            // (never local frames, and never churning equal/larger-claim peers).
            let need_slot = self.frames.len() >= self.max_frames;
            let need_bytes = self.frame_bytes.saturating_add(bytes) > self.max_frame_bytes;
            if need_slot || need_bytes {
                let incoming_prio = (frame.claims.len(), std::cmp::Reverse(bytes));
                let mut peer_victims: Vec<(Hash32, usize, usize)> = self
                    .frames
                    .iter()
                    .filter(|(_, entry)| !entry.local)
                    .map(|(h, entry)| (*h, entry.frame.claims.len(), entry.bytes))
                    .filter(|(_, c, b)| (*c, std::cmp::Reverse(*b)) < incoming_prio)
                    .collect();
                peer_victims.sort_by_key(|(h, c, b)| (*c, std::cmp::Reverse(*b), *h));

                let mut next_len = self.frames.len().saturating_add(1);
                let mut next_bytes = self.frame_bytes.saturating_add(bytes);
                let mut drop_list = Vec::new();
                for (vh, _, vb) in peer_victims {
                    if next_len <= self.max_frames && next_bytes <= self.max_frame_bytes {
                        break;
                    }
                    drop_list.push(vh);
                    next_len = next_len.saturating_sub(1);
                    next_bytes = next_bytes.saturating_sub(vb);
                }
                if next_len > self.max_frames || next_bytes > self.max_frame_bytes {
                    return false;
                }
                for vh in &drop_list {
                    self.remove_frame(vh);
                }
            }
            self.frame_bytes = self.frame_bytes.saturating_add(bytes);
            self.frames.insert(
                hash,
                StoredFrame {
                    frame,
                    bytes,
                    local: false,
                    claim_set,
                },
            );
            return true;
        }

        // Local frames (ticks / merges) always enter unless alone larger than
        // `max_frame_bytes`, evicting peer frames before touching older local ones.
        self.frame_bytes = self.frame_bytes.saturating_add(bytes);
        self.frames.insert(
            hash,
            StoredFrame {
                frame,
                bytes,
                local: true,
                claim_set,
            },
        );
        while self.frames.len() > self.max_frames || self.frame_bytes > self.max_frame_bytes {
            let victim = self
                .frames
                .iter()
                .filter(|(h, _)| **h != hash)
                .min_by_key(|(h, entry)| {
                    (
                        entry.local,
                        entry.frame.claims.len(),
                        std::cmp::Reverse(entry.bytes),
                        **h,
                    )
                })
                .map(|(h, _)| *h);
            match victim {
                Some(vh) => self.remove_frame(&vh),
                None => break,
            }
        }
        true
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
                    if self.keep(hash, frame.clone(), true) {
                        outcome.publish.push(frame);
                    }
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
            self.remove_frame(&hash);
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
            let mut order: Vec<(&Hash32, &ClaimFrame)> = self
                .frames
                .iter()
                .map(|(h, entry)| (h, &entry.frame))
                .collect();
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
            let merged_claim_set = self.sorted_claim_set(&merged);
            if self
                .frames
                .values()
                .any(|entry| entry.claim_set == merged_claim_set && entry.local)
            {
                break;
            }
            if !self.keep(merged_hash, merged.clone(), true) {
                break;
            }
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
        let mut order: Vec<(&Hash32, &StoredFrame)> = self
            .frames
            .iter()
            .filter(|(_, entry)| {
                entry
                    .frame
                    .claims
                    .iter()
                    .all(|claim| usable.contains(&claim.digest(domain)))
            })
            .collect();
        order.sort_by_key(|(hash, entry)| {
            (
                std::cmp::Reverse(entry.frame.claims.len()),
                std::cmp::Reverse(entry.local),
                **hash,
            )
        });
        let mut chosen: Option<ClaimFrame> = None;
        for (_, entry) in order {
            let frame = &entry.frame;
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
        self.retain_frames(|_, kept| kept.is_disjoint(frame));
    }

    /// A pending transaction left the node before finality: abandon its claim
    /// in the pool and drop any frame that carries it so zombie frames cannot
    /// occupy the store or poison later merges.
    pub(super) fn forget_claim(&mut self, digest: &Hash32) {
        self.pool.abandon_claim(digest);
        let domain = self.ctx.domain;
        self.retain_frames(|_, frame| {
            frame
                .claims
                .iter()
                .all(|claim| claim.digest(domain) != *digest)
        });
    }
}
