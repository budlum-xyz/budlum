//! The object layer's measurement ring (object-layer card step 10, the metric
//! table in Section 9).
//!
//! The directive asks for nine families of metrics. Three of them are
//! **durations** and are answered as a distribution, not as a number: `p50` and
//! `p95` over the last 256 observations per domain. The other six are counters
//! whose values are the state itself (`assets_in_object_layer`,
//! `value_in_object_layer`, `custody_delta`) or a running total
//! (`challenges_upheld`, `dependencies_rolled_back`, `composite_homes`).
//!
//! # Why the ring lives here and not in the registry
//!
//! The registry is consensus state: it is hashed into the settlement root and
//! every node must hold exactly the same bytes. A 256-slot ring is *not* that.
//! It is an observation, and two nodes that start observing at different
//! heights would disagree on the percentiles and therefore, if the ring were in
//! the state, on the state root. So the ring is derived: it is rebuilt by
//! replaying the events the state already holds, it is never hashed, and a node
//! that starts late reports a smaller sample rather than a wrong one.
//!
//! # Why the percentiles are computed by the reader
//!
//! The directive puts the percentile arithmetic in RPC ([`Ring::percentile`] is
//! the one implementation). Nothing on the consensus path reads a percentile,
//! so nothing consensus-critical can depend on a rounding choice.
//!
//! WIRING: unwired - [`ObjectLayerMetrics::record`] is called from the block-end
//! maintenance beside the registry's own counters and from the RPC read that
//! `bud_getObjectLayerMetrics` will serve; both land with the object-layer
//! transaction door. Until then `src/tests/object_layer_metrics.rs` and this
//! file's unit tests are the callers.

use std::collections::BTreeMap;

/// The number of observations one duration series keeps (Section 9's metric
/// note: "the last 256 measurements per domain").
pub const RING_SIZE: usize = 256;

/// A duration series: the last [`RING_SIZE`] observations, oldest first.
///
/// The ring stores raw block counts. It deliberately does not store a mean: a
/// mean of a heavy-tailed series hides the tail, and the tail is the number an
/// operator acts on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ring {
    samples: Vec<u64>,
    next: usize,
}

impl Ring {
    /// An empty ring.
    #[must_use]
    pub fn new() -> Self {
        Self {
            samples: Vec::with_capacity(RING_SIZE),
            next: 0,
        }
    }

    /// Record one observation, dropping the oldest once the ring is full.
    pub fn push(&mut self, blocks: u64) {
        if self.samples.len() < RING_SIZE {
            self.samples.push(blocks);
            self.next = self.samples.len() % RING_SIZE;
            return;
        }
        if let Some(slot) = self.samples.get_mut(self.next) {
            *slot = blocks;
        }
        self.next = (self.next + 1) % RING_SIZE;
    }

    /// How many observations the ring holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether the ring holds no observation yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The observations, oldest first. Empty until the first push.
    #[must_use]
    pub fn samples(&self) -> Vec<u64> {
        let mut out = Vec::with_capacity(self.samples.len());
        if self.samples.len() < RING_SIZE {
            out.extend_from_slice(&self.samples);
            return out;
        }
        // Full: the oldest sample is the one at `next`.
        out.extend_from_slice(&self.samples[self.next..]);
        out.extend_from_slice(&self.samples[..self.next]);
        out
    }

    /// The percentile the reader asks for, in whole blocks.
    ///
    /// Nearest-rank, the definition an operator can check by hand: sort the
    /// sample, take the value at `ceil(p/100 * n)`, 1-based, clamped into
    /// range. A percentile of an empty ring is `None`, not zero: "no
    /// observation" and "instant" are different facts and reporting the first
    /// as the second is the mistake this signature prevents.
    #[must_use]
    pub fn percentile(&self, percent: u8) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let n = sorted.len() as u128;
        let p = u128::from(percent.min(100));
        // ceil(p * n / 100), then at least 1.
        let rank = (p * n).div_ceil(100).max(1);
        let index = usize::try_from(rank.saturating_sub(1))
            .unwrap_or(usize::MAX)
            .min(sorted.len().saturating_sub(1));
        sorted.get(index).copied()
    }

    /// The pair the metric table names: `(p50, p95)`.
    #[must_use]
    pub fn median_and_tail(&self) -> (Option<u64>, Option<u64>) {
        (self.percentile(50), self.percentile(95))
    }
}

/// One domain's counters, as the state itself reports them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// `assets_in_object_layer`: assets whose placement is here.
    pub assets_in_object_layer: u64,
    /// `value_in_object_layer`, in class units. Reported in atoms so no reader
    /// can mistake a class unit for a whole token.
    pub value_in_object_layer_atoms: u128,
    /// `challenges_upheld`, from the registry.
    pub challenges_upheld: u64,
    /// `challenges_rejected`, from the registry.
    pub challenges_rejected: u64,
    /// `dependencies_rolled_back`.
    pub dependencies_rolled_back: u64,
    /// `dependencies_resolved`.
    pub dependencies_resolved: u64,
}

/// The composite width buckets the table names: 1, 2, 3, 4+.
pub const COMPOSITE_BUCKETS: usize = 4;

/// One domain's object-layer measurement surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainMetrics {
    /// `finalize_blocks`, written by `Resolve`.
    pub finalize_blocks: Ring,
    /// `rule_lag_blocks`, written by `RefreshClass`.
    pub rule_lag_blocks: Ring,
    /// `outbound_latency_blocks`, written by `ConfirmDeparture`.
    pub outbound_latency_blocks: Ring,
    /// `endpoint_header_age`, written by the entry proof path. Kept as raw
    /// observations for the same reason as the block counts.
    pub endpoint_header_age: Ring,
    /// `custody_delta`, written by `AuditCustody`. Signed: a negative delta is
    /// the one that freezes a class, so it must not be clamped away.
    pub custody_delta: i128,
    /// `reference_samples_verified`, written by `RegisterClass`.
    pub reference_samples_verified: u64,
    /// The counters.
    pub counters: Counters,
    /// `composite_homes`: how many distinct homes one `Call` or `Accept`
    /// touched, bucketed as 1, 2, 3, 4-or-more.
    pub composite_homes: [u64; COMPOSITE_BUCKETS],
}

impl DomainMetrics {
    /// Bucket one composite by the number of distinct homes it touched.
    ///
    /// The bucket index is `min(homes, 4) - 1`; a composite with no home does
    /// not land in any bucket, because a call that touches nothing is a
    /// refusal and never reaches this function.
    pub fn note_composite(&mut self, homes: usize) {
        if homes == 0 {
            return;
        }
        let index = homes.min(COMPOSITE_BUCKETS) - 1;
        if let Some(slot) = self.composite_homes.get_mut(index) {
            *slot = slot.saturating_add(1);
        }
    }
}

/// Every domain's object-layer metrics, keyed by domain id.
///
/// Node-local and derived: see the module header. Two nodes report different
/// percentiles when they started observing at different heights, and that is
/// stated rather than hidden, because the alternative is a state root that
/// depends on when a node was started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectLayerMetrics {
    domains: BTreeMap<u32, DomainMetrics>,
}

impl ObjectLayerMetrics {
    /// An empty surface.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The metrics for one domain, created on first write.
    pub fn entry(&mut self, domain: u32) -> &mut DomainMetrics {
        self.domains.entry(domain).or_default()
    }

    /// The metrics for one domain, if it has any.
    #[must_use]
    pub fn get(&self, domain: u32) -> Option<&DomainMetrics> {
        self.domains.get(&domain)
    }

    /// The domains this surface holds, in id order.
    pub fn domains(&self) -> impl Iterator<Item = (u32, &DomainMetrics)> {
        self.domains.iter().map(|(id, m)| (*id, m))
    }

    /// Whether nothing has been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Record a duration against `domain` for the metric named by `Series`.
    ///
    /// One entry point rather than five setters: the series are checked here
    /// so a caller cannot write `finalize_blocks` into `rule_lag_blocks`, which
    /// is the sort of transposition a copy-pasted call site produces once and
    /// nobody notices for a month.
    pub fn record(&mut self, domain: u32, series: Series, blocks: u64) {
        let metrics = self.entry(domain);
        match series {
            Series::FinalizeBlocks => metrics.finalize_blocks.push(blocks),
            Series::RuleLagBlocks => metrics.rule_lag_blocks.push(blocks),
            Series::OutboundLatencyBlocks => metrics.outbound_latency_blocks.push(blocks),
            Series::EndpointHeaderAge => metrics.endpoint_header_age.push(blocks),
        }
    }
}

/// The four duration series the table names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Series {
    /// Finality latency, written by `Resolve`.
    FinalizeBlocks,
    /// Rule lag, written by `RefreshClass`.
    RuleLagBlocks,
    /// Outbound latency, written by `ConfirmDeparture`.
    OutboundLatencyBlocks,
    /// Endpoint header age, written by the entry proof path.
    EndpointHeaderAge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_ring_reports_no_percentile() {
        let ring = Ring::new();
        assert!(ring.is_empty());
        assert_eq!(ring.percentile(50), None);
        assert_eq!(ring.median_and_tail(), (None, None));
    }

    #[test]
    fn the_ring_drops_the_oldest_and_keeps_the_order() {
        let mut ring = Ring::new();
        for i in 0..(RING_SIZE as u64 + 10) {
            ring.push(i);
        }
        assert_eq!(ring.len(), RING_SIZE);
        let samples = ring.samples();
        assert_eq!(samples.first().copied(), Some(10));
        assert_eq!(samples.last().copied(), Some(RING_SIZE as u64 + 9));
        assert_eq!(samples.len(), RING_SIZE);
    }

    #[test]
    fn the_percentile_is_the_nearest_rank() {
        let mut ring = Ring::new();
        for v in 1..=100u64 {
            ring.push(v);
        }
        // ceil(0.50 * 100) = 50 -> the 50th smallest value.
        assert_eq!(ring.percentile(50), Some(50));
        // ceil(0.95 * 100) = 95 -> the 95th smallest value.
        assert_eq!(ring.percentile(95), Some(95));
        assert_eq!(ring.percentile(100), Some(100));
        // A one-sample ring answers every percentile with that sample.
        let mut one = Ring::new();
        one.push(7);
        assert_eq!(one.percentile(50), Some(7));
        assert_eq!(one.percentile(95), Some(7));
    }

    #[test]
    fn a_series_cannot_be_written_into_another() {
        let mut m = ObjectLayerMetrics::new();
        m.record(9, Series::RuleLagBlocks, 12);
        let d = m.get(9).expect("the domain has metrics");
        assert_eq!(d.rule_lag_blocks.samples(), vec![12]);
        assert!(d.finalize_blocks.is_empty());
        assert!(d.outbound_latency_blocks.is_empty());
        assert!(d.endpoint_header_age.is_empty());
    }

    #[test]
    fn the_composite_buckets_cap_at_four() {
        let mut d = DomainMetrics::default();
        d.note_composite(1);
        d.note_composite(3);
        d.note_composite(9);
        assert_eq!(d.composite_homes, [1, 0, 1, 1]);
        // A composite that touched nothing is a refusal, never a bucket.
        d.note_composite(0);
        assert_eq!(d.composite_homes, [1, 0, 1, 1]);
    }
}
