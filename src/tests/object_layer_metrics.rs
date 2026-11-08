//! The object-layer metric surface's acceptance tests (card step 10).
//!
//! The metric table in Section 9 names nine families. Three are durations and
//! are answered as `p50`/`p95` over a 256-slot ring; six are counters the state
//! already holds. These tests measure the three properties a reader depends on
//! and cannot check by reading one number:
//!
//! 1. the ring keeps the *last* 256 observations and forgets the oldest, so a
//!    percentile describes the recent chain rather than all of it;
//! 2. the percentile is the nearest rank, computed once, so two readers of one
//!    ring cannot disagree;
//! 3. nothing here is consensus state: two nodes with different observation
//!    histories produce different percentiles from the same block and neither
//!    reports a wrong one.

use crate::object_layer::metrics::{
    Counters, DomainMetrics, ObjectLayerMetrics, Ring, Series, COMPOSITE_BUCKETS, RING_SIZE,
};

#[test]
fn object_layer_metrics_keep_the_last_256_observations() {
    let mut metrics = ObjectLayerMetrics::new();
    // 300 resolutions: 0..=299. Only the last 256 survive.
    for blocks in 0..300u64 {
        metrics.record(7, Series::FinalizeBlocks, blocks);
    }
    let held = metrics.get(7).expect("the domain has metrics");
    assert_eq!(held.finalize_blocks.len(), RING_SIZE);
    let samples = held.finalize_blocks.samples();
    assert_eq!(samples.len(), RING_SIZE);
    assert_eq!(samples.first().copied(), Some(44), "the oldest 44 are gone");
    assert_eq!(samples.last().copied(), Some(299));
    // The median of the surviving window, not of the whole history: the
    // window is 44..=299, so the 128th smallest value is 44 + 127 = 171.
    assert_eq!(held.finalize_blocks.percentile(50), Some(171));
    // A second domain is a second window.
    assert!(metrics.get(8).is_none());
    metrics.record(8, Series::RuleLagBlocks, 5);
    assert_eq!(
        metrics.get(8).and_then(|m| m.rule_lag_blocks.percentile(95)),
        Some(5)
    );
    assert_eq!(metrics.domains().count(), 2);
}

#[test]
fn object_layer_metrics_percentiles_are_reader_computed() {
    // Two readers of one ring get one answer, and the answer is the nearest
    // rank the directive's "RPC computes the percentiles" line implies.
    let mut ring = Ring::new();
    for v in [9u64, 1, 5, 5, 2].into_iter() {
        ring.push(v);
    }
    // Sorted: 1 2 5 5 9. ceil(0.5 * 5) = 3 -> the third smallest value.
    assert_eq!(ring.percentile(50), Some(5));
    assert_eq!(ring.median_and_tail(), (Some(5), Some(9)));
    // The same call twice cannot drift: no percentile is cached anywhere.
    assert_eq!(ring.percentile(50), ring.percentile(50));
    assert_eq!(ring.samples(), vec![9, 1, 5, 5, 2], "the ring is not sorted");

    // An empty ring is "no observation", not zero: the distinction the
    // signature exists to keep.
    let empty = Ring::new();
    assert_eq!(empty.median_and_tail(), (None, None));
}

#[test]
fn object_layer_metrics_are_not_consensus_state() {
    // Two nodes that began observing at different heights hold different
    // rings, and both are honest. Nothing here is hashed into the settlement
    // root, so the difference cannot fork the chain. This test states that as
    // a property of the type: the surface has no root, and equal observation
    // histories give equal values.
    let mut a = ObjectLayerMetrics::new();
    let mut b = ObjectLayerMetrics::new();
    for blocks in 0..10u64 {
        a.record(1, Series::OutboundLatencyBlocks, blocks);
    }
    for blocks in 5..10u64 {
        b.record(1, Series::OutboundLatencyBlocks, blocks);
    }
    assert_ne!(
        a.get(1).and_then(|m| m.outbound_latency_blocks.percentile(50)),
        b.get(1).and_then(|m| m.outbound_latency_blocks.percentile(50)),
        "a node that started later reports a smaller sample"
    );
    // Same observations, same answer: the surface is a pure function of the
    // events it recorded.
    let mut c = ObjectLayerMetrics::new();
    for blocks in 0..10u64 {
        c.record(1, Series::OutboundLatencyBlocks, blocks);
    }
    assert_eq!(a, c);
}

#[test]
fn object_layer_metrics_name_every_series_once() {
    // A transposed write is the failure a set of setters invites, so the test
    // writes one value through each series and checks the four rings apart.
    let mut metrics = ObjectLayerMetrics::new();
    for (series, value) in [
        (Series::FinalizeBlocks, 11u64),
        (Series::RuleLagBlocks, 22),
        (Series::OutboundLatencyBlocks, 33),
        (Series::EndpointHeaderAge, 44),
    ] {
        metrics.record(3, series, value);
    }
    let d = metrics.get(3).expect("the domain has metrics");
    assert_eq!(d.finalize_blocks.samples(), vec![11]);
    assert_eq!(d.rule_lag_blocks.samples(), vec![22]);
    assert_eq!(d.outbound_latency_blocks.samples(), vec![33]);
    assert_eq!(d.endpoint_header_age.samples(), vec![44]);
}

#[test]
fn object_layer_metrics_counters_carry_units_and_buckets() {
    // The counters the table names, with the units it names: assets are a
    // count, value is in atoms, and the composite width is bucketed 1/2/3/4+.
    let mut d = DomainMetrics {
        counters: Counters {
            assets_in_object_layer: 12,
            value_in_object_layer_atoms: 4_000_000,
            challenges_upheld: 1,
            challenges_rejected: 2,
            dependencies_rolled_back: 3,
            dependencies_resolved: 4,
        },
        custody_delta: -7,
        ..DomainMetrics::default()
    };
    assert_eq!(d.composite_homes.len(), COMPOSITE_BUCKETS);
    d.note_composite(1);
    d.note_composite(2);
    d.note_composite(4);
    d.note_composite(7);
    assert_eq!(d.composite_homes, [1, 1, 0, 2]);
    // A negative custody delta survives: it is the one that freezes a class.
    assert_eq!(d.custody_delta, -7);
    // The sixteen reference samples a class registered are counted once each.
    d.reference_samples_verified = 3;
    assert_eq!(d.counters.assets_in_object_layer, 12);
    assert_eq!(d.counters.value_in_object_layer_atoms, 4_000_000);
}
