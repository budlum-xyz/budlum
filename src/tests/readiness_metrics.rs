//! WP-41 item 6 and WP-20 item 13: the readiness and storage-health series
//! are computed from the chain, not from a number a test writes by hand.
//!
//! Each test here drives the production emit path (`emit_chain_metrics`), or
//! the refusal path that feeds it, and then reads the series out of the
//! Prometheus scrape body. A gauge that is registered and never written is the
//! failure this file exists to catch, and the `metrics_are_written` gate is the
//! static half of the same bar.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::metrics::Metrics;
use crate::storage::bud3::placement::{Class, Share};
use std::sync::Arc;

/// A chain with metrics bound and no store: the same shape the node builds
/// before it has a database, which is all the emit path needs.
fn chain_with_metrics(chain_id: u64) -> (Blockchain, Arc<Metrics>) {
    let consensus = Arc::new(PoWEngine::new(0));
    let metrics = Arc::new(Metrics::new().expect("metric names are literals in metrics.rs"));
    let bc = Blockchain::new(consensus, None, chain_id, None).with_metrics(metrics.clone());
    (bc, metrics)
}

/// Register one small object under `class` and return its key and the bytes
/// the placement holds for it, computed here from the same inputs so the test
/// does not restate the implementation.
fn register_object(
    state: &mut AccountState,
    owner: Address,
    class: Class,
    symbol_size: u16,
    symbols: u32,
) -> (crate::storage::bud3::registry::ObjectKey, u64) {
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;

    let profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size,
        fps: 10,
        k_max: 16,
    };
    let content = b"readiness metrics".repeat(8);
    let upload =
        prepare_public_upload(&content, &profile, &Bud3Limits::default(), 12).expect("prepare");
    let key = upload.record.commitment;
    let segments = upload.segments.len() as u64;
    let shares = (0..segments)
        .map(|segment| {
            (
                segment,
                Share {
                    validator: [9; 32],
                    class,
                    first_esi: 0,
                    symbols,
                },
            )
        })
        .collect();
    // `epoch`, then how many epochs the object is paid for. The second
    // argument is a lifetime, not a checkpoint interval: a zero lifetime is
    // refused by the registry.
    state
        .bud3_registry
        .register_object(upload.record, owner, shares, 0, 100)
        .expect("register");
    (key, segments * u64::from(symbols) * u64::from(symbol_size))
}

/// Section 7.7: the recovery trigger is stated in checkpoints, so the export
/// is in checkpoints, and the stall gauge turns on at the threshold.
///
/// The same lag in blocks means different things on two networks: 40 blocks is
/// eight checkpoints on the testnet (5-block checkpoints) and four on mainnet
/// (10-block checkpoints). The test drives the real emit path on the testnet
/// chain.
#[test]
fn finality_gauges_follow_the_chain() {
    let (mut bc, metrics) = chain_with_metrics(45261);
    let checkpoint = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(45261);
    assert_eq!(checkpoint, 5, "testnet checkpoints are five blocks");
    let producer = Address::from([1u8; 32]);

    // Under eight intervals this is a lag, not a stall.
    while bc.chain.len() as u64 <= checkpoint * 4 {
        bc.produce_block(producer).expect("block");
    }
    bc.emit_chain_metrics();
    assert_eq!(metrics.finality_lag.get(), bc.chain.len() as i64);
    assert_eq!(metrics.finality_lag_checkpoints.get(), 4);
    assert_eq!(
        metrics.finality_stalled.get(),
        0,
        "four checkpoint intervals is under the recovery trigger"
    );

    while bc.chain.len() as u64 <= checkpoint * 8 {
        bc.produce_block(producer).expect("block");
    }
    bc.emit_chain_metrics();
    assert_eq!(metrics.finality_lag_checkpoints.get(), 8);
    assert_eq!(
        metrics.finality_stalled.get(),
        1,
        "eight checkpoint intervals without finality is the recovery trigger"
    );

    // Finality catching up clears it again: the gauge describes the gap, not a
    // latch, or a node that recovered would alarm forever.
    bc.finalized_height = bc.chain.len() as u64;
    bc.emit_chain_metrics();
    assert_eq!(metrics.finality_lag_checkpoints.get(), 0);
    assert_eq!(metrics.finality_stalled.get(), 0);
}

/// R-11: a state-root disagreement is counted where it is detected.
///
/// `validate_candidate_chain` returns before any commit, so the counter
/// cannot wait for the next successful block: on a node that refuses every
/// candidate there is no next block, and the one series that explains the
/// outage would stay at zero.
#[test]
fn state_root_mismatch_is_counted_at_the_refusal() {
    let (mut bc, metrics) = chain_with_metrics(45262);
    let producer = Address::from([1u8; 32]);
    bc.produce_block(producer).expect("block 1");
    let good = bc.chain.clone();
    assert!(
        bc.is_valid_chain(&good),
        "the chain this node built is valid"
    );
    assert_eq!(
        metrics.state_root_mismatch_total.get(),
        0,
        "a valid chain is not a mismatch"
    );

    // Same blocks, one committed root replaced: this node re-executes them and
    // computes a different root, which is the determinism split.
    let mut tampered = good.clone();
    tampered[1].state_root = "ab".repeat(32);
    assert!(!bc.is_valid_chain(&tampered), "the candidate is refused");
    assert_eq!(
        metrics.state_root_mismatch_total.get(),
        1,
        "the refusal is counted"
    );
    assert_eq!(bc.chain, good, "nothing was adopted");
    assert!(metrics
        .encode()
        .contains("budlum_state_root_mismatch_total 1"));
}

/// The B.U.D. 3.0 health series read the rooted registry.
///
/// Custody is split by validator class because the mobile floor is a promise
/// about how much of the network's custody sits on phones; one total hides it.
/// Segment risk and the repair backlog are different questions and are counted
/// separately: a share that is waiting for its holder's acknowledgement puts
/// its segments at risk while no repair task is open, because repair is lazy
/// and fires only at `f / 2` lost shares.
#[test]
fn bud3_health_gauges_read_the_rooted_registry() {
    let (mut bc, metrics) = chain_with_metrics(45262);
    let owner = Address::from([4u8; 32]);
    let (_full_key, full_bytes) = register_object(&mut bc.state, owner, Class::Full, 128, 6);
    let (_mobile_key, mobile_bytes) =
        register_object(&mut bc.state, owner, Class::Mobile, 64, 3);
    bc.emit_chain_metrics();

    assert_eq!(metrics.bud3_objects.get(), 2);
    assert_eq!(
        metrics.bud3_segments_at_risk.get(),
        0,
        "a pending acknowledgement is not a lost share"
    );
    assert_eq!(metrics.bud3_repair_backlog.get(), 0);

    let scrape = metrics.encode();
    assert_eq!(
        parse_labelled(&scrape, "budlum_bud3_custody_bytes", "full"),
        i64::try_from(full_bytes).expect("fits")
    );
    assert_eq!(
        parse_labelled(&scrape, "budlum_bud3_custody_bytes", "mobile"),
        i64::try_from(mobile_bytes).expect("fits")
    );
    assert_ne!(
        full_bytes, mobile_bytes,
        "the two classes are reported apart, not summed"
    );

    // The one holder of both objects never comes back: every segment of both
    // is at risk, and still no repair task is open, because the lazy
    // threshold is measured in lost shares of a segment, not in a lost share.
    let holder = Address::from([9; 32]);
    bc.state.bud3_registry.mark_unseen(&holder);
    bc.emit_chain_metrics();
    let registry = &bc.state.bud3_registry;
    assert!(
        metrics.bud3_segments_at_risk.get() > 0,
        "the loss is visible before any repair task opens"
    );
    assert_eq!(
        metrics.bud3_segments_at_risk.get(),
        i64::try_from(registry.total_segments_at_risk()).expect("fits"),
        "the series is the registry's own answer"
    );
    assert_eq!(
        metrics.bud3_repair_backlog.get(),
        i64::try_from(registry.repair_backlog()).expect("fits")
    );

    let body = metrics.encode();
    for line in ["budlum_bud3_objects 2", "budlum_bud3_repair_backlog 0"] {
        assert!(body.contains(line), "missing {line} in the scrape");
    }
}

/// The custody byte count is the physical count: symbols times the symbol size
/// of the profile that placed them. A logical-size reading would let an
/// operator believe a phone holds a whole object when it holds a share.
#[test]
fn bud3_custody_bytes_count_symbols_times_symbol_size() {
    let (mut bc, _metrics) = chain_with_metrics(45262);
    let owner = Address::from([5u8; 32]);
    let (_key, expected) = register_object(&mut bc.state, owner, Class::Full, 128, 6);
    let (full, mobile) = bc.state.bud3_registry.custody_bytes_by_class();
    assert_eq!(full, expected);
    assert_eq!(mobile, 0);
    assert_enough_for_one_share(&bc, expected);
}

/// A guard against the helper and the registry agreeing on zero: the count has
/// to be a positive number of bytes for a non-empty object.
fn assert_enough_for_one_share(bc: &Blockchain, bytes: u64) {
    assert!(bytes > 0, "a registered object holds bytes");
    assert_eq!(
        bc.state.bud3_registry.object_count(),
        1,
        "exactly the object this test registered"
    );
}

/// Read `name{class="value"}` out of a Prometheus text body.
fn parse_labelled(body: &str, name: &str, label: &str) -> i64 {
    let needle = format!("{name}{{class=\"{label}\"}} ");
    body.lines()
        .find_map(|line| line.strip_prefix(&needle))
        .unwrap_or_else(|| panic!("series {name} with class={label} missing from: {body}"))
        .trim()
        .parse()
        .expect("series value is an integer")
}
