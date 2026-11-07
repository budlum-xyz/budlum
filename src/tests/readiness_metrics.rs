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
///
/// One share per segment, covering every coded symbol of it: the registry's
/// placement rule asks for at least `k + 2` covered ESIs per segment, and the
/// upload codes `symbols_per_segment` of them.
fn register_object(
    state: &mut AccountState,
    owner: Address,
    class: Class,
    symbol_size: u16,
    holder: Address,
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
    // One segment: 64 bytes of content is well under `symbol_size`, so the
    // object codes a single segment and the arithmetic below is one root.
    let upload =
        prepare_public_upload(&[7u8; 64], &profile, &Bud3Limits::default(), 24).expect("prepare");
    assert_eq!(upload.segments.len(), 1, "the fixture is one segment");
    let key = upload.record.commitment;
    let segments = upload.segments.len() as u64;
    let symbols = u64::from(upload.record.symbols_per_segment);
    let shares = (0..segments)
        .map(|segment| {
            (
                segment,
                Share {
                    validator: holder.0,
                    class,
                    first_esi: 0,
                    symbols: u32::try_from(symbols).expect("symbols per segment fits u32"),
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
    (key, segments * symbols * u64::from(symbol_size))
}

/// Section 7.7: the recovery trigger is stated in checkpoints, so the export is
/// in checkpoints, and the stall gauge turns on at the threshold.
///
/// The unit is the point. The same lag in blocks means different things on two
/// networks: eight checkpoints is 40 blocks on the testnet and 80 on mainnet, so
/// a rule written against blocks would be wrong on one of them.
///
/// This is a unit test of `emit_chain_metrics` over its own fields rather than
/// of block production: the chain a test can build here is not a testnet one
/// (a testnet chain has to satisfy the genesis ceremony first), so the height
/// the emit path reads is set directly. `integration.rs` already covers the
/// emit path over a real chain.
#[test]
fn finality_gauges_follow_the_chain() {
    use crate::core::chain_config::finality_checkpoint_interval_for_chain_id;
    assert_eq!(
        finality_checkpoint_interval_for_chain_id(45260),
        10,
        "mainnet checkpoints are ten blocks"
    );
    assert_eq!(
        finality_checkpoint_interval_for_chain_id(45261),
        5,
        "testnet checkpoints are five blocks"
    );

    let (mut bc, metrics) = chain_with_metrics(45262);
    let checkpoint = finality_checkpoint_interval_for_chain_id(45262);
    assert_eq!(checkpoint, 2, "devnet checkpoints are two blocks");
    assert_eq!(
        finality_checkpoint_interval_for_chain_id(9999),
        10,
        "a chain id with no network falls back to the mainnet interval"
    );

    // The genesis block is block 0 and is final; the emit path reads the height
    // as the chain length, so a finalized height of 1 makes the lag the number
    // of blocks after genesis.
    let genesis = bc.chain[0].clone();
    bc.finalized_height = 1;

    // Under eight intervals this is a lag, not a stall.
    bc.chain = vec![genesis.clone(); 1 + (checkpoint * 4) as usize];
    bc.emit_chain_metrics();
    assert_eq!(metrics.finality_lag.get(), bc.chain.len() as i64 - 1);
    assert_eq!(metrics.finality_lag_checkpoints.get(), 4);
    assert_eq!(
        metrics.finality_stalled.get(),
        0,
        "four checkpoint intervals is under the recovery trigger"
    );

    bc.chain = vec![genesis.clone(); 1 + (checkpoint * 8) as usize];
    bc.emit_chain_metrics();
    assert_eq!(metrics.finality_lag_checkpoints.get(), 8);
    assert_eq!(
        metrics.finality_stalled.get(),
        1,
        "eight checkpoint intervals without finality is the recovery trigger"
    );
    // The block reading of the same moment is the checkpoint reading times the
    // interval, which is exactly why the alert uses the second.
    assert_eq!(metrics.finality_lag.get(), 8 * checkpoint as i64);

    // Finality catching up clears it again: the gauge describes the gap, not a
    // latch, or a node that recovered would alarm forever.
    bc.finalized_height = bc.chain.len() as u64;
    bc.emit_chain_metrics();
    assert_eq!(metrics.finality_lag.get(), 0);
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
    tampered[0].state_root = "ab".repeat(32);
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
    let full_holder = Address::from([9; 32]);
    let mobile_holder = Address::from([10; 32]);
    let (_full_key, full_bytes) =
        register_object(&mut bc.state, owner, Class::Full, 128, full_holder);
    let (_mobile_key, mobile_bytes) =
        register_object(&mut bc.state, owner, Class::Mobile, 64, mobile_holder);
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
    bc.state.bud3_registry.mark_unseen(&full_holder);
    bc.state.bud3_registry.mark_unseen(&mobile_holder);
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
    let (_key, expected) = register_object(
        &mut bc.state,
        owner,
        Class::Full,
        128,
        Address::from([9; 32]),
    );
    let (full, mobile) = bc.state.bud3_registry.custody_bytes_by_class();
    assert_eq!(full, expected);
    assert_eq!(mobile, 0);
    // The helper and the registry must not both be counting zero.
    assert!(expected > 0, "a registered object holds bytes");
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
