//! The churn simulation (WP-14, directive 7.6).
//!
//! N Full and M Mobile validator nodes run in one process. The simulator
//! injects network latency and packet loss between them and produces random
//! leave and return events. It measures what Instant Task Handover must
//! guarantee: a sudden 10 percent departure of Full validators delays
//! finality by at most two checkpoint intervals, and a total Mobile departure
//! does not touch finality at all while no stored piece is lost. The same
//! tool feeds the WP-46 rehearsal.
//!
//! The run is deterministic: every per-node draw is a pure function of the
//! seed, the block height and the node index, so the baseline run and the
//! departure runs see the same network weather and differ only in their
//! departure events.

use budlum_core::core::chain_config::{finality_checkpoint_interval_for_chain_id, Network};
use budlum_core::validators::handover::{RepairTaskTracker, REPAIR_TASK_START_BLOCKS};

/// The testnet chain id (directive 1.5).
const TESTNET_CHAIN_ID: u64 = 45261;

/// Committee size cap (directive 7.4 and Ek A: up to 128 seats).
const MAX_SEATS: u32 = 128;

/// No validator holds more than a quarter of the seats (Ek A).
const MAX_SEATS_PER_VALIDATOR: u32 = 32;

/// Piece replicas across classes (directive 6.9: class-aware placement keeps
/// at least one Full holder per piece).
const PIECE_REDUNDANCY: usize = 3;

/// The deterministic draw for one (seed, height, node) cell: splitmix64, so
/// the baseline and the departure runs share one network-weather stream.
fn draw(seed: u64, height: u64, node: usize) -> u64 {
    let node_term = u64::try_from(node).unwrap_or(0);
    let mut z = seed
        ^ height.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ node_term.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Map a draw into `0..bound` without truncating casts. A zero bound maps to
/// index 0.
fn pick(value: u64, bound: usize) -> usize {
    let wide = u64::try_from(bound).unwrap_or(1);
    usize::try_from(value % wide.max(1)).unwrap_or(0)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Full,
    Mobile,
}

#[derive(Clone)]
struct SimNode {
    class: Class,
    online: bool,
    seats: u32,
    /// Base one-way latency in milliseconds.
    latency_ms: u64,
    pieces: Vec<u32>,
}

/// One departure event: the listed nodes stop at `at_block`. When `returns`
/// is set they come back `absence_blocks` later (random leave and return).
#[derive(Clone)]
struct Departure {
    at_block: u64,
    nodes: Vec<usize>,
    returns: bool,
    absence_blocks: u64,
}

#[derive(Clone)]
struct SimConfig {
    full_nodes: usize,
    mobile_nodes: usize,
    blocks: u64,
    /// Packet loss in parts per thousand.
    loss_per_mille: u64,
    piece_count: u32,
    seed: u64,
    departures: Vec<Departure>,
}

#[derive(Debug, Default)]
struct SimReport {
    /// The block heights at which a checkpoint finalized, in order.
    finalized_heights: Vec<u64>,
    /// The fewest holders any piece held at any moment.
    piece_min_holders: usize,
    /// The most consecutive checkpoint intervals without a finalization.
    max_finality_gap_intervals: u64,
}

/// Run one simulation. Pure with respect to `config`: the same config always
/// produces the same report.
fn run(config: &SimConfig) -> SimReport {
    let params = Network::from_chain_id(TESTNET_CHAIN_ID)
        .unwrap_or(Network::Devnet)
        .consensus_params();
    let interval = finality_checkpoint_interval_for_chain_id(TESTNET_CHAIN_ID);
    let quorum_num = params.finality_quorum_numerator;
    let quorum_den = params.finality_quorum_denominator;

    // Seats spread across Full validators, capped per validator.
    let seat_cap = MAX_SEATS / u32::try_from(config.full_nodes.max(1)).unwrap_or(1);
    let seat_cap = seat_cap.min(MAX_SEATS_PER_VALIDATOR).max(1);
    let mut nodes: Vec<SimNode> = Vec::new();
    for index in 0..(config.full_nodes + config.mobile_nodes) {
        let class = if index < config.full_nodes {
            Class::Full
        } else {
            Class::Mobile
        };
        // Mobile validators hold no finality seats (directive 7.2).
        let seats = if class == Class::Full { seat_cap } else { 0 };
        nodes.push(SimNode {
            class,
            online: true,
            seats,
            latency_ms: draw(config.seed, 0, index) % 400,
            pieces: Vec::new(),
        });
    }

    // Class-aware piece placement: one Full holder and two Mobile holders per
    // piece, so a total Mobile departure never takes the last copy.
    let mobile_base = config.full_nodes;
    for piece in 0..config.piece_count {
        let piece_index = usize::try_from(piece).unwrap_or(0);
        let full_holder = pick(draw(config.seed, 1, piece_index), config.full_nodes);
        nodes[full_holder].pieces.push(piece);
        for replica in 0..(PIECE_REDUNDANCY - 1) {
            let mobile_pool = config.mobile_nodes.max(1);
            let replica_height = u64::try_from(replica).unwrap_or(0) + 2;
            let draw_value = draw(config.seed, replica_height, piece_index);
            let mobile_holder = mobile_base + pick(draw_value, mobile_pool);
            if mobile_holder < nodes.len() {
                nodes[mobile_holder].pieces.push(piece);
            }
        }
    }

    let mut report = SimReport {
        piece_min_holders: usize::MAX,
        ..SimReport::default()
    };
    // Consecutive missed participation records per node (directive 7.5).
    let mut seat_misses: Vec<u32> = vec![0; nodes.len()];
    // Outstanding repairs: (piece, assignee, assigned height).
    let mut repairs: Vec<(u32, usize, u64)> = Vec::new();
    let mut gap_checkpoints = 0u64;
    let mut pending_returns: Vec<(u64, Vec<usize>)> = Vec::new();

    for height in 1..=config.blocks {
        // Departures and returns.
        for event in &config.departures {
            if event.at_block == height {
                for &node in &event.nodes {
                    nodes[node].online = false;
                    nodes[node].pieces.clear();
                }
                if event.returns {
                    pending_returns.push((height + event.absence_blocks, event.nodes.clone()));
                }
            }
        }
        pending_returns.retain(|(back_at, members)| {
            if height >= *back_at {
                for node in members.iter() {
                    nodes[*node].online = true;
                }
                false
            } else {
                true
            }
        });

        if height % interval == 0 {
            // Repair: a repair task per piece below redundancy, assigned to an
            // online Full node. The repair-task handover (20 blocks, directive
            // 7.6) moves the duty to the next candidate when the assignee
            // does not start in time; the piece is rewritten either way.
            let mut restored: Vec<usize> = Vec::new();
            for (index, (piece, assignee, assigned_at)) in repairs.iter_mut().enumerate() {
                let task = RepairTaskTracker::new(*assigned_at);
                let handover = task.handover_due(height);
                let target = (0..nodes.len())
                    .find(|candidate| {
                        nodes[*candidate].class == Class::Full
                            && nodes[*candidate].online
                            && !nodes[*candidate].pieces.contains(piece)
                    })
                    .unwrap_or(*assignee);
                if handover || nodes[*assignee].online {
                    if nodes[target].online && !nodes[target].pieces.contains(piece) {
                        nodes[target].pieces.push(*piece);
                        restored.push(index);
                    }
                }
            }
            for index in restored.into_iter().rev() {
                repairs.swap_remove(index);
            }
            // Queue repairs for pieces below redundancy.
            for piece in 0..config.piece_count {
                let holders = nodes
                    .iter()
                    .filter(|node| node.online && node.pieces.contains(&piece))
                    .count();
                if holders < PIECE_REDUNDANCY
                    && !repairs.iter().any(|(queued, _, _)| *queued == piece)
                {
                    repairs.push((piece, 0, height));
                }
            }
            let min_holders = (0..config.piece_count)
                .map(|piece| {
                    nodes
                        .iter()
                        .filter(|node| node.pieces.contains(&piece))
                        .count()
                })
                .min()
                .unwrap_or(0);
            report.piece_min_holders = report.piece_min_holders.min(min_holders);
        }

        // Checkpoint: Full validators vote their seats. Latency and loss
        // decide delivery before the checkpoint closes.
        if height % interval == 0 {
            let mut active_seats = 0u64;
            let mut votes = 0u64;
            for (index, node) in nodes.iter().enumerate() {
                if !node.online || node.class != Class::Full {
                    seat_misses[index] = seat_misses[index].saturating_add(1);
                    continue;
                }
                active_seats += u64::from(node.seats);
                let weather = draw(config.seed, height, index);
                let lost = weather % 1000 < config.loss_per_mille;
                let extra_delay = (weather >> 16) % 3_000;
                let delivered = !lost && node.latency_ms + extra_delay <= params.slot_ms;
                if delivered {
                    votes += u64::from(node.seats);
                    seat_misses[index] = 0;
                } else {
                    seat_misses[index] = seat_misses[index].saturating_add(1);
                }
            }
            // Instant seat handover: a seat absent from two consecutive
            // participation records passes to its standby within three
            // checkpoint intervals (directive 7.5 and 7.6). The standby is an
            // online Full node, so the seat stays in the committee.
            for index in 0..nodes.len() {
                if seat_misses[index] >= 2 && nodes[index].class == Class::Full {
                    let standby = (0..nodes.len()).find(|candidate| {
                        nodes[*candidate].class == Class::Full
                            && nodes[*candidate].online
                            && *candidate != index
                    });
                    if let Some(standby) = standby {
                        if nodes[index].seats > 0 {
                            let moved = nodes[index].seats;
                            nodes[index].seats = 0;
                            nodes[standby].seats = nodes[standby].seats.saturating_add(moved);
                            seat_misses[index] = 0;
                        }
                    }
                }
            }

            // Finality: more than two thirds of the active seats (directive
            // 7.4).
            let quorum = votes * quorum_den > active_seats * quorum_num;
            if quorum && active_seats > 0 {
                report.finalized_heights.push(height);
                gap_checkpoints = 0;
            } else {
                gap_checkpoints = gap_checkpoints.saturating_add(1);
                report.max_finality_gap_intervals =
                    report.max_finality_gap_intervals.max(gap_checkpoints);
            }
        }
    }
    report
}

/// The baseline schedule this tool simulates: testnet, checkpoint every 5
/// blocks, epoch 50 slots, repair bound 20 blocks. If the schedule moves, the
/// simulation must move with it.
#[test]
fn churn_runs_on_the_testnet_schedule() {
    assert_eq!(
        finality_checkpoint_interval_for_chain_id(TESTNET_CHAIN_ID),
        5
    );
    assert_eq!(
        Network::from_chain_id(TESTNET_CHAIN_ID).map(|network| network.epoch_len()),
        Some(50)
    );
    assert_eq!(REPAIR_TASK_START_BLOCKS, 20);
}

/// Ten percent of the Full validators stop at once. Finality keeps advancing
/// and the extra delay is at most two checkpoint intervals (directive 7.7 and
/// the WP-14 done criterion).
#[test]
fn ten_percent_full_departure_keeps_finality() {
    let full_nodes = 40;
    let mobile_nodes = 20;
    let baseline_config = SimConfig {
        full_nodes,
        mobile_nodes,
        blocks: 400,
        loss_per_mille: 20,
        piece_count: 64,
        seed: 0x5EED,
        departures: Vec::new(),
    };
    let departed: Vec<usize> = (0..(full_nodes / 10)).collect();
    let departure_config = SimConfig {
        departures: vec![Departure {
            at_block: 100,
            nodes: departed,
            returns: false,
            absence_blocks: 0,
        }],
        ..baseline_config.clone()
    };

    let baseline = run(&baseline_config);
    let after = run(&departure_config);

    assert!(
        !baseline.finalized_heights.is_empty(),
        "the baseline must finalize"
    );
    assert!(
        !after.finalized_heights.is_empty(),
        "finality must keep advancing after the departure"
    );
    assert!(
        after.finalized_heights[after.finalized_heights.len() - 1] > 350,
        "finality must reach the end of the run"
    );
    // The extra delay of every checkpoint is at most two intervals.
    for height in &after.finalized_heights {
        if *height < 100 {
            continue;
        }
        let baseline_next = baseline
            .finalized_heights
            .iter()
            .find(|candidate| **candidate >= *height)
            .copied()
            .unwrap_or(u64::MAX);
        let extra = height.saturating_sub(baseline_next);
        assert!(
            extra <= 2 * finality_checkpoint_interval_for_chain_id(TESTNET_CHAIN_ID),
            "finality at {height} runs {extra} blocks behind the baseline"
        );
    }
    assert!(
        after.max_finality_gap_intervals <= 2,
        "a finality gap crossed two checkpoint intervals"
    );
    assert!(
        after.piece_min_holders >= 1,
        "no piece may lose its last holder"
    );
}

/// Every Mobile validator stops at once. Mobiles hold no finality seats, so
/// the finality timeline is untouched, and class-aware placement keeps every
/// piece alive (directive 1.3 and the WP-14 done criterion).
#[test]
fn all_mobile_departure_does_not_touch_finality() {
    let baseline_config = SimConfig {
        full_nodes: 40,
        mobile_nodes: 20,
        blocks: 400,
        loss_per_mille: 20,
        piece_count: 64,
        seed: 0x5EED,
        departures: Vec::new(),
    };
    let mobiles: Vec<usize> = (40..60).collect();
    let departure_config = SimConfig {
        departures: vec![Departure {
            at_block: 100,
            nodes: mobiles,
            returns: false,
            absence_blocks: 0,
        }],
        ..baseline_config.clone()
    };

    let baseline = run(&baseline_config);
    let after = run(&departure_config);

    assert_eq!(
        baseline.finalized_heights, after.finalized_heights,
        "mobile validators hold no seats; the finality timeline must be identical"
    );
    assert!(
        after.piece_min_holders >= 1,
        "no piece may lose its last holder"
    );
    assert!(
        baseline.piece_min_holders >= 1,
        "no piece may lose its last holder in the baseline either"
    );
}

/// Random leave and return churn (directive 7.6: the tool produces random
/// departures and returns). Finality never stops for more than two intervals
/// and no piece loses its last holder while holders come and go.
#[test]
fn churn_random_leave_and_return_keeps_finality() {
    let config = SimConfig {
        full_nodes: 30,
        mobile_nodes: 30,
        blocks: 600,
        loss_per_mille: 40,
        piece_count: 96,
        seed: 0xC0FFEE,
        departures: vec![
            Departure {
                at_block: 50,
                nodes: vec![0, 1, 2, 30, 31],
                returns: true,
                absence_blocks: 40,
            },
            Departure {
                at_block: 150,
                nodes: vec![3, 4, 5, 32, 33, 34],
                returns: true,
                absence_blocks: 60,
            },
            Departure {
                at_block: 300,
                nodes: vec![6, 7, 8, 9, 35, 36, 37],
                returns: true,
                absence_blocks: 80,
            },
            Departure {
                at_block: 450,
                nodes: vec![10, 11, 38, 39, 40],
                returns: true,
                absence_blocks: 50,
            },
        ],
    };
    let report = run(&config);
    assert!(
        !report.finalized_heights.is_empty(),
        "finality must survive random churn"
    );
    assert!(
        report.max_finality_gap_intervals <= 2,
        "random churn pushed a finality gap past two checkpoint intervals"
    );
    assert!(
        report.piece_min_holders >= 1,
        "random churn lost the last holder of a piece"
    );
}
