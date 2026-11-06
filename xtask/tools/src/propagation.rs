//! `propagation-sim`: the block propagation measurement of
//!.
//!
//! A deterministic discrete-event simulation of store-and-forward gossip:
//! `nodes` nodes, each linked to `degree` random peers, every link with its
//! own one-way latency, every node with one uplink of `uplink_mbit`. A node
//! that has the whole block validates it for `validate_ms` and then sends it
//! to each peer that has not offered it yet, one after another over its
//! uplink. The measure is the p95 over nodes of the time the block reaches
//! them, for a block of `body + witness` bytes.
//!
//! The witness budget starts at 2,000,000 bytes and drops in 250,000-byte
//! steps until p95 is under 1,000 ms; the largest budget that meets the target
//! is the result. Every parameter is a TESTNET-DEFAULT, not
//! a measurement of a real network; the table says so.
//!
//! ```text
//! propagation-sim            print the table
//! propagation-sim --write    write docs/pq/PROPAGATION.md
//! propagation-sim --check    fail when the file differs from the table
//! ```

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt::Write;
use std::path::Path;

const DOC: &str = "docs/pq/PROPAGATION.md";

/// Body budget of, bytes.
pub const BODY_BUDGET: u64 = 1_000_000;
/// Witness budget starts from, bytes.
pub const WITNESS_START: u64 = 2_000_000;
/// Fallback step, bytes.
pub const WITNESS_STEP: u64 = 250_000;
/// The p95 target, milliseconds.
pub const TARGET_P95_MS: u64 = 1_000;

/// The simulated network. TESTNET-DEFAULT values.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub nodes: usize,
    pub degree: usize,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub uplink_mbit: u64,
    pub validate_ms: u64,
    pub seed: u64,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            nodes: 64,
            degree: 8,
            min_latency_ms: 20,
            max_latency_ms: 120,
            uplink_mbit: 1_000,
            validate_ms: 50,
            seed: 0x4255_444C_554D,
        }
    }
}

/// A 64-bit linear congruential generator (Knuth MMIX constants): the
/// simulation must give the same table on every machine.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next() % bound
        }
    }
}

/// Adjacency with a latency per link, symmetric. A ring keeps the graph
/// connected; random chords bring every node to `degree` links.
fn topology(params: &Params) -> Vec<Vec<(usize, u64)>> {
    let n = params.nodes;
    let mut rng = Lcg(params.seed);
    let mut links: Vec<Vec<(usize, u64)>> = vec![Vec::new(); n];
    let span = params.max_latency_ms.saturating_sub(params.min_latency_ms) + 1;
    let connect = |a: usize, b: usize, rng: &mut Lcg, links: &mut Vec<Vec<(usize, u64)>>| {
        if a == b || links[a].iter().any(|(peer, _)| *peer == b) {
            return;
        }
        let latency = params.min_latency_ms + rng.below(span);
        links[a].push((b, latency));
        links[b].push((a, latency));
    };
    for a in 0..n {
        connect(a, (a + 1) % n, &mut rng, &mut links);
    }
    let mut attempts = 0usize;
    while links.iter().any(|l| l.len() < params.degree) && attempts < n * params.degree * 16 {
        attempts += 1;
        let a = usize::try_from(rng.below(n as u64)).unwrap_or(0);
        let b = usize::try_from(rng.below(n as u64)).unwrap_or(0);
        if links[a].len() < params.degree && links[b].len() < params.degree {
            connect(a, b, &mut rng, &mut links);
        }
    }
    links
}

/// Arrival time (ms) of a `block_bytes` block at every node, the producer
/// being node 0 at time 0.
#[must_use]
pub fn arrivals(params: &Params, block_bytes: u64) -> Vec<u64> {
    let links = topology(params);
    let n = params.nodes;
    // Milliseconds to push the block through one uplink, rounded up.
    let bits = block_bytes.saturating_mul(8);
    let per_ms = params.uplink_mbit.max(1).saturating_mul(1_000);
    let send_ms = bits.div_ceil(per_ms);
    let mut arrival = vec![u64::MAX; n];
    let mut queue = BinaryHeap::new();
    arrival[0] = 0;
    queue.push(Reverse((0u64, 0usize)));
    while let Some(Reverse((time, node))) = queue.pop() {
        if time > arrival[node] {
            continue;
        }
        // The producer built the block; every other node validates it first.
        let ready = if node == 0 {
            time
        } else {
            time + params.validate_ms
        };
        let mut uplink_free = ready;
        for &(peer, latency) in &links[node] {
            if arrival[peer] <= ready {
                continue;
            }
            uplink_free += send_ms;
            let at = uplink_free + latency;
            if at < arrival[peer] {
                arrival[peer] = at;
                queue.push(Reverse((at, peer)));
            }
        }
    }
    arrival
}

/// The p95 of the arrival times, nearest rank.
#[must_use]
pub fn p95(mut times: Vec<u64>) -> u64 {
    if times.is_empty() {
        return 0;
    }
    times.sort_unstable();
    let rank = (times.len() * 95).div_ceil(100).max(1);
    times[rank - 1]
}

/// One row: witness budget and its p95.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub witness: u64,
    pub p95_ms: u64,
}

/// The fallback search: every budget from the start down to the first that
/// meets the target (or to zero).
#[must_use]
pub fn search(params: &Params) -> (Vec<Row>, Option<u64>) {
    let mut rows = Vec::new();
    let mut witness = WITNESS_START;
    loop {
        let p95_ms = p95(arrivals(params, BODY_BUDGET + witness));
        rows.push(Row { witness, p95_ms });
        if p95_ms < TARGET_P95_MS {
            return (rows, Some(witness));
        }
        if witness < WITNESS_STEP {
            return (rows, None);
        }
        witness -= WITNESS_STEP;
    }
}

/// The document the tool writes.
#[must_use]
pub fn render(params: &Params) -> String {
    let (rows, chosen) = search(params);
    let mut out = String::new();
    out.push_str("# Block propagation\n\n");
    out.push_str(
        "Generated by `cargo run --manifest-path xtask/tools/Cargo.toml -- propagation-sim --write`.\n\
         Do not edit by hand; CI runs `propagation-sim --check`.\n\n",
    );
    out.push_str(
        "This is a deterministic simulation of store-and-forward gossip, not a measurement of a \
         live network. Every parameter below is a TESTNET-DEFAULT. The live figure comes from the \
         testnet once it runs at full witness budget.\n\n",
    );
    out.push_str("| Parameter | Value |\n|---|---|\n");
    let _ = writeln!(out, "| Nodes | {} |", params.nodes);
    let _ = writeln!(out, "| Peers per node | {} |", params.degree);
    let _ = writeln!(
        out,
        "| One-way link latency | {} to {} ms |",
        params.min_latency_ms, params.max_latency_ms
    );
    let _ = writeln!(out, "| Uplink per node | {} Mbit/s |", params.uplink_mbit);
    let _ = writeln!(
        out,
        "| Validation before relay | {} ms |",
        params.validate_ms
    );
    let _ = writeln!(out, "| Body budget | {BODY_BUDGET} B |");
    let _ = write!(out, "| Target | p95 < {TARGET_P95_MS} ms |\n\n");
    out.push_str(
        "| Witness budget (B) | Block (B) | p95 (ms) | Meets target |\n|---|---|---|---|\n",
    );
    for row in &rows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            row.witness,
            BODY_BUDGET + row.witness,
            row.p95_ms,
            if row.p95_ms < TARGET_P95_MS {
                "yes"
            } else {
                "no"
            }
        );
    }
    out.push('\n');
    match chosen {
        Some(witness) => {
            let _ = writeln!(
                out,
                "Result: the largest witness budget that meets the target is **{witness} bytes**."
            );
        }
        None => {
            out.push_str("Result: no witness budget meets the target under these parameters.\n");
        }
    }
    out
}

/// Run the subcommand.
///
/// # Errors
///
/// A write that fails, or `--check` finding a stale file.
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    let text = render(&Params::default());
    match args.first() {
        None => Ok(text),
        Some(&"--write") => {
            std::fs::write(root.join(DOC), &text)
                .map_err(|e| format!("cannot write {DOC}: {e}"))?;
            Ok(format!("wrote {DOC}"))
        }
        Some(&"--check") => {
            let current = std::fs::read_to_string(root.join(DOC))
                .map_err(|e| format!("cannot read {DOC}: {e}"))?;
            if current == text {
                Ok(format!("{DOC} is current"))
            } else {
                Err(format!("{DOC} is stale; run propagation-sim --write"))
            }
        }
        Some(other) => Err(format!("propagation-sim: unknown argument `{other}`")),
    }
}

/// The canary: a bigger block never arrives earlier, every node is reached,
/// and the search stops at the first budget under the target.
///
/// # Errors
///
/// The first property that does not hold.
pub fn self_test() -> Result<String, String> {
    let params = Params {
        nodes: 12,
        degree: 3,
        ..Params::default()
    };
    let small = arrivals(&params, 10_000);
    let large = arrivals(&params, 3_000_000);
    if small.contains(&u64::MAX) {
        return Err("a node was never reached".into());
    }
    if small.iter().zip(&large).any(|(s, l)| s > l) {
        return Err("a larger block arrived earlier".into());
    }
    if p95(vec![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ]) != 19
    {
        return Err("p95 nearest rank is wrong".into());
    }
    let (rows, chosen) = search(&params);
    if let Some(witness) = chosen {
        if rows.last().map(|r| r.witness) != Some(witness) {
            return Err("the search did not stop at the first budget under the target".into());
        }
    }
    Ok("propagation-sim: gossip is monotone in block size and reaches every node".into())
}
