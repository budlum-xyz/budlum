//! The multi-node devnet smoke test: four genesis validators and a joiner.
//!
//! It replaces `ops/scripts/devnet-multinode-smoke.sh`. It brings the 4-node
//! `PoS` docker-compose devnet up and checks the claims below. All RPC goes
//! through node1 (`127.0.0.1:8545`); node2..4 deliberately open no RPC, which
//! the compose files enforce.
//!
//! 1. `bud_netListening` is true: the P2P stack is alive.
//! 2. node1 `bud_netPeerCount` is at least 3, and every follower's own
//!    `budlum_p2p_peers_connected` gauge is at least 1. The star that compose
//!    dials (node2..4 to node1) is up, seen from both ends. Links between
//!    followers are not asserted: compose dials only node1, so a mesh between
//!    followers would be discovery luck, not a property worth promising.
//! 3. `bud_blockNumber` grows across two measurements: consensus is live.
//! 4. `/metrics` on `127.0.0.1:9090` answers 2xx with a non-empty body.
//! 5. The operator RPC `127.0.0.1:8546` is unreachable from the host. If it
//!    leaks, the run fails.
//! 6. node2's chain height reaches node1's: a follower really syncs. Steps 1
//!    to 5 are all measured through node1, so a network whose followers never
//!    sync used to pass them. node2 opens no RPC, so its height is read from
//!    its own `/metrics` inside the container.
//! 7. Every one of the four validators produced at least one block: `PoS`
//!    leadership rotates by VRF, it is not one node producing for everyone
//!    .
//! 8. `bud_getStatus.finalizedHeight` is above 0 and grows: finality
//!    certificates form at the checkpoints.
//! 9. A validator joins while the chain runs: node5, funded at genesis but
//!    not in its validator set, sends `Stake` and `RegisterConsensusKeys`
//!    with `bud validator join` and then produces a block of its own.
//! 10. A node stops, restarts and syncs: node3 is stopped while the others
//!     keep producing, started again, and its tip reaches node1's.
//!
//! The tool does not tear the compose project down; the workflow does that in
//! its own always-run step, so the logs stay available on failure.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::rpc;

const RPC_PORT: u16 = 8545;
const METRICS_PORT: u16 = 9090;
const OPERATOR_PORT: u16 = 8546;
const PROJECT: &str = "budlum-multinode-smoke";
/// The CI overlay turns off RPC auth and publishes 8545. The base file stays
/// authenticated so it is safe to copy; the smoke probes need the
/// unauthenticated listener, so they ask for it explicitly.
const COMPOSE_FILES: [&str; 4] = [
    "-f",
    "ops/docker-compose.yml",
    "-f",
    "ops/docker-compose.ci.yml",
];

const PAUSE: Duration = Duration::from_secs(2);

fn pause(d: Duration) {
    std::thread::sleep(d);
}

/// Call node1 over RPC with the 5 second bound the shell version used.
fn node1(method: &str) -> Result<String, String> {
    rpc::call(RPC_PORT, method, "[]", Duration::from_secs(5))
}

fn compose(root: &Path, extra: &[&str]) -> Option<String> {
    compose_result(root, extra).ok()
}

/// `compose`, keeping the reason a call failed.
///
/// A command that exits non-zero used to come back as `None` with its stderr
/// dropped, so a step that runs a CLI inside a container (`bud validator
/// join`) could fail for a reason the job log never showed. The stderr tail is
/// part of the failure here, not a separate diagnosis someone has to guess at.
fn compose_result(root: &Path, extra: &[&str]) -> Result<String, String> {
    let out = Command::new("docker")
        .arg("compose")
        .args(COMPOSE_FILES)
        .args(["-p", PROJECT])
        .args(extra)
        .current_dir(root)
        .output()
        .map_err(|e| format!("docker could not be run: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let tail: String = stderr
        .lines()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    Err(format!(
        "`docker compose {}` exited {}: {tail}",
        extra.join(" "),
        out.status.code().map_or_else(|| "abnormally".into(), |c| c.to_string())
    ))
}

/// The metrics page of one container, read from inside it.
fn container_metrics(root: &Path, node: &str) -> Option<String> {
    compose(
        root,
        &[
            "exec",
            "-T",
            node,
            "curl",
            "-sf",
            "--max-time",
            "4",
            &format!("http://127.0.0.1:{METRICS_PORT}/metrics"),
        ],
    )
}

/// The node1 tip from a `bud_blockNumber` reply.
#[must_use]
pub fn block_number(body: &str) -> Option<u64> {
    rpc::result_string(body).and_then(|s| rpc::parse_hex_quantity(&s))
}

/// The peer count from a `bud_netPeerCount` reply; anything unreadable is 0,
/// as the shell version defaulted to `0x0`.
#[must_use]
pub fn peer_count(body: &str) -> u64 {
    rpc::result_string(body)
        .and_then(|s| rpc::parse_hex_quantity(&s))
        .unwrap_or(0)
}

/// The value of the metric `name` on a Prometheus page: the first line whose
/// first field is exactly the name, truncated to an integer. `None` when no
/// line matches. Labelled series (`name{...}`) do not match.
#[must_use]
pub fn metric_value(page: &str, name: &str) -> Option<i64> {
    page.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some(name)).then(|| {
            // awk's `int()`: cut the fraction, and read a non-number as 0.
            let value = fields
                .next()
                .and_then(|f| f.parse::<f64>().ok())
                .unwrap_or(0.0);
            format!("{:.0}", value.trunc()).parse::<i64>().unwrap_or(0)
        })
    })
}

/// The highest block in "Added block #N to local chain" log lines.
#[must_use]
pub fn logged_tip(logs: &str) -> Option<u64> {
    const OPEN: &str = "Added block #";
    const CLOSE: &str = " to local chain";
    logs.lines()
        .filter_map(|line| {
            let after = &line[line.find(OPEN)? + OPEN.len()..];
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            after[digits.len()..]
                .starts_with(CLOSE)
                .then(|| digits.parse::<u64>().ok())
                .flatten()
        })
        .max()
}

/// The gauge is the chain length; the RPC speaks tip indexes (length minus
/// one). A length below 1 means "no tip yet" and stays at -1.
#[must_use]
pub fn tip_from_gauge(length: i64) -> i64 {
    if length >= 1 {
        length - 1
    } else {
        -1
    }
}

/// Lag is bounded in both directions: a follower tip ahead of node1 is a
/// divergent or stale reading, not a synced follower. Within one block is what
/// a live follower looks like while node1 keeps producing.
#[must_use]
pub fn is_synced(node1_tip: i64, node2_tip: i64) -> bool {
    node1_tip > 0 && node2_tip >= 0 && node2_tip <= node1_tip && node1_tip - node2_tip <= 1
}

/// Run the smoke test.
///
/// # Errors
///
/// The first failed step, named with its measurements.
pub fn run(root: &Path) -> Result<String, String> {
    println!("== [0/10] compose up (ceremony, 4 validators, a joiner, prometheus) ==");
    if compose_up(root).is_err() {
        return Err("docker compose up".to_string());
    }
    step1_ready()?;
    step2_peers(root)?;
    step3_liveness()?;
    step4_metrics()?;
    step5_isolation()?;
    step6_sync(root)?;
    step7_producers()?;
    step8_finality(root)?;
    step9_join(root)?;
    step10_restart(root)?;
    Ok("DEVNET-MULTINODE-SMOKE: 10/10 PASS".to_string())
}

fn compose_up(root: &Path) -> Result<(), String> {
    let status = Command::new("docker")
        .arg("compose")
        .args(COMPOSE_FILES)
        .args(["-p", PROJECT, "up", "-d"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("docker could not be run: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("docker compose up failed".to_string())
    }
}

fn step1_ready() -> Result<(), String> {
    println!("== [1/10] RPC readiness: bud_netListening (max 120 s) ==");
    for _ in 0..60 {
        if node1("bud_netListening").is_ok_and(|b| b.contains("\"result\":true")) {
            println!("PASS [1/10]: bud_netListening=true");
            return Ok(());
        }
        pause(PAUSE);
    }
    Err("bud_netListening did not become true within 120 s".to_string())
}

fn step2_peers(root: &Path) -> Result<(), String> {
    println!(
        "== [2/10] peer connectivity: node1 bud_netPeerCount >= 0x3, node2..5 gauge >= 1 (max 120 s) =="
    );
    // The peer count node1 reports over RPC grows only on a connection that
    // was really established. On its own it proves node1's fanout, nothing
    // about the other end: the same three connections are therefore read
    // again from each follower's own gauge, inside the container.
    let mut count = 0;
    for _ in 0..60 {
        count = node1("bud_netPeerCount").map_or(0, |b| peer_count(&b));
        if count >= 3 {
            break;
        }
        pause(PAUSE);
    }
    if count < 3 {
        return Err(format!(
            "node1 did not reach three peers (bud_netPeerCount=0x{count:x}, expected >= 0x3)"
        ));
    }
    let mut report = String::new();
    for node in ["node2", "node3", "node4", "node5"] {
        let mut peers = -1;
        for _ in 0..30 {
            peers = container_metrics(root, node).map_or(-1, |page| {
                metric_value(&page, "budlum_p2p_peers_connected").unwrap_or(-1)
            });
            if peers >= 1 {
                break;
            }
            pause(PAUSE);
        }
        if peers < 1 {
            return Err(format!(
                "{node} reports no connected peer (budlum_p2p_peers_connected={peers}; -1: gauge unreadable)"
            ));
        }
        let _ = write!(report, " {node}={peers}");
    }
    println!(
        "PASS [2/10]: connectivity (node1 bud_netPeerCount=0x{count:x} -> {count} peers; follower gauges:{report})"
    );
    Ok(())
}

fn step3_liveness() -> Result<(), String> {
    println!("== [3/10] consensus liveness: bud_blockNumber grows (a max 20 s window) ==");
    let first = node1("bud_blockNumber")
        .ok()
        .and_then(|b| block_number(&b))
        .ok_or_else(|| "bud_blockNumber could not be read".to_string())?;
    let mut latest = first;
    for _ in 0..4 {
        pause(Duration::from_secs(5));
        if let Some(h) = node1("bud_blockNumber").ok().and_then(|b| block_number(&b)) {
            latest = h;
            if latest > first {
                println!("PASS [3/10]: liveness ({first} -> {latest})");
                return Ok(());
            }
        }
    }
    Err(format!("the height is not advancing ({first} -> {latest})"))
}

fn step4_metrics() -> Result<(), String> {
    println!("== [4/10] /metrics endpoint ==");
    // A retry loop: the metrics server is opened with tokio::spawn, so when
    // the RPC is ready (step 1) it may not be listening yet. The gate is not
    // weakened: the metrics must still really return 2xx with a non-empty
    // body; it merely waits.
    let mut body = String::new();
    for _ in 0..30 {
        if let Ok(reply) = rpc::request(
            "GET",
            METRICS_PORT,
            "/metrics",
            None,
            Duration::from_secs(5),
        ) {
            if reply.is_success() {
                body = reply.body;
                break;
            }
        }
        pause(PAUSE);
    }
    if body.is_empty() {
        return Err("/metrics is unreachable (HTTP != 2xx after 30 attempts)".to_string());
    }
    println!(
        "PASS [4/10]: /metrics 2xx ({} lines)",
        body.matches('\n').count()
    );
    Ok(())
}

fn step5_isolation() -> Result<(), String> {
    println!("== [5/10] operator RPC isolation (8546 must be closed from the host) ==");
    // `curl -s` without `-f` succeeds on any HTTP answer, whatever its
    // status. Any answer here means the port is open to the host.
    if rpc::request("GET", OPERATOR_PORT, "/", None, Duration::from_secs(2)).is_ok() {
        return Err(
            "the operator RPC 127.0.0.1:8546 is reachable from the host - LEAK".to_string(),
        );
    }
    println!("PASS [5/10]: the operator RPC is unreachable from the host (connection refused)");
    Ok(())
}

fn step6_sync(root: &Path) -> Result<(), String> {
    println!(
        "== [6/10] follower sync: node2 budlum_chain_height reaches node1 bud_blockNumber (max 120 s) =="
    );
    let (n1, n2) = wait_synced(root, "node2")?;
    println!("PASS [6/10]: follower sync (node1={n1}, node2={n2})");
    Ok(())
}

/// Wait up to 120 s until `node`'s tip is within one block of node1's.
///
/// node1's height says nothing about whether anyone else follows. The
/// followers open no RPC to the host; a follower's height is the
/// `budlum_chain_height` gauge on its own metrics listener, read from inside
/// the container, converted to a tip index before comparing.
///
/// The raw read names its failure: -1 means the metrics page could not be
/// fetched, -2 means the page came back without the gauge.
///
/// A second witness, independent of the metrics listener: the follower logs
/// "Added block #N to local chain" for every block it validates. The highest
/// N in its log is its tip as seen by the node itself.
fn wait_synced(root: &Path, node: &str) -> Result<(i64, i64), String> {
    let mut dump = String::new();
    let (mut n1, mut tip, mut raw, mut logged) = (0i64, -1i64, -1i64, None);
    for _ in 0..60 {
        n1 = node1("bud_blockNumber")
            .ok()
            .and_then(|b| block_number(&b))
            .and_then(|h| i64::try_from(h).ok())
            .unwrap_or(0);
        if let Some(page) = container_metrics(root, node) {
            raw = metric_value(&page, "budlum_chain_height").unwrap_or(-2);
            dump = page;
        } else {
            raw = -1;
            dump.clear();
        }
        logged = compose(root, &["logs", "--no-color", "--no-log-prefix", node])
            .and_then(|logs| logged_tip(&logs));
        tip = tip_from_gauge(raw);
        // The log witness is used when it is ahead of the gauge.
        if let Some(l) = logged.and_then(|l| i64::try_from(l).ok()) {
            if l > tip {
                tip = l;
            }
        }
        if is_synced(n1, tip) {
            return Ok((n1, tip));
        }
        pause(PAUSE);
    }
    println!(
        "{node} metrics read: raw gauge={raw} (-1: fetch failed, -2: gauge absent); logged tip={}",
        logged.map_or_else(|| "none".to_string(), |l| l.to_string())
    );
    println!("{}", crate::support::head_lines(&dump, 5));
    Err(format!(
        "{node} did not catch up with node1 (node1={n1}, {node} tip={tip})"
    ))
}

/// How many validators the compose ceremony makes.
const VALIDATORS: usize = 4;

/// The producer of block `number`, read through node1.
fn producer_of(number: u64) -> Option<String> {
    let body = rpc::call(
        RPC_PORT,
        "bud_getBlockByNumber",
        &format!("[{number}]"),
        Duration::from_secs(5),
    )
    .ok()?;
    producer_field(&body)
}

/// The `producer` of a `bud_getBlockByNumber` reply; `None` for a block
/// without one or an unreadable reply.
#[must_use]
pub fn producer_field(body: &str) -> Option<String> {
    crate::json::parse(body)
        .ok()?
        .get("result")?
        .get("producer")?
        .as_str()
        .map(str::to_string)
}

fn step7_producers() -> Result<(), String> {
    println!(
        "== [7/10] VRF leadership: each of the {VALIDATORS} validators produced a block (max 240 s) =="
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut scanned = 0u64;
    for _ in 0..120 {
        let tip = node1("bud_blockNumber")
            .ok()
            .and_then(|b| block_number(&b))
            .unwrap_or(0);
        while scanned < tip {
            scanned += 1;
            if let Some(producer) = producer_of(scanned) {
                seen.insert(producer);
            }
        }
        if seen.len() >= VALIDATORS {
            println!(
                "PASS [7/10]: {} distinct producers in blocks 1..={scanned}",
                seen.len()
            );
            return Ok(());
        }
        pause(PAUSE);
    }
    Err(format!(
        "only {} of {VALIDATORS} validators produced in blocks 1..={scanned}: {seen:?}",
        seen.len()
    ))
}

/// `finalizedHeight` of a `bud_getStatus` reply.
#[must_use]
pub fn finalized_height(body: &str) -> Option<u64> {
    match crate::json::parse(body)
        .ok()?
        .get("result")?
        .get("finalizedHeight")?
    {
        crate::json::Value::Number(n) => n.parse().ok(),
        _ => None,
    }
}

fn step8_finality(root: &Path) -> Result<(), String> {
    println!("== [8/10] finality: bud_getStatus.finalizedHeight > 0 and grows (max 240 s) ==");
    let mut first = None;
    for _ in 0..120 {
        let height = node1("bud_getStatus")
            .ok()
            .and_then(|b| finalized_height(&b))
            .unwrap_or(0);
        match first {
            None if height > 0 => first = Some(height),
            Some(start) if height > start => {
                println!("PASS [8/10]: finality advances ({start} -> {height})");
                return Ok(());
            }
            _ => {}
        }
        pause(PAUSE);
    }
    finality_log_witness(root);
    Err(format!(
        "finality did not advance (first finalized height seen: {first:?})"
    ))
}

/// The last finality-relevant lines of every node, printed when step 8 fails.
///
/// Without them the job log carries only the last 150 lines each container
/// wrote, which on a producing chain is block gossip: a vote that was never
/// cast and a vote that was rejected look identical from the assertion above,
/// and it only ever says the height stayed zero.
fn finality_log_witness(root: &Path) {
    const NEEDLES: [&str; 6] = [
        "prevote",
        "precommit",
        "finality",
        "finaliz",
        "quorum",
        "qc",
    ];
    for node in ["node1", "node2", "node3", "node4", "node5"] {
        // The two heights first: a mesh whose nodes disagree on the tip cannot
        // finalize whatever its vote logs say, and the difference between a
        // node that never voted and a node that is nine hundred blocks behind
        // is one number.
        match container_metrics(root, node) {
            Some(page) => println!(
                "[{node}] heights: chain={:?} finalized={:?} active_validators={:?}",
                metric_value(&page, "budlum_chain_height"),
                metric_value(&page, "budlum_finalized_height"),
                metric_value(&page, "budlum_active_validators")
            ),
            None => println!("[{node}] heights: metrics page unavailable"),
        }
        let Some(logs) = compose(root, &["logs", "--no-color", "--no-log-prefix", node]) else {
            println!("[{node}] logs unavailable");
            continue;
        };
        let mut printed = 0usize;
        for line in logs.lines() {
            let lower = line.to_ascii_lowercase();
            if NEEDLES.iter().any(|needle| lower.contains(needle)) {
                println!("[{node}] {line}");
                printed += 1;
                if printed >= 80 {
                    break;
                }
            }
        }
        if printed == 0 {
            println!("[{node}] no finality lines");
        }
    }
}

/// The address `bud validator join` reports: the hex word after
/// "validator " on its last line.
#[must_use]
pub fn joined_address(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let rest = line.strip_prefix("validator ")?;
        let word = rest.split_whitespace().next()?;
        (word.len() == 64 && word.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| word.to_ascii_lowercase())
    })
}

/// Does a block's `producer` name `address`? Both sides are hex; a `0x`
/// prefix and letter case do not matter.
#[must_use]
pub fn same_address(producer: &str, address: &str) -> bool {
    let clean = |text: &str| text.trim_start_matches("0x").to_ascii_lowercase();
    clean(producer) == clean(address)
}

fn step9_join(root: &Path) -> Result<(), String> {
    println!(
        "== [9/10] join: node5 bonds stake and registers its keys, then produces a block (max 240 s) =="
    );
    // The join runs inside node1's container against its own public RPC;
    // the key file sits on the read-only ceremony volume every node mounts.
    // The join is retried, not assumed: it is the one step that drives a CLI
    // from outside the node, and a transaction the mempool has not admitted
    // yet (an RPC that is one block behind, a node rotating its provider)
    // reads exactly like a refusal. The last error is what the job shows when
    // every attempt fails.
    let mut joined = None;
    let mut last_error = String::new();
    for attempt in 0..5 {
        match compose_result(
            root,
            &[
                "exec",
                "-T",
                "node1",
                "bud",
                "--rpc-url",
                "http://127.0.0.1:8545",
                "validator",
                "join",
                "--key-file",
                "/home/budlum/ceremony/node5.key",
                "--stake-bud",
                "1",
            ],
        ) {
            Ok(output) => {
                joined = Some(output);
                break;
            }
            Err(e) => {
                println!("attempt {}/5: {e}", attempt + 1);
                last_error = e;
            }
        }
        pause(PAUSE);
    }
    let output = joined
        .ok_or_else(|| format!("bud validator join failed inside node1: {last_error}"))?;
    let address = joined_address(&output)
        .ok_or_else(|| format!("bud validator join printed no address: {output}"))?;
    let mut scanned = node1("bud_blockNumber")
        .ok()
        .and_then(|b| block_number(&b))
        .unwrap_or(0);
    let joined_at = scanned;
    for _ in 0..120 {
        let tip = node1("bud_blockNumber")
            .ok()
            .and_then(|b| block_number(&b))
            .unwrap_or(0);
        while scanned < tip {
            scanned += 1;
            if producer_of(scanned).is_some_and(|producer| same_address(&producer, &address)) {
                println!("PASS [9/10]: joined validator {address} produced block {scanned}");
                return Ok(());
            }
        }
        pause(PAUSE);
    }
    Err(format!(
        "joined validator {address} produced no block in {joined_at}..={scanned}"
    ))
}

fn step10_restart(root: &Path) -> Result<(), String> {
    println!("== [10/10] restart: node3 stops, the chain moves on, node3 restarts and syncs ==");
    compose(root, &["stop", "node3"]).ok_or("docker compose stop node3 failed")?;
    let stopped_at = node1("bud_blockNumber")
        .ok()
        .and_then(|b| block_number(&b))
        .unwrap_or(0);
    // Let the remaining validators produce past the stop point, so the
    // restarted node has blocks to fetch rather than a tip it already holds.
    let mut moved = false;
    for _ in 0..30 {
        pause(PAUSE);
        let tip = node1("bud_blockNumber")
            .ok()
            .and_then(|b| block_number(&b))
            .unwrap_or(0);
        if tip >= stopped_at.saturating_add(5) {
            moved = true;
            break;
        }
    }
    if !moved {
        return Err(format!(
            "the chain did not move on while node3 was down (stopped at {stopped_at})"
        ));
    }
    compose(root, &["start", "node3"]).ok_or("docker compose start node3 failed")?;
    let (n1, n3) = wait_synced(root, "node3")?;
    println!("PASS [10/10]: node3 restarted and synced (node1={n1}, node3={n3}, stopped at {stopped_at})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_joined_address_and_compares_producers() {
        let hex = "ab".repeat(32);
        let output = format!(
            "stake sent: 0x01\nconsensus keys sent: 0x02\nvalidator {hex} is active from the next epoch once both are in a block\n"
        );
        assert_eq!(joined_address(&output), Some(hex.clone()));
        assert_eq!(joined_address("validator keys sent"), None);
        assert!(same_address(&format!("0x{}", hex.to_uppercase()), &hex));
        assert!(!same_address(&"cd".repeat(32), &hex));
    }

    #[test]
    fn reads_block_numbers_and_peer_counts() {
        assert_eq!(block_number(r#"{"result":"0x2a"}"#), Some(42));
        assert_eq!(block_number(r#"{"result":"nope"}"#), None);
        assert_eq!(block_number("garbage"), None);
        assert_eq!(peer_count(r#"{"result":"0x3"}"#), 3);
        assert_eq!(peer_count(r#"{"result":"0x10"}"#), 16);
        assert_eq!(peer_count("garbage"), 0);
        assert_eq!(peer_count(r#"{"error":{}}"#), 0);
    }

    #[test]
    fn metric_value_matches_the_exact_name_only() {
        let page = "# HELP x\nbudlum_p2p_peers_connected 3\nbudlum_chain_height 17.0\nbudlum_chain_height{shard=\"1\"} 99\n";
        assert_eq!(metric_value(page, "budlum_p2p_peers_connected"), Some(3));
        assert_eq!(metric_value(page, "budlum_chain_height"), Some(17));
        assert_eq!(metric_value(page, "budlum_p2p_peers"), None);
        assert_eq!(metric_value("", "budlum_chain_height"), None);
        assert_eq!(
            metric_value("budlum_chain_height 1e3\n", "budlum_chain_height"),
            Some(1000)
        );
    }

    #[test]
    fn a_gauge_at_zero_reads_zero_not_absent() {
        assert_eq!(
            metric_value("budlum_chain_height 0\n", "budlum_chain_height"),
            Some(0)
        );
    }

    #[test]
    fn logged_tip_takes_the_highest_block() {
        let logs = "x Added block #7 to local chain\nAdded block #12 to local chain\nAdded block #9 to local chain\nAdded block #99 to remote chain\nAdded block # to local chain\n";
        assert_eq!(logged_tip(logs), Some(12));
        assert_eq!(logged_tip("nothing here"), None);
    }

    #[test]
    fn the_gauge_is_a_length_and_the_rpc_a_tip_index() {
        assert_eq!(tip_from_gauge(0), -1);
        assert_eq!(tip_from_gauge(1), 0);
        assert_eq!(tip_from_gauge(18), 17);
        assert_eq!(tip_from_gauge(-2), -1);
    }

    #[test]
    fn sync_is_within_one_block_and_never_ahead() {
        assert!(is_synced(10, 10));
        assert!(is_synced(10, 9));
        assert!(!is_synced(10, 8));
        assert!(!is_synced(10, 11), "ahead of node1 is a divergent reading");
        assert!(!is_synced(0, 0), "node1 at genesis proves nothing");
        assert!(!is_synced(10, -1));
        assert!(is_synced(1, 0));
    }
}
