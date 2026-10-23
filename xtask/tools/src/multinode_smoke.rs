//! The four-node devnet smoke test.
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
//!    to 5 are all measured through node1, which produces the blocks itself,
//!    so a network whose followers never sync used to pass them. node2 opens
//!    no RPC, so its height is read from its own `/metrics` inside the
//!    container.
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
    let out = Command::new("docker")
        .arg("compose")
        .args(COMPOSE_FILES)
        .args(["-p", PROJECT])
        .args(extra)
        .current_dir(root)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
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
    println!("== [0/6] compose up (4 node + prometheus) ==");
    if compose_up(root).is_err() {
        return Err("docker compose up".to_string());
    }
    step1_ready()?;
    step2_peers(root)?;
    step3_liveness()?;
    step4_metrics()?;
    step5_isolation()?;
    step6_sync(root)?;
    Ok("DEVNET-MULTINODE-SMOKE: 6/6 PASS".to_string())
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
    println!("== [1/6] RPC readiness: bud_netListening (max 120 s) ==");
    for _ in 0..60 {
        if node1("bud_netListening").is_ok_and(|b| b.contains("\"result\":true")) {
            println!("PASS [1/6]: bud_netListening=true");
            return Ok(());
        }
        pause(PAUSE);
    }
    Err("bud_netListening did not become true within 120 s".to_string())
}

fn step2_peers(root: &Path) -> Result<(), String> {
    println!(
        "== [2/6] peer connectivity: node1 bud_netPeerCount >= 0x3, node2..4 gauge >= 1 (max 120 s) =="
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
    for node in ["node2", "node3", "node4"] {
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
        "PASS [2/6]: connectivity (node1 bud_netPeerCount=0x{count:x} -> {count} peers; follower gauges:{report})"
    );
    Ok(())
}

fn step3_liveness() -> Result<(), String> {
    println!("== [3/6] consensus liveness: bud_blockNumber grows (a max 20 s window) ==");
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
                println!("PASS [3/6]: liveness ({first} -> {latest})");
                return Ok(());
            }
        }
    }
    Err(format!("the height is not advancing ({first} -> {latest})"))
}

fn step4_metrics() -> Result<(), String> {
    println!("== [4/6] /metrics endpoint ==");
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
        "PASS [4/6]: /metrics 2xx ({} lines)",
        body.matches('\n').count()
    );
    Ok(())
}

fn step5_isolation() -> Result<(), String> {
    println!("== [5/6] operator RPC isolation (8546 must be closed from the host) ==");
    // `curl -s` without `-f` succeeds on any HTTP answer, whatever its
    // status. Any answer here means the port is open to the host.
    if rpc::request("GET", OPERATOR_PORT, "/", None, Duration::from_secs(2)).is_ok() {
        return Err(
            "the operator RPC 127.0.0.1:8546 is reachable from the host - LEAK".to_string(),
        );
    }
    println!("PASS [5/6]: the operator RPC is unreachable from the host (connection refused)");
    Ok(())
}

fn step6_sync(root: &Path) -> Result<(), String> {
    println!(
        "== [6/6] follower sync: node2 budlum_chain_height reaches node1 bud_blockNumber (max 120 s) =="
    );
    // node1 produces the blocks, so its height says nothing about whether
    // anyone else follows. node2 has no RPC by design; its height is the
    // budlum_chain_height gauge on its own metrics listener, read from inside
    // the container. The gauge is converted to a tip index before comparing.
    //
    // The raw read names its failure: -1 means the metrics page could not be
    // fetched, -2 means the page came back without the gauge.
    //
    // A second witness, independent of the metrics listener: the follower
    // logs "Added block #N to local chain" for every block it validates. The
    // highest N in node2's log is its tip as seen by the node itself.
    let mut dump = String::new();
    let (mut n1, mut n2, mut raw, mut logged) = (0i64, -1i64, -1i64, None);
    for _ in 0..60 {
        n1 = node1("bud_blockNumber")
            .ok()
            .and_then(|b| block_number(&b))
            .and_then(|h| i64::try_from(h).ok())
            .unwrap_or(0);
        if let Some(page) = container_metrics(root, "node2") {
            raw = metric_value(&page, "budlum_chain_height").unwrap_or(-2);
            dump = page;
        } else {
            raw = -1;
            dump.clear();
        }
        logged = compose(root, &["logs", "--no-color", "--no-log-prefix", "node2"])
            .and_then(|logs| logged_tip(&logs));
        n2 = tip_from_gauge(raw);
        // The log witness is used when it is ahead of the gauge.
        if let Some(l) = logged.and_then(|l| i64::try_from(l).ok()) {
            if l > n2 {
                n2 = l;
            }
        }
        if is_synced(n1, n2) {
            println!("PASS [6/6]: follower sync (node1={n1}, node2={n2})");
            return Ok(());
        }
        pause(PAUSE);
    }
    println!(
        "node2 metrics read: raw gauge={raw} (-1: fetch failed, -2: gauge absent); logged tip={}",
        logged.map_or_else(|| "none".to_string(), |l| l.to_string())
    );
    println!("{}", crate::support::head_lines(&dump, 5));
    Err(format!(
        "node2 did not catch up with node1 (node1={n1}, node2 tip={n2})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
