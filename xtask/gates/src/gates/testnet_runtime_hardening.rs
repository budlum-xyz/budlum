//! Live testnet P2P, `/sync`, and 2-hop BFT finality runtime hardening locks.
//!
//! Each check here guards a root-cause defect uncovered while running the full
//! multi-validator `45261` testnet mesh end-to-end:
//!
//! 1. Multi-entry `[p2p] bootnodes` in `src/main.rs` must be merged with
//!    `config.bootstrap` rather than truncated to `bootnodes.first()`.
//! 2. Simultaneous inbound/outbound dials to the same `PeerId` must bypass the
//!    `/24` subnet cap (`pm.is_connected(&peer_id)`), and closing a redundant
//!    TCP stream (`ConnectionClosed { num_established > 0 }`) must not drop
//!    the peer from `PeerManager` or gossipsub.
//! 3. `Node::bootstrap` must skip peers that already hold an active connection
//!    and `discovery_interval.reset()` must suppress duplicate `t=0` dials.
//! 4. Production code in `src/network/node.rs` must precede the first
//!    `#[cfg(test)]` block so source-lock tests inspect the entire event loop.
//! 5. Multi-chunk `/sync` (`plan_sync_headers` + `SyncRangeCursor`), stalled
//!    round expiry (`expire_stuck_sync_round`), and lockstep `height + 1` fork
//!    recovery (`if unjoined && self.sync_state.load(Ordering::SeqCst) == 0`)
//!    must remain wired in production code.
//! 6. Deferred finality votes must replay `held_prevotes` before
//!    `held_precommits`, retain `Precommit`s on
//!    `"Cannot precommit before prevote quorum"`, skip pushing `"Duplicate"`
//!    votes into `deferred_votes`, and keep `prevote_retry` active until
//!    `precommit_quorum_reached` across 2-hop gossip meshes.
//! 7. When `ops/testnet-local-validator.py` is present, `seat_bootnodes` must
//!    wire a bounded-degree mesh rather than a star topology exceeding the
//!    `/24` subnet peer cap.

use std::fs;
use std::path::Path;

fn read_text(root: &Path, rel: &str) -> Result<String, String> {
    let path = root.join(rel);
    fs::read_to_string(&path).map_err(|e| format!("cannot read {rel}: {e}"))
}

fn check_sources(
    main_rs: &str,
    peer_manager_rs: &str,
    node_rs: &str,
    launcher_py: Option<&str>,
) -> Vec<String> {
    let mut findings = Vec::new();

    if !main_rs.contains("for addr in &config.bootnodes") {
        findings.push(String::from(
            "src/main.rs: `config.bootnodes` is not merged into the bootstrap list; \
             multi-entry `[p2p] bootnodes` configs lose entries after the first",
        ));
    }

    if !peer_manager_rs.contains("pub fn is_connected(&self, peer_id: &PeerId) -> bool") {
        findings.push(String::from(
            "src/network/peer_manager.rs: missing `PeerManager::is_connected(&PeerId)`",
        ));
    }

    let prod_node = match node_rs.split_once("#[cfg(test)]") {
        Some((before_tests, _)) => before_tests,
        None => node_rs,
    };

    if !prod_node.contains("pub async fn run(") {
        findings.push(String::from(
            "src/network/node.rs: a `#[cfg(test)]` attribute precedes `Node::run`, \
             hiding production event-loop code from `split_once(\"#[cfg(test)]\")`",
        ));
    }

    for (needle, message) in [
        (
            "peer_manager_lock().is_connected(&peer_id)",
            "src/network/node.rs: `ConnectionEstablished` does not bypass `/24` subnet eviction \
             via `peer_manager_lock().is_connected(&peer_id)` for already-connected peers",
        ),
        (
            "if num_established > 0 {",
            "src/network/node.rs: `ConnectionClosed` drops peers even when `num_established > 0` \
             connections remain active",
        ),
        (
            "!self.swarm.is_connected(&peer_id)",
            "src/network/node.rs: `Node::bootstrap` dials peers without checking \
             `!self.swarm.is_connected(&peer_id)`",
        ),
        (
            "discovery_interval.reset();",
            "src/network/node.rs: `discovery_interval` is not reset after startup bootstrap",
        ),
        (
            "struct SyncRangeCursor",
            "src/network/node.rs: missing `SyncRangeCursor` multi-chunk `/sync` state",
        ),
        (
            "fn plan_sync_headers(",
            "src/network/node.rs: missing `plan_sync_headers` bounded locator planner",
        ),
        (
            "if unjoined && self.sync_state.load(Ordering::SeqCst) == 0",
            "src/network/node.rs: unjoined `height + 1` blocks do not open header `/sync`",
        ),
        (
            "self.expire_stuck_sync_round();",
            "src/network/node.rs: fast heartbeat does not expire stalled `/sync` rounds",
        ),
        (
            "if e.contains(\"Cannot precommit before prevote quorum\")",
            "src/network/node.rs: deferred precommits arriving before prevote quorum are not retained",
        ),
        (
            "if !e.contains(\"Duplicate\")",
            "src/network/node.rs: duplicate finality votes are re-queued into `deferred_votes`",
        ),
        (
            "let prevote_retry = agg_state.active\n                        && !agg_state.precommit_quorum_reached",
            "src/network/node.rs: `prevote_retry` stops at local prevote quorum instead of \
             staying active until `precommit_quorum_reached`",
        ),
    ] {
        if !prod_node.contains(needle) {
            findings.push(String::from(message));
        }
    }

    match (
        prod_node.find("for vote in held_prevotes"),
        prod_node.find("for vote in held_precommits"),
    ) {
        (Some(prevote_pos), Some(precommit_pos)) if prevote_pos < precommit_pos => {}
        _ => findings.push(String::from(
            "src/network/node.rs: deferred vote replay must process `held_prevotes` \
             strictly before `held_precommits`",
        )),
    }

    if let Some(py) = launcher_py {
        if !py.contains("def seat_bootnodes(") || !py.contains("((idx + 4) % 8)") {
            findings.push(String::from(
                "ops/testnet-local-validator.py: `seat_bootnodes` must wire the 3-regular \
                 chordal ring so no validator exceeds the `/24` subnet peer cap",
            ));
        }
    }

    findings
}

pub fn run(root: &Path) -> Result<String, String> {
    let main_rs = read_text(root, "src/main.rs")?;
    let peer_manager_rs = read_text(root, "src/network/peer_manager.rs")?;
    let node_rs = read_text(root, "src/network/node.rs")?;
    let launcher_path = root.join("ops/testnet-local-validator.py");
    let launcher_py = if launcher_path.is_file() {
        Some(read_text(root, "ops/testnet-local-validator.py")?)
    } else {
        None
    };

    let findings = check_sources(&main_rs, &peer_manager_rs, &node_rs, launcher_py.as_deref());
    if !findings.is_empty() {
        return Err(format!(
            "testnet-runtime-hardening failed ({} finding(s)):\n  - {}",
            findings.len(),
            findings.join("\n  - ")
        ));
    }
    Ok(String::from(
        "testnet-runtime-hardening: P2P connection, multi-chunk /sync, fork recovery, \
         and 2-hop BFT finality invariants verified",
    ))
}

const CLEAN_NODE_FIXTURE: &str = concat!(
    "struct SyncRangeCursor {}\n",
    "fn plan_sync_headers() {}\n",
    "impl Node {\n",
    "    fn bootstrap(&mut self) { if !self.swarm.is_connected(&peer_id) {} }\n",
    "    pub async fn run(&mut self) {\n",
    "        discovery_interval.reset();\n",
    "        self.expire_stuck_sync_round();\n",
    "        for vote in held_prevotes {}\n",
    "        for vote in held_precommits {\n",
    "            if e.contains(\"Cannot precommit before prevote quorum\") {}\n",
    "        }\n",
    "        let prevote_retry = agg_state.active\n",
    "                        && !agg_state.precommit_quorum_reached;\n",
    "        if self.peer_manager_lock().is_connected(&peer_id) {}\n",
    "        if num_established > 0 {}\n",
    "        if unjoined && self.sync_state.load(Ordering::SeqCst) == 0 {}\n",
    "        if !e.contains(\"Duplicate\") {}\n",
    "    }\n",
    "}\n",
    "#[cfg(test)]\nmod tests {}\n",
);

pub fn self_test() -> Result<String, String> {
    let clean_main = "fn boot() { for addr in &config.bootnodes {} }\n";
    let clean_pm =
        "impl PeerManager { pub fn is_connected(&self, peer_id: &PeerId) -> bool { true } }\n";
    let clean_node = CLEAN_NODE_FIXTURE;
    let clean_launcher = "def seat_bootnodes(seat, fb):\n    return ((idx + 4) % 8)\n";

    let baseline = check_sources(clean_main, clean_pm, clean_node, Some(clean_launcher));
    if !baseline.is_empty() {
        return Err(format!(
            "canary: clean fixture failed unexpectedly: {}",
            baseline.join("; ")
        ));
    }

    let cases: &[(&str, &str, &str, &str, Option<&str>)] = &[
        (
            "missing bootnodes merge",
            "fn boot() {}\n",
            clean_pm,
            clean_node,
            Some(clean_launcher),
        ),
        (
            "missing PeerManager::is_connected",
            clean_main,
            "impl PeerManager {}\n",
            clean_node,
            Some(clean_launcher),
        ),
        (
            "early #[cfg(test)] before Node::run",
            clean_main,
            clean_pm,
            "#[cfg(test)]\nmod early {}\npub async fn run(&mut self) {}\n",
            Some(clean_launcher),
        ),
        (
            "missing num_established guard",
            clean_main,
            clean_pm,
            &clean_node.replace("if num_established > 0 {}", ""),
            Some(clean_launcher),
        ),
        (
            "inverted held_precommits before held_prevotes",
            clean_main,
            clean_pm,
            &clean_node
                .replace("for vote in held_prevotes {}", "PLACEHOLDER")
                .replace(
                    "for vote in held_precommits",
                    "for vote in held_prevotes {}\nfor vote in held_precommits",
                )
                .replace("PLACEHOLDER", "for vote in held_precommits {}"),
            Some(clean_launcher),
        ),
        (
            "prevote_retry gated on prevote_quorum_reached",
            clean_main,
            clean_pm,
            &clean_node.replace(
                "&& !agg_state.precommit_quorum_reached",
                "&& !agg_state.prevote_quorum_reached",
            ),
            Some(clean_launcher),
        ),
        (
            "star-topology validator launcher",
            clean_main,
            clean_pm,
            clean_node,
            Some("def run(): pass\n"),
        ),
    ];

    for (label, m, pm, n, py) in cases {
        if check_sources(m, pm, n, *py).is_empty() {
            return Err(format!("canary: broken fixture `{label}` passed"));
        }
    }

    Ok(format!(
        "testnet-runtime-hardening self-test: {} negative canaries caught",
        cases.len()
    ))
}
