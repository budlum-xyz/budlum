//! WP-41 item 4: the compose stacks name only images that exist and ports that
//! the services they start actually bind.
//!
//! The two compose files are the two ways somebody runs this tree: the devnet
//! mesh in `ops/docker-compose.yml` (the file the README points at) and the
//! local rehearsal in `ops/testnet-local.yml`. A service there that cannot
//! start is worse than a missing one, because the stack comes up with a gap and
//! the smoke test reports it as a network symptom.
//!
//! The specific failure this file was written for: the faucet and the indexer
//! are two complete services in the rehearsal stack, and neither is in the
//! item's compose list. Nothing described what happens when one of them is the
//! thing that is broken, and the rehearsal read as "the mesh did not form".

use std::path::Path;

fn read(rel: &str) -> String {
    let mut path = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    path.push(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The service names of a compose file, in declaration order.
///
/// YAML nesting is significant and there is no YAML parser in this crate, so the
/// scan is deliberately narrow: a service is a line at two spaces of
/// indentation ending in `:` (`  node1:`), and the top-level `volumes:` and
/// `networks:` keys are skipped because they sit at zero indentation.
fn services(compose: &str) -> Vec<String> {
    let mut out = Vec::new();
    // The `services:` block only. Everything after the next zero-indented key
    // is `volumes:`/`networks:`, whose members look exactly like service names
    // at this indentation.
    let mut in_services = false;
    for line in compose.lines() {
        // A top-level key starts in column zero. The `x-node: &node` anchor
        // above `services:` is such a key, and so are `volumes:` and `networks:`
        // below it, which is exactly why the scan is bounded at both ends.
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            in_services = line.trim_end() == "services:";
            continue;
        }
        if !in_services {
            continue;
        }
        // A service name is at exactly two spaces; a service's own keys are
        // deeper, and a sequence item is not a key at all.
        if !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let trimmed = line.trim_end();
        let Some(name) = trimmed.strip_suffix(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.contains(' ') || name.starts_with('#') || name.starts_with('-') {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

/// The services the rehearsal stack must start, because a rehearsal that
/// leaves one out is not rehearsing the thing the launch runs.
const REQUIRED_LOCAL: &[&str] = &[
    "validator1",
    "validator2",
    "validator3",
    "validator4",
    "rpc",
    "faucet",
    "indexer",
    "prometheus",
    "grafana",
];

#[test]
fn the_rehearsal_stack_starts_every_service_the_launch_runs() {
    let compose = read("ops/testnet-local.yml");
    let declared = services(&compose);
    assert!(
        declared.len() >= REQUIRED_LOCAL.len(),
        "the scan found {} services; that is vacuous",
        declared.len()
    );
    for required in REQUIRED_LOCAL {
        assert!(
            declared.iter().any(|name| name == required),
            "ops/testnet-local.yml has no `{required}` service, so the rehearsal \
             cannot show what happens when it is the broken one; declared: {declared:?}"
        );
    }
}

/// A service that is published on the host is published on loopback.
///
/// The node's RPC, the faucet and the indexer have no authentication of their
/// own at the listener (the RPC key gate is the node's, and it is off in the
/// rehearsal so the stack can be probed). Publishing them on every interface
/// puts that on whatever network the host is attached to.
#[test]
fn published_ports_are_bound_to_loopback() {
    let compose = read("ops/testnet-local.yml");
    // Only `ports:` entries. A command argument is also a quoted string with
    // a colon in it (`--listen=0.0.0.0:18600`), and the very point of this test
    // is that such a listener is not what gets published.
    let published: Vec<&str> = compose
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- \""))
        .filter(|rest| rest.starts_with("127.0.0.1:") || rest.starts_with("0.0.0.0:"))
        .collect();
    assert!(
        published.len() >= 5,
        "the scan found {} published ports; that is vacuous",
        published.len()
    );
    for entry in published {
        assert!(
            entry.starts_with("127.0.0.1:"),
            "a rehearsal port is published on every interface: {entry}"
        );
    }
}

/// Both compose files pin the Prometheus image the same way, because the
/// dashboards, the rules and the recording of a rehearsal all read the same
/// exporter.
#[test]
fn both_stacks_pin_the_same_prometheus() {
    let devnet = read("ops/docker-compose.yml");
    let local = read("ops/testnet-local.yml");
    let pin = |body: &str| -> String {
        body.lines()
            .find_map(|line| line.trim().strip_prefix("image: prom/prometheus:"))
            .map(|rest| rest.trim().to_string())
            .unwrap_or_else(|| panic!("no prometheus image"))
    };
    assert_eq!(
        pin(&devnet),
        pin(&local),
        "the two stacks must scrape with the same reviewed Prometheus"
    );
    assert!(
        pin(&devnet).contains("@sha256:"),
        "the Prometheus image must be pinned to a digest, not a tag that can move"
    );
}
