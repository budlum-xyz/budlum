//! WP-41 item 5: the public TLS edge in `ops/Caddyfile.testnet` fronts the
//! services the node actually binds, and fronts nothing else.
//!
//! A reverse proxy config drifts quietly. The port changes in the node's config
//! and Caddy keeps forwarding to a socket nobody listens on: the edge answers
//! 502, the node looks healthy on loopback, and the incident starts as "the RPC
//! is down" rather than "the port moved". This file reads the ports out of the
//! two sides and compares them.
//!
//! The second half is the security posture: the operator listener and the
//! metrics listener are deliberately never proxied, because neither has
//! authentication of its own.

use std::path::{Path, PathBuf};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p: PathBuf = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

const CADDY: &str = include_str!("../../ops/Caddyfile.testnet");
const TESTNET_PROFILE: &str = include_str!("../../config/testnet.toml");
const FAUCET: &str = include_str!("../../src/bin/budlum-faucet.rs");
const INDEXER: &str = include_str!("../../src/bin/budlum-indexer.rs");

/// One proxied host: its site address prefix and the loopback port it forwards
/// to.
fn proxied_hosts() -> Vec<(String, u16)> {
    let mut out = Vec::new();
    let mut site: Option<String> = None;
    for line in CADDY.lines() {
        let is_top_level = !line.starts_with('\t') && !line.starts_with(' ');
        let trimmed = line.trim();
        if is_top_level && trimmed.ends_with('{') {
            let name = trimmed.trim_end_matches('{').trim().to_string();
            // `{` is the global options block and `(common)` is a snippet, not
            // a site. Neither proxies anything on its own.
            site = (!name.is_empty() && !name.starts_with('(')).then_some(name);
            continue;
        }
        if trimmed == "}" && is_top_level {
            site = None;
            continue;
        }
        let Some(host) = site.as_ref() else { continue };
        if let Some(rest) = trimmed.strip_prefix("reverse_proxy ") {
            let target = rest.split_whitespace().next().unwrap_or_default();
            let port = target
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("reverse_proxy target {target} has no port"));
            assert!(
                target.starts_with("127.0.0.1:"),
                "site {host} forwards to {target}: the node binds loopback only, \
                 and a proxy to a public address would bypass that"
            );
            out.push((host.clone(), port));
        }
    }
    out
}

/// The default port of a service's `--listen` argument, read from its own
/// source rather than restated here.
fn default_port(source: &str, arg: &str) -> u16 {
    let at = source
        .find(arg)
        .unwrap_or_else(|| panic!("{arg} must exist in the source under test"));
    // Walk backwards to the field, then forwards past it: the two services
    // spell the declaration differently (`listen: String` against a doc
    // comment line), so the window straddles the field rather than starting at
    // the argument name.
    let from = at.saturating_sub(200);
    let window = &source[from..(at + 400).min(source.len())];
    let marker = "default_value = \"127.0.0.1:";
    let start = window
        .find(marker)
        .unwrap_or_else(|| panic!("{arg} has no loopback default: {window}"))
        + marker.len();
    let rest = &window[start..];
    rest[..rest.find('"').unwrap_or(0)]
        .parse()
        .unwrap_or_else(|e| panic!("{arg} default port is not a number: {e}"))
}

/// Each public host forwards to the port of the service it names.
#[test]
fn the_edge_fronts_the_ports_the_services_bind() {
    let hosts = proxied_hosts();
    assert!(
        hosts.len() >= 3,
        "the Caddyfile must front the RPC, the faucet and the explorer API; \
         found {} hosts",
        hosts.len()
    );

    let rpc_port = TESTNET_PROFILE
        .lines()
        .find_map(|l| l.trim().strip_prefix("public_listener = \"127.0.0.1:"))
        .and_then(|rest| rest.trim_end_matches('"').parse::<u16>().ok())
        .expect("config/testnet.toml names the public RPC listener");
    let faucet_port = default_port(FAUCET, "listen: String,");
    let indexer_port = default_port(INDEXER, "listen: String,");

    let lookup = |prefix: &str| -> u16 {
        hosts
            .iter()
            .find(|(host, _)| host.starts_with(prefix))
            .unwrap_or_else(|| panic!("no site for {prefix} in the Caddyfile"))
            .1
    };
    assert_eq!(
        lookup("rpc."),
        rpc_port,
        "the RPC site must forward to [rpc].public_listener"
    );
    assert_eq!(
        lookup("faucet."),
        faucet_port,
        "the faucet site must forward to budlum-faucet's --listen default"
    );
    assert_eq!(
        lookup("explorer-api."),
        indexer_port,
        "the explorer site must forward to budlum-indexer's --listen default"
    );
}

/// The operator listener, the metrics listener and P2P are never proxied.
///
/// The first two have no authentication of their own by design; the RPC key
/// gate protects the public listener, not them. P2P is not HTTP at all.
#[test]
fn the_edge_never_proxies_an_unauthenticated_listener() {
    let operator = TESTNET_PROFILE
        .lines()
        .find_map(|l| l.trim().strip_prefix("operator_listener = \"127.0.0.1:"))
        .and_then(|rest| rest.trim_end_matches('"').parse::<u16>().ok())
        .expect("config/testnet.toml names the operator listener");
    let metrics = TESTNET_PROFILE
        .lines()
        .find_map(|l| l.trim().strip_prefix("listener = \"127.0.0.1:"))
        .and_then(|rest| rest.trim_end_matches('"').parse::<u16>().ok())
        .expect("config/testnet.toml names the metrics listener");

    for (host, port) in proxied_hosts() {
        for forbidden in [operator, metrics] {
            assert_ne!(
                port, forbidden,
                "site {host} proxies port {port}, which is an unauthenticated \
                 listener and must stay off the public edge"
            );
        }
    }
}

/// Every public site gets the shared hardening: HSTS, a body cap and no
/// `Server` banner.
#[test]
fn every_public_site_inherits_the_common_hardening() {
    let mut site: Option<String> = None;
    let mut sites = 0usize;
    let mut seen_import = vec![];
    for line in CADDY.lines() {
        let is_top_level = !line.starts_with('\t') && !line.starts_with(' ');
        let trimmed = line.trim();
        if is_top_level && trimmed.ends_with('{') && trimmed != "{" {
            let name = trimmed.trim_end_matches('{').trim();
            site = (!name.starts_with('(')).then(|| name.to_string());
            if let Some(ref name) = site {
                seen_import.push(name.clone());
                sites += 1;
            }
            continue;
        }
        if let Some(ref host) = site {
            if trimmed.starts_with("import ") {
                assert!(
                    trimmed.contains("common"),
                    "site {host} imports {trimmed}; every public site must take \
                     the shared hardening"
                );
            }
        }
    }
    assert!(sites >= 3, "found {sites} sites; that is vacuous");
    assert!(
        CADDY.contains("max_size"),
        "the common snippet must cap the request body: the edge buffers what it \
         forwards, and the node never re-reads it"
    );
    assert!(
        CADDY.contains("Strict-Transport-Security"),
        "every site must send HSTS"
    );
}

/// The faucet and the indexer are started behind this proxy, so the runbook
/// has to name the proxy as trusted; a service that trusts nobody ignores the
/// forwarded address and rate-limits the proxy instead of the client.
#[test]
fn the_proxied_services_are_told_the_proxy_is_trusted() {
    let operations = read("docs/OPERATIONS.md");
    // Whitespace-collapsed comparisons: the Caddyfile wraps its own comment.
    let flat = CADDY.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("--trusted-proxy 127.0.0.1"),
        "the Caddyfile must state the flag its two backends need"
    );
    assert!(
        operations.contains("Caddyfile.testnet"),
        "the operator documentation must name the edge config it expects"
    );
}
