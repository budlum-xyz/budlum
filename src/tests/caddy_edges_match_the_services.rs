//! The public TLS edge in `ops/Caddyfile.testnet` fronts the
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

use std::path::Path;

const CADDY: &str = include_str!("../../ops/Caddyfile.testnet");
const TESTNET_PROFILE: &str = include_str!("../../config/testnet.toml");
const FAUCET: &str = include_str!("../../src/bin/budlum-faucet.rs");
const INDEXER: &str = include_str!("../../src/bin/budlum-indexer.rs");

/// One proxied host: its site address and the loopback port it forwards to.
fn proxied_hosts() -> Vec<(String, u16)> {
    let mut out = Vec::new();
    let mut site: Option<String> = None;
    for line in CADDY.lines() {
        let top_level = !line.starts_with('\t') && !line.starts_with(' ');
        let trimmed = line.trim();
        if top_level && trimmed.ends_with('{') {
            let name = trimmed.trim_end_matches('{').trim();
            // `{` opens the global options block and `(common)` is a snippet,
            // not a site. Neither proxies anything on its own.
            site = (!name.is_empty() && !name.starts_with('(') && name != "{")
                .then(|| name.to_string());
            continue;
        }
        if top_level && trimmed == "}" {
            site = None;
            continue;
        }
        let (Some(host), Some(rest)) = (site.as_ref(), trimmed.strip_prefix("reverse_proxy "))
        else {
            continue;
        };
        let target = rest.split_whitespace().next().unwrap_or_default();
        let port = target
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("reverse_proxy target {target} has no port"));
        assert!(
            target.starts_with("127.0.0.1:"),
            "site {host} forwards to {target}: the node binds loopback only, so \
             a public address here would bypass that"
        );
        out.push((host.clone(), port));
    }
    out
}

/// The port a `127.0.0.1:` listener line of the profile names.
fn profile_port(needle: &str) -> u16 {
    let marker = format!("{needle} = \"127.0.0.1:");
    TESTNET_PROFILE
        .lines()
        .find_map(|line| line.trim().strip_prefix(&marker))
        .and_then(|rest| rest.trim_end_matches('"').parse::<u16>().ok())
        .unwrap_or_else(|| panic!("config/testnet.toml must name {needle} on loopback"))
}

/// The default port of a service's `--listen` argument, read from its own
/// source rather than restated here.
fn service_listen_port(source: &str) -> u16 {
    let marker = "default_value = \"127.0.0.1:";
    let at = source
        .find(marker)
        .unwrap_or_else(|| panic!("the service has no loopback --listen default"))
        + marker.len();
    let rest = &source[at..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("the --listen default is not terminated"));
    rest[..end]
        .parse()
        .unwrap_or_else(|e| panic!("the --listen default port is not a number: {e}"))
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
    let lookup = |prefix: &str| -> u16 {
        hosts
            .iter()
            .find(|(host, _)| host.starts_with(prefix))
            .unwrap_or_else(|| panic!("no site named {prefix}* in the Caddyfile"))
            .1
    };
    assert_eq!(
        lookup("rpc."),
        profile_port("public_listener"),
        "the RPC site must forward to [rpc].public_listener"
    );
    assert_eq!(
        lookup("faucet."),
        service_listen_port(FAUCET),
        "the faucet site must forward to budlum-faucet's --listen default"
    );
    assert_eq!(
        lookup("explorer-api."),
        service_listen_port(INDEXER),
        "the explorer site must forward to budlum-indexer's --listen default"
    );
}

/// The operator listener and the metrics listener are never proxied.
///
/// Neither has authentication of its own by design; the RPC key gate protects
/// the public listener, not them.
#[test]
fn the_edge_never_proxies_an_unauthenticated_listener() {
    let operator = profile_port("operator_listener");
    let metrics = profile_port("listener");
    assert_ne!(operator, metrics, "the two listeners must differ");
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

/// Every public site takes the shared hardening: HSTS, a body cap and no
/// `Server` banner.
#[test]
fn every_public_site_inherits_the_common_hardening() {
    let mut site: Option<String> = None;
    let mut sites = 0usize;
    for line in CADDY.lines() {
        let top_level = !line.starts_with('\t') && !line.starts_with(' ');
        let trimmed = line.trim();
        if top_level && trimmed.ends_with('{') {
            let name = trimmed.trim_end_matches('{').trim();
            site = (!name.is_empty() && !name.starts_with('(') && name != "{")
                .then(|| name.to_string());
            if site.is_some() {
                sites += 1;
            }
            continue;
        }
        if let (Some(host), Some(rest)) = (site.as_ref(), trimmed.strip_prefix("import ")) {
            assert!(
                rest.contains("common"),
                "site {host} imports {rest}; every public site must take the \
                 shared hardening"
            );
        }
    }
    assert!(sites >= 3, "found {sites} sites; that is vacuous");
    for required in [
        "max_size",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
    ] {
        assert!(
            CADDY.contains(required),
            "the common snippet must carry {required}"
        );
    }
}

/// The two backends behind this proxy are told the proxy is trusted, and the
/// operator documentation names the edge it expects.
///
/// A service that trusts nobody ignores the forwarded address and rate-limits
/// the proxy instead of the client - the one thing the edge exists to avoid.
#[test]
fn the_proxied_services_are_told_the_proxy_is_trusted() {
    let operations = read("docs/OPERATIONS.md");
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

fn read(rel: &str) -> String {
    let mut path = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    path.push(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}
