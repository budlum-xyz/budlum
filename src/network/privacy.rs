//! Network egress privacy policy seam.
//!
//! WIRING: wired - `Node` in `src/network/node.rs` installs a network-derived
//! [`NetworkPrivacyPolicy`] in `apply_network_security` and consults
//! [`check_egress`] on outbound dials (`dial_multiaddr`), `dial`, `bootstrap`,
//! mDNS discovery, and DNS seed resolution before calling `ToSocketAddrs` or
//! `swarm.dial`.
//!
//! This module does not implement an anonymity network. It gives Budlum a small,
//! deterministic boundary where outbound dials can be classified, routed through
//! a local proxy/overlay, and logged without leaking the concrete address.

use std::fmt;

/// Why the node wants to leave its local process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EgressPurpose {
    /// Dial a configured bootstrap peer.
    Bootstrap,
    /// Dial a normal peer address.
    PeerDial,
    /// Resolve/dial a configured DNS seed.
    DnsSeed,
    /// Local peer discovery traffic such as LAN discovery.
    LocalDiscovery,
    /// Outbound JSON-RPC or operator service call.
    RpcClient,
}

impl EgressPurpose {
    fn tag(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::PeerDial => "peer-dial",
            Self::DnsSeed => "dns-seed",
            Self::LocalDiscovery => "local-discovery",
            Self::RpcClient => "rpc-client",
        }
    }
}

/// Route selected for an outbound network action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressRoute {
    /// Plain host network. Strict privacy policies can refuse this.
    Direct,
    /// Local proxy selected by operator configuration.
    Proxy { route_id: String },
    /// Local overlay adapter selected by operator configuration.
    Overlay { route_id: String },
}

impl EgressRoute {
    fn kind_tag(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy { .. } => "proxy",
            Self::Overlay { .. } => "overlay",
        }
    }

    fn validate(&self) -> Result<(), NetworkPrivacyError> {
        match self {
            Self::Direct => Ok(()),
            Self::Proxy { route_id } | Self::Overlay { route_id } => validate_route_id(route_id),
        }
    }
}

/// Coarse target classification used by policy decisions and redacted logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    /// Numeric IP address or multiaddr IP target.
    IpAddress,
    /// Hostname/DNS target or multiaddr DNS target.
    DnsName,
    /// Local-only discovery/multicast target.
    LocalDiscovery,
    /// Opaque adapter target that must be interpreted by the chosen proxy/overlay.
    Opaque,
}

impl TargetKind {
    fn tag(self) -> &'static str {
        match self {
            Self::IpAddress => "ip",
            Self::DnsName => "dns",
            Self::LocalDiscovery => "local",
            Self::Opaque => "opaque",
        }
    }
}

/// Configurable policy for outbound network privacy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPrivacyPolicy {
    /// Refuse all direct egress; caller must choose a proxy/overlay route.
    pub require_private_route: bool,
    /// Permit direct numeric IP dials when `require_private_route` is false.
    pub allow_direct_ip: bool,
    /// Permit direct DNS/hostname dials when `require_private_route` is false.
    pub allow_direct_dns: bool,
    /// Permit local discovery traffic. Privacy-sensitive nodes can turn this off.
    pub allow_local_discovery: bool,
}

impl NetworkPrivacyPolicy {
    /// Strict node policy: no direct egress, no local discovery.
    #[must_use]
    /// Convenience: kept for devnet and tests, as above.
    pub const fn strict_private() -> Self {
        Self {
            require_private_route: true,
            allow_direct_ip: false,
            allow_direct_dns: false,
            allow_local_discovery: false,
        }
    }

    /// Normal public-node policy: direct IP is allowed, DNS still needs an
    /// explicit decision so seed resolution cannot be introduced accidentally.
    #[must_use]
    /// Convenience: kept for devnet and tests, as above.
    pub const fn public_node_no_dns_leak() -> Self {
        Self {
            require_private_route: false,
            allow_direct_ip: true,
            allow_direct_dns: false,
            allow_local_discovery: true,
        }
    }

    /// Test/devnet policy that allows all direct routes.
    #[must_use]
    /// Convenience: kept for devnet and tests. The three constructors are the
    /// named policy presets; the adapter that will pick one at startup is not
    /// in this PR (see the module's WIRING note).
    pub const fn devnet_clear() -> Self {
        Self {
            require_private_route: false,
            allow_direct_ip: true,
            allow_direct_dns: true,
            allow_local_discovery: true,
        }
    }
}

/// Egress request that can be checked before the caller dials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRequest {
    /// Purpose of the outbound action.
    pub purpose: EgressPurpose,
    /// Raw operator-provided target. It is not copied into approvals/log labels.
    pub target: String,
    /// Selected route.
    pub route: EgressRoute,
}

impl EgressRequest {
    /// Construct a request with an owned target string.
    #[must_use]
    pub fn new(purpose: EgressPurpose, target: impl Into<String>, route: EgressRoute) -> Self {
        Self {
            purpose,
            target: target.into(),
            route,
        }
    }
}

/// Approval returned by [`check_egress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressApproval {
    /// Purpose that was approved.
    pub purpose: EgressPurpose,
    /// Coarse target kind. The concrete target is intentionally omitted.
    pub target_kind: TargetKind,
    /// Route kind selected by the caller. The concrete route id is intentionally omitted.
    pub route_kind: &'static str,
    /// Redacted stable label suitable for metrics/logging.
    pub audit_label: String,
}

/// Egress privacy errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPrivacyError {
    /// Target string was empty.
    EmptyTarget,
    /// Route id was empty, path-like, URL-like, or otherwise non-deterministic.
    ///
    /// The id is not stored: a mistyped proxy URL may hold a user name and password.
    InvalidRouteId,
    /// Policy requires proxy/overlay egress but the caller selected direct.
    DirectEgressDenied {
        purpose: EgressPurpose,
        target_kind: TargetKind,
    },
    /// Policy refuses direct IP egress.
    DirectIpDenied { purpose: EgressPurpose },
    /// Policy refuses direct DNS/hostname egress.
    DirectDnsDenied { purpose: EgressPurpose },
    /// Policy refuses local discovery.
    LocalDiscoveryDenied,
}

impl fmt::Display for NetworkPrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTarget => f.write_str("network egress target must not be empty"),
            Self::InvalidRouteId => f.write_str("invalid network privacy route id"),
            Self::DirectEgressDenied {
                purpose,
                target_kind,
            } => write!(
                f,
                "direct egress denied for purpose={purpose:?}, target_kind={target_kind:?}"
            ),
            Self::DirectIpDenied { purpose } => {
                write!(f, "direct IP egress denied for purpose={purpose:?}")
            }
            Self::DirectDnsDenied { purpose } => {
                write!(f, "direct DNS egress denied for purpose={purpose:?}")
            }
            Self::LocalDiscoveryDenied => f.write_str("local discovery egress denied"),
        }
    }
}

impl std::error::Error for NetworkPrivacyError {}

/// Return true if `s` is an IPv4/IPv6 literal, including IPv6 link-local with
/// an RFC 6874 zone identifier such as `fe80::1%eth0`.
fn is_ip_literal(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((addr, zone)) = s.split_once('%') {
        return !zone.is_empty() && addr.parse::<std::net::Ipv6Addr>().is_ok();
    }
    false
}

/// The host part of a URL-style or `host:port` target: scheme, user info, path,
/// query, port and the brackets of an IPv6 literal are removed. Multiaddr
/// style targets (leading `/`) have no host in this sense.
fn host_part(lower: &str) -> Option<&str> {
    if lower.starts_with('/') {
        return None;
    }
    let rest = lower.split_once("://").map_or(lower, |(_, r)| r);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    if let Some(inner) = rest.strip_prefix('[') {
        return inner.split_once(']').map(|(h, _)| h);
    }
    // A bare IPv6 literal (optionally with %zone) has several colons and no port.
    if rest.matches(':').count() > 1 {
        return Some(rest);
    }
    Some(rest.rsplit_once(':').map_or(rest, |(h, _)| h))
}

/// Classify a target without resolving it or parsing mutable external state.
///
/// Bracketed IPv6 literals, zone-scoped link-local IPv6 literals, and URL-style
/// targets are classified by their host so they cannot slip past a no-direct-DNS
/// or no-direct-IP policy as `Opaque`. A bare dotless name stays `Opaque` on
/// purpose: it is an adapter target the chosen proxy interprets, except
/// `localhost`.
#[must_use]
pub fn classify_target(target: &str) -> TargetKind {
    let trimmed = target.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("mdns") || lower.contains("multicast") || lower.contains("/udp/5353") {
        return TargetKind::LocalDiscovery;
    }
    if lower.contains("/dns") {
        return TargetKind::DnsName;
    }
    if lower.contains("/ip4/") || lower.contains("/ip6/") {
        return TargetKind::IpAddress;
    }
    if let Some(host) = host_part(&lower) {
        if is_ip_literal(host) {
            return TargetKind::IpAddress;
        }
        let canonical_host = host.trim_end_matches('.');
        if canonical_host == "localhost"
            || (canonical_host.contains('.')
                && canonical_host.bytes().any(|b| b.is_ascii_alphabetic()))
            || (!canonical_host.is_empty() && (lower.contains("://") || has_numeric_port(&lower)))
        {
            return TargetKind::DnsName;
        }
    }
    TargetKind::Opaque
}

/// Check whether an outbound dial/lookup is permitted and return a redacted
/// approval. This function never resolves hostnames and never copies the raw
/// target into the returned audit label.
///
/// # Errors
///
/// Returns an error when the target is empty/whitespace, route id is invalid, or
/// the policy refuses the selected route/target kind.
pub fn check_egress(
    policy: &NetworkPrivacyPolicy,
    request: &EgressRequest,
) -> Result<EgressApproval, NetworkPrivacyError> {
    let trimmed = request.target.trim();
    if trimmed.is_empty() {
        return Err(NetworkPrivacyError::EmptyTarget);
    }
    request.route.validate()?;

    let mut target_kind = classify_target(trimmed);
    if request.purpose == EgressPurpose::LocalDiscovery {
        target_kind = TargetKind::LocalDiscovery;
    }

    if target_kind == TargetKind::LocalDiscovery && !policy.allow_local_discovery {
        return Err(NetworkPrivacyError::LocalDiscoveryDenied);
    }

    if matches!(request.route, EgressRoute::Direct) {
        if policy.require_private_route {
            return Err(NetworkPrivacyError::DirectEgressDenied {
                purpose: request.purpose,
                target_kind,
            });
        }
        match target_kind {
            TargetKind::IpAddress if !policy.allow_direct_ip => {
                return Err(NetworkPrivacyError::DirectIpDenied {
                    purpose: request.purpose,
                });
            }
            TargetKind::DnsName if !policy.allow_direct_dns => {
                return Err(NetworkPrivacyError::DirectDnsDenied {
                    purpose: request.purpose,
                });
            }
            _ => {}
        }
    }

    let route_kind = request.route.kind_tag();
    Ok(EgressApproval {
        purpose: request.purpose,
        target_kind,
        route_kind,
        audit_label: format!(
            "network-egress:{}:{}:{}",
            request.purpose.tag(),
            target_kind.tag(),
            route_kind
        ),
    })
}

/// `name:port` with a non-empty name and an all-digit port.
fn has_numeric_port(lower: &str) -> bool {
    lower.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
    })
}

fn validate_route_id(route_id: &str) -> Result<(), NetworkPrivacyError> {
    let valid = !route_id.is_empty()
        && route_id.len() <= 64
        && !route_id.contains("://")
        && !route_id.contains('/')
        && !route_id.contains('\\')
        && route_id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#');
    if valid {
        Ok(())
    } else {
        Err(NetworkPrivacyError::InvalidRouteId)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_classification_is_resolution_free() {
        assert_eq!(
            classify_target("/ip4/198.51.100.7/tcp/4001"),
            TargetKind::IpAddress
        );
        assert_eq!(classify_target("198.51.100.7:4001"), TargetKind::IpAddress);
        assert_eq!(
            classify_target("/dns4/bootstrap.example/tcp/4001"),
            TargetKind::DnsName
        );
        assert_eq!(classify_target("seed.example:4001"), TargetKind::DnsName);
        assert_eq!(classify_target("mdns://lan"), TargetKind::LocalDiscovery);
        assert_eq!(classify_target("adapter-target-1"), TargetKind::Opaque);
        // Shapes that used to fall through to Opaque.
        assert_eq!(classify_target("[2001:db8::1]:4001"), TargetKind::IpAddress);
        assert_eq!(
            classify_target("http://seed.example/x"),
            TargetKind::DnsName
        );
        assert_eq!(
            classify_target("https://[::1]:8545/"),
            TargetKind::IpAddress
        );
        assert_eq!(classify_target("localhost:4001"), TargetKind::DnsName);
        // A dotless host in a URL or with a port is still a name to resolve.
        assert_eq!(classify_target("http://intranet/x"), TargetKind::DnsName);
        assert_eq!(classify_target("intranet:4001"), TargetKind::DnsName);
        // Hardened edge cases: whitespace, IPv6 zone IDs, trailing dot, multicast ordering, IP URL.
        assert_eq!(classify_target("  127.0.0.1:4001  "), TargetKind::IpAddress);
        assert_eq!(classify_target("fe80::1%eth0"), TargetKind::IpAddress);
        assert_eq!(
            classify_target("[fe80::1%eth0]:4001"),
            TargetKind::IpAddress
        );
        assert_eq!(
            classify_target("/ip4/224.0.0.251/udp/5353"),
            TargetKind::LocalDiscovery
        );
        assert_eq!(classify_target("localhost."), TargetKind::DnsName);
        assert_eq!(
            classify_target("http://user:pass@127.0.0.1:8545/rpc"),
            TargetKind::IpAddress
        );
        assert_eq!(
            check_egress(
                &NetworkPrivacyPolicy::devnet_clear(),
                &EgressRequest::new(EgressPurpose::PeerDial, "   \t\n ", EgressRoute::Direct),
            ),
            Err(NetworkPrivacyError::EmptyTarget)
        );
    }

    #[test]
    fn strict_policy_requires_private_route_and_redacts_target() {
        let policy = NetworkPrivacyPolicy::strict_private();
        let direct = EgressRequest::new(
            EgressPurpose::Bootstrap,
            "/ip4/198.51.100.7/tcp/4001",
            EgressRoute::Direct,
        );
        assert!(matches!(
            check_egress(&policy, &direct),
            Err(NetworkPrivacyError::DirectEgressDenied { .. })
        ));

        let proxied = EgressRequest::new(
            EgressPurpose::Bootstrap,
            "/ip4/198.51.100.7/tcp/4001",
            EgressRoute::Proxy {
                route_id: "operator-proxy-a".into(),
            },
        );
        let approval = check_egress(&policy, &proxied).expect("proxied egress");
        assert_eq!(approval.target_kind, TargetKind::IpAddress);
        assert_eq!(approval.route_kind, "proxy");
        assert!(!approval.audit_label.contains("198.51.100.7"));
        assert!(!approval.audit_label.contains("operator-proxy-a"));
    }

    #[test]
    fn public_node_policy_refuses_direct_dns_until_explicitly_allowed() {
        let request = EgressRequest::new(
            EgressPurpose::DnsSeed,
            "seed.example:4001",
            EgressRoute::Direct,
        );
        assert!(matches!(
            check_egress(&NetworkPrivacyPolicy::public_node_no_dns_leak(), &request),
            Err(NetworkPrivacyError::DirectDnsDenied {
                purpose: EgressPurpose::DnsSeed
            })
        ));

        let approval = check_egress(&NetworkPrivacyPolicy::devnet_clear(), &request)
            .expect("devnet direct dns");
        assert_eq!(approval.target_kind, TargetKind::DnsName);
        assert_eq!(approval.audit_label, "network-egress:dns-seed:dns:direct");
        assert!(!approval.audit_label.contains("seed.example"));
    }

    #[test]
    fn local_discovery_can_be_disabled() {
        let request = EgressRequest::new(
            EgressPurpose::LocalDiscovery,
            "mdns://lan",
            EgressRoute::Direct,
        );
        assert_eq!(
            check_egress(&NetworkPrivacyPolicy::strict_private(), &request),
            Err(NetworkPrivacyError::LocalDiscoveryDenied)
        );
        let approval = check_egress(&NetworkPrivacyPolicy::devnet_clear(), &request)
            .expect("devnet local discovery");
        assert_eq!(approval.target_kind, TargetKind::LocalDiscovery);
    }

    #[test]
    fn proxy_and_overlay_route_ids_are_local_not_urls_or_paths() {
        let policy = NetworkPrivacyPolicy::strict_private();
        for route in [
            EgressRoute::Proxy {
                route_id: "https://proxy.example".into(),
            },
            EgressRoute::Overlay {
                route_id: "../overlay".into(),
            },
        ] {
            let request = EgressRequest::new(EgressPurpose::PeerDial, "adapter-target-1", route);
            assert!(matches!(
                check_egress(&policy, &request),
                Err(NetworkPrivacyError::InvalidRouteId)
            ));
        }

        let leaky = EgressRoute::Proxy {
            route_id: "https://user:secret@proxy.example".into(),
        };
        let request = EgressRequest::new(EgressPurpose::PeerDial, "adapter-target-1", leaky);
        let error = check_egress(&policy, &request).expect_err("a URL route id is refused");
        assert!(!format!("{error} {error:?}").contains("secret"));

        let request = EgressRequest::new(
            EgressPurpose::PeerDial,
            "adapter-target-1",
            EgressRoute::Overlay {
                route_id: "overlay-a".into(),
            },
        );
        let approval = check_egress(&policy, &request).expect("overlay route");
        assert_eq!(approval.target_kind, TargetKind::Opaque);
        assert_eq!(approval.route_kind, "overlay");
    }
}
