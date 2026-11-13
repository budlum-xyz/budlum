//! `Host` header to registry name (B14, `A3`).
//!
//! The rule: strip the configured suffix, then read what is left. One label is
//! the name itself, two labels are a subdomain and a name, anything else is not
//! a gateway address.
//!
//! ```text
//! ayaz.budlum.xyz       -> ayaz.bud       (no subdomain)
//! shop.ayaz.budlum.xyz  -> ayaz.bud       (subdomain "shop")
//! www.budlum.xyz        -> reserved       (goes to the main site, not BNS)
//! ```
//!
//! A parse failure is a 404. Every label goes through
//! [`crate::bns::registry::BnsRegistry::is_valid_label`], the same table the
//! registry sells from, so the gateway cannot invent a name the chain would
//! refuse or accept one it never sold.

use crate::bns::registry::BnsRegistry;
use crate::registry::params::RESERVED_LABELS;

/// The default suffix. `budlum.xyz` belongs to Budlum, so the gateway is the
/// only party that can serve `*.budlum.xyz` with a valid certificate.
pub const DEFAULT_GATEWAY_SUFFIX: &str = "budlum.xyz";

/// The most labels a gateway address may have after the suffix: one subdomain
/// and one name. `a.b.c.budlum.xyz` is not a site address.
const MAX_LABELS_AFTER_SUFFIX: usize = 2;

/// A name and, optionally, the subdomain label that was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The registry name, e.g. `ayaz.bud`.
    pub name: String,
    /// The subdomain label, e.g. `shop`, when the host had two labels.
    pub sub: Option<String>,
}

/// True when `label` is one of the reserved service labels.
///
/// Reserved labels belong to Budlum services: `www`, `app`, `api`, `rpc`,
/// `docs`, `mail`, `explorer`, `faucet`, `status`, `testnet`. They are never
/// sold as BNS names and are never served by the gateway. An explicit DNS
/// record backs every one of them, and an explicit record wins over the
/// wildcard.
#[must_use]
pub fn is_reserved_label(label: &str) -> bool {
    RESERVED_LABELS.contains(&label)
}

/// Strip the port from a `Host` header value.
///
/// `ayaz.budlum.xyz:8443` and `ayaz.budlum.xyz` are the same address. An IPv6
/// literal in brackets is never a gateway address, so it strips to something
/// the suffix match then rejects.
fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        // A bare `:` in a bracketed IPv6 literal keeps its last group, so only
        // treat the tail as a port when it is all digits.
        Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => host,
    }
}

/// Parse a `Host` header value against `suffix`.
///
/// Returns `None` when the host is not a gateway address: a reserved label, a
/// wrong suffix, more than one subdomain, an empty label, a label the registry
/// would refuse, or an empty host.
///
/// The comparison is case-insensitive: `AYAZ.budlum.xyz` and
/// `ayaz.budlum.xyz` are the same name, because DNS is case-insensitive and a
/// gateway that treated them differently would serve two different sites under
/// one certificate.
#[must_use]
pub fn parse_host(host: &str, suffix: &str) -> Option<Target> {
    let host = strip_port(host.trim()).to_ascii_lowercase();
    if host.is_empty() || suffix.is_empty() {
        return None;
    }
    let suffix = suffix.trim_matches('.').to_ascii_lowercase();
    if suffix.is_empty() {
        return None;
    }
    // The suffix must be the last labels of the host, preceded by a dot, so
    // `evilbudlum.xyz` and `budlum.xyz.evil.example` both fail.
    let rest = host.strip_suffix(&format!(".{suffix}"))?;
    if rest.is_empty() {
        // The bare suffix is the main site, not a registry name.
        return None;
    }
    let labels: Vec<&str> = rest.split('.').collect();
    if labels.len() > MAX_LABELS_AFTER_SUFFIX || labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let (label, sub) = match labels.as_slice() {
        [label] => (*label, None),
        [sub, label] => (*label, Some((*sub).to_string())),
        _ => return None,
    };
    if is_reserved_label(label) || sub.as_deref().is_some_and(is_reserved_label) {
        return None;
    }
    if !BnsRegistry::is_valid_label(label) {
        return None;
    }
    if let Some(sub) = &sub {
        if !BnsRegistry::is_valid_label(sub) {
            return None;
        }
    }
    // The registry sells 3..=32 character labels. A one- or two-character label
    // is not a name it will ever hold, so the gateway does not ask for one.
    if !(3..=32).contains(&label.chars().count()) {
        return None;
    }
    Some(Target {
        name: format!("{label}.bud"),
        sub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(host: &str) -> Option<Target> {
        parse_host(host, DEFAULT_GATEWAY_SUFFIX)
    }

    #[test]
    fn a_single_label_is_a_name_and_two_are_a_subdomain() {
        assert_eq!(
            parse("ayaz.budlum.xyz"),
            Some(Target {
                name: "ayaz.bud".into(),
                sub: None
            })
        );
        assert_eq!(
            parse("shop.ayaz.budlum.xyz"),
            Some(Target {
                name: "ayaz.bud".into(),
                sub: Some("shop".into())
            })
        );
    }

    #[test]
    fn case_and_port_do_not_change_the_answer() {
        let expected = Some(Target {
            name: "ayaz.bud".into(),
            sub: None,
        });
        assert_eq!(parse("AYAZ.budlum.xyz"), expected);
        assert_eq!(parse("Ayaz.BudLum.XYZ"), expected);
        assert_eq!(
            parse("ayaz.budlum.xyz:8443"),
            Some(Target {
                name: "ayaz.bud".into(),
                sub: None
            })
        );
        assert_eq!(
            parse("shop.ayaz.budlum.xyz:443"),
            Some(Target {
                name: "ayaz.bud".into(),
                sub: Some("shop".into())
            })
        );
    }

    #[test]
    fn the_bare_suffix_and_reserved_labels_go_to_budlum_not_to_bns() {
        // The apex is the main site.
        assert_eq!(parse("budlum.xyz"), None);
        // Explicit records for Budlum services win over the wildcard.
        for label in [
            "www", "app", "api", "rpc", "docs", "mail", "explorer", "faucet", "status", "testnet",
        ] {
            assert_eq!(
                parse(&format!("{label}.budlum.xyz")),
                None,
                "{label} is a service label, not a name"
            );
        }
        // The reserved check also covers the subdomain position, so
        // `www.ayaz.budlum.xyz` is not a way around it.
        assert_eq!(parse("www.ayaz.budlum.xyz"), None);
    }

    #[test]
    fn more_than_one_subdomain_is_not_an_address() {
        assert_eq!(parse("a.b.c.budlum.xyz"), None);
        assert_eq!(parse("a.b.ayaz.budlum.xyz"), None);
    }

    #[test]
    fn a_lookalike_suffix_or_an_empty_host_is_refused() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("   "), None);
        // A suffix that is not the last labels.
        assert_eq!(parse("ayaz.budlum.xyz.evil.example"), None);
        // The suffix glued to the label without a dot.
        assert_eq!(parse("evilbudlum.xyz"), None);
        // Another TLD.
        assert_eq!(parse("ayaz.budlum.xyz.tr"), None);
    }

    #[test]
    fn labels_follow_the_registry_table() {
        // Uppercase is folded before the check, so case alone is fine; what
        // fails is everything the registry would refuse.
        assert_eq!(parse("-ayaz.budlum.xyz"), None);
        assert_eq!(parse("ayaz-.budlum.xyz"), None);
        // Non-ASCII does not survive the lowercase fold into the ASCII table.
        assert_eq!(parse("ayaz\u{0131}.budlum.xyz"), None);
        assert_eq!(parse("ayaz_bud.budlum.xyz"), None);
        // Two characters and thirty-three characters are not registry names.
        assert_eq!(parse("ay.budlum.xyz"), None);
        assert_eq!(parse(&format!("{}.budlum.xyz", "a".repeat(33))), None);
        // The boundaries themselves are fine.
        assert!(parse(&format!("{}.budlum.xyz", "a".repeat(32))).is_some());
        assert_eq!(
            parse("a-1.budlum.xyz"),
            Some(Target {
                name: "a-1.bud".into(),
                sub: None
            })
        );
    }

    #[test]
    fn the_suffix_is_configuration_not_a_constant() {
        assert_eq!(
            parse_host("ayaz.example.test", "example.test"),
            Some(Target {
                name: "ayaz.bud".into(),
                sub: None
            })
        );
        // The default suffix no longer matches once it is configured away.
        assert_eq!(parse_host("ayaz.budlum.xyz", "example.test"), None);
    }
}
