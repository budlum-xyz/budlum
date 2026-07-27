//! Locks the vendored security patches.
//!
//! Three advisories reached this tree through libp2p and could not be closed by
//! upgrading it: libp2p 0.56.0 is the newest release, it pins hickory to
//! ^0.25.2, and libp2p-yamux hard-depends on the vulnerable yamux 0.12
//! alongside the patched 0.13.
//!
//! Rather than carry them as accepted risk, `third_party/` holds patched
//! versions wired in through `[patch.crates-io]`. These tests fail if that
//! wiring is removed or drifts back to a vulnerable version — the patch is
//! only worth anything while it is actually applied.

#[cfg(test)]
mod tests {
    /// The lockfile must not contain a vulnerable hickory or yamux.
    ///
    /// GHSA-3v94-mw7p-v465 and GHSA-q2qq-hmj6-3wpp affect hickory <= 0.25.2 and
    /// <= 0.26.0; GHSA-vxx9-2994-q338 affects yamux < 0.13.10. Checking the
    /// resolved graph rather than the manifest, because a transitive dependency
    /// can reintroduce either without any manifest changing.
    #[test]
    fn no_vulnerable_hickory_or_yamux_in_the_lockfile() {
        let lock = include_str!("../../Cargo.lock");

        let mut offenders = Vec::new();
        let mut name = String::new();
        for line in lock.lines() {
            if let Some(rest) = line.strip_prefix("name = \"") {
                name = rest.trim_end_matches('"').to_string();
            } else if let Some(rest) = line.strip_prefix("version = \"") {
                let version = rest.trim_end_matches('"');
                let bad = match name.as_str() {
                    "hickory-proto" | "hickory-resolver" | "hickory-net" => {
                        version.starts_with("0.25.") || version == "0.26.0"
                    }
                    "yamux" => version.starts_with("0.12."),
                    _ => false,
                };
                if bad {
                    offenders.push(format!("{name} {version}"));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "vulnerable versions are back in the dependency graph: {offenders:?}. \
             The [patch.crates-io] entries pointing at third_party/ are what keep \
             them out; check whether one was removed or a new dependency pulled \
             an unpatched copy."
        );
    }

    /// The patch wiring must stay in place.
    ///
    /// Without these entries the vendored sources are dead code and cargo
    /// silently resolves the vulnerable versions from crates.io instead.
    #[test]
    fn vendored_patches_are_wired_in() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(
            manifest.contains("[patch.crates-io]"),
            "the [patch.crates-io] section is gone; the vendored security \
             patches under third_party/ are no longer applied"
        );
        for crate_name in [
            "hickory-proto",
            "hickory-resolver",
            "hickory-net",
            "libp2p-dns",
            "libp2p-mdns",
            "libp2p-yamux",
        ] {
            assert!(
                manifest.contains(&format!("{crate_name} = {{ path = \"third_party/")),
                "{crate_name} is no longer patched to the vendored copy"
            );
        }
    }

    /// The vendored yamux shim must not reintroduce the 0.12 backend.
    ///
    /// Upstream libp2p-yamux links both majors and picks between them. The
    /// vendored copy drops 0.12 entirely; if an alias for it reappears, the
    /// vulnerable code is back in the binary even though the patch is present.
    #[test]
    fn vendored_yamux_has_no_012_backend() {
        let manifest = include_str!("../../third_party/libp2p-yamux/Cargo.toml");
        assert!(
            !manifest.contains("yamux012"),
            "third_party/libp2p-yamux declares a yamux012 dependency again; \
             GHSA-vxx9-2994-q338 is reachable through it"
        );
    }
}
