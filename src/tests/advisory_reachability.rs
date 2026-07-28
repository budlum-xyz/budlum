//! Locks the resolved versions of dependencies that used to carry advisories.
//!
//! Three advisories were carried for weeks as "unreachable" exceptions:
//!
//!   * GHSA-vxx9-2994-q338 — yamux remote panic (CVSS 8.7)
//!   * GHSA-3v94-mw7p-v465 / RUSTSEC-2026-0118 — hickory NSEC3 validation loop
//!   * GHSA-q2qq-hmj6-3wpp — hickory O(n²) message encoding
//!
//! Each exception rested on a fact a routine dependency change could silently
//! flip (the muxer picking the patched backend, DNSSEC not being compiled in,
//! the node never serving DNS). None of that is needed any more: libp2p 0.56
//! pinned the vulnerable versions, and pinning the 0.57.0 tree moves the graph
//! to yamux 0.14.0 and hickory 0.26.1, so the findings are **fixed** rather
//! than argued away.
//!
//! These tests now guard the fix instead of the excuse. They fail if the graph
//! slides back to a vulnerable version, and they fail if the scanner ignore
//! lists grow the old entries back.

#[cfg(test)]
mod tests {
    const LOCK: &str = include_str!("../../Cargo.lock");

    /// Every `name = "<crate>"` block in Cargo.lock, as (name, version) pairs.
    fn locked_versions(crate_name: &str) -> Vec<String> {
        let needle = format!("name = \"{crate_name}\"\n");
        LOCK.match_indices(&needle)
            .filter_map(|(at, _)| {
                let rest = &LOCK[at + needle.len()..];
                let line = rest.lines().next()?;
                line.strip_prefix("version = \"")
                    .and_then(|v| v.strip_suffix('"'))
                    .map(str::to_owned)
            })
            .collect()
    }

    /// Compare dotted numeric versions without pulling in a semver crate.
    fn version_at_least(have: &str, want: &str) -> bool {
        let parse = |v: &str| -> Vec<u64> {
            v.split(['-', '+'])
                .next()
                .unwrap_or(v)
                .split('.')
                .map(|p| p.parse::<u64>().unwrap_or(0))
                .collect()
        };
        let (a, b) = (parse(have), parse(want));
        for i in 0..a.len().max(b.len()) {
            let (x, y) = (
                a.get(i).copied().unwrap_or(0),
                b.get(i).copied().unwrap_or(0),
            );
            if x != y {
                return x > y;
            }
        }
        true
    }

    /// GHSA-vxx9-2994-q338: a remote peer could panic the node through yamux.
    ///
    /// libp2p-yamux 0.47 linked yamux 0.12.1 *and* 0.13.10 and chose between
    /// them at construction time, so the vulnerable crate was in the graph no
    /// matter what the call site did. libp2p-yamux 0.48 drops the 0.12 path
    /// entirely and moves to 0.14.
    #[test]
    fn yamux_is_patched_and_single_version() {
        let versions = locked_versions("yamux");
        assert!(!versions.is_empty(), "yamux must be in the graph");
        assert_eq!(
            versions.len(),
            1,
            "yamux resolves to {versions:?}; libp2p-yamux 0.47 linked two \
             versions at once and one of them (0.12.x) is vulnerable to \
             GHSA-vxx9-2994-q338"
        );
        assert!(
            version_at_least(&versions[0], "0.13.10"),
            "yamux {} is below the patched 0.13.10 (GHSA-vxx9-2994-q338)",
            versions[0]
        );
    }

    /// GHSA-3v94-mw7p-v465 has no patched 0.25.x release, and
    /// GHSA-q2qq-hmj6-3wpp is fixed in 0.26.1. Both are closed by moving the
    /// whole hickory family to 0.26.1.
    #[test]
    fn hickory_is_patched() {
        for crate_name in ["hickory-proto", "hickory-resolver"] {
            let versions = locked_versions(crate_name);
            assert!(
                !versions.is_empty(),
                "{crate_name} must be in the graph (libp2p `dns` feature)"
            );
            for v in &versions {
                assert!(
                    version_at_least(v, "0.26.1"),
                    "{crate_name} {v} is below the patched 0.26.1 \
                     (GHSA-3v94-mw7p-v465 has no 0.25.x fix, \
                     GHSA-q2qq-hmj6-3wpp is fixed in 0.26.1)"
                );
            }
        }
    }

    /// The patch that delivers those versions has to stay, and it has to stay
    /// explained. A bare `[patch.crates-io]` entry with no reason is how a
    /// temporary pin becomes permanent.
    #[test]
    fn libp2p_patch_records_why_it_exists() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(
            manifest.contains("[patch.crates-io]"),
            "the libp2p patch is gone; if 0.57.0 was published, drop the patch \
             *and* this test together, after checking the lockfile still \
             resolves yamux >= 0.13.10 and hickory >= 0.26.1"
        );
        for advisory in [
            "GHSA-vxx9-2994-q338",
            "GHSA-3v94-mw7p-v465",
            "GHSA-q2qq-hmj6-3wpp",
        ] {
            assert!(
                manifest.contains(advisory),
                "Cargo.toml must keep naming {advisory} as a reason for the \
                 libp2p patch, otherwise the pin looks arbitrary"
            );
        }
    }

    /// The three advisories must not reappear in any scanner's ignore list.
    ///
    /// This is the canary for the whole change: they are patched, so ignoring
    /// them would be silencing a finding that is already fixed — and would
    /// hide a regression if the graph ever slid back.
    #[test]
    fn patched_advisories_are_not_ignored_anywhere() {
        let configs: [(&str, &str); 3] = [
            (
                ".quality/deny.toml",
                include_str!("../../.quality/deny.toml"),
            ),
            (
                ".quality/osv-scanner.toml",
                include_str!("../../.quality/osv-scanner.toml"),
            ),
            (
                ".quality/grype.yaml",
                include_str!("../../.quality/grype.yaml"),
            ),
        ];

        // Only lines that actually suppress a finding count; the files explain
        // the history in comments and that has to stay allowed.
        for (name, body) in configs {
            for line in body.lines() {
                let code = line.split('#').next().unwrap_or("").trim();
                if code.is_empty() {
                    continue;
                }
                for advisory in [
                    "GHSA-vxx9-2994-q338",
                    "CVE-2026-32314",
                    "GHSA-3v94-mw7p-v465",
                    "GHSA-q2qq-hmj6-3wpp",
                    "RUSTSEC-2026-0118",
                    "RUSTSEC-2026-0119",
                ] {
                    assert!(
                        !code.contains(advisory),
                        "{name} suppresses {advisory}, but it is patched \
                         (yamux 0.14 / hickory 0.26.1). Remove the entry — an \
                         ignore rule over a fixed finding hides the regression \
                         if the graph slides back.\nline: {code}"
                    );
                }
            }
        }
    }

    /// The version comparison above is the load-bearing part of these locks,
    /// so it gets its own canary.
    #[test]
    fn version_comparison_is_not_lexicographic() {
        assert!(version_at_least("0.13.10", "0.13.9"), "10 > 9 numerically");
        assert!(version_at_least("0.26.1", "0.26.1"), "equal passes");
        assert!(!version_at_least("0.25.2", "0.26.1"));
        assert!(!version_at_least("0.12.1", "0.13.10"));
        assert!(version_at_least("0.14.0", "0.13.10"));
    }
}
