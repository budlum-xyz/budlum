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
    /// All three lockfiles. They are separate workspaces that resolve
    /// independently, and Dependabot reports each one separately — three
    /// advisories times three lockfiles is where the nine alerts came from.
    /// Fixing only the root would leave six of them open.
    const LOCKFILES: [(&str, &str); 3] = [
        ("Cargo.lock", include_str!("../../Cargo.lock")),
        (
            "budzero/Cargo.lock",
            include_str!("../../budzero/Cargo.lock"),
        ),
        ("fuzz/Cargo.lock", include_str!("../../fuzz/Cargo.lock")),
    ];

    /// Versions of `crate_name` recorded in one lockfile.
    fn locked_versions_in(lock: &str, crate_name: &str) -> Vec<String> {
        let needle = format!("name = \"{crate_name}\"\n");
        lock.match_indices(&needle)
            .filter_map(|(at, _)| {
                let rest = &lock[at + needle.len()..];
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
        for (name, lock) in LOCKFILES {
            let versions = locked_versions_in(lock, "yamux");
            assert!(!versions.is_empty(), "{name}: yamux must be in the graph");
            assert_eq!(
                versions.len(),
                1,
                "{name}: yamux resolves to {versions:?}; libp2p-yamux 0.47 \
                 linked two versions at once and one of them (0.12.x) is \
                 vulnerable to GHSA-vxx9-2994-q338"
            );
            assert!(
                version_at_least(&versions[0], "0.13.10"),
                "{name}: yamux {} is below the patched 0.13.10 \
                 (GHSA-vxx9-2994-q338)",
                versions[0]
            );
        }
    }

    /// GHSA-3v94-mw7p-v465 has no patched 0.25.x release, and
    /// GHSA-q2qq-hmj6-3wpp is fixed in 0.26.1. Both are closed by moving the
    /// whole hickory family to 0.26.1.
    #[test]
    fn hickory_is_patched() {
        for (name, lock) in LOCKFILES {
            for crate_name in ["hickory-proto", "hickory-resolver"] {
                let versions = locked_versions_in(lock, crate_name);
                assert!(
                    !versions.is_empty(),
                    "{name}: {crate_name} must be in the graph \
                     (libp2p `dns` feature)"
                );
                for v in &versions {
                    assert!(
                        version_at_least(v, "0.26.1"),
                        "{name}: {crate_name} {v} is below the patched 0.26.1 \
                         (GHSA-3v94-mw7p-v465 has no 0.25.x fix, \
                         GHSA-q2qq-hmj6-3wpp is fixed in 0.26.1)"
                    );
                }
            }
        }
    }

    /// Every manifest that depends on libp2p must take it from the pinned
    /// tree, and must pin it by full revision.
    ///
    /// The three workspaces resolve independently, so a crates.io requirement
    /// left in any one of them puts the vulnerable yamux/hickory back into
    /// that lockfile — six of the original nine Dependabot alerts.
    ///
    /// A direct git dependency is used rather than `[patch.crates-io]`
    /// because tools that re-resolve the manifest in a scratch directory
    /// (cargo-semver-checks among them) do not carry the patch table across,
    /// and then cannot select a version at all.
    #[test]
    fn every_libp2p_dependency_is_pinned_to_the_tree() {
        const REV: &str = "38b8a2c0e91bf6955f5357adcdd40d3b6683a0dd";
        for (name, manifest) in [
            ("Cargo.toml", include_str!("../../Cargo.toml")),
            (
                "budzero/bud-node/Cargo.toml",
                include_str!("../../budzero/bud-node/Cargo.toml"),
            ),
            ("fuzz/Cargo.toml", include_str!("../../fuzz/Cargo.toml")),
        ] {
            let dep = manifest
                .lines()
                .find(|l| l.trim_start().starts_with("libp2p = "))
                .unwrap_or_else(|| panic!("{name}: no libp2p dependency line"));
            assert!(
                dep.contains("git = \"https://github.com/libp2p/rust-libp2p\""),
                "{name}: libp2p must come from the pinned tree, got: {dep}"
            );
            assert!(
                dep.contains(REV),
                "{name}: libp2p must be pinned by full revision, got: {dep}"
            );
            assert!(
                !dep.contains("branch =") && !dep.contains("tag ="),
                "{name}: a branch or tag can move; pin by revision only"
            );
        }
    }

    /// No `[patch.crates-io]` may remain. It is what broke cargo-semver-checks,
    /// and keeping both it and the git pin would be two sources of truth.
    #[test]
    fn no_patch_table_shadows_the_git_pin() {
        for (name, manifest) in [
            ("Cargo.toml", include_str!("../../Cargo.toml")),
            (
                "budzero/Cargo.toml",
                include_str!("../../budzero/Cargo.toml"),
            ),
            ("fuzz/Cargo.toml", include_str!("../../fuzz/Cargo.toml")),
        ] {
            for line in manifest.lines() {
                let code = line.split('#').next().unwrap_or("").trim();
                assert_ne!(
                    code, "[patch.crates-io]",
                    "{name} still carries a patch table; the git pin on the \
                     dependency line is the single source of truth"
                );
            }
        }
    }

    /// cargo-deny denies unknown git sources, so the one exception has to be
    /// allow-listed explicitly and by host, not switched off wholesale.
    #[test]
    fn git_source_policy_stays_closed_except_for_libp2p() {
        // Both cargo-deny configs, not just the root one: budzero keeps its own
        // next to its manifest and CI runs the two as separate jobs, so a
        // policy that lands in only one of them leaves the other gate red.
        for (name, deny) in [
            (
                ".quality/deny.toml",
                include_str!("../../.quality/deny.toml"),
            ),
            ("budzero/deny.toml", include_str!("../../budzero/deny.toml")),
        ] {
            assert!(
                deny.contains("unknown-git = \"deny\""),
                "{name}: cargo-deny must keep denying unknown git sources"
            );
            assert!(
                deny.contains("allow-git = [\"https://github.com/libp2p/rust-libp2p\"]"),
                "{name}: the rust-libp2p host must be the only allowed git \
                 source; a broader allow-list would let any git dependency \
                 through"
            );
        }
    }

    /// The patch that delivers those versions has to stay, and it has to stay
    /// explained. A bare `[patch.crates-io]` entry with no reason is how a
    /// temporary pin becomes permanent.
    #[test]
    fn libp2p_patch_records_why_it_exists() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(
            manifest.contains("rust-libp2p"),
            "the libp2p git pin is gone; if 0.57.0 was published, drop the pin \
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

    /// The gossipsub PRUNE-backoff advisories must stay closed.
    ///
    /// Two disclosures, same handler, three months apart:
    ///
    /// * `CVE-2026-33040` / `GHSA-gc42-3jg7-rxr2` — a `PRUNE` carrying a
    ///   near-maximum backoff overflowed on *insertion*. Fixed in 0.49.3.
    /// * `CVE-2026-34219` / `GHSA-xqmp-fxgv-xvq5` — the same value survived
    ///   insertion and overflowed later, in the *heartbeat*, on
    ///   `backoff_time + slack`. Fixed in 0.49.4.
    ///
    /// Either one is a remote unauthenticated panic: any peer that can open a
    /// gossipsub session takes the node down with a single control message and
    /// replays it after every restart. Rust turns the overflow into a panic
    /// rather than memory corruption, so the class is denial of service — but
    /// for a validator, "the process is dead" is the whole impact.
    ///
    /// A version assertion alone is not enough here. `libp2p-gossipsub` comes
    /// from a git revision, not crates.io, so the `0.50.0` in the lockfile is
    /// whatever that tree happened to call itself — it is not evidence that
    /// either patch is in it. This asserts the version *and* names both
    /// advisories so a future pin bump has to be checked against them rather
    /// than trusted for having a larger number.
    #[test]
    fn gossipsub_prune_backoff_advisories_stay_closed() {
        let lock = include_str!("../../Cargo.lock");
        let versions = locked_versions_in(lock, "libp2p-gossipsub");
        assert!(
            !versions.is_empty(),
            "libp2p-gossipsub must be in the graph; gossipsub is how blocks propagate"
        );
        for version in &versions {
            assert!(
                version_at_least(version, "0.49.4"),
                "libp2p-gossipsub {version} predates the PRUNE backoff fixes \
                     (CVE-2026-33040 insertion overflow, fixed 0.49.3; \
                     CVE-2026-34219 heartbeat overflow, fixed 0.49.4). Any peer \
                     can panic this node with one control message."
            );
        }

        // The pin is by full revision, so record what was verified in that
        // tree. Checked by hand against
        // 38b8a2c0e91bf6955f5357adcdd40d3b6683a0dd:
        //
        //   behaviour.rs: const MAX_REMOTE_PRUNE_BACKOFF_SECONDS: u64 = 3600;
        //   backoff.rs:   backoff_time.checked_add(slack)
        //
        // the bound that closes the insertion path and the checked arithmetic
        // that closes the heartbeat path. If the revision moves, both have to
        // be re-checked in the new tree.
        let manifest = include_str!("../../Cargo.toml");
        assert!(
            manifest.contains("38b8a2c0e91bf6955f5357adcdd40d3b6683a0dd"),
            "the libp2p revision changed. Re-verify in the new tree that \
                 gossipsub still bounds remote PRUNE backoff \
                 (MAX_REMOTE_PRUNE_BACKOFF_SECONDS) and still uses checked_add for \
                 the heartbeat slack, then update this hash."
        );
    }
}
