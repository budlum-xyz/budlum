//! Locks the reachability arguments used to accept open advisories.
//!
//! Three advisories are currently carried rather than patched, each because the
//! vulnerable code path is not reachable from this build. That argument is only
//! worth anything while it stays true, and every one of them depends on a fact
//! that a routine dependency change can silently flip:
//!
//!   * GHSA-vxx9-2994-q338 (yamux panic) rests on `libp2p-yamux` selecting the
//!     patched 0.13 backend for `Config::default()`.
//!   * GHSA-3v94-mw7p-v465 (hickory NSEC3 loop) rests on DNSSEC validation not
//!     being compiled in.
//!   * GHSA-q2qq-hmj6-3wpp (hickory O(n²) encoding) rests on this node never
//!     serving DNS, only resolving as a client.
//!
//! These tests fail when the premise stops holding, so the exception has to be
//! re-argued instead of quietly becoming false. They are deliberately about the
//! *reason* for the exception, not about the advisory being listed somewhere.

#[cfg(test)]
mod tests {
    /// yamux: the default multiplexer config must resolve to the patched 0.13
    /// backend, and the 0.12 backend must stay unreachable from our code.
    ///
    /// `libp2p-yamux` 0.47 links both yamux 0.12.1 (vulnerable) and 0.13.10
    /// (fixed) and picks between them at construction time. `impl Default for
    /// Config` returns the 0.13 variant, and `src/network/node.rs` passes
    /// exactly `yamux::Config::default`. The 0.12 path is only reachable
    /// through APIs this repo never calls.
    ///
    /// Checked by source inspection rather than reflection: the crate exposes
    /// no way to ask a `Config` which backend it holds, so the guarantee is
    /// that the call site keeps using the default constructor.
    #[test]
    fn yamux_uses_the_default_config_constructor() {
        let node_rs = include_str!("../network/node.rs");

        assert!(
            node_rs.contains("yamux::Config::default"),
            "node.rs no longer builds the muxer with yamux::Config::default; \
             the GHSA-vxx9-2994-q338 exception assumed the patched 0.13 \
             backend, which only the default constructor selects"
        );

        // The three APIs that select the legacy 0.12 backend in
        // libp2p-yamux 0.47. If any of them appears, the exception's premise
        // is gone and the advisory becomes live.
        for legacy in ["WindowUpdateMode", "Config::client(", "Config::server("] {
            assert!(
                !node_rs.contains(legacy),
                "node.rs uses `{legacy}`, which selects the vulnerable \
                 yamux 0.12 backend; GHSA-vxx9-2994-q338 is no longer \
                 unreachable and the exception must be removed"
            );
        }
    }

    /// hickory: DNSSEC validation must not be compiled in.
    ///
    /// GHSA-3v94-mw7p-v465 is an unbounded loop in NSEC3 closest-encloser proof
    /// validation. That code only exists when hickory is built with its
    /// `dnssec` feature. Measured on the resolved graph (2026-07-27): the only
    /// active hickory-proto features are `std`, `tokio` and `futures-io`.
    ///
    /// Note this is *not* the argument the exception originally carried. The
    /// earlier text claimed hickory was reachable only through the optional
    /// `p2p-mdns` feature. That stopped being true when the libp2p `dns`
    /// feature was enabled to make `/dns4` multiaddrs dialable: hickory now
    /// ships in default builds via `libp2p-dns`. The advisory is still not
    /// reachable, but for a different reason, and the note was corrected.
    #[test]
    fn dnssec_validation_is_not_compiled_in() {
        // `cfg(feature = ...)` cannot see a dependency's features, so this is
        // asserted against the lockfile: enabling DNSSEC would pull in the
        // crates that implement it.
        let lock = include_str!("../../Cargo.lock");

        for dnssec_only in ["\"hickory-dnssec\"", "name = \"dnssec\""] {
            assert!(
                !lock.contains(dnssec_only),
                "Cargo.lock contains {dnssec_only}: DNSSEC support appears to \
                 be compiled in, which makes GHSA-3v94-mw7p-v465 reachable"
            );
        }
    }

    /// hickory: this node resolves names, it never serves DNS.
    ///
    /// GHSA-q2qq-hmj6-3wpp is quadratic behaviour while *encoding* a DNS
    /// message — it is triggered by producing responses, which is a server-side
    /// operation. `libp2p-dns` wraps the TCP transport in a client-side
    /// resolver: it issues queries and reads answers. Nothing in this tree
    /// constructs a DNS server or encodes a `Message` for transmission.
    #[test]
    fn no_dns_server_surface_in_tree() {
        // Walk the crate's own sources; a DNS server would have to name one of
        // these types to exist at all.
        let sources: &[&str] = &[
            include_str!("../network/node.rs"),
            include_str!("../main.rs"),
        ];

        for src in sources {
            for server_api in ["ServerFuture", "hickory_server", "hickory-server"] {
                assert!(
                    !src.contains(server_api),
                    "found `{server_api}`: this tree appears to serve DNS, \
                     which makes the encoding path of GHSA-q2qq-hmj6-3wpp \
                     reachable"
                );
            }
        }

        let lock = include_str!("../../Cargo.lock");
        assert!(
            !lock.contains("name = \"hickory-server\""),
            "hickory-server is in the dependency graph; the \
             GHSA-q2qq-hmj6-3wpp exception assumed client-only DNS use"
        );
    }

    /// The exceptions must stay written down where the scanners read them.
    ///
    /// Guards against the opposite failure: someone removes an advisory from
    /// one scanner's ignore list but not the others, leaving the gates
    /// disagreeing about what is accepted.
    #[test]
    fn advisory_exceptions_are_recorded_for_every_scanner() {
        let grype = include_str!("../../.quality/grype.yaml");
        let osv = include_str!("../../.quality/osv-scanner.toml");

        // The two scanners key the same finding by different identifiers:
        // grype reports GHSA ids, osv-scanner reports the RustSec alias.
        // Each entry is (grype id, osv-scanner id) for one advisory.
        for (ghsa, rustsec) in [
            ("GHSA-vxx9-2994-q338", "GHSA-vxx9-2994-q338"),
            ("GHSA-3v94-mw7p-v465", "RUSTSEC-2026-0118"),
        ] {
            assert!(
                grype.contains(ghsa),
                ".quality/grype.yaml no longer records {ghsa}"
            );
            assert!(
                osv.contains(rustsec),
                ".quality/osv-scanner.toml no longer records {rustsec} \
                 (the RustSec alias of {ghsa})"
            );
        }
    }
}
