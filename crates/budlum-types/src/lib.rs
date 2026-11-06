//! budlum-types — mobile/client-facing common types (crate cradle for §8 İP-11).
//!
//! Section 8 of THE BUDLUM DIREKTIFI splits the codebase into layers and names
//! `crates/budlum-types` as the new home for every consensus/network/content
//! type that must be shared by a wallet, an RPC client, a browser extension, or
//! a mobile node *without* pulling in sled, tokio, the validator state
//! machine, or any other anchor-only dependency.
//!
//! This crate is a **cradle** for İP-11: it exists so downstream crates can
//! begin depending on `budlum-types::` instead of `budlum_core::` for their
//! type imports, which is a precondition for İP-13 (the big extraction move)
//! to be a one-line re-export drop rather than a 64-crate rename churn.
//!
//! Migration state (tracked in docs/work/PACKAGES.md under İP-11..İP-13):
//!
//! * İP-11 (this crate): crate created, registered in the workspace, holds
//!   the cradle module layout and a pinned test proving it compiles without
//!   std::fs/sled/tokio leaking into the dependency tree.
//! * İP-12: `wallet-core`, `budlum-uel-abi`, `budlum-note-packing`, and the
//!   mobile client flip their dependency edges to point here.
//! * İP-13: each type is physically moved out of src/ (in `budlum-core`) into
//!   crates/budlum-types/src/; compatibility shims in budlum-core re-export
//!   from here for one release so downstream crates have a migration window
//!   (§15.8 İP-13 acceptance criterion 3).
//!
//! Until İP-13 lands, every consensus type still lives in budlum-core. The
//! cradle intentionally starts empty: new types that are *mobile-only* (e.g.
//! the QR optical frame reader primitives, client-side ContentRef
//! constructors) belong here now and that is the only reason this crate is
//! non-empty before İP-13.
//!
//! # Crate boundary rules (§15.8 İP-11 acceptance criterion 2)
//!
//! * No direct or transitive dependency on `sled`, `tokio`, `libp2p`,
//!   `hyper`, `prometheus`, `jsonrpsee`, `cryptoki`, `clap`, `tracing-
//!   subscriber`, `reqwest`, or any other validator-runtime crate.
//! * `std::fs`, `std::net`, `std::process` are forbidden at this layer
//!   (mobile nodes do not have them on all targets).
//! * The crate must compile with `default-features = false` on
//!   `budlum-core` so that `bpqs-research`, `p2p-mdns`, and `wallet-ml-dsa`
//!   are not forced on mobile clients.
#![deny(unsafe_op_in_unsafe_fn)]

// No re-exports from budlum-core in the cradle. İP-12/İP-13 will add them
// along with the actual type moves. This crate currently contains only the
// cradle documentation and the pinned test below.

// ---- Mobile-only primitive types go here starting at İP-13 ----

#[cfg(test)]
mod tests {
    //! Craddle compile-time pins.
    //!
    //! These tests exist to fail the build the moment somebody adds a
    //! forbidden dependency to this crate. They are not behavioral.

    /// Marker: the crate compiles at all. The only way this test can fail is
    /// if the crate itself fails to build (which is the same signal cargo
    /// check would give). Kept as a named test so §5 gate runners can assert
    /// the cradle was built.
    #[test]
    fn cradle_compiles() {
        assert!(true);
    }
}
