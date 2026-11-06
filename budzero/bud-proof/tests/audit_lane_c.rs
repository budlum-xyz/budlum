//! Lane C live-verification notes and pins for the BudZero proving stack
//! (directive section 14, lane C). Recorded findings live in
//! `docs/audit/live/lane-c.md` (repo root); this file pins the facts the
//! proving stack already guarantees so the closing packages (İP-33, İP-56,
//! İP-60) cannot regress them quietly.
//!
//! Deviation note: WP-03's lock path in directive 15.8 names
//! `budzero/tests/audit_lane_c.rs`; `budzero/` is a virtual workspace with no
//! root package, so this integration test lives under `bud-proof`, the crate
//! whose STARK verifier carries the posture under test.

/// BLG-223 (pin, not a fix): the production PCS is `TwoAdicFriPcs`, whose
/// `Pcs::ZK` is `false` — the proofs are succinct and sound and hide nothing.
/// The existing unit pin `zk_flag_is_pinned`
/// (`src/plonky3_prover.rs`) fails if the PCS ever starts claiming `ZK`.
/// This source lock pins the *documented* state so the pin test cannot be
/// deleted without this file noticing. İP-56/İP-60 flip both in the same PR.
#[test]
fn blg_223_zk_absence_is_documented_and_pinned() {
    let prover = include_str!("../src/bud_stark/prover.rs");
    assert!(
        prover.contains("whose `Pcs::ZK` is `false`"),
        "the ZK-absence documentation must stay in the prover until İP-56 lands"
    );
    let plonky = include_str!("../src/plonky3_prover.rs");
    assert!(
        plonky.contains("fn zk_flag_is_pinned("),
        "the zk_flag_is_pinned unit pin must stay in plonky3_prover.rs"
    );
}
