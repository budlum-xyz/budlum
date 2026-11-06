//! Lane C live-verification locks (WP-03, directive section 14).
//!
//! `docs/audit/live/lane-c.md` records 74 ledger entries against the live tree.
//! Four are closed in this snapshot (`Kapalı (önceden düzeltilmiş)`) and
//! sixteen more carry a closed *foot*: a guard that already exists inside a
//! record whose other feet are still open. This file holds those guards down.
//!
//! Every lock here is a **source lock**: it reads the production file the claim
//! lives in and asserts the guard is still there, in the order that matters. A
//! failing lock means the tree regressed below the state
//! `docs/audit/live/lane-c.md` records, not that a closing package did its work.
//! A closing package that tightens a lock moves the tightened lock into its own
//! pull request.
//!
//! A record marked `Açık` or `Doğrulandı` in the ledger gets **no** lock here:
//! a lock that asserts a defect is still present would block the fix. The red
//! reproduction test for each open record is owed on the `audit/repro-c` branch
//! and moves into the closing package's pull request (directive sections 14.1
//! and 15.8, S-3).
//!
//! The BudZero-side feet of the same lane live in `budzero/tests/audit_lane_c.rs`.

/// Only the shipped half of a file: everything before the first
/// `#[cfg(test)] mod tests`. A guard that exists only in a test cannot hold a
/// record closed.
fn production_part(src: &str) -> &str {
    src.split("\n#[cfg(test)]\nmod tests").next().unwrap_or(src)
}

/// The byte range between two anchors, panicking with the ledger identity when
/// either anchor is gone. Anchors are matched on content, never on line number.
fn between<'a>(src: &'a str, id: &str, open: &str, close: &str) -> &'a str {
    let start = src
        .find(open)
        .unwrap_or_else(|| panic!("{id}: anchor `{open}` is gone from the file"))
        + open.len();
    let rest = &src[start..];
    let end = rest
        .find(close)
        .unwrap_or_else(|| panic!("{id}: anchor `{close}` is gone from the file"));
    &rest[..end]
}

/// BLG-039 (closed record): `degree_bits` comes out of the proof bytes and is
/// used as a shift amount. The bound must be tested **before** the shift, or a
/// corrupt proof aborts the node rather than being rejected.
#[test]
fn blg_039_degree_bits_is_bounded_before_the_shift() {
    let verifier = production_part(include_str!("../../budzero/bud-proof/src/bud_stark/verifier.rs"));
    let bound = verifier
        .find("> MAX_VERIFIER_DEGREE_BITS")
        .expect("the degree_bits bound must exist in the verifier");
    let shift = verifier
        .find("let degree = 1 << degree_bits;")
        .expect("the degree shift must exist in the verifier");
    assert!(
        bound < shift,
        "degree_bits is shifted before it is bounded: a corrupt proof aborts the node"
    );
    assert!(
        verifier.contains("return Err(VerificationError::InvalidProofShape)")
            && verifier.contains("pub const MAX_VERIFIER_DEGREE_BITS: usize = 32;"),
        "the bound must refuse with InvalidProofShape and stay below usize::BITS"
    );
}

/// BLG-043 (open, foot closed): the unlock credits the exact units the burn
/// recorded, never a fresh split from live fee parameters, and a transfer with
/// no recorded debit is refused.
#[test]
fn blg_043_the_unlock_credits_the_recorded_burn() {
    let bridge = production_part(include_str!("../cross_domain/bridge_tx.rs"));
    let unlock = between(
        bridge,
        "BLG-043",
        "pub fn unlock_from_verified_event(",
        "\n}\n",
    );
    assert!(
        unlock.contains("transfer.burned_amount == 0"),
        "the unlock must refuse a transfer that recorded no debit"
    );
    assert!(
        unlock.contains("let returned = transfer.burned_amount;"),
        "the unlock must credit the recorded burn, not a recomputed split"
    );
    assert!(
        unlock.contains("check_burn_matches_lock_domain"),
        "the unlock must cross-check the lock domain before any credit"
    );
    assert!(
        bridge.contains("fn check_burn_matches_lock_domain"),
        "the domain cross-check must be a named rule, not an inline comparison"
    );
}

/// BLG-054 (open, foot closed): an unlock without an explicit
/// `expected_block_hash` is refused at the chain door. The burn payload commits
/// the Ethereum destination.
#[test]
fn blg_054_the_unlock_door_requires_an_expected_block_hash() {
    let chain = production_part(include_str!("../chain/blockchain.rs"));
    let door = between(
        chain,
        "BLG-054",
        "pub fn unlock_bridge_transfer_from_verified_event(",
        "\n    pub fn get_transaction_by_hash",
    );
    assert!(
        door.contains("Bridge unlock requires explicit expected_block_hash"),
        "the unlock door must refuse a missing expected_block_hash"
    );
    assert!(
        door.contains("ok_or_else"),
        "the refusal must be a fallible conversion, not an assertion"
    );
}

/// BLG-057 (open, foot closed): every bridge lock carries a real expiry. A zero
/// expiry never expires, and an expiry at or below the source height would let
/// the refund win the race against delivery.
#[test]
fn blg_057_a_bridge_expiry_is_real() {
    let bridge = production_part(include_str!("../cross_domain/bridge.rs"));
    assert!(
        bridge.contains("Bridge lock expiry must be set (zero never expires)"),
        "a zero expiry must be refused"
    );
    assert!(
        bridge.contains("Bridge lock expiry must be after the source height"),
        "an expiry at or below the source height must be refused"
    );
    assert!(
        bridge.contains("MAX_BURN_EXPIRY_BLOCKS"),
        "a burn expiry must be bounded by a named ceiling"
    );
}

/// BLG-040 (open, foot closed): the proving cost of one block is bounded. A
/// block of near-limit contract calls repeats the heaviest proof
/// `MAX_TRANSACTIONS_PER_BLOCK` times without this budget.
#[test]
fn blg_040_one_block_has_a_proving_budget() {
    let zkvm = production_part(include_str!("../execution/zkvm.rs"));
    assert!(
        zkvm.contains("pub const MAX_BLOCK_CONTRACT_GAS: u64 = 64 * DEFAULT_CONTRACT_GAS_LIMIT;"),
        "the per-block contract proving budget must exist"
    );
    let executor = production_part(include_str!("../execution/executor.rs"));
    assert!(
        executor.contains("MAX_BLOCK_CONTRACT_GAS"),
        "the executor must enforce the budget it declares"
    );
}

/// BLG-130 (open, foot closed): a sync-committee rotation without the finality
/// branch is refused. The previous unconditional swap let any holder of a
/// `SyncCommitteeState` inject a chosen committee on the next period.
#[test]
fn blg_130_rotation_requires_the_finality_branch() {
    let sync = production_part(include_str!("../cross_domain/evm/sync_committee.rs"));
    let rotate = between(
        sync,
        "BLG-130",
        "pub fn rotate_period(",
        "\n}\n",
    );
    assert!(
        rotate.contains("Err(SyncCommitteeError::RotationBranchRequired)"),
        "a rotation without the branch must be refused, not performed"
    );
    assert!(
        !rotate.contains("state.next_sync_committee ="),
        "the rotation must not swap the committee unconditionally"
    );
}

/// BLG-154 (open, foot closed): a proof that drops its aux commitment cannot
/// skip the LogUp constraints, including the Program CTL that binds executed
/// instructions to the committed program.
#[test]
fn blg_154_the_aux_commitment_cannot_be_dropped() {
    let verifier = production_part(include_str!("../../budzero/bud-proof/src/bud_stark/verifier.rs"));
    assert!(
        verifier.contains("if preprocessed_width > 0 && commitments.aux_trace.is_none()"),
        "a program AIR without its aux commitment must be refused by shape"
    );
    assert!(
        verifier.contains("air_requires_aux"),
        "the verifier must re-derive the requirement from the AIR, never trust the proof"
    );
}

/// BLG-198 (open, foot closed): the parser bounds nesting depth, so no AST can
/// drive the compiler into a stack overflow inside the 64 KiB limit.
#[test]
fn blg_198_the_parser_bounds_nesting_depth() {
    let parser = production_part(include_str!("../../budzero/bud-compiler/src/parser.rs"));
    let depth = parser
        .find("pub const MAX_NESTING_DEPTH: u32 = 32;")
        .expect("the nesting bound must exist");
    let check = parser
        .find("if self.depth >= MAX_NESTING_DEPTH")
        .expect("the nesting bound must be enforced");
    assert!(
        depth < check,
        "the bound must be declared before it is enforced"
    );
    assert!(
        parser.contains("nests deeper than {MAX_NESTING_DEPTH} levels"),
        "the refusal must name the bound it applied"
    );
}

/// BLG-199 (open, foot closed): an odd tail is promoted under its own function,
/// so a three-leaf tree and a four-leaf tree with a duplicated tail cannot share
/// a root. The named collision is pinned by the module's own test.
#[test]
fn blg_199_the_odd_tail_is_promoted_not_duplicated() {
    let merkle = production_part(include_str!("../consensus/merkle_tree.rs"));
    assert!(
        merkle.contains("odd_promotion_sentinel"),
        "the promotion sentinel must exist so a verifier sees `no sibling here`"
    );
    assert!(
        merkle.contains("pub fn merkle_root_from_proof"),
        "the verifier rebuild must consume the sentinel"
    );
    let commitment = include_str!("../settlement/commitment_tree.rs");
    assert!(
        commitment.contains("an_odd_tail_never_mimics_a_duplicated_leaf"),
        "the collision must stay pinned by a named regression test"
    );
}

/// BLG-205 (open, foot closed): readmission rebuilds the adapter from the
/// **stored** golden sample and refuses a domain the adapter still admits. The
/// old path trusted a re-uploaded rule set.
#[test]
fn blg_205_readmit_rebuilds_the_stored_adapter() {
    let external = production_part(include_str!("../cross_domain/external/external_tx.rs"));
    let readmit = between(external, "BLG-205", "fn readmit(", "\nfn schedule_fork(");
    assert!(
        readmit.contains("entry.golden.clone()"),
        "readmission must rebuild from the stored golden sample"
    );
    assert!(
        readmit.contains("admit(adapter.as_ref(), &entry.policy)"),
        "readmission must re-run the admission gate instead of trusting the caller"
    );
    assert!(
        readmit.contains("MAX_READMIT_REASON_BYTES"),
        "the reason the readmission records on chain must be bounded"
    );
}

/// The ledger and the locks must agree on which records are closed: a name in
/// this file that the ledger calls `Kapalı` must be the only kind of record the
/// file locks. This keeps the next author from adding a lock that freezes a
/// defect in place.
#[test]
fn the_lane_c_locks_never_pin_an_open_headline() {
    let ledger = include_str!("../../docs/audit/live/lane-c.md");
    for id in ["BLG-039", "BLG-043", "BLG-040", "BLG-054", "BLG-057"] {
        let row = ledger
            .lines()
            .find(|line| line.starts_with(&format!("| {id} |")))
            .unwrap_or_else(|| panic!("{id} must have a row in the ledger"));
        assert!(
            row.contains("Kapalı") || row.contains("closed foot") || row.contains("Closed foot"),
            "{id}: a lock needs a closed record or a written closed foot"
        );
    }
}
