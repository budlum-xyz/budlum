// BudZero-side lane C locks (WP-03, directive section 14).
//
// The lane C ledger (`docs/audit/live/lane-c.md`) closes four records in this
// snapshot and holds several more feet of open records. The BudZero workspace is
// a separate build with its own `deny.toml` and its own lint profile, so its
// locks live here, at the workspace root the WP-03 card names, and are compiled
// as the `audit_lane_c` test of `bud-proof` through the include shim at
// `bud-proof/tests/audit_lane_c.rs`.
//
// These are pure source locks: no feature, no proving and no wall clock. They
// assert that the guard the ledger relies on is still in the production half of
// the file. A lock failing means the tree regressed below the recorded state.
// Open records get no lock: a test that pins a defect would block the fix, and
// the red reproduction tests are owed on the `audit/repro-c` branch (S-3).
//
// Paths are relative to this file (`budzero/tests/`).

/// Only the shipped half of a file: everything before the first
/// `#[cfg(test)] mod tests`.
fn production_part(src: &str) -> &str {
    src.split("\n#[cfg(test)]\nmod tests").next().unwrap_or(src)
}

/// BLG-039 (closed record): `degree_bits` is read out of the proof bytes and is
/// shifted. The bound is tested first, so a corrupt proof is rejected instead of
/// aborting a node whose release profile is `panic = "abort"`.
#[test]
fn blg_039_degree_bits_is_bounded_before_the_shift() {
    let verifier = production_part(include_str!("../bud-proof/src/bud_stark/verifier.rs"));
    let bound = verifier
        .find("> MAX_VERIFIER_DEGREE_BITS")
        .expect("the bound test must exist");
    let shift = verifier
        .find("let degree = 1 << degree_bits;")
        .expect("the shift must exist");
    assert!(bound < shift, "the bound must precede the shift");
    assert!(
        verifier.contains("MAX_VERIFIER_DEGREE_BITS: usize = 32"),
        "the bound must stay well below usize::BITS: it is shifted a second time"
    );
}

/// BLG-114 (closed record): a `match` integer pattern is generated like any
/// other literal, so a wide value is range checked and split rather than cut to
/// an `i32` immediate.
#[test]
fn blg_114_a_match_pattern_is_not_cut_to_i32() {
    let codegen = production_part(include_str!("../bud-compiler/src/codegen.rs"));
    let arm = codegen
        .find("MatchPattern::IntLit(val) => {")
        .expect("the match arm must exist");
    let window = &codegen[arm..(arm + 900).min(codegen.len())];
    assert!(
        window.contains("self.generate_expr(&Expr::Int(*val), scope, storage)"),
        "the pattern must go through the ordinary literal path"
    );
    assert!(
        !window.contains("as i32"),
        "the pattern must not be truncated to an i32 immediate"
    );
    let regression = include_str!("../bud-compiler/tests/regression.rs");
    for test in [
        "match_pattern_is_not_truncated_to_i32",
        "arm_let_does_not_clobber_outer_variable",
        "duplicate_main_and_oversized_literal_are_refused",
    ] {
        assert!(
            regression.contains(test),
            "the permanent regression test `{test}` must stay"
        );
    }
}

/// BLG-136 (closed record): a call used as a statement compiles. An identifier
/// followed by an opening parenthesis is never taken as an assignment target.
#[test]
fn blg_136_a_bare_call_statement_is_a_statement() {
    let parser = production_part(include_str!("../bud-compiler/src/parser.rs"));
    assert!(
        parser.contains("Token::Ident(_) if self.tokens.get(self.pos + 1) == Some(&Token::ParenOpen)"),
        "the bare-call arm must exist"
    );
    let regression = include_str!("../bud-compiler/tests/regression.rs");
    assert!(
        regression.contains("bare_call_statement_compiles_and_runs"),
        "the permanent regression test must stay"
    );
}

/// BLG-162 (closed record): CRLF is whitespace and a comment may carry several
/// stars. Both were source-shape bugs, so both are one regex away from coming
/// back.
#[test]
fn blg_162_crlf_is_whitespace_and_comments_may_carry_stars() {
    let lexer = production_part(include_str!("../bud-compiler/src/lexer.rs"));
    assert!(
        lexer.contains(r"[ \t\r\n\f]+"),
        "the whitespace skip class must keep carrying backslash-r"
    );
    assert!(
        lexer.contains("*+[^*/]"),
        "the block-comment regex must keep accepting a run of stars"
    );
    let lib = include_str!("../bud-compiler/src/lib.rs");
    assert!(
        lib.contains("fn crlf_line_ends_are_whitespace"),
        "the permanent regression test must stay"
    );
    let regression = include_str!("../bud-compiler/tests/regression.rs");
    assert!(
        regression.contains("hex_match_pattern_matches"),
        "a hexadecimal match pattern must stay accepted"
    );
}

/// BLG-154 (open, foot closed): a proof that drops its aux commitment cannot
/// skip the LogUp constraints, including the Program CTL that binds the executed
/// instructions to the committed program.
#[test]
fn blg_154_the_aux_commitment_cannot_be_dropped() {
    let verifier = production_part(include_str!("../bud-proof/src/bud_stark/verifier.rs"));
    assert!(
        verifier.contains("if preprocessed_width > 0 && commitments.aux_trace.is_none()"),
        "a program AIR without its aux commitment must be refused by shape"
    );
    assert!(
        verifier.contains("air_requires_aux"),
        "the requirement must be re-derived from the AIR, not trusted from the proof"
    );
}

/// BLG-198 (open, foot closed): the parser bounds nesting depth, so no input can
/// drive the compiler into a stack overflow inside the 64 KiB limit.
#[test]
fn blg_198_the_parser_bounds_nesting_depth() {
    let parser = production_part(include_str!("../bud-compiler/src/parser.rs"));
    assert!(
        parser.contains("pub const MAX_NESTING_DEPTH: u32 = 32"),
        "the nesting bound must exist"
    );
    assert!(
        parser.contains("if self.depth >= MAX_NESTING_DEPTH"),
        "the nesting bound must be enforced"
    );
}

/// The ledger is the map for these locks: every record this file locks must be
/// written down there as closed or as a closed foot.
#[test]
fn every_budzero_lock_is_recorded_in_the_ledger() {
    let ledger = include_str!("../../docs/audit/live/lane-c.md");
    for id in ["BLG-039", "BLG-114", "BLG-136", "BLG-162", "BLG-154", "BLG-198"] {
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
