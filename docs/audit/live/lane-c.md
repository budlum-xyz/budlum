# Lane C live verification (WP-03)

Scope: ledger rows whose "Kapatan IP" column names IP-26 to IP-35, IP-44 or IP-49 to IP-60. Live branch: `main` at `14d9a18` (see `baseline.md`). Status vocabulary and ID blocks are defined in `baseline.md`. New findings use BLG-332 to BLG-363.

Method: the old ledger is outside the repository, so each claim is derived from the directive title, then located on the live branch by content (identifier search, function reading). Line numbers are never used as evidence. "Test name" is the permanent regression test (Previously fixed), the repro test on branch `audit/repro-c` (Verified), or `owed: <name>` when a repro is still to be written (Verified (static)).

Related files: `docs/audit/live/engine-inventory.md`.

## Special audits

Filled in below the findings table (sections "Special audit 1" to "Special audit 5").

## Findings

| ID | Live status | Test name | Evidence | Closing package | Severity suggestion | English title | Notes |
|---|---|---|---|---|---|---|---|
| BLG-114 | Previously fixed | `audit_lane_c_blg_114_match_pattern_is_not_truncated_to_i32`, `audit_lane_c_blg_114_arm_let_does_not_clobber_outer_variable`, `audit_lane_c_blg_114_duplicate_main_and_oversized_literal_are_refused` (`budzero/bud-compiler/tests/audit_lane_c.rs`, green) | `bud-compiler/src/codegen.rs::generate_stmt` (If/While/Match/For compile in a cloned child scope; match `IntLit` goes through `generate_expr(Expr::Int)`), `codegen.rs::generate_expr` (Int arm refuses `v >= GOLDILOCKS_P`), `sema.rs` ("defined twice" checks) | IP-33 | Critical | bud-compiler silent miscompilation: match pattern truncation, scope leak, duplicate fn shadowing, field overflow | All four sub-claims fixed. Arithmetic still wraps mod P by design (BudL has one `u64` that is a Goldilocks element). Closing package keeps the tests. |
| BLG-198 | Previously fixed | `audit_lane_c_blg_198_long_operator_and_field_chains_return_parser_error`, `audit_lane_c_blg_198_unknown_struct_field_read_is_refused` (`budzero/bud-compiler/tests/audit_lane_c.rs`, green) | `bud-compiler/src/parser.rs::grow_tree` (`MAX_EXPR_TREE_HEIGHT = 128`, `MAX_NESTING_DEPTH = 32`), `codegen.rs` FieldAccess (unknown struct refused), `bud-proof/benches/proof_baseline.rs` (public inputs derived from the trace and receipt) | IP-33 | Critical | bud-compiler deep-chain stack overflow, quadratic field codegen, unconstrained benchmark public inputs | Sub-claim "sub-crate root surface gaps" is not defined by the title or the tree; it is not decided here (the row text says part of the finding closes by removal). The three checkable sub-claims are fixed. |
