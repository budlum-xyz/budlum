# Verification of the pre-merge Rust syntax gate (WP-42, BLG-299/BLG-318)

| Field | Value |
|---|---|
| Date | 2026-11-06 |
| Branch | `arena/0c480ae6-budlum` (PR #96) |
| Gate | `xtask/gates/src/gates/rust_syntax_is_parseable.rs`, CLI name `rust-syntax-is-parseable` |
| Wired | `xtask/gates/src/main.rs`: `pub mod rust_syntax_is_parseable;` plus a `Gate` entry, so `--all` and `--self-test` run it |
| Regression lock | `xtask/gates/tests/stack_compatibility.rs` |
| Local replica | `ops/scripts/rust_syntax_gate_replica.py` |

## Why the gate exists

`git merge` is not a compiler. The mechanical audit
(`docs/audit/STACK_COMPATIBILITY_AUDIT_2026-11-06.md`) parsed 1,522 changed
`.rs` blobs across 75 open PR heads and found 11 broken files on three
branches: #8, #9 and #55. A clean merge carries those bytes downstream. No gate
in the tree refused that class of defect.

## Local verification (no Rust toolchain in this workspace)

The Rust workspace cannot be compiled here: no `cargo`, `rustc`, `rustfmt`,
`clippy` or crate registry is reachable. The gate's Rust source was therefore
transcribed line-for-line into a Python replica. Both files were then run; the
outputs below are the actual outputs, not descriptions of them.

```
$ python3 ops/scripts/rust_syntax_gate_replica.py --self-test
rust-syntax gate replica self-test OK: 5 defect classes refused, clean tree accepted

$ python3 ops/scripts/rust_syntax_gate_replica.py
scanned 907 Rust files, 0 structural findings

$ python3 ops/scripts/rust_syntax_gate_replica.py /tmp/budlum_broken_check
scanned 5 Rust files, 12 structural findings
  /tmp/budlum_broken_check/pr55_private_dedup.rs:150: `{` is never closed
  /tmp/budlum_broken_check/pr8_content_ref.rs:239: enum variant `Bud3NotReady` outside an enum
  /tmp/budlum_broken_check/pr8_db.rs:132: closing `)` does not match `{` opened at line 128
  /tmp/budlum_broken_check/pr8_db.rs:135: unmatched closing `}`
  /tmp/budlum_broken_check/pr8_priority_findings.rs:129: test attribute is followed by `f`, not a function
  /tmp/budlum_broken_check/pr8_priority_findings.rs:130: lone identifier `f` at module level
  ... (12 findings over 4 files)
```

The five canary shapes are: an orphan `#[test]` followed by a lone `f`, an
unclosed brace, a deleted method name after `self.`, a stray `f` prefix on a
comment line, and an enum variant outside its enum. The clean canary includes
braces inside comments, strings and multi-line raw strings.

## Two corrections found by running the replica on the live tree

1. A per-line literal scanner reported 315 false positives. Multi-line raw
   strings (`r#"..."#`), multi-line string literals and block comments were
   being read as code. The scanner is now a state machine that carries the
   literal state across lines.
2. `#[cfg(test)]` was mistaken for `#[test]`, and a generic parameter line
   (`SC,`) was mistaken for an orphan enum variant. Attribute matching now
   looks at the final path segment, and the enum-variant refusal requires an
   immediately preceding item close at module level.

Both corrections were applied to the Rust gate and to the replica. The tree
then scanned at zero findings, which is the reason this gate can be wired
without raising a baseline.

## Evidence boundary

- The Rust gate itself was **not executed** locally. Its source was parsed with
  the tree-sitter Rust grammar (zero `ERROR`/`MISSING` nodes) and `git diff
  --check` passes. CI on this branch compiles and runs `--all --self-test`; that
  run is the compiler and canary verifier (directive 0.3 item 5).
- The gate is a structural pre-merge check, not a full Rust parser. PR #9's
  `src/tests/integration.rs` (a field inserted mid-expression) has balanced
  delimiters and is caught only by the tree-sitter audit tool. The two checks
  are complementary and both are committed.
- No CI run number and no green CI result is claimed here.
