# Work packages: what this branch lands, and what it leaves

## WP-43: documents, README and the launch report

Lane D. `T-Launch`, launch-gated, critical path. Dependencies: WP-46, WP-47 and
WP-48, none of which has merged, so the README rewrite (items 1, 2 and 5) and the
launch report (item 7) are not in reach of this branch. The two gates that pin
the README push back against drift in the meantime, and they are the half of
item 3 and item 4 that can land without the rewrite.

| Gate | Reads | Refuses | Finding |
|---|---|---|---|
| `readme-definition-block-is-verbatim` | `README.md` lines 1 to 14 and `README.tr.md` lines 1 to 15, as bytes with LF endings | any change to the block against the pinned SHA-256, a CRLF rewrite included | KR-21, section 1.3 item 8: the definition is a decision, not an edit |
| `readme-has-no-placeholders` | both READMEs, every line, fenced blocks included | a `{{...}}` slot that `.github/readme-placeholders-baseline.txt` does not record, a recorded slot that has gone, and a `TODO`, `TBD` or `FIXME` marker (never recorded) | section 1.3 item 8: an unfilled value reads as a measurement |

The digests are the directive's: `dd9be520...f063467` for `README.md` and
`c883e001...c903fe` for `README.tr.md`. The gate computes SHA-256 in
`xtask/gates/src/sha256.rs`, so the gate crate gains no dependency for the
question. Both digests were measured on the live tree before the gate was
written, and this branch's README change sits below the pinned block, so the
digests still hold.

`readme_claims_are_wired` (item 4, second half) is not landed. Its rule is that
a README sentence claiming the system works names a test that exists and a
caller or path. Measured against the live prose, the verb reader fires on a
subjunctive ("Once verified, the commitment enters the `GlobalBlockHeader`"), on
the continuation line of a wrapped paragraph, and on the rows of a file-name
table: twenty findings on `README.md` and two on `README.tr.md`, none of them
the sentence the gate exists to catch. The alternatives are to baseline them,
which is the softening the directive forbids, or to rewrite those sentences,
which is items 1 and 2 of this same package. The gate ships with the rewrite.

## WP-42: CI, gates and supply chain

`no-float-in-consensus-paths` and `workflows-cover-every-workspace` are already
in flight on PR #24, written against a `syn` AST and wired in `ci.yml`. That is
the stronger implementation for the float gate (it catches `0.5` and
`f64::NAN`, not only the type name), and a second gate under the same name
cannot merge beside it. This branch therefore adds no copy of either.

The one gap that work leaves open is closed here: **every workspace is built, or
the tree says so.** PR #24's workspace gate discovers a workspace only when the
directory holds both `Cargo.toml` and `Cargo.lock`, so
`contracts/object-layer/cosmwasm` and `contracts/object-layer/svm` are invisible
to it: both hold a manifest only, both are standalone workspaces, and no
workflow builds either. The root `cargo build`, `cargo test --workspace` and
`cargo clippy --all-targets` never see them, and the Solidity job compiles the
`.sol` files beside them. `solidity.yml` gains the `contract-crates` job, one
matrix entry per crate: format, clippy `-D warnings`, build and test.

`solidity.yml` is inside WP-42's `.github/workflows/` lock path, which no live
pull request holds, and the job is additive: it names a workspace that no
existing job names.
