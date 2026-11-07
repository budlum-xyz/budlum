# The conformance runner

Section 8.13 item 1 of the directive puts the conformance packages here, in Rust,
and Section 8.13 item 2 puts the heavy ones in a nightly workflow that is a required
gate. This directory is the plan for that runner. It holds no crate yet, and the
reason is written down here rather than discovered later.

## Why there is no crate in this delivery

Section 8.14 item 1 makes every execution environment its own Cargo workspace:
`execution/evm/`, `execution/wasm/`, `execution/svm/`, `execution/move/`,
`execution/budzero/`, each with its own `Cargo.lock`, `deny.toml` and
`supply-chain/`. The runner is the harness those five workspaces feed, so it lands
with the first of them, WP-27.

A runner added ahead of the engines would be a crate that builds, a nightly job that
runs it, and a hundred cases that all refuse for one reason: no worker. That is a red
required gate with a known cause, and the repository already pays for enough of
those. The state of every case is recorded instead, in
[`docs/EXECUTION_LIMITS.md`](../../docs/EXECUTION_LIMITS.md), where a lock test
compares it with the tree on every commit.

## What a case is

One row of a section in `docs/EXECUTION_LIMITS.md`. Five cells:

| Cell | Meaning |
|---|---|
| Case | the package or tool test of Section 8.13, in the words of that table |
| State | `pass` when the case test ran and was green, `limits` when it did not |
| Test | the case test, named `<environment>_conformance_<case>` |
| Reason | why the case is not run. Empty in a `pass` row |
| Owner | the work package that turns the row green (`WP-NN`) |

The suite test for an environment is `uel_conformance_<environment>`. It reads its
own section and fails when one case is neither green with its case test behind it nor
recorded here with a reason and an owner.

## What the runner will do

1. One binary per case group, so a red case names its tool rather than its suite.
2. The Rust suites (`ethereum/execution-spec-tests` state tests, the aptos-framework
   Move unit tests, the BudZero package) run in process against the worker.
3. The external tools (Foundry, Hardhat, the solana CLI, Anchor, the aptos CLI,
   CosmJS) run in a pinned container and their exit status is the case result. Each
   pin is recorded next to the case so a tool upgrade is visible in a diff.
4. A case that cannot run in the container reports `limits` with the reason, never a
   skip that reads as a pass.
5. The suite writes nothing to `docs/EXECUTION_LIMITS.md` by itself. The document is
   edited with the run result in hand, because a generator that rewrites the limits
   table can also delete a limit.

## The nightly job

`.github/workflows/conformance-nightly.yml` is the required gate of Section 8.13
item 2. It is not added by this delivery: a required nightly that runs a runner which
does not exist yet is a permanently red check, and a permanently red required check
is one an operator learns to ignore. It lands with the runner, in WP-27, and the
workflow's own gate then reads this directory and finds the cases it must carry.
