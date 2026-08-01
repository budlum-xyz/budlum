<!--
Sync Impact Report
==================
Version change:      (none) → 1.0.0
Ratification:        initial adoption

Added sections:
  - Core Principles I–VI
  - Consensus and Wire Compatibility
  - Development Workflow
  - Governance

Removed sections:    none
Renamed principles:  none

Provenance: every principle below is a written statement of a rule this
repository already enforces in CI, not a new policy. Each carries the concrete
mechanism that enforces it, so a reader can check the claim rather than take it
on trust. Where a rule is enforced by convention rather than by a gate, that is
said plainly.

Follow-up TODOs:
  - PRINCIPLE VI names formal verification as expanding coverage. Signature
    verification and Merkle paths are still open work, recorded in SECURITY.md.
-->

# Budlum Core Constitution

Budlum is a permissionless multi-consensus L1. The code decides who holds funds
and which chain is real, so the bar is not "reviewed and looks correct" - it is
"a machine refuses the change when the property breaks".

These principles describe what the repository already does. They are written
down so the next contributor inherits the reasoning, not just the rules.

## Core Principles

### I. A Gate Must Be Able To Fail

Every quality gate carries a canary: a deliberately planted violation that the
gate must reject. A gate that cannot fail proves nothing about the commit it
passed, while still appearing in the check list.

This is not hypothetical. Four gates were once removed from this repository
because they printed `echo OK; exit 0` - they had never rejected anything, and
one of them pointed at a source file that was not in the tree.
`scripts/check-gates-are-wired.sh` closed the door behind them: a
`scripts/check-*.sh` that no workflow invokes now fails CI by name.

**Enforcement**: all 22 `scripts/check-*.sh` support `--self-test`, and the
workflows run the canary before the gate. `check-gates-are-wired.sh` verifies
every script is referenced by a workflow; its `ALLOWED_UNWIRED` list is empty on
purpose.

### II. Ratchets Only Tighten

Baselines record the current state so it cannot get worse. Raising one to make
a red build green converts the ratchet into a rubber stamp.

`.github/clippy-extra-baseline.txt` is the live example: 7108 pedantic/nursery
warnings, measured, with the measurement's provenance written in the file. New
warnings fail the build. The number may fall in a deliberate commit; it may not
rise to accommodate one.

**Enforcement**: `scripts/check-clippy-extra.sh` fails when the count exceeds
the baseline, and its canary proves both directions - 999999 warnings must fail,
2 must pass.

### III. Findings Are Measured, Not Asserted

A claimed bug is not a bug until it has been reproduced. Before a fix is
written, the broken behaviour is demonstrated with a canary and the measurement
goes in the commit message. After the fix, reverting it must fail the new tests.

This cuts both ways, and the discipline earns its keep on the second half: a
plausible-looking finding that survives investigation is worth more than a fix,
and a plausible-looking finding that does *not* survive must be dropped rather
than shipped. Several have been - a duplicate-leaf collision in
`calculate_state_root` was real at the tree level and unreachable in practice,
because the leaf commits to the account address and `accounts` is a `BTreeMap`.

**Enforcement**: convention, carried by review. The measurement in a commit
message is checkable against the code it describes.

### IV. Tests Pin Behaviour, Not Implementations

A test that passes only against a synthetic input its author chose is not a
test of production. A test asserted against the value the buggy code happens to
produce pins the bug.

Both have happened here. `team_vesting_uses_wall_clock_when_timestamp_is_available`
fed `seconds_per_epoch() * team_cliff_epochs` - the one input that makes the
broken conversion return the expected answer, and a value production cannot
produce. It passed for as long as the bug existed and would have failed the
moment the bug was fixed.

Tests come in pairs where a fix could over-correct: the property must hold, and
the mechanism must still do its job. A cliff that never opens satisfies "the
cliff holds" just as well as a correct one.

**Enforcement**: convention, plus the paired-test habit visible in
`src/tests/tokenomics.rs` and `src/mempool/pool.rs`.

### V. Consensus Constants Are Not Names

Domain-separation tags, wire enum values, on-disk serde keys and tx-type bytes
are protocol. Renaming them forks a running network or silently drops state,
and neither failure announces itself.

The `budlumxyz` rename is the worked example: types, modules and prose all
moved, while `BDLM_HUB_REGISTRY_V2`, `b"hub_v1"`, `HUB_REGISTER_APP = 19` and
the prost-generated paths stayed exactly as they were. The snapshot field was
renamed in Rust and kept its disk key through `#[serde(rename = "hub")]` -
without that, `#[serde(default)]` would have loaded every existing snapshot
*successfully*, with an empty registry.

**Enforcement**: `scripts/check-domain-tags.sh` holds a 126-tag inventory and
fails on drift. Wire and serde compatibility rest on review; the reasoning is
recorded in the commits that touched them.

### VI. Prove What Can Be Proved

Where logic is bounded and self-contained, a proof beats a sample.
`kani::any()` covers every value of a type; a unit test covers the values
someone thought of.

Model checking is not free and is not applied everywhere. It is applied where
the property is worth the cost and the solver can close it - bond arithmetic
decides how much stake a validator loses, and it is pure `u64`/`u128` maths.
Proptests are kept alongside, not replaced.

**Enforcement**: `scripts/check-kani.sh` fails on a failed proof *and* when the
number of harnesses that ran is lower than the number declared in the source -
a proof that silently stops compiling would otherwise leave the gate green.

## Consensus and Wire Compatibility

Changes that alter how bytes are hashed, ordered, or interpreted are consensus
changes even when they look like refactors.

- **Determinism**: iteration order that reaches a hash must be canonical.
  `HashSet` ordering has produced a fork primitive here before; `BTreeMap` and
  explicit tie-breaks are the fix, and `src/mempool/pool.rs` documents one.
- **Merkle construction**: a lone node is promoted, never paired with itself
  (RFC 6962). Pairing it with itself is CVE-2012-2459, and it was live in
  `calculate_tx_root` until measured and fixed.
- **Both sides of a check**: a rule enforced in the mempool but not at block
  connection is not enforced. This is the shape of Litecoin's March 2026 MWEB
  inflation and Bitcoin's CVE-2018-17144.
- **Schedules are anchored**: a duration in epochs is measured against a
  genesis-relative counter, never against a wall clock divided by an interval.
  Getting this wrong released 60% of supply at the first epoch close.

## Development Workflow

- **One finding, one pull request.** The commit message states what broke, what
  was measured, and what the fix does not cover.
- **Green means all of it.** A pull request merges when every check passes.
  `#[allow(...)]`, `#[ignore]`, `|| true` and baseline increases are not ways to
  get there.
- **Delete the branch after the merge, not before.**
- **Open risks stay written down.** SECURITY.md records what is not covered,
  including work deliberately deferred. A risk that is not written down is a
  risk the next contributor has to rediscover.

## Governance

This constitution describes the rules the repository enforces. Where it and the
code disagree, the code is the fact and the document is the bug - unless the
disagreement is a gate that stopped working, which is Principle I.

**Amendment**: a change to these principles is a pull request that says which
principle changed and why, and updates the enforcing mechanism in the same
commit. A principle whose enforcement is removed must be removed from this
document, or restored.

**Versioning**: MAJOR for a removed or redefined principle, MINOR for a new one
or materially expanded guidance, PATCH for clarifications.

**Compliance**: the gates are the review. This document exists so that a
reviewer can tell whether a gate is missing, not to add a step in front of one.

**Version**: 1.0.0 | **Ratified**: 2026-07-31 | **Last Amended**: 2026-07-31
