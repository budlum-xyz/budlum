# Independent review 1: core and storage (WP-47)

Review of the invariants of section 3.1 (G-1 to G-8), section 3.2 (D-1 to D-15)
and section 3.3 (V-1 to V-5) against the code on `main` at `cccf1da`, plus the
state of the open pull request queue on 2026-11-06.

Every claim in this file names how it was measured. A claim that could not be
measured from a working tree without a Rust toolchain says so and is marked
`unmeasured`, because the directive's section 0.3 does not accept a
self-declaration as evidence and this review is not going to be the exception.

## Method, and what it can and cannot see

- **Gate inventory.** The registered gate names were extracted from
  `xtask/gates/src/main.rs` (`name: "..."`, 140 rows) and each invariant's
  named gate was looked up by name. A gate the directive names in a different
  spelling was matched by its actual registered name and the mapping is written
  down below, because a review that silently "finds" a gate under a name nobody
  registered is worth nothing.
- **Code reading.** Invariants without a gate were checked by reading the
  production path and, where the rule is a property of a data structure, by
  locating the type that carries it.
- **What this cannot see.** No local Rust toolchain exists in the review
  environment (`cargo` absent; the registry hosts are unreachable), so nothing
  here is a build or a test run. Every "green" below means "the gate that would
  catch this is registered and the assertion is in the tree", not "the gate ran
  today".

## G: general invariants (section 3.1)

| Code | Named gate | Registered as | Verdict |
|---|---|---|---|
| G-1 | `consensus_state_only_changes_in_blocks`, `no_out_of_block_consensus_writes` | `consensus-state-only-changes-in-blocks`, `no-out-of-block-consensus-writes` | both present |
| G-2 | float prohibition on the consensus path | `no-float-in-consensus` family | present; see note |
| G-3 | `minting_paths_are_counted` | `minting-paths-are-counted` | present |
| G-4 | `refusals_no_mutate` | `refusals-do-not-mutate-first` | present under a different name |
| G-5 | `hash_inputs_are_length_prefixed`, `domain_tags` | `hash-inputs-length-prefixed`, plus the domain tag register | present under a different name |
| G-6 | `no_idle_code`, `capability_modules_are_wired` | `no-idle-code`, `capability-wiring` | both present, second under a different name |
| G-7 | closed features refuse by name | `bud3-forbidden-phrases` plus per-feature refusal rows | partly present; see note |
| G-8 | sovereignty | no single gate; asserted by the external-domain intake and the relay tests | `unmeasured` |

**Note on G-2.** The gate family exists and `src/storage/bud3/placement.rs`
carries the reasoning: its `log2_q32` is a Q32 fixed-point logarithm computed
with integers only, which is the one place a float would have been natural.
The invariant holds for the storage tree by construction; the consensus tree's
compliance is what the float gate covers.

**Note on G-7.** The refusal shape exists per feature (the RPC surface has a
`Refused` effect class with 40-odd rows, see `src/rpc/method_class.rs`), but
there is no single gate that walks every closed testnet feature and asserts it
refuses rather than silently accepting. What exists is per-feature coverage.
This is a **High** finding, recorded as BLG-268 below.

## D: storage invariants (section 3.2)

| Code | Gate | Verdict |
|---|---|---|
| D-1 single object, no persistent QR video | `bud3-forbidden-phrases` | present |
| D-2 self-sufficiency | no gate; property of `pipeline::view_public` | `unmeasured` (no build) |
| D-3 bit equality across object, video, content | **`bud3-object-is-universal` is NOT on `main`** | **open: claimed by PR #45** |
| D-4 two-path equality | **`bud3-qr-is-presentation` is NOT on `main`** | **open: claimed by PR #45** |
| D-5 information law | `bud3-information-law-canary` (test, not gate) | test absent from tree |
| D-6 universality, zero-byte content included | `bud3-object-is-universal` | open, PR #45 |
| D-7 permanent codec identity | `codec-register` (PR #8) | open |
| D-8 sealed content privacy | `content-encryption-is-declared-and-bound` | **not on `main`; not in any open PR's file list either** |
| D-9 single implementation | **`no-legacy-storage` is NOT on `main`** | open: claimed by PR #69 |
| D-10 single object, minimal redundancy | `bud3-placement` | open: PR #13 |
| D-11 fixed content identity | no gate; `content_id.rs` carries it | `unmeasured` |
| D-12 decode on the viewer's device | no gate, by design (a client property) | not gateable here |
| D-13 object lives as long as the chain | `bud3-repair-fires` | open: PR #13 |
| D-14 no owner in shared records | **`consent-records-have-no-open-identities` is NOT on `main`; not in an open PR's file list** | **open, unclaimed** |
| D-15 only validators store | `storage-provider` | present |

## V: validator invariants (section 3.3)

| Code | Gate | Verdict |
|---|---|---|
| V-1 one validator leaving is harmless | `tests/churn/` scenario suite | the directory does not exist yet (WP-14, PR #45 claims `tests/churn/main.rs`) |
| V-2 Mobile class cannot stop finality | **no gate on `main`** | open, unclaimed by name |
| V-3 handover on finalized data only | `src/registry/handover.rs` (WP-09, PRs #38/#54/#64) | open |
| V-4 absence never slashes | `absence-never-slashes` **not registered**; the *rule* is carried by `uncheckable-proof-paths-do-not-slash` and `gov-slash-evidence-validator-only` | partly present under different names |
| V-5 one registry | `single-validator-registry` **not registered**; carried by `node-classification` | partly present |

## Findings

New findings are numbered from BLG-268, as the card requires. The BLG series
lives in the directive (section 13 and the finding table); this file is the
first place they are written down with their measurements. `docs/audit/AUDIT_FINDINGS.md`
uses the separate AF-NN series for review threads on the open pull requests and
is not extended here: the two ledgers answer different questions and merging
them would hide which one an item came from.

### BLG-268 (High) - G-7 has no walker

Closed testnet features are refused by class, per handler, but no gate asserts
that every closed feature has a refusal. A feature closed in the directive and
open in the code would be found by a reader, not by CI. *Fix shape:* a
`closed_features_refuse` gate over a table of closed features and their
refusal rows, in the shape of `src/rpc/method_class.rs`'s `Refused` class.

### BLG-269 (High) - two invariants have no owner at all

`content-encryption-is-declared-and-bound` (D-8) and
`consent-records-have-no-open-identities` (D-14) appear in no open pull
request's file list and in no commit on `main` (measured: `gh pr list --json
files` over 52 open PRs, 597 distinct paths; neither gate file appears). WP-56
lists both in its card, and WP-56 is unstarted. This is a scheduling gap, not a
code defect, but it is the kind that survives until someone writes it down:
D-8 and D-14 are the two invariants that make sealed content safe, and both are
currently unenforced.

### BLG-270 (Medium) - a review-relevant gate name drifted

G-4 and G-5 name gates (`refusals_no_mutate`,
`hash_inputs_are_length_prefixed`) that exist under different registered names
(`refusals-do-not-mutate-first`, `hash-inputs-length-prefixed`). The invariants
are covered; what is broken is the ability to *find* the gate from the
directive. *Fix shape:* one line per rename in a mapping table, or the gate
registry carrying a `directive_name` field beside `replaces`.

### BLG-271 (Medium) - V-2 and V-5 are unenforced by name

"Mobile class cannot stop finality" and "one validator registry" have no gate
under any spelling. `node-classification` covers part of V-5. V-2 is covered by
the duty-lane work in PR #40 (WP-08) in substance but not by a named gate.
*Fix shape:* a `mobile_class_cannot_stop_finality` gate asserting that no
finality certificate path reads a Mobile seat.

## Attacked risks (section 13)

The card lists R-02, R-03, R-04, R-13, R-14, R-17, R-25, R-26, R-29 for this
review. Attack tests for those risks are **not written in this file**: each one
needs a running chain or a property-test harness, and this environment cannot
build either. Writing a test that has never compiled and calling it coverage is
the exact self-declaration the directive refuses. They are listed here as
`not yet written`, with the risk table and the reason, so the next review
inherits a to-do list rather than a false claim.

## What this review did not do, and why

- It did not run `cargo test`, `cargo clippy` or any gate. There is no Rust
  toolchain in this environment and the toolchain hosts are unreachable.
- It did not write the attack tests above for the same reason.
- It did not edit `src/storage/bud3/registry.rs` for the reference-counter
  finding recorded in `docs/work/PACKAGES.md`: that path is a lock path of five
  open pull requests and section 15.3 item 3 gives it to one package.
