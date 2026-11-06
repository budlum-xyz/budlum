# Package Ledger

The status record the directive asks for in section 15.3 item 7 and section 15.5 item 7.
Every package writes its row when its last pull request opens: the package, its lane,
its status, the pull requests that delivered it, the last commit and the CI runs that
carry the evidence.

This file is append-only and is one of the shared paths of section 15.3 item 4, so a
package adds its row and does not rewrite another's. A rebase resolves the collision,
because two rows about two packages do not disagree.

Status values are the ones section 15.1 defines: `todo`, `in-progress`, `blocked`,
`merged`. A row moves to `merged` only when its pull request is on `main`; a green pull
request is `in-progress` with a CI run number beside it, because a pull request is not
evidence until it has merged.

## Rows

| Package | Lane | Status | Pull requests | Last commit | CI runs | Findings closed |
|---|---|---|---|---|---|---|
| WP-10 - B.U.D. 3.0 skeleton, shared types and the wire contract | B | `in-progress` | this PR (WP-10, 1/1) | `pending on this PR` | `pending on this PR` | none (the card names none) |

## What WP-10 delivered

- `proto/budlum/storage/v3/bud3.proto` - the symbol protocol, the upload stream, the
  custody proof batch, the view session and the two-path check. 29 messages, none
  unreachable, no field number used twice, no BOF-1 header field and no drawing on the
  wire (section 6.3.2 rules 1 and 7, section 15.8 WP-10 item 6).
- `src/storage/bud3/types.rs` - the section 6.2 vocabulary that is a shape rather than
  an algorithm: `Frame`, `QrVideo`, `CustodyShare`, `PlacementGroup`, `RefCount`,
  `AggregationVolume`, `Payload`, `SourceSymbol`, `RepairSymbol`, `LogicalPath`,
  `OpticalPath`. Each one carries the invariant the directive states for it.
- `xtask/gates/src/gates/bud3_proto_is_total.rs` - the gate that makes the wire
  contract's totality checkable, with a canary for each of its five refusals.
- `src/tests/bud3_types.rs` - the caller that keeps the vocabulary on the production
  path (G-6) and checks each invariant against the parts the pipeline really produces.

## What WP-10 did not deliver, and why

Section 15.8's card also lists a module tree, `bud3.proto` fields that later packages
add, and golden vector directories. They are not in this pull request for one reason
each, recorded here rather than left to be discovered:

- The module tree (`volume`, `repair`, `upload`, `view`, `dedup`, `refcount`, `seal`,
  `keys`, `grants`, `fees`, `access_tiering`, `content_gateway`, `rpc`, `maintenance`)
  is filled by the package that first uses each module, which the card itself states.
  Declaring empty modules now would add idle surface that `no-idle-code` and
  `dead-pub-api-is-ratcheted` both refuse.
- `ContentRef` (section 5.7) belongs to WP-07's legacy removal, whose card owns that
  path; WP-10's card names `limits.rs`, `meter.rs`, `bud3.proto` and the vector layout.
- The golden vector directories already exist (`tests/vectors/bud3/{bof1,codec,custody,fountain,placement}`)
  and were created with the packages that produce those vectors.
- `src/storage/bud3/mod.rs`, `src/tests/mod.rs`, `xtask/gates/src/main.rs` and
  `.github/workflows/ci.yml` are shared append-only paths; this row's pull request adds
  lines to each and rewrites none.

## WP-28 (lane C, T-Open), 1/N and 2/N, this pull request

The Ethereum JSON-RPC compatibility gateway. `src/rpc/compat/` did not exist on this
branch and is claimed by no open pull request among the 52 measured on 2026-11-06.

| Row | What it lands | State |
|---|---|---|
| WP-28 1/N | `src/rpc/compat/ethereum/{methods,limits}.rs`: section 8.11.2's 37 methods with listener and effect, the `eth_getProof` refusal at `-32601`, and rule 3's filter bounds | in this PR |
| WP-28 2/N | `config.rs`: section 8.11.1's loopback bind, enforced, and the foreign chain id kept apart from this chain's answer | in this PR |

Deliberately not in this slice, with the reason beside each:

- **Handlers, transport and block encoding.** `eth_call` and `eth_estimateGas` need
  WP-27's EVM worker; `eth_getBalance` needs the execution-state view; a block response's
  `stateRoot` is `execution_root`, which is header V8 (WP-35) and does not exist yet.
  Registering handlers that answer "not available" would put stubs in the served set,
  which the directive forbids. The table is complete and every handler is absent, so
  `is_served` is the only thing that says a method is reachable.
- **`bud_getExecutionProof`.** The `eth_getProof` refusal message points at it and it is
  not served anywhere yet. That is a live contradiction between section 8.10 rule 6 and
  the native surface; it is recorded here rather than left for a reviewer to find.

## Module-tree collisions in the open queue, measured 2026-11-06

Section 15.3 item 3 gives a lock path to one package. Measured across the 52 open pull
requests (`gh pr list --json files`, 597 distinct paths), two paths are claimed by more
than one, and both are declared in `src/storage/bud3/mod.rs`:

| Path | Claimed by | What a merge produces |
|---|---|---|
| `src/storage/bud3/volume.rs` | #45, #55 (WP-19), #57 (WP-21) | three `pub mod volume;` lines, or two files claiming one module |
| `src/storage/bud3/content_ref.rs` | #45, #69 (WP-07) | the same, and the second package's `ContentRef` meaning |

All three volume patches apply cleanly to `main` on their own, so no build catches this:
the collision exists only in the queue. The fix belongs on the pull requests that own
the paths, not on a new branch: #57 is titled for WP-21 and #55 for WP-19, and section
15.5 requires one package per pull request, so one of them must drop the file before
either merges. This session cannot push to those branches (each is another session's),
so the finding is recorded here with the evidence and the fix is named.

`bud3-module-claims-do-not-collide` (`xtask/gates/src/gates/bud3_module_claims.rs`) is the
durable half of that rule: it fails when a `mod.rs` declares one module twice, declares
one name at two visibilities, or leaves a module file that no declaration reaches. Those
are the shapes the collisions produce once they land, and they are visible from the tree
without asking GitHub what is open.

## Finding: one concept, two definitions, and the chain uses the short one

Measured in the tree today, not in a pull request:

`src/storage/bud3/types.rs` states section 6.8.2's reference counter correctly -
`RefCount { references, bound }`, `total()` saturating over both terms, `is_zero()`
asking both.

`src/storage/bud3/registry.rs` - the chain state - declares `ObjectEntry` with
`references: BTreeSet<NftId>` and no bound term at all. Its `refcount()` is
`references.len()`, its `burn_reference()` deletes when `references.is_empty()`, its
state root folds `references.len()`, and its query answer reports `references.len()`.

Section 6.8.2 rule 2 says both an NFT **and** every delta or derived object bound to
the object raise the counter; section 6.8.3 rule 2 deletes at zero. So an object that
only a delta names is deleted while the delta still needs its bytes.

Why this is a finding and not a patch here: `src/storage/bud3/registry.rs` is a lock
path of five open pull requests (#45, #55, #59, #65), and section 15.3 item 3 gives a
lock path to one package. Editing it on this branch is exactly the collision
`bud3-module-claims-do-not-collide` refuses one level down. The fix belongs on the
pull request that next touches the counter.

A gate for this (`bud3_refcount_terms`, written and canaried, four canaries including
one that proves a commented-out field does not count) is deliberately **not**
registered: `all_selection` runs every gate that takes no arguments, so registering it
would turn `ci.yml`'s `--all` step red on this branch for a defect this branch is not
allowed to fix. It is parked at `/tmp/parked/bud3_refcount_terms.rs.pending` and lands
with the fix, on the pull request that owns the counter.
