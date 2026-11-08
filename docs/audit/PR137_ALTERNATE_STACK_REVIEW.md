# PR #137 alternate full-stack review and live-broadcast slice

## Decision

PR #137 source head `cad686cad8313d73cae988fab179c89f47f34c7a` is an alternate
full-stack integration, not the small migration variant that can be copied over
the current tree. Its title and body claim all WP-01..WP-64 and 5,081 library
tests, but the observed check inventory is only **1 passed, 48 pending and 2
skipped**. Neither that title nor an unexecuted test count is accepted as
completion evidence.

This review selectively integrates the WP-55 2/N live-broadcast module and its
minimum live/fountain adaptations. It does not merge the source head, make it
ancestral, close PR #137, activate T-Expansion, or mark any work package
complete. The source head also contains a commit dated 2026-11-07, so the
user's source-PR closing condition for that date is not met.

The comparison base is the pushed PR #86 integration commit
`0007279e59bb88007e519365011fdecbe6cf362c`. The full per-path evidence is in
`PR137_PATH_INVENTORY.tsv`; every one of the 822 API-reported paths has an
explicit comparison and disposition.

## Complete path accounting

The merge-base diff reports 822 files, 113,170 insertions and 36,978 deletions.
Blob comparison against the current integration base gives the following
partition. Deferred work is not accepted work, and rejected source is not
silently described as integrated.

| Comparison | Count | Disposition |
|---|---:|---|
| Byte-identical | 196 | No change needed. |
| Absent from both trees | 2 | The directive and `docs/GRAFT.md` stay absent; no rename/deletion residue was restored. |
| Different blobs | 385 | Three live/fountain/module files were adapted, five migration paths retained the hardened PR #61 behavior, and the other 377 current variants were not overwritten in this slice. |
| Source-only | 147 | One live-broadcast file was adapted; 108 paths remain deferred to their owning package reviews and 38 were rejected as placeholders, fail-open gates, duplicate layouts/packages or legacy restoration. |
| Current-only because the source deletes them | 92 | No wholesale `bud/` or gate deletion was applied in this slice. The current legacy-removal ratchet and module registry remain authoritative. |

The inventory separately identifies each deferred codec, mobile FFI/iOS,
Aptos/Solana, CI, rehearsal, explorer, documentation and test path. A generic
"retain current" row is a merge disposition, not a claim that every line of the
alternate 113,170-line implementation was proved equivalent.

## Integrated WP-55 2/N slice

### BLG-316 - visible, sticky coding failures and real ESI limits

The source driver's `next_symbol` converted `symbol_for` failure to `None`, so
`BadEsi`, `UnknownSegment` and `FountainError` could look like normal end of
plan. It also created repair plans with the global `MAX_ESI`, while the RFC
6330 encoder applies a lower per-segment limit after source-block padding.

The integrated adaptation makes the following changes:

- `next_symbol` returns `Result<Option<Symbol>, BroadcastError>` and `drive`
  propagates the error. Normal exhaustion remains `Ok(None)`.
- A coding failure is sticky. A later call returns the same failure instead
  of skipping the offending frame. Rebuilding the driver is required.
- The emitted counter uses checked arithmetic and advances only after symbol
  production.
- `SegmentEncoder::max_esi` exposes the encoder's actual inclusive limit.
  `RatiolessPlan::with_repair_limits` validates equal table lengths and the
  RFC domain, and the driver constructs its plan from those limits.
- `bud3_live_broadcast_distinguishes_errors_from_exhaustion` covers a forced
  plan/encoder mismatch, sticky refusal, zero emitted symbols and the true
  empty-plan `Ok(None)` control. `ratioless_plan_honors_per_segment_repair_limits`
  covers bounded completion and invalid limit tables. These tests are present
  but were not executed.

Current-tree type/API review also removed unsupported `Eq` and `Debug`
requirements: `FountainError` is not `Eq`, and the external RFC 6330 encoder
is not required to implement `Debug`. The new ESI accessor is non-const because
the underlying source-block calculation is non-const.

### Gateway and activation boundary

`LiveGateway` supplies object/viewer admission functions and
`BroadcastDriver` supplies an in-process fan-out model. The source had no
caller outside `live_broadcast.rs`; comments claiming that the content gateway
already called these doors were false. The integrated comments now state that
the module is unwired.

The existing BOF-1/testnet live-flag refusal remains the admission path of
record. `ACTIVATION` remains `None`, no executor or content-gateway call was
added, and no live traffic is enabled. Seven broadcast-module tests and twelve
live-core tests exist in source after this slice; their presence is not a test
run.

### BLG-319 - aggregate memory work remains open

The per-viewer limits are real, but 1,024 viewers times 4,096 cloned 2,911-byte
P0 payloads is about 12.2 GB before queue overhead. The driver also snapshots
all supplied segments and encoder state. This is not viewer-independent sender
memory or a practical aggregate byte budget.

The documentation now says so explicitly. The module remains closed and
unwired; shared payloads, an aggregate byte/symbol budget and an incremental
persistent lifecycle are required before production wiring. No such lifecycle
is claimed by this integration.

## Rejected and deferred source work

### BLG-317 - the proposed syntax gate fails open

`rust_syntax_is_parseable` silently returns on directory-read failures and
continues past metadata/read failures and files over 8 MiB. It can report that
all Rust sources parsed while skipping sources it could not examine. The gate
was not added or registered. A replacement must fail closed on traversal,
metadata, decoding and size failures. The current 61 baseline parser-error
files independently prevent a whole-tree syntax-green claim.

### BLG-318 - placeholder expansion workers are not execution environments

The NEAR, Plutus and TVM workers return `SHA-256(input)` as a successful call.
The UTXO worker returns the same digest without verifying a transaction. They
use fixed gas and discard host-write results. Their crates and workspace
registration were not integrated. This evidence does not support the source's
WP-50..53 completion claim.

### Other retained boundaries

- The migration paths retain PR #61's hardened factory authority, proof,
  pricing and quote behavior. The older unsafe variant is not restored.
- The current `network.budlum.validator` Android app remains canonical; the
  source's duplicate `dev.budlum.validator` package was not added. The distinct
  mobile-core key/FFI and iOS alternatives remain deferred, not rejected as
  reviewed duplicates.
- Canonical `src/rpc/compat/aptos.rs` and `solana.rs` remain in place. A second
  Aptos `mod.rs` owner was not mounted. Useful worker/subscription behavior
  needs separate reconciliation and RPC-table/runtime tests.
- Deleted legacy `src/gateway/` files, the wholesale `bud/` deletion and old
  baselines were not used to overwrite the current migration/gate state.
- Codec, explorer, object-layer, AI, mobile FFI/iOS, rehearsal and remaining
  expansion paths retain their exact deferred dispositions in the TSV. This
  slice makes no claim that their package closing conditions hold.

## Source audit tools

The source `tree_compatibility_audit.py` was run unchanged from a temporary
location. Its first current-tree scan covered 1,448 text files and reported 177
typographic-dash findings plus one historical Turkish-character finding in the
dated package snapshot. It reported zero module-declaration, action-pin and
JSON/TOML parse findings. Two dash findings introduced by the PR #86 review
heading were removed. The final scan covered 1,450 text files and retained 175
baseline dash findings plus the same one historical package-snapshot finding;
module, action-pin and JSON/TOML counts remained zero. The source tool is not a
replacement for the registered Rust gates, and its baseline findings are not
represented as a pass.

The source RPC audit was not used as current evidence: it requires the old
`src/rpc/compat/aptos/mod.rs` layout and fixed source pins, so running it
unmodified would produce structural false findings against canonical
`aptos.rs`. It was not integrated.

## Verification boundary

- Tree-sitter-rust parsed `live.rs`, `live_broadcast.rs`, `fountain.rs` and
  `bud3/mod.rs` with zero error/missing nodes. The 1,108-file whole-tree scan
  retained 61 baseline error files and none in the four affected files.
- The TSV contains 822 unique paths and a nonempty disposition for every path.
- Static call/trait checks cover every changed `next_symbol`/`drive` caller,
  the removed unsupported derives, the non-const ESI calculation, encoder
  limits, sticky failures and one module/re-export registration.
- `python3 ops/scripts/integration_audit.py` passed all 14 checks, and its
  self-test rejected a real violation in each of the 14 canaries.
- Whitespace/diff checks are clean on the reviewed changes.
- No Rust compiler, formatter, Clippy or test runner is available. No Rust
  test count, formatting, compilation, lint, determinism, live transport,
  gateway wiring, VM conformance or testnet success is claimed.

PR #137 stays open for the deferred paths, the fail-closed syntax-gate redesign,
real execution-environment implementations, aggregate broadcast memory design,
and pinned Rust/CI evidence. BLG-316 through BLG-319 are not closed by this
selective integration.
