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
