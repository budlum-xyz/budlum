# Work packages: state on the live branch

One row per package of the work-package table. The directive calls a package
`WP-NN` in its Turkish text; the repository and GitHub use the same `WP-NN` id
(section 15.3 item 1), so there is one name for one package.

A row is written only from evidence: a path in the tree, an open pull request,
or a CI run whose number is quoted. A package with no evidence is absent from
this table rather than described from memory (sections 0.3 item 5 and 0.4).

This is a shared append file (section 15.3 item 4). Each package appends its own
row; a conflict is resolved by rebase, never by dropping another package's row.

Two process notes, recorded because the table would otherwise misdescribe how
the work is running:

* GitHub issues are disabled on this repository, so a package cannot be claimed
  with an `in-progress` label on an issue (sections 15.3 items 1 and 2). The
  claim is the pull request named in the row.
* The workspace fixes the branch name of a session (`arena/<id>-budlum`), so the
  `wp/NN-<name>` branch shape of section 15.5 item 1 is not available. The
  package id in the pull-request title is the authoritative one.

## State

| Package | Lane | State | Branch or pull request | Evidence |
|---|---|---|---|---|
| WP-21 | B | in progress | this pull request | `src/storage/bud3/volume.rs`, `src/storage/bud3/pipeline.rs` (`prepare_volume_upload`, `view_volume_bytes`, `view_volume_member`), the acceptance test `bud3_aggregation_volume` |

## WP-21, slice delivered by this pull request

The card asks for nine things. This pull request delivers item 4, the
aggregation volume of section 6.12, and the part of item 5 that the volume
owns:

1. `src/storage/bud3/volume.rs`: the volume, its member table, the member root
   over length-prefixed leaves, the volume id over the visibility and the
   bytes, the member path and its check, deletion with the seven-day recode
   deadline for a public volume, immediate crypto shredding for a sealed one,
   and the recode that removes the holes.
2. `src/storage/bud3/pipeline.rs`: `prepare_volume_upload` refuses an object
   that is not smaller than one symbol, joins the batch in one volume, codes the
   volume as one segment and returns the record with its symbols.
   `view_volume_bytes` and `view_volume_member` rebuild the volume from symbols
   and check the length, the volume id, the member table layout and the member
   root before a member is handed out; a member is handed out only when its own
   object commitment still matches.
3. `src/storage/bud3/limits.rs`: `volume_bytes` joins the genesis parameters,
   TESTNET-DEFAULT 4 MiB (section 6.12 item 6). The capacity a volume really
   gets is the smaller of that value and one segment of the profile, because the
   volume is coded as one segment.

Not in this pull request, and named so the next slice is unambiguous: the
reference counter (`refcount`) and the delete transaction that calls
`AggregationVolume::remove`, the upload session RPCs, and the `ReplaceObject`
flow of section 6.14. Those are items 1, 2, 5 (the transaction half), 6 and 7 of
the card.

## Open findings

None. This pull request closes no directive finding. The acceptance test it
delivers is `bud3_aggregation_volume` (section 16.4 item 3, section 6.12), and
the finding ledger is not touched because no finding is claimed closed on a self
declaration (section 0.3 item 5).
