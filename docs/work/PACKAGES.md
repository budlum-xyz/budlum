# Package Ledger

The status record the directive asks for in section 15.3 item 7 and section 15.5
item 7. Every package writes its row when its last pull request opens: the
package, its lane, its status, the pull requests that delivered it, the last
commit and the CI runs that carry the evidence.

This file is append-only and is one of the shared paths of section 15.3 item 4,
so a package adds its row and does not rewrite another's. A rebase resolves the
collision, because two rows about two packages do not disagree.

Status values are the ones section 15.1 defines: `todo`, `in-progress`,
`blocked`, `merged`. A row moves to `merged` only when its pull request is on
`main`; a green pull request is `in-progress` with a CI run number beside it,
because a pull request is not evidence until it has merged.

## Rows

| Package | Lane | Status | Pull requests | Last commit | CI runs | Findings closed |
|---|---|---|---|---|---|---|
| WP-24 - A0 codec registry and the access layer | B | `in-progress` (slice 1/3) | this PR (WP-24, 1/3) | `1ff76edd` | `queued on this PR` | none in this slice |

## What WP-24 slice 1 delivered: object replacement

Section 6.14 asks for a second, better representation of one content id, and
section 6.6.3 rule 9 says the content id never changes while the object that
carries the content may. This slice puts that state machine on the production
path.

- `src/storage/bud3/registry.rs` - `Replacement` (the old commitment, the new
  commitment, the content id, both lengths, the proposer, the epoch and the
  finalized flag), the `replacements` map, and `propose_replacement`:
  - item 2 and item 3's on-chain half: the proposer is a Full validator that
    holds a share of the old object, so the proposal comes from the placement
    group. A sealed object is replaced only by its owner (item 9), because only
    the owner's client can re-code sealed bytes.
  - item 4: the replacement records the content id, the old commitment, the new
    commitment and both object lengths.
  - item 5: the NFT references move to the new object in the same step, and the
    content id is unchanged.
  - item 6: the old shares are not released until every new share is confirmed.
    `ack` finalizes the record at that moment; the old commitment then answers
    as a redirect instead of a deletion.
  - item 7's refusal half: a record that carries another content id is refused
    with `BadReplacement("the replacement carries different content")`, a
    commitment that is already live is refused because dedup already carries
    the content (section 6.6.4, S1), and a codec that is not open is refused
    with `CodecNotOpen`. A refusal leaves the state root unchanged.
- `src/storage/bud3/tx.rs` - `StorageTxV3::ReplaceObject`, appended after every
  earlier variant so no signed payload of an earlier variant changes its bytes,
  and `Applied::Replaced`.
- `src/tests/bud3_replace.rs` - the T22 acceptance: content id, reference
  movement, staged share release, refusal of other content, the Full validator
  rule, the sealed owner rule, a closed codec, a second pending proposal, an
  already live target, the wire round trip, and the executor door so the slice
  is on the production path (G-6).
- `src/storage/bud3/mod.rs` - the module map and the wiring note.

Wire change: one new payload variant inside the existing `TransactionType::StorageV3` envelope. The transaction type tag stays `70`; the A0 payload is the
signed bincode variant index, and the new variant takes the next index without
renumbering any earlier one. No RPC method and no field number changes.

## What WP-24 did not deliver in this slice, and why

- Item 7's second half, the provable wrong-repair slash for a proposer whose
  replacement produces other content, needs the validator directory's slash
  door. The registry has no slashing surface, so slice 3 wires it there rather
  than inventing one here.
- Item 1's codec table and the open set: this slice keeps the register as it is
  and uses it (a closed id is refused). Opening codecs 2, 3, 4, 10 and 11 needs
  their decoders and golden vectors, which is slice 2.
- Item 8's access tiering and the recording-only transition at launch is slice
  2 as well; it is a node-local read recorder, not a chain transaction.
- Item 6 of the card, the build-ratio measurements and
  `docs/STORAGE_MEASUREMENTS.md`, needs a Rust build of the workspace, which the
  directive forbids replacing with a declared number (section 0.5).
