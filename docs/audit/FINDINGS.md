# Findings ledger

The directive (Section 14) keeps one ledger for every finding: `BLG-001` to
`BLG-267` from the four retired documents, and `BLG-268` onwards for anything
found while working. This file is that ledger in the repository. It is English,
as the tree is (Section 14.1 item 9).

The full text of 267 findings lives in the directive, which is outside the tree
(the directive says so itself, Section 0.1 item 5). This file carries the part
the repository needs: the live status of a finding, the test that proves it,
and the commit and the CI run that closed it. A finding is `Closed` only when
the fix is on `main` and the test named on its row is green there.

## Closing protocol (Section 14.1 item 5)

1. Write the test the finding's "required test" field asks for; if there is
   none, choose a name and write it down.
2. The test is red before the fix. The pull request carries the red output.
3. Write the fix. The test turns green.
4. The pull request merges. The finding becomes `Closed` and its row carries the
   commit SHA and the CI run number.

A finding whose every site is deleted becomes `Removal closed`, and its
evidence is the `no_legacy_storage` gate output (Section 14.1 item 6).

## Status summary at 2026-11-06

No packet has verified the ledger on a live branch yet: WP-01 to WP-04 produce
that verification, and they are open pull requests, not merged work. So the
severity counts in Section 14.2 of the directive are the only numbers this file
can state, and they are the directive's, not a measurement of `main`.

## Closed

| Finding | Severity | Title | Status | Test | Package | Commit | CI run |
|---|---|---|---|---|---|---|---|
| BLG-255 | Low | Concept names are spread across the tree: a count gate and a baseline that only falls | Closed | `concept_names_gate_catches_injected_name`, `baseline_disagrees_with_measurement_canary`, `concept_map_owner_is_a_known_package` (all in `xtask/gates/src/gates/concept_names.rs`) | WP-05 | this pull request | see the pull request |

`BLG-255`'s directive note says the last zeroing of the count belongs to WP-43;
the count does not reach zero in this packet. What closes here is the packet's
own part: the map carries the owning package on every entry, the baseline is the
gate's own measurement, and the gate refuses a baseline that disagrees with it.

## Open

The rows WP-01 to WP-04 will fill. Until then the directive's Section 14.3
tables are the record, and every row of them is `Open` or `To verify` as that
section writes.
