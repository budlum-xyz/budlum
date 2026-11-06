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

| BLG-012 | High | The coverage ratchet reads the first file's percentage instead of the total and lets a `NaN` baseline through | Closed | `baseline_must_be_a_finite_percentage` and `the_total_is_read_not_the_first_file` in `xtask/gates/src/gates/coverage.rs` | WP-42 | already fixed, before this packet | the pull request names the tree |
| BLG-014 | Medium | The backup drill ignores the `--check-db` exit code and accepts a substring as success | Closed | `check.status.success()` plus `integrity_line` in `xtask/tools/src/backup_drill.rs`, pinned by `backup_drill::self_test` step 4 and `integrity_line_reports_what_matched` | WP-42 | already fixed, before this packet | the pull request names the tree |

`BLG-012` and `BLG-014` were both already closed in the tree when this packet
read them: `coverage.rs` takes `data[0].totals.lines.percent` (the totals), and
`parse_baseline` refuses `nan`, `inf`, a negative floor and anything above 100;
`backup_drill.rs` returns an error when `--check-db` exits non-zero and parses
the integrity line with `integrity_line` instead of accepting a substring. The
WP-42 card lists them because the directive's snapshot predates the fixes. No
test was added here, because both already have one and a second test of the same
line proves nothing; the evidence is those tests, by name.

### Partly closed, with the remainder named

| Finding | Severity | Title | Status | What is done | What remains |
|---|---|---|---|---|---|
| TEST-GAP-02 | Medium | Kani covers a quarter of the `SECURITY.md` targets | Partly closed | `kani/` builds, and `workflows-cover-every-workspace` makes its coverage by a workflow a measured fact instead of a claim | the harnesses for seat allocation, `frac_attos` arithmetic and the fee formula are proof work, not gate work; they are not in this packet |

## Open

The rows WP-01 to WP-04 will fill. Until then the directive's Section 14.3
tables are the record, and every row of them is `Open` or `To verify` as that
section writes.
