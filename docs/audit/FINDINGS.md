# Findings ledger

One ledger for every finding, in one number sequence. Record `BLG-NNN` never
changes and is never reused (directive section 14.1 item 1).

* **Severity**: Critical, High, Medium, Low.
* **State**: Open, Verified (open and reproduced), Closed (a fix merged),
  Closed by removal (the code is gone), Invalid (the condition no longer
  exists, with evidence).
* **Closing protocol** (section 14.1 item 5): the finding's test is written
  first and observed red, the fix follows, the pull request carries the red
  output, and the merged record carries the commit SHA and the CI run number.
  A record is never marked Closed on a self-declaration (section 0.3 item 5).
* **New findings** during the work take the next free id from `BLG-268`
  upward (section 14.1 item 9).

The 267 directive findings and the 44 archive records (`BULGU-*`,
`TEST-GAP-*`, `DOC-GAP-*`) are listed per lane in `docs/audit/live/lane-a.md`
through `lane-d.md`. This file is the repository-side ledger those lanes report
into; the summary of all of them is `docs/audit/LIVE_STATUS.md`.

---

## Round 1 - 2026-11-06

Findings raised while reading the live tree (`main` `cccf1da1`) for WP-05, the
concept-name map and counter.

| Id | Severity | Area | Finding | Evidence | Closing package |
|---|---|---|---|---|---|
| BLG-276 | Low | naming, CI | The concept-name counter has never run on this tree, so the directive's analysis-base count (BLG-255: `Filiz` in 15 files, `Mikoriza` 13, `Graft` 24, `Pollen` 44) is not the live count. Measured on `cccf1da1`: `Filiz (leader election)` 11 files, `Mikoriza` 23, `Graft` 41, `Pollen` 71. The ratchet compares against a baseline that was written from a different tree, and a first run on `main` reports the whole difference at once. | `config/naming/concept_map.toml`, `.github/concept-names-baseline.txt`, and the gate's own report; section 14.5 BLG-255 | WP-05 (the baseline is set from the live measurement, and the divergence is stated in the baseline's header) |
| BLG-277 | Medium | naming, CI | The concept map of appendix C has an `owner` field per entry and the repository's map did not. An entry with no owner is a rename nobody performs: the map would name a term to retire and no package to retire it. The gate did not read the field, so the omission was invisible. | `config/naming/concept_map.toml` before this change, appendix C of the directive, `xtask/gates/src/gates/concept_names.rs` | WP-05 |
| BLG-278 | Medium | build, CI | `tree_is_english` fails on any commit that changes `.github/concept-names-baseline.txt`, because the gate scans the file and the baseline quotes the retired Turkish names as its keys. The file is in `ALLOWED_FILES` now; before, the only reason the gate passed was that the file never changed. | `xtask/gates/src/gates/tree_is_english.rs`, `ALLOWED_FILES`, and `.github/concept-names-baseline.txt` | WP-05 |

BLG-278 is the kind of finding the suite cannot report about itself: a gate
whose exemption list is one entry short passes until the day the exempted file
is touched, and then it fails on the change that improves it.
