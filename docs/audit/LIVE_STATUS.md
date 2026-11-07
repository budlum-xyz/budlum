# Live status (M0, partial)

Scope of this file: what was checked on the live branch, with the evidence and the limits of each check.
M0 (section 15.6 of the directive) is not reached. This file records what is verified and what is not.

## Environment

| Item | Value | Evidence |
|---|---|---|
| Base commit of `main` | `20140e8` | `git log` |
| Working branch | `arena/d9464f95-budlum` | `git branch` |
| Rust toolchain in the sandbox | not installed (`cargo` missing) | `which cargo` returns nothing |
| Crate registry access | not allowed (`crates.io` is outside the outbound allowlist) | sandbox policy |
| Consequence | no `cargo build`, `cargo test`, or `xtask` gate run was possible | this file |
| GitHub Issues | disabled for the repository | `gh issue list` error |
| CI runs for this branch | not triggered by this session | no workflow run was waited for |

Result: no compile, test, or CI result is claimed in this file. Each claim below comes from a file or PR listing.

## Repository facts (verified)

| Fact | Value |
|---|---|
| Tracked files on `main` | 1209 |
| `THE_BUDLUM_DIREKTIF.md` tracked on `main` | yes |
| `.gitignore` excludes the directive | no |
| Legacy storage modules still present under `src/storage/` | yes (for example `living_threshold.rs`, `mobile_self.rs`, `qr_*.rs`) |
| `src/consensus/filiz.rs` present | yes |
| `src/validators/` present | no |
| Open PRs | 105 (8 draft) |
| Distinct files touched by open PRs | 859 |
| Open PRs touching `THE_BUDLUM_DIREKTIF.md` | 39 |
| Open PRs naming `WP-42` in title or branch | 28 |

The 28-PR overlap on `WP-42` and the 39 PRs that edit the directive file mean the open stack is not a clean queue. It needs one integration owner (section 15.5 rule 5 and section 15.3 rule 4).

## Concept names (verified on this branch)

- Concept map: `config/naming/concept_map.toml` (27 entries, from Ek C, parsed with a TOML reader).
- Count baseline: `.github/concept-names-baseline.txt`, produced by `scripts/concept_names_count.py --write`.
- Gate status: the count check runs as a Python script. The Rust `concept-names` gate in `xtask` is not written. Its self test is not written.
- Discrepancy with BLG-255: the directive gives `Filiz` 15 files, `Mikoriza` 13, `Graft` 24, `Pollen` 44. This tree gives 11, 23, 41, and 69. The directive numbers come from the analysis snapshot `testnet-quantum`, and this tree is a different snapshot. The baseline here is the value for this tree. BLG-255 is not closed by this file.

## Findings status

- `docs/audit/FINDINGS.md`: not written. Each of the 267 findings (BLG-001 to BLG-267) needs a reproduction test on the live tree. No test could be run in this session, so no finding is marked closed or open here.
- Section 14 of the directive lists the findings. Their live status remains unknown.

## Open items for M0

1. Install a Rust toolchain from an allowed source, or run the checks in a CI runner that has one.
2. Run section 14.1 reproduction tests for each finding and record the result in `docs/audit/FINDINGS.md`.
3. Run each lane's audit and write `docs/audit/live/lane-*.md`. Lanes: A (consensus), B (storage), C (execution), D (clients and CI).
4. Choose one integration order for the 105 open PRs (section 15.5 rule 5).
