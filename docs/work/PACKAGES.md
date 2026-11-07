# Work package status

One row per work package of the directive (section 15.7). A row is written only
from evidence: a merged path in the tree, an open pull request, or a command
output quoted in the row. The record protocol is directive section 15.5 item 7:
package, status, pull requests, last commit, CI run, closed findings.

Status vocabulary: `not started`, `in progress`, `in review`, `merged`,
`blocked`.

## Live state this file was written against

| Item | Value | How it was read |
|---|---|---|
| Date | 2026-11-06 | Clock of the working session |
| `main` | `cccf1da` ("Add files via upload") | `git log --oneline -1 origin/main` |
| Open pull requests | 9 (`WP-12`), 8 (codec register and dedup index) | `gh pr list --state all` |
| CI on `main` | red | run 42050659038, jobs listed in `docs/audit/FINDINGS.md` |
| CI on the two open pull requests | red at the time of reading | `gh run list` |

The tree is a single imported snapshot, so the "last commit" column names the
commit that carried the work into `main` where one exists.

## Packages

| Package | Title | Lane | Layer | Status | Pull requests | Last commit | Evidence |
|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Launch | not started | none | none | `docs/audit/LIVE_STATUS.md` does not exist |
| WP-02 | Live verification: storage | B | T-Launch | not started | none | none | `docs/audit/LIVE_STATUS.md` does not exist |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | T-Launch | not started | none | none | `docs/audit/LIVE_STATUS.md` does not exist |
| WP-04 | Live verification: clients, operations, CI, documents | D | T-Launch | in progress | none | none | This file and `docs/audit/FINDINGS.md` are its first output |
| WP-05 | Concept name map and counter gate | D | T-Launch | in progress | none | `cccf1da` | `config/naming/concept_map.toml`, `xtask/gates/src/gates/concept_names.rs` and `.github/concept-names-baseline.txt` exist. The `owner` field and the `concept_map_owner_is_a_known_package` test do not |
| WP-06 | Persistence and state recovery migration | B | T-Launch | not started | none | none | The three old gates of the state recovery family are still in the gate table under their old names |
| WP-07 | Removal of the legacy storage systems | B | T-Launch | not started | none | none | `src/storage/` still holds the legacy modules; the `no_legacy_storage` gate does not exist |
| WP-08 | Validator classes and one registry | A | T-Launch | not started | none | none | No class split in `src/validators/` yet |
| WP-09 | Execution environment interface | C | T-Launch | not started | none | none | No environment catalogue module |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Launch | merged (skeleton) | 5, 6 | `cccf1da` | `src/storage/bud3/` with `content_id`, `limits`, `meter`, `varint`, `bof1`, `segment`, `fountain` |
| WP-12 | Committee finality, instant seat handover, consensus hardening | A | T-Launch | in review | 9 | branch `arena/5b54fce9-budlum` | Pull request 9 touches `src/validators/committee.rs`, `src/chain/finality.rs`, `src/tests/finality_*.rs` |
| WP-19 | BOF-1 object, QR presentation, video commitment | B | T-Launch | in progress | none | `cccf1da` | `src/storage/bud3/bof1.rs` exists. The gates `bud3_object_is_universal` and `bud3_qr_is_presentation` and the tests `bud3_every_format_round_trips`, `bud3_two_paths_are_identical`, `bud3_text_format_round_trips`, `video_commitment_ignores_png_bytes` do not |
| WP-20 | Class aware placement, custody proof, repair | B | T-Launch | in review | 13 | `ca01543` | `placement.rs`, `custody.rs` and the custody and repair paths of `registry.rs` exist. Pull request 13 adds the gates `bud3-placement`, `bud3-custody-proofs` and `bud3-repair-fires`. Remaining: the `placement-table` tool, `repair.rs`, `symbol_protocol.rs`, `maintenance.rs`, the vectors under `tests/vectors/bud3/`, and the named tests |
| WP-21 | Upload, view, `StorageTx` v3 and RPC | B | T-Launch | in progress | none | `cccf1da` | `pipeline.rs`, `tx.rs` and the registry exist and are marked `WIRING: unwired`; the transaction door is not connected to block execution |
| WP-24 | A0 codec register and access layer | B | T-Launch | in review | 8, 6 | branch `arena/b7784c85-budlum` | Pull request 8 carries `bud/src/bud_format_*.rs` and `src/storage/bud3/dedup_index.rs` |
| WP-42 | CI, gates and supply chain | D | T-Launch | in progress | none | `cccf1da` | 142 gate modules under `xtask/gates/src/gates/`. The gates `no_float_in_consensus_paths` and `workflows_cover_every_workspace` do not exist |
| WP-43 | Documents, README and the launch report | D | T-Launch | not started | none | none | `README.md` is not the target text of the directive; the gates `readme_definition_block_is_verbatim`, `readme_has_no_placeholders` and `readme_claims_are_wired` do not exist; `config/naming/concept_map.toml` is still in `count` mode |

Rows for the other packages are added when their evidence exists. A row without
evidence would be a claim, and a claim is not a record.

## Claim protocol

Directive section 15.3 item 1 has WP-04 open one issue per package, and item 2
claims a package with a `CLAIM` comment and an `in-progress` label. GitHub
issues are disabled on this repository, so a package cannot be claimed that
way yet. Until an issue tracker is available, this file is the claim record: a
row with `in progress` or `in review` and a branch or pull request beside it
names the work in flight, and a row with `not started` names none.

## This branch

- Package: WP-20, a slice of it (gate work). Directive section 15.5 item 2
  allows a large package to be delivered in several pull requests.
- Pull request: 13. Last commit at the time of this record: `ca01543`.
- CI on the pull request: queued when this record was written. The `gates` job
  is the one that runs `bud3-placement`, `bud3-custody-proofs` and
  `bud3-repair-fires`, both through `--all --self-test` and through `--all`.
- Paths: `xtask/gates/src/gates/bud3_placement.rs`,
  `xtask/gates/src/gates/bud3_custody_proofs.rs`,
  `xtask/gates/src/gates/bud3_repair_fires.rs`, the gate table in
  `xtask/gates/src/main.rs`, `docs/work/PACKAGES.md` and
  `docs/audit/FINDINGS.md`.
- Not touched: `src/storage/bud3/`. The gates read the modules and add no code
  to them, so the two open pull requests cannot conflict on this branch beyond
  the shared gate table.
