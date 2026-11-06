# Work packages: state on the live branch

One row per package of the work-package table. The directive calls a package
`İP-NN`; the repository and GitHub call it `WP-NN` (section 15.3 item 1), and
the two names mean the same package.

A row is written only from evidence: a path in the tree, an open pull request,
or a CI run whose number is quoted. A package with no evidence is absent from
this table rather than described from memory (sections 0.3 item 5 and 0.4).

Two process notes, both recorded because the table would otherwise misdescribe
how the work is running:

* GitHub issues are disabled on this repository, so the claim of a package
  cannot be an issue comment with an `in-progress` label (sections 15.3 items 1
  and 2). The claim is written here, and a row says so.
* The workspace fixes the branch name of a session (`arena/<id>-budlum`), so the
  `wp/NN-<name>` branch shape of section 15.5 item 1 is not available either.
  The package id in the pull-request title is the authoritative one.

## State

| Package | Lane | State | Branch or pull request | Evidence |
|---|---|---|---|---|
| WP-01 | A | in review | #12, `arena/b0362659-budlum` | `docs/audit/live/lane-a.md`, `src/tests/audit_lane_a.rs` in that pull request |
| WP-02 | B | in review | #12, #15 | `docs/audit/live/lane-b.md`, `docs/audit/live/legacy-storage-inventory.md` |
| WP-03 | C | in review | #12, #15 | `docs/audit/live/lane-c.md`, `docs/audit/live/engine-inventory.md` |
| WP-05 | D | in review (this pull request) | `arena/984dc17c-budlum` | `config/naming/concept_map.toml` carries an `owner` for all 27 entries; the gate refuses an entry without one; `docs/NAMING.md` states the ownership table; the baseline is lowered in the same change |
| WP-06 | B | in review | #11 | `src/persistence/` in that pull request |
| WP-12 | A | in review | #9 | committee seat table, `src/chain/finality.rs` in that pull request |
| WP-20 | B | in review | #13 | `xtask/gates/src/gates/bud3_placement.rs`, `bud3_custody_proofs.rs`, `bud3_repair_fires.rs` |
| WP-24 | B | in review | #8 | `crates/bud-codec/`, the codec register in `src/storage/bud3/` |
| WP-44 | A | in review | #14 | `src/settlement/testnet_features.rs`, `docs/audit/FEATURE_DECISIONS.md` |

## WP-05, as delivered

The card asks for six things. Each one is named with the file that carries it:

1. The map of appendix C, in `config/naming/concept_map.toml`. All 27 entries
   are the appendix's entries, in the appendix's order, with the appendix's
   `patterns`, `paths`, `allow_paths`, code names, English terms, areas and
   reasons.
2. The gate, in `xtask/gates/src/gates/concept_names.rs`. It searches `src`,
   `crates`, `budzero`, `execution`, `mobile`, `xtask`, `docs`, `config`,
   `proto` and `contracts`, skips `global_allow_paths` and each entry's
   `allow_paths`, and counts per entry.
3. Two modes, `count` and `absolute`. The starting mode is `count`; the map says
   so, and `mode = "absolute"` is WP-43's closing change.
4. The baseline, `.github/concept-names-baseline.txt`: one line per entry,
   `name|files|matches`. A rise fails CI; a fall fails CI until the line is
   lowered; the writer refuses to raise a number.
5. An `owner` per entry, and the English ownership table in `docs/NAMING.md`.
6. A self test that injects a legacy name into a staged tree and requires the
   red verdict, plus the two ratchet tests.

## Notes for the next package

* The live measurement and the directive's analysis-base count in section 14.5
  (BLG-255) differ. The baseline carries the live number, and the divergence is
  recorded as BLG-276 in `docs/audit/FINDINGS.md`.
* The counter's `PUL` entry reads one match higher in this workspace than the
  baseline it inherits, and the difference is the workspace's own checkout
  (`budzero/Cargo.lock`, a generated file). CI's checkout is a different set of
  files, so no baseline number was invented to make the local count equal it.
  The finding is BLG-276 too, because it is the same question: which tree is
  being counted.
