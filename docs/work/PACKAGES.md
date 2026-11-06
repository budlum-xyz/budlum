# Work package status

One row per work package of the directive (section 15.7). A row is written
only from evidence: a merged path in the tree, an open pull request, or a
command output quoted in the row. The record protocol is directive
section 15.5 item 7: package, status, pull requests, last commit, CI run,
closed findings.

Status vocabulary: `not started`, `in progress`, `in review`, `merged`,
`blocked`.

## Packages

| Package | Title | Lane | Layer | Status | Pull requests | Last commit | CI run | Closed findings |
|---|---|---|---|---|---|---|---|---|
| WP-05 | Concept name map and counter gate | D | T-Launch | in review | #20 | `cc772c9` | `42168200804` (Gates queued) | BLG-255 (owner field and owner test; the counter is unchanged) |

## WP-05 evidence

- `config/naming/concept_map.toml`: 27/27 entries carry an `owner` in
  `WP-01..WP-64`.
- `docs/NAMING.md`: the owner column is present for all 27 rows.
- `xtask/gates/src/gates/concept_names.rs`: `parse_map` requires `owner`
  and calls `parse_owner`; the canary rejects `WP-99` and `WP-5`.
- `concept_map_owner_is_a_known_package` pins the real map.
- The legacy-name counts are unchanged, so the baseline is unchanged.
