# Live audit status

Maintained by package WP-04, lane D. It indexes the four lane ledgers, counts what they hold, and
maps the source directive clauses of section 14.7 to finding ids.

Snapshot: `main` = `cccf1da1f4bcfe97503a3a00cfba24b172b49b31`, read 2026-11-06 05:45 UTC.
The only lane ledger on `main` at the snapshot is this delivery's `lane-d.md` (lane D).

## 1. Lane ledger index

| Lane | Agent | Ledger file | State |
|---|---|---|---|
| A | A | `docs/audit/live/lane-a.md` | not on `main`; open PR #12 carries a lane A ledger |
| B | B | `docs/audit/live/lane-b.md` | not on `main`; open PR #12 carries a lane B ledger |
| C | C | `docs/audit/live/lane-c.md` | not on `main`; open PRs #12, #15 and #16 carry lane C ledgers |
| D | D | `docs/audit/live/lane-d.md` | **delivered** by this PR |

The lane A to C ledgers are named in open pull requests and are not files on `main`, so their rows
cannot be counted here. No count in this file includes them.

## 2. Ledger size, as the directive writes it

| Source | Id range | Count | Rows found in the section 14 tables |
|---|---|---|---|
| Old finding ledger | BLG-001 to BLG-207 | 207 | 207 |
| B.U.D. 3.0 directive, code defects H1 to H15 | BLG-208 to BLG-222 | 15 | 15 |
| BudZero directive, findings E1 to E23 | BLG-223 to BLG-245 | 23 | 23 |
| This directive's own review | BLG-246 to BLG-267 | 22 | 22 |
| Archive families | BULGU-001 to 027, TEST-GAP-01 to 08, DOC-GAP-01 to 09 | 44 | 44 |
| **Total** | | **311** | **311** |

The directive's header table says "267 findings and 44 archive records", and both figures match the
tables: 267 rows carry a `BLG-` id, 44 carry an archive id (27 `BULGU-`, 8 `TEST-GAP-`, 9
`DOC-GAP-`), and no id is missing or duplicated. "267 findings" refers to the `BLG-` range alone; it
is not a total, and reading it as one is a counting error this table exists to prevent.

## 3. Distribution by closing package

Every one of the 311 rows names at least one closing package. Grouped over all rows, a row counted
once per package it names:

| Closing package | Records | Lane |
|---|---|---|
| WP-17 | 44 | A |
| WP-42 | 32 | D |
| WP-45 | 31 | B |
| WP-44 | 29 | A |
| WP-07 | 27 | B |
| WP-33 | 26 | C |
| WP-12 | 23 | A |
| WP-16 | 13 | A |
| WP-61 | 13 | D |
| WP-56 | 11 | B |
| WP-19 | 10 | B |
| WP-43 | 8 | D |
| WP-23 | 7 | B |
| WP-15 | 6 | A |
| WP-41 | 5 | D |
| WP-22 | 5 | B |
| WP-57 | 5 | A |
| WP-08, WP-21, WP-24, WP-26, WP-39, WP-40, WP-60 | 4 each | mixed |
| WP-11 | 3 | D |
| WP-18, WP-36 | 2 each | B, D |
| WP-05, WP-13, WP-20, WP-25, WP-27, WP-28, WP-29, WP-31, WP-32, WP-46 | 1 each | mixed |

The sum of this column is larger than 311 because a row can name two packages (for example BLG-030
closes under WP-61 and WP-41). It is a load figure per package, not a partition of the ledger.

## 4. Lane totals

| Lane | Records whose closing package is in the lane | Source |
|---|---|---|
| D | 70 | `lane-d.md` section 8 |
| A, B, C | not countable at the snapshot | the lane ledgers are not on `main` |

## 5. Importance

The section 14 tables do not use one severity vocabulary. Sections 14.3 and 14.5 write words,
section 14.4 writes the B.U.D. 3.0 and BudZero identifiers `H1` to `H15` and `E1` to `E23`, and
section 14.6 writes `S1`, `S2`, `S3`.

| Label as written | Rows |
|---|---|
| Critical | 75 |
| High | 90 |
| Medium | 64 |
| Low | 8 |
| `H1` to `H15` | 15 |
| `E1` to `E23` | 23 |
| `S1` | 1 |
| `S2` | 5 |
| `S3` | 30 |

A single ordering over this table is a decision, not an observation. The proposed mapping, for the
final WP-04 pull request to accept or reject, is `S1` = Critical, `S2` = High, `S3` = Medium, with
`H1` to `H15` and `E1` to `E23` left as their source-document identifiers rather than re-ranked
here.

## 6. Section 14.7: source directive clauses, mapped to finding ids

Section 14.7 says the clauses of two earlier directives are tracked through finding ids, and that
this file carries the mapping. The directive names the clause families, not the per-clause rows:

| Clause family | Codes | Tracked through | Rows in section 14 |
|---|---|---|---|
| Testnet master directive | B-01 to B-21 | finding ids | the mapping to individual ids is not written in the directive |
| Testnet master directive | A-01 to A-08 | finding ids | same |
| Testnet master directive | E-01 to E-08 | finding ids | same |
| Quantum directive | K-01 to K-27 | finding ids | same |

The earlier table (section 4.2 and 4.3 of the old ledger) that holds the per-clause rows is not in
this tree, so this table cannot be completed without it. It is written here with the gap stated, not
filled with an invented mapping (section 0.3 rule 1, section 0.5 rule 1).

## 7. CI baseline

WP-04 card item 2 asks for each workflow's last state, the list of red jobs, and runner memory
limits. The first two are measured below from the Actions API; the third is not answerable from this
tree and is recorded as a gap rather than guessed.

Measured 2026-11-06 06:45 UTC, over all 30 workflow files in `.github/workflows/`.

### Last state, per workflow

| State | Count | Workflows |
|---|---|---|
| `success` | 5 | Build error relay, Fuzz Nightly, Provenance (SBOM attestation), Release signature, Watchdog (older run) |
| `failure` | 2 | Testnet Rehearsal (`main`, 2026-11-05T09:29:57Z), Watchdog (`main`, 2026-11-06T04:33:54Z) |
| `queued` / `pending` | 22 | the remaining files, all triggered by pushes made during this session |
| `cancelled` | 1 | AIR Mutants Nightly (`2026-11-05T09:32:06Z`) |

The 22 queued runs are not a green signal and not a red one: no step has started. This file's earlier
snapshots reported 0 completed runs; that is no longer true, and the change is not this lane's doing.

### The two red jobs, and what they assert

Both are on `main`, both are scheduled drift detectors, and both failed in a *single step*:

| Workflow | Job | Failed step | What the step means |
|---|---|---|---|
| Watchdog | Main health pulse | `Lockfiles still match their manifests on main` | For every `Cargo.lock` in the tree, `cd` to its directory and run `cargo metadata --format-version 1 --locked`. A nonzero exit means a manifest changed without its lockfile |
| Watchdog | RustSec drift | `Audit every workspace lockfile` | `cargo audit --file` over all 15 lockfiles, against a freshly fetched advisory DB. The workflow states that a failed DB fetch is itself a failure, so a red here can also mean the DB did not refresh |

The exact `cargo` output is not reachable from this environment: the job log endpoints for both jobs
return an `EOF` from the blob storage redirect on every attempt, and `--log-failed` returns empty.
What is cited here is the workflow source and the failed step's name, not the error text. A reader
with log access should read the failing `=== freshness: <dir> ===` line to name the stale lockfile.

The same job has two further steps that *passed*, which is worth recording because they bound the
failure: `Workflows still parse (actionlint)` and the two `budlum-gates regen-health-door` runs. So
the workflow YAML parses and the regen gate is wired; the drift is in a manifest/lockfile pair.

### What could not be measured

- **Runner memory limits.** No workflow pins a runner size: every job uses `ubuntu-latest` (89
  occurrences) or a matrix value, and no file states a memory ceiling, a swap size, or an OOM
  budget. The limit is therefore whatever GitHub gives `ubuntu-latest` at run time, which is not in
  this tree. Card item 2 asks for it, so it is recorded as a gap instead of a number.
- **Per-job timing.** Not requested by the card and not fetched here.

## 8. Proposed replacement for section 14.2 of the directive

WP-04 card item 7 asks for a proposal, not an edit: the directive is the authority and this lane does
not rewrite it. The proposal is the table below, which keeps section 14.2's shape (source, id range,
count) and adds the two columns a reader needs before trusting a count.

Two things are wrong with section 14.2 as it stands, and the proposal is the fix for each:

1. **"the ledger has 1 closed (BLG-005)" is stale for this branch.** Section 14.3 marks BLG-005
   `Closed (ledger record), to be verified` and still gives it a closing package (WP-16). Read
   against the live tree, the record's condition is absent: `.gitignore:16-17` excludes `/secrets/`
   and `/data/`. The proposal moves the count into the verify column instead of restating it.
2. **The severity column was never written.** Section 14.2 gives severities for the ledger family
   only. The four other families carry severities in their own tables and the counts are not
   summed anywhere, so a reader who wants "how many critical findings does this repository have"
   cannot answer it from the summary. The proposal sums them and renders every severity in
   English, because repository content is English (section 0.4): sections 14.3 to 14.5 use four
   words, and section 14.6 uses an `S1` to `S3` prefix.

| Source | Id range | Count | Critical | High | Medium | Low | Rows found in the 14 tables |
|---|---|---|---|---|---|---|---|
| Old finding ledger | BLG-001 to BLG-207 | 207 | 73 | 80 | 51 | 3 | 207 |
| B.U.D. 3.0 directive, H1 to H15 | BLG-208 to BLG-222 | 15 | 2 | 6 | 6 | 1 | 15 |
| BudZero directive, E1 to E23 | BLG-223 to BLG-245 | 23 | 0 | 8 | 12 | 3 | 23 |
| This directive's own review | BLG-246 to BLG-267 | 22 | 2 | 9 | 9 | 2 | 22 |
| Archive families | BULGU-001 to 027, TEST-GAP-01 to 08, DOC-GAP-01 to 09 | 44 | 1 (`S1`) | 6 (5 `S2` + 1 High) | 34 (30 `S3` + 4 Medium) | 3 | 44 |
| **Total** | | **311** | **78** | **109** | **112** | **12** | **311** |

The mapping the archive column needs is the one section 14.2 does not state: `S1` reads as Critical,
`S2` as High and `S3` as Medium, because the archive table marks severities with an `S` prefix while
the other four use words. The archive row keeps both spellings so the mapping is visible rather than
implied. If the directive prefers a different mapping, only that row and the totals change.

### 8.1 What the proposal deliberately does not change

- The "267 findings and 44 archive records" reading. The 267 is the `BLG-` range and the 44 is the
  archive; adding them is the counting error section 2 of this file exists to prevent.
- The sample observation paragraph. Its claim that "206 open is not current for this branch" is
  still true, and this lane's readings make it more true, not less: ten of its records are
  `Previously fixed`, six are narrowed, and one closes by removal.

### 8.2 One more number a closing package needs

The proposal adds a per-package count to the summary because section 15.7's package table is ordered
by priority, and priority reads as effort. Lane D is 70 records across 15 packages, and the whole
311 splits as: WP-17 44, WP-42 32, WP-45 31, WP-44 29, WP-07 27, WP-33 26, WP-12 23, WP-16 13,
WP-61 13, WP-56 11, WP-19 10, WP-43 8, WP-23 7, WP-15 6, WP-41 5, WP-22 5, WP-57 5, then eight
packages with 4 each and ten with 1 each. A package that carries 44 records cannot be closed in the
same PR shape as one that carries 1, and the summary table is where that is cheapest to see.

## 9. What this file does not claim

- No finding is closed, verified or invalidated here.
- No CI run number is cited: 400 sampled runs on this repository are 155 `cancelled` and 245 without
  a conclusion, and no run has a `success` or `failure` conclusion.
- The numbers in sections 2 to 5 are row counts of the directive's own tables, not measurements of
  code. Section 0.5 rule 1 keeps them labelled that way.

## Rows carried from pr-68 (M0 live verification)

- New findings: BLG-268+ (not yet identified)
