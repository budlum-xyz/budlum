# Live status

The M0 output: the index of the four lane files, the summary counts
recomputed from the live tree, and the source-directive item mapping.

Read with `docs/audit/FINDINGS.md` (the ledger) and
`docs/work/PACKAGES.md` (the package register). Every number here is
recomputed from the ledger rows on this branch, not carried over from the
ledger's own summary.

## Lane files

| Lane | Scope | File | State |
|---|---|---|---|
| A | Core: consensus, finality, validator registry, network, state transition, genesis, economics, domains, bridge | `docs/audit/live/lane-a.md` | not started - WP-01 has no branch |
| B | Storage: B.U.D. 3.0, persistence, dependent modules, privacy and AI boundary | `docs/audit/live/lane-b.md` | not started - WP-02 has no branch |
| C | Execution, BudZero, domains, privacy, AI | `docs/audit/live/lane-c.md` | not started - WP-03 has no branch |
| D | Clients, operations, CI, documentation, unified status | `docs/audit/live/lane-d.md` | written on this branch (WP-04, 1/2) |

M0 is not reached: it needs WP-01, WP-02, WP-03 and WP-04 merged, and three
of the four have no branch. This file exists now because WP-04's deliverables
are the index the other three lanes write into, and an index that appears
after the lanes is an index nobody used.

## Summary, recomputed

| Measure | Count |
|---|---|
| Ledger rows | 311 |
| critical | 77 |
| high | 104 |
| medium | 82 |
| low | 12 |
| archive rows carrying the old S1/S2/S3 codes | 36 |

| Live status | Rows |
|---|---|
| `open - live verification pending` | 296 |
| `open - verified` | 3 |
| `open - verified and ratcheted` | 1 |
| `open - partly fixed` | 1 |
| `open - not re-scanned` | 1 |
| `closed - previously fixed` | 8 |
| `closed by removal` | 1 |

**176 critical and high rows are still open.** The launch gate needs
that number at zero, or the feature each one belongs to switched off on the
testnet chain id with a test that proves it is off.

The ledger's own summary says 207 rows split 73 critical, 80 high, 51 medium
and 3 low, with one closed. Recomputed from the rows themselves the split is
identical, which is the check that the ledger was transcribed and not
paraphrased. The counts above are larger because they cover all four
sources, not the ledger alone.

### The sample observation holds

The ledger warns that its own "206 open" figure is stale for this branch,
because six of the nine rows it hand-checked carried a fix. Lane D confirms
the warning on its own scope: of the 68 rows it owns, 7 were already fixed
and 1 was already removed before this branch existed. Extrapolating that
rate to the other three lanes is exactly what the ledger forbids, so no
extrapolation is recorded here.

## Rows by owning lane

| Lane | Rows |
|---|---|
| A | 116 |
| B | 86 |
| C | 29 |
| D | 68 |
| A/B | 4 |
| A/C | 2 |
| A/D | 1 |
| B/C | 4 |
| B/D | 1 |

A row with two lanes is closed by two packages, one leg each; the star
convention in the ledger marks those. The lane that owns the row's evidence
is the one whose package owns the code path named in the finding.

## Source-directive item mapping

The ledger binds the Testnet Master Directive items (B-01 to B-21, A-01 to
A-08, E-01 to E-08) and the Quantum Directive items (K-01 to K-27) to
finding identities in its own section 4.2 and 4.3 tables. **Those tables are
not in the tree.** The ledger lives outside the repository and only its
finding rows were carried into this directive, so the item-to-finding
mapping cannot be produced from what is here, and inventing it would be
worse than leaving the gap named.

What the tree does carry:

| Source item | Finding | Where the reference lives |
|---|---|---|
| K-15, the public framing rule | BLG-092 | named in the ledger row itself; `README.md` line 25 and line 461 satisfy it on this branch |

Everything else in that mapping is owed by WP-01 to WP-03 against the source
ledger, and is recorded as owed rather than guessed.

## New findings raised by this pass

| Identity | Severity | Title | Closing package |
|---|---|---|---|
| BLG-268 | high | The binding directive sits in the tree as a Turkish file the English gate does not allow | WP-42, WP-43 |
| BLG-269 | low | The repository has GitHub issues disabled, so the one issue per package cannot exist | WP-04 |
| BLG-270 | medium | No workflow on `main` has ever completed, so no gate has produced a verdict on this history | WP-42 |

## CI and measurement baseline

23 workflows have a run on `main`; none has completed. The only completed
runs on this history are cancelled. So no gate has a verdict, no measurement
document can cite a run number, and every green claim in the 51 open pull
requests is unbacked. The first completed run of this branch's pull request
is the first real baseline, and `docs/work/PACKAGES.md` records it when it
exists.

