# Audit Directory Index

What is in this directory, and what the binding directive says should be in it.
Two of the files below are registers the directive makes binding; the rest of the
directory is the material that feeds them.

| File | What it is | Directive reference | State |
|---|---|---|---|
| `AUDIT_FINDINGS.md` | Review-round ledger for two earlier pull requests: records `AF-01`..`AF-15`, each with the commit that closes it | none; it predates the directive | Present |
| `TESTNET_TRACEABILITY.md` | Every line of an earlier directive mapped to its code, its test and the job that runs it | none; it maps a superseded document | Present, stale |
| `LIVE_STATUS.md` | Index of the live finding status, the summary, and what M0 still needs | 14.1 item 4, 15.8 WP-04 | Present |
| `FINDINGS.md` | One row per finding, in English, with live status, test name and closing package | 14.1 item 9, 15.8 WP-04 | **Missing** |
| `GATES.md` | The live gate suite read against the directive's gate inventory and gate-change table | 16.3, 5.4 | Present |
| `TLG_REPORT.md` | The Testnet Launch Gate register: 27 items, evidence type, what the tree has, status | 18 | Present |
| `live/lane-a.md` .. `live/lane-d.md` | One file per lane, each carrying that lane's finding records | 15.8 WP-01..WP-04 | **Missing** |
| `REVIEW_1.md`, `REVIEW_2.md` | The two independent reviews | 18 TLG-22, 15.8 WP-47, WP-48 | **Missing** |

## How to read the pair `LIVE_STATUS.md` and `FINDINGS.md`

`FINDINGS.md` is the register: one row per finding identity, with the live state a
lane measured. `LIVE_STATUS.md` is the index over it: the summary counts, the
mapping back to the directive's own numbers, and the list of what is missing.

Neither can be written before the four lane files exist, because a state that no
lane measured is not a state (directive 0.4 item 3). `LIVE_STATUS.md` exists anyway,
because a gap recorded in the tree is worth more than a gap recorded in a pull
request comment: the next agent reads the tree.

## Status vocabulary

`GATES.md` and `TLG_REPORT.md` use three words, and they are not interchangeable.

- **Present** - the artifact the directive names exists in this tree.
- **Unverified** - the artifact exists and no verdict exists for it, because no
  workflow run has completed for the commit under review.
- **Red** - the artifact does not exist, or exists and contradicts the item.

No item in `TLG_REPORT.md` is green, and none is approved. Directive 18 rule 1
requires the report to be approved by an agent from the other lane, and that agent
writes a CI run number. There is no such run to write.
