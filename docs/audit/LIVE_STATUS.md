# Live Status

The index of the live finding status (directive 14.1 item 4). One file per lane
carries that lane's records; this file carries the index, the summary and the
mapping back to the directive's own numbers. It is the M0 artifact of WP-04, and M0
is not complete.

Written on a branch based on `main` at `20140e87`. Everything under "measured" was
measured on that commit; everything under "the directive says" is the directive's
snapshot and is labelled as such, because the directive's own rule 0.4 item 3 says a
state held in a document is not a state.

## Measured

| Artifact | State here | Consequence |
|---|---|---|
| `docs/audit/live/lane-a.md` | absent | WP-01 has no record |
| `docs/audit/live/lane-b.md` | absent | WP-02 has no record |
| `docs/audit/live/lane-c.md` | absent | WP-03 has no record |
| `docs/audit/live/lane-d.md` | absent | WP-04 has no record |
| `docs/audit/FINDINGS.md` | absent | No finding has a live status, a reproduction test name, or an evidence line |
| `docs/work/PACKAGES.md` | present | The package register exists as of this change |
| `docs/audit/TLG_REPORT.md` | present | The launch gate register exists as of this change |
| `docs/audit/AUDIT_FINDINGS.md` | present, different register | Review rounds `AF-01`..`AF-15` from two earlier pull requests. It contains 0 `BLG-` identities, so it is not this register and cannot stand in for it |

The finding register is the one artifact every closure claim depends on: directive
14.5 makes a finding closed only when a test named `blg_NNN_<short name>` was red
before the fix and green after it. Measured on this tree:

```
$ grep -rn "fn blg_" --include=*.rs . | wc -l
0
```

So not one finding can be closed by the protocol today, whatever the code does. That
is a statement about the tree, not about the work of the four lanes: a lane that
verifies a finding and finds it already fixed (14.1 item 7) must still land the test
that proves it, and none is in the tree.

## The directive's numbers, not re-measured

| Source | Identity range | Count |
|---|---|---|
| Finding Register (`main` `c5b06799`) | BLG-001 to BLG-207 | 207: 73 Critical, 80 High, 51 Medium, 3 Low |
| B.U.D. 3.0 directive, code defects H1..H15 | BLG-208 to BLG-222 | 15 |
| BudZero directive, findings E1..E23 | BLG-223 to BLG-245 | 23 |
| The directive's own review | BLG-246 to BLG-267 | 22 |
| Archive families | BULGU-001..027, TEST-GAP-01..08, DOC-GAP-01..09 | 44 |

These are the directive's snapshot counts. They are reproduced here so the next
reader does not have to open the directive to know the order of magnitude, and they
are explicitly not a live count: this tree has no artifact that could produce one.

## Recount proposal (WP-04 job 7)

The directive's own sample says the register's "206 open" is stale for the analysis
base, because 6 of 9 sampled findings already carry a fix. The same is likely here,
and a live number is what M0 asks for. The proposal, in the order it has to happen:

1. Write the four lane files. Each lane takes the findings whose closing package
   belongs to it (directive 15.2) and records, per finding: identity, live state,
   reproduction test name, evidence (file and line), closing package.
2. Write `docs/audit/FINDINGS.md` from those four files, in English, one row per
   finding, with the state the lane measured.
3. Recount by state and severity, and replace the table above with the recount.
4. Only then update the directive's summary, and only with the recount.

Step 1 is the whole of M0 and it is not started. This file exists so that the gap is
visible in the tree rather than in a comment on a pull request.

## Blocked: one record per package

Directive 15.3 item 1 opens one GitHub record per package, with the card's English
body, and WP-04 job 5 repeats it. Measured:

```
$ gh issue list --limit 5
the 'lubothebook/budlum' repository has disabled issues
```

The step cannot be done in this repository. `docs/work/PACKAGES.md` is therefore the
only package record that exists, and it says so in its own closing section. This is
recorded here as blocked rather than silently skipped, which is what directive 15.1
item 9 asks an agent to do with a blocked step.

## What this file does not claim

1. It does not claim that any finding is closed, open or invalid.
2. It does not claim that any lane is complete.
3. It does not replace the four lane files, which do not exist.
