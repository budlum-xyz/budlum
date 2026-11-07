# Testnet rehearsal results

This file is the record the README measurement table reads. It carries one
section per rehearsal run: the hardware, the software version including the
commit, the date, and the measured rows. A row that no run produced is not
written here.

## Recorded runs

None. No rehearsal has run yet, so this file has no measurement to report and
the README table reads `not measured yet` in every row.

## What a run must record

The rehearsal is the input of the drills T-1 to T-7 and of the launch gate rows
TLG-07 to TLG-10 and TLG-18. A run is recorded here only when it carries:

| Field | Content |
| --- | --- |
| Commit | The commit under test, in full. |
| Binary | The node and worker binaries, with their build identifiers. |
| Hosts | Per host: CPU, RAM, disk, kernel and cloud region. |
| Duration | Start and end in UTC. |
| Validators | Full validators, Android phones, simulated Mobile validators. |
| Finality | Median and p95 finality delay. |
| T-1 | All Mobile validators left at once: the finality delay change and the number of objects lost. |
| T-2 | 10 percent of Full validators left at once: the extra delay in checkpoints. |
| T-3, T-4, T-5, T-7 | The drill result and the recorded evidence path. |
| Phone budget | Battery and data per day on the default policy. |
| Connectivity | Direct, hole punched and relayed ratios. |
| Redundancy | The achieved storage redundancy. |
| Full validator cost | CPU, RAM and daily disk growth. |

## Status

- Drills recorded: none.
- Measurement documents this run must feed: this file, `docs/EXECUTION_LIMITS.md`
  (conformance), `docs/MOBILE_DEVICE_MATRIX.md` (phones, not in the tree yet)
  and `docs/audit/TLG_REPORT.md` (the gate rows).
