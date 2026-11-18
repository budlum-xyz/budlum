# B-0051: the stale clippy-extra baseline blocks a real CI quality job

- Location: `.github/clippy-extra-baseline.txt:1` on `budlum-stack` source `df970fc98402e0d025b7832ebada47581f8174f6`. The first line is `8513`. The gate's stall check is `xtask/gates/src/gates/clippy_extra.rs:94-102`.
- Severity: low, verification availability and quality-policy drift. This is not a new compiler error or evidence of a security exploit.
- Faulty configuration: `8513` remains as the allowed warning count after the current measured count has dropped substantially.
- Actual CI reproduction: [CI run 1845, run id 44292586425, Budlum Core quality job 134761302116](https://github.com/budlum-xyz/budlum/actions/runs/44292586425/job/134761302116), source `df970fc98402e0d025b7832ebada47581f8174f6`. The all-features build canary, documentation, normal Clippy and formatting steps pass; the pedantic/nursery ratchet fails. The relevant CI output is:

  ```text
  FAIL [clippy-extra]: clippy-extra: 7223 | baseline: 8513
  FAIL: the baseline is 1290 above the measured count, more than the 10% a ratchet may be off by.
  Lower `.github/clippy-extra-baseline.txt` to 7223
  ```

- Why it is wrong: the gate deliberately rejects both new warnings and a baseline that becomes more than ten percent stale. An unchanged high baseline would otherwise silently permit 1,290 additional warnings. The gate is working as designed; its threshold must not be disabled or loosened to make CI pass.
- Impact: the quality job is red, and an all-green merge or readiness claim is invalid even though normal Clippy passes. A local `clippy -D warnings` result does not exercise this extra ratchet.
- Repair: preserve the gate and its stall limit. Lower the baseline only using a complete authoritative CI measurement for the exact branch/source being repaired, retain the source SHA/run reference in the baseline justification, and rerun the gate plus the complete quality job. Do not apply an upper-branch count to Garden, main or the audit head without their own measured run. Respect the Garden additive-path restriction; this record does not authorize an unrelated baseline edit on Garden.
- Local gate check: the existing `budlum-gates clippy-extra --self-test` passes, including over-baseline and stale-baseline rejection. Its output is not a replacement for the CI measurement.
- Evidence: job metadata and full downloaded job log are retained locally at `/home/user/validation/github/stack-core-quality/{job.json,job.log}`. The paginated GitHub snapshot that first observes the failed check is `/home/user/validation/github/final-network-paginated/snapshot.json.gz`.
- Status: repair pushed 2026-11-18, commit `f36491d2` on `budlum-stack` (PR #183): `.github/clippy-extra-baseline.txt` first line 8513 -> 7223 with the CI measurement recorded (run 44292586425, job 134761302116, source `df970fc98402e0d025b7832ebada47581f8174f6`). No gate logic, threshold, license, suppression, or other branch baseline was changed. Successful replacement CI run is still outstanding: at push time the PR has 140 check runs, all newer ones queued (runner starvation), so the gate has not yet been observed green on `f36491d2`. Garden, main and the aggregation heads keep their own baselines until each has its own complete CI measurement.
