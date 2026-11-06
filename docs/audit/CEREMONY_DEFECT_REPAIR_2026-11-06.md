# WP-46 ceremony rehearsal: defect reproduction and repair

| Field | Value |
|---|---|
| Date | 2026-11-06 |
| Branch | `arena/0c480ae6-budlum` (PR #96) |
| Carried from | PR #92 (`arena/db4e6429-budlum`, WP-36/37/46, 1/N) and PR #94 (`arena/1bc4b5d3-budlum`, WP-04 review harness) |
| Finding | BLG-315 (Critical) |
| Repaired paths | `ops/rehearsal/genesis_rehearsal.sh`, `tests/review/rehearsal_ceremony_regressions.py`, `.github/workflows/ceremony.yml`, `.github/workflows/mobile.yml` |

## 1. The live situation

PR #92 delivered the WP-36 Android skeleton, the WP-37 device matrix and the
WP-46 rehearsal scaffolding as 42 new files. PR #94 then reproduced four
defects in #92's ceremony with an independent black-box harness, but could not
push the repair to #92's branch. This session carries #92's files onto its own
fixed branch and repairs them there. No PR was closed, merged or retargeted.

## 2. Red evidence, reproduced here

The original #92 script and template and the original #94 harness were copied
into a temporary checkout from their Git blobs and run:

```
$ python3 tests/review/harness.py /tmp/budlum_pr92_check
Ran 4 tests in 0.567s
FAILED (failures=4)
FAIL: test_empty_full_claims_are_not_validator_records -- invalid ceremony accepted
FAIL: test_duplicate_validator_records_do_not_form_a_committee
FAIL: test_record_filename_is_not_executed_as_python -- a record filename was executed as Python code
FAIL: test_private_key_material_is_not_published -- 'SENTINEL-PRIVATE-KEY' ... found in genesis
```

The script accepted `{"class": "Full"}` eight times, accepted eight identical
records, interpolated a record filename into `python3 -c` source (so the
filename executed), and copied every field of every record, including
`private_key`, into the published genesis.

## 3. Green evidence after the repair

```
$ python3 tests/review/rehearsal_ceremony_regressions.py .
Ran 10 tests in 0.285s
OK
```

The harness now has ten tests: the four original refusals, plus six new ones:
a valid ceremony publishes exactly the public projection, its digest matches
the bytes, the audit report lists eight distinct public digests, fewer than
eight Full records is refused, `Mobile` records do not count, a private field
on an otherwise valid record is refused, malformed JSON is refused, and a
duplicate `peer_id` is refused.

These are local Python/Bash runs, not Rust CI runs. No green CI run number is
claimed (directive 0.3 item 5). The harness is wired to PRs by
`.github/workflows/ceremony.yml`.

## 4. What the repair changes

| Rule | Before (#92) | After (this branch) |
|---|---|---|
| Class check | a JSON key equal to `Full` | `Full` plus all eight directive 7.3 public fields, with type checks |
| Identity | none | distinct `owner`, `peer_id` and canonical public-record digest |
| Publication | whole input record copied | a whitelist projection; any unknown or private-shaped key refuses |
| Filenames | interpolated into `python3 -c` source | read only through `pathlib.Path.glob`, never into source |
| Output | created before validation | published atomically only after every check passed |
| Audit | none | `rehearsal-ceremony-audit.json` with the SHA-256 digest and the public validator digests |

## 5. A second carried-over defect: unpinned actions (BLG-321)

`.github/workflows/mobile.yml` from #92 used `actions/checkout@v4`,
`actions/setup-java@v4`, `gradle/actions/setup-gradle@v4` and
`reactivecircus/android-emulator-runner@v2`. Directive 16.2 item 4 requires
actions pinned to a commit SHA. The carried workflow now uses the repository's
existing `actions/checkout` SHA, the peeled commit of the other three tags, and
`persist-credentials: false`. It also builds and tests the WP-37
`mobile/tools/log-analyzer` workspace, which #92 shipped without a CI job.

The tag SHAs were read from the upstream tag refs with `git ls-remote`; the
annotated tags use their peeled commit (`^{}`), not the tag object.

## 6. Evidence boundary

No Android build, emulator run, 24-hour service test, 72-hour rehearsal or
Rust compile was executed here. Those remain WP-36/WP-37/WP-46 obligations and
are recorded as such in `docs/work/PACKAGES.md`.
