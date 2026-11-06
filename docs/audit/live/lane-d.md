# Lane D live verification (WP-04)

## Live base and scope

- Agent: Arena coding agent, lane D.
- Date: 2026-11-06 (UTC).
- Branch: `arena/d8c6419d-budlum` (fixed by the session).
- Local start and live GitHub `main`: `cccf1da1f4bcfe97503a3a00cfba24b172b49b31`.
- Delivery: 1/N. This is not the final WP-04 consolidation PR.
- Locks: this file and `src/tests/audit_lane_d.rs`.
- Shared append: `src/tests/mod.rs`, to register the tests in `cargo test --lib`.

The directive's WP-04 scope includes WP-05, WP-11, WP-36 through WP-43,
WP-46, WP-61 and the related archive records. This first delivery records
an initial subset, not a completed audit of that scope. No row is closed.
"Fix trace" below means inspected source, not a green test result or the
formal Verified status (which requires red reproduction output).

## Initial evidence

| ID | Severity proposal | English title | Live status | Production evidence | Permanent test evidence | Closing package |
|---|---|---|---|---|---|---|
| BLG-004 | Medium | Overwriting a key preserves broad file permissions | Open; fix trace, execution pending | `src/crypto/primitives.rs`, `write_key_file`, `KeyPair::save`: sibling file uses create_new, mode 0600, sync_all and rename | `audit_lane_d_blg_004_key_overwrite_is_private_and_roundtrips`; `audit_lane_d_blg_004_failed_save_preserves_existing_key` | WP-61 |
| BLG-009 | Medium | PQ verification lacks mandatory FIPS context and explicit scheme | Open; fix trace, execution pending | `src/crypto/pq.rs`, `verify`; explicit SchemeId and context checks | `regression_ops_crypto::pq_verify_requires_context_and_explicit_scheme` | WP-61 |
| BLG-010 | Medium | PKCS#11 label is applied after binding the key | Open; fix trace, execution pending | `src/crypto/pkcs11.rs`, connect and extract_ed25519_public_key take key_label before binding | `regression_ops_crypto::pkcs11_label_is_applied_before_the_key_is_bound` | WP-61 |
| BLG-011 | Medium | Service omits RPC credentials and enables core dumps | Open; fix trace, execution pending | `ops/budlum-core.service`: RPC environment file and key variable, LimitCORE=0 | `regression_ops_crypto::service_unit_sets_rpc_key_and_closes_core_dumps` | WP-41 |
| BLG-012 | High | Coverage ratchet reads the first file and accepts NaN baseline | Open; fix trace, execution pending | `xtask/gates/src/gates/coverage.rs`, parse_baseline and percent_from_json: finite baseline and data[0].totals.lines.percent | `regression_ops_crypto::coverage_gate_reads_the_total_and_refuses_nan`; gate unit test `the_total_is_read_not_the_first_file` | WP-42 |
| BLG-013 | Medium | Prepush uses an invalid all-features composition | Open; fix trace, execution pending | `.github/workflows/ci.yml`, all-features build canary; current source has no feature-exclusion compile_error macro | `regression_ops_crypto::all_features_is_a_buildable_composition` | WP-42 |
| BLG-014 | Medium | Backup drill ignores check-db exit status | Open; fix trace, execution pending | `xtask/tools/src/backup_drill.rs`, explicit check.status.success and status.success checks | `regression_ops_crypto::backup_drill_checks_the_exit_status` | WP-42 |
| BLG-022 | Medium | Next-checkpoint query loops or overflows at large heights | Open; fix trace, execution pending | `src/light_client/mod.rs`, LightClient::next_checkpoint_height: checked_add and closed-form alignment | `audit_lane_d_blg_022_checkpoint_matches_bounded_reference`; `audit_lane_d_blg_022_checkpoint_handles_overflow_and_huge_intervals` | WP-11 |
| BLG-099 | High | API-key comparison self-comparison leaks key length after optimization | Open; functional refusal tests added, timing evidence pending | `src/rpc/server.rs`, constant_time_eq_str; no self-comparison in current implementation | `audit_lane_d_blg_099_api_key_comparison_refuses_every_single_byte_change`; functional results cannot establish constant-time behavior | WP-61 |
| BULGU-011 | S3 (inherited) | Wildcard CORS reflects request headers | Open; fix trace, execution pending | `src/rpc/server.rs`, cors_outcome and apply_cors_headers: literal wildcard, fixed allowed headers | Existing `cors_wildcard_does_not_reflect_headers` and `regression_ops_crypto::cors_does_not_reflect_request_headers` | WP-61 |
| BULGU-012 | S3 (inherited) | Serialization failure silently becomes null | Open; fix trace, execution pending | `src/rpc/server.rs`, explicit serialization error mapping | Existing `rpc_serialization_error_is_explicit` | WP-61 |

The analysis snapshot's unresolved wording does not prove these defects remain:
these rows already have fix traces in the actual base. Conversely, a source
marker or a test definition does not establish closure. Partial multi-location
findings remain open until every leg has evidence.

## Queue and overlap check

The open PR list and changed paths were read live before claiming this work:

| PR | Scope | Treatment |
|---|---|---|
| #8 | Codec register and dedup index | Do not touch storage or codec paths |
| #9 | WP-12 committee finality | Do not touch finality, validators or protocol paths |
| #11 | WP-06 persistence migration | Do not touch persistence or its storage callers |
| #12 | WP-01/02/03 live ledgers | Do not overwrite lane A/B/C files |
| #13 | WP-20 placement, custody and repair | Do not edit its gates or findings entries |
| #14 | WP-44 testnet feature closures | Do not edit feature closures or its package entries |
| #15 | WP-03 audit artifacts | Lane C overlaps #12; consolidation must resolve ownership before importing either |

WP-04 has no dependency for its initial lane audit. Its final consolidation
waits for WP-01/02/03 to merge. No such merge is present on the live main base.
This delivery does not duplicate their work and does not represent pending
PRs as merged packages. It does not take any dependent implementation package.

## Execution and process constraints

- No cargo, rustc or rustfmt executable is available locally. New Rust tests
  have not run. Run `cargo test --lib audit_lane_d` with the pinned toolchain.
- CI is not polled or awaited in this delivery, per the user's instruction.
  No CI run number or green verdict is claimed. WP-04's workflow-by-workflow
  baseline and runner memory evidence remain outstanding, not inferred from
  workflow labels or local sandbox memory.
- `.github/workflows/ci.yml` already runs `cargo test --lib`; the new module is
  registered there through `src/tests/mod.rs`, not left as an orphan file.
- GitHub reports that repository issues are disabled. The 64 package issues,
  CLAIM issue comment and in-progress label cannot be created. No repository
  settings are changed implicitly. The PR description carries the claim.
- The session permits only its fixed branch. No audit/repro-d or wp/04 branch
  is created. No deliberately failing reproduction test enters this PR.
- The external historical findings ledger is not supplied. The directive and
  current source are the available evidence; historical detail is not invented.
- No measurements, wire formats, protobuf tags, RPC names or legacy concept
  names change. The concept-name baseline is unchanged.

## Remaining WP-04 work

Audit the rest of lane D and archive rows; obtain actual execution evidence;
record the CI baseline when permitted; open package issues after issues are
enabled; consolidate all four lane ledgers, source-directive mappings and
status/severity totals after their merge. Only the final delivery writes the
combined LIVE_STATUS, FINDINGS and PACKAGES records. M0 is not complete.
