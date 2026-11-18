# B-0048: `Account::auth_program_hash` cannot be read back after it is written

- **Location:** `src/core/account.rs:179` on `agg/phase-5-pcs-claims` head `f45cd034d486ce2643b49de291d393663c862a0a` (PR #198). The field was introduced by `c023981a` (Phase 4, `Account.auth_program_hash`) and reaches `budlum-stack` only through the aggregation stack.
- **Severity:** high. Every account row written by `Storage::commit_durable_batch` and `Storage::save_account` fails to load once the build carries Phase 4. That is a startup-path failure on any node that upgrades, which makes it a consensus-critical storage break rather than a cosmetic one.
- **Status:** fixed in code in `834ee878` on `agg/phase-5-pcs-claims`. Four targeted tests pass on the fixed tree and two of them fail again when the defect is restored, so the fix is measured. A green full CI run on a head that contains `834ee878` is still outstanding, so the finding is fixed and not yet CI-proven.

## What the attribute does

`Account` is persisted with `bincode` through `encode` (`src/persistence/db.rs:144`) and read back through `decode` (`:161`). Both calls are bincode only. The Phase 4 field carried:

```rust
// src/core/account.rs:179-180, before the fix
#[serde(default, skip_serializing_if = "Option::is_none")]
pub auth_program_hash: Option<[u8; 32]>,
```

`bincode` is not self describing. It writes fields positionally and carries no field names, so a field that is skipped on write is still expected on read. `Option<T>` on the wire is one tag byte plus the payload, and that tag byte is exactly what `Option::None` contributes to the record.

## Reproduction

A minimal program with the same field shape, built from `bincode 1.3` in this workspace (`/home/user/bcheck`):

```
skipped-none len=8 [7, 0, 0, 0, 0, 0, 0, 0]
skipped-none roundtrip FAIL: io error: unexpected end of file
kept-none    len=9 [7, 0, 0, 0, 0, 0, 0, 0, 0]
kept-none    roundtrip OK: Kept { a: 7, opt: None }
```

The account record with the attribute is 8 bytes where the decoder needs 9, which is the error CI reports.

## Observed failure

Three check runs on `f45cd034` fail on one and the same test, and the panicking line is the account load:

```
thread 'persistence::db::tests::test_durable_commit_batch_and_recovery' panicked at src/persistence/db.rs:3008:52:
called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidData, error: "io error: unexpected end of file" }
```

- `Budlum Core library test` (job `134647646918`): `6196 passed; 1 failed`, `finished in 2804.69s`
- `Fork-Choice Invariants` (job `134647647016`): same test, same line, `0 passed; 1 failed`
- `Network Hardening` (job `134647646941`): same test, same line, `0 passed; 1 failed`
- `Coverage (nextest + llvm-cov, ratchet)` (job `134647647057`): same test, then `Cancelling due to test failure: 3 tests still running`

Line 3008 of that file is `storage.load_all_accounts().unwrap()`, reached through `load_all_accounts` (`:1895-1910`) and `decode::<Account>` (`:1906`). The write side is `commit_durable_batch` (`:747-751`), which is where the short row is produced.

## The fix

The attribute is removed and the field is serialized unconditionally, which is what every other `Option` on a bincode-persisted consensus type in the tree already does. The source comment records why the attribute must not come back.

Three tests pin the property:

- `persistence::db::tests::a_program_free_account_survives_the_durable_encode_decode_pair` writes `Account::with_balance` through `save_account` and reads it back through `load_all_accounts`.
- `persistence::db::tests::a_program_authorized_account_survives_the_durable_encode_decode_pair` does the same for `Account::with_auth_program`, so the fix cannot regress into "drop the field".
- `chain::snapshot::tests::a_written_optional_substate_changes_the_snapshot_digest` guards the digest side, described below.

All four targeted runs on the fixed tree:

```
test_durable_commit_batch_and_recovery ... ok
a_program_free_account_survives_the_durable_encode_decode_pair ... ok
a_program_authorized_account_survives_the_durable_encode_decode_pair ... ok
a_written_optional_substate_changes_the_snapshot_digest ... ok
```

Negative control: with only the serde attribute restored, `cargo test --lib --no-run` succeeds and then `a_program_free_account_survives_the_durable_encode_decode_pair` and `test_durable_commit_batch_and_recovery` both report `FAILED. 0 passed; 1 failed`. The tests measure the root cause and not the symptom.

## Scope check

The leaf hash is unaffected. `hash_account_leaf` (`src/core/account.rs:5567-5584`) hashes `pubkey`, `balance`, `nonce`, `frac_attos` when non-zero, and the program hash behind `TAG_ACCOUNT_AUTH_PROGRAM` only when it is set. Removing the serde attribute changes no committed root.

Seven `skip_serializing_if` attributes were in `src/` at `f45cd034`; one is removed by this fix and six remain. The remaining six and their readers:

- `src/chain/genesis.rs:239,251` (`anchor_ledger`, `reward_pool`). Genesis is read and written as JSON (`serde_json::from_str` at `:1892`, `:2112`). JSON is self describing, so omission is harmless and no bincode digest covers genesis.
- `src/settlement/registries.rs:67,73` (`quantum`, `object_layer`). These are part of `SettlementRegistries`, which `StateSnapshotV2::calculate_digest` hashes at `src/chain/snapshot.rs:1235` with `hash_opt_serializable`, and that helper is `bincode::serialize`. Both attributes are safe only because `SettlementRegistries::root` (`src/settlement/registries.rs`, the `fields` fold) includes each sub-state only when it is non-empty and each carries an `is_empty` guard. The new digest test pins that invariant.
- `src/settlement/proof_market.rs:758,762` (`retired_tasks_by_creator`, `last_closed_epoch`). Reached by the same digest at `src/chain/snapshot.rs:1191`. The state root (`src/settlement/proof_market.rs`, the `BDLM_SETTLEMENT_PROOF_MARKET_RETIRED_BY_CREATOR_V1` block) folds both, and both are omitted only at their default, so the fold stays injective over the values that matter.

## The snapshot digest hazard in the same family

`StateSnapshotV2::calculate_digest` (`src/chain/snapshot.rs:1040-1256`) folds optional sub-states through `hash_serializable` (`:923-929`), which is `bincode::serialize` into a SHA3 hasher. A `skip_serializing_if` on a field reached that way removes the field from the preimage, and two chains that differ only in that field then compute the same digest. `a_written_optional_substate_changes_the_snapshot_digest` pins the property for the settlement registries: a registry that has recorded its first quantum-canary commit must not digest equal to one that has recorded none. Any future attribute added on a field reachable from `calculate_digest` fails that test the day it is added.

## Why the attribute is wrong for this codebase at all

The tree holds `bincode` at 1.x deliberately (`Cargo.toml`, the comment above the dependency). A format that is not self describing cannot express an omitted field: skipping on write means the reader expects a byte that is not there. The attribute is only correct where the reader is self describing, which here means JSON, and JSON is used for genesis and for the on-disk snapshot file, not for the durable row a node reads at startup.
