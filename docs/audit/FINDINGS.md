# Findings ledger

The single findings ledger of the directive (section 14). The register of
BLG-001 to BLG-267 is written in the directive itself; this file carries the
findings found after it, from BLG-268 on, and the closure record of every
finding whose fix is carried or merged.

## Rules

1. An identity (`BLG-NNN`) is never reused and never renumbered.
2. Severity is Critical, High, Medium or Low.
3. Status is `open`, `confirmed` (open and reproduced), `closed` (the fix
   merged), `closed by removal` (the code is gone) or `invalid` (the condition
   no longer exists, with evidence).
4. Live verification of BLG-001 to BLG-267 belongs to WP-01 to WP-04, and its
   output is `docs/audit/LIVE_STATUS.md`.
5. Closure protocol: the required test is written and covers the failure mode,
   the fix makes it green, and the record carries the pull request / commit and
   CI run.
6. A new finding is written here with the next free identity, and the row names
   the package that closes it.

## New findings

| Identity | Severity | Location | Finding | Evidence | Closing package |
|---|---|---|---|---|---|
| BLG-268 | High | `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs`, `src/chain/chain_actor.rs` | The gate refuses an unmodified copy of the tree: `chain_actor.rs` calls `required_fee` on `self.blockchain.state`, and the gate reads that as a consensus-state write outside block execution. | CI 42050659038, job 127488353707 | WP-17 |
| BLG-269 | Medium | `xtask/gates/src/gates/indexing_is_not_new.rs` | Two files under `src/` are outside the recorded index at run time, so the ratchet cannot be satisfied by the tree it guards. | CI 42050659038 | WP-42 |
| BLG-270 | Medium | `xtask/gates/src/gates/dead_pub_api.rs`, `.github/dead-pub-api-baseline.txt` | The dead public API count is 182 against a baseline of 173. | CI 42050659038 | WP-42 |
| BLG-271 | Medium | `xtask/gates/src/gates/guards_reachable.rs` | Five guards are unwired against a baseline of three. | CI 42050659038 | WP-42 |
| BLG-272 | High | `src/tests/bud3_door.rs`, `src/storage/bud3/bof1.rs`, `crates/bud-codec/src/lib.rs` | `cargo fmt --check` reports three diffs on `main` (`cccf1da`). | CI 42050659038, job 127488354480 | WP-10 |
| BLG-273 | Critical | `Cargo.toml` feature matrix, `src/` test suite | Core feature matrix `--no-default-features --features "pq-ml-dsa wallet-ml-dsa"` and library test suite fail on `main`. | CI 42050659038, jobs 127488354234 and 127488354235 | WP-01 |
| BLG-274 | Medium | `src/network/`, `.github/workflows/ci.yml` | Network hardening test step fails with exit 101 on `main`. | CI 42050659038, job 127488354561 | WP-15 |
| BLG-275 | Low | `deny.toml`, `.github/workflows/ci.yml` | Cargo deny jobs (root and fuzz) fail on `main`. | CI 42050659038, jobs 127488354574 and 127488354282 | WP-42 |
| BLG-276 | High | `crates/uel-abi/src/lib.rs`, `crates/uel-abi/src/transport.rs`, `crates/uel-abi/src/mock.rs`, `crates/uel-abi/tests/transport.rs` | `crates/uel-abi` unconditionally compiled `std::os::unix::net::UnixStream` in `transport.rs`, breaking `Cross-Platform Digest (windows-latest)` whenever `budlum-uel-abi` is built on Windows, and `panic_digest` / `panic_message` lived inside the Unix-only module rather than `host.rs`. | `crates/uel-abi/src/transport.rs:24` (`use std::os::unix::net::UnixStream;`); closed in PR `#36` (`aa7b8c5`, `47d4e05`) | WP-26 |
| BLG-277 | High | `src/execution/coordinator/foreign/mod.rs` | `ForeignLaneState::process_foreign_tx` and `apply_adopt_tx` mutated `accounts`, `next_cosmos_account_number`, or `next_nonce` before completing nonce, `account_number`, and balance-transfer checks (`G-4` violation). | `docs/audit/REVIEW_2.md`; closed in PR `#36` | WP-48 |
| BLG-278 | Critical | `src/execution/coordinator/foreign/mod.rs` | `QuantumAlertLevel::Level2Restricted` trusted unbound outer `direct_native_pq_recipient` metadata without verifying `PostQuantum` target class and signed payload alias match (`Y-7`, `K-3`, `R-36`). | `docs/audit/REVIEW_2.md`; closed in PR `#36` | WP-48 |
| BLG-279 | Medium | `src/execution/coordinator/state.rs`, `src/execution/coordinator/foreign/mod.rs` | Foreign alias collision checks covered only EVM, and `seen_solana_signatures` did not evict signatures when expired blockhashes left the 150-block window (`R-12`). | `docs/audit/REVIEW_2.md`; closed in PR `#36` | WP-48 |
| BLG-280 | High | `src/execution/coordinator/universal_call.rs`, `src/execution/coordinator/wasm_ee.rs` | Non-static `0x...B001` `call(...)` and `BudlumMsg::UniversalCall` accepted payloads prefixed with reserved `BDLM_UCALL_STATIC_V1`, causing static-mode confusion and 20-byte truncation. | `docs/audit/REVIEW_2.md`; closed in PR `#36` | WP-48 |
| BLG-281 | Medium | `src/validators/mod.rs:556`, `src/core/account.rs:2758` | `request_operator_rotation` and `ValidatorTx::Register` check active `operator_key` uniqueness but not `pending_operator_key` queued in the same epoch (`R-25` lock held by PR `#70`). | `docs/audit/REVIEW_2.md` | WP-13 |

## Closure record (WP-09, WP-26..WP-33, PR #36)

| Identity | Status | Location | Verification test / gate | Pull request |
|---|---|---|---|---|
| BLG-088 | closed (in review, PR #36) | `crates/uel-abi/src/transport.rs`, `crates/uel-abi/tests/transport.rs` | `handshake_echoes_request_id_and_rejects_mismatch` | PR `#36` |
| BLG-039 | closed (in review, PR #36) | `src/execution/proof_verifier.rs`, `src/execution/budzero_ee/mod.rs` | `blg_039_and_blg_142_verifier_dos_bounds_and_optional_proof_market` | PR `#36` |
| BLG-142 | closed (in review, PR #36) | `src/execution/budzero_ee/mod.rs` | `blg_039_and_blg_142_verifier_dos_bounds_and_optional_proof_market` | PR `#36` |
| BLG-223 (opcode leg) | closed on testnet (in review, PR #36) | `src/execution/budzero_ee/mod.rs`, `src/execution/zkvm.rs` | `verify_merkle_is_closed_on_testnet` | PR `#36` |
| BLG-226 | closed on testnet (in review, PR #36) | `src/execution/budzero_ee/mod.rs`, `src/execution/zkvm.rs` | `verify_inference_is_closed_on_testnet` | PR `#36` |
| BLG-230 (execution leg) | closed (in review, PR #36) | `src/execution/zkvm.rs` (`address_to_four_words`), `src/execution/budzero_ee/mod.rs` | `budzero_sender_is_four_words` | PR `#36` |
| BLG-248 | closed (in review, PR #36) | `src/execution/coordinator/mod.rs` (`StatefulBudZeroEe`), `src/execution/coordinator/state.rs` | `budzero_stateful_storage_persists_across_blocks`, `budzero_ee_stateful_program_persists` | PR `#36` |
| BLG-250 | closed (in review, PR #36) | `execution/Cargo.toml`, `src/execution/coordinator/worker.rs`, `xtask/gates/src/gates/ee_workers_build_with_unwind.rs` | `uel_worker_panic_yields_fault_receipt`, `uel_worker_death_does_not_commit`, gate `ee-workers-build-with-unwind` | PR `#36` |
| BLG-256 | closed (in review, PR #36) | `src/core/account.rs`, `xtask/gates/src/gates/economy_invariants.rs` | `frac_attos_stays_below_1e12`, `uel_bud_conservation`, gate `economy-invariants` | PR `#36` |
| BLG-260 | closed (in review, PR #36) | `src/execution/coordinator/overlay.rs` (`BlockReadCache`, `TxOverlay`), `docs/EXECUTION.md` | `coordinator_overlay_rolls_back_frame`, `execution_root_binds_every_namespace`, `uel_cross_arch_roots_equal` | PR `#36` |
| BLG-267 | closed (in review, PR #36) | `src/execution/coordinator/foreign/`, `docs/pq/classical_allowlist.toml`, `xtask/gates/src/gates/classical_crypto_is_paired.rs` | `foreign_account_cannot_touch_pq_holding`, `emergency_alert_suspends_foreign_keeps_adopt`, gate `classical-crypto-is-paired` | PR `#36` |
| BLG-276 | closed (in review, PR #36) | `crates/uel-abi/src/{lib,host,mock,transport}.rs`, `crates/uel-abi/tests/transport.rs` | `Cross-Platform Digest (windows-latest)` + `crates/uel-abi` test suite | PR `#36` |
| BLG-277 | closed (in review, PR #36) | `src/execution/coordinator/foreign/mod.rs` | `review_2_refused_foreign_txs_never_mutate_state_blg_277` | PR `#36` |
| BLG-278 | closed (in review, PR #36) | `src/execution/coordinator/foreign/mod.rs` | `review_2_quantum_alert_level2_spoofed_recipient_refused_blg_278` | PR `#36` |
| BLG-279 | closed (in review, PR #36) | `src/execution/coordinator/{state.rs,foreign/mod.rs}` | `review_2_cross_ee_alias_collision_and_bounded_solana_window_blg_279` | PR `#36` |
| BLG-280 | closed (in review, PR #36) | `src/execution/coordinator/{universal_call.rs,wasm_ee.rs}` | `review_2_static_prefix_spoofing_refused_blg_280` | PR `#36` |
| BLG-064 | closed (in review, PR #36) | `src/data_market/mod.rs`, `src/rpc/{api,method_class}.rs` | `data_market_sale_uses_grant` | PR `#36` |
| BLG-065 | closed (in review, PR #36) | `src/socialfi/nft_folders.rs` | `socialfi_nft_burn_needs_owner` | PR `#36` |
| BLG-109 | closed (in review, PR #36) | `src/socialfi/nft_folders.rs` | `socialfi_nft_burn_needs_owner` | PR `#36` |
| BLG-261 | closed (in review, PR #36) | `src/education_domain/mod.rs` | `education_domain_registers_object` | PR `#36` |
| BLG-262 | closed (in review, PR #36) | `src/wallet/identity_profile.rs`, `src/explorer_evidence/mod.rs`, `src/storage/content_gateway.rs` | `gateway_tree_is_gone` | PR `#36` |
| BLG-268 | closed (in review, PR #36) | `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs` | `no-out-of-block-consensus-writes` (`required_fee` read classification) | PR `#36` |
| BLG-269 | closed (in review, PR #36) | `src/bin/support/http.rs`, `src/storage/bud3/dedup_index.rs` | `indexing-is-not-new` | PR `#36` |
| BLG-270 | closed (in review, PR #36) | `src/storage/bud3/view.rs`, `.github/dead-pub-api-baseline.txt` | `dead-public-api-is-ratcheted` (`165` = baseline `165`) | PR `#36` |
| BLG-271 | closed (in review, PR #36) | `src/storage/bud3/view.rs` (`admit_lifetime`, `admit_mobile_quota`) | `guards-are-reachable` (`3` = baseline `3`) | PR `#36` |
| BLG-272 | closed (in review, PR #36) | `crates/bud-codec/src/lib.rs`, `src/storage/bud3/bof1.rs`, `src/tests/bud3_door.rs` | `cargo fmt --all -- --check` | PR `#36` |

## RPC and cryptography closure record
WP-61 (lane D, RPC and crypto hardening) locks the thirteen findings of its card.
Nine were already fixed in the analysed snapshot, so directive section 14.1 item 7
applies: the finding is closed by the test that stays in the tree, and the note
says `pre-fixed`. The state below is written against `origin/main`
`cccf1da1f4bcfe97503a3a00cfba24b172b49b31`. Closure takes effect when the pull
request merges; the merge commit and the CI run number are written into these rows
by that merge, and no row below claims one.

The branch carrying these rows is `arena/e55d486b-budlum`, pull request #41, head
commit recorded in `docs/work/PACKAGES.md`.

| Identity | Severity | Status | Lock | Note |
|---|---|---|---|---|
| BLG-004 | Medium | pre-fixed, locked here | `blg_004_validator_key_save_resets_a_wide_mode` (`src/crypto/primitives.rs`) | `write_key_file` creates a sibling with `create_new` and mode `0o600`, syncs, then renames, so the mode of the replaced file is never kept. The snapshot held the rule for `KeyPair`; the validator key file, which also carries the BLS and PQ secrets, is now driven by the same assertion. |
| BLG-009 | Medium | pre-fixed, locked here | `blg_009_an_unregistered_context_or_scheme_is_refused_before_the_keys` (`src/crypto/pq.rs`) | `check_context` refuses an empty, an over-long and an unregistered context, and `verify` takes the scheme identifier as an argument instead of inferring it from a key length. |
| BLG-010 | Medium | pre-fixed, locked here | `blg_010_a_slot_with_more_than_one_key_is_refused_not_guessed` (`src/crypto/pkcs11.rs`) | `connect` binds `key_label` before the key is read, and `require_single_key` refuses a slot holding more than one Ed25519 key. |
| BLG-029 | High | pre-fixed, locked here | `blg_029_a_forged_forwarded_for_entry_buys_no_fresh_quota` (`src/rpc/server.rs`) | `extract_client_ip` answers with the rightmost `X-Forwarded-For` entry, the one the trusted proxy appended, and the quota table is keyed on it, so a forged left entry neither escalates privileges nor resets the window. |
| BLG-030 | Critical | pre-fixed for the grant rows, locked here | `blg_030_view_grant_writes_refuse_and_name_their_transaction_door` (`src/rpc/tests.rs`) | The chain actor answers `IssueViewGrant`, `RevokeViewGrant` and `SocialDelete` with the transaction door and mutates nothing; the read side still answers, so a refusal is not an outage. The faucet half belongs to WP-41. |
| BLG-032 | Medium | pre-fixed, already locked | `prepare_templates_carry_valid_nonce_and_fee` (`src/rpc/server.rs`) | `finish_template` overwrites the nonce with the sender's next nonce and the fee with `required_fee`, and sets `max_fee` to the same value, for every `Prepare` template. |
| BLG-099 | High | pre-fixed, locked here | `blg_099_the_api_key_compare_never_early_returns_on_length` (`src/rpc/server.rs`) | The compare walks the expected key, folds the length difference into the accumulator and clamps the candidate index, so a length mismatch costs the same work as a byte mismatch and no same-buffer self-comparison remains. |
| BLG-150 | Critical | signer feet pre-fixed, locked here; the nullifier feet are open | `blg_150_block_prevote_and_precommit_signatures_are_not_interchangeable` (`src/crypto/signer.rs`) | `sign_prevote` and `sign_precommit` hash their own `BDLM_*_ED25519_V1` tag and each verifies over its own domain. The `nullifier == 0` feet live in `src/privacy/` and `src/relayer/`, which are outside the WP-61 lock set, so they stay open for their owning packages. |
| BLG-192 | High | pre-fixed, locked here | `blg_192_estimate_gas_carries_the_proportional_cut` (`src/rpc/tests.rs`) | `estimate_gas` answers `tx.fee.max(required_fee)`, and `required_fee` adds the proportional cut of `required_transfer_fee` to the floor. |
| BLG-200 | Critical | key material half pre-fixed, locked here; the aggregator and RLP feet are open | `blg_200_zero_and_identity_bls_material_is_refused` (`src/crypto/primitives.rs`) | `from_seed` refuses a seed that reduces to the zero scalar; `from_bytes` demands an exact length, refuses a zero secret and re-derives the public half, so the identity encoding is refused by the pairing check and not by a failed decode. The `FinalityAggregator` foot is in `src/chain/finality.rs`, held by WP-12, and the depth-unbounded RLP foot is in `src/cross_domain/evm/rlp.rs`, held by WP-44. |
| BULGU-011 | Medium | pre-fixed, already locked | `cors_wildcard_does_not_reflect_headers` (`src/rpc/server.rs`) | A `*` configuration answers with the literal `*`; the caller's `Origin` is never echoed, and no credentials grant is sent. |
| BULGU-012 | Low | pre-fixed, already locked | `rpc_serialization_error_is_explicit` (`src/rpc/server.rs`) | A value that cannot be encoded is a `-32603` error naming the field, not a `null` that reads as absent. |
| TEST-GAP-07 | High | ratchet delivered, gap recorded | `rpc_every_method_has_success_and_refusal_test` and `rpc_method_coverage_catches_an_injected_gap` (`src/rpc/method_class.rs`), `.github/rpc-method-coverage-baseline.txt` | 166 rows in the method table; 76 rows have the answer test and any required refusal test the rule can see, 90 rows carry 150 gap lines (down from 31 covered rows and 264 lines at the first commit of the branch). Removing the 20 legacy storage methods also removed their 15 recorded gaps. The remaining B.U.D. 3.0 custody read retains explicit answer/refusal coverage, and the three Object Layer reads added during integration retain their coverage without new baseline gaps. The file only shrinks, so the gap cannot grow and every delivery that adds RPC tests lowers it. Closing TEST-GAP-07 needs the remaining rows covered, in later WP-61 pull requests. |

---

## PR #88 mobile continuation findings

Append-only WP-11 continuation records from PR #88. Earlier ledger sections
proposed by other open PRs must be retained at integration. No finding below
is closed: local evidence is not a substitute for the pinned-toolchain CI run
required by the closing protocol.

A live scan of open PR bodies and changed audit documents found BLG-297 as
the highest allocated identifier before this slice reserved BLG-298 through
BLG-301 in PR #88. Existing open PRs reuse some earlier identifiers for
unrelated findings; references to those records include their originating PR.

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-298 | Medium | Open; locally corrected, CI evidence pending | `quota::fits` used saturating addition, so `fits(u64::MAX, 1, u64::MAX)` incorrectly succeeded. `mobile_quota_overflow_is_a_refusal` executed red after `224deb93d27634c28a7d53f79f72378ee12c4702`. Checked addition in `0886af28034319c96b63659b97a069e0b2af6e1e` makes it green. Policy's 64 GiB limit bounds the normal caller; the public quota helper and store still must reject arithmetic overflow. |
| BLG-299 | Medium | Open; locally corrected, CI evidence pending | Replaying one assignment allocated another local id and stored another copy. The replay regression executed red after `cf15d20726dd094eeae0fc4a339b6636fa697f7b`: expected a refusal, got `ShareRecord { id: ShareId(1), ... }`. `0886af28034319c96b63659b97a069e0b2af6e1e` refuses an existing `(object, segment, position)` or `(object, segment, ESI)` before mutation. Controls prove refusal preserves free space, quota, records and pending duties, while distinct symbols of one segment remain usable. |
| BLG-300 | Low | Open; locally corrected, CI evidence pending | `next_id.saturating_add(1)` could reuse the final local id and overwrite a record after exhaustion. `mobile_share_id_exhaustion_does_not_overwrite_a_record` executed red at `320adcfcc1877bd71fe2f6080466c4c30c30064c`. `0886af28034319c96b63659b97a069e0b2af6e1e` checks the increment before mutation and refuses exhaustion. The final control also preserves an existing record and the counter. This is a local-store boundary, not a chain share identifier. |
| BLG-301 | Medium | Open; locally corrected, CI evidence pending | The inherited mobile suite did not compile on stable Rust 1.99.0: `sig.as_slice()` on an existing byte slice triggered E0658. `cf15d20726dd094eeae0fc4a339b6636fa697f7b` removes the extra call. All-target Clippy also reported `manual_range_contains` in `Policy::set_quota`; `b041519678e16914823df3e3395d85f2537a6a1e` uses the equivalent inclusive-range check without a lint exemption. The local suite and strict Clippy now pass; Rust 1.97.1 and CI remain unverified. |

## Existing compatibility findings, not renumbered

- **PR #77 / BLG-289:** PR #85 scopes audit selection to the named object.
  `ef5b471cdb78300dfbd55ff2e6b1eaa6ce6a2935` retains that object in every
  returned `(object, proof)` pair. A two-object, identical-symbol regression
  executed red before the latter correction and is green afterward. This
  fixes the local selection/retention legs only. Shared types, signed wire
  round trips and node integration evidence remain outstanding.
- **PR #77 / BLG-288:** the mobile and PR #70 node presence preimages still
  differ. The G-5 vector is locked in `tests/vectors/presence/v1/` and checked
  by `presence_preimage_matches_shared_golden_vector`. No node source is
  silently changed to conceal the unresolved incompatibility.
- **PR #77 / BLG-290:** mobile release duties still carry process-local ids,
  while PR #45 proposes an object/optional-segment/quota-delta payload. The
  directive requires chain share identities and a new quota. These contracts
  must be reconciled before a valid mobile release transaction can be built.

Detailed red/green output, source/toolchain caveats, scope constraints and the
remaining integration blockers are in `MOBILE_CORE_REVIEW.md`. No performance
measurement, package completion or testnet readiness is claimed.

## PR #79 execution-budget finding

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-302 | High | Open; locally corrected, pinned Rust CI pending | `MAX_BLOCK_CONTRACT_GAS` was `64 * DEFAULT_CONTRACT_GAS_LIMIT` (64,000,000 BGU), exceeding the coordinator's 60,000,000-BGU hard block limit. PR #79 identified the defect as `BLG-280`, but that identity already belongs to the closed static-call prefix-confusion finding above, so it is not reused. The adapted correction makes the BudZero soft budget equal to `BLOCK_BGU_LIMIT`, adds compile-time cross-module assertions and locks the 60/61-call boundary plus the separate conformance runner in `src/tests/conformance_locks.rs`. Static source/table checks are not a Rust build or test run; closure requires the pinned toolchain and required CI evidence. |

## PR #80 worker-transport and economic-boundary findings

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-303 | High | Open; locally corrected, pinned Rust CI pending | Socket timeouts applied per syscall, reconnect handshakes received a fresh budget, and worker-side partial frames/host callbacks lacked a shared absolute deadline. `DeadlineIo` and `WorkerFrameIo` now use checked `Instant` deadlines across handshake, request, callback and response I/O. Five deadline regressions cover dribbled handshake/response frames, reconnect budget sharing, `Duration::MAX`, and unusable final responses; worker tests cover a started partial frame and an unanswered host callback. Idle connections may still wait before the first byte, and arbitrary host/engine code is not preempted. |
| BLG-304 | Critical | Open; locally corrected, pinned Rust CI pending | A syntactically framed but unusable final response could leave a poisoned client connection reusable, and a wrong host-response oneof arm or undefined error code could be mapped into an engine's deterministic revert. All three client methods now poison the connection on final decode/shape errors; `RemoteHost` validates operation/response discriminants and defined nonzero error codes and marks malformed callbacks broken. Regressions cover empty/wrong/malformed final responses, three malformed host replies, and the valid deterministic-refusal control. |
| BLG-305 | Medium | Open; locally corrected, pinned Rust CI pending | Execute/query panics had a catch boundary but `validate_deploy` did not. Worker deploy validation is now inside `catch_unwind`; because its response has no fault arm, a panic becomes a transport protocol error and closes the connection rather than inventing code info or an environment verdict. `PanicValidate` locks the boundary. No worker-process supervisor or restart result is claimed. |
| BLG-306 | High | Open; locally corrected, pinned Rust CI pending | Admission, pending-balance projection and execution duplicated divergent liquid-cost classifications; one executor gate also read raw rather than spendable balance. `checked_liquid_cost` is now shared by all four paths, fee-only doors reject no amount-plus-fee overflow, amount-bearing doors still reject overflow, and the current zero-liquid-cost `AiOperatorWithdraw` exit is preserved. Transfer/stake/delegation retain their specific arm errors. The shared vesting-gate assertion now expects its actual `vesting_locked` class, and the no-raw-gate source lock remains. |
| BLG-307 | High | Open; locally corrected, pinned Rust CI pending | `burn_from`, external-bond slash and timed-burn counters could saturate, recording less destruction than occurred and reopening supply headroom; slash reward/counter checks were not all preflighted. Exact checked counters now replace saturation, burn and slash preflights precede value movement, timed-burn counters are checked per increment, and no-producer fee totals use checked folding. Regressions use `catch_unwind` to assert that counter-overflow refusal leaves balances/escrow unchanged and to pin challenger-overflow refusal. Fail-stop panic semantics for an impossible counter overflow are retained, not presented as a `Result` API. |
| BLG-308 | Medium | Open; locally corrected, pinned gate/Rust CI pending | The live actor makes two read-only subregistry `query_json` calls that the consensus-write gate did not recognize. The gate now admits only `.bud3_registry.query_json(` and `.validator_directory.query_json(` with balanced-call termination, rejects direct/unknown/mutating queries and rejects a chained `.insert` after an allowed read. The required-fee exception remains exact; no broad `query_json` read exemption was added. |

## PR #77 continuation finding

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-309 | Medium | Open; locally corrected, pinned gate/Rust CI pending | The ABI integration-test files carry one crate-level allowance each for `clippy::unwrap_used` and `clippy::expect_used`, but the suppression gate had no corresponding budgets after the worker tests were integrated. PR #77's ten justified budget rows are now present for `frames.rs`, `transport.rs`, and the three worker-boundary test files. The allowances remain test-only and limited to one occurrence per lint/file; no production suppression or baseline widening was added. |

## PR #81 committee/finality findings

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-310 | Critical | Open; locally corrected, pinned Rust CI pending | The source's `seat_table_version != 0 && ...` guard allowed a legacy/base certificate to be recounted under a handed-over table, and its base table used the checkpoint height rather than version zero. Base derivation now consistently uses version zero in aggregators, snapshot verification and chain replay; committee epoch and exact table version are mandatory in both BLS and PQ-alarm verification. Regressions pin base-certificate refusal after a version change and seat-not-stake quorum behavior. |
| BLG-311 | Critical | Open; locally corrected, pinned Rust CI pending | Seat-table replay was capped by `finalized_height`, even though certificate verification changes that same output, and removing the cap without an archive guard would let a future round silently use the base table. Replay is now a pure function of checkpoint/epoch/snapshot plus canonical blocks (and the uninstalled candidate segment during pruned import), requires the certified checkpoint block, and never reads the finalized marker. The live round-start wrapper separately requires the lowest unfinalized checkpoint. Regressions derive the same handover before/after finality advances, refuse a next checkpoint whose block is absent, and refuse an archived future round whose predecessor is not final. |
| BLG-312 | High | Open; locally corrected, pinned Rust CI pending | The quantum-alarm PQ-only path derived a fresh base table rather than the handover-aware table used by the round. It now uses the same canonical replay and exact version check as the BLS path before counting verified PQ signer seats. The snapshot-only light-client fallback remains explicitly legacy stake/count because it lacks handover history; WP-12 does not claim that migration. |
| BLG-313 | Medium | Open; locally corrected, pinned Rust/gate CI pending | Current-tree integration exposed a duplicate `handover` module declaration, Rust-2024 `raw` identifiers reintroduced in merged conversions and one later bridge test, a later `FinalityCert` literal missing the new field, stale stake/count quorum assertions, and an unjustified committee-test suppression. These were repaired/adapted; all 26 changed Rust files parse, every relevant struct literal/call surface was scanned, and no new suppression budget was added. This is static evidence, not a compiler or test result. |

## PR #86 live-stream findings

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-314 | Medium | Open; locally corrected, pinned gate CI pending | The source added `BDLM_BUD3_LIVE_STREAM_V1` and `BDLM_BUD3_LIVE_END_V1` without registering either in the central domain-tag inventory. Both are now listed and used, and `DOMAIN_TAGS` remains sorted and unique with 439 entries. The source-wide inventory comparison still has the pre-existing `BDLM_LIVENESS_TRACKER_V4`, `BUDLUM_BUD3_ACCEPTANCE_TRIALS`, `BUDLUM_GIT_HASH` and stale `BDLM_LIVENESS_TRACKER_V3` differences; #86 adds no new difference and does not claim a global domain-tag gate pass. |
| BLG-315 | Medium | Open; locally corrected, pinned Rust CI pending | `push_segment` used saturating timestamp addition, which could collapse the fixed segment window at the upper `u64` boundary, and `verify_chain` returned a successful empty commitment list for an empty broadcast. The segment window now uses checked addition and returns `TimestampOverflow`; empty chains return `EmptyStream`. `bud3_live_stream_refuses_timestamp_overflow_and_empty_chain` locks both refusals, but no Rust test runner was available to execute it. |

## PR #137 alternate-stack live-broadcast findings

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-316 | High | Open; locally corrected, pinned Rust CI pending | The proposed `BroadcastDriver::next_symbol` used `self.symbol_for(frame).ok()?`, making an invalid ESI or RFC 6330 encoder refusal indistinguishable from normal plan exhaustion. Its global `MAX_ESI` plan could also exceed the lower per-encoder limit caused by source-block padding. The adapted driver returns errors from `next_symbol`/`drive`, makes coding failures sticky, checks the emitted counter and builds plans with each encoder's actual `max_esi`. `RatiolessPlan::with_repair_limits`, `bud3_live_broadcast_distinguishes_errors_from_exhaustion` and `ratioless_plan_honors_per_segment_repair_limits` cover the contract in source, but were not executed. |
| BLG-317 | High | Open; source gate rejected, fail-closed redesign required | The proposed `rust_syntax_is_parseable` gate returns silently on directory-read errors and skips metadata/read failures and every Rust file over 8 MiB. It can therefore report that every Rust file parsed without examining all of them. The gate was not integrated or registered. A replacement must fail closed on scan/read/size failures; the current 61 baseline parser-error files also prevent an honest whole-tree syntax-green claim. |
| BLG-318 | High | Open; placeholder workers rejected | The source NEAR, Plutus and TVM workers return `SHA-256(input)` as a successful contract call, and the UTXO worker returns the same digest without transaction verification. They also use fixed gas and ignore host-write results. These are not real execution environments and do not support the source's WP-50..53 completion claim. None of those workers or their workspace registration was integrated. |
| BLG-319 | Medium | Open; aggregate memory-budget work pending, no production wiring | Each of up to 1,024 subscribers can retain 4,096 cloned P0 symbols; at 2,911 payload bytes per symbol that is about 12.2 GB of queued payload before queue overhead, while the driver also snapshots all supplied segments. Per-viewer bounds are real but are not a practical aggregate byte budget. The integrated module is closed and unwired, and its documentation no longer claims viewer-independent sender memory. A shared-payload/aggregate-budget lifecycle is required before production wiring. |

## PR #91 shared mobile types, presence and FFI findings

The source reserved BLG-350 through BLG-360. The integrated follow-up uses
BLG-361 and BLG-362 for the additional defects found during current-tree
review. Corrections without their required executed test remain open.

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-350 | High | Open; layouts locally aligned, Rust/Kotlin CI pending | The node registry hashed raw concatenation, the Rust mobile core used length-prefixed SHA3-256, and the current Android WorkManager used SHA-256 over decimal strings. The class and signal now live in `budlum-types`; the registry calls the same `presence_message`, mobile core re-exports it, and Android builds the 65-byte length-prefixed SHA3-256 preimage. Node, shared-type, mobile-core and Android regressions pin the `26a5bec8...` vector. Kotlin remains an unwired adapter under BLG-357; no cross-language or BLS device run is claimed. |
| BLG-351 | High | Closed by removal in the integrated tree | The cited #70 `src/validators/presence.rs` and its mismatched `BTreeMap` key/value types were not integrated. Current `PresenceGossipInbox` stores `BTreeMap<(Address, u64), PresenceSignal>` and uses that tuple consistently. This records source-path removal, not a compiler result for the new shared-signal integration. |
| BLG-352 | Medium | Open; locally corrected, pinned tree gates pending | Turkish status words and typographic dashes introduced by the source package were not restored. The integrated review and changed files use English/ASCII prose; historical baseline files are not represented as globally clean. |
| BLG-353 | Medium | Closed by removal | `THE_BUDLUM_DIREKTIF.md` and `arena_claude.py`, the two paths named by the source finding, are absent from the integrated tree. No Turkish baseline entry was added for either path. Other historical baseline findings are outside this row. |
| BLG-354 | Medium | Open; locally corrected, pinned domain-gate CI pending | The domain scan omitted `mobile/`, leaving the Rust phone presence domains outside review. The scan and its unlisted-mobile-tag canary now include `mobile`; `BDLM_PRESENCE_V1`, `BDLM_PRESENCE_HINT_V1` and the current Android audit tag are registered. The known pre-existing global inventory differences are not claimed fixed. |
| BLG-355 | Low | Open; locally corrected, pinned Clippy CI pending | The crate-level `cfg_attr(test, allow(expect_used, unwrap_used))` suppression was removed. Tests use the existing test-body policy rather than widening the production lint exemption. |
| BLG-356 | Medium | Open; locally corrected, pinned Rust CI pending | The mobile core accepted an opportunistic quota above the consensus 8-GiB ceiling. `MobileCore::set_policy` now checks `ValidatorClass::max_custody_quota_bytes` before changing policy or releasing shares. Core and FFI boundary tests cover 8 GiB versus 8 GiB + 1, but were not executed here. |
| BLG-357 | Medium | Open; application migration and device evidence pending | Android and iOS still reimplement policy, storage and duty orchestration instead of consuming the generated Rust bindings. The integrated FFI does not submit duties or expose duty signing, and Android still has a separate audit/reward path. Only the presence digest was aligned; canonical custody, operator-duty signing, outbox submission and app migration remain incomplete. |
| BLG-358 | Medium | Open; locally corrected, documentation gate pending | Duplicate WP-37 analyzer work was reconciled to the current single `mobile/tools/log-analyzer` tree, but the device matrix still said suspension followed two missed presence epochs. It now states the 24/72/168-hour class thresholds and checked epoch conversion. No physical-device campaign result is claimed. |
| BLG-359 | Medium | Open; locally corrected, pinned tree-gate CI pending | Shipped Android Turkish strings were not covered by the localization exemption. Only `mobile/android/app/src/main/res/values-tr/` was added; acceptance and default-locale spill canaries cover the boundary in source but were not run. |
| BLG-360 | Low | Open; per-key Android AAD and generated-vault wiring pending | Current `KeystoreKeyVault` authenticates a purpose label, an improvement over the cited source, but not the operator label-plus-public-key context required by `KeyVault`. It also does not implement the generated `PlatformVault`. Ciphertext substitution therefore still lacks the second platform-cipher binding even though Rust re-derives and compares the public key. |
| BLG-361 | Medium | Open; locally corrected, pinned Rust CI pending | The shared class conversion treated zero slot duration and zero epoch length as one and saturated oversized epoch counts, inventing a consensus schedule. `hours_to_epochs` and both class-window wrappers now return `Result`, reject zero parameters and report overflow. Regression source covers rounding, zero hours, both zero-parameter errors and `u64` overflow. |
| BLG-362 | Medium | Open; locally corrected, pinned Rust CI pending | The FFI recovered poisoned core/outbox/listener mutexes on the unsupported assumption that every method was panic-atomic. A panic can invalidate that assumption, so lock acquisition is now fail-stop rather than continuing with possibly partial duties. `mobile_ffi_poisoned_lock_is_fail_stop` uses a child process to require termination; it has not been executed. |

## PR #86 segment-count follow-up

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-363 | Medium | Open; locally corrected, pinned Rust CI pending | `push_segment` and `finish` converted `segments.len()` with `as u64`, which could truncate a count on a wider-than-64-bit host and bind the wrong index/final segment count. Both now call the same `TryFrom`-based `checked_segment_count` helper and return `SegmentCountOverflow`. The regression uses that exact generic helper to accept `u64::MAX` and reject `u128::from(u64::MAX) + 1`; no Rust runner was available. BLG-315 remains a distinct timestamp/empty-chain finding. |

## Bloom-filter sizing follow-up

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-364 | Medium | Open; locally corrected, pinned Rust CI pending | Bloom-filter sizing used manual ceiling division, triggering the denied `manual_div_ceil` lint and adding an avoidable addition before division. The implementation now uses `bits.div_ceil(64)`; `the_bloom_filter_uses_div_ceil` pins the standard operation and rejects the former expression. No Rust runner was available. |

## Storage admission and repair-query review

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-365 | High | Closed by non-integration in the integrated tree | The proposed custody query cloned the complete registry and scanned every object to compute an unauthenticated what-if repair plan on each RPC call. That adds attacker-controlled CPU and allocation growth to a read endpoint. `RepairPlan`, its clone-based implementation, the custody-response field and their source locks were not integrated. The live custody query remains read-only without the additional full-registry clone; a bounded non-mutating plan would need a separately reviewed contract. |
| BLG-366 | Medium | Closed by non-integration; current gate evidence remains pending | The proposed admission report appended hard-coded self-check JSON to object reads rather than enforcing admission in the upload path. Actual lifetime and mobile-quota guards are already called by `upload.rs` and `registry.rs`, and the placement RPC derives values from the registered object and placement row. The parallel report module and response-field change were not integrated and do not close BLG-270 or BLG-271. |

## Directive-boundary metadata follow-up

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-367 | Medium | Open; locally corrected, pinned gate CI pending | The directive exclusion used `symlink_metadata(...).is_ok()`, so permission, `ENOTDIR` and other metadata errors were treated as absence instead of failing closed. `require_directive_absent` now accepts only `NotFound`, rejects every present file type and returns other metadata errors. A non-directory-root canary covers the error branch; the expected count is 67. No Rust runner was available. |

## Concept-pattern boundary follow-up

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-368 | Medium | Open; locally corrected, pinned concept-gate CI pending | The proposed unbounded `(?i)lubot` pattern also matches the repository owner name `lubothebook`, creating false naming matches and potentially inflating the ratchet with unrelated URLs and metadata. The current map uses `(?i)\blubot\b`; the source-wide pattern was not restored. No Rust gate runner was available. |

## Android and rehearsal integration review

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-369 | High | Open; locally corrected, pinned Android CI pending | The current app used `compileSdk = 36` with AGP 8.7.2 and Gradle 8.9, and its workflow had no Gradle assemble/unit-test job. AGP is now 8.9.1, both Gradle invocations use 8.11.1, and a pinned `android-gradle` job runs `assembleDebug` and `testDebugUnitTest`. `android_compile_sdk_uses_a_compatible_toolchain` locks the versions and commands. Neither Gradle nor an emulator ran locally. |
| BLG-370 | High | Closed by non-integration in the integrated tree | The proposed mobile workflow used movable action tags and an SDK-install fallback that converted installation failure into a warning. That would weaken both supply-chain pinning and build evidence. The current SHA-pinned actions were retained; the ported Gradle job has no `|| true` or warning-only SDK fallback. |
| BLG-371 | Medium | Closed by non-integration in the integrated tree | The parallel Android vault caught any `ProviderException` as though StrongBox were absent, potentially hiding unrelated provider failures while silently retrying with weaker backing. The current provider retries only for `StrongBoxUnavailableException`. The old duplicate app and vault were not integrated. |

## Solana response-integrity follow-up

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-372 | High | Open; locally corrected, pinned Rust CI pending | The standalone Solana adapter returned a successful signature after executing only on a cloned preview, returned a constant genesis hash and an always-empty program-account list, and used `{}` as the successful fallback for other unimplemented methods. It now serves only `getHealth`, `getVersion`, `getSlot` and `getBlockHeight`; the faucet keeps its explicit refusal, and the other 30 table entries are classified and returned as named `-32004` refusals. `solana_unimplemented_methods_never_return_invented_success` covers every refusal and the four preserved reads. No production Solana listener was wired by this correction, and no Rust runner was available. |

## RPC compatibility and Aptos pinning follow-ups

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-373 | High | Open; locally corrected, pinned Rust CI pending | The proposed Solana listener moved its security configuration before reading it, awaited a synchronous semaphore method, omitted remote-address admission, and did not await plain-HTTP serving. The integrated listener follows the primary/Aptos service pattern, filters only Solana callbacks, and applies remote-address admission, body/connection/batch limits and TLS. `solana_dedicated_listener_enforces_admission_and_method_filter` locks the behavior but has not run without a Rust toolchain. |
| BLG-374 | Medium | Open; locally corrected, pinned Rust CI pending | The proposed Solana reads ignored commitment configuration, and a backward processed head could leave a slot subscriber waiting indefinitely for the old height. `getSlot`/`getBlockHeight` now honor only processed/finalized, and a backward head closes the feed. The standalone adapter rejects configurations it cannot honor. Parser, catch-up, handler and admission tests were added; execution remains pending. |
| BLG-375 | Medium | Open in the source proposal; excluded from integration | The older Move worker used a custom unsigned envelope and inserted every fresh replay ID into an unbounded cache before returning its intentional worker-unavailable refusal. Wiring that shape would create unauthenticated admission and memory growth without executing a transaction. It was not integrated. The current signed Aptos `SignedTransaction` decoder, authenticator checks and bounded production path remain canonical. |
| BLG-376 | Low | Open; locally corrected, pinned Rust CI pending | The current pinned Aptos `Scheme` table omitted IDs 4, 5, 250, 251 and 255 and mislabeled the derived-object IDs. The table now matches all 12 IDs at aptos-core commit `81d89f428fe8e4b69d53b4916993e9a930afc37c`; the source vector and a regression comparison are included. `0xBD` was and remains disjoint, so this was not an active alias collision. |

## iOS custody follow-up

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-377 | High | Open; locally corrected, Swift CI pending | The current engine interpolated an unvalidated segment string into write/delete paths and kept only an in-memory share map. Segment IDs are now exactly 64 hex characters and normalized before path construction; storage is read from disk after reopen, overwrite quota accounting excludes the old file, and Leave deletes only canonical share files. Traversal, persistence and unknown-file regression tests were added. No production network caller was wired before this fix. |
| BLG-378 | High | Open; locally corrected, Swift CI pending | `runBackgroundProcessingWindow` returned the complete raw custody share as a purported audit proof and incremented a presence counter without publishing presence. The engine now requires an injected `CustodyAuditSigning` boundary, fails with `auditSigningUnavailable` by default, and has no presence-success counter. Tests prove reopen-from-disk signing, no raw share in the test signature, and zero success on the unavailable path. |
| BLG-379 | Medium | Open; locally corrected, Swift CI/device gates pending | The key wrapper claimed Secure Enclave/Keychain/biometric properties while always constructing a software P-256 key with no persistent reference, and the UI toggled registration as a local boolean. Enclave availability is now mandatory, wrap/unwrap is implemented, registration is disabled until a production core exists, unused permissions were removed, and documentation states the remaining integration work. No hardware pass is claimed. |
| BLG-380 | High | Open in the source proposal; excluded from integration | PR #100 named its adapter `ProductionCore` but initialized it with `FakeMobileCore`; its Keychain documentation had no concrete Keychain `WrapKeyStore`. Importing that UI would have made fake registration/audit/presence results production-visible. The parallel package was not integrated. Its useful parity concept was adapted to the current target with a fail-closed Rust/Swift comparison and four executed mutation/unit tests. |

## Rust source-gate follow-up

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-381 | Medium | Open; locally corrected, pinned gate CI pending | The first integrated structural gate only matched delimiters and selected mangled lines, so mid-expression syntax defects could pass; the proposed full-parser replacement also skipped unreadable/oversized files and directory errors. The canonical gate now uses `syn::parse_file` across every source root plus `build.rs`, fails closed on I/O and size violations, rejects scans below 50 files, and adds vacuity and invalid-UTF-8 canaries. The obsolete heuristic replica was removed. Tree-sitter independently parsed 1,117 current Rust files with zero error files; the Rust/syn gate itself has not run locally. |

## Registry commitment and source-gate follow-ups

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-382 | Critical | Open; locally corrected, Rust tests and pinned CI pending | `Bud3Registry::state_root` omitted object identity/profile/codec fields, share class and assignment epoch, audit presence/segment, the exact public index and NFT ownership. Distinct consensus states could therefore share a root, and an orphaned restored index was hidden. The V2 domain-separated root now commits every serialized registry field, including later endowment/grant/replacement state, with field-mutation, orphan-index and snapshot-rebuild tests. The changed Rust files pass tree-sitter; no Rust test or compiler ran locally. |
| BLG-383 | Medium | Open; locally corrected, gate CI pending | The English-tree gate exempted all of `docs/NAMING.md` and the bilingual claims source, allowing unrelated Turkish prose to hide in those files. Exact Turkish aliases now remain in the linked canonical concept map; only standalone literals present in the live claims dictionary are exempt. Five mutation canaries cover literal/other-file/comment/unknown/trailing cases, raising the expected total to 72. The gate was not executed locally. |

## Execution, naming and persistence reconciliation follow-ups

| Identity | Severity | Status | Evidence |
|---|---|---|---|
| BLG-384 | Critical | Open; locally corrected, Rust tests and pinned CI pending | Execution, mempool admission and RPC precheck did not share one AI/privacy feature boundary, generic AI `RoleBond` remained available outside Devnet, and native `ContractCall` inference events could pass before the AI door. The shared policy now runs at all three boundaries; generic role bonds close while role unbond/withdraw and pre-existing AI escrow/bond exits remain open, and inference events are refused before grant/registry/escrow writes. `src/tests/privacy_ai_execution.rs` carries direct and indirect state-unchanged regressions. Mainnet/testnet privacy refusal compatibility is preserved. Static parsing only; no Rust test ran locally. |
| BLG-385 | Medium | Open; locally corrected, gate CI pending | The concept-name writer could create a missing baseline, accept duplicate or unmapped rows and silently discard entries while rewriting it. Parsing now rejects duplicates and writing requires an exact existing one-row-per-current-concept baseline before the non-increasing check. Duplicate, missing and extra-row regressions were added in `concept_names.rs`; tree-sitter parsing passed, but the gate/tests were not executed locally. |
| BLG-386 | Medium | Open; locally corrected, Rust tests and pinned CI pending | An explicit CLI `--fee 0` was indistinguishable from the unsigned template's unresolved-fee sentinel and could reach signing flows. Every optional CLI fee argument now uses `parse_positive_fee`, and `resolve_network_fee` independently rejects `Some(0)` before any network call. Positive explicit fees still win; omitted fees retain `bud_estimateGas` with `bud_gasPrice` fallback. `cli_explicit_zero_fee_is_refused_without_contacting_the_network` was added but not run locally. |
| BLG-387 | Critical | Open; locally corrected, Rust tests and pinned CI pending | Seventy execution nonce increments saturated at `u64::MAX`, direct execution could mutate before discovering exhaustion, and candidate block application did not recheck the current-state nonce when witnesses were pruned. Nonce advancement is now checked, exhaustion is preflighted before any arm, candidate nonces must equal current state, and receiver-credit overflow is preflighted before sender debit. `blg_113_block_nonce_failures_are_atomic` and `blg_113_direct_execution_rejects_exhausted_nonce_before_mutation` cover the boundary; execution evidence remains pending. |
| BLG-388 | High | Open; locally corrected, Rust tests and pinned CI pending | Snapshot publication used `rename`, which replaces an existing destination on Unix and can destroy an earlier verified backup on a timestamp collision. Publication now syncs and closes an exclusive partial, publishes through a no-clobber hard link, verifies the linked destination, removes the partial and syncs the parent directory. `snapshot_never_replaces_an_existing_backup` protects existing bytes and partial cleanup; it has not run locally. |
| BLG-389 | Medium | Open; checked arithmetic added, runtime regression and pinned CI pending | Storage-bond slash and burn counters used saturating addition, allowing accounting to cap while supply records advanced. The slash path now preflights both counter additions and returns an error before updating them, while destroyed supply uses the canonical checked recorder. Source inspection and tree-sitter parsing passed; a direct overflow regression is still owed, so this is not represented as test-verified. |
| BLG-390 | Medium | Open; locally corrected, gate CI pending | The exact-grant AI authorization repair introduced 59 new legacy `Pollen` occurrences in four AI crate files, while five other concept counters had drifted below their recordings. The AI source/grant API now uses `DataMarket` names throughout those files without changing enum order or authorization behavior, and all 27 baselines were regenerated only where file/match counts did not increase. The independent full-tree measurement now matches all 27 rows; the Rust gate and crate tests remain unexecuted. |
