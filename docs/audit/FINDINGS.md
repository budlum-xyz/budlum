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
