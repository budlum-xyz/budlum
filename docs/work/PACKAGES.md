# Work package status

One row per work package of the directive (section 15.7) with live evidence on
`main` (`cccf1da`) or an open pull request.

Status vocabulary: `not started`, `in progress`, `in review`, `merged`,
`blocked`.

## Packages

| Package | Title | Lane | Layer | Status | Pull requests | Last commit | Evidence |
|---|---|---|---|---|---|---|---|
| WP-01 | Live verification: core | A | T-Launch | in review | 12 | branch `arena/a1` | Pull request 12 carries `docs/audit/live/lane-a.md` and `src/tests/audit_lane_a.rs` |
| WP-02 | Live verification: storage | B | T-Launch | in review | 12 | branch `arena/a1` | Pull request 12 carries `docs/audit/live/lane-b.md` and `src/tests/audit_lane_b.rs` |
| WP-03 | Live verification: execution, BudZero, domains, privacy, AI | C | T-Launch | in review | 12, 16 | branch `arena/c1` | Pull requests 12 and 16 carry `docs/audit/live/lane-c.md` |
| WP-04 | Live verification: clients, operations, CI, documents | D | T-Launch | in review | 18 | branch `arena/d1` | Pull request 18 carries `docs/audit/live/lane-d.md` |
| WP-05 | Concept name map and counter gate | D | T-Launch | in review | 20 | branch `arena/d2` | Pull request 20 adds `owner` fields and `concept_map_owner_is_a_known_package` |
| WP-06 | Persistence and state recovery migration | B | T-Launch | in review | 11 | branch `arena/b1` | Pull request 11 moves node-local persistence into `src/persistence/` |
| WP-09 | UEL ABI crate (`crates/uel-abi`) and transport handshake | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 closes `BLG-088` handshake `request_id` echo/validation (`handshake_echoes_request_id_and_rejects_mismatch`) and Windows portability (`BLG-276`) |
| WP-10 | B.U.D. 3.0 skeleton and shared types | B | T-Launch | merged (skeleton) | 5, 6 | `cccf1da` | `src/storage/bud3/` skeleton modules exist on `main` |
| WP-12 | Committee finality, instant seat handover, consensus hardening | A | T-Launch | in review | 9 | branch `arena/5b54fce9-budlum` | Pull request 9 touches `src/validators/committee.rs`, `src/chain/finality.rs`, `src/chain/{blockchain,snapshot}.rs` |
| WP-20 | Class aware placement, custody proof, repair | B | T-Launch | in review | 13 | `ca01543` | Pull request 13 adds B.U.D. 3.0 placement, custody proof, and repair gates |
| WP-24 | A0 codec register and access layer | B | T-Launch | in review | 8, 6 | branch `arena/b7784c85-budlum` | Pull request 8 carries codec register and dedup index |
| WP-26 | Execution Coordinator and EE workers (slice 1/2) | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 implements `frac_attos` (`BLG-256`), Windows ABI guard (`BLG-276`), account aliases, `execution_root`, BGU gas/fees, mempool lanes, `BlockReadCache` + `TxOverlay` (`BLG-260`), `WorkerSupervisor` + `ExecutionCoordinator` (`BLG-250`), `StatefulBudZeroEe` (`BLG-248`), deploy freeze (`R-21`), `execution/` workspace + `budlum-ee-*`, `ee-workers-build-with-unwind`, and all 8 named `WP-26` tests. Slice 2/2 (`TransactionType::{Execute,Foreign}` + `GlobalBlockHeader` V8 wire path) follows once lock-path PRs `#9` and `#14` settle |
| WP-27 | EVM Execution Environment and Ethereum envelope | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 implements `EvmEe` (`budlum-ee-evm`), Prague runtime, `CREATE2` alias collision check, `SSTORE` growth metering (`evm_state_growth_is_metered`), `0x...B001` Universal Call precompile, and EIP-1559 `45261` foreign envelope (`foreign_evm_tx_round_trip`, `wrong_chain_id_rejected`) |
| WP-28 | Ethereum JSON-RPC compatibility gateway | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 implements `src/rpc/compat/ethereum.rs` (`127.0.0.1:18547`, `eth_rpc_method_table_is_complete`, `eth_get_proof_returns_method_not_found`, `eth_filters_are_bounded`, `stateRoot = execution_root`) |
| WP-29 | CosmWasm WASM Execution Environment and Cosmos gateway | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 implements `WasmEe` (`budlum-ee-wasm`, `wasm_float_code_refused`, `wasm_ibc_entry_points_refused`), `BudlumMsg::UniversalCall`, `CosmosTxRaw` (`budlum-testnet-1`), and CometBFT/ABCI RPC gateway (`src/rpc/compat/cosmos.rs`) |
| WP-30 | Universal Call and Universal Asset Registry | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 implements `contracts/uel/BudlumUniversal.sol`, `0x...B001`, BudZero `0x40`, `uel/assets`, and zero-balance CW20/CW721 <-> ERC-20/ERC-721 pointers (`uel_evm_calls_wasm_atomically`, `uel_pointer_holds_no_balance`, `pointer_allowance_lives_at_home`, `asset_id_is_deterministic`, `universal_call_log_is_visible_to_evm_indexers`) |
| WP-31 | SVM Execution Environment and Solana gateway | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 implements `SvmEe` (`budlum-ee-svm`, `svm_jit_is_disabled`), SPL Token/ATA/Memo/System programs, Vote/Stake refusal, `BDLM_SVM_UNIVERSAL_PROGRAM_V1` CPI, `SolanaV0Tx`, and `src/rpc/compat/solana.rs` |
| WP-32 | Move Execution Environment and Aptos REST gateway | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 implements `MoveEe` (`budlum-ee-move`, `execution/move/deny.toml`), `0xBD` disjointness (`move_alias_scheme_byte_is_unused`), `0x1::randomness`, `0x1::budlum_universal`, `AptosSignedTx` (`chain_id = 205`), and `src/rpc/compat/aptos.rs` |
| WP-33 | Compatibility Lane quantum isolation, Alert, and Adopt | C | T-Launch | in review | 36 | branch `arena/48ccda24-budlum` | Pull request 36 closes `BLG-267` with K-3 holding isolation (`foreign_account_cannot_touch_pq_holding`), `QuantumAlertLevel` (`emergency_alert_suspends_foreign_keeps_adopt`), `AdoptForeignAccountTx` (`adopt_moves_balance_and_retires_foreign_signer`), and category `"f"` in `classical_crypto_is_paired` |
| WP-44 | Testnet feature closures and launch decision record | D | T-Launch | in review | 14 | branch `arena/d4` | Pull request 14 records launch closure tracking |
