# Universal Execution Layer (UEL)

This document specifies the runtime architecture, state model, gas accounting,
and IPC latency profile of the Universal Execution Layer implemented in
`src/execution/coordinator/`, `crates/uel-abi/`, and `execution/`.

## 1. Process Isolation and Fault Model

The node binary (`Cargo.toml`) compiles with `panic = "abort"` and holds the
canonical state store (`AccountState`). Execution environments (`budlum-ee-*`)
live in the separate Cargo workspace `execution/Cargo.toml`, which compiles with
`panic = "unwind"` and `overflow-checks = true` (enforced by the
`ee-workers-build-with-unwind` gate).

| Property | Value | Enforcement |
|---|---|---|
| IPC transport | Unix domain socket (`AF_UNIX` stream), `u32` length-prefixed `budlum.execution.v1.Envelope` | `crates/uel-abi/src/transport.rs` (`#[cfg(unix)]`) |
| Frame ceiling | 16 MiB (`MAX_FRAME_BYTES`) | `crates/uel-abi/src/frame.rs` |
| Per-request watchdog | 2 seconds (`WATCHDOG`) | `crates/uel-abi/src/transport.rs` |
| Worker virtual memory cap | 4 GiB (`WORKER_RLIMIT_AS_BYTES`, `ulimit -v 4194304`) | `src/execution/coordinator/worker.rs` |
| Deterministic engine panic | Caught via `catch_unwind`, hashed with `BDLM_UEL_PANIC_V1`, returned as `EeFault` receipt; full `gas_limit_bgu` charged, worker restarted, block continues | Closes `BLG-250` |
| Non-deterministic worker death | Socket EOF, timeout, or `SIGKILL` discards the block candidate, restarts workers, and retries up to 3 times (`MAX_BLOCK_WORKER_RETRIES`) before raising a critical halt alarm without committing partial state | `ExecutionCoordinator::execute_block` |

On non-Unix hosts (`windows-latest`), `budlum-uel-abi` omits the Unix socket
transport (`BLG-276`) and the coordinator runs in-process environments behind
the same `catch_unwind` boundary.

## 2. State Access and IPC Read Latency (`BLG-260`)

Workers are stateless. Every state read, write, balance check, transfer, log,
and cross-environment `UniversalCall` crosses `HostRead` / `HostApi` into the
coordinator (`HostBridge`). Keeping a single state store inside the node
eliminates multi-process database lock contention (`BLG-260`).

To bound IPC read amplification within a block:

1. `TxOverlay` (`src/execution/coordinator/overlay.rs`) serves uncommitted writes
   from the active frame stack (root frame plus up to 8 nested `UniversalCall`
   frames; `MAX_UNIVERSAL_CALL_DEPTH = 8`, cross-EE re-entrancy forbidden).
2. `BlockReadCache` caches committed `(namespace, key)` lookups across all
   transactions in the block and invalidates keys touched by committed writes or
   merged `UniversalCall` child frames.

| Path | Typical Latency (local x86_64/arm64 Linux) | Notes |
|---|---|---|
| Active `TxOverlay` frame hit (worker -> coordinator -> worker) | ~15-35 us over `AF_UNIX`; < 1 us in-process | Reads uncommitted writes staged earlier in the same transaction |
| `BlockReadCache` hit on committed key | ~15-35 us over `AF_UNIX`; < 1 us in-process | Avoids repeated hex decode and namespace map traversal across transactions in one block |
| Cold `ExecutionState` miss | ~20-45 us over `AF_UNIX` | Populates `BlockReadCache` for subsequent transactions in the same block |

## 3. Unified Accounts, Aliases, and BUD Sub-Units (`BLG-256`)

All environments share one 32-byte Budlum `Address` space and one BUD ledger:

- **Account classes**: native post-quantum accounts, foreign Compatibility Lane
  accounts (`BDLM_FOREIGN_ACCOUNT_V1`), and contract accounts
  (`BDLM_CONTRACT_ACCOUNT_V1`). A classical foreign account may never mutate
  holdings owned by a post-quantum account (`AccountQuantumClass::may_touch`).
- **Deterministic aliases (`uel/alias`)**:
  - EVM (`0x01`): `keccak256("BDLM_EVM_ALIAS_V1" || addr32)[12..32]`; colliding
    foreign/deploy 20-byte targets are refused (`check_evm_alias_collision`).
  - WASM (`0x02`): `bech32("bud", addr32)`.
  - SVM (`0x03`): `SHA256("BDLM_SVM_ALIAS_V1" || addr32 || seed)` selecting the
    highest `seed` in `255..=0` whose digest lies off the Ed25519 curve.
  - Move (`0x04`): `SHA3-256(addr32 || 0xBD)`.
  - BudZero (`0x00`): `addr32`.
- **Sub-atom precision**: `Account` carries `balance: u64` (atoms, `10^-6` BUD)
  and `frac_attos: u64` (`0 <= frac_attos < 10^12` attoBUD, `10^-18` BUD).
  Environment transfer quanta: `EvmWei = 1`, `SvmLamport = 10^9`,
  `MoveOcta = 10^10`, `WasmUbud = 10^12`, `BudZeroAtom = 10^12` attoBUD.
  `circulating_supply()` rounds up across fractional sub-units and
  `total_bud_committed_attos()` tracks exact attoBUD supply (`economy-invariants`
  gate).

## 4. BGU Gas, Mempool Lanes, and EIP-1559 Fee Split

- **Mempool lanes** (`src/mempool/lanes.rs`): six isolated lanes (`Native`,
  `Ethereum`, `Solana`, `Aptos`, `Cosmos`, `Duty`) with independent entry and
  byte budgets and cross-lane priority-fee block selection.
- **Budlum Gas Unit (BGU)** (`src/execution/coordinator/gas.rs`):
  - Hard block limit: `60,000,000` BGU (`TARGET_BLOCK_BGU = 30,000,000`).
  - Soft per-environment limits: EVM `30,000,000`, WASM `24,000,000`,
    SVM `24,000,000`, Move `24,000,000` (`1 Move gas unit = 100 BGU`),
    BudZero `MAX_BLOCK_CONTRACT_GAS`.
  - EIP-1559 base fee (`MIN_UEL_BASE_FEE_ATTOS = 1,000,000` attoBUD/BGU, max
    `1/8` step per block): **10% burned**, **90% to the Network Security Pool**,
    and **100% of priority fee to the block proposer**.

## 5. Commitments, Stateful BudZero (`BLG-248`), and Feature Flags (`R-21`)

Twelve canonical namespaces (`ee/evm/{account,code,storage}`,
`ee/wasm/{code,contract,store}`, `ee/svm/account`, `ee/move/state`,
`ee/budzero/{program,storage}`, `uel/alias`, `uel/assets`) map into seven
depth-256 sparse binary Merkle subtrees (`BDLM_UEL_NS_KEY_V1`,
`BDLM_UEL_NS_LEAF_V1`, `BDLM_UEL_NS_NODE_V1`) folded into
`execution_root = H("BDLM_UEL_ROOT_V1", evm, wasm, svm, move, budzero, alias, asset)`
and committed into `AccountState::calculate_state_root` (`uel_execution_v1`).

`StatefulBudZeroEe` (`BLG-248`) executes deployed 8-byte-aligned BudZero
programs with persistent per-contract key-value storage in `ee/budzero/storage`.
Each environment carries an independent deployment flag (`deploy_frozen_ees`,
`R-21`) that freezes new contract deployments with `UelReceiptStatus::DeployFrozen`
while keeping existing contracts live.

## 6. Execution Environments, Universal Call, and Compatibility Gateways

- **Execution workers (`execution/`)**:
  - `budlum-ee-evm` (`EeId::EVM` = `0x01`, `src/execution/coordinator/evm_ee.rs`):
    Prague EVM runtime, `CREATE2` alias collision check, `SSTORE` state-growth
    metering (`84 * STATE_GROWTH_GAS_PER_BYTE`), and Universal Call precompile
    at `0x000000000000000000000000000000000000B001` (`contracts/uel/BudlumUniversal.sol`).
  - `budlum-ee-wasm` (`EeId::WASM` = `0x02`, `src/execution/coordinator/wasm_ee.rs`):
    deterministic CosmWasm subset refusing floating-point types/instructions,
    non-trapping `trunc_sat`, memory above `64 MiB`, IBC exports, and Cosmos
    staking/distribution/gov/IBC messages; exposes `BudlumMsg::UniversalCall`
    and `BudlumQuery::UniversalView`.
  - `budlum-ee-svm` (`EeId::SVM` = `0x03`, `src/execution/coordinator/svm_ee.rs`):
    interpreted SBPF runtime (`jit_enabled = false`), System / SPL Token /
    Token-2022 / ATA / Memo / BPF Loader programs, Vote/Stake refusal, and
    built-in Universal Call program `SHA256("BDLM_SVM_UNIVERSAL_PROGRAM_V1")`.
  - `budlum-ee-move` (`EeId::MOVE` = `0x04`, `src/execution/coordinator/move_ee.rs`):
    sequential Move VM (`block_stm_parallel = false`), `0x1::randomness` bound
    to `BlockContext.randao`, staking/governance refusal, `execution/move/deny.toml`,
    and native `0x1::budlum_universal::call`.
  - `budlum-ee-budzero` (`EeId::BUDZERO` = `0x00`): native BudZero environment
    with `UNIVERSAL_CALL` syscall `0x40`.
- **Universal Asset Registry (`uel/assets`, `WP-30`)**:
  - `asset_id = SHA3-256("BDLM_UEL_ASSET_V1" || home_ee || len_le64 || home_ref)`.
  - Zero-balance deterministic pointers between CW20/CW721 and ERC-20/ERC-721;
    all balances and allowances live exclusively in the home environment.
- **Foreign Compatibility Lane & Quantum Alert (`WP-33`, `BLG-267`)**:
  - Verifies EIP-1559 (`chain_id = 45261`), Cosmos `TxRaw` (`budlum-testnet-1`),
    Solana v0 (`150`-block window), and Aptos signed transactions (`chain_id = 205`,
    `0xBD` alias scheme disjointness).
  - Enforces K-3 holding isolation, `QuantumAlertLevel` (`Normal`,
    `Elevated` -> `10x` BGU surcharge + `3600s` quarantine, `Emergency` ->
    foreign admission suspended, `Adopt` remains open), and category `"f"`
    enforcement in `classical_crypto_is_paired`.
- **Compatibility RPC/REST Gateways (`src/rpc/compat/`)**:
  - Ethereum JSON-RPC (`127.0.0.1:18547`, `WP-28`): all 34 T-Launch public
    methods + operator `debug_traceTransaction` / `debug_traceCall` +
    `bud_getExecutionProof` / `bud_getImportedContract`; filters are strictly
    bound to their owning peer; `eth_getProof` returns `-32601` (`Method not
    found; use bud_getExecutionProof`); block `stateRoot` equals
    `execution_root` (sparse binary Merkle commitment, not an Ethereum MPT).
  - Solana JSON-RPC (`127.0.0.1:18548`, `WP-31`), Aptos REST (`127.0.0.1:18549`,
    `WP-32`), and CometBFT RPC + Cosmos LCD (`127.0.0.1:18550` / `18551`, `WP-29`).
- **EVM Migration Kit (`src/execution/coordinator/migration/`, `src/bin/bud-migrate.rs`, `WP-34`)**:
  - Verifies source deployment MPT proof (direct `CREATE` or proven factory
    `CREATE`/`CREATE2`), EIP-712 `MigrationAuthorization`, finalized account
    proof (`src/cross_domain/evm/account_proof.rs`), and multi-chunk storage MPT
    proofs (`ImportEvmStorageChunk` -> `FinalizeEvmImport`), installing exact
    20-byte address, bytecode, storage, and `imported_from` with zero native
    balance (`docs/EVM_MIGRATION.md`).
- **Remaining wire integration (`WP-26` slice 2/2, deferred due to active
  lock-path PRs `#9` and `#14`)**: wiring `TransactionType::{Execute,Foreign}`
  in `src/core/transaction.rs` and `src/execution/executor.rs`, and adding
  `execution_root` to `GlobalBlockHeader` V8.
