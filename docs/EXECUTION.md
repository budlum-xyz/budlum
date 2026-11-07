# Universal Execution Layer (`UEL`)

Budlum executes unmodified contracts from multiple virtual-machine ecosystems
against one post-quantum consensus ledger and one sparse-Merkle state root
(`execution_root`).

## 1. Out-of-Process Worker Isolation (`BLG-250`)

The validating node (`budlum-core`) compiles with `[profile.release] panic = "abort"`.
Running guest virtual machines inside the node process would allow a single
deterministic engine panic to abort every validator on the same block.

Every execution environment therefore runs in a dedicated worker binary
(`budlum-ee-budzero`, `budlum-ee-evm`, `budlum-ee-wasm`, `budlum-ee-svm`,
`budlum-ee-move`) compiled with `[profile.release] panic = "unwind"` (enforced
by the `ee-workers-build-with-unwind` CI gate) and supervised by
`src/execution/coordinator/worker_manager.rs` over Unix domain sockets
(`crates/uel-abi`):

- Per-request wall-clock watchdog: `2s` (`WORKER_WATCHDOG`).
- Per-worker address-space ceiling: `4 GiB` (`WORKER_RLIMIT_AS_BYTES`).
- Deterministic refusal (`Revert`, `OutOfGas`, `InvalidCode`, `EeRefusal`):
  transaction overlay frame is discarded, gas is charged, block continues.
- Caught deterministic engine panic (`EeFault { ee, panic_digest }`):
  transaction overlay is discarded, full `gas_limit` is charged, worker
  reconnects/restarts, `budlum_ee_fault_total{ee}` increments, block continues.
- Non-deterministic worker death (`TransportError`):
  the entire block attempt is discarded without committing state, workers are
  restarted, and the block is retried up to `3` times (`MAX_BLOCK_WORKER_ATTEMPTS`).
  After three consecutive transport failures the node halts fail-closed.

## 2. Coordinator State Access and Block Read Cache (`BLG-260`)

Workers hold zero persistent state. Every storage read and write passes through
`HostRead` / `HostApi` into `src/execution/coordinator/overlay.rs`:

- `OverlayCore` maintains a nested call-frame stack (`MAX_UNIVERSAL_CALL_DEPTH = 8`)
  with cross-environment reentrancy protection (`ReentrancyForbidden`) and the
  EIP-150 `63/64` stipend cap.
- `BlockReadCache` caches clean `(namespace, key)` reads in the node process
  across transactions within the same block and updates entries atomically on
  root transaction commit, eliminating repeated storage lookups over IPC
  (`BLG-260`). Single-process `sled` / RocksDB ownership stays strictly inside
  the node process; IPC read round-trips over local `AF_UNIX` streams stay
  sub-100 microseconds for uncached keys and sub-microsecond on `BlockReadCache`
  hits.

## 3. Unified Account, Alias, and BUD Unit Model (`BLG-256`)

All environments share the single Budlum BUD supply:

- Each `Account` stores whole atoms (`balance: u64`, `10^-6 BUD`) plus
  sub-atom fractional attoBUD (`frac_attos: u64 < 10^12`, `10^-18 BUD`).
- Exact account value is `balance * 10^12 + frac_attos` attoBUD, conserved
  across every environment (`EVM` wei `10^0`, `SVM` lamport `10^9`, `Move`
  octa `10^10`, `WASM` `ubud` `10^12`, `BudZero` atom `10^12`).
- Local post-quantum accounts (`Address` V3) derive deterministic key-free
  aliases in every environment (`uel/alias`), including off-curve PDA-style
  `SVM` aliases (`CompressedEdwardsY::decompress().is_none()`).

## 4. Universal Gas (`BGU`) and Fee Split

- Block limit: `60,000,000 BGU`; EIP-1559 target: `30,000,000 BGU` (`12.5%` max
  per-block base-fee step).
- Environment soft caps: `EVM = 30M BGU`, `WASM = 24M BGU`, `SVM = 24M BGU`,
  `Move = 24M BGU`, `BudZero = MAX_BLOCK_CONTRACT_GAS`.
- Fee distribution (`settle_bgu_fee_split`): `10%` of base fee burned, `90%` of
  base fee routed to `reward_pool`, `100%` of priority tip routed to the block
  proposer.

## 5. Sparse-Merkle State Commitment (`execution_root`) and Stateful Contracts (`BLG-248`)

Twelve canonical namespaces (`ee/evm/{account,code,storage}`,
`ee/wasm/{code,contract,store}`, `ee/svm/account`, `ee/move/state`,
`ee/budzero/{program,storage}`, `uel/alias`, `uel/assets`) commit into seven
256-depth sparse binary Merkle sub-trees folded with `u64`-LE length prefixes
under `BDLM_UEL_ROOT_V1`. Stateful `ContractCall` (`BDLM_UEL_STATEFUL_V1`)
deploys persistent BudZero programs to deterministic contract addresses and
persists contract storage across transactions without running validator-side
STARK proving on every call (`BLG-248`).

## 6. EVM Execution Environment and Foreign Envelope (`WP-27`, `BLG-267`)

- Pinned EVM engine: `revm = "=43.0.3"` (`budlum-ee-evm` worker in `execution/evm/`).
- Supported EVM hardfork: **`Osaka`** (`SpecId::OSAKA`, the latest stable hardfork
  in `revm` `43.0.3`; experimental `Amsterdam` is disabled).
- Chain ID: `45261` (`EIP-155`). Accepted transaction types: Type `0` (EIP-155
  replay-protected only), Type `1` (`EIP-2930`), Type `2` (`EIP-1559`), and Type `4`
  (`EIP-7702`). Type `3` (`EIP-4844` blob transactions) is deterministically refused.
- Classical-signature custody boundary (`K-3`, `BLG-267`): `Foreign::Ethereum`
  accounts carry `QuantumClass::Classical` and can move only their own foreign
  account holdings; they cannot debit any `QuantumClass::PostQuantum` native
  account. A dual-signed `Adopt` operation (`BDLM_FOREIGN_ADOPT_V1`) sweeps
  foreign holdings into a post-quantum `Address` V3 once and remains open even
  under `QuantumAlertLevel::Isolated`.
- Universal Call precompile skeleton: `0x000000000000000000000000000000000000B001`
  (`contracts/uel/BudlumUniversal.sol`).

## 7. Ethereum JSON-RPC Compatibility Gateway (`WP-28`, `BLG-249`)

- Public HTTP and WebSocket listener: `127.0.0.1:18547` (`src/rpc/compat/ethereum/`,
  configured under `[compat.ethereum]` in `config/*.toml`).
- Method classification table: `src/rpc/compat/ethereum/method_class.rs`
  (`ETH_METHOD_CLASSES`). `debug_traceTransaction` and `debug_traceCall` are served
  exclusively on the loopback operator listener (`127.0.0.1:18557`).
- Block `stateRoot` semantics (`Section 8.10` items 5 and 6): the `stateRoot` field
  returned by `eth_getBlockByNumber`, `eth_getBlockByHash`, and `newHeads` is
  Budlum's sparse-Merkle `execution_root` (`BDLM_UEL_ROOT_V1`), **not** an Ethereum
  hexary Patricia MPT root. Consequently, `eth_getProof` deterministically returns
  JSON-RPC `-32601` (`Method not found`) and directs callers to `bud_getExecutionProof`.

## 8. WASM (CosmWasm ABI) and Cosmos Compatibility Gateway (`WP-29`, `BLG-249`)

- Out-of-process worker: `budlum-ee-wasm` (`execution/wasm/`, `wasmi = "=2.0.0"`),
  floating-point instructions forbidden (`floats(false)`), 64 MiB linear-memory limit,
  IBC entry points and `StakingMsg` / `DistributionMsg` / `GovMsg` / `IbcMsg` refused.
- Foreign transaction lane: `Foreign::Cosmos` (`src/execution/coordinator/foreign/cosmos.rs`),
  `cosmos.tx.v1beta1.TxRaw` under `SIGN_MODE_DIRECT` (`budlum-testnet-1`).
- Gateways (`src/rpc/compat/cosmos/`): CometBFT JSON-RPC on `127.0.0.1:18550` and
  Cosmos LCD REST on `127.0.0.1:18551` (`[compat.cosmos]`).

## 9. Universal Call and Universal Asset Registry (`WP-30`, `BLG-250`, `BLG-252`)

- Synchronous cross-VM calls (`src/execution/coordinator/universal_call.rs`):
  max cross-EE depth `8`, Phase-1 `ReentrancyForbidden`, `is_static` write prohibition,
  EVM precompile `0x000000000000000000000000000000000000B001` (`contracts/uel/BudlumUniversal.sol`)
  emitting `UniversalCallExecuted(uint8,bytes,bool)`, WASM `BudlumMsg::UniversalCall`,
  and BudZero syscall `0x40` (`UNIVERSAL_CALL`).
- Universal Asset Registry (`src/execution/coordinator/assets/`): `uel/assets`
  namespace, `RegisterAsset`, `CreatePointer`, and stateless CW20/ERC-20 & CW721/ERC-721
  pointers whose balances and allowances live exclusively in the home environment.

## 10. SVM Execution Environment (`WP-31`, `BLG-249`)

- Out-of-process worker: `budlum-ee-svm` (`execution/svm/`, `solana-sbpf = "=0.10.0"`
  with `default-features = false` so JIT is disabled at compile time).
- Built-in programs: System, SPL Token, Token-2022, Associated Token Account, Memo,
  BPF Upgradeable Loader, and Universal Call (`SHA256("BDLM_SVM_UNIVERSAL_PROGRAM_V1")`).
  Solana `Vote` and `Stake` programs are deterministically refused (`Section 8.15`).

## 11. Move (Aptos) Execution Environment and Foreign Envelope (`WP-32`, `BLG-249`)

- Out-of-process worker: `budlum-ee-move` (`execution/move/`, `EeId::MOVE = 0x04`,
  `BLOCK_STM_ENABLED = false`, `1 Aptos gas unit = 100 BGU`, `1 octa = 10^10 attoBUD`),
  with `0xBD` local-alias authentication-key scheme byte verified unused against pinned
  `aptos-core` (`81d89f428fe8e4b69d53b4916993e9a930afc37c`), `0x1` staking/governance
  modules disabled, `0x1::randomness` bound to `BlockContext`, and
  `0x1::budlum_universal::call`.
- Foreign envelope (`src/execution/coordinator/foreign/aptos.rs`): BCS `SignedTransaction`
  for chain ID `205` (`45261 mod 256`), verifying `Ed25519`, `MultiEd25519`, and
  `SingleKey` (`Ed25519` / `Secp256k1Ecdsa`) authenticators while refusing OIDC keyless
  accounts, expired timestamps, and sequence-number replays (`uel_foreign_tx_replay_refused_aptos`).

## 12. Conformance, Gas Calibration, and Cross-Architecture Determinism (`WP-35`)

- Conformance runner: `budlum-ee-conformance` (`execution/conformance/`), exercising
  `uel_conformance_{budzero,evm,wasm,svm,move}`, `uel_gas_calibration_bound`
  (`1 BGU <= 16 ns` p95 in `--release`), and `uel_cross_arch_roots_equal`.
- Nightly cross-arch gate: `.github/workflows/conformance-nightly.yml` compares
  `UEL_EXECUTION_ROOT` byte-for-byte between `ubuntu-24.04` (`x86_64`) and
  `ubuntu-24.04-arm` (`aarch64`).

## 13. SVM and Move Stateless Pointers & `KR-UEL-REENTRANCY` (`WP-52`)

- Height-gated (`PointerActivationPolicy`): closed at launch on testnet `45261`
  (`svm_move_pointers_is_closed_on_testnet`, `Section 1.5`) and enabled at
  `svm_move_activation_height`.
- Stateless pointer codecs in `execution/svm/src/pointer/` and `execution/move/src/pointer/`
  plus 4-way coordinator translation (`svm_pointer_holds_no_balance`,
  `move_pointer_holds_no_balance`, `pointer_allowance_lives_at_home`).
- `KR-UEL-REENTRANCY` (`IP-52` item 3): cross-environment reentrancy prohibition
  (`Section 8.7.3` item 6) remains enforced (`REENTRANCY_RULE_RETAINED_WP52 = true`).

## 14. Deterministic Access-Set Parallel Block Execution (`WP-59`)

- Height-gated (`ParallelSchedulerPolicy` in `src/execution/coordinator/scheduler/`):
  closed at launch on testnet `45261` (`parallel_scheduler_is_closed_on_testnet`) and
  switches to deterministic access-set wave execution (`StateKey::Account` +
  `StateKey::UelSlot`) with automatic sequential barrier fallback on conflict.
- Intra-environment (`Block-STM`) parallelism stays behind a separate flag and requires
  passing state-root equality verification (`intra_ee_parallelism_active()`).
- Calibration timing report (`PARALLEL_BLOCK_TIMING_JSON`) is emitted and uploaded by
  `conformance-nightly.yml` alongside `parallel_schedule_equals_sequential_root` and
  `parallel_scheduler_is_deterministic_across_arch`.

## 15. Move (Sui Dialect) Execution Environment (`WP-50`, `EeId::MOVE_SUI = 0x05`)

- Standalone out-of-process worker `budlum-ee-move-sui` (`execution/move-sui/`,
  `panic = "unwind"`, pinned upstream `MystenLabs/sui` reference
  `e5b8d9a4c2718f140933b42c66d8c04a7d1e9b02`, `Apache-2.0`).
- Sui object model in `ee/sui/object` (`AddressOwner`, `ObjectOwner`, `Shared`,
  `Immutable`, Lamport versioning, `BLAKE2b-256` object digests), `Foreign::Sui`
  (`ForeignScheme::SuiEd25519 = 0x05`), and Sui JSON-RPC subset (`src/rpc/compat/sui/`).
- Closed at launch on testnet `45261` (`move_sui_is_closed_on_testnet`,
  `foreign_sui_is_closed_on_testnet`) with proposed activation height `50_000`.

## 16. Cairo (Starknet) Execution Environment (`WP-51`, `EeId::CAIRO = 0x06`)

- Standalone out-of-process worker `budlum-ee-cairo` (`execution/cairo/`,
  `panic = "unwind"`, audited engine licenses `lambdaclass/cairo-vm` `Apache-2.0`
  and `starkware-libs/sequencer` `blockifier` `Apache-2.0`).
- Starknet Account Abstraction (`__validate__`, `__validate_declare__`, `__execute__`)
  bound to the caller's post-quantum Budlum local alias under `ee/cairo/state`, plus
  read-only Starknet JSON-RPC v0.7 subset (`src/rpc/compat/starknet/`).
- Closed at launch on testnet `45261` (`cairo_is_closed_on_testnet`) with proposed
  activation height `55_000`.

## 17. Expansion Catalog Workers (`WP-53`, `0x07`..`0x0B`)

- `0x08` PolkaVM (`execution/polkavm/`, `budlum-ee-polkavm`, RV32EM interpreter with
  JIT disabled, `ee/polkavm/state`, closed on testnet `45261` until height `60_000`,
  `polkavm_is_closed_on_testnet`, `uel_conformance_polkavm`).












