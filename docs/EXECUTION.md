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



