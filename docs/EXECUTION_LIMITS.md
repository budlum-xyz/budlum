# Execution limits and the state of the conformance suites

| Field | Value |
|---|---|
| Directive | Section 8.9 (gas), 8.13 (conformance), 8.15 (the limits of "runs unchanged"), 8.16 (tests) |
| Work package | WP-35, delivery 1/3 |
| Lane | C |
| Measured by | nothing. This delivery holds no measurement, and every row below says so |
| Enforced by | `src/tests/conformance_locks.rs` |

This is the limits table Section 8.15 and Section 8.13 item 3 require: one row per
conformance case, one row per environment parameter, and one record of every claim
that does not hold yet. A case is `pass` only when a test named in the row exists in
the tree and that test has run. A case is `limits` when it is not run, and then the
row carries the reason and the package that owes the run.

The file has one rule: a `pass` row may name only a test the tree has, and a
`limits` row must name the case test that will close it. The lock test reads this
file, reads the source of three named constants, and fails when a `pass` row names a
missing function, when a case test leaves its `<environment>_conformance_` prefix,
or when the numbers below disagree with the code.

## 1. The BGU parameter table (Section 8.9)

The block gas limit is 60 000 000 BGU and the slot is 3 seconds, both
`TESTNET-DEFAULT` (Section 8.9 items 2 and 3). One BGU is one unit of the universal
gas unit; an environment's own unit converts into it at the rate in column three.
The last column records whether the rate is measured. None of them is: the
calibration of Section 8.9 item 4 needs the reference machine (8 cores, sequential
execution) and the most expensive 5 percent of transaction types, and this delivery
ran neither.

| Environment | Unit | BGU per unit | Soft limit (BGU) | Block limit (BGU) | Measurement |
|---|---|---|---|---|---|
| evm | gas | 1 | 30000000 | 60000000 | not measured |
| wasm | wasmi fuel | 1 | 24000000 | 60000000 | not measured |
| svm | compute unit | 1 | 24000000 | 60000000 | not measured |
| move | aptos gas unit | 100 | 24000000 | 60000000 | not measured |
| budzero | budzero gas | 1 | 60000000 | 60000000 | not measured |

Section 8.9 item 3 says a per-environment soft limit may not exceed the total block
limit. Four of the five rows were already inside it. The BudZero row was not: its
soft limit was the in-tree constant `MAX_BLOCK_CONTRACT_GAS`, which was
`64 * DEFAULT_CONTRACT_GAS_LIMIT`, that is 64 000 000 BGU, and a block limit of
60 000 000 BGU cannot contain it. Section 5 is that record.

The BudZero row is not typed here and left to rot: the lock test reads
`BLOCK_GAS_LIMIT_BGU`, `DEFAULT_CONTRACT_GAS_LIMIT` and `MAX_BLOCK_CONTRACT_GAS`
out of `src/execution/zkvm.rs` and requires the three numbers to agree with this
table.

## 2. The conformance suites (Section 8.13)

Five environments, one section each. Every case is `limits` in this delivery: no
environment worker is in the tree, so no case can be run, and a `pass` that no run
backs is the claim this file exists to prevent. The counts line above each table is
machine read and must equal the rows below it.

The `Test` column names the test that decides the case, not the suite: the suite
test is `uel_conformance_<environment>`, which fails when one case of its section is
neither `pass` nor recorded here. A case test is named
`<environment>_conformance_<case>`, so a row cannot borrow its suite's name to look
green, and a `pass` row whose test is not in the tree is a test failure.

### 2.1 evm

Counts: cases=7 pass=0 limits=7

| Case | State | Test | Reason | Owner |
|---|---|---|---|---|
| ethereum/execution-spec-tests state tests at the pinned forks | limits | evm_conformance_execution_spec_tests | the EVM worker is not in the tree, so the state tests have a harness and no engine | WP-27 |
| forge create, forge script and cast | limits | evm_conformance_foundry | Foundry needs the Ethereum JSON-RPC gateway and the EVM worker together | WP-27 |
| Hardhat deploy | limits | evm_conformance_hardhat | the same two dependencies as the Foundry row | WP-27 |
| viem and ethers send a transaction | limits | evm_conformance_viem_and_ethers | the same two dependencies as the Foundry row | WP-27 |
| MetaMask as a custom network, by hand | limits | evm_conformance_metamask_custom_network | a manual case: it needs a person and a running gateway | WP-28 |
| OpenZeppelin contracts | limits | evm_conformance_openzeppelin | the state tests row is its precondition | WP-27 |
| Uniswap v2 core | limits | evm_conformance_uniswap_v2 | the state tests row is its precondition | WP-27 |

### 2.2 wasm

Counts: cases=3 pass=0 limits=3

| Case | State | Test | Reason | Owner |
|---|---|---|---|---|
| cw-plus: cw20-base, cw721-base, cw1, cw3, cw4 | limits | wasm_conformance_cw_plus | the CosmWasm worker is not in the tree, so the contracts have no host | WP-29 |
| the CosmWasm hackatom example | limits | wasm_conformance_hackatom | the same missing host as the cw-plus row | WP-29 |
| CosmJS SigningCosmWasmClient uploads, instantiates, executes and queries | limits | wasm_conformance_cosmjs | CosmJS needs the CometBFT subset and the worker together | WP-29 |

### 2.3 svm

Counts: cases=7 pass=0 limits=7

| Case | State | Test | Reason | Owner |
|---|---|---|---|---|
| the SPL Token program test suite | limits | svm_conformance_spl_token | the SVM worker is not in the tree | WP-31 |
| the Token-2022 program test suite | limits | svm_conformance_token_2022 | the SVM worker is not in the tree | WP-31 |
| the Associated Token Account program test suite | limits | svm_conformance_associated_token_account | the SVM worker is not in the tree | WP-31 |
| the Memo program test suite | limits | svm_conformance_memo | the SVM worker is not in the tree | WP-31 |
| solana program deploy | limits | svm_conformance_solana_deploy | the deploy path needs the Solana JSON-RPC subset and the worker | WP-31 |
| anchor deploy and anchor test | limits | svm_conformance_anchor | the same two dependencies as the deploy row | WP-31 |
| a transfer through @solana/web3.js | limits | svm_conformance_web3js_transfer | the same two dependencies as the deploy row | WP-31 |

### 2.4 move

Counts: cases=6 pass=0 limits=6

| Case | State | Test | Reason | Owner |
|---|---|---|---|---|
| the aptos-framework Move unit tests at the pinned revision | limits | move_conformance_framework_unit_tests | the Move worker is not in the tree | WP-32 |
| the hello_blockchain example | limits | move_conformance_hello_blockchain | the Move worker is not in the tree | WP-32 |
| the coin example | limits | move_conformance_coin | the Move worker is not in the tree | WP-32 |
| the fungible_asset example | limits | move_conformance_fungible_asset | the Move worker is not in the tree | WP-32 |
| aptos move publish and aptos move run | limits | move_conformance_aptos_cli | the Aptos REST subset and the worker together | WP-32 |
| a transfer through the Aptos TypeScript SDK | limits | move_conformance_aptos_ts_sdk | the same two dependencies as the publish row | WP-32 |

### 2.5 budzero

Counts: cases=2 pass=0 limits=2

| Case | State | Test | Reason | Owner |
|---|---|---|---|---|
| the in-tree BudZero test package through bud-cli | limits | budzero_conformance_test_package | the engine is in the tree and the suite has no runner yet, and this delivery adds no run | WP-35 |
| the zkVM contract call path with its per-block budget | limits | budzero_conformance_block_budget | the budget is a constant and the proof run needs the proving profile | WP-33 |

## 3. The limits of "runs unchanged" (Section 8.15)

| Ecosystem | Runs unchanged | Does not run unchanged |
|---|---|---|
| evm | bytecode, Solidity and Vyper, Foundry, Hardhat, viem, ethers, MetaMask as a custom network | blob transactions (type 3), eth_getProof (it needs an MPT and Budlum has a sparse Merkle tree), signatures pinned to the old chain id, external contracts that name the old network (price feeds, bridges), the EIP-4788 beacon root |
| wasm | CosmWasm bytecode that uses no float, CosmJS, cw-plus | IBC entry points, StakingMsg, DistributionMsg and GovMsg, which are refused by name, and any contract that uses a float |
| svm | program bytecode, Anchor, @solana/web3.js, the solana CLI | vote and stake programs, external programs that name the old network, and timing assumptions tied to the 400 ms slot |
| move | Move modules, the aptos CLI, the TypeScript SDK | the Aptos staking and governance modules, OIDC keyless accounts, and the exact timing of the Aptos randomness API, which binds to the Budlum epoch randomness |
| all | application code | the RPC address and the chain id change. That is what changing network means |

## 4. What the criterion needs and this delivery does not have

1. `uel_gas_calibration_bound` needs a measured table. Section 8.9 item 4 sets the
   bar at 1 BGU per 16 ns on the reference machine for the most expensive 5 percent
   of transaction types. Nothing in this delivery measured a nanosecond. The name
   is used by the lock test for the parameter arithmetic only, and the test fails if
   any row claims a measurement it does not have.
2. `uel_cross_arch_roots_equal` needs two runners, x86_64 and aarch64, and the
   golden block sequence of Section 8.16. The sandbox this delivery was written in
   has one architecture and no engine, so the row stays in the nightly job's scope
   and not here.
3. The runner crate. Section 8.13 item 1 puts the suites in `execution/conformance/`
   as Rust. That directory holds the plan today and no crate, because a crate that
   cannot build is a red job with no result: `execution/<environment>/` is a
   separate Cargo workspace (Section 8.14 item 1) and the first one lands with
   WP-27. `execution/conformance/README.md` writes the layout the runner will take.

## 5. The finding this delivery closes

| Field | Value |
|---|---|
| Id | BLG-280 |
| Severity | High (it is a block budget on a consensus path) |
| Area | Universal Execution Layer, BudZero environment |
| Title | The BudZero contract gas budget was larger than the block gas limit |
| Where | `src/execution/zkvm.rs`, `MAX_BLOCK_CONTRACT_GAS` |
| Class | a per-environment soft limit that exceeds the total block limit, against Section 8.9 item 3 |
| Live state | closed by this delivery |

What it was: `MAX_BLOCK_CONTRACT_GAS` was `64 * DEFAULT_CONTRACT_GAS_LIMIT`, that is
64 000 000 BGU, while the block limit of Section 8.9 item 2 is 60 000 000 BGU. At one
BudZero gas per BGU the two numbers are the same unit, so the budget of one
environment could not fit in the block that carries it: the cap the block code
enforces was unreachable, and the documentation of the block limit and the code of
the block budget disagreed by 4 000 000 BGU.

What it is now: `MAX_BLOCK_CONTRACT_GAS` is `BLOCK_GAS_LIMIT_BGU`, which is
60 000 000. The two names sit in one file and a compile-time assertion refuses a
build in which a single contract call limit exceeds the block limit. The behaviour
change is bounded: a block carries at most sixty full contract calls where it
carried sixty-four, so the refusal threshold moves by four calls and nothing else
moves. The existing test
`execution::zkvm::tests::a_block_over_the_contract_gas_budget_is_refused_before_execution`
derives its count from the constant, so it follows the change instead of pinning the
old number.

Evidence this delivery can give: the source lock in
`src/tests/conformance_locks.rs` (the table and the three constants agree) and the
compile-time assertion in `src/execution/zkvm.rs`. Evidence it cannot give: a CI run
number. The job that would produce one has not run on this branch, and Section 0.3
item 5 says a self report is not evidence, so this row does not claim a green run.
