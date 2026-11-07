# UEL Execution Limits and Launch Refusal Matrix

This table records every intentional T-Launch execution boundary and upstream
feature exclusion specified in section 8.15 of the Budlum architecture (`WP-35`).
Every row names the module that enforces the refusal and the automated test that
locks it.

| Environment | Excluded or Bounded Feature | Rationale (Section 8.15) | Enforcing Module | Verification Test |
|---|---|---|---|---|
| EVM (`0x01`) | EIP-4844 type-3 blob transactions (`BLOBHASH`, `BLOBBASEFEE`) | Object storage lives in B.U.D. 3.0 rather than ephemeral EVM blobs | `src/execution/coordinator/foreign/ethereum.rs` | `evm_blob_tx_refused` |
| EVM (`0x01`) | `SELFDESTRUCT` full account deletion | Prague EIP-6780 semantics apply; full code deletion outside same-tx creation is disabled | `src/execution/coordinator/evm_ee.rs` | `uel_conformance_evm` |
| EVM (`0x01`) | EIP-3860 initcode above `49,152` bytes | Bounds deploy metering and worker frame size | `src/execution/coordinator/evm_ee.rs` | `uel_conformance_evm` |
| Ethereum RPC | `eth_getProof` (`-32601` Method not found) | `execution_root` is a depth-256 sparse binary Merkle tree, not an Ethereum hexary MPT; proofs are served by `bud_getExecutionProof` | `src/rpc/compat/ethereum.rs` | `eth_get_proof_returns_method_not_found` |
| WASM (`0x02`) | Floating-point value types (`f32`, `f64`), float opcodes (`0x2a..0x2b`, `0x38..0x39`, `0x43..0x44`, `0x5b..0x66`, `0x8b..0xa6`, `0xb2..0xbf`), and `0xfc:0..=7` `trunc_sat` | Prevents NaN payload non-determinism across x86_64 and aarch64 | `src/execution/coordinator/wasm_ee.rs` | `wasm_float_code_refused` |
| WASM (`0x02`) | Linear memory above `1,024` pages (`64 MiB`) | Bounds worker memory per contract invocation | `src/execution/coordinator/wasm_ee.rs` | `uel_conformance_wasm` |
| WASM (`0x02`) | IBC entry points (`ibc_*`) and `StakingMsg` / `DistributionMsg` / `GovMsg` / `IbcMsg` | Cross-domain settlement and staking belong to Budlum native consensus | `src/execution/coordinator/wasm_ee.rs` | `wasm_ibc_entry_points_refused` |
| SVM (`0x03`) | SBPF JIT compilation (`jit_enabled = false`) | Guarantees cross-architecture interpreter determinism and eliminates JIT gadget surface | `src/execution/coordinator/svm_ee.rs` | `svm_jit_is_disabled` |
| SVM (`0x03`) | Solana Vote and Stake built-in programs | Consensus voting and validator staking belong exclusively to Budlum native validator seats | `src/execution/coordinator/svm_ee.rs` | `uel_conformance_svm` |
| Move (`0x04`) | Block-STM parallel execution (`block_stm_parallel = false`) | Sequential deterministic execution at T-Launch (parallel scheduling deferred to `WP-59`) | `src/execution/coordinator/move_ee.rs` | `move_sequential_randomness_staking_refusal_and_universal_call` |
| Move (`0x04`) | Aptos staking and governance framework modules (`0x1::stake`, `0x1::aptos_governance`, `0x1::voting`, `0x1::delegation_pool`) | Staking and governance belong to Budlum native protocol | `src/execution/coordinator/move_ee.rs` | `uel_conformance_move` |
| Move (`0x04`) | Aptos OIDC keyless accounts | Classical/OIDC witness complexity excluded at T-Launch | `src/execution/coordinator/foreign/aptos.rs` | `uel_foreign_tx_replay_refused` |
| BudZero (`0x00`) | `VerifyMerkle` and `VerifyInference` proof-dependent consensus opcodes | Closed on testnet pending full 64-depth Merkle and AI inference circuit soundness (`BLG-223`, `BLG-226`) | `src/execution/budzero_ee/mod.rs` | `verify_merkle_is_closed_on_testnet`, `verify_inference_is_closed_on_testnet` |
| All EEs | Cross-environment re-entrancy (`A -> B -> A`) and call depth `> 8` | Each stateless worker holds one execution stack at T-Launch (`ReentrancyForbidden`) | `src/execution/coordinator/overlay.rs` | `uel_reentrancy_across_ees_refused`, `uel_call_depth_cap_enforced` |
| Foreign Lane | Classical foreign account touching post-quantum holdings (K-3) | Prevents quantum key compromise of classical ECDSA/Ed25519 accounts from draining PQ holdings | `src/execution/coordinator/foreign/mod.rs` | `foreign_account_cannot_touch_pq_holding` |
