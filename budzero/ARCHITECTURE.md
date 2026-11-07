# BudZKVM Architecture

BudZKVM is a ZKP-native Layer 1 execution environment designed from first principles for deterministic provability and high performance.

## 1. Programming Language: BudL (.bud)
- **Statically Typed**: Optimized for Goldilocks field arithmetic.
- **ZK-Intrinsics**: Native support for `poseidon()`, `constrain()`, and `emit()`.
- **State Management**: Built-in `storage` blocks and `Map<K, V>` structures.

## 2. Compiler Pipeline
- **Lexer**: Tokenizes source using `logos`.
- **Parser**: Recursive descent parser building an Abstract Syntax Tree (AST).
- **Sema**: Semantic analyzer for symbol resolution and type checking.
- **Codegen**: Translates AST to Bud-ISA bytecode with jump patching.

## 3. Virtual Machine: BudVM
- **Register-based ISA**: 32 general-purpose 64-bit registers.
- **Execution Trace**: Records every state transition (PC, registers, opcodes) for proving.
- **Syscalls**: Host-provided context (sender, block height).
- **Events**: Off-chain log buffer.

## 4. Proving Layer: bud-proof
- **Trace Matrix**: Converts VM trace into a row-major execution matrix.
- **STARK Prover**: Generates deterministic proofs based on field-accumulated trace hashes.
- **Segment & Batch Folding (Post-Launch Staged)**: `bud-proof` verifies individual program STARK proofs at testnet launch; binary segment recursion and `D = 8` block batch proofs (`src/cross_domain/external/phase_a_dual.rs`) are height-gated for post-launch activation. In-circuit Poseidon2 uses width 12 (`POSEIDON_G12_V1`).

## 5. State Layer: bud-state
- **Merkle Roots**: XOR-based state accumulation for account and storage integrity.
- **Account Model**: Tracking nonces and balances.

## Execution Flow
`Source (.bud)` -> `Bytecode` -> `VM Execution` -> `Trace` -> `STARK Proof` (-> post-launch staged segment folding)
