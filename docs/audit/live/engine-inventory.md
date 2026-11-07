# Execution engine inventory

The catalog of the Universal Execution Layer, measured against the tree at
`20140e87061efc9d8d4076e04305c1318705e348` plus the branch that adds this file.
The package that owns this document is WP-03, and its done criterion asks for
engine, version, licence and the `cargo-deny` pre-check.

## What the directive requires

Section 8.2 names five execution environments and the engine each one is meant
to be built on:

| Environment | Engine named by the directive | Testnet at launch |
|---|---|---|
| EVM | `revm` | Open (WP-27) |
| WASM (CosmWasm ABI) | `wasmi` | Open (WP-29) |
| SVM | `solana-svm` and `solana-sbpf` | Open (WP-31) |
| Move (Aptos dialect) | `aptos-vm` | Open (WP-32) |
| BudZero | the in-tree `bud-vm` | Open (WP-33) |

## What the tree contains

| Engine | Present as a dependency | Version | Licence | `cargo-deny` pre-check |
|---|---|---|---|---|
| `revm` | No | not measured | not measured | not run |
| `wasmi` | No | not measured | not measured | not run |
| `solana-svm` | No | not measured | not measured | not run |
| `solana-sbpf` | No | not measured | not measured | not run |
| `aptos-vm` | No | not measured | not measured | not run |
| `bud-vm` (in-tree, `budzero/bud-vm`) | Yes, a workspace member | see `budzero/Cargo.toml` | `LicenseRef-PolyForm-Shield-1.0.0` | not run |

Measurement: `Cargo.lock` has no `revm`, `wasmi`, `solana-svm`, `solana-sbpf`,
`solana-program` or `aptos-vm` package entry, and no manifest in the tree names
one. `src/execution/` contains three modules: `executor.rs`, `proof_verifier.rs`
and `zkvm.rs`.

The only execution path that exists is the in-tree BudZero VM. A
`TransactionType::ContractCall` transaction executes its own bytecode through
`ZkVmExecutor::execute_bytecode`, and `src/execution/zkvm.rs` fixes the memory
at 8192 bytes per call. That is a stateless contract VM, not one of the five
catalog entries, and BLG-248 is the finding that says so.

## What is not measured here, and why

1. **Licences.** A crate's licence field lives in its manifest inside the
   registry cache. This environment has no cargo, no registry cache and no
   network access to `crates.io`, so every licence cell says "not measured"
   rather than a guess. `.quality/deny.toml` sets the allow-list the tree is
   held to; the per-engine answer needs `cargo metadata` or a vendored tree.
2. **The `cargo-deny` pre-check.** `cargo` is absent, so the check cannot run.
   A row that says "not run" is the honest record; a row that said "allowed"
   without the run would be the gate failure this document exists to prevent.
3. **Versions.** "Newest stable at the analysis date" is a measurement of a
   registry, not of the tree. Since no engine is a dependency, there is no
   version in the tree to report, and reporting an upstream number would
   suggest an integration that does not exist.

## Consequence

The WPs that add the five environments (WP-26 for the coordinator and the
worker ABI, WP-27, WP-29, WP-31, WP-32 and WP-33 for the environments) have no
dependency edge in the tree yet. The testnet feature matrix rows that say
"Open" for EVM, WASM, SVM and Move describe the launch target, not the current
state: nothing in the tree can execute an EVM, WASM, SVM or Move program.
