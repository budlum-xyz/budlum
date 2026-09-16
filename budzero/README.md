# BudZero: BudZKVM

STARK-provable execution for **[Budlum](https://github.com/budlum-xyz/budlum)**’s Universal Settlement Layer.

A compact deterministic ISA, a gas-metered VM that emits execution traces, and a [Plonky3](https://github.com/Plonky3/Plonky3) 0.5.x STARK prover/verifier. Domains produce state; BudZKVM proves the computation that produced it.

[![CI](https://github.com/budlum-xyz/budlum/actions/workflows/ci.yml/badge.svg)](https://github.com/budlum-xyz/budlum/actions)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm_Shield_1.0.0-blue.svg)](../LICENSE.md)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org/)

---

## Role in the stack

```
  Consensus domains (PoW / PoS / PoA / BFT / ZK)
                    │
                    ▼
         Budlum L1 settlement (proofs + bridge)
                    │
                    ▼
         ┌─────────────────────┐
         │  BudZero (this repo) │
         │  ISA · VM · STARK    │
         └─────────────────────┘
```

Budlum-core depends on `bud-isa`, `bud-vm`, and `bud-proof` directly from this
in-tree workspace (`budzero/`). L1 and proof-system compatibility now share one
repository commit.

---

## Workspace crates

| Crate | Purpose |
| --- | --- |
| `bud-isa` | Opcode set, encode/decode, **Production vs Testing profiles** |
| `bud-vm` | Interpreter, gas, storage ops, trace emission |
| `bud-proof` | Plonky3 AIR, prover, verifier, public inputs |
| `bud-compiler` | BudL → bytecode |
| `bud-state` | Account state + nested transaction backup stack |
| `bud-cli` / `bud-node` | Tooling |

---

## Quick start

```bash
git clone https://github.com/budlum-xyz/budlum.git
cd budlum/budzero

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

**Feature flags**

| Feature | Effect |
| --- | --- |
| default | **Production** ISA, experimental opcodes (e.g. `VerifyMerkle`) rejected at decode |
| `experimental` | Enables experimental opcodes for ZK harness / research (`bud-proof` enables this for itself) |

---

## Soundness work (honest status)

This crate set is the [`budzero/`](./) tree **inside this monorepo** (there is no separate `budlum-xyz/BudZero` checkout; this is the source). **Z-B:** `proves_verify_merkle_valid_64_depth` is green. VerifyMerkle is **mainnet-gated** (`MainnetActivation`, default off) with a staged ceremony rollout; this is not the same as the old experimental-ISA lock.

| Item | Status |
| --- | --- |
| Public inputs (Z-A) | Bound (incl. event_digest Log fix ) |
| `VerifyMerkle` path AIR (Z-B) | Expansion + Poseidon round checks; pre-round currents, single-round path hash, original-only root check, expand gas |
| Valid 64-depth prove | OK `proves_verify_merkle_valid_64_depth` green (matrix chain + full prove/verify) |
| Production gate | `MainnetActivation` default **off** (staged ceremony rollout); ISA `is_experimental()==false` |
| `VerifyInference` | Opcode, gas and activation gate exist; **no verification circuit yet**, so the gate stays off and no proof claims inference correctness |
| Termination / halt (Z-C/D) | Landed .zk |
| Storage gas (SRead/SWrite) | Higher than Load/Store; AIR aligned |
|  performance benches | Planned Tur **13.5** |
|  external audit | Checklist Tur **13.9** (not claimed done) |

Z-B 64-depth soundness proof is green. Merkle membership inside STARK proofs is
cryptographically constrained; mainnet still requires `MainnetActivation` flip
post-ceremony. **B.U.D.** proof-of-storage productization remains a separate
integration  on top of this L1 primitive.

---

## Gas (selected)

| Opcode | Gas |
| --- | --- |
| Load / Store | 3 |
| SRead | 8 |
| SWrite | 12 |
| Poseidon / VerifyMerkle | 10 |

---

## State (`bud-state`)

- Nested transactions use a **LIFO `backup_stack`** (not a single-slot backup).
- `State::save()` returns `Result` (no process-killing `expect` on I/O failure).

---

## Development gates

CI enforces:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` (run from `budzero/`): the count is whatever CI
   measures on the current tree; it is not copied into this file, because a
   copied number drifts the moment a test is added.

The module separation rule: the BudZero count is reported on its own row in
the root README dashboard table; it is not mixed into the Core count.

No `#[allow(clippy::…)]` as a substitute for fixing lints on new work.

---

## Relationship to Budlum

The root CI runs Budlum and this complete workspace from the same checkout.
There is no external pin to drift: any prover/verifier change must pass both CI
jobs in one commit.

---

## License

PolyForm Shield 1.0.0, see [LICENSE.md](../LICENSE.md).

## See also

- [Budlum L1](https://github.com/budlum-xyz/budlum), settlement, bridge, multi-consensus
