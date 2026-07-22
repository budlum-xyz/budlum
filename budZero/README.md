# BudZero — BudZKVM

STARK-provable execution for **[Budlum](https://github.com/lubosruler/budlum)**’s Universal Settlement Layer.

A compact deterministic ISA, a gas-metered VM that emits execution traces, and a [Plonky3](https://github.com/Plonky3/Plonky3) 0.5.x STARK prover/verifier. Domains produce state; BudZKVM proves the computation that produced it.

[![CI](https://github.com/lubosruler/budlum/actions/workflows/ci.yml/badge.svg)](https://github.com/lubosruler/budlum/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
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
git clone https://github.com/lubosruler/budlum.git
cd budlum/budzero

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

**Feature flags**

| Feature | Effect |
| --- | --- |
| default | **Production** ISA — experimental opcodes (e.g. `VerifyMerkle`) rejected at decode |
| `experimental` | Enables experimental opcodes for ZK harness / research (`bud-proof` enables this for itself) |

---

## Soundness work (honest status)

Aligned with [budlum-xyz/BudZero](https://github.com/budlum-xyz/BudZero) phases 0–12. Org README claims “all 31 opcodes production”; **this fork keeps `VerifyMerkle` experimental** until the 64-depth positive proof is green.

| Item | Status |
| --- | --- |
| Public inputs (Z-A) | Bound (incl. event_digest Log fix Phase 0.358) |
| `VerifyMerkle` path AIR (Z-B) | Expansion + Poseidon round checks; **Phase 0.36 partial**: pre-round currents, single-round path hash, original-only root check, expand gas |
| Valid 64-depth prove | **`#[ignore]`** — still `InvalidProof` (Commit 3.5 remaining) |
| Production gate | `VerifyMerkle` **experimental** — off in Production decode |
| Termination / halt (Z-C/D) | Landed Phase 0.30.zk |
| Storage gas (SRead/SWrite) | Higher than Load/Store; AIR aligned |
| Phase 10 performance benches | Planned Tur **13.5** |
| Phase 11 external audit | Checklist Tur **13.9** (not claimed done) |

Until Z-B Commit 3.5 lands, do **not** treat Merkle membership inside STARK proofs as production-safe. **B.U.D.** proof-of-storage (org storage vision) is **Phase 0.38**, not this repo’s L1 host work.

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
3. `cargo test --workspace` — **124 test geçerli sayım** (CI-kanıtlı, 2026-07-18)

Modül-ayrımı kuralı (Phase 10 §4): bu sayı kök README'nin dashboard tablosunda
kendi satırında raporlanır; toplam Core sayısına (755 lib) karışmaz.

No `#[allow(clippy::…)]` as a substitute for fixing lints on new work.

---

## Relationship to Budlum

The root CI runs Budlum and this complete workspace from the same checkout.
There is no external pin to drift: any prover/verifier change must pass both CI
jobs in one commit.

---

## License

MIT — see [LICENSE](LICENSE).

## See also

- [Budlum L1](https://github.com/lubosruler/budlum) — settlement, bridge, multi-consensus
- Paradigm analysis in the L1 `docs/` tree
