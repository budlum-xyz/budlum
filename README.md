# Budlum Core

**Universal Settlement Layer** for a post-quantum, multi-consensus world.

Budlum is a research-grade Layer-1 that does **not** replace other chains. It **settles** them: each domain keeps its own consensus (PoW, PoS, PoA, BFT, ZK, or custom); Budlum verifies finality proofs and records cross-domain value transfer as cryptographic fact.

[![CI](https://github.com/lubosruler/budlum/actions/workflows/ci.yml/badge.svg)](https://github.com/lubosruler/budlum/actions)
[![Tests](https://img.shields.io/badge/tests-450%20lib-blue)](https://github.com/lubosruler/budlum)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

> **Controlled public-devnet candidate (v0.3-dev)**  
> Suitable for research and controlled experiments with explicit risk disclosure.  
> **Not** audited mainnet software. **Do not** use for real-value production traffic.

---

## Why Budlum

| Problem today | Budlum shift |
| --- | --- |
| Quantum break of ECDSA/Ed25519 (~2030–35) | **BLS + Dilithium5 hybrid finality** in the core path |
| 20k+ isolated chains | **Universal Settlement Layer** — verify any domain’s finality |
| CBDC / sovereign silos | Domains + trust-minimized bridge lifecycle |
| TradFi (PoA) vs DeFi (PoS) wall | Same `GlobalBlockHeader` settlement record |
| Bridge hacks ($2.5B+) | Lock → mint → burn → unlock with proof gates |
| AI agents without settlement | BudZKVM STARK execution (sibling repo) |

Strategic analysis: [`docs/03_paradigma_analizi.md`](docs/03_paradigma_analizi.md).

---

## Architecture

```
   PoW domain    PoS domain    PoA domain    ZK / Custom
        \             |             |             /
         \            |             |            /
          v           v             v           v
        DomainFinalityAdapter  (per-consensus proof)
                          |
                          v
              ┌───────────────────────────┐
              │   BUDLUM SETTLEMENT L1    │
              │  GlobalBlockHeader        │
              │  BridgeState + nonces     │
              │  BudZKVM proofs (BudZero) │
              └───────────────────────────┘
```

**Crates / layout**

| Path | Role |
| --- | --- |
| `src/consensus/` | PoW · PoS · PoA engines |
| `src/domain/` | Domain registry, finality adapters |
| `src/cross_domain/` | Bridge, messages, replay protection |
| `src/chain/` | Blockchain, finality (BLS/QC), snapshots |
| `src/execution/` | Tx executor + BudZKVM host |
| `src/rpc/` | JSON-RPC (auth, IP, CORS, rate limits) |
| `src/crypto/` | Ed25519, BLS, Dilithium, PKCS#11 |

Sibling execution layer: **[BudZero](https://github.com/lubosruler/BudZero)** (BudZKVM + STARK prover).

---

## Quick start

```bash
# Requires Rust 1.94+, protoc
git clone https://github.com/lubosruler/budlum.git
cd budlum

# BudZero must sit as a sibling checkout (CI pins a known-good ref)
git clone https://github.com/lubosruler/BudZero.git ../BudZero

cargo build --release
cargo test --lib
cargo run -- --network devnet
```

**Mainnet validators:** PKCS#11 is required for consensus signing. Disk-backed `ValidatorKeys` (BLS + PQ material) are **rejected on mainnet** until HSM paths exist for those secrets (Tur 12.5).

---

## Security posture (selected)

Hardening is iterative (Tur 9–12.5). Highlights:

- Cheap tx checks before signature verify (DoS)
- Governance: validator-only proposals, fee/reward bounds, registry param validation
- Bridge mint requires `expected_block_hash`; **PoW-domain mint disabled** until light-client PoW
- PoA leader selection uses hash-mix (not pure round-robin)
- BLS keypair load validates G2 encoding and `pk = g·sk`
- RPC: auth default on for operator profiles; **X-Real-IP only if `trusted_proxies` set**; constant-time API key compare
- BudZKVM `VerifyMerkle` gated off in Production ISA until Z-B Commit 3.5

This is **not** a substitute for a professional external audit.

---

## Development

```bash
cargo fmt --all -- --check
cargo clippy --lib --tests -- -D warnings
cargo test --lib          # 450 unit/integration tests (lib)
```

CI (GitHub Actions): fmt → clippy `-D warnings` → `cargo test --lib`, with BudZero checked out as a sibling.

---

## Status & roadmap

| Area | State |
| --- | --- |
| Multi-consensus domains | Implemented |
| BLS + Dilithium QC finality | Implemented |
| Bridge lifecycle | Implemented + forgery gates |
| BudZKVM host | Path-dependent on BudZero pin |
| Full Z-B Merkle soundness | In progress (ignore + prod gate) |
| PoW light-client finality | Partial (hash work + mint ban) |
| BLS/PQ HSM | Not yet — disk keys banned on mainnet |

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Prefer small, tested PRs that keep CI green.
