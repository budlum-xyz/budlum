# Budlum Core

**Universal Settlement Layer** for a post-quantum, multi-consensus world.

Budlum is a research-grade Layer-1 that does **not** replace other chains. It **settles** them: each domain keeps its own consensus (PoW, PoS, PoA, BFT, ZK, or custom); Budlum verifies finality proofs and records cross-domain value transfer as cryptographic fact.

[![CI](https://github.com/lubosruler/budlum/actions/workflows/ci.yml/badge.svg)](https://github.com/lubosruler/budlum/actions)
[![Tests](https://img.shields.io/badge/tests-452%20lib-blue)](https://github.com/lubosruler/budlum)
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
| AI agents without settlement | In-tree BudZKVM STARK execution |

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
| `budzero/` | BudZKVM ISA, VM, compiler, state and STARK prover workspace |

Since Tur 13.5, **BudZero is integrated into this repository**. The former
`lubosruler/BudZero` repository is historical input, not a build-time dependency.

---

## Quick start

```bash
# Requires Rust 1.94+, protoc
git clone https://github.com/lubosruler/budlum.git
cd budlum

# L1 (uses the in-tree budzero crates)
cargo build --release
cargo test --lib

# Full BudZero/BudZKVM workspace
cargo test --manifest-path budzero/Cargo.toml --workspace

cargo run -- --network devnet
```

**Mainnet validators:** PKCS#11 is required for consensus signing. Disk-backed `ValidatorKeys` (BLS + PQ material) are **rejected on mainnet** until HSM paths exist for those secrets (Tur 12.5).

---

## Security posture (selected)

Hardening is iterative (Tur 9–12.5). Highlights:

- Cheap tx checks before signature verify (DoS)
- Governance: validator-only proposals, fee/reward bounds, registry param validation
- Bridge mint requires `expected_block_hash`; PoW mint requires a bounded, recomputed `pow-header-chain-v1` proof (legacy declared-depth proofs stay mint-gated)
- PoA leader selection uses hash-mix (not pure round-robin)
- BLS keypair load validates G2 encoding and `pk = g·sk`
- RPC: public auth fail-closed; operator methods are mode-gated/localhost-only; **X-Real-IP only if `trusted_proxies` set**; constant-time API key compare
- BudZKVM `VerifyMerkle` gated off in Production ISA until Z-B Commit 3.5
- BudZero event-digest AIR/public-input alignment retained and its crates moved in-tree (Tur 13.5)

This is **not** a substitute for a professional external audit.

---

## Development

```bash
cargo fmt --all -- --check
cargo clippy --lib --tests -- -D warnings
cargo test --lib          # 452 unit/integration tests (lib)
```

CI (GitHub Actions): separate fmt → clippy `-D warnings` → test gates for the L1 and the in-tree BudZero workspace.

---

## Status & roadmap

Aligned with [budlum-xyz/Budlum](https://github.com/budlum-xyz/Budlum) Research Roadmap + ch12 mainnet blockers. Full matrix: `TUR13_ORG_ROADMAP_AUDIT.md` (working notes) and below.

| Area | State | Org roadmap |
| --- | --- | --- |
| Multi-consensus domains | Implemented | ✓ |
| BLS + Dilithium QC finality | Implemented | ✓ |
| Bridge lifecycle | Implemented + forgery gates; PoW mint only after applied header-chain finality | ✓ Tur 13.5 |
| BudZKVM host | In-tree `budzero/` workspace; one-commit compatibility boundary | ✓ Tur 13.5 |
| Full Z-B Merkle soundness | Partial fixes Tur 13; **Production-gated** until positive 64-depth green | BudZero Phase 5 claim vs reality |
| PoW light-client finality | Bounded contiguous headers; recomputed hash/link/root/difficulty/work; legacy proof mint-gated | ✓ Tur **13.5** |
| BLS/PQ HSM (beyond Ed25519 PKCS#11) | Disk keys banned on mainnet; full HSM path open | Tur **13.9** |
| Personas (user / developer / enterprise PoA) | `config/personas/*` + [docs/PERSONAS.md](docs/PERSONAS.md) | Tur **13** |
| Archive/backup/runbooks | Archive fail-closed policy, atomic verified backup + restore drill, PoA/RPC/HSM runbook | ✓ Tur **13.5** |
| BudZero performance | Reproducible proof time/size baseline harness | ✓ baseline Tur **13.5** |
| B.U.D. storage network | Out of scope here | **Tur 14** only |
| External audit / TLA+ / Privacy / AI | Process / research — not claimed done | Checklist Tur 13.9 |

### Personas (same binary)

Operational guides: [production / enterprise PoA](docs/operations/PRODUCTION_RUNBOOK.md)
and [archive backup/restore](docs/operations/ARCHIVE_AND_BACKUP.md).

```bash
cargo run -- --config config/personas/user-devnet.toml
cargo run -- --config config/personas/developer.toml
# enterprise-poa.toml requires PKCS#11 + env secrets; no disk ValidatorKeys
```

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Prefer small, tested PRs that keep CI green.
