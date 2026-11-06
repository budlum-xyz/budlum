# Execution engine inventory (WP-03)

WP-03 special audit: the directive section 8.2 engine catalog with versions
and licenses, and the `cargo-deny` pre-audit state. English per
`tree_is_english`. Verification base: `HEAD` = `cccf1da` (`main`).

## Headline state

**No external execution engines are vendored in this snapshot.** The
Universal Execution Layer exists only as the `crates/uel-abi` interface
skeleton (frame, host, mock, transport, types, wire) plus the test-net-gated
external adapters for Ethereum finality verification. The EVM (revm), WASM
(wasmi), SVM (solana-svm/solana-sbpf) and Move (aptos-vm) engines are not
dependencies of the workspace: none of those crate names appear in
`Cargo.lock` (637 packages). WP-26 (İP-26, blocked on İP-07 ← PR #8) builds
the coordinator and EE workers; each engine lands with its own package
(WP-27/29/31/32, blocked on İP-26).

What follows is the inventory of what *is* in the tree, because BudZero runs
an in-house STARK stack and the crypto primitives are shared with it.

## In-tree proving / execution stack (BudZero)

| Engine | Version | License (as declared in-tree) | cargo-deny state |
|---|---|---|---|
| p3-air / p3-challenger / p3-commit / p3-dft / p3-field / p3-fri / p3-goldilocks / p3-keccak / p3-matrix / p3-maybe-rayon (plonky3) | 0.7.0 (all p3-* in `Cargo.lock`) | MIT/Apache-2.0 (upstream) | Not re-audited locally (no toolchain); supply-chain gates exist (`cargo_vet`, `supply-chain/`, `cargo-vet.yml` workflow, `deny.toml`) |
| budzero/bud-vm (Budlum interpreter) | workspace `budzero/` (PolyForm Shield 1.0.0 at workspace root) | LicenseRef-PolyForm-Shield-1.0.0 | covered by workspace gates |
| budzero/bud-proof (STARK verifier, `bud_stark`, Plonky3Adapter) | workspace `budzero/` | LicenseRef-PolyForm-Shield-1.0.0 | covered by workspace gates |
| budzero/bud-isa, bud-state, bud-pul, verifier-registry | workspace `budzero/` | LicenseRef-PolyForm-Shield-1.0.0 | covered by workspace gates |
| bud-compiler / bud-cli (BudL toolchain) | workspace `budzero/` | LicenseRef-PolyForm-Shield-1.0.0 | covered by workspace gates |
| crates/uel-abi (the İP-09 interface) | workspace root | LicenseRef-PolyForm-Shield-1.0.0 | `crates/uel-abi` carries its own `Cargo.lock` |

## Crypto primitives (shared with consensus) — from `Cargo.lock`

| Crate | Version(s) |
|---|---|
| bls12_381 | 0.9.0 |
| ed25519-dalek | 2.2.0, 3.0.0 (two lines in the tree) |
| k256 | 0.14.0 |
| p256 | 0.14.0 |
| ml-dsa | 0.1.1 |
| sha2 | 0.10.9, 0.11.0 (two lines) |
| blake3 | see Cargo.lock (present) |

## Engines named in directive section 8.2, checked present/absent

| Engine (section 8.2) | Present | Notes |
|---|---|---|
| revm | **absent** | WP-27 (İP-27) will introduce it; license check owed then (MIT/Apache-2.0 upstream) |
| wasmi | **absent** | WP-29 (İP-29, CosmWasm ABI) |
| solana-svm / solana-sbpf | **absent** | WP-31 (İP-31) |
| aptos-vm / move-vm | **absent** | WP-32 (İP-32) |
| cosmwasm (production vm.rs) | **absent** | WP-29 |
| budzero (BudL interpreter + STARK) | present | see above |
| zkVM (in-house) | present | `src/execution/zkvm.rs`, `ZkVmExecutor` |

## cargo-deny pre-audit

No local Rust toolchain exists in this environment, so `cargo deny check` was
not run here. The structural controls in the tree: `deny.toml`, `cargo_vet`
gate (`xtask/gates/src/gates/cargo_vet.rs`), `.github/workflows/cargo-vet.yml`,
`supply-chain/` directory, `osv-scanner.toml`, and the `advisory_reachability`
lock (`src/tests/advisory_reachability.rs`). The two crypto lines carried
twice in `Cargo.lock` (ed25519-dalek 2.2.0 + 3.0.0, sha2 0.10.9 + 0.11.0)
should be consolidated when İP-26 lands the engine dependency set; BLG-016
tracks the six-lockfile RustSec finding.

## Conclusions for the directive's engine rule (8.2)

1. No engine ships today, so no engine has a license violation today. The
   risk register opens at İP-26/27/29/31/32: each engine introduction must
   regenerate this inventory in the same PR.
2. The bridge for external finality verification *is* wired in production
   (see `docs/audit/live/lane-c.md`, BLG-235): `EthereumSyncAdapter::new` is
   constructed on the production intake path (`src/cross_domain/external/intake.rs:188`).
3. BudZero's proving stack is in-house (no external STARK engine license to
   track), but its parameters are the live audit surface (see lane C rows
   BLG-036..142, 154, 159, 182, 191).
