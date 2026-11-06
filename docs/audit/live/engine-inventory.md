# Execution engine inventory (WP-03 special audit 1)

Directive section 15.8, WP-03 (İP-03) special audit 1 asks for the section 8.2
catalog engines: the engine, its version, its licence file, and the `cargo-deny`
pre-check result. This file is that inventory, verified against the live tree at
`cccf1da`.

## The one measured fact

**No engine from the section 8.2 catalog is a dependency of any workspace in
this tree.** The verification is mechanical and repeatable:

```
grep -rn "revm\|wasmi\|solana-svm\|solana-sbpf\|solana_rbpf\|aptos-vm\|sui-execution\|near-vm-runner"
  Cargo.toml Cargo.lock crates/*/Cargo.toml budzero/Cargo.toml crates/uel-abi/Cargo.toml
```

returns no entry. `crates/uel-abi` is the worker ABI (frame, host, wire, mock,
transport) and carries no engine. `src/execution/ee.rs` states the state of the
wiring in its own words: `WIRING: unwired - the Execution Coordinator is the
first consumer of [EeClient]; this module is where it attaches`.
`src/execution/coordinator/mod.rs` is a declaration with a `WIRING` note that
"a later step builds the coordinator itself".

Therefore:

- There is **no version** to read from `Cargo.lock` for any of the five engines
  the card names.
- There is **no licence file** in the registry cache to read, because nothing is
  in the cache.
- There is **no `cargo-deny` result** to report, because the dependency graph
  does not contain the crate. The pre-check below is a policy check against the
  allow list, not a scan.

The directive's measurement rule (section 0.5) forbids writing a number that was
not measured. No version here is invented, and no "newest stable at analysis
time" is claimed beyond what section 8.2 itself records.

## Catalog rows the card names

| Engine | Catalog id | Environment | Version recorded in section 8.2 | Licence in section 8.2 | In the tree | `cargo-deny` policy pre-check |
|---|---|---|---|---|---|---|
| `revm` | `0x01` | EVM (Solidity, Vyper, Yul, Huff, Fe) | `=43.x`; `43.0.3` was the newest stable at analysis time | MIT | No | Passes: `MIT` is on the allow list in `.quality/deny.toml` |
| `wasmi` | `0x02` | WASM, CosmWasm ABI | Not pinned in section 8.2 (the ABI layer is in-tree) | MIT or Apache-2.0 | No | Passes: both licences are on the allow list |
| `solana-svm` | `0x03` | SVM | Agave line, pinned at add time; no number in section 8.2 | Apache-2.0 | No | Passes: `Apache-2.0` is on the allow list |
| `solana-sbpf` | `0x03` | SVM (BPF loader; JIT off) | Agave line, pinned at add time; no number in section 8.2 | Apache-2.0 | No | Passes: `Apache-2.0` is on the allow list |
| `aptos-vm` | `0x04` | Move, Aptos dialect | Fixed `aptos-core` commit at add time; no number in section 8.2 | Apache-2.0 | No | Passes: `Apache-2.0` is on the allow list. Note: `aptos-vm` drags `move-*` crates; the licence check must be run on the resolved graph, not on the root crate |

The licence policy that applies is `.quality/deny.toml`: every licence not on the
`allow` list fails, which refuses the GPL/AGPL/LGPL family by construction. The
list is `MIT`, `Apache-2.0`, `BSD-3-Clause`, `BSD-2-Clause`, `CC0-1.0`, `ISC`,
`OpenSSL`, `Zlib`, `Unicode-3.0`, `CDLA-Permissive-2.0`, `NCSA` and the
repository's own `LicenseRef-PolyForm-Shield-1.0.0`. The BudZero workspace has its
own counterpart at `budzero/deny.toml`, which is checked as a separate graph.

## What the adding packages must do (WP-27, WP-29, WP-31, WP-32)

The inventory cannot be completed before the engine exists. Each package that
adds an engine writes its own row here in the same PR that adds the dependency:

1. The exact version, pinned with `=` the way `raptorq` and `hpke` are pinned in
   the root manifest.
2. The licence SPDX identifier as `cargo-deny` reports it, plus the path to the
   licence file in the crate source.
3. The `cargo deny check licenses` output line for the resolved graph.
4. The interpreter-only confirmation (section 8.2 rule 3: no JIT on the
   consensus path). The SVM entry in particular is JIT-capable upstream; the
   package must show the JIT is off.
5. The process boundary chosen for BLG-250. `panic = "abort"` is in
   `[profile.release]`, so an engine that panics inside the node process takes
   the node down. The engine must run behind `crates/uel-abi`'s transport
   (`EeClient`) in a worker process, or the profile must change with a written
   decision.

## Environment roster of the live tree

| Environment | Catalog row | Live state |
|---|---|---|
| BudZero (in-tree) | `0x00` | `budzero/bud-vm`, `budzero/bud-isa`, `budzero/bud-proof`; bytecode runs and proves |
| BudZero RV32 | `0x0C` | Not present (`budzero/bud-isa` has one ISA, BLG-234) |
| EVM, WASM/CosmWasm, SVM, Move(Aptos) | `0x01`-`0x04` | Not present |
| Move(Sui), Cairo, NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | `0x05`-`0x0B` | Not present; all are T-Genişleme (İP-50, İP-51, İP-53) |

This table is the input to TLG items 6 and 7. Both are red until at least
`0x01`, `0x02`, `0x03`, `0x04` and `0x00` exist and the cross-environment call
path of İP-30 exists.
