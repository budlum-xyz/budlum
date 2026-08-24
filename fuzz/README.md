# Fuzzing

> **Status:** the setup is complete. Long fuzz runs are not executed in CI; the
> build/check plus manual runs are used in preparation for an external audit or
> for mainnet.

## Fuzz targets

| Target | Purpose | Status |
|--------|---------|--------|
| `block_deserialize` | Random bytes -> `Block` bincode deserialize, panic/DoS check | Present |
| `transaction_deserialize` | Random bytes -> `Transaction` bincode deserialize, panic/DoS check | Present |
| `snapshot_deserialize` | `StateSnapshot` + `StateSnapshotV2::from_bytes` parse/migration hook fuzz | Present |
| `consensus_validate` | `BlockHeader` serialize safety over random header fields | Present |
| `fuzz_blockchain_serialize` | A minimal byte-slice harness; a placeholder for a future roundtrip extension | Present |
| `evm_rlp_decode` | F10.1 RLP decoder: random relayer bytes -> canonical decode/error, no panic | Present |
| `evm_mpt_verify` | F10.1 MPT verifier: bounded key/proof pieces -> verify/error, no panic | Present |
| `consensus_state_transition` | produce_block + try_reorg panic freedom / MAX_REORG_DEPTH | Present |
| `relayer_escrow` | bridge lock -> mint -> burn -> unlock plus the UniversalRelayer proof path | Present |
| `zk_verifier` | ProofEnvelope bincode + DefaultAdapter::verify fail-closed | Present |
| `budl_compile` | Budl source -> compiler front end, no panic on malformed input | Present |
| `budl_compile_then_run` | Compile plus execute, the compiler and the VM on the same input | Present |
| `vm_execute` | BudZero VM execution over a random program, panic/DoS check | Present |
| `reputation` | The reputation accounting path, no panic and no overflow | Present |

## Running

**Prerequisite:** the Rust nightly toolchain (for fuzzing only).

```bash
rustup install nightly
cargo +nightly install cargo-fuzz

cargo +nightly fuzz run block_deserialize
cargo +nightly fuzz run transaction_deserialize
cargo +nightly fuzz run snapshot_deserialize
cargo +nightly fuzz run consensus_validate
cargo +nightly fuzz run fuzz_blockchain_serialize
cargo +nightly fuzz run evm_rlp_decode
cargo +nightly fuzz run evm_mpt_verify
```

A short smoke run example:

```bash
cargo +nightly fuzz run snapshot_deserialize -- -max_total_time=30
cargo +nightly fuzz run evm_rlp_decode -- -max_total_time=300
cargo +nightly fuzz run evm_mpt_verify -- -max_total_time=300
```

## Seed corpus

The ZKVM oriented seed corpus files live under `fuzz/corpus/zkvm/`. The EVM
target seeds are under `fuzz/corpus/evm_rlp_decode/` and
`fuzz/corpus/evm_mpt_verify/`; these are the canonical empty RLP and empty trie
starting inputs of the in-tree F10 tests, not the official Ethereum fixture
package. To produce new seeds:

```bash
cargo run --manifest-path ../xtask/tools/Cargo.toml -- seed-corpus
```

## CI integration

The quick job in `ci.yml` runs the listed targets for 60 seconds each. Long runs
are handled by `fuzz-nightly.yml` (a schedule, 4h per target, with a corpus
cache). A target only fuzzes when three files agree: the harness, the `[[bin]]`
entry and the workflow that runs it; the `fuzz-targets-are-wired` gate measures
exactly that agreement.

## Acceptance criteria

- [x] `fuzz/Cargo.toml` exists.
- [x] 14 targets exist under `fuzz/fuzz_targets/`.
- [x] Every target is registered as an explicit `[[bin]]` in `Cargo.toml`.
- [x] The F10.1 RLP and MPT panic/DoS targets are registered; the MPT input is
      bounded to 64 nodes and 128 bytes per node.
- [x] The deserialization targets consume a `Result` instead of panicking.
- [ ] `cargo +nightly fuzz check` is clean in an authorised environment.
- [ ] Long fuzz run reports are stored as artifacts before a release.

## Related

- `ops/scripts/audit-deps.sh`: the dependency audit report.
- `ops/scripts/generate-sbom.sh`: CycloneDX SBOM generation.
- `target/audit/DEPENDENCY_AUDIT.md`: the latest dependency audit status.
- `target/audit/SBOM.md`: the SBOM generation procedure.
