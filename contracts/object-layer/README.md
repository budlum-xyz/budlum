# Object-layer settlement endpoints

One settlement endpoint and one Budlum finality verifier per home VM family.
The Budlum side reads them through
`src/object_layer/family/<family>.rs`; the canonical digests that a charter
is checked against are computed from these files (`FamilyProfile::canonical_build`).

| Family | Endpoint | Verifier | Toolchain |
|---|---|---|---|
| EVM | `BudlumSettlementEndpoint.sol` | `BudlumFinalityVerifier.sol` | Foundry, solc 0.8.26 |
| CosmWasm | `cosmwasm/src/contract.rs` | `cosmwasm/src/verifier.rs` | cosmwasm/optimizer |
| SVM | `svm/src/lib.rs` | `svm/src/verifier.rs` | cargo build-sbf |
| Move | `move/sources/settlement_endpoint.move` | `move/sources/budlum_verifier.move` | aptos move compile |

Common rules, every family:

- No admin key, no upgrade path, no pause switch.
- `deposit` measures what it received (balance difference) and emits
  `budlum/object-layer/arrive/v1`.
- `home_call` binds the caller (`msg.sender`, `info.sender`, the signer) and
  a per-sender nonce, and emits `budlum/object-layer/call/v1`.
- `accept_header` takes a Budlum checkpoint only when the verifier says it is
  final, and restarts the silence clock.
- `release` and `escape` need an opening of the object-layer root in an
  accepted Budlum header (global header V9). Until that step
  lands they refuse, and **no endpoint may be deployed**: custody would have
  no exit. The verifiers are fail-closed for the same reason, until the
  succinct Budlum finality proof lands.

The event layouts are pinned by the Rust translators' fixtures
(`src/object_layer/family/*.rs`, `mod fixture`).
