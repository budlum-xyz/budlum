# budlum-finality-core

Common finality-proof model + **fail-closed** cross-domain security verifier
for Budlum - the *consensus of consensuses*.

Every external domain (PoW, PoS, PoA, BFT, ZK, DAG, capacity-proof, …) keeps its
own finality engine. Budlum verifies each domain's finality proof and folds it
into a single `GlobalBlockHeader`. This crate is the **shared proof model**
([`FinalityProof`]) and the **centralized choke point**
([`verify_finality_backing`]) that the Universal Settlement Layer intake
(`src/cross_domain/external/intake.rs`) currently lacks.

## Why

`intake.rs` only mentions `slashable` in comments - it never enforces the
`require_slashable` policy field. Enforcement is scattered across adapters
(`ethereum.rs:719`, `tendermint.rs:1066`, `domain_bridge.rs:163`). A new
adapter that forgets the check silently lets an *unsashable* backing reach the
`GlobalBlockHeader`. One function, called from every intake path, removes that
risk. **Fail-closed**: any condition not provably safe is a rejection.

## Properties (verified by the tests)

* **Fail-closed** - `require_slashable` + a non-slashable backing ⇒ reject.
* **No admin key** - verification is pure, deterministic, key-free.
* **Deterministic** - identical inputs ⇒ identical output.
* **Quorum sanity** - malformed quorums are rejected, never trusted.

## Build & test (standalone)

```sh
cd crates/budlum-finality-core
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

This crate is intentionally **decoupled** (its own `[workspace]`); it does not
join the 900+-crate `budlum-core` build graph so it can be compiled and audited
in isolation.

## Recommended wiring (CI-gated)

Call `verify_finality_backing(backing, policy)` from
`src/cross_domain/external/intake.rs` immediately after an adapter produces a
`SecurityBacking`, before it is folded into the `GlobalBlockHeader`. The exact
diff is tracked in the workspace audit note for cross-domain intake.

[`FinalityProof`]: ./src/lib.rs
[`verify_finality_backing`]: ./src/lib.rs
