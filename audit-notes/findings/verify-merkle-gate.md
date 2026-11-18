# B-0054: `open_deal` requires a Merkle proof unconditionally, and the proof it requires is a format check

- **Location:** `src/domain/storage_deal.rs:2880-2905` on `budlum-stack` head `df970fc9` (reaches `garden` through PR #183). The flag that is supposed to decide this is `features_verify_merkle`, declared at `src/cli/commands.rs:380`, read from `[features] verify_merkle` at `:1149-1150`, and documented at `:751-753` as "Legacy configuration field. Testnet keeps `VerifyMerkle` closed".
- **Severity:** medium. Not a fund-loss path. It is a directive deviation and a false assurance: the profile says the gate is closed, the startup path says the requested value is "not applied", mainnet refuses the flag outright, and the storage-deal path behaves as if the gate were open and the verifier finished.
- **Status:** fixed in PR [#201](https://github.com/budlum-xyz/budlum/pull/201), commit `02de7030` on `fix/verify-merkle-gate`, base `budlum-stack`. Three tests pin it and a negative control reproduces the client-visible refusal. CI run number pending.

## The fix

`StorageDomainParams::require_merkle_proof` is now the one decision. It defaults to `false`, which matches every shipped profile, and `open_deal` reads it once:

- Closed gate: the envelope is optional, a deal without one opens and records `merkle_proof: None`, and a supplied envelope is still format-checked.
- Open gate: proof and root are both mandatory and a half envelope is refused. The envelope is still only format-checked until the 64-depth verifier exists, and the source says so instead of implying the gate is already open.

Tests: `a_closed_verify_merkle_gate_opens_a_deal_without_an_envelope`, `an_open_verify_merkle_gate_refuses_a_half_or_missing_envelope` (three cases), `a_closed_gate_still_refuses_a_malformed_envelope`. The negative control is exact: reverting only the `open_deal` branch makes the first test report `a closed gate must not demand a proof it cannot check: MerkleProofRequired`, which is the refusal a client was hitting. `cargo fmt --all -- --check` and `cargo check --lib --tests` are both clean at `02de7030`.

The 64-depth verifier stays closed and no committed root moves: the new field is serde-default, so existing domain rows decode to the closed gate they were registered under.

## The three surfaces

1. Every checked-in profile sets the flag closed:

```
config/mainnet.toml:95        verify_merkle = false
config/sentry.toml:69         verify_merkle = false
config/validator-shielded.toml:88  verify_merkle = false
```

2. Startup reports the value as inert (`src/main.rs:843-849`):

```rust
if config.features_verify_merkle {
    println!(
        "   VerifyMerkle: requested by [features] verify_merkle, not applied \
         (the VM uses MainnetActivation defaults; see bud-vm)"
    );
}
```

3. `StorageRegistry::open_deal` (`src/domain/storage_deal.rs:2896-2905`) treats the proof as mandatory, with no flag read at all:

```rust
let proof_bytes = merkle_proof
    .as_ref()
    .ok_or(StorageError::MerkleProofRequired)?;
let root = storage_root.ok_or(StorageError::MerkleProofRequired)?;
Self::validate_merkle_proof_format(proof_bytes, &root)?;
```

The error variant's own doc comment asserts the state the code claims: `MerkleProofRequired`: "B.U.D.: `merkle_proof` and `storage_root` are mandatory / Now that `VerifyMerkle` production gate is open" (`:1156-1158`).

So the code is written against an enabled gate while the configuration, the startup log and the mainnet refusal are all written against a closed one. One of those statements is false on every node that runs today, and it is the code comment plus the behaviour.

## What "validate" does here

`validate_merkle_proof_format` (`src/domain/storage_deal.rs:5151-5176`) checks that the blob is at least 64 bytes, decodes as a `ProofEnvelope` under the byte budget, and that the inner `proof_bytes` is non-empty. It then discards the root:

```rust
// Log the proof acceptance (storage_root validated off-chain).
let _ = storage_root;
Ok(())
```

That is a shape check, not a proof check. Nothing binds the envelope to `storage_root`, to the manifest, to the operator, or to any column. A caller that can produce any well-formed `ProofEnvelope` satisfies it, so the mandatory envelope adds a formatting cost and no soundness. The honest reading is: the proof is currently required and currently meaningless, and neither the requirement nor the emptiness is stated where an operator would look.

## Why this matters for the directive

The standing constraint is that `VerifyMerkle` 64-depth stays disabled in production. This code does not enable the 64-depth verifier, so the constraint is not violated in the sense of switching the verifier on. It does violate it in the sense that matters for review: the deal path is gated on a proof it cannot check, and every comment along the path says the gate is open. A reader auditing "is the verifier on" gets three different answers from three files.

## What the fix has to decide, not assume

There are two coherent designs and they are not interchangeable:

- **Closed gate, proof optional.** `open_deal` accepts `None` and `None` means "no proof claimed", recorded as such. Any supplied proof is still format-checked. This matches `verify_merkle = false` on every profile and makes a later gate opening a state change rather than a code change.
- **Open gate, proof checked.** `open_deal` requires the envelope and `validate_merkle_proof_format` becomes a real verification bound to the root and the manifest. This cannot ship until the verifier exists, and the directive says it does not.

The current code is neither: it is the first design's configuration with the second design's requirement and no verification in either.

This finding does not pick one. It records that the tree cannot keep all three statements, and that whichever is chosen has to be made true in the same commit on all three surfaces.

## Evidence trail

- `grep -n "verify_merkle" config/*.toml` returns `false` for mainnet, sentry and validator-shielded.
- `src/main.rs:843-849` prints "not applied".
- `src/cli/commands.rs:1607-1615` exits with `CRITICAL SECURITY FAILURE: VerifyMerkle cannot be enabled on mainnet until storage challenge proofs are checkable`.
- `src/domain/storage_deal.rs:2896-2905` requires the envelope; `:5151-5176` never uses the root.
- `MerkleProofRequired` appears six times in `src/domain/storage_deal.rs`. The two `merkle_proof: None` literals in the file (`:7131`, `:11333`) are inside `the_deal_leaf_commits_to_the_shard_size` (`:7118`) and an `insert_test_deal` helper (`:11310`), so neither calls `open_deal` and neither pins the refusal.

## The client-visible shape of the disagreement

The transaction path converts the wire representation into `None` before calling the registry (`src/domain/storage_tx.rs:1033-1042`):

```rust
merkle_proof: if open.merkle_proof.is_empty() {
    None
} else {
    Some(open.merkle_proof.clone())
},
storage_root: if open.storage_root == [0u8; 32] {
    None
} else {
    Some(open.storage_root)
},
```

An `OpenDeal` transaction that leaves both fields empty is therefore turned into `(None, None)` and refused with `MerkleProofRequired` at `src/domain/storage_deal.rs:2896-2900`. The `verify_merkle = false` profiles tell an operator the gate is closed, so an operator will send the empty form, and the deal path rejects it. Nothing in the tree tests that refusal, because the only `merkle_proof: None` literals never reach `open_deal`.
