# Budlum intent policy

A dependency-free, bounded **offline** route checker and library. It does not
connect to a chain, authenticate a quote, prove a fiat peg, lock funds or execute
a payment. A successful result is not a settlement receipt or debit authority.

## Run

```sh
cargo run --manifest-path crates/intent-policy/Cargo.toml -- \
  crates/intent-policy/examples/payment.route
cargo test --manifest-path crates/intent-policy/Cargo.toml --all-features
cargo clippy --manifest-path crates/intent-policy/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path crates/intent-policy/Cargo.toml -- --check
```

## Strict text format

Each non-comment line has one of these forms. Tokens use whitespace separation.
Inline comments and extra fields are refused. Identities use exactly 64 hex digits.
Integers use unsigned decimal notation. Capability flags are exactly `0` or `1`.

```text
height BUDLUM_SNAPSHOT_HEIGHT
domain DOMAIN SNAPSHOT ACTIVE SWAP TRANSFER LOCAL_ATOMIC CONDITIONAL_ESCROW
intent SOURCE_DOMAIN SOURCE_ASSET TARGET_DOMAIN TARGET_ASSET MAX_DEBIT MIN_CREDIT VALID_UNTIL MODE
leg KIND SOURCE_DOMAIN SOURCE_ASSET TARGET_DOMAIN TARGET_ASSET INPUT OUTPUT INPUT_FEE
```

`MODE` is `atomic` or `conditional`. `KIND` is `swap` or `transfer`.
A swap stays in one domain and changes the exact asset identity. A transfer
crosses domains. Its destination representation is not inferred from a ticker.
The final `OUTPUT` is net of destination-side deductions.

Each leg's fee is denominated in that leg's input asset. For connected legs,
previous output must equal next input plus next fee. No implicit dust or hidden
top-up is allowed. Only the first debit and the final credit are compared with
the user's endpoint limits. Unlike asset units are never summed as a global fee.

Atomic mode requires a single domain with local atomic execution. Two EVM chains
are not one atomic execution context. Conditional mode checks escrow capability
claims at each end, not an escrow implementation or its liveness. An authenticated
execution protocol, per-chain finality checks, deadlines, signer authorization,
quote commitments and replay protection remain mandatory before settlement.

Limits: eight legs, sixteen distinct domain views, 32 KiB input. Snapshot heights
all refer to Budlum, not an ordering of external-chain heights. Views used by a
route must match the supplied snapshot. The expiry boundary is exclusive.

The CLI's successful prefix is `POLICY_ONLY`. Failure exits nonzero. Fixtures
are synthetic; passing them makes no assertion about any named live blockchain.
