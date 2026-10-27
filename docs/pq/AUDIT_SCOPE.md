# Post-quantum audit scope

Six packages. Each package names its scope, the threat it answers
(see `THREAT_MODEL.md`), and the tests and gates that carry its evidence. A
package closes when every finding of the external report has a task, and every
task has a commit SHA and a CI run number. Claim rung I-4 opens only
when all six packages are closed.

| Package | Status |
|---|---|
| A1 Signatures, composite, key derivation | OPEN (not yet sent) |
| A2 Filiz Chain | OPEN (not yet sent) |
| A3 Frost Alarm (canaries) | OPEN (not yet sent) |
| A4 PUL-Lite, Seal Layer, regeneration | OPEN (not yet sent) |
| A5 BudZero parameters, VerifyMerkle, Poseidon set | OPEN (not yet sent) |
| A6 Network PQ layer and HPKE | OPEN (not yet sent) |

## A1 Signatures, composite, key derivation

Scope:

- `src/crypto/scheme.rs`: scheme ids, suites, the status ladder and the
  chain-state registry.
- `src/crypto/pq.rs`: the verification facade and the dual ML-DSA verifier
  (RustCrypto `ml-dsa` and `libcrux-ml-dsa`, portable backend), the
  disagreement metric.
- `src/crypto/composite.rs`: the composite message representative and the
  two-component verification.
- `src/crypto/ctx.rs`: FIPS 204/205 context strings.
- `src/crypto/key_derivation.rs`, `crates/wallet-core`: the SHAKE256 branch
  derivation, 24-word entropy, passphrase, account and index.
- `src/crypto/address_v3.rs`: address V3.
- `src/core/transaction.rs`, `src/core/tx_bundle.rs`: TxV7, TxV8, bundles,
  recovery rotation.

Threat: a forged user or validator signature; a scheme confusion; a context or
suite substitution; key branch correlation.

Evidence: `src/crypto/pq_vector_tests.rs` (ACVP, Wycheproof and known-bug
vectors), composite rejection tests in `src/crypto/composite.rs`,
`crates/wallet-core/kat/`, gates `scheme-is-never-inferred`, `pq-ctx-is-bound`,
`wallet-node-address-agree`, `classical-crypto-is-paired`.

## A2 Filiz Chain

Scope: `src/consensus/filiz.rs`, the registration binding in
`src/consensus/registration.rs`, and the epoch randomness derivation.

Threat: leader prediction before the reveal, grinding, commitment copying,
chain exhaustion.

Evidence: unit tests in `src/consensus/filiz.rs` (valid reveal, wrong
preimage, uniqueness, activation delay, exhaustion, threshold distribution).

## A3 Frost Alarm (canaries)

Scope: `src/security/quantum_canary.rs`, `src/security/alarm_effects.rs`, the
`CanaryCommit` and `CanaryReveal` executor arms.

Threat: a false alarm (a proof accepted that does not show the capability), a
missed alarm, front-running of a claim, a state transition that differs
between nodes.

Evidence: pinned genesis digests of the canary set, commit and reveal tests,
alarm effect tests per level.

## A4 PUL-Lite, Seal Layer, regeneration

Scope: witness budgets and pruning (`src/consensus/budget.rs`,
`src/chain/snapshot.rs` pruning), the Handoff Certificate
(`src/consensus/handoff.rs`), Anchor V2 and its ledger
(`src/settlement/pq_anchor.rs`, `pq_anchor_verify.rs`, `anchor_ledger.rs`,
`anchor_production.rs`), the Root Seal (`src/settlement/root_seal.rs`), the
cold committee (`src/settlement/cold_quorum.rs`), resealing
(`src/settlement/reseal.rs`), and regeneration
(`src/domain/pq_canonical.rs`, `regen_health.rs`, `regen_mempool.rs`,
`regeneration_stage.rs`).

Threat: a witness deleted before finality, a below-threshold anchor or handoff
accepted, a node regenerated onto a fork from a classical or unsigned source,
an honest block lost during a lattice-alarm reseal.

Evidence: INV-06, INV-10, INV-13 and INV-14 tests (see `CLAIMS.md`).

## A5 BudZero parameters, VerifyMerkle, Poseidon set

Scope: `budzero/bud-proof/src/plonky3_prover.rs` (`build_config`), the
`stark-soundness` tool, the Poseidon set in `budzero/bud-vm` and the AIR,
the 256-bit VerifyMerkle node, the `budzero/bud-pul` chips.

Threat: a soundness level below 128 provable bits; a 64-bit binding; a VM and
AIR mismatch.

Evidence: the `stark-soundness` tool output in `MEASUREMENTS.md`, the
`security-parameters` and `no-pairing-snark-in-verification-path` gates, VM
and AIR parity tests.

## A6 Network PQ layer and HPKE

Scope: `src/crypto/tls.rs` (rustls with aws-lc-rs, X25519MLKEM768 only), the
RPC TLS listener, `src/crypto/hpke.rs` (KEM 0x647a, HKDF-SHA256,
ChaCha20-Poly1305), the B.U.D. key package (`src/storage/view_grant.rs`), the
Pollen policy (`src/pollen/data_rights.rs`), and the peer identity binding
.

Threat: a classical-only key exchange, a downgrade, a recipient confusion in
HPKE, a gossip author signature treated as consensus input.

Evidence: negotiated group tests, HPKE KAT and round-trip tests, the Pollen
policy rejection test, the gossip author test.
