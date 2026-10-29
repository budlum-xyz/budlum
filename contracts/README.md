# Ethereum-side contracts

Solidity 0.8.26, built and tested with Foundry through the Rust wrapper
:

```
cargo run --manifest-path xtask/tools/Cargo.toml -- contracts build
cargo run --manifest-path xtask/tools/Cargo.toml -- contracts test
cargo run --manifest-path xtask/tools/Cargo.toml -- contracts deploy
```

The `Solidity` workflow compiles every file with a pinned solc and runs
`contracts test` with a pinned Foundry. The tests carry their own cheat-code
interface (`test/Harness.sol`); the tree has no Solidity dependency.

No contract has an owner, a pause switch or an upgrade path.

| Contract | Purpose | Budlum side |
|---|---|---|
| `external-domain/BudlumFinalityVerifier.sol` | Verifies Budlum finality (BLS12-381 aggregate and ML-DSA) with the EIP-2537 and EIP-8051 precompiles, optimistic window when one is missing | `src/cross_domain/external/evm_hybrid.rs` (signing root and digest encoder) |
| `graft/GraftExecutor.sol` | A solver makes a Graft intent's call through it; it emits the fulfilment message | `GraftTx::Fulfill`, `fulfilled_payload_hash` |
| `graft/GraftExecutor.sol` (`BudlumGraftClaimer`) | What an origin application inherits to name its Budlum payout | `GraftTx::Claim`, `claim_payload_hash` |
| `graft/BudlumPaymentReceiver.sol` | On-chain check of a Graft payment: finalized state root, global header, Graft root, payment window | `verify_graft_payment` |
| `graft/BudlumRemoteAccountFactory.sol` | Graft level 3: CREATE2 accounts a Budlum user controls with Budlum payments | Graft payments with a call authorization as memo |
| `mikoriza/BudlumRegistrar.sol` | The Mikoriza AVS: binds a Budlum validator and BLS key to an EigenLayer operator, reports allocations | `SharedSecurityTx::Observe`, `allocation_payload_hash` |
| `mikoriza/BudlumSlasher.sol` | Slashes an operator for a Budlum finality double vote, verified with EIP-2537 | `checkpoint_signing_message` |

## Speaking to Budlum

Every contract that sends Budlum a message emits one log shape
(`lib/BudlumOutbound.sol`):

```
event BudlumOutbound(bytes kind, bytes32 indexed recipient,
                     bytes32 indexed correlationId, bytes32 payloadHash)
```

`src/cross_domain/evm/outbound.rs` (`message_from_log`) turns it into a
cross-domain message whose sender is the emitting contract. Payload hashes use
the Budlum field hash (`lib/BudlumHash.sol`, `hash_fields_bytes` in Rust):
SHA-256 over every field, each preceded by its little-endian u64 length. The
known-answer tests on both sides (`test/Graft.t.sol`, `test/Mikoriza.t.sol`,
and the matching Rust tests) pin the same values.

## Deployment

Addresses and constructor parameters live in `config/testnet-ethereum.toml`.
The deployment rule: no deployment while any negative
test (`test/BudlumFinalityVerifier.t.sol`) is red in CI. The deployer key never
enters the tree: `contracts deploy` reads the keystore path from
`BUDLUM_ETH_KEYSTORE`, the endpoint from `BUDLUM_ETH_RPC_URL`, and forge reads
the password from `ETH_PASSWORD`.

The ML-DSA precompile is not live on Ethereum. EIP-8051 and EIP-8355 are
drafts and their addresses overlap, so the verifier probes at run time and
never assumes an address. Whether Budlum keys use the FIPS-204 encoding or the
ML-DSA-ETH variant is a decision taken once, in writing, by Ayaz.
