# Standard 4 - `IBudlumFinality` read surface and family counterparts

| Field | Value |
|---|---|
| Consumers | contracts, wallets, explorers and indexers on any chain Budlum settles |
| Vectors | `docs/standards/vectors/ibudlum-finality-v1.json` |
| Production sources | `contracts/external-domain/BudlumFinalityVerifier.sol`, `contracts/lib/BudlumHash.sol`, `contracts/object-layer/cosmwasm/src/verifier.rs`, `contracts/object-layer/svm/src/verifier.rs` |

`FinalityMode` is one enum with one meaning everywhere. Every family counterpart must
answer the same four questions with the same discriminants, because a consumer that
routes on "is this height final" must not have to learn five dialects of it.

## The surface

```solidity
enum FinalityMode { None, ClassicalOnly, PostQuantumOnly, Hybrid }   // 0, 1, 2, 3

interface IBudlumFinality {
    function rootAtHeight(uint64 height) external view returns (bytes32);
    function heightFinal(uint64 height) external view returns (bool);
    function latestFinalHeight() external view returns (uint64);
    function finalityModeAtHeight(uint64 height) external view returns (FinalityMode);
}
```

| Method | Contract for a conforming implementation |
|---|---|
| `rootAtHeight(h)` | the state root Budlum committed at `h`; **`bytes32(0)` if `h` was never finalised**, never a revert. A zero return is the only encoding of "no answer" that survives being called inside another contract's loop |
| `heightFinal(h)` | true iff Budlum finalised `h` **and** this verifier has accepted the attestation covering it. It is not a synonym for "seen" |
| `latestFinalHeight()` | the highest finalised height, `0` when nothing is final. Monotone: it never decreases for a live verifier |
| `finalityModeAtHeight(h)` | the signature posture that attested `h`. A height finalised before the activation of the ML-DSA companion stays `ClassicalOnly` forever; re-tagging it as `Hybrid` after activation is a rewrite of history and the vectors forbid it <!-- claim:L-FINALITY-01 --> |

## `FinalityMode` discriminants

| Value | Name | Meaning |
|---|---|---|
| 0 | `None` | no accepted attestation covers this height |
| 1 | `ClassicalOnly` | attested by the BLS12-381 aggregate only, no `mlDsaSignature` present: the height stands on the discrete-log assumption alone, which is exactly what `Hybrid` exists to relieve <!-- claim:L-FINALITY-01 --> |
| 2 | `PostQuantumOnly` | attested by ML-DSA only |
| 3 | `Hybrid` | both families attested; the mode a mainnet consumer should require |

The discriminant is a single byte inside `signing_message` on the Rust counterparts and a
`uint8`-sized enum value on Solidity. It is never a boolean: `ClassicalOnly` and
`PostQuantumOnly` are both "signed", and a boolean surface makes the difference
invisible to exactly the consumer that must react to it.

## Attestation encoding (EVM)

```solidity
struct Attestation {
    uint64  height;
    bytes32 stateRoot;
    uint64  epoch;
    uint64  chainId;          // Budlum chain id, NOT the host chain
    bytes   g2AggregatePubkey;
    bytes   g2Generator;
    bytes   g1NegSignature;
    bytes   mlDsaSignature;
    bytes   mlDsaPubkey;
    bool    mlDsaEthVariant;  // false: FIPS 204 context, true: Ethereum-style variant
}
```

```text
attestationDigest = keccak256(abi.encode(
    "bud-attestation-v1", height, stateRoot, epoch, chainId,
    keccak256(g2AggregatePubkey), keccak256(g2Generator), keccak256(g1NegSignature),
    keccak256(mlDsaSignature), keccak256(mlDsaPubkey), mlDsaEthVariant))

signingRoot = keccak256(concat(
    "bud-finality-signing-root-v1", bytes32(block.chainid),
    bytes8(height), stateRoot, bytes8(epoch), bytes8(chainId)))

pendingIdentity = keccak256(abi.encode("bud-attestation-pending-v1", height, stateRoot))
```

Three rules a re-implementation must not "tidy up":

1. **Variable-length fields are hashed before they enter the head.** `keccak256(field)`
   is placed in the 32-byte slot instead of an ABI tail. A consumer that writes plain
   `abi.encode` over the struct gets a different digest - and a different one per field
   length, which is how an implementation passes its own fixtures and fails the network.
2. **`signingRoot` binds `block.chainid`, `attestationDigest` does not.** The signing root
   is what the validator signs, so it must be host-chain-bound or the same signature is
   replayable on every chain that ever accepts Budlum attestations. The digest is the
   *identity* of the attestation inside one verifier, so it must be host-independent to
   let one attestation be recorded in several verifiers.
3. **`chainId` in the payload is Budlum's**, checked against the verifier's own
   `budlumChainId` before anything is hashed. `0` state root and a wrong Budlum chain id
   both revert; they are not false returns, because "no" and "you pointed at the wrong
   network" must not share an encoding.

`bytes8(x)` is the 8 big-endian bytes of a `uint64`; `bytes32(block.chainid)` is its
32-byte big-endian form. Truncation of a wider integer is a revert, not a wrap.

## Events (the indexer contract)

| Event | Emitted when | A consumer may treat it as |
|---|---|---|
| `AttestationVerified(digest, height, stateRoot)` | the attestation's signatures verify and it is accepted | provisional finality, inside the challenge window |
| `AttestationOptimistic(digest, height, reason)` | accepted without a full on-chain re-verification | **not** finality; the reason string is the audit trail |
| `ChallengeOpened(digest, challenger)` | a bond-escrowed challenge starts | the height is contested; hold outbound value |
| `ChallengeProven(digest, challenger, fraud)` | the challenge resolves | `fraud == true` freezes the attester set for that epoch |

## Family counterparts

| Family | Answers the surface via | Signature posture |
|---|---|---|
| EVM | `IBudlumFinality` (above) | BLS12-381 aggregate + ML-DSA, both re-verified on chain |
| CosmWasm | `height_final`, `root_at_height`, `header_at`, `latest_final_height`, `finality_mode_at_height` in `contracts/object-layer/cosmwasm/src/verifier.rs` | committee signers over `signing_message`, epoch-keyed, `rotate_committee` for handoff |
| Solana object layer | the same five functions over `VerifierState`, plus `verify_ed25519_from_sysvar` | Ed25519 checked through the syscall, so no curve arithmetic is re-implemented in program code |

The counterpart rule: **a digest recomputed on one family must equal the digest recorded
by another family for the same (height, state root, epoch, mode)**. If it does not, the
two adapters disagree about what they attested, and that is a settlement-level fault, not
a formatting bug. `handoff_message(chain_id, from_epoch, next)` is committed the same way
in both Rust counterparts so a key rotation cannot be applied on one host and not the
other.

## What is deliberately absent, and why it is a problem

- **No alert level.** `QuantumAlertLevel` (`Level0Open`, `Level1Advisory`,
  `Level2Restricted`, `Level3Isolated`, `src/execution/coordinator/foreign/mod.rs`)
  governs which foreign transactions Budlum admits, and the EVM read surface exposes no
  view for it. A downstream contract therefore cannot stop honouring classically-signed
  withdrawals when Budlum's canary escalates: the safest thing it can see is
  `finalityModeAtHeight() == ClassicalOnly`, which is a statement about history, not
  about the alarm. Closing this is the on-chain half of the canary work: one
  `alertLevel()` view returning the same four discriminants, readable in the same
  checkpoint that the certificate root updates.
- **No `proofOfInclusion(height)`** on this surface. Inclusion is standard 3; a consumer
  that needs it verifies against `rootAtHeight`, which is why `rootAtHeight` is
  specified to return the *committed* root rather than a per-host summary hash.

## Vectors

`docs/standards/vectors/ibudlum-finality-v1.json` is the normative test set. Three rules make it checkable without trusting
anyone's code:

1. **A positive case states its input, not just its answer.** Recompute `expected` from `input`
   with the rules above; every published number must fall out, including the ones a producer is
   tempted to shortcut.
2. **A negative case states how it was made.** Each one names a `basis` positive case and
   a `mutate` object; recompute `a` from the basis input and `b` from that input with the mutation
   overlaid. Nothing has to be taken on faith: the deltas are what make the two digests differ,
   and the point of the case is that they *must* differ.
3. **Nothing is unexplained.** Every integer in `input` is either a documented discriminant or a
   filler value derived from the domain id, so re-deriving the inputs from the published rules
   reproduces the
   file byte for byte.

## Selector provenance

`docs/standards/vectors/ibudlum-finality-v1.json` also carries a `solidity` block, and every byte
of it is derived from `contracts/external-domain/BudlumFinalityVerifier.sol` and
`contracts/object-layer/BudlumFinalityVerifier.sol` rather than transcribed: the declaration line,
its file, its line number, the canonical signature Solidity would hash, and the 4-byte selector.
Two consequences are worth stating before anyone tries to edit the file:

1. `attestationDigest` and `signingRoot` take a struct, so their canonical form is the tuple of
   `Attestation`'s member types. Reordering the struct's fields changes those selectors and breaks
   every caller's ABI, which is why the vectors publish the expansion and not just the hash.
2. A function declared twice with two different canonical forms is a defect, not a choice: a call
   through one interface would revert on the other. The same rule that makes this vector file
   checkable makes that visible, because both declarations and both hashes are in the tree.

`python3 docs/standards/check_vectors.py` performs rules 1 and 2 with the Python standard library
alone - no node, no toolchain, milliseconds. `--self-test` additionally mutates one published
value at a time and fails if the check does not notice, so a checker that always prints OK cannot
be mistaken for a verification.

## Boundary of this document

| Claimed | Not claimed |
|---|---|
| the four views have one meaning across the three families, and their encodings are fixed | that every deployed verifier instance has been audited for these semantics |
| a mode of `ClassicalOnly` is visible to a consumer and can be refused by it | that refusing it is enough: a classical key may already be compromised without Budlum's canary seeing it |
| `attestationDigest`/`signingRoot` are reproducible from this text | that the challenge window is long enough for your bridge's withdrawal delay - that is an operator parameter |
