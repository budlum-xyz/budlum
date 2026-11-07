# Migration Kit

The Migration Kit moves state from an existing EVM chain into Budlum with a
proof, so a contract arrives with its storage rather than with a promise. It is
a beta feature: it does not block the testnet launch, and it is not claimed to
work before it has run against a real chain.

## What the directive asks for

1. An EVM state proof is verified against a block header the destination chain
   accepts.
2. The migrated account state is written once, under an activation height.
3. A second migration of the same account is refused.
4. The kit is a tool, not a privileged chain function. No admin path exists to
   skip the proof.

## State in the tree

The kit itself is not implemented. There is no module, tool or test for it in
this tree today, so this page records the requirement and the gap rather than a
design that does not exist.

What does exist and would carry it:

| Piece | Where | Use |
| --- | --- | --- |
| Foreign account envelopes | `src/execution/coordinator/foreign/ethereum.rs` | Holds the foreign account identity a migrated account becomes. |
| Ethereum header and receipt types | `src/rpc/compat/ethereum/` | The header form a state proof is checked against. |
| Classic signature lane | `src/crypto/composite.rs`, `classical_crypto_is_paired` gate | A foreign account proves its own asset moves; it cannot move a Budlum account. |
| Activation height mechanism | `src/chain/` | The height gate a migration must sit behind. |

## Status

- Implemented: nothing of the kit itself.
- Blocking the launch: no. The package is beta by the directive.
- Next step: a first slice that verifies one account proof against a header and
  refuses a replay, with a red-first test that names the refusal.

Recorded in `docs/work/PACKAGES.md` as WP-34.
