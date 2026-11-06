# Validator roles: what a node signs up for

A Budlum validator has one duty and two optional ones. The registry
(`budzero/verifier-registry`) already models each as a separate `RoleId` with
its own stake, so a node opts in per role and is slashed per role.

## 1. Consensus: the duty

`roles::VALIDATOR` (RoleId 1). Producing and voting on blocks. This is what
"being a validator" means; the other two do not substitute for it.

## 2. B.U.D. storage: optional

`roles::STORAGE_OPERATOR` (RoleId 5). Holding content shards and answering
retrieval challenges. A validator may take this on; a non-validator may take it
on without ever producing a block. Neither direction is forced.

## 3. AI inference layer compute: optional

`roles::AI_OPERATOR` (RoleId 8). Supplying CPU/GPU capacity for AI inference
and submitting results. Same freedom: any account may register, and a validator
is under no obligation to.

## Why they are separate stakes

Failing at storage should not cost a node its consensus stake, and vice versa.
The registry keeps `(account, role)` pairs independent, so:

- a hardware fault that makes an operator miss retrieval challenges slashes the
  storage bond only;
- equivocating on an inference result touches the AI inference layer bond only;
- consensus faults (double-signing) remain governed by the consensus slashing
  path.

## Choosing freely

Nothing in the protocol ties the three together. A node can run:

| Configuration | Registered roles |
|---|---|
| consensus only | VALIDATOR |
| consensus + storage | VALIDATOR, STORAGE_OPERATOR |
| consensus + storage + compute | VALIDATOR, STORAGE_OPERATOR, AI_OPERATOR |
| storage only (no block production) | STORAGE_OPERATOR |
| compute only | AI_OPERATOR |

The registry never checks role membership against a fixed list, `RoleId` is an
open `u32` newtype precisely so this stays extensible.

## Where the money goes

AI inference layer's costs are settled the same way consensus rewards are: they accrue to
validators. The split between the three duties is **not fixed in this
document**: the ratios currently in the repository stand until governance
revisits them.

## Hardware honesty

AI inference layer compute is not uniform: an operator answers with the machine it owns.
`src/ai_inference/effort.rs` makes that explicit through effort tiers (`0.5x` … `10x`),
and an operator advertises the deepest tier its hardware can serve. If no
registered operator advertises a given tier, requests at that tier are
unservable and fail closed rather than being answered with cheaper work. In
particular, **without hardware capable of `10.0x`, no verifier can run AI inference layer at
that depth**: the request is refused, not downgraded.
