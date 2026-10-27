# Delegation (testnet)

Budlum is the consensus of consensuses. Every network keeps its own rules.
Budlum unifies their finality into a single proof.

This document covers validator rental in its first two forms (testnet
): a BUD holder delegating stake to a validator, and a
validator running a node that carries other people's stake. Every value
marked TESTNET-DEFAULT is a genesis parameter; mainnet values are decided
separately.

## 1. What delegation is

A delegator moves BUD from its liquid balance into a position with one
validator. The position adds to the validator's voting weight for VRF
leadership and BLS finality, earns a share of the rewards the validator
actually receives, and carries the validator's slashing risk.

There is no fixed yield. The chain pays what the reward pool pays for an
epoch, split by stake; a jailed validator earns nothing for that epoch, and
neither do its delegators. No interface built on this chain should show a
promised rate. A profile shows what happened, never what will.

## 2. Transactions

All four are signed transactions applied in a block. No RPC writes
delegation state.

| Transaction | Signer | Effect |
|---|---|---|
| `Delegate { validator }` (tag 58) | delegator (V5 wallet) | Debits the signed amount, adds it to the position and to the validator's stake |
| `Undelegate { validator }` (tag 59) | delegator | Moves the amount out of the position into the exit queue; it leaves voting weight at once and stays slashable |
| `WithdrawDelegation { validator }` (tag 60) | delegator | Credits every matured exit of this delegator with this validator |
| `SetValidatorCommission { commission_ppm }` (tag 61) | validator | Sets the commission taken from delegators' rewards |

A validator cannot delegate to itself; its own bond is `Stake`. A
delegator can always undelegate, also from a jailed or inactive validator:
leaving matters most exactly then.

## 3. Parameters

| Parameter | Testnet value | Field |
|---|---|---|
| Validator self-bond floor for accepting delegation | `min_stake` (1,000 BUD) | `RegistryParams::min_stake` |
| Maximum commission | 200,000 ppm (20 percent), TESTNET-DEFAULT | `max_validator_commission_ppm` |
| Maximum commission change per epoch | 10,000 ppm (one point), TESTNET-DEFAULT | `max_commission_change_ppm_per_epoch` |
| Delegation unbonding | 100 epochs, TESTNET-DEFAULT | `delegation_unbonding_epochs` |
| Positions and exits held in state | 100,000 each | `MAX_DELEGATIONS` |

A commission may change once per epoch, by at most the per-epoch limit.

## 4. Rewards

At every epoch boundary the reward pool pays each active, unjailed,
unslashed validator its stake-weighted share. For one validator:

1. The delegated part of its share is `share * delegated / stake`.
2. The commission is taken from the delegated part first:
   `delegated_part * commission_ppm / 1,000,000`.
3. The validator receives its self part plus the commission.
4. The rest of the delegated part is split across positions by amount, in
   delegator address order; the last position takes the rounding remainder.

Nothing is minted. The pool pays from its own balance, and the supply
invariant tests hold.

## 5. Slashing

A slash cuts the validator's whole stake by the slash ratio. The cut is
mirrored on every position in proportion to its amount, and every pending
exit with that validator is cut by the same ratio. A delegator shares the
risk of the validator it chose. Liveness faults jail the validator; a jailed
validator and its delegators earn nothing until the jail ends.

## 6. Command line

```
bud delegate --key-file wallet.key --validator <address> --amount-bud 100
bud undelegate --key-file wallet.key --validator <address> --amount-bud 40
bud withdraw-delegation --key-file wallet.key --validator <address>
bud validator commission --key-file ./secrets/testnet-validator.key --rate-ppm 50000
```

The wallet password comes from `--password-file` or `BUD_WALLET_PASSWORD`.

## 7. Reading the state

| RPC | Returns |
|---|---|
| `bud_validatorProfile(address)` | Stake, self stake, delegated stake, delegator count, pending exits, commission and its last change epoch, jail and slash record, missed checkpoints |
| `bud_validatorList()` | Every validator's profile, in address order |
| `bud_getValidatorDelegations(address)` | The positions and pending exits of one validator |

The declared region and hardware tier fields are `null`: no transaction
door records a declaration yet, and the profile does not invent one.

## 8. Hardware rental

A validator may run its node for someone else's stake. The chain does not
see or enforce that arrangement; it sees a validator, its self bond and its
delegations. The validator guide (`docs/VALIDATOR_GUIDE.md`) covers running
the node.

## 9. The other direction

Budlum validators are not rented out to other domains. A system that wants a
different fee policy runs its own validators.
