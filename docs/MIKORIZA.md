# Mikoriza: shared security from restaked Ethereum collateral

Mikoriza (code name `shared_security`) lets an Ethereum operator that
restakes secure Budlum as well. The operator keeps its Ethereum duties and
runs a second piece of software, a Budlum validator. The same collateral backs
two networks. There are two separate proof-of-stake systems: Gasper on
Ethereum and Budlum PoS (leader election plus BLS and ML-DSA finality) here.
The keys are separate.

The name is the fungal network that shares nutrients between roots.

Status: the Budlum side is wired behind a genesis flag. It is on for devnet
and off for testnet until the end-to-end Sepolia test passes; the mainnet
decision is not taken. The Ethereum contracts (`BudlumRegistrar`,
`BudlumSlasher`) are part of.

## Interface

`src/settlement/shared_security.rs` defines the `SharedSecuritySource` trait.
EigenLayer is the first adapter (`EigenLayerSource`). Symbiotic and Babylon
are later adapters behind the same trait. Budlum's side does not depend on the
restaking protocol: a source names the event kind its registrar emits and the
payload the event commits to.

## Joining

1. On Ethereum: register in the Budlum operator set and allocate a share of
   the restaked collateral (one or two transactions).
2. On Ethereum: bind. The operator records its Budlum validator address and
   its Budlum BLS public key in `BudlumRegistrar`. Both keys sign the binding.
   The record is the operator's own claim, keyed by `(validator, operator)`: an
   operator may rebind (a key rotation, a move to another validator) and two
   operators may claim the same validator. No claim is the validator's, and no
   claim is permanent on Ethereum; which one is true is decided on Budlum, by
   the key the validator registered (`RegisterConsensusKeys`).
3. On Budlum: `bud validator join` (stake, then `RegisterConsensusKeys`).
4. Run `budlum-core`.

An Ethereum validator key is never reused on Budlum. `bud validator init`
creates new, Budlum-only keys and says so.

## How Budlum reads Ethereum

Budlum reads Ethereum state only through verified evidence. The registrar
emits one allocation event per change. A relayer carries the event to Budlum
as an anchored external result (the same evidence path the bridge, the relayer
intents and Graft use): the result leaf must reach the external root Budlum
has anchored for that domain. No trusted party reports Ethereum state.

The event binds:

| Field | Value |
|---|---|
| kind | `budlum/mikoriza/allocation/v1` |
| sender | the registrar contract the domain operator named (`SetRegistrar`) |
| recipient | the Budlum validator address |
| correlation id | `H("BDLM_MIKORIZA_OPERATOR_V1", eth_operator)` |
| payload hash | `H("BDLM_MIKORIZA_ALLOCATION_V1", source, validator, eth_operator, units, observed_epoch, bls_key)` |

The transaction `SettlementTx::SharedSecurity(Observe { .. })` carries the
fields in clear; the door recomputes the payload hash, refuses a replayed
event, refuses an allocation older than the recorded one, refuses a BLS key
that differs from the validator's registered key, and lets the newest report
name another Ethereum operator: the validator's key is the authority, so the
row follows it instead of belonging to the first operator ever recorded.

Each record is a `RestakedValidator { budlum_validator, eth_operator,
allocated_units, source, observed_epoch, status, bls_public_key }`. An
allocation of zero units sets the status to `Exited`.

## Weight

```
effective_weight = bud_stake + f(units)
f(units)         = units * units_to_weight_ppm / 1_000_000
```

The restaked part of the total is capped: `R / (B + R) <= max_restaked_share_ppm`.
Above the cap every restaked weight is scaled down by the same ratio. The
weights are recomputed at the epoch boundary only, and only for eligible,
unslashed validators. Leader election and the finality snapshot read
`Validator::voting_weight()`. Governance quorums still count BUD stake only.

| Parameter | Testnet default | Note |
|---|---|---|
| `max_restaked_share_ppm` | `300_000` | TESTNET-DEFAULT. Below one third: ETH-backed validators cannot finalize alone. |
| `units_to_weight_ppm` | `1_000_000` | TESTNET-DEFAULT. One BUD weight atom per allocated unit (one gwei of allocated ETH magnitude). |
| minimum BUD bond | `min_stake` | testnet value is 0. The activation path still requires `min_stake`. |

## Slashing

The slashable offence is a Budlum finality double vote: two BLS signatures by
one validator for different hashes at the same chain id, epoch and height. The
signed message is `checkpoint_signing_message` (`src/chain/finality.rs`), and
the cipher suite is `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`.

- On Budlum the existing evidence path jails and slashes. A slashed
  validator's restaked weight drops to zero at the next epoch boundary.
- On Ethereum `BudlumSlasher` verifies the two signatures with the EIP-2537
  precompiles (pairing, map-to-G1) and SHA-256 against the key the evidence's
  operator bound for the validator, then slashes that operator through the
  EigenLayer operator set. An operator's key cannot slash another operator.
- A liveness fault does not slash ETH on testnet. It only jails on Budlum.

## Rewards

Rewards are paid on Budlum in native BUD to the validator address. No bridge
is needed.

## RPC

| Method | Returns |
|---|---|
| `bud_getRestakedValidators` | every restaked validator: operator, units, source, observed epoch, status, and the capped weight in force this epoch |

Facts only, no score.
