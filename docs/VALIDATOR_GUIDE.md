# Validator guide (testnet)

Budlum is the consensus of consensuses. Every network keeps its own rules.
Budlum unifies their finality into a single proof.

This guide covers the Budlum settlement chain's own validators: proof of
stake with VRF leader election and BLS finality votes. It follows the
. Every value marked TESTNET-DEFAULT is a testnet
parameter; mainnet values are decided separately.

## 1. What a validator does

- Proposes blocks when its VRF output wins the slot (leader rounds widen
  when a slot stalls, so a missing leader does not stop the chain).
- Signs finality votes (prevote and precommit, BLS) at every finality
  checkpoint. A checkpoint finalizes with a two-thirds stake quorum.
- Earns a share of the validation reward pool every epoch, by stake.
- Risks its stake: a double signature is slashed, a liveness fault is
  jailed.

## 2. Requirements

| Item | Testnet value | Where it is set |
|---|---|---|
| Minimum stake | 1,000 BUD | `Network::Testnet` in `src/core/chain_config.rs` |
| Epoch | 50 slots of 3 s (150 s) | same |
| Finality checkpoint | every 5 blocks | same |
| Unbonding | 7 epochs (`UNBONDING_EPOCHS`) | `src/core/account.rs` |
| Keys | signing key, VRF key, BLS key with proof of possession, PQ key | `bud validator init` |

Hardware figures are not published yet: they have not been measured (see
section 9). Nothing in this guide is an estimate presented as a measurement.

## 3. Generate keys and the public record

```
bud validator init \
  --key-file ./secrets/testnet-validator.key \
  --record-out ./validator-record.json \
  --chain-id 45261 \
  --moniker my-validator
```

- The key file holds the secret keys in plaintext, mode 0600. Keep it on the
  validator host and back it up offline. Mainnet refuses this file; mainnet
  validators use an HSM.
- The record holds public keys only: the validator address, the VRF key, the
  BLS key, the BLS proof of possession bound to chain 45261 and to the
  address, and the PQ key. It is safe to publish.
- These keys are new and Budlum-only. Never reuse an Ethereum validator key
  here, and never reuse these keys on Ethereum.

## 4. Launch validators: the genesis ceremony

The testnet genesis is assembled from at least four operators' records. The
template in `config/testnet-genesis.json` has no validators; a node refuses
it.

1. Each operator sends its `validator-record.json` to the coordinator.
2. The coordinator puts the records in one directory and runs:

   ```
   cargo run --manifest-path xtask/tools/Cargo.toml -- testnet-genesis \
     --operators ./records \
     --community <faucet address> \
     --liquidity <address> --ecosystem <address> \
     --team <address> --burn-reserve <address> \
     --out config/testnet-genesis.json
   ```

   The tool checks every proof of possession against chain 45261 and the
   operator's address, requires at least four validators, checks that the
   genesis holds exactly the 100M fixed supply (the validators' stake and the
   reward pool are drawn from the ecosystem share), and prints the genesis
   hash.
3. Every operator runs the same command on the same inputs and compares the
   hash before starting its node. All inputs are public, so the assembly is
   reproducible.

## 5. Run the node

```
budlum-core --config config/testnet.toml \
  --validator-key-file ./secrets/testnet-validator.key
```

`config/testnet.toml` selects the testnet profile, the genesis file and the
loopback RPC listeners. Add your peers to `bootnodes` or pass `--bootstrap`;
a node with no peer source refuses to start. `bud_getStatus` reports the
tip (`blockNumber`) and the finalized height (`finalizedHeight`).

## 6. Join a running testnet

1. Get BUD from the faucet, or
   from another holder. Joining needs the minimum stake plus two fees.
2. Bond the stake and register the keys:

   ```
   bud validator join --rpc-url http://127.0.0.1:18545 \
     --key-file ./secrets/testnet-validator.key --stake-bud 1000
   ```

   This sends a `Stake` transaction and then a `RegisterConsensusKeys`
   transaction, both signed with the validator's signing key. The keys are
   checked in block, including the proof of possession for the node's chain
   id.
3. The validator is active from the next epoch and starts producing and
   voting once its node runs with the same key file.

## 7. Leave

Send an `Unstake` transaction. The stake enters the unbonding queue and is
released after the unbonding period. Stake in the queue stays slashable: a
fault proven during unbonding cuts the queue entry by the same ratio.

## 8. Faults

| Fault | Evidence | Result |
|---|---|---|
| Double signature (two different blocks signed for the same height) | Slashing evidence in a block | Stake slashed by the registry's rate; validator jailed |
| Liveness (missed participation over an epoch) | Recorded at the epoch close | Jailed; slashed only where the registry parameters enable it |

A jailed validator is paid nothing from the reward pool while jailed.

## 9. Rewards

Rewards come from a pre-funded pool, not from minting. The testnet genesis
moves 10M BUD from the ecosystem share into a keyless pool account
. At every epoch boundary the block transition pays
the closing epoch's budget (pool divided by 100,000 epochs, capped by what
the pool holds) to the active, unjailed, unslashed validators, in proportion
to stake. There is no fixed yield: what a validator earns is what the
transition paid, readable from its balance history.

## 10. Resource measurement (open)

 item 10 asks for measured CPU, memory, disk and bandwidth for one
validator, and separately for a personal validator (phone, mini PC). No
measurement has been taken yet, so no figure is given. The method:

1. Run the four-validator rehearsal (`ops/docker-compose.yml`, see
   `xtask/tools devnet-multinode-smoke`).
2. Sample `docker stats` (CPU, memory, network I/O) every 10 s for one hour.
3. Record the data directory size every 1,000 blocks.
4. Repeat on the personal-validator hardware with the same profile.

## 11. Mainnet gap: VRF in an HSM

Mainnet validators sign from an HSM, and no PKCS#11 backend computes the
chain's VRF (schnorrkel over Ristretto). A mainnet PoS validator therefore
exits at startup today. Options, for Ayaz to choose (D-07): an HSM with a
native VRF over the chain's curve; the VRF in a separate signing process
with its own key isolation; or a VRF construction an HSM supports, which
changes consensus.
