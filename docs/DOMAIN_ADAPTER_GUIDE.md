# Writing a domain adapter

An adapter is the code that reads another network's finality evidence and
tells Budlum what that network has finalized. Budlum settles two kinds of
domain, and each has its own door:

| Kind | Door | Adapter interface |
|---|---|---|
| Consensus domains (PoW, BFT, PoA, ZK) settled by commitment | `TransactionType::Settlement` (`SettlementTx::RegisterDomain`, `SubmitCommitment`) | `src/domain/finality_adapter.rs` |
| External networks (Ethereum, a BudZKVM program) settled by evidence | `TransactionType::ExternalDomain` (`Register`, `SubmitEvidence`) | `ExternalFinalityAdapter` in `src/cross_domain/external/spec.rs` |

Both doors run inside blocks. No RPC writes adapter state; a node that
receives evidence over the network only forwards the transaction.

## 1. The external adapter interface

`ExternalFinalityAdapter` has four required methods and one optional one:

- `descriptor()`: the adapter's identity (`AdapterId`), version, accepted
  evidence versions, finality kind, required depth, time unit and trust
  model. It is read at registration and compared on every call, so an
  adapter cannot be swapped under a domain that already points at its id.
- `verify(evidence, policy)`: derives the height and root from the payload
  and returns a `FinalityAttestation`, or an `AdapterError`. There is no
  partial attestation: when in doubt, refuse.
- `fault_probes()`: the negative cases the adapter must refuse, written as
  data (`FaultProbe` with a `BytePatch` and an `ExpectedRefusal`).
- `golden_evidence()`: one known-good evidence sample for the current
  evidence version.

Rules every adapter follows:

1. Read the evidence version from the envelope; never sniff the format.
2. Derive the height and root from the payload and refuse a declaration
   that does not match (`DeclarationMismatch`).
3. Take time from `policy.now`; an adapter has no clock.
4. Refuse with the most specific `AdapterError` variant. Probes pin the
   variant through `RefusalKind`, and a probe that pins a variant is
   stronger than one that accepts any error.

## 2. Admission

Registration runs `admit` (`src/cross_domain/external/selftest.rs`): the
golden sample must verify, then every probe is applied to the golden sample
and must be refused as it expects. The report commits to the exact probes
that ran (`probe_commitment`), so a probe cannot be swapped for a no-op
under the same name. The probe set and the golden sample are part of the
registration and of what the bond covers.

Admission proves that the adapter refuses the faults its author thought
of. It does not prove that the adapter is correct. Correctness is backed by
the bond: a prover whose evidence is shown wrong is slashed.

Run the same harness locally before bonding anything:

```
bud domain selftest --adapter zkvm --network <label> --golden golden.json \
    [--program-hash <hex>] [--chain-id <id>] [--now <time>]
```

`golden.json` is a `RawConsensusEvidence` in JSON. The command prints the
admission report and exits non-zero when the adapter would not be
admitted.

## 3. Registering and operating

1. Register the domain with `ExternalDomainTx::Register`. The poster must
   be the sender, and the bond is escrowed from the poster's balance; a
   refused registration returns it.
2. Bond additional provers with `BondProver`.
3. Submit evidence with `SubmitEvidence`. The submitter must be the sender.
   Evidence the registry refuses for a registered domain is still an
   accepted transaction: the refusal is recorded.
4. A faulted domain returns with `Readmit`, which reruns admission from the
   stored spec and golden sample.
5. A new evidence format is introduced with `ScheduleFork`; a multi-prover
   rule with `SetQuorumPolicy`. Only the registrant changes the rules.

External-domain writes are refused on mainnet until the mainnet readiness
gates are met (`docs/MAINNET_READINESS.md`).

## 4. Consensus domains

A consensus domain is registered with `bud domain register-pow` (PoW,
header-chain adapter) or a `SettlementTx::RegisterDomain` transaction built
by the domain's own tooling. The operator must be the sender and its bond
is escrowed. Commitments come from a sender with an active RELAYER bond and
carry a finality proof the registered adapter checks in the block.
Equivocation or a parent mismatch freezes the domain in the block; a
governance unfreeze is applied in a later block. Custom plugin domains that
cannot be verified in a block are refused.
