# B-0045: The PoSpace engine has no production plot registration and weights self-declared capacity

- **Location:** `src/consensus/pospace.rs` on `budlum-consensus-of-consensuses` head `7533b71b4812a20ca078611c77d9d82c1f28ebfc` (PR #194). The engine is constructed for every domain of kind `Pospace` in `src/main.rs:1498` and paired with `PospaceDomainPlugin` in `src/main.rs:1511`.
- **Severity:** high for correctness and for the guarantee the module claims; no immediate fund loss, because no domain in the shipped catalog is registered with `ConsensusKind::Pospace` (`src/unification/domain_catalog.rs:160-423` lists PoS, PoW, BFT, ZK, `StorageAttestation`, `AiInference` and two `Custom` kinds, no PoSpace). The defect is reachable by any operator who registers a PoSpace domain through the settlement registration path.

## Part 1: the plot registry can never be filled in a production build

`register_plot` is the only writer of the `plots` map, and it is compiled out of every non-test build:

```rust
// src/consensus/pospace.rs:164
#[cfg(test)]
fn register_plot(&self, address: &str, plot_id: [u8; 32], size_bytes: u64) -> Result<(), ConsensusError>
```

`PoSpaceEngine::new` (`:150-156`) creates the map empty, and the only other mutating call site is inside `register_plot` itself (`:183-198`). Consequences in a production binary:

- `prepare_block` fails for every input: `plots.get(&key)` misses and returns `PoSpace producer {key} has no registered plot`, or the empty-map branch returns `PoSpace engine has no registered plots` (`:269-283`).
- `validate_block` fails for every block: a block with `producer: Some(p)` hits `PoSpace producer {key} is not registered in plot registry` (`:333-339`); a block with `producer: None` hits `PoSpace block references an unregistered plot` (`:345-353`).

So a domain registered with `ConsensusKind::Pospace` can neither produce nor accept a block. The chain accepts the domain registration, builds the plugin, and then the domain is permanently frozen. Nothing in the test suite exercises this: every PoSpace test calls the test-only `register_plot` first (`:469-616`), so the production path is never executed.

## Part 2: fork choice credits capacity no one registered, and the "space proof" carries no secret

`fork_choice_score` (`:389-442`) walks a candidate chain, checks each block's hash, linkage, witness shape, challenge binding and response, and then adds `size_bytes` to `proven_capacity` (`:435`). The registry comparison is conditional on finding a record:

```rust
// src/consensus/pospace.rs:422-434
if let Some(ref plots) = plots_guard {
    if let Some(producer) = block.producer {
        if let Some(reg) = plots.get(&producer.to_hex()) {          // miss => no check, capacity still credited
            if reg.plot_id != plot_id || reg.size_bytes != size_bytes { return 0; }
        }
    } else if let Some(reg) = plots.values().find(|r| r.plot_id == plot_id) {   // miss => no check
        if reg.size_bytes != size_bytes { return 0; }
    }
}
```

A missing record is therefore not a zero score, unlike `validate_block` where a missing record is a hard error. The branch's own test pins this behaviour: `pospace_fork_choice_scores_candidate_chain_capacity_deterministically` (`:544-572`) builds a 200 MB chain with one engine and asserts that a second engine that registered only a 2 MB plot still prefers that 200 MB chain, "regardless of engine state".

The weight is consequently self-declared. The proof itself binds nothing:

```rust
// src/consensus/pospace.rs:55-64
pub fn compute_plot_response(plot_id: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    // Sha256("BDLM_POSPACE_RESPONSE_V1" || plot_id || challenge)
}
```

`plot_id` is a free 32-byte witness field, the challenge is derived from the parent hash and height (`:128-138`, `:256-260`), and the response is a public hash of both. No value in the proof depends on data the prover must actually store, so anyone can mint a valid `(plot_id, challenge, size, response)` tuple for any capacity up to `MAX_PLOT_SIZE_BYTES = 1 PiB` (`:24`, enforced at `:309-314` and `:415-421`). What would bind capacity to storage is registration, and registration is exactly the piece that the scoring function treats as optional and the production build cannot perform.

## Claim mismatch

The module documentation states that "PoSpace requires miners to commit verifiable storage capacity ('plots')" and that "fork choice scores each candidate chain strictly by the verified plot capacity committed inside that candidate chain" (`:1-9`), and the local architecture plan repeats that `PoSpaceEngine` provides a challenge-bound space proof with candidate-chain capacity scoring. Neither statement holds as written: the capacity is an unauthenticated field, and the registry that could authenticate it is unreachable in production.

## Impact

- A PoSpace domain registered by an operator is dead on arrival: no producer can build a block and no verifier accepts one. That is a liveness failure of an advertised consensus family, not a fund loss.
- If a registration path is added without changing scoring, fork choice will keep weighting capacity that no state vouches for, because the weight is read from the witness rather than from registered domain state. The 1 PiB clamp then turns "prove 1 PiB" into "declare 1 PiB per block".
- Because the clamp is per block and cumulative, declared capacity grows with chain length; a fork-choice rule that only counts declared bytes gives no Sybil resistance at all.

## Repair plan

1. Commit plots to domain state: a registration transaction (operator or governance) that records `(producer, plot_id, size_bytes)` in consensus state, inside the value the domain's `config_hash` or `validator_set_hash` covers.
2. Score only registered capacity: in `fork_choice_score`, treat a producer with no registry record as `0` (fail closed) exactly as `validate_block` already does, and read `size_bytes` from the registered record rather than from the witness.
3. If real space is intended, make the response depend on stored data (for example a Merkle opening over a plot the prover committed to, with the commitment in state), instead of `Sha256(tag || plot_id || challenge)` over public inputs.
4. Regressions: a production-shaped engine (no test-only registration) must fail `prepare_block` and `validate_block` with a named error rather than only in tests; an unregistered 1 PiB chain must score `0` and must never win `is_better_chain`; a registered plot presenting a different `size_bytes` must score `0` (already covered at `:600-605`).
5. Until (1) to (3) land, document PoSpace as not deployable and remove it from the list of consensus families asserted to be production-ready in the plan and README claims.

## Status

open. No fixing commit, no reproduction harness outside the branch's own tests and no CI evidence. The analysis is source-level on head `7533b71b`; the resolution of `reject_unregistered_set_for_bridge` in the PoSpace finality adapter (`src/domain/finality_adapter.rs:2416-2476`) was reviewed and does bind the authority set when `validator_set_hash` is non-zero, so the finality door is not the weak point here: the engine is.
