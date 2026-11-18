# B-0046: the consensus domain plugin layer is registered at bootstrap and never consulted

- **Location:** `src/domain/plugin.rs` (trait `ConsensusDomainPlugin`), `src/domain/plugin_registry.rs:133`, `src/main.rs:1502-1517`, `src/chain/blockchain.rs:156`.
- **Severity:** medium. Architecture claim versus runtime behaviour; no exploit and no fund loss is claimed. It matters because the whole per-family engine story (DAG ordering, PoH ladder, PoSpace plots, PoS/PoA domain rules) rests on a surface nothing calls.

## The chain of evidence

1. Bootstrap builds one plugin per domain and registers it:

   ```rust
   // src/main.rs:1502-1516
   let plugin: std::sync::Arc<dyn ConsensusDomainPlugin> = match &domain.kind { ... };
   if let Err(e) = blockchain.plugin_registry.register(domain.id, plugin) {
       println!("Plugin registration failed (domain {}): {}", domain.id, e);
   }
   ```

   A failed registration prints to stdout and execution continues; the domain then has no plugin and nothing notices.

2. The registry exposes exactly one read: `pub fn get(&self, domain_id) -> Option<&Arc<dyn ConsensusDomainPlugin>>` (`src/domain/plugin_registry.rs:133`).

3. `get` has no production caller. Every call site of `DomainPluginRegistry::get` is inside `#[cfg(test)]` blocks (`src/domain/plugin_registry.rs:167, 168, 218`). `replace()` (`:110`) calls `self.plugins.get(...)`, which is `BTreeMap::get`, not the registry accessor.

4. Therefore the three trait methods that make a plugin do something have no production caller either:
   - `validate_domain_block`: declared at `src/domain/plugin.rs:51`, overridden at `:256`; the only call site in the tree is a unit test at `src/consensus/dag.rs:428`.
   - `extract_commitment`: declared at `src/domain/plugin.rs:66`, overridden at `:289`; no call site at all.
   - `consensus()`: `src/chain/chain_actor.rs:3264` calls `Blockchain::consensus()` (`src/chain/blockchain.rs:10010`), the main chain's engine, not a plugin's.

5. What the chain actually verifies about a foreign domain is the relayer-supplied commitment plus its finality proof: `SettlementTx::SubmitCommitment` (`src/settlement/domains.rs:1713-1741`) calls `verify_commitment_finality_observed`, which dispatches to the adapter for the domain's kind (`src/settlement/domains.rs:632-698`). The adapters are wired; the engines are not.

## Complete reachability map

The conclusion is stronger than "the accessor has no caller". Every engine the plugin layer would drive is unreachable in every configuration:

| engine | possible caller | verdict |
|---|---|---|
| `PoWEngine`, `PoSEngine`, `PoAEngine` | `Blockchain::consensus` as the main chain engine, chosen by `ConsensusType` (`src/cli/commands.rs:7-15`: only `pow`, `pos`, `poa`) | live, main chain |
| `DagEngine`, `PohEngine`, `PoSpaceEngine` | main chain: not selectable, `ConsensusType` has no such variant. Domain: plugin never consulted | unreachable outside tests |
| `BftDomainPlugin`, `ZkDomainPlugin`, `StorageAttestation`, `AiInference`, `Custom` domains | the bootstrap engine match ends in `_ => continue` (`src/main.rs:1499`), so no plugin is ever built or registered for these kinds | unreachable, and the `ConsensusKind::Bft` arm at `src/main.rs:1508` can never execute |

So the answer to "is the DAG/PoH/PoSpace work in #194/#198 enforced anywhere?" is no, not for block ordering. What those heads do enforce is the finality half: `verify_commitment_finality_observed` (`src/settlement/domains.rs:583`) dispatches to `DagFinalityAdapter`, `PohFinalityAdapter`, `PospaceFinalityAdapter` and the rest, and that dispatch is real, is on the settlement path, and is covered by the mainnet classical-only refusal (`src/settlement/domains.rs:126-140`, applied at `:1720` and `:2653` - both production doors, verified).

## Consequences

- A domain's own block rules are not enforced by the chain. For a `Dag` domain that means multi-parent ordering, the height-strictly-greater rule and parent resolution never run on an imported domain block; for `Pospace` the plot registry never runs; for `Poh` the ladder never runs. Only the finality certificate gates the commitment, so the domain's agreement is as strong as its quorum and no stronger.
- The unit tests that "prove" engine behaviour (`src/consensus/dag.rs:319-430`, `src/consensus/pospace.rs:468-616` and the PoH equivalents) assert about code no production path executes. That is not a test defect; it is a reason not to read those files as evidence of protocol behaviour.
- Latent defects inside those engines are unreachable today, which is what keeps B-0045 at "latent" rather than "live". The moment `get()` gains a caller, all of it becomes live at once, unexercised.
- The local architecture plan says DAG, PoH and PoSpace "run with full `ConsensusDomainPlugin` and `DomainFinalityAdapter` support". The adapter half is true. The plugin half is not: the plugin is constructed, stored and never asked anything.

## Repair plan

1. Either wire it: have domain block intake resolve the domain's plugin through `plugin_registry.get` and call `validate_domain_block` before `extract_commitment`, with a refusal (not a silent pass) when a domain of a consensus kind has no registered plugin.
2. Or say it plainly: mark the plugin surface `WIRING:` with the sentence that says it lands with the domain block intake, add the registry accessor to the dead-API baseline, and correct the plan and README claims so they describe adapters, not plugins.
3. In both cases, make a failed `plugin_registry.register` at bootstrap fatal for that domain rather than a `println!`, so a domain is never silently plugin-less.
4. Add a regression that fails if `DomainPluginRegistry::get` loses its last non-test caller while the plan still claims plugin validation.

## Status

open. Source-level evidence on `budlum-consensus-of-consensuses` head `7533b71b4812a20ca078611c77d9d82c1f28ebfc`. No reproduction harness: the claim is an absence of call sites, which `git grep` settles for this tree.
