# Garden settlement audit

## B-0001: Garden writes the Budlum domain view outside blocks

- Status: open. Fix commit: none. Green CI run: none.
- Severity: high. This is a consensus-consistency risk, not a demonstrated chain split.
- Reviewed source: Garden PR #164, head `d4a76a7521de3e06ac2c582670bacca3e206b3db`; main base `95c07fd72faaf21656e1e44d2dff51ed4dee05f3`.
- Directive: G-1 requires consensus state changes inside blocks. Garden section 4.3 prohibits new primary-chain transaction types and section 0.3 requires dependencies already merged to main.

### Evidence

`src/garden/node.rs:483-493` calls `link.register` when its local domain view is absent. `src/garden/settlement.rs:132-142` then calls:

```rust
self.chain
    .register_consensus_domain(domain_record(genesis, operator, hash))
    .await
```

`src/chain/chain_actor.rs:3791-3792` sends this directly to `Blockchain::register_consensus_domain`. `src/chain/blockchain.rs:1453-1457` writes the node's `domain_registry` and persists the row. This call does not construct, submit or execute a block transaction. The report path in `src/garden/settlement.rs:148-164` similarly rotates the local authority set and submits a local commitment. The lifecycle path at lines 168-180 calls a local status mutation. The authority and status writes end in `store_updated_consensus_domain` at `src/chain/blockchain.rs:1557-1570`.

### Why it matters

Two Budlum nodes can receive different Garden calls while executing the same Budlum blocks. They can then hold different domain registries or commitments and disagree about the Garden view or a later global header. The current single-node path does not establish canonical replication. A two-node failure has not yet been run; this risk follows from the traced write path.

### Required correction

1. Recheck the code and the merged main head immediately before implementation.
2. Route domain registration, authority-set updates, commitments and lifecycle transitions through an authenticated, deterministic, existing block-only interface available on main. Do not introduce a primary-chain transaction type contrary to the Garden directive.
3. Define how a first-time Garden user obtains any required fees and bond without assuming an existing account. Demonstrate this rather than silently waiving admission or charging an undisclosed account.
4. Exercise the full flow against at least two independent Budlum nodes. Both must replay the same blocks to the same domain state and commitment roots. Direct, unauthenticated and out-of-block mutations must fail without changing state.
5. Verify restart and historical replay, test all four lifecycle states, and run the five-validator Garden acceptance and NAT scenarios in CI.

### Blocker

At the captured main head, the directly invoked registry path is node-local. The block-only settlement work is in PR #110, not merged to main. Its registration and fees require an operator funding and bond model. The present evidence does not establish an implementation satisfying all Garden constraints. Do not claim this issue fixed or treat the unmerged PR as an available main dependency. Continue with independent Garden work while the dependency and funding path are resolved.
