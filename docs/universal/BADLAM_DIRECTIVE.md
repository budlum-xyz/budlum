# Badlam directive: Budlum sovereign interoperability program

Status: active design and first offline implementation, not universal network support.
PR title: Budlum. Commit messages for this work: Badlam.
Stack: testnet-quantum (#110) -> testnet (#126) -> garden (#164) -> budlum.
Baseline: garden e5d21c49. The PR targets garden, above all three existing PRs.
No existing consensus rules are replaced by this plan.

Live discovery: garden now targets testnet. The initial draft on testnet is
superseded by this branch so the actual PR stack matches the requested order.
A trial merge of garden into the latest testnet-based work exposed 23 conflicted
files. That trial was aborted without changing either upstream branch. This
stack does not claim those pre-existing integration conflicts are resolved.

## Product contract

Budlum unifies access to sovereign networks without substituting their consensus,
execution rules, asset identities or trust assumptions. A user requests an outcome.
A bounded, evidence-carrying plan states the required domains, resources, fees,
deadlines and settlement semantics. Unknown adapters and unsupported capabilities
fail closed. An extensible protocol is not a claim that every chain works today.

A shared VM does not provide cross-chain atomicity. A USD ticker does not establish
redemption rights. A content commitment does not prove retrieval availability.
A post-quantum envelope does not strengthen classical source-chain consensus.

## Architecture and existing boundaries

Reuse src/domain/{types,registry,plugin_registry}.rs and the existing
src/cross_domain/external/{spec,registry,selftest,versioning}.rs framework.
Do not create a second external-domain registry. Internal u32 DomainId and external
32-byte DomainKey require an explicit collision-free, versioned binding, not truncation.
Use existing bridge asset namespaces, message authentication, replay nonces,
settlement registries, execution coordinator and B.U.D. 3.0 representation.

1. Identity: genesis/fork-bound domain identities and adapter versions.
2. Capability: proof-backed, versioned transfer, swap, call, storage, identity and credit capabilities.
3. Resource: domain-scoped asset, representation, position, data object and right identities.
4. Intent: signed outcome, bounded debit, minimum credit, expiry, recipient and risk policy.
5. Execution: local atomic, conditional escrow, asynchronous compensation or LP-funded delivery.
6. Evidence: actual finality, availability, authentication and settlement receipts.
7. Product: wallet, POS, SDK, explorer and operations share explicit refusal reasons.

## Implemented slice and honest boundary

crates/intent-policy is a dependency-free offline library and CLI. It checks
bounded route structure, exact identities, snapshot consistency, domain state,
capability claims, debit/credit limits and per-input-asset fee continuity.
It refuses overflow, cycles, ambiguous domains and cross-domain local atomicity.
The CLI limits reads to 32 KiB and labels success POLICY_ONLY.

It does not authenticate domain views, signatures, quotes or evidence. It does
not submit transactions, reserve liquidity, escrow assets, authorize a debit,
perform a swap or connect to payment-card networks. It is a real offline tool,
not yet wired into on-chain payment execution. Callers must not reinterpret its
RouteAssessment as a settlement permission or receipt.

Local tests: 12 library tests, 2 parser tests, 6 executable integration tests passed.
Clippy all-targets/all-features with -D warnings and format checks passed.
The independent CI matrix targets Ubuntu, macOS and Windows. Remote results
remain pending until a concrete run verifies this commit. Root node build,
security suite, real-device tests and public-chain payment E2Es are not complete.

## Payment scenario

Merchant specifies an exact target asset or an explicit fiat-settlement contract.
User signs source asset, recipient, invoice nonce, maximum debit, minimum credit,
fee policy, expiry and permitted assumptions. Solvers propose a source swap,
verified transfer, optional target swap and merchant delivery. Fees remain in
per-leg units. Final receipt binds actual net delivery and verified finality.
A fast LP-funded payment assigns confirmation risk to the LP explicitly.
Refund is a new authorized payment, not history reversal. Fiat rails require
real providers, certification and applicable compliance; the protocol cannot
manufacture bank redemption guarantees.

## Invariants

- Consensus state changes only inside block execution.
- Refusal changes no persistent state, including nonces and reservations.
- Proof, identity, replay and amount checks precede irreversible effects.
- Every allocation, queue, route and proof has an explicit bound.
- No unitless addition of fees, balances or collateral from different assets.
- No equivalence inferred from symbols, decimals or a solver assertion.
- No opaque security score replaces an explicit dependency/assumption graph.
- Source domain sovereignty and PoA isolation remain intact.
- Existing license and review gates remain unchanged. No force-push or bypass.
- A design, a local test and a public testnet readiness claim are different artifacts.

## Work packages

Each package requires production wiring, negative tests, commit SHA and CI run
before it is complete. All packages below remain planned except the offline
subset of BD-008 described above.

### BD-001: Domain identity binding

Bind internal and external registries to genesis and fork context. Refuse aliases, collisions, restart ambiguity and retired-domain reuse.

Integration surface: `src/domain/registry.rs; src/cross_domain/external/registry.rs`. Evidence remains open.

### BD-002: Adapter acceptance SDK

Require evidence grammar, resource budgets, golden vectors and fault probes. Test accept-all/refuse-all adapters and wrong roots.

Integration surface: `src/cross_domain/external/spec.rs; selftest.rs; versioning.rs`. Evidence remains open.

### BD-003: Finality families

Implement real network-specific PoW, PoS, BFT, DAG and validity readers. Test reorgs, long-range attacks and conflicting certificates.

Integration surface: `src/domain/finality_adapter.rs; src/cross_domain/external/`. Evidence remains open.

### BD-004: Rollup dependency graph

Separate L1 finality, L2 execution, DA and sequencer trust. Test premature optimistic withdrawal and invalid validity proofs.

Integration surface: `external adapters; domain profiles`. Evidence remains open.

### BD-005: Capability manifests

Bind enabled capabilities to admitted adapter code, schema, snapshot and limits. Reject self-asserted or downgraded capabilities.

Integration surface: `domain profiles; external intake`. Evidence remains open.

### BD-006: Asset representation graph

Track origin, local id, wrapper path, issuer and redemption rights. Test same-symbol assets, rebasing and transfer fees.

Integration surface: `src/cross_domain/bridge.rs; object_layer`. Evidence remains open.

### BD-007: Signed user intent

Bind payer, recipient, nonce, amount bounds, deadline, refund policy and quote authority. Test replay and recipient substitution.

Integration surface: `account_abstraction; cross_domain/message.rs`. Evidence remains open.

### BD-008: Bounded route policy

Extend the implemented offline tool with authenticated snapshots and quote commitments before settlement integration.

Integration surface: `crates/intent-policy`. Evidence remains open.

### BD-009: Permissionless solver market

Commit quotes, reserve capacity once and select deterministically. Test overbooked liquidity and solver censorship.

Integration surface: `relayer; proof_market; new intent execution surface`. Evidence remains open.

### BD-010: Conditional escrow protocol

Model prepare/commit/abort/refund with per-chain time/finality margins. Test double release, partition and timeout races.

Integration surface: `cross_domain/bridge_tx.rs; external adapters`. Evidence remains open.

### BD-011: Merchant receipts and refunds

Bind exact net credit, invoice nonce and finality. Test duplicate invoices and unauthorized FX changes on refund.

Integration surface: `wallet-core; RPC; explorer_evidence`. Evidence remains open.

### BD-012: POS and card boundaries

Define QR/NFC request schemas, device authority and explicit PSP adapters. Test cloned devices and fake bank confirmations.

Integration surface: `wallet SDK; payment gateway boundary`. Evidence remains open.

### BD-013: Gas abstraction

Bound sponsorship, repayment asset and failure charges. Test sponsor exhaustion, revert spam and unlimited gas abuse.

Integration surface: `account_abstraction; solver execution`. Evidence remains open.

### BD-014: Liquidity aggregation

Integrate AMM, orderbook and RFQ receipts. Test slippage, stale reserves, partial fills and sandwich attacks.

Integration surface: `execution coordinator; market adapters`. Evidence remains open.

### BD-015: Lending and liquidation

Represent collateral locks, debt, oracle policy and auction receipts. Test double-counted collateral and stale-price liquidation.

Integration surface: `object_layer; oracle adapters; lending adapters`. Evidence remains open.

### BD-016: Margin isolation

Enforce per-domain exposure and explicit haircuts. Test depeg, correlated defaults and insolvent LPs.

Integration surface: `risk policy; settlement receipts`. Evidence remains open.

### BD-017: Stablecoin and fiat claims

Carry issuer, redemption restrictions and freeze risk. Test false USD equivalence and incorrect decimals.

Integration surface: `asset registry; payment adapters`. Evidence remains open.

### BD-018: NFT and game resources

Separate ownership, usage, rental and metadata rights. Test duplicate representations and mutable metadata.

Integration surface: `object_layer; application bindings`. Evidence remains open.

### BD-019: Identity and delegation

Support domain-scoped accounts, session keys and recovery. Test expired delegation and cross-domain address confusion.

Integration surface: `account_abstraction; identity_profile; wallet-core`. Evidence remains open.

### BD-020: Universal execution

Preserve VM caller authority, budgets and rollback. Test malicious workers, reentrancy and persistent rejected debits.

Integration surface: `src/execution/coordinator; crates/uel-abi`. Evidence remains open.

### BD-021: Storage federation

Keep B.U.D. 3.0 as the internal canonical object. Reference verified external storage services without adding a competing internal store.

Integration surface: `src/storage/bud3; storage_deal; external adapters`. Evidence remains open.

### BD-022: Availability and access rights

Bind custody, retrieval challenges, encryption and payment. Test unavailable content, lost keys and false deletion claims.

Integration surface: `bud-codec; storage economics; privacy`. Evidence remains open.

### BD-023: Oracles and data market

Make provenance, units, age and challenge policy explicit. Test stale prices, manipulated feeds and API outages.

Integration surface: `data_market; proof_market; oracle adapters`. Evidence remains open.

### BD-024: Selective disclosure

Use scoped nullifiers and minimum disclosure. Test metadata correlation, replay and invalid predicate proofs.

Integration surface: `BudZero; privacy; identity adapters`. Evidence remains open.

### BD-025: Governance and upgrades

Bind activation height, code hash and open intents to versions. Test downgrade, faulty migration and old-proof reuse.

Integration surface: `plugin_registry; external/versioning.rs`. Evidence remains open.

### BD-026: Security assumption propagation

Carry the weakest source dependency without laundering it through a stronger envelope. Test classical-source/PQ-target routes.

Integration surface: `crypto/facts; domain profiles; message envelope`. Evidence remains open.

### BD-027: Evidence explorer

Expose causal intent state, pending reasons and final receipts. Test indexer restart and missing or duplicate events.

Integration surface: `explorer_evidence; RPC; indexer`. Evidence remains open.

### BD-028: Recovery and liveness

Bound retries and provide permissionless alternative carriers. Test solver outages, disk exhaustion and snapshot corruption.

Integration surface: `ops; relayer; persistence`. Evidence remains open.

### BD-029: Performance budgets

Measure worst-case CPU, proof bytes, state growth and route search. Publish no unmeasured TPS or latency claims.

Integration surface: `benches; bounded queues; CI`. Evidence remains open.

### BD-030: Developer and wallet SDK

Ship schemas, vectors, harnesses and refusal catalog. Test version drift and mismatched signing displays.

Integration surface: `crates/wallet-core; sdk; examples`. Evidence remains open.

### BD-031: Model and economic testing

Model escrow state machines and liquidity obligations. Test timeout interleavings, bad debt and adversarial solvers.

Integration surface: `kani; fuzz; loom; property tests`. Evidence remains open.

### BD-032: Launch gates

Require per-adapter devnet, public-testnet, audit and canary evidence. Label each integration verified, experimental or planned.

Integration surface: `CI; ops; audit notes`. Evidence remains open.

## Delivery order

Identity, adapter acceptance, capability, asset identity and signatures precede
fund-moving execution. Next integrate authenticated route simulation and quotes.
Then prove local merchant settlement, followed by a two-domain escrow model and
actual adapter-backed execution. Add gas, liquidity and fiat-risk disclosure
before expanding to lending/liquidation. Storage, VM and identity integrations
reuse the same resource/capability model. Security, measurement, recovery and
platform testing run throughout, not as a final cleanup phase.

## Research, not activated features

- Capability-path compiler: optimize a graph of proof obligations, not just price.
  Measure saved verification work without dropping security dependencies.
- Finality-gap liquidity: price LP confirmation risk explicitly. Model capacity,
  capital cost and default rather than promising instant universal finality.
- Portable retrieval contracts: keep an object identity stable while verified
  storage providers change; preserve encryption and access rights.
- Risk-budgeted intents: expose cost, delay and assumption choices without an
  opaque universal trust score.
- Proof dependency graphs: isolate failures in DA, settlement, issuers or source
  finality without freezing unrelated domains.
- Resource-rights algebra: distinguish ownership, execution, custody, usage and
  redemption. Test that one right cannot silently authorize another.

These are research candidates, not novelty, patentability or security claims.

## Verification and remaining gates

Unit and property tests cover conservation, identity, units and refusal atomicity.
Model checking covers commit/refund interleavings. Fuzzing covers proof envelopes,
route parsers, metadata and ABI boundaries. Adversarial runs include malicious
solvers, relayers, LPs and price feeds. Rehearsals include reorgs, real external
nodes, persistence restore, low memory and retrieval outages.

Platform evidence distinguishes native, VM and emulated runs. Current local
execution is Debian x86_64. An added CI matrix is not evidence of native tests
having passed. Full security tools, human review, Strix and branch protection
remain merge gates. Existing PRs are not closed or merged by this work.

## Living evidence log

For every slice record changed design, production call path, test command,
results, commit SHA, CI run and unresolved risks. Never mark planned code done.
The Turkish reader-facing working document is Badlam direktif.md in the workspace;
this English engineering document belongs in the repository. Secrets and the
attached Turkish source directives stay out of Git.

No claim of testnet readiness is made. No background development is implied when
no process is actually running. A completed conversation turn is not a completed
interoperability program.
