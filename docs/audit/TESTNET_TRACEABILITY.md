# Testnet traceability matrix (#110)

Every line of the #110 directive, the location in the tree that implements it, the test
that pins it, and the CI job that runs that test. A line without a code location is
unfinished work; a line without a test is unverified work; a line without a job is
unrun work. This file is the ledger for all three, and it is kept next to
`AUDIT_FINDINGS.md` because the claim gate excludes `docs/audit/` by design.

Legend for "State":

* `coded + tested` - both columns are filled and the named job is green on
  `testnet-quantum`.
* `coded + tested (fix in this round)` - the named finding moved it to that state in
  this round; see `AUDIT_FINDINGS.md`.

## A. Testnet half of the directive

| Directive line | Code location | Test | Job | State |
|---|---|---|---|---|
| Settlement and domain layer | `src/settlement/` (`anchor_ledger.rs`, `anchor_production.rs`, `cold_quorum.rs`), `src/domain/` (`deal_open.rs`, `commitment_registry.rs`, `finality_adapter.rs`) | `src/tests/settlement_prod.rs`, `src/tests/domain_edge_cases.rs`, `src/tests/distributed_settlement.rs` | `Budlum Core library test` | coded + tested |
| Permissionless registry | `src/registry/` (`permissionless.rs`, `evidence.rs`, `identity.rs`) | `src/tests/permissionless.rs`, `src/tests/permissionless_e2e.rs` | `Budlum Core library test`, `Governance Invariants` | coded + tested (AF-03, AF-11) |
| RPC surface and method classes | `src/rpc/` (`api.rs`, `method_class.rs`, `server.rs`) | `src/tests/hardening_h4_locks.rs`, `src/tests/hardening.rs` | `Hardening H4 locks`, `Network Hardening` | coded + tested |
| RPC auth and rate limiting | `src/rpc/server.rs` (API-key gate, per-peer buckets) | `src/tests/hardening_h4_locks.rs` | `Network Hardening` | coded + tested |
| Network layer: message size and rate limits, no unbounded allocation | `src/network/` (`peer_manager.rs` ceilings and buckets, `protocol.rs` `MAX_CHAIN_SYNC_BLOCKS`, `gossip_dedup.rs`) | `src/tests/network_hardening_locks.rs`, `src/tests/adversarial_p2p.rs`, `src/tests/hardening_h5_h7_locks.rs` | `Network Hardening` | coded + tested (AF-09) |
| Network layer: a fork is not misbehaviour | `src/network/node.rs` (`finality_cert_names_a_block_we_lack`, gossip `Block` arm, sync `Blocks` arm), `src/network/peer_manager.rs` (`report_unjoined_block`) | `src/network/node.rs::a_fork_or_a_missing_block_is_not_peer_misbehaviour`, `src/network/peer_manager.rs::unjoined_blocks_demote_but_never_ban` | `Budlum Core library test`, `Devnet Multi-Node Smoke` | coded + tested (fix in this round, AF-09) |
| Storage and persistence across restart | `src/storage/`, `src/chain/snapshot.rs`, `src/chain/storage_maintenance.rs` | `src/tests/persistence.rs`, `src/tests/snapshot_chaos.rs`, `src/tests/migration_v2.rs`, `src/tests/hard_prune.rs` | `Budlum Core library test` | coded + tested (AF-01, AF-12) |
| Mempool, priority and fee market | `src/mempool/` (`pool.rs`, `authority_cache.rs`) | `src/tests/mempool_dos_locks.rs`, `src/tests/private_transfer_fee_market.rs` | `Mempool canary` (Repo Lint), `Budlum Core library test` | coded + tested |
| CLI and binaries | `src/bin/`, `src/cli/`, `bud/` | `src/tests/bns.rs`, `src/tests/bud_e2e.rs` | `Budlum Core library test`, `BNS`/`bud_e2e` completeness gates | coded + tested |
| Tooling and repository gates | `xtask/gates/` (one module per gate, each with `--self-test`), `xtask/tools/` | every gate's `--self-test` canary; `src/tests/audit_findings_locks.rs` | `Repo Lint (actionlint + buf + genesis + zizmor)` | coded + tested (AF-10 to AF-14) |
| Ops and monitoring | `ops/` (`docker-compose.yml`, `docker-compose.ci.yml`, `monitoring/`, `prometheus.yml`), `xtask/tools/src/multinode_smoke.rs` | `devnet-multinode-smoke` harness, 10 steps | `Devnet Multi-Node Smoke` | coded + tested (AF-09) |
| Contracts | `contracts/` (`foundry.toml`, `graft/`, `external-domain/`) | `src/tests/evm_finality_contract.rs`, forge test suite | `Solidity`, `Budlum Core library test` | coded + tested |
| Testnet configuration and genesis | `config/testnet.toml`, `config/testnet-genesis.json`, `xtask/tools/src/testnet_genesis.rs`, `xtask/tools/src/testnet_rehearsal.rs` | `src/tests/genesis_repro.rs`, `testnet-rehearsal` tool | `Genesis Reproducibility (item 1)`, `Testnet rehearsal` | coded + tested |
| Operator and participation docs | `README.md`, `docs/TESTNET.md`, `docs/VALIDATOR_GUIDE.md`, `docs/OPERATIONS.md`, `config/testnet.toml` | `pq-claims-are-backed`, `tree-is-english`, `no-unicode-dashes` gates | `Repo Lint` | coded + tested (AF-13, AF-14) |

## B. Quantum half of the directive

| Directive line | Code location | Test | Job | State |
|---|---|---|---|---|
| Post-quantum signature schemes and composite accounts | `crates/bpqs/`, `src/crypto/` (`composite.rs`, `address_v3.rs`, `ctx.rs`) | `crates/bpqs` unit tests, `src/crypto/pq_vector_tests.rs`, `src/tests/hash_input_serialize_locks.rs`, `pq-claims-are-backed` canary | `Budlum Core PQ build`, `Timing-Safe Regression` | coded + tested (AF-08) |
| Chain and mempool wiring of the PQ schemes | `src/chain/` (account canary, `state_root` fold), `src/mempool/` authority cache | `quantum-account`, `parallel-execution` (state-root determinism), `mempool-mev-free` canaries in `Repo Lint`, `src/tests/audit_findings_locks.rs` | `Repo Lint`, `Budlum Core library test` | coded + tested |
| Block signature, composite block form and validator keys | `src/consensus/block_signature.rs`, `src/consensus/pos.rs` (`validate_block`) | `src/tests/consensus_expanded.rs`, `src/tests/multi_consensus_locks.rs` | `Budlum Core library test` | coded + tested |
| Light client and security surface | `src/light_client/`, `src/security/` | `src/tests/pow_light_client.rs`, `src/tests/security_auditor.rs` | `Security Hardening`, `Budlum Core library test` | coded + tested |
| BudZero proving system | `budzero/bud-proof/src/` (`plonky3_prover.rs`, `plonky3_air.rs`, `adapter.rs`) | `src/tests/prover.rs`, `src/tests/zkvm.rs`, `stark-soundness --self-test`, AIR selector / LogUp / cross-table gates | `Budlum Core library test`, `Repo Lint` | coded + tested (AF-14) |
| Wallet and note-packing crates | `crates/wallet-core/`, `crates/note-packing/`, `crates/budscan/`, `crates/ai-inference/` | crate unit tests, `src/tests/ai_inference_runtime.rs` | `Crates`, `Budlum Core library test` | coded + tested |
| PQ gates and tooling | `xtask/gates/src/gates/pq_claims_are_backed.rs`, `security_parameters_are_derived.rs`, `logup_multipliers_are_boolean.rs`, `air_selectors_are_opcode_bound.rs` | each gate's `--self-test` | `Repo Lint` | coded + tested |
| PQ measurement documents | `docs/pq/MEASUREMENTS.md` (generated), `docs/pq/*` | `stark-soundness --check` regenerates and compares | `Repo Lint` | coded + tested (AF-14) |

## C. Cross-cutting directive lines

| Directive line | Code location | Test | Job | State |
|---|---|---|---|---|
| No `unwrap`/`panic!`/`todo!`/`unimplemented!` on production paths | whole workspace | `Cargo.toml` `[lints.clippy] unwrap_used = "deny"`, `expect_used = "deny"`; `gates-do-not-panic` gate; the `todo!`/`unimplemented!` sweep in `ast_security_gates` | `Budlum Core quality` (clippy `-D warnings`), `Gates` | coded + tested |
| No implemented-but-uncalled function, field or module | whole workspace | `no-idle-code` ratchet plus `dead-public-api-is-ratcheted` | `Repo Lint`, `Gates` | coded + tested (AF-04, AF-11) |
| New logic fires on production paths (genesis, epoch transition, init, post-restart load) | `src/genesis*`, `src/consensus/pos.rs`, `src/chain/blockchain.rs`, `src/chain/snapshot.rs` | `genesis_repro`, `consensus_rounds`, `persistence`, `regeneration_recovery` | `Budlum Core library test`, `Genesis Reproducibility (item 1)` | coded + tested (AF-04, AF-12) |
| Each fix comes with a regression test | `docs/audit/AUDIT_FINDINGS.md`, one test per finding | AF-01 `slashing_matrix`, AF-02 `byzantine_settlement`, AF-03 `permissionless`, AF-04 `audit_findings_locks`, AF-06 rustdoc gate, AF-07 `minting-paths-are-counted`, AF-08 re-run evidence, AF-09 `peer_manager` floor tests, AF-10 to AF-14 gate self-tests | `Budlum Core library test`, `Repo Lint` | coded + tested |
| No secret, token or personal data in the repository | history | `gitleaks`, `trufflehog`, `zizmor`, `semgrep` | `Secret Scan (gitleaks, full history)`, `Secret Verification (trufflehog)` | coded + tested |
| Gates that cannot run are not a protection | `.github/workflows/*.yml` | `security scan gate self-test` (a softener in a must-block job is refused) | `Repo Lint` | coded + tested |
| Dependency and CVE scanning, fuzz smoke, integration and e2e gates present and logged | `.github/workflows/` (`cargo-deny`, `osv-scanner`, `grype`, `cargo-vet`, `supply-chain-extra`, `fuzz-nightly`, `docker-smoke`) | each workflow's own step; `fuzz/` corpus in `fuzz-nightly.yml` | `Cargo Deny (x10)`, `OSV Scanner`, `Grype`, `Fuzz smoke` | coded + tested |

## D. Testnet Readiness Gate

| Item | Code location | Test | Job | State |
|---|---|---|---|---|
| Clean build, green CI | workspace | all of the above | `Budlum Core`, `Budlum Core quality`, `Budlum Core PQ build` | green on `829b3ee`; re-verified per push |
| Genesis, config, node start end to end | `src/genesis*`, `config/`, `bud` CLI | `genesis_repro` | `Genesis Reproducibility (item 1)`, `docker-smoke` | coded + tested |
| Restart persistence with related counters consistent | `src/chain/snapshot.rs`, `src/chain/storage_maintenance.rs` | `persistence`, `snapshot_chaos` | `Budlum Core library test` | coded + tested (AF-01) |
| Network layer: unbounded allocation, size and rate limits, DoS surface closed | `src/network/` | `network_hardening_locks`, `adversarial_p2p`, `mempool_dos_locks` | `Network Hardening` | coded + tested (AF-09) |
| RPC auth and rate limiting | `src/rpc/server.rs` | `hardening_h4_locks` | `Network Hardening` | coded + tested |
| Consensus and tokenomics per directive, tested, integrated | `src/consensus/`, `src/tokenomics/` | `consensus_rounds`, `p01_consensus_rounds`, `tokenomics`, `tokenomics_proptest`, `finality_live_path` | `Economy Invariants`, `Fork-Choice Invariants`, `Governance Invariants` | coded + tested (AF-05, AF-10) |
| No `unwrap`/`panic!`/`todo!`/`unimplemented!` on production paths | workspace | `Cargo.toml` `[lints.clippy]` plus `gates-do-not-panic` | `Budlum Core quality`, `Gates` | coded + tested |
| README, install and run steps, config examples, testnet participation doc | `README.md`, `docs/TESTNET.md`, `docs/VALIDATOR_GUIDE.md`, `config/testnet.toml` | `pq-claims-are-backed`, `tree-is-english` | `Repo Lint` | coded + tested (AF-14) |
| No secret, token or PII in the repo | history | `gitleaks`, `trufflehog` | `Secret Scan`, `Secret Verification` | coded + tested |
| Multi-node mesh behaves | `ops/`, `xtask/tools/src/multinode_smoke.rs` | 10-step harness | `Devnet Multi-Node Smoke` | coded + tested (AF-09) |
