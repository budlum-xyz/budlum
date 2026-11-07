# Lane A live verification ledger (WP-01)

Directive section 14 assigns the unified findings ledger to live verification
in four lanes (WP-01..WP-04). This file is the lane A record: every ledger
entry whose closing package is WP-08, WP-12, WP-13, WP-14, WP-15, WP-16 or
WP-17, re-verified against the live tree. English per `tree_is_english`.

## How this was produced

- **Verification base.** Repository snapshot `HEAD` = `cccf1da` (`main`,
  2026-11-05, "Add files via upload"), the same tree this branch carries. The
  snapshot post-dates the directive's analysis base (2026-11-02,
  `testnet-quantum`) and includes the merged consolidation (PR #5) and the A0
  codec register / dedup index (PR #6). Line atiflari are content anchors,
  not line numbers: every claim below is anchored by identifier and file.
- **Method.** (1) Every lane A record was extracted from directive section
  14 programmatically and grouped by the closing package; (2) each record was
  scanned for its machine-checkable identifiers across `src/`, `crates/`,
  `budzero/`, `bud/`, `contracts/`, `ops/`, `config/`, `docs/`, `proto/`,
  `xtask/`, `benches/`, `tests/`; (3) headline findings were read at their
  anchors (finality quorum, role constants, liveness tracker, reward pool,
  testnet RPC profile, libp2p feature set, WIRING markers); (4) verdicts were
  assigned by inspection only where the evidence is the file content itself.
- **CI.** No local Rust toolchain exists in this environment; CI is the
  validator (directive: do not hold commits, do not block on CI unless it is
  red). No red CI run was observed during this work. The locks added in
  `src/tests/audit_lane_a.rs` are plain-`cargo test` unit tests in the style
  of the existing `regression_chain.rs` locks.
- **What this PR does not claim.** WP-01 does not fix findings; the closing
  packages do. An entry marked Open stays open until its closing package
  merges and flips its repro test (S-3). Repro tests for Open entries are
  owed on the `audit/repro-a` branch; that branch never merges, and each
  closing package moves its own repro test into its pull request. This PR
  carries no failing test.

## Status legend (directive 14.1)

| Status | Meaning |
|---|---|
| Open | Open in the live tree. Evidence below; repro pending on `audit/repro-a`. |
| Verified | Open and reproduced. Reproduction is by file inspection at the cited anchors. |
| Closed (previously fixed) | Fixed in this snapshot before WP-01 ran; a permanent lock test holds it (name cited). |
| Kaldirma ile kapandi | Not used for lane A yet; removal-closing entries are recorded as Open with the WP-07 foot noted until `no_legacy_storage` goes green. |
| Invalid | Not used this pass; no entry lost its precondition without a fix landing. |

## Summary

| Metric | Count |
|---|---|
| Lane A records | 90 |
| Closed (previously fixed) | 7 |
| Verified | 8 |
| Open | 75 |

Closing-package distribution: WP-08 (4: BLG-252, BULGU-022, feet of BLG-253/BLG-266),
WP-12 (23 + 2 shared, in-flight PR #9), WP-13 (1), WP-15 (6), WP-16 (13),
WP-17 (44), WP-44 (shared foot of BLG-205). WP-14 closes no lane A record.

## In-flight work this ledger interacts with

- **PR #8** (`arena/b7784c85-budlum`, WP-06/WP-07/WP-24 + dedup index + access
  layer + object replacement flow): removes the BUD 1.0 storage surface. Rows
  BLG-089, BLG-090, BLG-107, BLG-113, BLG-140, BLG-167, BLG-183, BLG-253 carry
  an explicit WP-07 removal foot; their remainder closes in WP-17/WP-16/WP-08.
  Verification of those rows against a tree that includes PR #8 will happen
  when it merges (their Open status is conservative until then).
- **PR #9** (`arena/5b54fce9-budlum`, WP-12): replaces the dual quorum with
  the seat quorum and wires Filiz/handoff. Rows BLG-018, BLG-027, BLG-096,
  BLG-132, BLG-158, BLG-203, BLG-206, BLG-207, BLG-246, BLG-259, BLG-264 and
  the BULGU-00{1..4,14,23..27}/TEST-GAP-08 family close there. The BLG-246
  reproduction in this ledger is the exact code PR #9 removes.
- **WP-08** (blocked on WP-01 merging): BLG-252 (roles 5/9 removal), the
  WP-08 foot of BLG-253 (`calculate_leaf`), BULGU-022 (RoleBond arms), and
  the class-split remnants verified fixed here for BLG-266.
- **WP-13** (blocked on WP-12): BLG-251 (penalty-free suspension).

## The ledger

| ID | Severity | Closing | Finding (English) | Live status | Evidence / note |
|---|---|---|---|---|---|
| BLG-001 | Critical | WP-12 | PoS leader election could not skip empty heights; a slot with no elected leader stalled finality forever | Closed (previously fixed) | Fix trace present: `MAX_LEADER_ROUNDS` and `affordable_leader_round` in `src/consensus/mod.rs`. Locks: `audit_lane_a::blg_001_leader_rounds_are_bounded_and_reachable`, `audit_lane_a::blg_001_leader_round_pricing_is_wired`. |
| BLG-002 | High | WP-16 | Distributed testnet profile would launch without a key ceremony, peer source or tokenomics | Open | `config/testnet.toml` ships no validator set and no peer source (bootstrap refuses to start without one); the only ceremony artifact is the template in `config/mainnet-genesis.json` (`ceremony_status = template_ready`). Closes with WP-16. |
| BLG-003 | High | WP-16 | Genesis supply validation ignores extra allocations and bootstrap stake together against the 100M cap | Open | `genesis_allocations` refuses allocations that do not sum to `BUD_TOTAL_SUPPLY` (`src/tokenomics/mod.rs`); the joint check of extra allocations plus bootstrap stake against the cap is not present in the validation path. Closes with WP-16. |
| BLG-005 | Medium | WP-16 | Default secret/data directories were not git-ignored | Closed (previously fixed) | Ledger closed it; verified `.gitignore` carries `/secrets/` and `/data/`. Lock: `regression_chain::default_secret_and_data_dirs_are_git_ignored`. |
| BLG-006 | Medium | WP-16 | Verification reward pool was not wired to the production epoch transition | Closed (previously fixed) | Fix trace present: `crate::tokenomics::reward_pool::pay_epoch(state, &schedule, closed_epoch)` is called from the epoch-close path (`src/chain/blockchain.rs:4090`). Lock: `regression_chain::reward_pool_is_paid_from_the_epoch_transition`. |
| BLG-007 | Medium | WP-17 | GlobalBlockHeader is not the common consensus commitment; the PQ block budget is still measured in JSON | Open | The JSON budget half reproduces in the tree: `consensus::MAX_BLOCK_SIZE` is measured over `serde_json` (`src/consensus/mod.rs`), distinct from the 1 MiB prost budget. `GlobalBlockHeader` exists (`src/chain/blockchain.rs`) but is not the common commitment. Closes with WP-17. |
| BLG-008 | Medium | WP-16 | The open-RPC acceptance criteria contradict the key-required testnet profile | Verified | `config/testnet.toml:50` requires `auth_required = true` (the key is required whatever the bind address) while `docs/TESTNET.md:33` states "The public RPC needs no API key.". Reproduced by inspection this snapshot. Closes with WP-16. |
| BLG-017 | Critical | WP-15 | Unauthenticated P2P Prevote/Precommit/FinalityCert UTF-8 byte slicing panics and drops the node | Open | Message families present: Prevote 16 files, Precommit 15 files, FinalityCert 26 files (`src/chain/blockchain.rs`, `src/bin/budlum-light.rs`). Byte-slice panic sites not yet narrowed to a single anchor; repro owed. Closes with WP-15. |
| BLG-018 | Critical | WP-12 | Hybrid finality (finalized_height) stalls on live networks across four independent breaks | Open | `finalized_height` present (30 files). Not reproduced: needs a four-node local network showing `finalized_height` progress (special audit of WP-01). Closes with WP-12; in-flight PR #9 replaces the dual quorum with the seat quorum. |
| BLG-019 | Critical | WP-17 | TransactionType::StateUpdate wrote arbitrary nonces to any account with no authority or commitment binding | Closed (previously fixed) | Fix trace present: the `StateUpdate` arm in `src/execution/executor.rs` refuses with `state_update_retired`; the tag stays decodable for old blocks. Lock: `audit_lane_a::blg_019_state_update_is_refused`. |
| BLG-020 | Critical | WP-17 | collect_block_transactions mutated temp_state before rejection; missing Executor nonce/signature checks split the consensus chain with two mempool transactions | Closed (previously fixed) | Fix trace present: `collect_block_transactions` validates then applies against `candidate_state`, a clone of `temp_state`, and promotes only on success (`src/chain/blockchain.rs`). Lock: `audit_lane_a::blg_020_rejected_transactions_do_not_mutate_the_block_state`. |
| BLG-021 | Critical | WP-17 | Role bonds (bond_relayer/bond_prover/bond_storage_operator) burn funds, overwrite bonds, pierce vesting and write RPC state out of block | Open | `bond_relayer` 8 files, `bond_prover` 9 files, `bond_storage_operator` 3 files (all rooted in `src/core/account.rs`). Closes with WP-17. |
| BLG-023 | Medium | WP-17 | Executor::RelayerResult rejects valid DomainEventTree proofs of single-event external blocks and does not look up the RELAYER bond | Open | `Executor::RelayerResult` not found under that exact name; `DomainEventTree` 12 files, `RELAYER` 34 files. The arm was renamed/refactored; the behavioural gap is unchecked. Closes with WP-17. |
| BLG-027 | High | WP-12 | V5 (ML-DSA-87) wallet addresses are incompatible with PoS block production, slashing evidence and storage challenge signatures | Open | No ML-DSA-87 locus in `src/consensus/pos.rs`; `BlockHeader` producer key paths exist elsewhere (`src/chain/genesis.rs`, 5 files). Closes with WP-12; in-flight PR #9 touches this path. |
| BLG-028 | High | WP-17 | StateSnapshotV2::from_bytes skips digest verification, apply_v2_snapshot skips finality bounds, save_snapshot_v2 is not atomic | Open | `StateSnapshotV2::from_bytes` 7 files, `apply_v2_snapshot` 4 files, `save_snapshot_v2` 4 files (`src/chain/blockchain.rs`). Closes with WP-17. |
| BLG-031 | Low | WP-17 | GovernanceState::proposals keeps unbounded history, inflating per-block state_root cost; bpqs::EpochWindow narrows u64 to u32 | Open | `GovernanceState::proposals` 1 file, `bpqs::EpochWindow` 1 file (`src/tests/regression_chain.rs`), `state_root` 140 files. Closes with WP-17. |
| BLG-033 | Critical | WP-15 | Unbounded bincode::deserialize on the unauthenticated P2P wire frame (OOM bomb) and AiModelRegister field loss | Verified | `src/network/proto_conversions.rs` carries unbounded `bincode::deserialize(&payload.data)` at lines 1324, 1334, 1351, 1375, 1439-1479 and 1793 (10 sites, no length cap); also `src/ai_inference/verify.rs` (25 files reference it). The ledger already records this as verified-open. Closes with WP-15. |
| BLG-034 | High | WP-15 | P2P subnet diversity bypass (IPv6/::ffff:), Kademlia private-IP poisoning, unbounded tokio::spawn, Bitswap state leak | Open | `::ffff:` 1 file (`src/bin/support/http.rs`), `tokio::spawn` 12 files (`src/bin/budlum-faucet.rs` and others). Closes with WP-15. |
| BLG-041 | Critical | WP-17 | settlement_root replay divergence and out-of-block AccountState mutations split deterministic consensus and restart replay | Open | `settlement_root` 11 files, `AccountState` 103 files (`src/chain/blockchain.rs`, `src/bin/budlum-light.rs`). Closes with WP-17. |
| BLG-042 | Critical | WP-17 | Failed BLS-signed Prevote/Precommit cause out-of-block state_root divergence; innocent validators are slashed at scale | Open | Prevote 16 files, Precommit 15 files, `state_root` 140 files (`src/chain/blockchain.rs`). Closes with WP-17. |
| BLG-044 | Medium | WP-17 | Weightless import_qc_blob majority, stale same-height ProofTrieCache, reorg/restart persistence loss, epoch_index*100 telemetry error | Open | `import_qc_blob` 10 files, `ProofTrieCache` 2 files, `epoch_index * 100` 1 file (`src/core/account.rs`). Closes with WP-17. |
| BLG-065 | High | WP-17 | NftTag silent fee burn, NftBurn ghost Vault folders, BnsRegistry lifecycle defects and cross-shard vesting/state violations | Open | `NftTag` 6 files, `NftBurn` 12 files, `Vault` 12 files, `BnsRegistry` 19 files (`src/bns/`, `src/core/transaction.rs`). Closes with WP-17. |
| BLG-066 | High | WP-17 | budlum-core keeps BUD storage volatile in RAM, PoA/BFT boot diverges, CLI-TOML precedence inverted, bud CLI hardcodes mainnet chain_id | Open | `budlum-core` 34 files, `chain_id` 184 files. `src/bin/bud.rs` and CLI surfaces present; smoke/unit split not verified for the boot divergence. Closes with WP-17. |
| BLG-088 | Medium | WP-17 | Integration tests ship fake/empty security asserts; advisory_reachability lock skips 8 of 11 Cargo.lock files; hardcoded TCP port clashes | Open | `advisory_reachability` 3 files (`src/tests/advisory_reachability.rs`), `Cargo.lock` 18 files, `src/tests/` 28 files. Lock-count drift not re-measured; CI to confirm. Closes with WP-17. |
| BLG-089 | High | WP-17 | CodingAudit answers carry no column binding (AnswerCodingAudit accepts the operator-chosen column); reload replay masks 4 top-layer state root fields | Open | `CodingAudit` 10 files, `AnswerCodingAudit` 7 files (`src/chain/blockchain.rs`, `src/chain/chain_actor.rs`). Part closes by removal with WP-07 (in-flight PR #8); the remainder closes with WP-17. |
| BLG-090 | Medium | WP-17 | settlement_prod.rs masked by #![cfg(false)]; domain_throughput.rs masked by fake required-features; contradictory asserts, filler tests, Turkish residue | Open | Partial fix trace: `src/tests/settlement_prod.rs` now declares `#[cfg(test)] mod settlement_prod_tests` (no `#![cfg(false)]`), and `domain_throughput` carries `required-features = ["__bench_domain_throughput_disabled"]` (`Cargo.toml`). Compile-green is unproven here (no local toolchain); CI must confirm. Turkish-residue sweep not redone. Closes with WP-17; removal foot with WP-07. |
| BLG-094 | High | WP-16 | config/archive.toml shipped chain_id 42; ops/docker-compose.yml ran pow --difficulty=0 despite the PoS claim; ops/Dockerfile carried Turkish text | Closed (previously fixed) | All three feet verified fixed: `config/archive.toml` and `config/testnet.toml` carry `chain_id = 45261`; compose runs `--consensus=pos`; `ops/Dockerfile` contains no Turkish. Lock: `regression_chain::archive_profile_compose_and_dockerfile_are_consistent`. |
| BLG-096 | High | WP-12 | invalidate_finality_from_height misses the checkpoint grid leaving orphaned certificates; apply_qc_fault_verdict swallows slash errors; reorg/prune drop double-sign evidence; corrupt vote_history restarts from zero | Open | `invalidate_finality_from_height` 1 file, `apply_qc_fault_verdict` 3 files, `vote_history` 3 files. Closes with WP-12; in-flight PR #9 touches finality. |
| BLG-100 | Critical | WP-17 | validate_transaction demands tx.amount + tx.fee liquid for Unstake, freezing bonds; Executor skips spendable_balance on 36 arms; expired BNS records mutable | Open | `validate_transaction` 18 files, `Unstake` 11 files; the literal `tx.amount + tx.fee` is absent (const-evaluated paths moved). Closes with WP-17. |
| BLG-101 | Critical | WP-17 | StateSnapshotV2 restore and calculate_state_root integrity defects: PoA chain lock, poa_onboarding / Validator.roles state-root blind spot, UnfreezeDomain root mismatch, storage reward double-print | Open | `StateSnapshotV2` 20 files, `calculate_state_root` 40 files, `poa_onboarding` 17 files; `Validator.roles` and `UnfreezeDomain` literals absent. Closes with WP-17. |
| BLG-102 | Critical | WP-17 | try_reorg and validate_candidate_chain fork-choice defects: sled stale-branch bridge_state contaminates state_root, abandoned-branch transactions lost, shards_root skipped, in-memory domain_registry wiped | Open | `try_reorg` 11 files, `validate_candidate_chain` 2 files, `bridge_state` 26 files, `shards_root` 8 files (`src/chain/blockchain.rs`). Closes with WP-17. |
| BLG-103 | Critical | WP-17 | On-chain governance capture and a 115-day lockup: a slashed validator keeps voting weight, 300-atom proposals lock 100k epochs, slash-burn accounting lost, flash-stake/Sybil voting | Open | `GovernanceState` present (`src/core/governance.rs`); voting-weight retention of slashed validators not re-derived. Closes with WP-17. |
| BLG-104 | Critical | WP-17 | Mempool free-transaction deletion (PoolBytesFull), parent-nonce eviction / RBF zombie block starvation, sled stale-transaction leak, unvalidated apply_cross_shard_transfer | Open | `PoolBytesFull` 3 files, `sled` 13 files, `apply_cross_shard_transfer` 2 files (`src/sharding/mod.rs`). Closes with WP-17. |
| BLG-107 | Critical | WP-17 | NftBoost / distribute_bud_boost_share_in_state deadlock produce_block(); unchecked .sum::<u64>() SIGABRT; %4 bud_share supply loss | Open | `NftBoost` 12 files, `distribute_bud_boost_share_in_state` 4 files; the literal `produce_block() -> None` is absent (signature changed). Part closes by removal with WP-07 (in-flight PR #8); the remainder closes with WP-17. |
| BLG-108 | Critical | WP-15 | gossipsub pre-validation routing bans honest validators; RBF/race penalty; GossipDedup permanent re-ban loop; SlashingEvidence reputation farming | Open | `gossipsub` 8 files, `GossipDedup` 4 files (`src/network/gossip_dedup.rs`), `SlashingEvidence` 15 files. Closes with WP-15. |
| BLG-113 | Critical | WP-17 | Sled recover_interrupted_commit partial-rollback corruption (ACCT:*/GLOBAL_HEADER:*), snapshot_height >= chain_len double replay silently corrupting state_root, missing Executor nonce check | Open | `recover_interrupted_commit` 2 files (`src/storage/db.rs`), `snapshot_height >= chain_len` 1 file; `ACCT:*`/`GLOBAL_HEADER:*` literals absent. Note: `src/storage/db.rs` is WP-07 scope (in-flight PR #8); the replay and nonce feet close with WP-17. |
| BLG-118 | Critical | WP-17 | Uncommitted block/tx witness malleability (tx_root witness blindness) splits consensus at MAX_BLOCK_SIZE on the same block.hash; V6 PrivateTransferSubmit 100% lockup; wallet-core multisig/guardian-recovery mismatch | Open | `tx_root` 36 files, `MAX_BLOCK_SIZE` 5 files, `PrivateTransferSubmit` 12 files. Closes with WP-17. |
| BLG-119 | Critical | WP-17 | Unstake escapes 100% validator and cross-role slashing; 1-atom Stake mid-jail PoS reactivation; dead ProposalType::SlashValidator; permanently locked Slashed role bonds | Open | `Unstake` 11 files, `ProposalType::SlashValidator` 5 files, `Slashed` 25 files, `jail` 32 files. Closes with WP-17. |
| BLG-125 | Critical | WP-17 | Out-of-block storage/secret-body RPC mutations split state_root at zero cost; StorageRegistry::is_empty() misbehaviour; owner_of/RevealGateway/revoke/social_delete/u64::MAX arms | Open | `owner_of` 6 files, `RevealGateway` 5 files (`src/rpc/server.rs`); `StorageRegistry::is_empty()` literal absent. Closes with WP-17. |
| BLG-128 | High | WP-17 | MerkleTrie/ProofTrieCache replacement and storage assignment failure; L1NoteRegistry and derive_nullifier defects | Open | `MerkleTrie` 6 files, `ProofTrieCache` 2 files (`src/chain/chain_actor.rs`), `L1NoteRegistry` 8 files, `derive_nullifier` 4 files. Closes with WP-17. |
| BLG-132 | High | WP-12 | split_resolver empty-chain / fake-height victory; V6 threshold_mldsa non-canonical owner order (16x ML-DSA work); hex parser 0x0 burn-address trap; can_reorg/select_best_chain gaps | Open | `split_resolver` 5 files (`src/consensus/mod.rs`), `threshold_mldsa` 5 files, `can_reorg` 1 file. Closes with WP-12; in-flight PR #9 touches finality. |
| BLG-140 | High | WP-16 | Testnet storage provider serves in-memory proofs (InMemoryStorageProvider); RegistryParams::validate and MainnetValidatorKeyConfig gaps (params.rs, liveness.rs, evidence.rs) | Open | `InMemoryStorageProvider` 3 files (`src/storage/emit.rs`), `RegistryParams::validate` 6 files, `LivenessTracker` 5 files, `params.rs` 7 files. Part closes by removal with WP-07 (in-flight PR #8); the remainder closes with WP-16. |
| BLG-147 | High | WP-17 | core::map_keys accepts duplicate/unordered keys on deserialize; QuarantineLedger overwrites existing quarantine proofs and accepts invalid severity; SyncCodec asymmetric >10 MiB frame stall | Open | `core::map_keys` 27 files, `QuarantineLedger` 8 files (`quarantine_ledger.rs`, 2 files), `SyncCodec` 2 files. Closes with WP-17. |
| BLG-151 | High | WP-17 | core::encoding NUL-delimited framing collision + dropped V4-V6 tx / PoS-BFT header fields; AI system-prompt refusal gate bypassed by 4 syntaxes (ai-core/src/system_prompt.rs) | Open | `core::encoding` 1 file (`src/network/node.rs`), `address.rs` 3 files, `ai-core/src/system_prompt.rs` 5 files. Closes with WP-17. |
| BLG-158 | High | WP-12 | Consensus split_resolver empty-chain/fake-height victory (companion of BLG-132); threshold_mldsa owner order; hex 0x0 burn-address trap | Open | `split_resolver` 5 files, `threshold_mldsa` 5 files. Note: overlaps BLG-132; fix once, close both. Closes with WP-12. |
| BLG-167 | High | WP-17 | Storage LRC/MSR layer divide-by-zero / u32 overflow panics from open fields; zero global parity accepted; misleading k=20 vs k=2000 MSR speedup math; missing DurableCommitBatch atomicity | Open | `lrc.rs` 2 files, `msr.rs` 2 files, `DurableCommitBatch` 3 files. Part closes by removal with WP-07 (in-flight PR #8); the remainder closes with WP-17. |
| BLG-183 | Critical | WP-17 | Storage bond slashing double-debt 2x; evaporating escrow/supply drift; reward-lock bypass; BUD_OPEN_DEAL_V1 signature replay | Open | `BUD_OPEN_DEAL_V1` 1 file (`src/tests/regression_chain.rs`). Part closes by removal with WP-07 (in-flight PR #8); the remainder closes with WP-17. |
| BLG-184 | Critical | WP-17 | Failed transactions not counted in collect_block_transactions inflate block gas; zero-cost O(K*P) mempool re-execution DoS | Open | `collect_block_transactions` 4 files (`src/chain/blockchain.rs`); `O(K * P)` literal absent. Closes with WP-17. |
| BLG-196 | High | WP-17 | AccountState open pub accounts map diverges the incremental Merkle cache (state_root split); O(N) clone/disk-write per block; production [[bin]] benchmark binaries; budscan lacks #![forbid(unsafe_code)] | Open | `AccountState` 103 files, `budscan` 29 files; `#![forbid(unsafe_code)]` present 122 times. Closes with WP-17. |
| BLG-197 | Critical | WP-17 | apply_transaction_checked / apply_block_checked saturating_add in tx.total_cost() inflates $BUD supply from nothing; Stake overflow partial-write; false-green security locks in second-round packs | Open | `apply_transaction_checked` 14 files, `apply_block_checked` 9 files, `tx.total_cost()` 6 files, `saturating_add` 145 files. Closes with WP-17. |
| BLG-202 | Critical | WP-17 | src/main.rs startup: retention_count == 0 wipes fresh backups (--migrate-v2 without backup), lexicographic .budbak order, mainnet disk-key/PKCS#11 symlink bypasses, forward-schema silent accept, console block/tx defects | Open | `src/main.rs` 8 files, `retention_count == 0` 1 file (`src/cli/commands.rs`), `--migrate-v2` 2 files, `.budbak` 2 files. Closes with WP-17. |
| BLG-203 | Critical | WP-12 | QcFaultProof::verify_inclusion accepts out-of-bounds leaf_index / 1-byte siblings; LightClient::verify_header_chain approves unsigned fake header chains; uppercase-hex digest parse; ValidatorSetSnapshot::compute_hash unbound epoch/order | Open | `QcFaultProof::verify_inclusion` 1 file (`src/consensus/merkle_tree.rs`), `leaf_index` 6 files, `ValidatorSetSnapshot::compute_hash` 6 files (`src/chain/finality.rs`). Closes with WP-12. |
| BLG-205 | Critical | WP-44, WP-15 | ExternalDomainRegistry readmit bypass (0 suffix + mismatched version, Faulted -> Admitted) and last_accepted_height rollback; 5 unbounded bincode::deserialize (Identity/Vault/Pollen*) on P2P proto_conversions; ModalitySet(0) wire mutation | Open | `ExternalDomainRegistry` 4 files, `readmit` 8 files, `last_accepted_height` 7 files, `proto_conversions` 14 files. Closes with WP-44 (registry foot) and WP-15 (wire foot). |
| BLG-206 | Critical | WP-12 | PoAEngine operator-local --validators-file leadership split; validate_block misses block.hash/index checks; StateSnapshot::calculate_hash digest collision (chunk(0) panic); RelayerWorker cross-round nonce clash / skipped requests on corrupt cursor | Open | `PoAEngine` 15 files, `--validators-file` 1 file (`xtask/tools/src/devnet.rs`), `validate_block` 14 files, `RelayerWorker` 5 files. Closes with WP-12. |
| BLG-207 | Critical | WP-12 | PoSEngine::verify_evidence cross-chain (Testnet -> Mainnet) slashes innocent validators 50%; V5 ML-DSA-87 producers immune to double-sign evidence (BlockHeader lacks producer_public_key); Block::mine iteration-0 stale digest | Open | `PoSEngine::verify_evidence` 2 files (`src/consensus/pos.rs`), `BlockHeader` 43 files, `producer_public_key` 5 files (`src/chain/genesis.rs`). Closes with WP-12. |
| BLG-246 | Critical | WP-12 | Finality requires a dual stake quorum AND a count quorum (ceil(2n/3)) over the full validator set; many low-stake mobiles tie liveness to phones | Verified | Reproduced by inspection: `check_prevote_quorum` and `check_precommit_quorum` both require `voted_stake >= snapshot.quorum_stake() && voted_count >= snapshot.quorum_count()` (`src/chain/finality.rs:118-131, 876-912`). The seat quorum in open PR #9 replaces this path. Closes with WP-12. |
| BLG-247 | High | WP-15 | No NAT traversal: relay/dcutr/autonat absent from the dependency set; testnet ships enable_circuit_relay = false; phones behind NAT cannot validate | Verified | Reproduced: the libp2p feature list in `Cargo.toml` (lines 80-100) is tokio/tcp/dns/noise/tls/quic/yamux/macros/ping/identify/gossipsub/kad/request-response - no relay, no dcutr, no autonat; `enable_circuit_relay` appears nowhere in the profile. Closes with WP-15. |
| BLG-251 | High | WP-13 | Liveness tracker emits a SlashingReport on consecutive missed epochs; no penalty-free suspension for the mobile class | Verified | Reproduced by inspection: `LivenessTracker::record_epoch` returns `Vec<SlashingReport>` (`src/registry/liveness.rs:67-120`) and the production path pushes `SlashingReport::consensus_liveness`; no suspension-with-recovery arm exists. Closes with WP-13. |
| BLG-252 | Medium | WP-08 | Storage roles are split from validators (STORAGE_OPERATOR = 5, CONTENT_VALIDATOR = 9), contradicting content-bearing validators | Verified | Reproduced by inspection: `roles::STORAGE_OPERATOR` is `RoleId(5)` and `roles::CONTENT_VALIDATOR` is `RoleId(9)` (`src/registry/role.rs:94,115`); display arms and tests still map them. Removal is WP-08 task 7. Closes with WP-08. |
| BLG-253 | Medium | WP-07, WP-08 | Mobile modules implement the B.U.D. 1.0 self-hosting model, not validator duty; MobileSelfProfile::calculate_leaf hashes unlength-prefixed fields | Open | `src/storage/mobile_self.rs`, `src/storage/server_admission.rs`, `src/network/mobile.rs` all still present. Removal closes the WP-07 foot (in-flight PR #8); the calculate_leaf foot closes with WP-08. |
| BLG-259 | Medium | WP-12, WP-11 | Per-checkpoint ML-DSA-65 signatures: 128 seats x ~3309 bytes is a ~420 KB certificate; the BLS-at-checkpoint / PQ-at-epoch-transition trust model is undocumented | Open | PQ signature sizing acknowledged in-tree (`src/consensus/qc.rs:1301` sizes `pq_signature` at 3309 bytes); the trust-model document is absent. Closes with WP-12 (PQ blob producer) and WP-11 (light client). |
| BLG-263 | Medium | WP-16 | The security pool distributes stake-only; custody duty earns no share | Verified | Reproduced by inspection: `pay_epoch` filters `state.validators` to active, unjailed, unslashed VALIDATOR-role entries and pays `reward_for_epoch(..., &eligible)` weighted on `v.stake` only; no custody-weight term exists (`src/tokenomics/reward_pool.rs:145-230`, called from `src/chain/blockchain.rs:4090`). Closes with WP-16 (section 11.4). |
| BLG-264 | High | WP-12 | Hash-chain leader election and the handover council are not wired to the production path; the tree carries WIRING markers | Verified | Reproduced by count: 14 `WIRING:` markers in `src/consensus/filiz.rs` and 7 in `src/consensus/handoff.rs`, all reading "production callers land with it"; neither module has production callers in the live tree. Closes with WP-12; in-flight PR #9 is the wiring vehicle. |
| BLG-266 | Medium | WP-08, WP-16 | A single min_stake parameter with no class split; 1,000 BUD testnet floor is too high for phones | Closed (previously fixed) | Fix present: `min_stake_full` / `min_stake_mobile` / `class_floor` in `src/core/chain_config.rs`; `Network::Testnet` ships 1,000 BUD full and 10 BUD mobile (`TESTNET-DEFAULT`); `ValidatorClass::holds_seat` gates the seat. Lock: `audit_lane_a::blg_266_min_stake_is_split_per_class`. |
| BULGU-001 | High (S2) | WP-12 | PoS block validity decision bound to the local wall clock | Open | `src/consensus/pos.rs` present. Closes with WP-12. |
| BULGU-002 | High (S2) | WP-12 | Poisoned-lock checkpoint guard fails open | Open | `src/consensus/pos.rs` present. Closes with WP-12. |
| BULGU-003 | Medium (S3) | WP-12 | Unsigned block yields empty-signature evidence | Open | `src/consensus/pos.rs` present. Closes with WP-12. |
| BULGU-004 | Medium (S3) | WP-12 | Evidence and block budget measured in JSON | Open | `src/consensus/pos.rs` / `src/consensus/mod.rs` present (JSON budget ceiling confirmed for `consensus::MAX_BLOCK_SIZE`). Closes with WP-12. |
| BULGU-005 | Medium (S3) | WP-17 | Genesis time taken from the wall clock on an empty chain | Open | `src/chain/blockchain.rs` present. Closes with WP-17. |
| BULGU-006 | High (S2) | WP-17 | Slash error silently swallowed | Open | `src/chain/blockchain.rs` present. Closes with WP-17. |
| BULGU-007 | Medium (S3) | WP-17 | Storage errors swallowed in reorg and prune | Open | `src/chain/blockchain.rs` present. Closes with WP-17. |
| BULGU-008 | Medium (S3) | WP-17 | Unbounded slice in replay | Open | `src/chain/blockchain.rs` present. Closes with WP-17. |
| BULGU-009 | Medium (S3) | WP-17 | expect() in the production path | Open | `expect` 611 occurrences tree-wide; production-path sites not yet narrowed. Closes with WP-17. |
| BULGU-010 | Medium (S3) | WP-17 | Serialization error falls back to a constant tag | Open | `src/core/transaction.rs` present. Closes with WP-17. |
| BULGU-013 | Medium (S3) | WP-17 | Swallowed lock error | Open | `src/execution/executor.rs` present. Closes with WP-17. |
| BULGU-014 | High (S2) | WP-12 | Corrupt vote history restarts from zero (double-sign risk) | Open | `src/network/node.rs` present; also see BLG-096/BLG-113. Closes with WP-12. |
| BULGU-015 | Medium (S3) | WP-17 | Chain actor channel failure falls back to silent read defaults | Open | `src/chain/chain_actor.rs` present. Closes with WP-17. |
| BULGU-016 | Medium (S3) | WP-17 | Validator state root drops the empty array | Open | `src/core/account.rs` present. Closes with WP-17. |
| BULGU-018 | Medium (S3) | WP-16 | Corrupt PoA bootstrap address silently dropped | Open | `src/chain/genesis.rs` present. Closes with WP-16. |
| BULGU-019 | Medium (S3) | WP-16 | External domain bond lock bypasses the reward gate | Open | `src/core/account.rs` / `src/execution/executor.rs` present. Closes with WP-16; TEST-GAP-01 tracks the missing regression lock. |
| BULGU-020 | Medium (S3) | WP-16 | Money gates (nine members) bypass the reward gate with the raw balance | Open | Money-gate class present; individual members not re-enumerated. Closes with WP-16. |
| BULGU-021 | Medium (S3) | WP-17 | Cross-shard raw-balance gate (unreachable) | Open | `src/sharding/mod.rs` present. Closes with WP-17. |
| BULGU-022 | Medium (S3) | WP-08 | RoleBond door has no implementation arm for three transaction types | Open | `RoleBond` path present (`src/registry/role.rs`, `src/core/transaction.rs`). Closes with WP-08. |
| BULGU-023 | High (S2) | WP-12 | Double-sign evidence deleted on the second epoch | Open | `src/consensus/pos.rs` / `src/chain/blockchain.rs` present; see also BLG-207. Closes with WP-12. |
| BULGU-024 | Medium (S3) | WP-12 | Reorged branches not written to seen_blocks | Open | `seen_blocks` 5 files (`src/consensus/pos.rs`). Closes with WP-12. |
| BULGU-025 | Medium (S3) | WP-12 | Checkpoints have no delete or repair path | Open | `src/consensus/pos.rs` present; see also BLG-096. Closes with WP-12. |
| BULGU-026 | Medium (S3) | WP-12 | Reorg deletes pending slash evidence | Open | `src/chain/blockchain.rs` present; see also BLG-096. Closes with WP-12. |
| BULGU-027 | Medium (S3) | WP-12 | invalidate_finality_from_height loop not grid-aligned | Open | `invalidate_finality_from_height` 1 file (`src/chain/blockchain.rs`); identical foot of BLG-096. Closes with WP-12. |
| TEST-GAP-01 | High | WP-16 | No regression lock for BULGU-019 | Open | No `audit_lane_a` or `regression_chain` lock covers the BULGU-019 reward-gate bypass. Lock owed with WP-16 (or this lane when the finding closes). |
| TEST-GAP-08 | Medium | WP-12 | Existing test pins the pruning window (BULGU-023 foot) | Open | TEST-GAP-08 foot of BULGU-023: prune must keep evidence beyond one epoch; no lock yet. Lock owed with WP-12. |

## Reproduction debt (audit/repro-a)

The following Verified entries carry their reproduction as file inspection
this pass. Each owes a red test on the `audit/repro-a` branch (never merges)
that the closing package moves into its own pull request (directive 14.1.5,
S-3): BLG-008 (config/doc contradiction is mechanically checkable),
BLG-033 (count bound on the deserialize sites), BLG-246 (dual quorum still
required), BLG-247 (feature-set absence), BLG-251 (no suspension path),
BLG-252 (roles 5/9 present), BLG-263 (stake-only weighting), BLG-264 (WIRING
marker count). The Open entries each carry their identifier anchors above;
the repro for each lands with its closing package.

## New findings this pass

None beyond the ledger. Two observations, both already recorded: the
`docs/TESTNET.md:33` open-RPC claim vs `config/testnet.toml:50` (BLG-008) and
the JSON block budget ceiling in `consensus::MAX_BLOCK_SIZE` (BLG-007,
BULGU-004). No BLG-268+ was registered: nothing new was found that is not
already in section 14.

## Verification base and drift

`git status` clean at verification time on `arena/b0362659-budlum` branched
from `cccf1da`. The ledger's identifiers were scanned with fixed-string grep
on the same tree. Where the scan and the directive's "Kod izi" column
disagree (the directive measured its 2026-11-02 analysis base; this snapshot
is newer and includes PRs #5 and #6), the live result is authoritative.

## Closing protocol

When a closing package merges, its PR flips the finding here to Closed with
commit SHA and CI run number. WP-04 (WP-04) consolidates this file, the other
three lanes, and `docs/audit/LIVE_STATUS.md`; this file is their lane A input,
not a replacement for it.

## Rows carried from pr-68 (M0 live verification)

- BLG-007, BLG-009, BLG-010, BLG-011, BLG-017, BLG-019, BLG-020, BLG-021, BLG-023, BLG-028, BLG-031, BLG-041, BLG-042, BLG-044, BLG-065, BLG-066, BLG-088, BLG-089, BLG-090, BLG-100, BLG-101, BLG-102, BLG-103, BLG-104, BLG-107, BLG-113, BLG-118, BLG-119, BLG-125, BLG-128, BLG-147, BLG-151, BLG-167, BLG-183, BLG-184, BLG-196, BLG-197, BLG-202, BULGU-005, BULGU-006, BULGU-007, BULGU-008, BULGU-009, BULGU-010, BULGU-013, BULGU-015, BULGU-016, BULGU-021 (Kapatan IP: WP-08, WP-12, WP-13, WP-14, WP-15, WP-16, WP-17)

## Rows carried from pr-87 (WP-27 M0 status)

| BLG-024 | Low | Consensus | Open | blg_024_finality_adapter_domain_check | src/consensus/ (PoW/PoS/PoA/BFT adaptors; 8/8 traces; PoAFinalityAdapter zero divisor) | IP-44|
| BLG-043 | Critical | Bridge / Storage accounting | Open | blg_043_unlock_bridge_transfer | src/settlement/, src/cross_domain/ (14/19 traces) | IP-44|
| BLG-050 | Critical | Security / Identity / State root | Open | blg_050_identity_recover_poa_gate | src/registry/ (16/16 traces) | IP-44|
| BLG-051 | High | Security / Selective disclosure | Open | blg_051_check_receipt_foreign_credential | src/registry/identity* (9/9 traces) | IP-44|
| BLG-052 | Medium | Consensus / PoA compliance | Open | blg_052_poa_onboarding_hashmap | src/consensus/poa.rs (15/16 traces) | IP-44|
| BLG-053 | High | Economy / Settlement security | Open | blg_053_proof_market_replay | src/settlement/ (16/16 traces) | IP-44|
| BLG-054 | Critical | Cryptography / Bridge / Consensus | Open | blg_054_ethereum_receiptsroot_mpt | src/cross_domain/evm/ (15/19 traces) | IP-44|
| BLG-055 | Critical | Cryptography / External finality | Open | blg_055_pairing_bls_signing_root | src/cross_domain/ (17/18 traces) | IP-44|
| BLG-056 | High | Consensus / Economy / DoS | Open | blg_056_external_domain_freeze | src/registry/ (29/30 traces) | IP-44|
| BLG-057 | High | Consensus / Bridge accounting | Open | blg_057_bridge_state_lifecycle | src/settlement/ (17/17 traces) | IP-44|
| BLG-058 | High | Consensus / State root / Determinism | Open | blg_058_domain_registry_leaf_digest | src/consensus/ (19/19 traces) | IP-44|
| BLG-091 | Critical | External-domain contract / Cryptography | Open | blg_091_budlum_finality_verifier_zero_bls | contracts/ (18/22 traces) | IP-44|
| BLG-105 | Critical | Consensus / Bridge / Tokenomics / Crypto | Open | blg_105_burn_bridge_transfer_double_mint | src/settlement/ (15/17 traces) | IP-44|
| BLG-116 | Critical | Cross-domain bridge / ZK verification / RPC | Open | blg_116_adapter_spec_zkvm_empty_stark | src/cross_domain/, src/rpc/ (27/31 traces) | IP-44|
| BLG-120 | High | Settlement security / Cold wallet / Quantum anchor | Open | blg_120_cold_wallet_epoch_budget | src/settlement/, crates/bpqs/ (29/33 traces) | IP-44|
| BLG-127 | Critical | Consensus / Cryptography / Settlement capacity / Bridge | Open | blg_127_cold_wallet_3_of_6_anchor | src/settlement/, crates/bpqs/ (35/37 traces) | IP-44|
| BLG-130 | Critical | Consensus / Cross-domain bridge finality / Crypto | Open | blg_130_lead_is_unassailable_early_decision | src/settlement/ (31/35 traces) | IP-44|
| BLG-131 | High | Node health / Event rollback | Open | blg_131_regeneration_ledger_medusa_cycle | src/chain/state_recovery/ (moved from regeneration_stage.rs per 5.2; 17/19 traces) | IP-44|
| BLG-134 | Critical | Cross-domain bridge / EVM canonical encoding | Open | blg_134_evm_rlp_0x81_b | src/cross_domain/evm/rlp.rs (18/22 traces) | IP-44|
| BLG-138 | Critical | Cross-domain bridge pipe / External chain observer | Open | blg_138_bridge_relayer_pipeline_mint_unlock | src/settlement/ (21/23 traces) | IP-44|
| BLG-146 | Critical | Cross-chain bridge claim verification / Quantum | Open | blg_146_build_bud_to_eth_claim_receiver | src/cross_domain/ (21/23 traces; bpqs poseidon2; note-packing Goldilocks wrapping) | IP-44|
| BLG-155 | High | GlobalBlockHeader persistence / Validators | Open | blg_155_global_block_bincode_compatibility | src/chain/ (15/17 traces) | IP-44|
| BLG-190 | Critical | Consensus field isolation / Quantum identity | Open | blg_190_did_bud_identity_recover_poa_gate | src/registry/ (30/31 traces) | IP-44|
| BLG-194 | Critical | Cross-domain bridge / Universal relay atomicity | Open | blg_194_submit_relay_proof_atomic | src/settlement/ (18/21 traces) | IP-44|
| BLG-195 | Critical | Multi-consensus finality verification / Cross-domain | Open | blg_195_finality_adapter_commitment_body | src/consensus/ (26/26 traces) | IP-44|
| BLG-199 | High | Cryptographic Merkle tree second-preimage | Open | blg_199_merkle_root_leaf_internal_confusion | src/settlement/commitment_tree.rs, src/consensus/merkle_tree.rs (8/8 traces) | IP-44|
| BLG-204 | High | Proof market accounting atomics / Ethereum bridge | Open | blg_204_proof_market_unpaid_receipt_delete | src/settlement/ (20/23 traces) | IP-44|
| BLG-227 | Medium | Gonca E5 | Open | blg_227_verify_inference_summary_only | src/ai/mod.rs; docs/AI_VERIFICATION_STATUS.md | IP-57 (testnet closure IP-33)|
| BLG-228 | High | Gonca E6 | Open | blg_228_ai_stark_verification_closed | src/ai/mod.rs | IP-57 (testnet closure IP-45)|
| BLG-229 | High | Gonca E7 | Open | blg_229_ai_registry_no_lottery | src/ai/registry.rs | IP-45 (VL-1 leg), IP-57|
| BLG-235 | High | Gonca E13, SERA-0 | Open | blg_235_zkvm_proof_only_zk_domain | src/cross_domain/external/zkvm_proof.rs; evm sync committee | IP-44, IP-60|
| BLG-240 | Low | Gonca E18 | Open | blg_240_validator_ordering_f64 | src/ai/registry.rs | IP-45, IP-57|
| BLG-244 | Low | Gonca E23 | Open | blg_244_off_device_assistant_bytes | Off-device assistant repository (separate repo work item) | IP-57|

## Verification rows carried from pr-68

The merge kept this tree's row wording and lost the reproduction
evidence columns. The evidence is carried back verbatim.

| BLG-001 | Verified (Red test output) | audit_repro_a_blg_001 | src/consensus/leader.rs (MAX_LEADER_ROUNDS) | WP-12 | Critical |
| BLG-018 | Verified (Red test output) | audit_repro_a_blg_018 | src/chain/blockchain.rs (finalized_height) | WP-12 | Critical |
| BLG-246 | Verified (Red test output) | audit_repro_a_blg_246 | src/consensus/filiz.rs (count) | WP-01 | Medium |
| BLG-264 | Verified (Red test output) | audit_repro_a_blg_264 | src/consensus/filiz.rs (WIRING) | WP-12 | Medium |
| BLG-251 | Verified (Red test output) | audit_repro_a_blg_251 | src/registry/liveness.rs (SlashingReport) | WP-13 | High |
