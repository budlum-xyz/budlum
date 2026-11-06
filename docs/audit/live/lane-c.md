# Lane C live verification ledger (WP-03)

Directive section 14 assigns the unified findings ledger to live verification in
four lanes (WP-01..WP-04). This file is the lane C record: every ledger entry
whose closing package is İP-26 to İP-35, İP-44, or İP-49 to İP-60, re-verified
against the live tree. English per `tree_is_english`.

## How this was produced

- **Verification base.** Repository snapshot `HEAD` = `cccf1da` (`main`,
  2026-11-05, "Add files via upload"). The snapshot post-dates the directive's
  analysis base (2026-11-02, `testnet-quantum`) and includes the merged
  consolidation (PR #5) and the A0 codec register / dedup index (PR #6).
  Citations are content anchors: every claim below is anchored by identifier and
  by file, never by a line number.
- **Method.** (1) Every lane C record was extracted from directive section 14
  programmatically: 74 records. (2) Each record was scanned for its
  machine-checkable identifiers across `src/`, `crates/`, `budzero/`, `bud/`,
  `contracts/`, `xtask/`, `docs/`, `config/`. (3) Headline records were read at
  their anchors: the BudZero AIR and verifier, the compiler and VM, the
  cross-domain bridge and external-domain intake, the cold-wallet and anchor
  settlement, the execution environment interface, and the RPC method table.
  (4) A verdict was assigned only where the evidence is the file content itself.
- **CI.** No local Rust toolchain exists in this environment; CI is the
  validator (directive: do not hold commits, do not block on CI unless it is
  red). No red CI run was observed during this work. The locks added in
  `src/tests/audit_lane_c.rs` and `budzero/tests/audit_lane_c.rs` are plain
  `cargo test` unit tests; the BudZero locks are pure source locks and need no
  build feature.
- **What this PR does not claim.** WP-03 does not fix a finding. A record marked
  Açık stays open until its closing package merges and flips its repro test
  (S-3). Repro tests for Açık records are owed on the `audit/repro-c` branch;
  that branch never merges, and each closing package moves its own repro test
  into its pull request. This PR carries no failing test.

## Status legend (directive 14.1)

| Status | Meaning |
|---|---|
| Açık | Open in the live tree. Evidence below; repro pending on `audit/repro-c`. |
| Doğrulandı | Open and reproduced. Reproduction is by reading the code path the record names at the cited anchor. |
| Kapalı (önceden düzeltilmiş) | Fixed in this snapshot before WP-03 ran. A permanent test holds it closed (name cited). |
| Kaldırma ile kapandı | Not used this pass. Records with a removal foot are recorded as Açık with the İP-07 foot written in the evidence column. |
| Geçersiz | Not used this pass. No record lost its precondition without a fix landing. |

A record closes only as a whole. Where a record has several feet and some are
already held by a guard, the record stays Açık and the closed foot is written
in the evidence column. The foot locks in `src/tests/audit_lane_c.rs` keep those
feet from silently reopening.

## Summary

| Metric | Count |
|---|---|
| Lane C records | 74 |
| Kapalı (önceden düzeltilmiş) | 4 |
| Doğrulandı | 19 |
| Açık | 51 |
| Kaldırma ile kapandı | 0 |
| Geçersiz | 0 |

Severity split of the 74 records, as the directive records it: 30 Critical, 28 High, 13 Medium, 3 Low.

Closing-package distribution (a record counts once per package its closing
column names; a record with two feet counts in both): İP-26 (4), İP-27 (1),
İP-28 (1), İP-29 (1), İP-31 (1), İP-32 (1), İP-33 (25), İP-44 (29), İP-45 (6),
İP-56 (11), İP-57 (5), İP-60 (4). Two rows also carry a foot owned outside lane C:
BLG-148 (`src/storage/lifecycle.rs`, İP-07 removal) and BLG-237 (İP-22).

## The load-bearing observation of this lane

The lane C area is not mostly "old findings in an old tree". It is an area where
the closing packages have not started:

1. **No execution engine is in the tree.** `Cargo.toml`, `Cargo.lock`,
   `crates/uel-abi/Cargo.toml` and every workspace manifest carry no `revm`, no
   `wasmi`, no `solana-svm`, no `solana-sbpf` and no `aptos-vm` entry. The
   section 8.2 catalog has thirteen environments; the tree has one (BudZero) plus
   an ABI crate with no engine behind it. `src/execution/ee.rs` says so itself:
   `WIRING: unwired - the Execution Coordinator is the first consumer`.
2. **The coordinator is a stub.** `src/execution/coordinator/mod.rs` is eight
   lines and declares that "a later step builds the coordinator itself".
3. **The RPC surface is Budlum-only.** `src/rpc/method_class.rs` classifies 186
   `bud_*` rows; there is no `src/rpc/compat/` directory and no `eth_`, `sol_`,
   `aptos_` or Cosmos method anywhere in the tree.

Consequence for the testnet gate: TLG items 6 and 7 (five execution environments
run, and an EVM contract calls a CosmWasm contract in one atomic transaction)
cannot be reached by any package that has merged. İP-26 is the first package that
can change this, and it is the shortest path in lane C.

## Special audits the WP-03 card names

### 1. Engine inventory (section 8.2 versions and licences)

The full table is `docs/audit/live/engine-inventory.md`. Result: none of the five
engines the card names is a dependency of any workspace, so there is no version
to record from the tree and no licence file to read in the registry cache. The
catalogued versions and licences are recorded there from section 8.2, together
with the `cargo-deny` pre-check: the root `.quality/deny.toml` allows `MIT` and
`Apache-2.0` and refuses copyleft, so `revm` (MIT), `wasmi` (MIT/Apache-2.0),
`solana-svm` and `solana-sbpf` (Apache-2.0) and `aptos-vm` (Apache-2.0) all pass
the policy on paper. The pre-check is on paper only: nothing can be scanned that
nothing depends on.

### 2. `src/execution/executor.rs` `ContractCall` path (BLG-248)

Reproduced. `TransactionType::ContractCall` reaches
`ZkVmExecutor::execute_bytecode(&tx.data, ..)` in `src/execution/zkvm.rs`, with
`CONTRACT_VM_MEMORY_BYTES = 8192` and a compile-time assertion against
`bud_vm::MAX_MEMORY_BYTES`. There is no deploy, no storage namespace and no
persistent code store. One foot is closed: `MAX_BLOCK_CONTRACT_GAS` bounds the
proving cost of one block at 64 full calls, so the proving-DoS foot of BLG-040
is held by a constant.

### 3. BudZero `Pcs::ZK` and the 64-bit commitment paths (BLG-223, BLG-224)

Reproduced. `budzero/bud-proof/src/bud_stark/config.rs::is_zk` returns
`Self::Pcs::ZK`, and `budzero/bud-proof/src/bud_stark/prover.rs` records that the
PCS is `TwoAdicFriPcs` "whose `Pcs::ZK` is `false` (p3-fri 0.7.0)". The verifier
enforces the same bit in both directions
(`opened_values.random.is_some() != SC::Pcs::ZK` is refused), so the proof format
is consistent and not private.

The note path is 64 bits: `budzero/bud-state/src/note.rs` builds a note from
`from_field_elements(commitment_fe: u64, nullifier_fe: u64)`, packs it into a
32 byte `Hash` with the upper 24 bytes zero, and `budlum-note-packing` is the one
definition of the packing. Collision resistance is therefore the Goldilocks field
size, not 256 bits.

### 4. Ethereum sync committee module's production call site (BLG-235)

Reproduced. `src/cross_domain/evm/sync_committee.rs` opens with
`WIRING: unwired - verify_execution_block_finality is reached in this tree only
through the adapter modules that declare themselves unwired`. One foot is
closed: `rotate_period` now returns `SyncCommitteeError::RotationBranchRequired`
unconditionally, and the module records that the previous unconditional swap let
a holder inject a chosen committee. The refusal is pinned by
`rotate_period_without_the_branch_refuses`.

### 5. Bridge findings BLG-043, BLG-057, BLG-105, BLG-194 (the section 1.5 gate)

All four are **not closed** in this ledger, so the bridge stays closed on testnet
(section 1.5: the bridge opens only if these four close). The verification did
find closed feet, and they are written down so the closing packages do not redo
them:

- `unlock_from_verified_event` credits `transfer.burned_amount` to the owner and
  refuses a transfer whose `burned_amount` is zero (`src/cross_domain/bridge_tx.rs`).
  The "100 percent fund loss / fresh split from live fee parameters" foot of
  BLG-043 is closed.
- `unlock_bridge_transfer_from_verified_event` refuses a missing
  `expected_block_hash` (`src/chain/blockchain.rs`); the
  `sync_attestation: None` header-forgery foot of BLG-054 is closed at the door.
- `bridge_mint_forgery_gate_rejects_none_expected_block_hash` in
  `src/tests/bridge_lifecycle.rs` pins the mint door.
- `BridgeState::lock` refuses `expiry_height == 0` and any expiry not after the
  source height, and a burn expiry is bounded
  (`src/cross_domain/bridge.rs`); the "no expiry" and "unbounded expiry" feet of
  BLG-057 are closed.
- `unlock_from_verified_event` cross-checks the lock domain, the burn domain, the
  sender, the recipient and the payload hash against the transfer row, and
  `check_burn_matches_lock_domain` is called before any credit; the routing feet
  of BLG-105 are closed.
- `submit_relay_proof` is delegated to the single
  `cross_domain::bridge_tx::submit_relay_proof` body, so there is one atomicity
  surface (BLG-194's first foot still needs its own red repro: the function is
  `#[cfg(test)]`-gated in `Blockchain`).

## In-flight work this ledger interacts with

- **PR #8** (`arena/b7784c85-budlum`, WP-06/WP-07/WP-24): removes the BUD 1.0
  storage surface and wires the codec register. Lane C records that name a
  `src/storage/` location and carry an İP-07 foot (BLG-148) stay Açık until it
  merges. No lane C lock reads a file PR #8 deletes or moves.
- **PR #9** (`arena/5b54fce9-budlum`, WP-12): consensus finality, lane A. It
  changes no file this ledger or its locks read.
- **PR #11** (`arena/792d7fb2-budlum`, WP-06): moves `src/storage/db*` to
  `src/persistence/`. BLG-260 cites `src/storage/db.rs` today; when PR #11 merges
  the citation moves to `src/persistence/db.rs` in the same closing package
  (the lock is written against an identifier, not a path, so it survives).
- **PR #12** (`arena/b0362659-budlum`, WP-01/WP-02): lanes A and B. Lane C's
  records are disjoint from these two lanes; the shared feet (BLG-024 has no
  lane A foot, BLG-205 has the İP-49 foot recorded in lane A) are noted per row.
- **PR #13** (`arena/df5c50ec-budlum`, WP-20): placement and custody gates
  inside `src/storage/bud3/`. It touches no lane C lock path.

## Records

English title column: the English title each record owes `docs/audit/FINDINGS.md`
(WP-04, section 15.8 İP-04 item 3).

| ID | Severity | Area | English title | Live status | Test or lock | Evidence (file, identifiers) | Closing package |
|---|---|---|---|---|---|---|---|
| BLG-024 | Low | Domain finality | The PoW/PoS/PoA/BFT finality adapters do not check `domain.id == commitment.domain_id` inside themselves and `PoAFinalityAdapter` divides by an unguarded denominator | Doğrulandı | owed: `audit_lane_c_blg_024_*` | `src/domain/finality_adapter.rs`: `PoAFinalityAdapter`, `verify_poa_pq`, `reject_commitment_domain_mismatch` (mismatch foot called from all four adapters; `required_signatures` still calls `div_ceil(self.quorum_denominator)` with no zero guard) | İP-44 |
| BLG-036 | Critical | ZK circuit soundness | `BudAir` register and memory sorted tables lack activity contiguity and key/clock ordering, and `m_same` has no inverse witness | Açık | owed: `audit_lane_c_blg_036_*` | `budzero/bud-proof/src/plonky3_air.rs`: `COL_M_SAME_*`, the `m_same = 0` note at the memory-table docs, `TRACE_WIDTH` | İP-33 |
| BLG-037 | Critical | ZK circuit soundness | `VerifyInference` approves a forged AI inference through free witness columns and `SWrite` breaks state-digest limb canonicality | Açık | owed: `audit_lane_c_blg_037_*` | `budzero/bud-isa/src/lib.rs`: `VerifyInference` (documented as "reserved, verifies nothing"); `src/execution/zkvm.rs`: `SWrite`, `state_writes_digest` | İP-33 |
| BLG-038 | Critical | ZK crypto and privacy | Linear initial-memory commitment collision, unframed `event_digest` sum, unbound `chain_id >> 32`, and a `ZK = false` leak | Doğrulandı | owed: `audit_lane_c_blg_038_*` | `budzero/bud-proof/src/adapter.rs`: `COL_EVENT_DIGEST_0..8` are eight `u32` limbs added per `Log` row, so the accumulator is a sum of 32 bit halves; `budzero/bud-proof/src/bud_stark/config.rs`: `is_zk()` returns `Self::Pcs::ZK` (= false) | İP-33 |
| BLG-039 | Critical | ZK verifier DoS | A STARK verifier aborts the node on `degree_bits >= 27` and a zero-gas `setup_preprocessed` leaks memory and CPU | Kapalı (önceden düzeltilmiş) | `budzero/bud-proof/tests/fiat_shamir_binding.rs::degree_bits_is_bounded_before_it_is_shifted`; new source lock `blg_039_degree_bits_is_bounded_before_the_shift` | `budzero/bud-proof/src/bud_stark/verifier.rs`: `MAX_VERIFIER_DEGREE_BITS = 32` and `if *degree_bits > MAX_VERIFIER_DEGREE_BITS { return Err(InvalidProofShape) }` before `let degree = 1 << degree_bits`; `security_parameters()` observed into the transcript | İP-33 |
| BLG-040 | High | ZKVM and circuit semantics | One-round reversible `VerifyMerkle` digest, ZKVM to `BudAir` semantic mismatches, and a `ZkVmExecutor` proving DoS | Açık | owed: `audit_lane_c_blg_040_*` | `budzero/bud-isa/src/lib.rs`: `VerifyMerkle`, `VerifyInference` (single Poseidon round documented); `src/execution/zkvm.rs`: proving path. Closed foot: `MAX_BLOCK_CONTRACT_GAS` bounds one block's proving work at 64 calls | İP-33 |
| BLG-043 | Critical | Bridge and supply accounting | `unlock_bridge_transfer` loses 100 percent of the funds, `opener_bond` and the reallocation fee are never refunded, and the relay mints without verification | Açık | owed: `audit_lane_c_blg_043_*` | Closed feet: `src/cross_domain/bridge_tx.rs::unlock_from_verified_event` credits `transfer.burned_amount` and refuses a zero debit; `src/chain/blockchain.rs::unlock_bridge_transfer_from_verified_event` makes `expected_block_hash` mandatory; `src/cross_domain/bridge_tx.rs::unlock_from_verified_event` calls `check_burn_matches_lock_domain`. Open: opener-bond refund and the reallocation fee on a refused unlock | İP-44 |
| BLG-050 | Critical | Identity and state root | `IdentityTx::Recover` bypasses the PoA gate, key loss is unrecoverable, a third party can overwrite `credential_root`, and `IdentityRegistry::root()` commits nothing | Açık | owed: `audit_lane_c_blg_050_*` | `src/core/transaction.rs`: `IdentityTx::Recover`, `credential_root`, `credential_roots`; `src/registry/identity.rs` and `src/chain/chain_actor.rs` recovery path | İP-44 |
| BLG-051 | High | Identity and verification | `check_receipt` accepts an empty or foreign credential and `identity::merkle_root` accepts twin leaves | Açık | owed: `audit_lane_c_blg_051_*` | `src/registry/identity_fill.rs`: `check_receipt` and its module docs; `src/chain/chain_actor.rs` call site | İP-44 |
| BLG-052 | Medium | PoA compliance | `PoAOnboarding` admin-field and KYC renewal inconsistencies, a non-deterministic `HashMap` in `PoaComplianceRegistry`, and a missing `unfreeze` | Açık | owed: `audit_lane_c_blg_052_*` | `src/registry/poa_onboarding.rs`: `PoAOnboarding`; `src/registry/` `PoaComplianceRegistry` (held in `src/core/account.rs`: `poa_compliance`) | İP-44 |
| BLG-053 | High | Settlement economics | `ProofMarketState` replays a completed task, prunes an unpaid receipt, exposes an unframed `root()`, and accepts unbounded `PqAnchor` signatures | Açık | owed: `audit_lane_c_blg_053_*` | `src/settlement/proof_market.rs` (`ProofMarketState`), `src/settlement/pq_anchor.rs` (`PqAnchor`, `verify_anchor_full`), both held in `src/core/account.rs`: `proof_market` | İP-44 |
| BLG-054 | Critical | EVM receipt proof | The `receiptsRoot` MPT verifier hashes keys with Keccak-256, accepts non-canonical HP and envelope encodings, and forges a header through `sync_attestation: None` | Açık | owed: `audit_lane_c_blg_054_*` | `src/cross_domain/evm/mpt.rs` and `src/cross_domain/evm/adapter.rs`: `receiptsRoot`. Closed foot: `expected_block_hash` is mandatory at `Blockchain::unlock_bridge_transfer_from_verified_event` | İP-44 |
| BLG-055 | Critical | External finality crypto | BLS key substitution in `EthereumSyncAdapter` and `PairingBls`, with a fixed `signing_root`, forges external finality with one random key | Açık | owed: `audit_lane_c_blg_055_*` | `src/cross_domain/external/ethereum.rs`: `EthereumSyncAdapter`, `rotate_committee`; `src/cross_domain/external/intake.rs`: `PairingBls`; `src/cross_domain/evm/sync_committee.rs`: `signing_root` | İP-44 |
| BLG-056 | High | External domain registry | `serves()` and `require_slashable` are not enforced, a bare call can freeze a domain, `readmit_external_domain` did not work, and the bond and slash accounting is unfunded | Açık | owed: `audit_lane_c_blg_056_*` | `src/cross_domain/external/registry.rs` (`serves`, `require_slashable`), `src/cross_domain/external/intake.rs` (`IntakeState`, `ExternalDomainRegistry`), `src/cross_domain/external/external_tx.rs` (`readmit`). Closed foot: `readmit` rebuilds the stored adapter from the stored golden sample and refuses a healthy domain | İP-44 |
| BLG-057 | High | Bridge accounting | `BridgeState` (`lock`/`mint`/`unlock`) has expiry, replay and fee-overflow holes, and `CrossDomainMessage` / `UniversalRelayer` have state defects | Açık | owed: `audit_lane_c_blg_057_*` | Closed feet: `src/cross_domain/bridge.rs::lock` refuses a zero expiry and an expiry at or below the source height, and a burn expiry is bounded (`MAX_BURN_EXPIRY_*`). Open: replay and fee overflow across the three doors | İP-44 |
| BLG-058 | High | Domain registry determinism | The `ConsensusDomainRegistry` leaf digest omits `zk_program_allowlist` and `plugin_code_hash`, and `DomainForkChoice` accepts a single-candidate quorum | Açık | owed: `audit_lane_c_blg_058_*` | `src/core/transaction.rs`: `domain.zk_program_allowlist`, `domain.plugin_code_hash` (wire fields exist); `src/domain/registry.rs` leaf fold; `src/domain/types.rs` `DomainForkChoice` | İP-44 |
| BLG-067 | High | Compiler and toolchain | `bud-compiler` and `bud-cli` crash on entry-point argument ABI (`StackUnderflow`), truncate `match` integers, leak `storage` and scope types, and keep a volatile `NodeLedger` | Açık | partly held: `budzero/bud-compiler/tests/regression.rs::match_pattern_is_not_truncated_to_i32` | `budzero/bud-vm/src/lib.rs`: `VmError::StackUnderflow`; `budzero/bud-cli/src/main.rs`: `NodeLedger` (in-memory ledger). Closed feet: `match` truncation and the scope leak | İP-33 |
| BLG-069 | Medium | Verifier registry | The `verifier-registry` state root omits parameters and history, and a zero-expectation `Liveness` proof slashes | Açık | owed: `audit_lane_c_blg_069_*` | `budzero/verifier-registry/src/{lib,params,registry,evidence}.rs`: state-root fold, `SlashingProof::Liveness`, `EmptyLivenessWindow` | İP-33 |
| BLG-091 | Critical | Finality contract | `BudlumFinalityVerifier.sol` finalises an arbitrary fake `stateRoot` with a zero BLS infinity point and an ML-DSA key unbound to the committee | Açık | owed: `audit_lane_c_blg_091_*` | `contracts/object-layer/BudlumFinalityVerifier.sol` (the path the tree embeds: `src/object_layer/family/evm.rs`: `VERIFIER_PATH`) | İP-44 |
| BLG-105 | Critical | Bridge, tokenomics, crypto | `burn_bridge_transfer_with_event` does not debit the balance (2x `$BUD` mint), the bridge vesting lock is pierced, `RelayerExternalResult::result_leaf` is an unframed SHA-256, and a multi-transfer proof replays | Açık | owed: `audit_lane_c_blg_105_*` | Closed feet: `src/cross_domain/bridge_tx.rs::burn_with_event` reads `burner_balance` and records `burned_amount`; `src/cross_domain/bridge.rs` `MAX_TOTAL_SUPPLY` check. Open: the result-leaf frame and the multi-proof replay. `src/tests/hash_input_serialize_locks.rs` names `RelayerExternalResult::result_leaf` | İP-44 |
| BLG-114 | Critical | zkVM compiler | `bud-compiler` silently miscompiles: `MatchPattern::IntLit` truncates `u64` to `i32`, `if`/`while`/`match` scopes leak and zero outer variables, duplicate `fn`/`main` shadow, and a `u64` literal overflows the Goldilocks base | Kapalı (önceden düzeltilmiş) | `budzero/bud-compiler/tests/regression.rs::match_pattern_is_not_truncated_to_i32`, `::arm_let_does_not_clobber_outer_variable`, `::duplicate_main_and_oversized_literal_are_refused`; `budzero/bud-compiler/src/lib.rs::duplicate_functions_structs_storage_and_params_are_refused`; source lock `blg_114_compiler_guards_are_present` | `budzero/bud-compiler/src/{codegen,parser,sema}.rs` | İP-33 |
| BLG-115 | Critical | ZKVM state and dispatch | Dynamic storage has a `2^32` slot collision, a negative Poseidon slot panics the prover, an error-path `Halt` is unprovable, and `bud-state` does not separate SMT fields | Açık | partly held: `budzero/bud-compiler/tests/regression.rs::unknown_struct_field_read_is_refused` | `budzero/bud-vm/src/lib.rs`: `constant_storage_slot`, `run_receipt` (synthetic terminal row, see BLG-191); `budzero/bud-state/src/lib.rs`: SMT | İP-33 |
| BLG-116 | Critical | Cross-domain bridge and RPC | `AdapterSpec::ZkVm` (`Trustless`) forges an arbitrary external `state_root` with an empty `[Halt]` STARK proof, `Faulted` domains stay `Finalized` through `ExternalDomainFinalityBridge`, and an unauthenticated RPC leaks fault and gold-sample data | Açık | owed: `audit_lane_c_blg_116_*` | `src/core/transaction.rs`: `AdapterSpec::ZkVm`; `src/cross_domain/external/zkvm_proof.rs`: `Plonky3Adapter::verify_with_activation`; `src/cross_domain/external/domain_bridge.rs`: `TrustModel::Trustless` | İP-44 |
| BLG-120 | High | Settlement, cold wallet, anchor | `ColdWalletState` trusts `request.epoch` for the epoch budget and deletes the refusal log at zero signatures, `PqAnchor` repeats a rotation across chains, and 10 000 revoked receipts lock the proof market | Açık | owed: `audit_lane_c_blg_120_*` | `src/settlement/cold_wallet.rs`: `request.epoch`, `budget_epoch`; `src/settlement/pq_anchor.rs`; `src/settlement/proof_market.rs` | İP-44 |
| BLG-127 | Critical | Consensus, anchor, bridge | One compromised device key beats a `3-of-6` `ColdWallet` / `PqAnchor` threshold, `merkle_root_from_proof` accepts a high-bit index masquerade and a ghost leaf at `index=3`, `RelayerWorker`/`RelayerPolicyRegistry` lock up, and `InvalidVoteTracker`/`PoaMembershipRegistry` wedge the state | Açık | owed: `audit_lane_c_blg_127_*` | `src/settlement/cold_wallet.rs`, `src/settlement/pq_anchor.rs` (3-of-6), `src/consensus/merkle_tree.rs`: `merkle_root_from_proof`, `odd_promotion_sentinel`; `src/cross_domain/relayer.rs` | İP-44 |
| BLG-130 | Critical | External quorum and intake | `lead_is_unassailable` early-decides differently, `Answer::Infrastructure` exhausts seats, a `ConsensusRefusal` over garbage data freezes a domain into `Faulted`, `evm_hybrid` accepts an unbound BLS point, and `sync_committee::rotate_period` rotates without proof | Açık | closed foot pinned: new lock `blg_130_rotation_requires_the_finality_branch`; existing `sync_committee.rs::rotate_period_without_the_branch_refuses` | `src/cross_domain/external/{quorum,intake,intake_quorum}.rs`, `src/cross_domain/evm/sync_committee.rs`: `lead_is_unassailable`, `Answer::Infrastructure`, `rotate_period` (now `Err(RotationBranchRequired)` unconditionally) | İP-44 |
| BLG-131 | High | Node health and regeneration | `RegenerationLedger` breaks the audit trail on a self-stage (`Medusa -> Medusa`), `max_stages_per_event` depth is unchecked, and `revert_after_forgery` bypasses the policy and lifetime budget | Açık | owed: `audit_lane_c_blg_131_*` | `src/domain/regeneration_stage.rs`: `RegenerationLedger`, `revert_after_forgery`; `src/domain/regen_health.rs`: `assess`, `validate`, `cheapest_target` | İP-44 |
| BLG-134 | Critical | EVM canonical encoding | EVM canonical RLP accepts `[0x81, b]`, `ReplayNonceStore` lets one message lock a channel at `u64::MAX`, and external adapters skip their version and self-test gates | Açık | owed: `audit_lane_c_blg_134_*` | `src/cross_domain/evm/rlp.rs`; `src/cross_domain/nonce.rs`: `ReplayNonceStore`; `src/cross_domain/external/{versioning,selftest}.rs` | İP-44 |
| BLG-136 | High | Smart contract compiler | The parser rejects a bare call statement, swallows the end-of-file token, and `BudIR` (`lower`, `verify`) has type and SSA holes | Kapalı (önceden düzeltilmiş) | `budzero/bud-compiler/tests/regression.rs::bare_call_statement_compiles_and_runs`, `::long_operator_and_field_chains_return_parser_error`; source lock `blg_136_parser_and_ir_guards_are_present` | `budzero/bud-compiler/src/parser.rs`, `budzero/bud-compiler/src/ir/{lower,verify}.rs` | İP-33 |
| BLG-138 | Critical | Bridge relayer pipeline | `BridgeRelayerPipeline` mints and unlocks without a proof and pollutes state on a failed lock, `ChainAdapter::verify_observation` accepts a failed or cross-chain observation, and a `ConsensusDomain` default ships a zero bond | Açık | owed: `audit_lane_c_blg_138_*` | `src/cross_domain/bridge_relayer.rs`: `BridgeRelayerPipeline`; `src/cross_domain/chain_adapter.rs`: `verify_observation`; `src/domain/{types,plugin}.rs` default bond | İP-44 |
| BLG-139 | Critical | Privacy note state tree | `bud-state` `NoteRegistry` leaks the plaintext `nullifier`, so a forged nullifier burns a victim's note or double-spends, and `QuarantineLedger` has a canonical-program DoS, a 4 096 record eviction and a volatile `bud-cli` log | Açık | owed: `audit_lane_c_blg_139_*` | `budzero/bud-state/src/note.rs`: `PrivacyNote` (`nullifier: Hash`), `NoteRegistry`; `budzero/bud-proof/src/quarantine.rs`; `budzero/bud-cli/src/main.rs` | İP-33 |
| BLG-142 | Critical | STARK verifier soundness | The `bud_stark` verifier crashes a node on Goldilocks 2-adicity (`degree_bits`), panics on a zero inverse and a ZK underflow, drops the `max_constraint_degree` check in release, accepts `postcard` trailing bytes, and skips the `canonical_boot` check | Açık | closed feet: `budzero/bud-proof/tests/fiat_shamir_binding.rs::degree_bits_is_bounded_before_it_is_shifted` | `budzero/bud-proof/src/bud_stark/verifier.rs` (`MAX_VERIFIER_DEGREE_BITS` closed the shift foot), `budzero/bud-proof/src/bud_stark/symbolic.rs`: `max_constraint_degree`, `budzero/bud-proof/src/canonical_boot.rs` | İP-33 |
| BLG-146 | Critical | Cross-chain claim and hashes | `build_bud_to_eth_claim` does not bind the recipient and accepts a zero address and an empty burn proof, `BpqsHash` truncates a `u16` field length and breaks `permute16`, and `note-packing` wraps Goldilocks non-canonically | Açık | owed: `audit_lane_c_blg_146_*` | `src/cross_domain/evm/bud_to_eth.rs`: `build_bud_to_eth_claim`; `crates/bpqs/src/{hash,poseidon2}.rs`: `BpqsHash`, `permute16`; `crates/note-packing/src/lib.rs` | İP-44 |
| BLG-148 | High | Storage lifecycle and registry bounds | `StorageLifecycleState` makes `Missed` and `ActiveReplacement` terminal on one missed challenge, and `StorageDomainParams` / `verifier-registry` accept `u64::MAX` and a zero-modulus malicious slash | Açık | owed: `audit_lane_c_blg_148_*` | `src/storage/lifecycle.rs`: `StorageLifecycleState`, `Missed`, `ActiveReplacement` (İP-07 removal foot: the file is in the legacy-storage removal list); `src/domain/storage_deal.rs`: `lifecycle_state`; `budzero/verifier-registry/src/params.rs` | İP-33 (registry foot), İP-07 (lifecycle foot) |
| BLG-154 | Critical | STARK verifier and canonical recovery | PCS-bypassing `aux_trace_next` proves a malleable proof, `VerticalPair` and `preprocessed` panics crash a remote node, K2 `canonical_recovery` single-source-quorum is bypassed, and Keccak is used unlabelled | Açık | closed foot pinned: new lock `blg_154_the_aux_commitment_cannot_be_dropped` | `budzero/bud-proof/src/bud_stark/verifier.rs`: refuses `preprocessed_width > 0 && commitments.aux_trace.is_none()` and re-derives `air_requires_aux`; `budzero/bud-proof/src/bud_stark/folder.rs`; `budzero/bud-proof/src/{canonical_recovery,canonical_set}.rs` | İP-33 |
| BLG-155 | High | Global header persistence | `GlobalBlockHeader` claims `bincode` backwards compatibility and has an unsigned proposer field, `key_set_preimage` misses the `Option` presence byte, `PruningPolicy` prunes inside a one-block reorg, and a stale `TeeAttestation` is accepted | Açık | owed: `audit_lane_c_blg_155_*` | `src/settlement/global_block.rs`; `src/settlement/key_set_preimage.rs`; `src/storage/pruning.rs`: `PruningPolicy`; `src/security/tee.rs`: `TeeAttestation` | İP-44 |
| BLG-159 | High | ZK proof system setup | `setup_preprocessed` panics on a bit shift and on the height, `StarkConfig` security parameters are empty or modular-fitting, and `SubAirBuilder` slices out of bounds | Açık | owed: `audit_lane_c_blg_159_*` | `budzero/bud-proof/src/bud_stark/preprocessed.rs`: `setup_preprocessed`; `budzero/bud-proof/src/bud_stark/config.rs`: `StarkConfig`; `budzero/bud-proof/src/bud_stark/sub_builder.rs` | İP-33 |
| BLG-162 | High | BudL lexer | The lexer refuses `%100` and CRLF sources, mis-handles a multi-star comment, refuses a `0x..` constant in a `match` arm, and erases the struct name in `BudIR` | Kapalı (önceden düzeltilmiş) | `budzero/bud-compiler/src/lib.rs::crlf_line_ends_are_whitespace`, `budzero/bud-compiler/tests/regression.rs::hex_match_pattern_matches`; source lock `blg_162_lexer_guards_are_present` | `budzero/bud-compiler/src/lexer.rs`: the whitespace skip pattern includes `\r`; `budzero/bud-compiler/src/parser.rs`: `MatchPattern::IntLit` | İP-33 |
| BLG-182 | Critical | ZKVM STARK soundness | `Plonky3Adapter` / `BudAir` leave public inputs unbound (`final_state_root`, `exit_code`, `gas_limit`, `initial_state_root[16..32]`, `COL_EVENT_DIGEST_1..7`) and the `bud-cli` structure test skips proving | Açık | owed: `audit_lane_c_blg_182_*` | `budzero/bud-proof/src/adapter.rs`, `budzero/bud-proof/src/plonky3_air.rs`: `COL_EVENT_DIGEST_1..7`, `initial_state_root`; `src/ai/types.rs`: `final_state_root`, `gas_limit` | İP-33 |
| BLG-186 | Critical | ZKVM field canonicality | Canonical syscall context (`sender`, `nonce`, `block_height`) and `gas_used` are not canonical under the Goldilocks overlap (`x` vs `x + P`), and `ProofEnvelope::degree_bits` is malleable | Açık | owed: `audit_lane_c_blg_186_*` | `src/execution/zkvm.rs`: `TxContext::{sender,nonce,block_height}`; `budzero/bud-proof/src/adapter.rs`: `ProofEnvelope::degree_bits` | İP-33 |
| BLG-190 | Critical | Identity isolation | The `did:bud` `IdentityRegistry` lets `IdentityTx::Recover` bypass the PoA field gate, social recovery does not work on key loss, a fake `credential_root` is injected over the wire, and the mempool gap stays open | Açık | owed: `audit_lane_c_blg_190_*` | `src/registry/identity.rs`, `src/core/transaction.rs`: `IdentityTx::Recover`, `credential_root`; `src/mempool/` acceptance path | İP-44 |
| BLG-191 | Critical | ZKVM completeness | `Vm::run_receipt` appends a synthetic `Halt` row to an error trace, which contradicts the `Plonky3Adapter` program CTL (`COL_PROG_MULT`), so a failed zkVM trace cannot be proved | Doğrulandı | owed: `audit_lane_c_blg_191_*` | `budzero/bud-vm/src/lib.rs::run_receipt`: the `if error.is_some()` block appends a "synthetic Halt step" when the last row is not a `Halt`; `budzero/bud-proof/src/plonky3_air.rs`: `COL_PROG_MULT`, the `Vm::run_receipt` note | İP-33 |
| BLG-194 | Critical | Cross-domain relay atomicity | `Blockchain::submit_relay_proof` deletes the relay non-atomically (`AlreadyRelayed` locks the funds forever), `BridgeBurn` exceeds `MAX_TOTAL_SUPPLY` (100M BUD), and `BridgeState::lock` accepts a sub-threshold amount | Açık | owed: `audit_lane_c_blg_194_*` | `src/chain/blockchain.rs::submit_relay_proof` delegates to `src/cross_domain/bridge_tx.rs::submit_relay_proof`; `src/cross_domain/relayer.rs`: `RelayerError::AlreadyRelayed`; `src/cross_domain/bridge.rs`: `BridgeBurn`, `MAX_TOTAL_SUPPLY`. İP-07 note: none | İP-44 |
| BLG-195 | Critical | Multi-consensus finality | The `PoA`/`BFT`/`PoS` finality adapters accept a malleable commitment body (`event_root`, `state_updates`), replay a `domain_id` across domains, accept fake finality on an unregistered bridge-free domain, and `PoWEngine` has an exponent-product (`2^128`) difficulty explosion and suffix-slice blindness | Açık | owed: `audit_lane_c_blg_195_*` | `src/domain/finality_adapter.rs`: `PoAFinalityAdapter`, `reject_commitment_domain_mismatch`, `reject_unregistered_set_for_bridge`; `src/consensus/pow.rs`: `PoWEngine`; `src/core/transaction.rs`: `event_root`, `state_updates` | İP-44 |
| BLG-198 | Critical | Compiler stack safety | `budl_compile` overflows the stack with a deep iterative binary or suffix AST chain inside the 64 KiB limit, `FieldAccess` code generation is `O(N^2)`, `proof_baseline` public inputs are unbounded, and the sub-vault root surface is incomplete | Açık | closed feet: `budzero/bud-compiler/src/parser.rs::MAX_NESTING_DEPTH`, `budzero/bud-compiler/tests/regression.rs::long_operator_and_field_chains_return_parser_error` | `budzero/bud-compiler/src/parser.rs`: `MAX_NESTING_DEPTH = 32` and the depth refusal; `xtask/gates/src/gates/every_fuzz_target_is_run.rs` records the real stack overflow `budl_compile_then_run` found. Open: the `O(N^2)` `FieldAccess` codegen and the unbounded `proof_baseline` publics | İP-33 |
| BLG-199 | High | Merkle second-preimage resistance | `settlement::commitment_tree::merkle_root`, `consensus::merkle_tree::merkle_root` and `pq_anchor::aggregate_finality_roots` do not separate leaf from inner nodes (1-leaf/2-leaf and 2-leaf/3-leaf root collisions), and the storage hook has visibility gaps | Açık | closed feet: `src/settlement/commitment_tree.rs::an_odd_tail_never_mimics_a_duplicated_leaf` | `src/settlement/commitment_tree.rs::merkle_root` (promotion sentinel `BDLM_EMPTY_MERKLE_ROOT_V1`), `src/consensus/merkle_tree.rs`: `merkle_root`, `odd_promotion_sentinel`, `merkle_proof`. Open: `pq_anchor`'s aggregate root and the storage hook | İP-44 |
| BLG-204 | High | Proof market atomicity | `ProofMarketState` records a `u64::MAX` reward with no escrow, `prune_paid_receipts` deletes an unpaid receipt through a pre-overflow `Paid` mark, `Paid -> Revoked` is written backwards, and `budlum-relayer` bypasses liveness with a mainnet `"0x0"` | Açık | owed: `audit_lane_c_blg_204_*` | `src/settlement/proof_market.rs`: `prune_paid_receipts`, `Paid`, `Revoked`; `src/bin/budlum-relayer.rs` | İP-44 |
| BLG-205 | Critical | External domain registry consensus | `ExternalDomainRegistry::readmit` skips verification (`0` suffix and a mismatched version take `Faulted -> Admitted`), `last_accepted_height` rewinds, five unbounded `bincode::deserialize` calls on P2P `proto_conversions` are an OOM vector, and `ModalitySet(0)` is mutable on the wire | Açık | closed feet pinned by new lock `blg_205_readmit_rebuilds_the_adapter`; existing `external_tx.rs::readmitting_a_healthy_domain_is_refused_by_the_registry`, `::an_oversized_readmission_reason_is_refused` | Closed feet: `src/cross_domain/external/external_tx.rs::readmit` rebuilds the stored adapter from the stored golden sample; `src/cross_domain/external/intake.rs::live_policy_clock`; `src/network/proto_conversions.rs` now uses protobuf with `with_limit(..)` decoders. Open: the version-suffix readmission path and `ModalitySet` | İP-44 |
| BLG-223 | High | BudZero proof privacy | PCS `Pcs::ZK = false`: a proof does not hide its witness, so the witness of a privacy opcode can leak | Doğrulandı | owed: `audit_lane_c_blg_223_*`; new source lock `blg_223_the_pcs_is_not_zk` | `budzero/bud-proof/src/bud_stark/config.rs::is_zk` returns `Self::Pcs::ZK`; `budzero/bud-proof/src/bud_stark/prover.rs` records "whose `Pcs::ZK` is `false` (p3-fri 0.7.0)"; `verifier.rs` refuses random commitments when `SC::Pcs::ZK` is false | İP-56 (testnet closure İP-33 and İP-45) |
| BLG-224 | High | Note commitment width | The note commitment and the nullifier are 64 bits, so a general collision needs about 2^32 operations | Doğrulandı | owed: `audit_lane_c_blg_224_*` | `budzero/bud-state/src/note.rs`: `PrivacyNote::from_field_elements(commitment_fe: u64, nullifier_fe: u64)`, `Hash = [u8; 32]` with the upper 24 bytes zero, packing delegated to `budlum-note-packing` (`field_from_hash`, `is_packed`) | İP-56 (testnet closure İP-45) |
| BLG-225 | High | Private transfer binding | A private transfer does not bind ownership, conservation or membership, and spent commitments are written in the clear | Açık | owed: `audit_lane_c_blg_225_*` | `src/privacy/submit.rs`; `src/account_abstraction/private_transfer_auth.rs` (commitment now binds amount, recipient and nullifier: the record's core foot is held by that module and its tests). İP-45 testnet switch still closed | İP-45, İP-56 |
| BLG-226 | High | VerifyMerkle capacity | The `VerifyMerkle` node hash is a single round with no capacity | Açık | owed: `audit_lane_c_blg_226_*` | `budzero/bud-isa/src/lib.rs`: `VerifyMerkle` is `requires_mainnet_activation()`, so the opcode is closed on testnet and the G-7 closed-feature test is the owed evidence | İP-56 (testnet closure İP-33) |
| BLG-227 | Medium | VerifyInference semantics | `VerifyInference` checks only a digest equality, so its name claims more than it proves | Doğrulandı | owed: `audit_lane_c_blg_227_*` | `budzero/bud-isa/src/lib.rs`: `VerifyInference` is documented as "Reserved opcode. It verifies nothing." and "The AIR forces the opcode selector to zero"; `docs/AI_VERIFICATION_STATUS.md` | İP-57 (testnet closure İP-33) |
| BLG-228 | High | AI STARK verification | Full AI STARK verification is off, the initial-memory folding is collidable, and the output commitment and context are not bound to the proof | Açık | owed: `audit_lane_c_blg_228_*` | `src/ai/mod.rs` (module-level claim list), `src/ai/execution/guest.rs`: `initial_state_root`, limb recombination | İP-57 (testnet closure İP-45) |
| BLG-229 | High | AI registry | There is no per-request randomness or commitment-reveal and no deterministic inference profile | Açık | owed: `audit_lane_c_blg_229_*` | `src/ai/registry.rs` (request lifecycle), `src/ai/verification_level.rs` | İP-45 (VL-1 foot), İP-57 |
| BLG-230 | Medium | ZKVM address width | In a VM context `sender` is 64 bits while a Budlum address is 256 bits | Doğrulandı | owed: `audit_lane_c_blg_230_*`; new source lock `blg_230_the_vm_sender_is_eight_bytes` | `src/execution/zkvm.rs::TxContext`: "`sender` is the first eight bytes of the address, little endian"; `budzero/bud-vm/src/lib.rs` | İP-33 (execution foot), İP-56 |
| BLG-232 | Medium | AIR width | One AIR with 1073 columns, so a simple program pays the width of the most expensive opcode | Doğrulandı | owed: `audit_lane_c_blg_232_*`; new source lock `blg_232_one_air_of_1073_columns` | `budzero/bud-proof/src/plonky3_air.rs`: `pub const TRACE_WIDTH: usize = 1073` | İP-56 |
| BLG-233 | Medium | FRI and MMCS hashing | MMCS and the challenger are Keccak-256 and there is no recursion | Doğrulandı | owed: `audit_lane_c_blg_233_*` | `budzero/bud-proof/src/plonky3_prover.rs`: `MyHasher = SerializingHasher<Keccak256Hash>`, `MyCompress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>`, `MyChallenger = SerializingChallenger64<..>` | İP-60 |
| BLG-234 | Medium | ISA coverage | Only the BudL ISA exists; Rust-written adapters cannot be proved | Doğrulandı | owed: `audit_lane_c_blg_234_*` | `budzero/bud-isa/src/lib.rs` (single ISA, no RV32 front end), `budzero/ARCHITECTURE.md` | İP-60 |
| BLG-235 | High | External proof and sync committee | Only the ZK domain uses a BudZero proof, the Ethereum sync committee module is unwired, it counts two-thirds participation as "finalized", and the finality branch does not exist | Doğrulandı | owed: `audit_lane_c_blg_235_*`; new lock `blg_235_the_sync_committee_is_unwired` | `src/cross_domain/evm/sync_committee.rs` module docs: `WIRING: unwired - verify_execution_block_finality is reached in this tree only through the adapter modules that declare themselves unwired`; `src/cross_domain/external/zkvm_proof.rs` | İP-44, İP-60 |
| BLG-236 | Medium | Sealed content | There is no plaintext-bound commitment, so no property of sealed content can be proved | Açık | owed: `audit_lane_c_blg_236_*` | `src/storage/payload_crypt.rs`, `docs/BUD_CONTENT_ENCRYPTION.md`; `src/storage/view_grant.rs` now carries `ConfidentialBodyCommit` and `confidential_commit_digest`, which is the commitment foot this record asks for | İP-56 |
| BLG-237 | High | View grant privacy | A view grant is a plaintext on-chain row (`content_id`, `issuer`, `grantee`), so the social graph leaks | Doğrulandı | owed: `audit_lane_c_blg_237_*` | `src/storage/view_grant.rs::ViewGrant`: `content_id: ContentId`, `issuer: Address`, `grantee: Option<Address>`, `commitment()` exists but the row is still plaintext | İP-22 (confidential consent İP-56) |
| BLG-239 | Medium | Signature aggregation | The aggregation proof does not bind its statements inside the AIR | Açık | owed: `audit_lane_c_blg_239_*` | `budzero/bud-pul/` (aggregation), `budzero/bud-proof/src/plonky3_air.rs`; `docs/MAINNET_READINESS.md` (AF-24) | İP-60 |
| BLG-240 | Low | AI registry ordering | Validator ranking is computed in `f64` (RPC only) | Açık | owed: `audit_lane_c_blg_240_*` | `src/ai/registry.rs` ranking helper | İP-45, İP-57 |
| BLG-242 | Medium | Commitment hash identity | Commitments carry no hash-suite identifier | Açık | owed: `audit_lane_c_blg_242_*` | `src/crypto/domain_tags.rs` tags, but no suite id in `PrivacyNote` / `ProofEnvelope` commitments | İP-56 |
| BLG-243 | Medium | Event aggregation | Event accumulation is bound with 32 bit sums and the `Log` output is not binding | Doğrulandı | owed: `audit_lane_c_blg_243_*` | `budzero/bud-proof/src/adapter.rs`: every `Log` row adds "the low 32 bits" into `COL_EVENT_DIGEST_0..8`; `budzero/README.md`, `docs/AI_VERIFICATION_STATUS.md` | İP-56 |
| BLG-244 | Low | Device assistant | Citations are bound to a byte digest and the answer is not bound to a BudZero proof | Açık | owed: `audit_lane_c_blg_244_*` | Separate repository (on-device assistant store); no location in this tree | İP-57 (separate repository work item) |
| BLG-245 | Medium | Sealed manifest and read fee | The exact size of a sealed object is visible and the read fee binds the reader and the content | Açık | owed: `audit_lane_c_blg_245_*` | `src/storage/manifest.rs` size fields; read-fee model in `src/domain/storage_tx.rs` | İP-22 (Padmé), İP-56 |
| BLG-248 | High | Execution environments | There is no general-purpose stateful contract: `ContractCall` runs the bytecode in the transaction statelessly, the VM memory is 8 KiB, and there is no deploy or persistent storage | Doğrulandı | owed: `audit_lane_c_blg_248_*`; new source lock `blg_248_contract_call_is_stateless` | `src/execution/executor.rs`: the `TransactionType::ContractCall` arm; `src/execution/zkvm.rs`: `CONTRACT_VM_MEMORY_BYTES = 8192`, `ZkVmExecutor::execute_bytecode` | İP-26, İP-33 |
| BLG-249 | High | RPC surface | There is no ecosystem-compatible RPC; only `bud_*` methods exist, so Ethereum, Solana, Aptos and Cosmos tools cannot attach | Doğrulandı | owed: `audit_lane_c_blg_249_*`; new source lock `blg_249_the_rpc_table_is_budlum_only` | `src/rpc/method_class.rs`: 186 classified rows, all `bud_*`; no `src/rpc/compat/` directory in the tree | İP-28, İP-29, İP-31, İP-32 |
| BLG-250 | Critical | Process isolation | With `panic = "abort"` in the release profile, an in-process execution environment that panics kills every node and stops the chain | Doğrulandı | owed: `audit_lane_c_blg_250_*`; new source lock `blg_250_the_release_profile_aborts_on_panic` | `Cargo.toml`: `[profile.release] panic = "abort"`; `src/execution/coordinator/mod.rs` (no worker process is spawned; `WIRING` note in `src/execution/ee.rs`) | İP-26 |
| BLG-256 | High | Balance precision | A BUD balance is an integer atom (10^-6); there is no fraction field for EVM (18 decimals) and SVM (9 decimals), so an exact unit transfer cannot be made | Doğrulandı | owed: `audit_lane_c_blg_256_*`; new source lock `blg_256_the_balance_is_an_integer_atom` | `src/core/account.rs`: `pub balance: u64`; `src/tokenomics/` `bud()` scaling | İP-26 |
| BLG-260 | Medium | State store concurrency | The state store is single-process (`sled`), so execution-environment workers cannot read state directly and IPC reads are a performance risk | Doğrulandı | owed: `audit_lane_c_blg_260_*`; new source lock `blg_260_the_state_store_is_one_process` | `src/storage/db.rs`: `use sled::Db`, `sled::open`; PR #11 moves this file to `src/persistence/db.rs` without changing the identifier | İP-26 |
| BLG-267 | High | Classical cryptography gate | The gate refuses every classical-signature acceptance path, and there is no compatibility lane for Ethereum, Solana, Aptos and Cosmos formatted transactions | Doğrulandı | owed: `audit_lane_c_blg_267_*`; new source lock `blg_267_no_compatibility_lane_exists` | `xtask/gates/src/gates/classical_crypto_is_paired.rs`: `CLASSICAL_TOKENS`, `ALLOWLIST = "docs/pq/classical_allowlist.toml"`, count mode with `unregistered_baseline` | İP-27 |

## New findings

None this pass. No condition was found that directive section 14 does not
already record. `BLG-268` and later identifiers stay unused.
