# Package state record

This file records the state of every work package (İP-01 through İP-64) in
THE BUDLUM DIREKTIF against the live branch, as required by Section 15.5
item 7 and İP-04 (delivery 4/4). It is the single source of truth for "what
is done", "what is in flight", and "what is blocked".

## Legend

| State | Meaning |
|---|---|
| T-Launch | Blocking the Testnet Launch Gate (TLG). |
| T-Expansion | Ships after launch at an activation height. |
| Open | A PR is open against `main` for the package. |
| Partial | A delivery of the package is open; later deliveries remain. |
| Not started | No PR open; work is queued behind its dependencies. |

## Lane A (consensus, validators, settlement, bridge)

| Package | Layer | State | PRs | Notes |
|---|---|---|---|---|
| İP-01 Live verification: core | T-Launch | Partial | #68 | Lane A ledger started in #68; full live verification across all four lanes is İP-04. |
| İP-08 Validator classes and single registration | T-Launch | Partial | #45, #60 | Validator class types and `RegisterValidator` are present in `src/validators/`; reserved roles 5/9 and the mobile duty lane ship with follow-up PRs. |
| İP-12 Committee finality, ISH and consensus hardening | T-Launch | Partial | #9, #45 | Committee seat table exists in `src/consensus/`; the BLG-246 count-quorum fix lands in İP-12. |
| İP-13 Presence protocol and suspension (V-4) | T-Launch | Open | #70 | Presence aggregation and suspension, V-4 invariant. |
| İP-14 Instant Task Handover and disaster mode | T-Launch | Not started | — | Depends on İP-12, İP-13. |
| İP-16 Genesis, ceremony tool and economics | T-Launch | Partial | #34, #52, #58, #59 | Genesis parameters, 100M supply invariant, faucet tokenomics split across several PRs. |
| İP-17 State transition and chain hardening | T-Launch | Partial | #60, #62, #66, #67 | Failure-atomic block application and checked arithmetic are in progress. |
| İP-44 Domains, bridge, settlement, contracts | T-Launch | Partial | #44, #49 | Domain registry is present; bridge decision (KR-28) waits on BLG-043/57/105/194. |
| İP-49 Universal Object Layer | T-Expansion | Not started | — | Code exists under `src/object_layer/` and `contracts/object-layer/`; gated closed on testnet (KR-29). |
| İP-62/63/64 UOL families (CosmWasm, SVM, Move) | T-Expansion | Not started | — | EVM family ships with İP-49; other families follow İP-29/31/32. |

## Lane B (B.U.D. 3.0, BudZero)

| Package | Layer | State | PRs | Notes |
|---|---|---|---|---|
| İP-02 Live verification: storage | T-Launch | Not started | — | Legacy storage inventory ships with İP-02. |
| İP-06 Persistence and state-recovery move | T-Launch | Started (this branch) | #11, #60 | Stub directories created (`src/persistence/`, `src/chain/state_recovery/`); mechanical move follows. |
| İP-07 Legacy storage removal | T-Launch | Started (this branch) | #69, #71 | `no_legacy_storage` gate wired with a shrinking baseline; `ContentRef` temporary interface in place; actual file deletion lands in follow-up PRs. |
| İP-10 B.U.D. 3.0 skeleton and common types | T-Launch | Partial | — | `src/storage/bud3/` already contains bof1, segment, fountain, placement, custody, meter, limits, registry, tx, varint, pipeline, dedup_index; missing modules (object, repair, volume, upload, view, refcount, delete, seal, keys, grants, fees, access_tiering, content_gateway, rpc, maintenance) are added by İP-18 through İP-25. |
| İP-18 Segmentation and RFC 6330 fountain code | T-Launch | Partial | — | `fountain.rs`, `segment.rs` present. |
| İP-19 BOF-1 object format, QR presentation, video commitment | T-Launch | Partial | #55 | `bof1.rs` present; BOF-1 path is exercised by golden vectors. |
| İP-20 Class-aware placement, custody proofs and repair | T-Launch | Partial | #57 | Placement table, custody sub-block tree and audit draw present in `placement.rs`, `custody.rs`. |
| İP-21 Upload, view, `StorageTx` v3 and RPC | T-Launch | Partial | #56 | `StorageTxV3` apply door present; upload/view pipeline and RPC surface pending. |
| İP-22 Dedup, refcount, delete, sealed content and grants | T-Launch | Partial | #65 | `dedup_index.rs` present; sealed content path and view grants land here. |
| İP-23 Dependent module B.U.D. 3.0 transition | T-Launch | Partial | #23, #50 | BNS, SocialFi/Vault→nft_folders, Data Market/pollen, education domain/deed and content gateway all reference legacy manifests. |
| İP-24 A0 codec register and access tiering | T-Launch | Partial | #47, #57 | Codec skeleton in `crates/bud-codec/`; codecs 14-22 gated on the İP-24 acceptance test. |
| İP-25 Storage fee, endowment and rewards | T-Launch | Partial | #67 | Fee arithmetic and physical-byte pricing pending. |
| İP-33 BudZero EE and soundness | T-Launch | Not started | — | `budzero/` workspace present; EE adapter ships with İP-26/33. |
| İP-54 Shared compression context, extra codecs, private dedup | T-Expansion | Not started | — | Codecs 6, 7, 8, 12, 13, 23-26; activation height after launch. |
| İP-55 Live streaming | T-Expansion | Partial | #55 | BOF-1 bit1 stays refused on testnet. |
| İP-56 BudZero privacy core, predicate proofs, consent, PTP-1 | T-Expansion | Not started | — | Privacy transfers closed on testnet (KR-26). |
| İP-60 BudZero recursion, RV32, precompiles, domain finality proof, block aggregate proof | T-Expansion | Partial | — | `bud-sigagg` crate (PUL) referenced; RV32 and aggregate proof land in T-Expansion. |

## Lane C (Execution, UEL, EE workers, compatibility RPC)

| Package | Layer | State | PRs | Notes |
|---|---|---|---|---|
| İP-03 Live verification: execution, BudZero, domains, privacy, AI | T-Launch | Not started | — | Engine inventory (`docs/audit/live/engine-inventory.md`) ships with İP-03. |
| İP-09 EE interface (uel-abi) | T-Launch | Partial | — | `crates/uel-abi/` exists; protobuf/UDS transport pending. |
| İP-26 Execution Coordinator and EE workers | T-Launch | Partial | #36 | Worker isolation, attoBUD ledger and state commitments started in #36. |
| İP-27 EVM EE and foreign envelope | T-Launch | Partial | #24, #61 | EVM adapter pending; depends on UEL Coordinator. |
| İP-28 Ethereum JSON-RPC gateway | T-Launch | Partial | #56, #72 | Method table and graceful refusals in #72; state methods wait for İP-27. |
| İP-29 WASM (CosmWasm ABI) and Cosmos RPC subset | T-Launch | Not started | — | Depends on İP-26, İP-09. |
| İP-30 Universal Call and Universal Asset Registry | T-Launch | Partial | #24, #36 | Pointer contract shape pending EVM and WASM workers. |
| İP-31 SVM and Solana RPC subset | T-Launch | Not started | — | Depends on İP-26. |
| İP-32 Move (Aptos) and Aptos REST subset | T-Launch | Not started | — | Depends on İP-26. |
| İP-34 Migration kit | T-Launch | Partial | #46, #52, #61 | EVM state-transfer verification core in `src/cross_domain/evm/`. |
| İP-35 Conformance, gas calibration, cross-arch determinism | T-Launch | Partial | #36 | Execution conformance suites under `execution/conformance/` pending. |
| İP-50 Move (Sui dialect) EE | T-Expansion | Not started | — | After İP-32. |
| İP-51 Cairo EE | T-Expansion | Not started | — | After İP-35. |
| İP-52 SVM and Move pointers | T-Expansion | Not started | — | After İP-30, İP-31, İP-32. |
| İP-53 NEAR WASM, PolkaVM, TVM, UTXO script, Plutus | T-Expansion | Not started | — | Each EE gets its own workspace and PR series. |
| İP-57 AI Verification Layer | T-Expansion | Partial | #43, #44, #45 | VL-1 gating in `src/ai/` and `crates/ai-inference/`. |
| İP-59 Parallel execution | T-Expansion | Not started | — | After İP-35. |

## Lane D (mobile, clients, tooling, CI, docs, operations, hardening)

| Package | Layer | State | PRs | Notes |
|---|---|---|---|---|
| İP-04 Live verification: clients, ops, CI, docs and unified status | T-Launch | Started (this branch) | #72 | `docs/work/PACKAGES.md` (this file) created; full four-lane status, `FINDINGS.md`, `LIVE_STATUS.md` and per-lane lane files ship with İP-04. |
| İP-05 Concept name map and counter gate | T-Launch | Partial | #20, #31, #50, #68 | `config/naming/concept_map.toml`, `.github/concept-names-baseline.txt`, `xtask/gates/src/gates/concept_names.rs` all wired. Counter ratchets down; switch to "absolute" at İP-43. |
| İP-11 Mobile core and light client | T-Launch | Not started | — | `crates/budlum-types/` split and UniFFI mobile core pending. |
| İP-36 Android validator application | T-Launch | Not started | — | `mobile/` tree pending; Kotlin + Jetpack Compose, `specialUse` FGS. |
| İP-37 Mobile device matrix and field test | T-Launch | Not started | — | After İP-36. |
| İP-38 iOS opportunistic application | T-Launch (beta) | Not started | — | Does not block launch. |
| İP-39 Wallet core and CLI | T-Launch | Not started | — | After İP-11. |
| İP-40 Explorer and indexer | T-Launch | Partial | — | `crates/budscan/` present; rename to `budlum-explorer` is İP-40. |
| İP-41 Faucet and operations | T-Launch | Partial | #34, #52, #58, #59 | POW faucet and testnet ops surface in progress. |
| İP-42 CI, gates and supply chain | T-Launch | Partial | #29, #30, #31, #42, #63 | `no_float_in_consensus_paths` (this branch), `workflows_cover_every_workspace`, `readme_has_no_placeholders`, `bud3_object_is_universal`, `bud3_qr_is_presentation`, `bud3_placement`, `bud3_repair_fires`, `bud3_custody_proofs`, `bud3_paid_view`, `bud3_custody_rewards`, `bud3_fee_uses_physical_bytes`, `bud3_object_is_universal`, `ee_workers_build_with_unwind`, `explorer_parity`, `explorer_patchset` remain to be wired or renamed. |
| İP-43 Docs, README and TLG report | T-Launch | Partial | #51 | README target text in Ek A/B of the directive; final write waits for measured numbers. |
| İP-45 Privacy, AI and account abstraction: testnet boundary | T-Launch | Partial | #43, #44, #49 | `private_transfers_is_closed_on_testnet` and AI refusal tests land here. |
| İP-46 Ceremony rehearsal, rehearsal network and measurements | T-Launch | Not started | — | After İP-36. |
| İP-47 Independent review 1 (core and storage) | T-Launch | Not started | — | After code freeze. |
| İP-48 Independent review 2 (execution, mobile, clients) | T-Launch | Not started | — | After code freeze. |
| İP-58 F-Droid and reproducible Android build | T-Expansion | Not started | — | After İP-36. |
| İP-61 RPC and crypto hardening | T-Launch | Open | #41, #53 | BLG-004, BLG-009, BLG-010, BLG-029, BLG-030, BLG-032, BLG-099, BLG-150, BLG-192, BLG-200, TEST-GAP-07. |

## Gates wired in this delivery

* `no-legacy-storage` (İP-07, Section 5.4/5.5): identifier and path ban with a
  shrinking ratchet and canary.
* `no-float-in-consensus-paths` (İP-42, Section 16.3): refuses `f32`/`f64`
  tokens under consensus-critical roots with a shrinking baseline.
* Gate renames queued (delivered when İP-06 moves the files):
  * `regeneration` -> `canonical_programs_reproduce`
  * `zkvm_immune_regeneration` -> `zkvm_refuses_untrusted_proofs`
  * `regen_health_door` -> `state_recovery_door`
  * `budscan_parity`/`budscan_patchset` -> `explorer_parity`/`explorer_patchset` (İP-40)

## Directories introduced in this delivery

* `src/persistence/` (İP-06): target home for `db`, `traits`, `state_trie`,
  `pruning`, `witness_retention`.
* `src/chain/state_recovery/` (İP-06): target home for the moved regeneration
  health files; renames `RegenerationLedger` to `RecoveryLedger`.
* `docs/work/` (İP-04): package-state records and PR coordination audit
  (see `docs/work/PR_COORDINATION.md` produced by #72).

## Directive deviation log

None in this delivery. THE BUDLUM DIREKTIF lives at the repository root
per Section 0.1 item 5 ("Bu belge depoya girmez"). A follow-up in İP-43
moves it to the out-of-tree location and wires the directive-outside-tree
check that WP-42 names.
