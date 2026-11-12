# Budlum Testnet Requirements Index

This document lists every item that `THE_BUDLUM_DIREKTIF.md` (v1.0, dated 2026-11-04) requires for the Budlum testnet launch.

## Directive Status and Scope Rules

1. `THE_BUDLUM_DIREKTIF.md` is intentionally absent from `budlum-xyz/budlum`. Section 0.1.5 and the `tree_is_english` gate forbid adding Turkish directive files to the repository tree.
2. We read the full directive externally at `/home/user/THE_BUDLUM_DIREKTIF.md` (6,044 lines, Sections 0 to 20 and Appendices A to D).
3. Repository rules forbid opening extra pull requests or GitHub issues. We track every work package and design note under `audit-notes/testnet/` on the single audit pull request branch instead of creating `WP-NN` GitHub issues.
4. Work packages divide into three layers:
   - **T-Launch (Required)**: 47 TLG-blocking packages (`WP-01` to `WP-33`, `WP-35` to `WP-37`, `WP-39` to `WP-48`, and `WP-61`).
   - **T-Launch (Beta)**: 2 non-blocking packages (`WP-34` Migration Kit and `WP-38` iOS opportunistic app).
   - **T-Expansion (Post-Launch)**: 15 packages (`WP-49` to `WP-60`, `WP-62` to `WP-64`). Features from T-Expansion stay closed on testnet chain ID `45261` and require explicit `<feature>_is_closed_on_testnet` refusal tests at launch.
5. Current `main` (`95c07fd7`) baseline observations:
   - `config/testnet.toml`, `config/testnet-genesis.json`, `config/archive.toml`, and `src/core/chain_config.rs` already define `chain_id = 45261`.
   - `docs/TESTNET.md` does not exist on `main`.
   - Legacy storage trees (`bud/`, `budzero/bud-node/`, legacy `src/storage/` modules), old concept directories (`src/pollen/`, `src/deed/`, `src/budlumxyz/`, `crates/budscan/`), and pre-UEL execution still reside on `main`.
   - Target directories (`src/persistence/`, `src/storage/bud3/`, `src/validators/`, `src/execution/coordinator/`, `src/rpc/compat/`, `crates/bud-codec/`, `crates/uel-abi/`, `crates/budlum-types/`, `execution/`, `mobile/`, `config/naming/concept_map.toml`) are not yet present on `main`.

---

## 1. Testnet Chain Identity and Core Parameters (`KR-34`, Sections 6.21, 7.2, 8.6.2, 8.9, 11.10)

| Parameter | Required Testnet Value | Tag / Rule |
|---|---|---|
| Chain ID | `45261` | Fixed (`KR-34`) |
| Network magic | `BDLT` | Fixed (`KR-34`) |
| Aptos compat chain ID | `205` | Fixed (`KR-34`) |
| Cosmos compat chain ID | `budlum-testnet-1` | Fixed (`KR-34`) |
| Genesis Full validators | `>= 8` across `>= 3` cloud regions, `>= 2` providers, `>= 4` operators | `TLG-17`, Section 17.2 |
| Slot duration | `3 s` (`ROUND_TIMEOUT_MS` bounded) | `TESTNET-DEFAULT` |
| Epoch length | `50` slots (`150 s`) | `TESTNET-DEFAULT` |
| Checkpoint interval `I` | `5` blocks (`15 s`) | `TESTNET-DEFAULT` |
| Total BUD supply | `100,000,000 BUD` (`u128`, unified ledger + `frac_attos`) | Fixed (`G-3`, `KR-20`) |
| Block gas limit | `60,000,000 BGU` (EIP-1559: `10%` burn, `90%` pool) | `TESTNET-DEFAULT` (`KR-24`) |
| Network Security Pool | `10,000,000 BUD` over `100,000` epochs (`40%` consensus, `50%` custody, `10%` repair and relay) | `TESTNET-DEFAULT` (`KR-15`) |
| Storage fee rate `P_s` | `1 BUD / GiB / year`, minimum `0.001 BUD` (`95%` Storage Endowment, `5%` upload gateway) | `TESTNET-DEFAULT` (`KR-14`) |
| Validator stake floors | `1,000 BUD` (`Full`), `10 BUD` (`Mobile`, `MobileOpportunistic`) | `TESTNET-DEFAULT` (`KR-10`) |
| Mobile duty tx lane | Fee-free, batch rate-limited (`1/validator/window`), `20%` block byte cap | `TESTNET-DEFAULT` (`KR-10`) |
| Finality committee `S` | `min(128, 4 * |E_e|)`, cap `floor(S / 4)` per validator, `R = 3` standbys, handover cap `ceil(S / 10)` per checkpoint, quorum `floor(2 * A_x / 3) + 1` seats | `TESTNET-DEFAULT` (`KR-06`, `KR-07`) |
| Audit / Presence / Suspend | Full: `2` epochs / `1` epoch / `1` day; Android Mobile: `24 h` / `4` epochs / `72 h`; iOS: `48 h` / app + bg / `7 d` | `TESTNET-DEFAULT` (`KR-41`) |
| Audit sample probability | `2%` Full, `1%` Mobile per custody share per epoch; `1%` repair symbol verification | `TESTNET-DEFAULT` (6.10, 6.11) |
| Slashing events | Double-sign (`equivocation`), proven bad repair (`1%`), presence double-sign (`1%`); absence suspends without slashing | Fixed (`V-4`, `KR-08`, `KR-16`) |
| B.U.D. 3.0 bounds | Max content `16 GiB`, segment `K_MAX = 4096`, P0 symbol `2911 B` (`10 fps`), `64 MiB` pixel-verify split, aggregation volume `4 MiB`, mobile floor `phi = 30%`, `1-64 GiB` mobile quota (`4 GiB` default), `6 h` upload TTL, `4` open sessions/acct, `64 GiB/day` upload/acct, `64` gateway sessions, `30 d` to `10 y` lifetime | `TESTNET-DEFAULT` (6.12, 6.17, 6.21) |
| Faucet bounds | `100 BUD / address / day`, `1 req / IP / day`, `100,000 BUD / day` total, PoW per request | `TESTNET-DEFAULT` (`KR-32`) |
| Universal Call limits | Max depth `8`, reentrancy forbidden | Fixed (`KR-23`) |
| Compat RPC listeners | `127.0.0.1:18545` (Budlum public), `18546` (operator, auth), `18547` (Ethereum), `18548` (Solana HTTP), `18549` (Solana WS), `18550` (Aptos REST), `18551` (Cosmos) | `KR-25`, `KR-33`, Section 8.11 |

---

## 2. Testnet Feature Matrix (Section 1.5)

Every closed or unmet conditional feature must be rejected on chain ID `45261` with an explicit reason and proven by a `<feature>_is_closed_on_testnet` test (`G-7`, `TLG-02`).

| Feature | Launch State | Opening Condition / Governing Work Package |
|---|---|---|
| PoS, committee finality, instant seat handover | Open | `WP-12`, `WP-13`, `WP-14` |
| Full validator (`ValidatorClass::Full`) | Open | `WP-08` |
| Mobile validator (`ValidatorClass::Mobile`, Android) | Open | `WP-08`, `WP-20`, `WP-36` |
| Mobile validator (`ValidatorClass::MobileOpportunistic`, iOS) | Beta | `WP-38` (does not block launch) |
| B.U.D. 3.0 public content | Open | `WP-18` to `WP-25` |
| B.U.D. 3.0 sealed content (same-owner dedup) | Open | `WP-22` |
| B.U.D. 3.0 cross-owner private deduplication | Closed | `WP-54`, `WP-56` (`private_dedup_is_closed_on_testnet`) |
| B.U.D. 2.0 format codecs `14` to `22` | Open if `WP-24` gate passes | `WP-24` (five-part codec gate; otherwise closed) |
| Context codecs (`12`, `13`), CM (`8`), preflate (`6`), lossless audio (`7`), genomic (`23`), Office (`24`), point cloud (`25`), lossless image (`26`) | Closed | `WP-54` (`closed_codecs_are_refused_on_testnet`) |
| Live streaming (BOF-1 `flags` bit1) | Closed | `WP-55` (`live_streaming_is_closed_on_testnet`) |
| EVM execution environment and Ethereum JSON-RPC | Open | `WP-27`, `WP-28` |
| WASM execution environment (CosmWasm ABI) and Cosmos RPC subset | Open | `WP-29` |
| SVM execution environment and Solana RPC subset | Open | `WP-31` |
| Move execution environment (Aptos dialect) and Aptos REST subset | Open | `WP-32` |
| BudZero execution environment (execution-only mode) | Open | `WP-33` |
| Universal Call (cross-EE atomic invocation) | Open | `WP-30` |
| Universal Asset Registry with EVM and WASM pointers | Open | `WP-30` |
| SVM and Move asset pointers | Closed | `WP-52` (`svm_move_pointers_are_closed_on_testnet`) |
| Migration Kit (verified EVM state transfer) | Beta | `WP-34` (does not block launch) |
| Consensus domain registration (`PoW`, `PoS`, `PoA`, `BFT`, `ZK`) | Open | `WP-44` |
| Bridge (`lock`, `mint`, `burn`, `unlock`) | Conditional | Open if `BLG-043`, `BLG-057`, `BLG-105`, `BLG-194` are closed; else closed (`bridge_is_closed_on_testnet`) |
| Universal Object Layer (`object_layer`) | Closed | `WP-49` (`object_layer_is_closed_on_testnet`) |
| Remote Application Binding (`app_binding`) | Closed | Separate decision after `WP-49` (`app_binding_is_closed_on_testnet`) |
| Shared Security (`shared_security`) | Closed | Opens when Sepolia E2E test passes (`shared_security_is_closed_on_testnet`) |
| Private transfers (`private_transfer_v1` / PTP-1) | Closed | `WP-56` (`private_transfer_is_closed_on_testnet`) |
| On-chain AI inference layer (`ai_verification`) | Conditional | Open at `VL-1` if `BLG-059` to `BLG-062` close and `VL-1` conditions (`n=5`, `k=4`, `100`-block challenge, `1%` sample) hold (`WP-45`); else closed |
| BNS, SocialFi (`nft_folders`), Data Market, Content Gateway | Open | `WP-23` (migrated to B.U.D. 3.0) |
| Explorer and indexer (`crates/budlum-explorer`) | Open | `WP-40` |
| Faucet (`budlum-faucet`) | Open | `WP-41` |

---

## 3. Core Architectural Deliverables Required for Testnet

### 3.1 Single Storage System (`B.U.D. 3.0`) and Legacy Removal (Sections 5 and 6)

1. Relocate node key-value store to `src/persistence/` and node recovery to `src/chain/state_recovery/`.
2. Remove B.U.D. 1.0, B.U.D. 2.0, generative content (`BudStorageEdition`, `generated.rs`, `render.rs`, `fixed_point.rs`), `bud/`, `budzero/bud-node/`, legacy `StorageTx` variants, roles `5` and `9`, legacy storage RPC methods, and obsolete storage gates.
3. Add `no_legacy_storage` and `bud3_forbidden_phrases` CI gates.
4. Implement `crates/bud-codec/` (A0 pipeline `S0`-`S5`, deterministic dictionary training, MCU crop derivation, FastCDC delta, codec registry `0`-`5`, `10`-`11`, and gated `14`-`22`).
5. Implement `src/storage/bud3/`:
   - `BOF-1` canonical binary and text formats (`B3`, LEB128 bounds, `flags`, `content_len = 0` when sealed, `BDLM_BUD3_SEGMENT_V1`, `BDLM_BUD3_OBJECT_V1`).
   - Streaming segmentation and RFC 6330 `raptorq` (`K_MAX = 4096`).
   - Optical QR frame presentation (`P0` / `P1`), logical video commitment, two-path gate (video-decoded bytes == encoder bytes), and round-trip gate (`<= 64 MiB` full pixel decode, `> 64 MiB` `>= 32` frames/segment and `>= 1%` pixel sample).
   - Class-aware wide-stripe placement (`>= 30%` mobile floor, stake-weighted rendezvous, precomputed genesis `PlacementTable`), custody sub-block Merkle tree (`BDLM_BUD3_SYMBOL_V1`, `BDLM_BUD3_SYMBOLS_V1`), `CustodyAck`, `CustodyProofBatch`, lazy repair (`f/2` trigger, `20`-block handover, `1%` repair audit), and `DeclineContent` / `ReleaseShares`.
   - `AggregationVolume` (`4 MiB`), `ObjectCommitment` replacement with 3-validator verification, access-tier telemetry (transitions closed without Y-class codecs), deduplication (public and same-owner sealed), refcounting, `SocialDelete` / `BurnReference` crypto-shredding, Padme bucketing, and HPKE X-Wing (`0x647a`) + `ViewGrant` consent enforcement.
   - `StorageTx` v3, storage RPCs, libp2p protocols (`/budlum/bud3/{symbols,custody,upload}/1`), and Storage Endowment accounting.
   - Migrate `src/bns/`, `src/socialfi/`, `src/data_market/`, `src/education_domain/`, `src/app_registry/`, and `content_gateway.rs` onto `bud3` (`ContentRef` / `ContentId`).
   - Pass all B.U.D. 3.0 acceptance tests (`T1` to `T12`, `T14` to `T26`, `T34` to `T45`).

### 3.2 Validator Network, Mobile Validator, and Instant Handover (Section 7)

1. Implement unified stake registry (`TransactionType::RegisterValidator`, `ChangeValidatorClass`, `ResumeValidator`, `RotateOperatorKey`) covering `Full`, `Mobile`, and `MobileOpportunistic` classes and `20%` fee-free mobile duty mempool lane.
2. Implement seat-based finality committee (`BLG-246`): `S <= 128`, `floor(S/4)` cap, `floor(2*A_x/3)+1` seat quorum, BLS RFC 9380 + single ML-DSA-65 signature per signer (`BUDLUM_PREVOTE_V3`, `BUDLUM_PRECOMMIT_V3`), sequential checkpoint voting, `HandoffCertificate`, and shadow-mode `hash_chain_election`.
3. Implement Instant Seat Handover solely from finalized `SeatParticipation` bitmaps, `ParticipationOmission` evidence, Instant Duty Handover across all 9 duties, catastrophic finality-stall recovery mode (`8` missed checkpoints / `40` blocks), and `budlum_finality_stalled` metric.
4. Implement `/budlum/presence/1` gossip, in-block `PresenceAggregate`, non-slashing suspension (`V-4`), and double-sign slashing (`1%`).
5. Extract `crates/budlum-types` and build `mobile/core` (`budlum-mobile-core` via UniFFI, embedded DB via `redb` or flat-file WAL without `sled`) and `mobile/android` (`aarch64-linux-android`, `x86_64-linux-android`, `minSdk 29`, current Play `targetSdk`, `specialUse` foreground service, 15-minute WorkManager job, Keystore/StrongBox operator keys, manufacturer battery guide, field matrix across `>= 20` Android phones).
6. Enable libp2p `relay`, `dcutr`, `autonat`, `[relay]` node config, and `SecurityConfig.enable_circuit_relay`.

### 3.3 Universal Execution Layer (UEL) and Compatibility Gateways (Section 8)

1. Define `crates/uel-abi` and `proto/budlum/execution/v1/ee.proto` (UDS + protobuf, out-of-process workers with `panic = "unwind"`, interpreter-only sequential execution across `x86_64` and `aarch64`).
2. Build Execution Coordinator (`src/execution/coordinator/`): `GlobalBlockHeader` V8 `execution_root`, overlay write log + atomic frame rollback, unified BUD ledger (`frac_attos` `u128`), deterministic derived aliases, `UniversalCall` (depth `<= 8`, no reentrancy), and `UniversalAssetRegistry` (EVM + WASM pointers open; SVM + Move pointers closed).
3. Implement 5 T-Launch EE workers:
   - `0x00` BudZero (`execution/budzero`, execution-only).
   - `0x01` EVM (`execution/evm`, `revm =43.x`, foreign Ethereum envelope).
   - `0x02` WASM (`execution/wasm`, `wasmi` + CosmWasm ABI, no floats, foreign Cosmos envelope).
   - `0x03` SVM (`execution/svm`, `solana-svm` + `solana-sbpf` interpreter without JIT, foreign Solana envelope).
   - `0x04` Move (`execution/move`, `aptos-vm` sequential without Block-STM, foreign Aptos envelope).
4. Tag foreign accounts as quantum-class `classical` (`classical_crypto_is_paired`), isolate quantum-safe balances, and expose compatibility RPC gateways (`127.0.0.1:18547..18551`).
5. Pass cross-arch determinism, BGU gas calibration, conformance suites (`docs/EXECUTION_LIMITS.md`), `uel_evm_calls_wasm_atomically`, and unmodified tooling CI checks (Foundry, Hardhat, viem, ethers, CosmJS, Anchor, solana CLI, `@solana/web3.js`, aptos CLI, Aptos TS SDK).

### 3.4 Hardening, Renaming, Operations, Rehearsal, and Documentation (Sections 2, 10 to 12, 16 to 18)

1. Harden consensus, state transition, P2P, RPC (key permissions, CORS header sanitization, explicit serialization errors, `Prepare` nonce/fees, `method_class.rs` parity, auth separation between public and operator listeners), cryptography (`domain_tags.rs` inventory, ML-DSA context strings, PKCS#11 label selection), genesis ceremony tooling (`testnet-genesis`), domains/bridge, and AI/privacy testnet boundaries.
2. Execute concept renaming via `config/naming/concept_map.toml` and `concept_names` CI gate until baseline reaches zero (`WP-05` -> `WP-43`).
3. Build operational stack: `budlum-faucet`, `crates/budlum-explorer` + `budlum-indexer`, `wallet-core` + `bud` CLI + `src/project_manifest.rs`, `ops/rehearsal/` drill automation (`T-1` through `T-7`), reproducible release + SBOM + signatures (`v1.0.0-testnet`), and CI/nightly/supply-chain gates.
4. Deliver verified documentation: `README.md` (verbatim Appendix A), `README.tr.md` (verbatim Appendix B), `docs/TESTNET.md`, `docs/VALIDATOR_GUIDE.md`, `docs/MOBILE_VALIDATOR.md`, `docs/STORAGE.md`, `docs/STORAGE_ENCRYPTION.md`, `docs/EXECUTION_LIMITS.md`, `docs/MOBILE_DEVICE_MATRIX.md`, `docs/SHARED_SECURITY.md`, `docs/APP_BINDING.md`, `docs/rehearsal/RESULTS.md`, and `docs/audit/{LIVE_STATUS,FINDINGS,REVIEW_1,REVIEW_2,TLG_REPORT}.md`.

---

## 4. Complete Work Package Register (`WP-01` to `WP-64`)

### 4.1 T-Launch TLG-Blocking Packages (47 Items)

Step 5 designs and verifies each item in `audit-notes/testnet/WP-NN.md`.

| ID | Design File | Title | Lane | Milestone | Dependencies | Lock Paths | Findings Closed |
|---|---|---|---|---|---|---|---|
| `WP-01` | `audit-notes/testnet/WP-01.md` | Live Verification: Core | A | M0 | None | `docs/audit/live/lane-a.md`, `src/tests/audit_lane_a.rs` | Live-verify Lane A `BLG`/`BULGU` items |
| `WP-02` | `audit-notes/testnet/WP-02.md` | Live Verification: Storage | B | M0 | None | `docs/audit/live/lane-b.md`, `src/tests/audit_lane_b.rs` | Live-verify Lane B `BLG`/`BULGU` items |
| `WP-03` | `audit-notes/testnet/WP-03.md` | Live Verification: Execution, BudZero, Domains, Privacy, AI | C | M0 | None | `docs/audit/live/lane-c.md`, `src/tests/audit_lane_c.rs`, `budzero/tests/audit_lane_c.rs` | Live-verify Lane C `BLG`/`BULGU` items |
| `WP-04` | `audit-notes/testnet/WP-04.md` | Live Verification: Clients, Ops, CI, Docs, Unified Status | D | M0 | `WP-01` to `WP-03` (before final docs) | `docs/audit/live/lane-d.md`, `docs/audit/LIVE_STATUS.md`, `docs/audit/FINDINGS.md`, `docs/work/PACKAGES.md`, `src/tests/audit_lane_d.rs` | Consolidate all live status |
| `WP-05` | `audit-notes/testnet/WP-05.md` | Concept Name Map and Counter Gate | D | M1 | `WP-04` | `config/naming/concept_map.toml`, `xtask/gates/src/gates/concept_names.rs`, `.github/concept-names-baseline.txt`, `docs/NAMING.md` | `BLG-255` (ratchet) |
| `WP-06` | `audit-notes/testnet/WP-06.md` | Persistence and State Recovery Relocation | B | M1 | `WP-02` | `src/storage/{db,traits,merkle_trie,pruning,witness_retention}.rs`, `src/persistence/`, `src/domain/{regeneration_stage,regen_health,regen_mempool}.rs`, `src/network/regen_health_tick.rs`, `src/chain/state_recovery/`, gates (`regeneration`, `zkvm_immune_regeneration`, `regen_health_door`) | Scope prep for `WP-17` |
| `WP-07` | `audit-notes/testnet/WP-07.md` | Legacy Storage Systems Removal | B | M1 | `WP-06` | `bud/`, `budzero/bud-node/`, legacy `src/storage/`, `src/domain/{storage_deal,storage_params,deal_open,storage_tx}.rs`, `src/chain/{storage_economics_tests,storage_maintenance}.rs`, `src/execution/executor.rs` (`StorageTx`), `src/rpc/server.rs` (storage), `proto/budlum/network/protocol.proto`, `xtask/gates/src/gates/`, `crates/bud-codec/`, `tests/vectors/bud3/corpus/`, storage docs | `BLG-035`, `045`-`047`, `073`-`080`, `122`, `123`, `141`, `148*`, `152`, `153`, `156`, `208`, `209`, `217`, `253`, `254`, `258`, `BULGU-017`, `TEST-GAP-06` |
| `WP-08` | `audit-notes/testnet/WP-08.md` | Validator Classes and Unified Registry | A | M1 | `WP-01` | `src/validators/`, `src/registry/{role,permissionless}.rs`, `src/core/account.rs`, `src/core/chain_config.rs`, `src/mempool/` | `BLG-252`, `253*`, `266`, `BULGU-022` |
| `WP-09` | `audit-notes/testnet/WP-09.md` | Execution Environment ABI (`uel-abi`) | C | M1 | `WP-03` | `crates/uel-abi/`, `proto/budlum/execution/v1/ee.proto` | UEL interface contract |
| `WP-10` | `audit-notes/testnet/WP-10.md` | B.U.D. 3.0 Skeleton and Shared Types | B | M2 | `WP-07` | `src/storage/bud3/`, `crates/bud-codec/`, `proto/budlum/storage/v3/bud3.proto`, `tests/vectors/bud3/`, `xtask/gates/src/gates/bud3_forbidden_phrases.rs` | `T15` phrase gate |
| `WP-11` | `audit-notes/testnet/WP-11.md` | Mobile Core and Light Client | D | M4 | `WP-10`, `WP-12`, `WP-13`, `WP-15`, `WP-20` | `mobile/core/`, `crates/budlum-types/`, `src/light_client/` | `BLG-022`, `257*`, `259*` |
| `WP-12` | `audit-notes/testnet/WP-12.md` | Committee Finality, Instant Seat Handover, Consensus Hardening | A | M2 | `WP-08` | `src/consensus/`, `src/chain/finality.rs`, `src/chain/blockchain.rs`, `src/security/`, `src/validators/committee.rs` | `BLG-001`, `018`, `027`, `096`, `132`, `158`, `203`, `206`, `207`, `246`, `259`, `264`, `BULGU-001`..`004`, `014`, `023`..`027`, `TEST-GAP-08` |
| `WP-13` | `audit-notes/testnet/WP-13.md` | Presence Protocol and Non-Slashing Suspension | A | M3 | `WP-12` | `src/validators/presence.rs`, `src/registry/liveness.rs`, `src/network/` (`/budlum/presence/1`), `src/chain/blockchain.rs` | `BLG-251` |
| `WP-14` | `audit-notes/testnet/WP-14.md` | Instant Duty Handover and Catastrophic Finality Mode | A | M4 | `WP-12`, `WP-13`, `WP-20`, `WP-21` | `src/validators/handover.rs`, `src/storage/bud3/{custody,repair}.rs` (hooks), `src/consensus/pos.rs`, `tests/churn/` | All 9 duty handovers |
| `WP-15` | `audit-notes/testnet/WP-15.md` | Network: NAT Traversal and P2P Hardening | A | M2 | `WP-01` | `src/network/`, `Cargo.toml` (`libp2p`), `config/*.toml` (`[relay]`), `src/core/chain_config.rs` (`SecurityConfig`) | `BLG-017`, `033`, `034`, `108`, `205*`, `247` |
| `WP-16` | `audit-notes/testnet/WP-16.md` | Genesis, Ceremony Tool, and Economy | A | M3 | `WP-08` | `src/chain/genesis.rs`, `src/tokenomics/`, `config/testnet-genesis.json`, `config/testnet.toml`, `config/archive.toml`, `xtask/tools/src/`, `src/registry/` | `BLG-002`, `003`, `005`, `006`, `008`, `094`, `140`, `263`, `266*`, `BULGU-018`..`020`, `TEST-GAP-01` |
| `WP-17` | `audit-notes/testnet/WP-17.md` | State Transition and Chain Hardening | A | M2 | `WP-01`, `WP-06` | `src/chain/`, `src/core/`, `src/mempool/`, `src/execution/executor.rs` (native), `src/sharding/`, `src/main.rs`, `src/persistence/`, `src/tests/` | `BLG-007`, `019`..`021`, `023`, `028`, `031`, `041`, `042`, `044`, `065`, `066`, `088`..`090`, `100`..`104`, `107`, `113`, `118`, `119`, `125`, `128`, `147`, `151`, `167`, `183`, `184`, `196`, `197`, `202`, `BULGU-005`..`010`, `013`, `015`, `016`, `021` |
| `WP-18` | `audit-notes/testnet/WP-18.md` | Segmentation and RFC 6330 Fountain Code | B | M3 | `WP-10` | `src/storage/bud3/{segment,fountain}.rs`, `src/storage/qr_carousel.rs`, `tests/vectors/bud3/fountain/`, `Cargo.toml` (`raptorq`) | `BLG-213`, `216` |
| `WP-19` | `audit-notes/testnet/WP-19.md` | BOF-1 Object Format, QR Presentation, Video Commitment | B | M3 | `WP-10`, `WP-24` | `src/storage/bud3/{object,bof1,frame,qr,video,two_path}.rs`, legacy QR files, `tests/vectors/bud3/bof1/`, gates (`bud3_object_is_universal`, `bud3_qr_is_presentation`) | `BLG-048`, `137`, `144`, `163`, `210`, `211`, `214`, `215`, `218`, `TEST-GAP-03` |
| `WP-20` | `audit-notes/testnet/WP-20.md` | Class-Aware Placement, Custody Proofs, and Repair | B | M3 | `WP-08`, `WP-18` | `src/storage/bud3/{placement,custody,repair,maintenance,symbol_protocol}.rs`, `src/storage/assignment.rs`, `xtask/tools/src/placement_table.rs`, `config/testnet-genesis.json` (`placement_table`), gates (`bud3_placement`, `bud3_repair_fires`, `bud3_custody_proofs`) | `BLG-220` |
| `WP-21` | `audit-notes/testnet/WP-21.md` | Upload, View, `StorageTx` v3, and Storage RPC | B | M3 | `WP-18`, `WP-19`, `WP-20` | `src/storage/bud3/{upload,view,volume,tx,rpc,content_gateway}.rs`, `content_ref.rs`, legacy `three_*` / `content_id.rs`, `src/domain/storage_tx.rs`, `src/rpc/`, gates (`bud3_paid_view`, `bud_e2e`) | `BLG-161`, `168`, `208*`, `212` |
| `WP-22` | `audit-notes/testnet/WP-22.md` | Deduplication, Refcount, Deletion, Sealed Content, Grants | B | M3 | `WP-21` | `src/storage/bud3/{dedup,refcount,delete,seal,keys,grants}.rs`, legacy `{key_package,payload_crypt,view_grant,social_delete}.rs`, `content_encryption_is_declared_and_bound.rs` | `BLG-049`, `221`, `237`, `238`, `245` |
| `WP-23` | `audit-notes/testnet/WP-23.md` | Dependent Modules Migration to B.U.D. 3.0 | B | M4 | `WP-22` | `src/bns/`, `src/socialfi/`, `src/pollen/` (`src/data_market/`), `src/deed/` (`src/education_domain/`), `src/budlumxyz/` (`src/app_registry/`), `src/gateway/` | `BLG-064`, `109`, `110`, `129`, `212*`, `261`, `262` |
| `WP-24` | `audit-notes/testnet/WP-24.md` | A0 Codec Registry and Access Tiering | B | M3 | `WP-10` | `crates/bud-codec/`, `src/storage/bud3/{access_tiering,replace}.rs`, legacy `{transformed,dictionary,derived,living_threshold}.rs`, `tests/vectors/bud3/codec/`, `derived_content.rs` | `BLG-133`, `135`, `219`, `222` |
| `WP-25` | `audit-notes/testnet/WP-25.md` | Storage Fee, Storage Endowment, and Custody Rewards | B | M4 | `WP-16`, `WP-21` | `src/storage/bud3/fees.rs`, `src/storage/three_regime.rs`, `src/tokenomics/`, gates (`bud3_fee_uses_physical_bytes`, `bud3_custody_rewards`) | `BLG-209*` |
| `WP-26` | `audit-notes/testnet/WP-26.md` | Execution Coordinator and EE Worker Supervisor | C | M2 | `WP-07`, `WP-09` | `src/execution/coordinator/`, `src/execution/executor.rs`, `src/core/account.rs` (`frac_attos`), `src/core/transaction.rs`, `src/mempool/`, `execution/`, `src/settlement/global_block.rs` (`execution_root`, V8) | `BLG-248`, `250`, `256`, `260` |
| `WP-27` | `audit-notes/testnet/WP-27.md` | EVM Execution Environment and Foreign Envelope | C | M3 | `WP-26` | `execution/evm/`, `src/execution/coordinator/foreign/`, `classical_crypto_is_paired.rs`, `contracts/uel/` | `BLG-267` |
| `WP-28` | `audit-notes/testnet/WP-28.md` | Ethereum JSON-RPC Compatibility Gateway | C | M4 | `WP-27` | `src/rpc/compat/ethereum/`, `config/*.toml` (`[compat.ethereum]`) | `BLG-249` (EVM leg) |
| `WP-29` | `audit-notes/testnet/WP-29.md` | WASM (CosmWasm ABI) EE and Cosmos RPC Subset | C | M3 | `WP-26` | `execution/wasm/`, `src/execution/coordinator/foreign/cosmos.rs`, `src/rpc/compat/cosmos/` | `BLG-249*` (Cosmos leg) |
| `WP-30` | `audit-notes/testnet/WP-30.md` | Universal Call and Universal Asset Registry | C | M4 | `WP-27`, `WP-29` | `src/execution/coordinator/universal_call.rs`, `src/execution/coordinator/assets/`, `execution/evm/src/precompile_universal.rs`, `execution/wasm/src/budlum_msg.rs`, `contracts/uel/` | `uel_evm_calls_wasm_atomically` |
| `WP-31` | `audit-notes/testnet/WP-31.md` | SVM EE and Solana RPC Subset | C | M4 | `WP-26` | `execution/svm/`, `src/execution/coordinator/foreign/solana.rs`, `src/rpc/compat/solana/` | `BLG-249*` (Solana leg) |
| `WP-32` | `audit-notes/testnet/WP-32.md` | Move (Aptos Dialect) EE and Aptos REST Subset | C | M4 | `WP-26` | `execution/move/`, `src/execution/coordinator/foreign/aptos.rs`, `src/rpc/compat/aptos/`, `execution/move/deny.toml` | `BLG-249*` (Aptos leg) |
| `WP-33` | `audit-notes/testnet/WP-33.md` | BudZero Execution Environment and Hardening | C | M3 | `WP-26` | `budzero/` (excluding `bud-node`), `execution/budzero/`, `src/execution/zkvm.rs`, `src/execution/budzero_ee/` | `BLG-036`..`040`, `067`, `069`, `114`, `115`, `136`, `139`, `142`, `148*`, `154`, `159`, `162`, `182`, `186`, `191`, `198`, `248*`, `TEST-GAP-05` |
| `WP-35` | `audit-notes/testnet/WP-35.md` | Conformance Suites, Gas Calibration, Cross-Arch Parity | C | M4 | `WP-27`, `WP-29`, `WP-31`, `WP-32`, `WP-33` | `execution/conformance/`, `.github/workflows/conformance-nightly.yml`, `docs/EXECUTION_LIMITS.md` | `TLG-12`, `TLG-15`, `TLG-16` |
| `WP-36` | `audit-notes/testnet/WP-36.md` | Android Validator Application (`specialUse` FGS) | D | M4 | `WP-11` | `mobile/android/`, `.github/workflows/mobile.yml` | `BLG-257*`, `265` |
| `WP-37` | `audit-notes/testnet/WP-37.md` | Mobile Device Matrix and Field Testing | D | M4 | `WP-36` | `mobile/android/devicetests/`, `mobile/tools/log-analyzer/`, `docs/MOBILE_DEVICE_MATRIX.md` | `TLG-10`, `TLG-11` |
| `WP-39` | `audit-notes/testnet/WP-39.md` | Wallet Core and CLI | D | M4 | `WP-08`, `WP-21`, `WP-27` | `crates/wallet-core/`, `src/wallet/`, `src/cli/`, `src/bin/bud.rs`, `src/developer_os.rs` (`src/project_manifest.rs`) | `BLG-026`, `098`, `117`, `DOC-GAP-08` |
| `WP-40` | `audit-notes/testnet/WP-40.md` | Explorer and Indexer (`budlum-explorer`) | D | M4 | `WP-21`, `WP-26` | `crates/budscan/` (`crates/budlum-explorer/`), `src/bin/budlum-indexer*`, gates (`explorer_parity`, `explorer_patchset`) | `BLG-068`, `121`, `143`, `169` |
| `WP-41` | `audit-notes/testnet/WP-41.md` | Faucet and Operations | D | M4 | `WP-16` | `src/bin/budlum-faucet*`, `ops/`, `config/testnet.toml`, `release/` | `BLG-011`, `030*`, `095`, `DOC-GAP-01`, `DOC-GAP-04` |
| `WP-42` | `audit-notes/testnet/WP-42.md` | CI, Gates, and Supply Chain | D | M2 | `WP-04` | `.github/workflows/`, `xtask/`, `fuzz/`, `kani/`, `benches/`, `supply-chain/`, `deny.toml` | `BLG-012`..`016`, `081`..`087`, `097`, `170`..`172`, `174`..`181`, `187`..`189`, `193`, `254*`, `TEST-GAP-02`, `04`, `DOC-GAP-07` |
| `WP-43` | `audit-notes/testnet/WP-43.md` | Documentation, Verbatim READMEs, and TLG Report | D | M6 | `WP-46`, `WP-47`, `WP-48` | `docs/`, `README.md`, `README.tr.md`, `assets/`, `budzero/{ARCHITECTURE,README}.md`, readme gates | `BLG-092`, `231`, `241`, `255` (zero baseline), `DOC-GAP-02`, `03`, `05`, `09` |
| `WP-44` | `audit-notes/testnet/WP-44.md` | Domains, Bridge, Settlement, and Solidity Contracts | A | M4 | `WP-01` | `src/domain/`, `src/cross_domain/`, `src/settlement/`, `src/relayer/`, `src/registry/{identity,poa_}*`, `contracts/`, `docs/{SHARED_SECURITY,APP_BINDING}.md` | `BLG-024`, `043`, `050`..`058`, `091`, `105`, `116`, `120`, `127`, `130`, `131`, `134`, `138`, `146`, `155`, `190`, `194`, `195`, `199`, `204`, `205*`, `235` (testnet close) |
| `WP-45` | `audit-notes/testnet/WP-45.md` | Privacy, AI, and Account Abstraction: Testnet Boundary | B | M4 | `WP-22` | `src/privacy/`, `src/account_abstraction/`, `src/prover/`, `src/ai/`, `src/ai_inference/`, `crates/{ai-inference,note-packing,bpqs}/`, `src/execution/executor.rs` | `BLG-025`, `059`..`063`, `070`..`072`, `093`, `106`, `111`, `112`, `124`, `126`, `145`, `149`, `157`, `160`, `164`..`166`, `173`, `185`, `201`, `223`..`225`, `228`, `229*`, `240` |
| `WP-46` | `audit-notes/testnet/WP-46.md` | Ceremony Rehearsal, Rehearsal Network, Measurements | D | M5 | M4 complete | `ops/rehearsal/`, `docs/rehearsal/`, `config/rehearsal-genesis.json` | `DOC-GAP-06`, drills `T-1`..`T-7` |
| `WP-47` | `audit-notes/testnet/WP-47.md` | Independent Review 1: Core and Storage | Cross (C/D) | M5 | M4 complete | `docs/audit/REVIEW_1.md` | `TLG-22` |
| `WP-48` | `audit-notes/testnet/WP-48.md` | Independent Review 2: Execution, Mobile, and Clients | Cross (A/B) | M5 | M4 complete | `docs/audit/REVIEW_2.md` | `TLG-22` |
| `WP-61` | `audit-notes/testnet/WP-61.md` | RPC and Cryptography Hardening | D | M2 | `WP-01` | `src/rpc/` (non-compat, non-storage), `src/crypto/` | `BLG-004`, `009`, `010`, `029`, `030`, `032`, `099`, `150`, `192`, `200`, `BULGU-011`, `012`, `TEST-GAP-07` |

### 4.2 T-Launch Beta Packages (2 Non-Blocking Items)

| ID | Design File | Title | Lane | Blocking? | Dependencies | Lock Paths |
|---|---|---|---|---|---|---|
| `WP-34` | `audit-notes/testnet/WP-34.md` | Migration Kit (Verified EVM State Transfer) | C | No (Beta) | `WP-28` | `src/cross_domain/evm/account_proof.rs`, `src/execution/coordinator/migration/`, `src/bin/bud-migrate.rs` |
| `WP-38` | `audit-notes/testnet/WP-38.md` | iOS Opportunistic Validator Application | D | No (Beta) | `WP-11` | `mobile/ios/`, `.github/workflows/mobile-ios.yml` |

### 4.3 T-Expansion Packages (15 Post-Launch Items, Closed at Launch)

| ID | Title | Lane | Dependencies | Activation Condition |
|---|---|---|---|---|
| `WP-49` | Universal Object Layer (`object_layer`) | A | M7, `WP-30`, `WP-34`, `WP-44` (+ `WP-60` sync committee) | Post-launch activation height; closed on `45261` |
| `WP-50` | Move (Sui Dialect) EE | C | `WP-35` | Post-launch; closed on `45261` |
| `WP-51` | Cairo EE | C | `WP-35` | Post-launch; closed on `45261` |
| `WP-52` | SVM and Move Universal Asset Pointers | C | `WP-30`, `WP-31`, `WP-32` | Post-launch; closed on `45261` |
| `WP-53` | NEAR WASM, PolkaVM, TVM, UTXO Script, Plutus EEs | C | `WP-35` | Post-launch; closed on `45261` |
| `WP-54` | Shared Compression Context, Extra Codecs (`6`-`8`, `12`-`13`, `23`-`26`), Private Dedup | B | `WP-22`, `WP-24`, `WP-56` | Post-launch; closed on `45261` |
| `WP-55` | Live Streaming (BOF-1 bit1) | B | `WP-21` | Post-launch; closed on `45261` |
| `WP-56` | BudZero Privacy Kernel, Predicate Proofs, Consent, PTP-1 | B | `WP-22`, `WP-33` | Post-launch (`BLG-223`..`245`); closed on `45261` |
| `WP-57` | AI Verification Layer (`VL-2`, `VL-3`, chips) | A | `WP-45`, `WP-56`, `WP-60` | Post-launch (`BLG-227`..`244`) |
| `WP-58` | F-Droid and Reproducible Android Build | D | `WP-36` | Post-launch |
| `WP-59` | Parallel Execution Scheduler | C | `WP-35` | Post-launch; deterministic sequential at launch |
| `WP-60` | BudZero Recursion, RV32, Precompiles, Domain Finality & Block Aggregate Proofs | C | `WP-56` | Post-launch (`BLG-233`..`235`, `239`) |
| `WP-62` | Universal Object Layer Family: CosmWasm / Cosmos SDK | A | `WP-49`, `WP-29` | Post-launch |
| `WP-63` | Universal Object Layer Family: SVM | A | `WP-49`, `WP-31` | Post-launch |
| `WP-64` | Universal Object Layer Family: Move | A | `WP-49`, `WP-32` | Post-launch |

---

## 5. Testnet Launch Gate Checklist (`TLG-01` to `TLG-27`, Section 18)

| Gate | Requirement | Evidence Target | Source Packages |
|---|---|---|---|
| `TLG-01` | Zero open Critical or High findings (or feature closed on testnet with proof test) | `docs/audit/FINDINGS.md` | All |
| `TLG-02` | Every Closed / unfulfilled Conditional feature has passing `<feature>_is_closed_on_testnet` test | CI | All |
| `TLG-03` | Zero legacy storage code in tree | `no_legacy_storage` gate | `WP-07` |
| `TLG-04` | B.U.D. 3.0 acceptance tests green (`T1`-`T12`, `T14`-`T26`, `T34`-`T41`; nightly `T3`, `T4`, `T6`, `T7`, `T17` green 7 nights) | CI | `WP-18` to `WP-25` |
| `TLG-05` | Committee finality and seat handover tests green (Section 7.12) | CI | `WP-12`, `WP-13` |
| `TLG-06` | Instant Duty Handover tests and churn simulation green | CI | `WP-14` |
| `TLG-07` | Rehearsal drill `T-1` passes: 100% mobile departure does not delay finality or lose objects | Rehearsal log | `WP-46` |
| `TLG-08` | Rehearsal drill `T-2` passes: 10% Full validator departure delays finality by at most 2 checkpoints | Rehearsal log | `WP-46` |
| `TLG-09` | Rehearsal drills `T-3`, `T-4`, `T-5`, `T-7` pass | Rehearsal log | `WP-46` |
| `TLG-10` | Real Android phones (`>= 20`) act as validators in rehearsal (store, audit, serve symbols, claim rewards) | Explorer + rehearsal log | `WP-36`, `WP-46` |
| `TLG-11` | Device matrix results documented (`24 h` FGS, battery budget, NAT matrix) | `docs/MOBILE_DEVICE_MATRIX.md` | `WP-37` |
| `TLG-12` | EVM, WASM, SVM, Move (Aptos), BudZero conformance suites pass or document limits | CI + `docs/EXECUTION_LIMITS.md` | `WP-35` |
| `TLG-13` | Unmodified tooling nightly green (Foundry, Hardhat, viem, ethers, CosmJS, Anchor, solana CLI, `@solana/web3.js`, aptos CLI, Aptos TS SDK) | CI | `WP-28` to `WP-32` |
| `TLG-14` | EVM contract atomically calls CosmWasm contract (`uel_evm_calls_wasm_atomically` and drill `T-6`) | CI + rehearsal log | `WP-30`, `WP-46` |
| `TLG-15` | Cross-architecture root determinism green (`x86_64` vs `aarch64`) | `determinism.yml` | `WP-35` |
| `TLG-16` | Gas calibration bound met (`uel_gas_calibration_bound`) | CI | `WP-35` |
| `TLG-17` | Genesis ceremony rehearsal passes; supply audit green; `>= 8` Full validators | Ceremony report | `WP-16`, `WP-46` |
| `TLG-18` | NAT traversal (`relay`, `dcutr`, `autonat`) nightly green and rehearsal rates logged | CI + `docs/rehearsal/RESULTS.md` | `WP-15`, `WP-46` |
| `TLG-19` | Economy pool split, fees, rewards preserve fixed supply (`economy_invariants`) | CI | `WP-16`, `WP-25`, `WP-26` |
| `TLG-20` | RPC listeners, method tables, rate limits green and drill `T-7` passes | CI + rehearsal log | `WP-28` to `WP-32`, `WP-61` |
| `TLG-21` | Faucet, explorer, dashboards, and alerts run cleanly in rehearsal | Rehearsal log | `WP-40`, `WP-41` |
| `TLG-22` | Independent reviews 1 and 2 complete; new Critical/High findings closed | `docs/audit/REVIEW_1.md`, `docs/audit/REVIEW_2.md` | `WP-47`, `WP-48` |
| `TLG-23` | `README.md` equals Appendix A, `README.tr.md` equals Appendix B, definition blocks verbatim, no placeholders, measured numbers from CI/rehearsal | `readme_*` gates | `WP-43` |
| `TLG-24` | Concept naming gate green in absolute zero-baseline mode | `concept_names` gate | `WP-43` |
| `TLG-25` | All CI workflows green and all nightly workflows green for 7 nights | CI | `WP-42` |
| `TLG-26` | Reproducible release binaries (`x86_64`, `aarch64`), SBOM, and signatures published | `release.yml` | `WP-41`, `WP-42` |
| `TLG-27` | Bridge decision and AI layer decision recorded in TLG report and proven by tests | CI | `WP-44`, `WP-45` |

---

## 6. Binding Decisions (`KR-01` to `KR-42`) and Invariants (Sections 3 and 19)

1. **Core Invariants**:
   - **General (`G-1` to `G-8`)**: Consensus state changes only in blocks; deterministic execution without floats or unordered hashing; fixed `100,000,000 BUD` supply; refusals do not mutate state; length-prefixed hashes with registered domain tags; zero unwired idle code; closed features refuse explicitly; domain sovereignty with zero team-operated critical SPOFs.
   - **Storage (`D-1` to `D-15`)**: `B.U.D. 3.0` is the single persistent object; objects self-decode without raw content or video; bit-level equality across content, video, and object; two-path byte equality; information-law lower bound; zero-byte and universal format support; immutable codec decoders; zero plaintext digests or keys on public state for sealed content; single code home (`src/storage/bud3/`, `crates/bud-codec/`); single network object with minimal redundancy; fixed `ContentId` across object replacement; client-side default decoding; object survival down to 1 Full validator; owner privacy in accounting; every custody node is a staked validator.
   - **Validator Network (`V-1` to `V-5`)**: Single departure never stalls finality or loses content; full mobile withdrawal never stalls finality; seat handovers derive solely from finalized participation; absence suspends without slashing; single unified validator stake registry.
   - **Execution (`Y-1` to `Y-7`)**: Unmodified bytecode execution; unified state root and sequential block order; atomic `UniversalCall` rollback; single unified BUD ledger (`frac_attos`); no wrapped/re-minted pointer supply; isolated worker processes (`panic = "unwind"`); classical foreign accounts strictly tagged and isolated from quantum-safe accounts.
   - **Crypto and Privacy (`K-1` to `K-4`)**: Named tests back every privacy/ZK/PQ claim; plaintext/key retrieval enforces consent proof types; classical signatures never touch quantum-safe balances; single canonical crypto definition shared across wallet, node, and VM.
   - **Process (`S-1` to `S-5`)**: CI (`fmt`, `clippy -D warnings`, tests, `xtask` gates) is the sole verifier; no loosening (`allow`, `ignore`, baseline inflation, commit pinning); test-first red-to-green evidence for every fix; new gates in Rust only; `#![forbid(unsafe_code)]` in node core plus `cargo-deny`, `cargo-vet`, `cargo-geiger`.
2. **Decisions (`KR-01` to `KR-42`)**:
   - `KR-01`..`KR-03`: B.U.D. 3.0 sole storage; clean testnet genesis allowing wire/tag/RPC renames; staked validators store shares (roles `5` and `9` deleted).
   - `KR-04`..`KR-10`: `Full` + `Mobile` (Android) + `MobileOpportunistic` (iOS beta); mobile holds zero finality seats; seat-based committee quorum; finalized-only seat handover; non-slashing suspension; Android `specialUse` FGS mandatory, iOS non-blocking; `1,000` / `10 BUD` stakes and `20%` fee-free mobile duty lane.
   - `KR-11`..`KR-17`: RFC 6330 (`raptorq`, `K_MAX = 4096`); offline genesis class-aware placement table with `30%` mobile floor; `10^-12` loss and `10^-4` unavailability targets; `1 BUD/GiB/yr` (`95/5%`); `10M BUD` security pool (`40/50/10%`); unified slashing rules; no price oracles.
   - `KR-18`..`KR-25`: Out-of-process UDS+protobuf EE workers without JIT; 5 launch EEs (BudZero, `revm`, `wasmi`, `solana-svm`, `aptos-vm`); unified `frac_attos` BUD ledger; verbatim README headers; foreign envelopes (`classical` tag); `UniversalCall` max depth `8` with no reentrancy; `60M BGU` EIP-1559; loopback compat RPCs.
   - `KR-26`..`KR-33`: `PTP-1` closed until `WP-56`; conditional AI (`VL-1`) and bridge gates; `object_layer`, `shared_security`, `app_binding` closed at launch; only BudZero and B.U.D. concept names remain; 4-lane tracking rules; faucet `100 BUD/addr/day`; unauthenticated public vs authenticated operator RPC listeners.
   - `KR-34`..`KR-42`: Testnet parameters (`45261`, `BDLT`, `3 s`, `50` slots, `5` blocks, `205`, `budlum-testnet-1`); VRF leader at launch with shadow `hash_chain_election`; same-owner sealed dedup + Padme padding; `redb` or flat-file WAL for mobile (never `sled`); Wi-Fi default, `4 GiB` quota, mandatory thermal pause; documented catastrophic stall recovery; M5 freeze; exact audit/presence/suspend windows; fixed-share relay payout at launch.

---

## 7. Consolidated Finding Register Scope (Section 14)

The directive consolidates all known audit findings and requires live verification of every item (`WP-01` to `WP-04` and Step 3 line-by-line audit) plus root-cause closure (or testnet feature closure) before `TLG-01` passes:
- `BLG-001` to `BLG-207`: consolidated ledger findings (`WP-01` to `WP-48`, `WP-61`).
- `BLG-208` to `BLG-245`: source-directive code findings (`B.U.D. 3.0`, `BudZero`, `UOL` / `AI` / privacy).
- `BLG-246` to `BLG-267`: new directive findings (committee quorum, mobile NAT, UEL, compat RPC, BUD ledger, presence, stake, legacy admission, codec/fountain, naming, BGU, Android FGS/keys, content gateway, genesis faucet, finality PQ scale, Play target SDK, explorer, foreign tx bounds).
- `BULGU-001` to `BULGU-027`, `TEST-GAP-01` to `TEST-GAP-08`, and `DOC-GAP-01` to `DOC-GAP-09`: archive audit findings, test coverage gaps, and documentation gaps mapped across `WP-07`, `WP-08`, `WP-12`, `WP-16`, `WP-17`, `WP-19`, `WP-33`, `WP-39`, `WP-41` to `WP-43`, `WP-46`, `WP-61`.
