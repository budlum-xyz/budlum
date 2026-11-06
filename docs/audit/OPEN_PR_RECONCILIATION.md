# Live open-pull-request reconciliation

Snapshot: 2026-11-06. Source: GitHub REST pull-request and paginated file endpoints for `lubothebook/budlum`.
This continues the stack audit in #73 with the live 54-PR set. It is an audit delivery, not a claim that any work package or launch gate is complete.

## Verified baseline

| Item | Evidence |
|---|---|
| Main | `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` |
| Session base | the same commit |
| Working tree before edits | clean; no pre-existing uncommitted changes |
| Open deliveries | 54; one draft (#37) |
| Distinct changed paths | 794 |
| Paths changed by multiple deliveries | 222 |
| Newly added paths with differing blob IDs | 47 |
| Local Rust compiler | unavailable (`cargo` and `rustc` are not installed) |

GitHub changed-line counts below include documentation, deletions and generated files. They are not the directive's normalized 1,500-line measure. Blob differences identify content disagreement, not proof of a semantic defect. Pull-request descriptions are claims, not test evidence.

## All live deliveries

| PR | Base | Head | Files | GitHub changed lines | Title |
|---|---|---|---:|---:|---|
| [#8](https://github.com/lubothebook/budlum/pull/8) | `ccr-c224ffbb-cbjvam` | `a5f30fb86c4beca501cdeb0a0a1ccc90c92419e6` | 344 | 67611 | The codec register and the dedup index |
| [#9](https://github.com/lubothebook/budlum/pull/9) | `arena/b7784c85-budlum` | `3c5bb36dead516dc1840922274e830fb6a041701` | 25 | 1456 | WP-12: the committee seat table, the seat quorum and instant seat handover |
| [#11](https://github.com/lubothebook/budlum/pull/11) | `main` | `521d20ee27d2f263772ee53973822775d580851e` | 60 | 6710 | WP-06: move node-local persistence out of content storage |
| [#12](https://github.com/lubothebook/budlum/pull/12) | `main` | `ab89e67f9b0c3b388dfbe6b32ee4406a219b8172` | 10 | 1085 | WP-01, WP-02, WP-03: the lane A, B and C live verification ledgers |
| [#13](https://github.com/lubothebook/budlum/pull/13) | `main` | `599d29dd50cce747749a4f181fda38452668ccea` | 6 | 1861 | WP-20: the placement, custody proof and repair gates |
| [#14](https://github.com/lubothebook/budlum/pull/14) | `main` | `4da68e015ed73d50e5eae2234c51601206bac689` | 2 | 6165 | WP-44: testnet feature closures and the launch decision record |
| [#16](https://github.com/lubothebook/budlum/pull/16) | `main` | `0757719e4dcf1f4386956629f4c81f79b6eeceef` | 7 | 861 | WP-03: the lane C live verification ledger, the engine inventory and its locks |
| [#18](https://github.com/lubothebook/budlum/pull/18) | `main` | `3e37bc137db9384d9f26e7b9f98454feb43a1baf` | 3 | 206 | WP-04: start lane D live verification and behavioral regression tests |
| [#20](https://github.com/lubothebook/budlum/pull/20) | `main` | `edb7ba8aa377661e202af7d307a7e7c9df8c6a9c` | 4 | 186 | WP-05: concept name owners and the owner gate |
| [#24](https://github.com/lubothebook/budlum/pull/24) | `main` | `e4198bd5890dbccec537328e093503ca6de4d7b3` | 72 | 19482 | WP-05, WP-42, WP-26, WP-33, WP-27, WP-28 (+ WP-29, WP-30): UEL Coordinator, BudZero, EVM, Ethereum RPC, WASM & Universal Call |
| [#29](https://github.com/lubothebook/budlum/pull/29) | `main` | `befd1f5990436a08ecef79337c5c9b87ffec1a53` | 15 | 1282 | WP-42: continue PR #30 with the required-nightly gate and BLG-240 pin |
| [#30](https://github.com/lubothebook/budlum/pull/30) | `main` | `02ca179800c60eacf0dc5c9980dc4bc495ddb07e` | 13 | 1489 | WP-42: the float gate, the workspace coverage gate and the conformance nightly |
| [#31](https://github.com/lubothebook/budlum/pull/31) | `main` | `3889b6aa637cc51fe1d614d0fb87cda171d38e3e` | 15 | 2225 | WP-05 + WP-42 + WP-08: the concept map, two missing CI gates, and the mobile duty lane |
| [#34](https://github.com/lubothebook/budlum/pull/34) | `main` | `438eacd3c32fdf9de26545fce7b4670f9588a134` | 9 | 6573 | WP-61, WP-16, WP-41: RPC & crypto hardening, genesis ceremony/tokenomics, and faucet/ops |
| [#35](https://github.com/lubothebook/budlum/pull/35) | `main` | `6854f514e2501ab4c045df0f264a1d4ce9f9bf1e` | 9 | 966 | WP-04: the lane D live verification ledger and the audit status index |
| [#36](https://github.com/lubothebook/budlum/pull/36) | `main` | `4385312c0684dada1961d17b645f2f78a86e5af2` | 79 | 23721 | WP-26, 1/2: Execution Coordinator, EE worker isolation, attoBUD ledger, and UEL state commitments |
| [#37](https://github.com/lubothebook/budlum/pull/37) | `main` | `34ae1f85024d420952f6d698792bdec424984640` | 1 | 142 | WP-16: reserve the 40/50/10 epoch pool shares |
| [#38](https://github.com/lubothebook/budlum/pull/38) | `main` | `54c7aa3dd2b5a219091b27f8359350095c826c15` | 2 | 56 | WP-09: bind the worker handshake to its request id |
| [#39](https://github.com/lubothebook/budlum/pull/39) | `main` | `9dc088232e137d44868a0f1d158a6e3a81dc8251` | 5 | 390 | WP-16: the pool pays by three shares, 40 consensus, 50 storage, 10 repair and relay (BLG-263) |
| [#40](https://github.com/lubothebook/budlum/pull/40) | `main` | `3291d77e13f35de14761b753b6b56fd48b480bbb` | 13 | 1950 | WP-08 + WP-25: the Mobile duty lane and the storage fee |
| [#41](https://github.com/lubothebook/budlum/pull/41) | `main` | `556c4d6f08ce9c9995fe1ef98ded31aa6b1ce1d8` | 10 | 1647 | WP-61: RPC and crypto finding locks and the method coverage ratchet |
| [#42](https://github.com/lubothebook/budlum/pull/42) | `main` | `4a241cb3a9056a473a51cf37588c40e1a609e749` | 3 | 6067 | WP-42: keep the directive outside the tree and unblock the consensus-write canary |
| [#43](https://github.com/lubothebook/budlum/pull/43) | `main` | `8364a38149f45fde928f47d051180305043d334c` | 97 | 11431 | WP-45, WP-39, WP-18: privacy/AI/BPQS testnet boundary, wallet-core hardening, and B.U.D. 3.0 segmentation locks |
| [#44](https://github.com/lubothebook/budlum/pull/44) | `main` | `4b561323b0c115264fb4b8094ad485ce084518a1` | 11 | 1499 | WP-45 + WP-11: close privacy and the AI layer on testnet, rank AI reputation on integers, and give the address one shared definition |
| [#45](https://github.com/lubothebook/budlum/pull/45) | `main` | `3fdcf11d226280f531c956737e9a794319ea6cfe` | 85 | 22965 | bud3 & validators: WP-25 fees/endowment, WP-19 optical/text, WP-22 sealed/grants, WP-13 presence |
| [#46](https://github.com/lubothebook/budlum/pull/46) | `main` | `2c75d686086153aa7e4c4f95202f927c2a66c61f` | 9 | 1500 | WP-34: the EVM migration kit verification core and the bud-migrate tool |
| [#47](https://github.com/lubothebook/budlum/pull/47) | `main` | `646f09f3b63a41f682bd988eaf670a20975ba719` | 3 | 377 | WP-18: RFC 6330 acceptance, the retired carousel ceilings and the object ceiling |
| [#48](https://github.com/lubothebook/budlum/pull/48) | `main` | `c0e1fdaf046abc063e30f8ad5325c3acedae599f` | 9 | 700 | WP-15: bounded P2P payload decoding, the IPv6 eclipse bucket and the routing-table policy |
| [#49](https://github.com/lubothebook/budlum/pull/49) | `main` | `ab6c6e9a6c5b849d54b8a06d13a4dee88551fd62` | 2 | 297 | WP-45: close the privacy and on-chain AI verification surfaces on testnet |
| [#50](https://github.com/lubothebook/budlum/pull/50) | `main` | `03a4d680616f405d7543d93c034db42aa6f000b5` | 7 | 327 | WP-05: the concept-name map, the ownership table and the counter |
| [#51](https://github.com/lubothebook/budlum/pull/51) | `arena/e8f2bf7d-budlum` | `8e9aa8c530485c45ed82dc4dd69e0ab38875a4bd` | 9 | 979 | WP-43: the README definition and placeholder gates, and the contract-crate build (stacked on #24) |
| [#52](https://github.com/lubothebook/budlum/pull/52) | `main` | `059d466640569457f617914e0c23095a6e2efc38` | 9 | 920 | WP-16 + WP-41 continuation: complete the deliveries missing from #34 and #39 |
| [#53](https://github.com/lubothebook/budlum/pull/53) | `main` | `3369a86a961c5f9aa6dedfd7369ab056e2b68025` | 14 | 2342 | WP-61: RPC and crypto hardening (BLG-004 read side, BLG-010 label, TEST-GAP-07 coverage gate) |
| [#54](https://github.com/lubothebook/budlum/pull/54) | `arena/3bf4ef42-budlum` | `c330d562709be945bd32127b26a8b9ee122a5e4a` | 4 | 85 | WP-09: reject overridden worker ABI versions |
| [#55](https://github.com/lubothebook/budlum/pull/55) | `main` | `fe4a8aed7204024778cfb0c1f20ea4ea1780830d` | 16 | 3180 | WP-19: BOF-1 object path, the two paths and the video commitment |
| [#56](https://github.com/lubothebook/budlum/pull/56) | `main` | `96baad177953ee5cc471468f8cd70f90c99c0608` | 18 | 3367 | WP-10 + WP-28 + WP-47: wire contract, Ethereum gateway table, and the core/storage review |
| [#57](https://github.com/lubothebook/budlum/pull/57) | `main` | `a79abf00b7c858271cb6dea76d8a3ac32f2d0a29` | 5 | 1180 | WP-21: the aggregation volume for sub-symbol objects (T25 acceptance) |
| [#58](https://github.com/lubothebook/budlum/pull/58) | `arena/14810b46-budlum` | `c93ef989daddd028a00c4f55f0fcaef215b1bc98` | 17 | 1330 | WP-41: proof-of-work faucet and the testnet operations surface (continues PR #34) |
| [#59](https://github.com/lubothebook/budlum/pull/59) | `main` | `811e4489d8c47a029995d4335da291f30bd89028` | 19 | 2319 | WP-41 + WP-20: write the readiness and storage-health series and alert on them (continues #34, #39, #52) |
| [#60](https://github.com/lubothebook/budlum/pull/60) | `arena/792d7fb2-budlum` | `d28eb44c7fafb0e29a59b57eb69efd7358b3a5d1` | 47 | 2551 | WP-06 continuation + WP-17/WP-14/WP-44: complete persistence move and implement undone core packages |
| [#61](https://github.com/lubothebook/budlum/pull/61) | `arena/b0ebe4a4-budlum` | `3bef5f1c3a544966e2e25aee5bba41b8ab7bc191` | 11 | 1236 | WP-34, 3/3: prove direct deployment authority and price migration work |
| [#62](https://github.com/lubothebook/budlum/pull/62) | `arena/73c802bb-budlum` | `e95c76625fd2cde898428154a69e60820ed30523` | 2 | 59 | WP-17: make checked block application failure-atomic (1/N) |
| [#63](https://github.com/lubothebook/budlum/pull/63) | `main` | `9807d4226e6d6175760d6539ce636582be8beb44` | 5 | 6183 | WP-42: remove the binding directive from the tree and classify required_fee as a read |
| [#64](https://github.com/lubothebook/budlum/pull/64) | `arena/ca83ba96-budlum` | `29d663abbbc952a168208c0d8225dc8a7d87bb6a` | 2 | 95 | WP-09: do not retry uncertain worker request writes |
| [#65](https://github.com/lubothebook/budlum/pull/65) | `main` | `8fbf6d9737d88f5b66c2d6d722cc8f4c6305c531` | 6 | 1048 | WP-24, 1/3: object replacement, the second representation of one content id |
| [#66](https://github.com/lubothebook/budlum/pull/66) | `arena/28ede405-budlum` | `1f45474a170540cc40e91a8146a0ea59106bbebf` | 5 | 93 | WP-17: reject overflowing transaction costs |
| [#67](https://github.com/lubothebook/budlum/pull/67) | `main` | `80bd3be16f4f85d58f17d8303c579d9124365992` | 4 | 95 | WP-17, 2/N: spendable-balance fee gates and checked supply-path arithmetic |
| [#68](https://github.com/lubothebook/budlum/pull/68) | `main` | `cecf85a14808acaf6820678f89d4173d100b1483` | 15 | 1250 | WP-01/02/03/04/05: Initial live verification (M0) and Concept name map (Delivery 1/2) |
| [#69](https://github.com/lubothebook/budlum/pull/69) | `main` | `2a5ab783b60e8c77cda7499f6eac26c484738a0b` | 17 | 1113 | WP-07 (1/N): no_legacy_storage gate, ContentRef temporary interface, Bud3NotReady refusal |
| [#70](https://github.com/lubothebook/budlum/pull/70) | `main` | `d611e8aa6624147762da096cb68f447cf29b65d8` | 12 | 1004 | WP-13: presence protocol and suspension (absence never slashes, V-4) |
| [#71](https://github.com/lubothebook/budlum/pull/71) | `arena/8f1fe85d-budlum` | `1a77d0341a4fefdae04d6de9c14d893912661f18` | 9 | 1417 | WP-07 (2/N): remove legacy storage RPC surface |
| [#72](https://github.com/lubothebook/budlum/pull/72) | `main` | `85873f2737381d4662f1500d424b8f8e5c0b54c2` | 11 | 1768 | WP-28 (1/2): the Ethereum JSON-RPC namespace, plus the audit of where the 52 open pull requests collide |
| [#73](https://github.com/lubothebook/budlum/pull/73) | `main` | `7a7001e61907cfb5047cd63a91fc6c65df97ab47` | 55 | 1112 | WP-40, 1/N: the budlum-explorer rename, the misplaced CI step fix, and the 52-PR stack audit |
| [#74](https://github.com/lubothebook/budlum/pull/74) | `arena/f398bd1e-budlum` | `fc0926a3593fc2e7031da4ef9f32f6ea3ea5a8da` | 1 | 17 | WP-42: guard the required_fee read classification |

## Package representation in live PR titles

This table is deliberately title-based. It does not assign ownership or infer implementation completeness. In particular, #8 has no package prefix; its codec commits overlap WP-24. Body-only claims and stacked dependencies require review before ownership is assigned.

| Package | PRs whose titles name it | Merge state |
|---|---|---|
| WP-01 | #68, #12 | Not merged into the verified main baseline |
| WP-02 | #12 | Not merged into the verified main baseline |
| WP-03 | #16, #12 | Not merged into the verified main baseline |
| WP-04 | #35, #18 | Not merged into the verified main baseline |
| WP-05 | #50, #31, #24, #20 | Not merged into the verified main baseline |
| WP-06 | #60, #11 | Not merged into the verified main baseline |
| WP-07 | #71, #69 | Not merged into the verified main baseline |
| WP-08 | #40, #31 | Not merged into the verified main baseline |
| WP-09 | #64, #54, #38 | Not merged into the verified main baseline |
| WP-10 | #56 | Not merged into the verified main baseline |
| WP-11 | #44 | Not merged into the verified main baseline |
| WP-12 | #9 | Not merged into the verified main baseline |
| WP-13 | #70, #45 | Not merged into the verified main baseline |
| WP-14 | #60 | Not merged into the verified main baseline |
| WP-15 | #48 | Not merged into the verified main baseline |
| WP-16 | #52, #39, #37, #34 | Not merged into the verified main baseline |
| WP-17 | #67, #66, #62, #60 | Not merged into the verified main baseline |
| WP-18 | #47, #43 | Not merged into the verified main baseline |
| WP-19 | #55, #45 | Not merged into the verified main baseline |
| WP-20 | #59, #13 | Not merged into the verified main baseline |
| WP-21 | #57 | Not merged into the verified main baseline |
| WP-22 | #45 | Not merged into the verified main baseline |
| WP-23 | No title claim observed | Not merged into the verified main baseline |
| WP-24 | #65 | Not merged into the verified main baseline |
| WP-25 | #45, #40 | Not merged into the verified main baseline |
| WP-26 | #36, #24 | Not merged into the verified main baseline |
| WP-27 | #24 | Not merged into the verified main baseline |
| WP-28 | #72, #56, #24 | Not merged into the verified main baseline |
| WP-29 | #24 | Not merged into the verified main baseline |
| WP-30 | #24 | Not merged into the verified main baseline |
| WP-31 | No title claim observed | Not merged into the verified main baseline |
| WP-32 | No title claim observed | Not merged into the verified main baseline |
| WP-33 | #24 | Not merged into the verified main baseline |
| WP-34 | #61, #46 | Not merged into the verified main baseline |
| WP-35 | No title claim observed | Not merged into the verified main baseline |
| WP-36 | No title claim observed | Not merged into the verified main baseline |
| WP-37 | No title claim observed | Not merged into the verified main baseline |
| WP-38 | No title claim observed | Not merged into the verified main baseline |
| WP-39 | #43 | Not merged into the verified main baseline |
| WP-40 | #73 | Not merged into the verified main baseline |
| WP-41 | #59, #58, #52, #34 | Not merged into the verified main baseline |
| WP-42 | #74, #63, #42, #31, #30, #29, #24 | Not merged into the verified main baseline |
| WP-43 | #51 | Not merged into the verified main baseline |
| WP-44 | #60, #14 | Not merged into the verified main baseline |
| WP-45 | #49, #44, #43 | Not merged into the verified main baseline |
| WP-46 | No title claim observed | Not merged into the verified main baseline |
| WP-47 | #56 | Not merged into the verified main baseline |
| WP-48 | No title claim observed | Not merged into the verified main baseline |
| WP-49 | No title claim observed | Not merged into the verified main baseline |
| WP-50 | No title claim observed | Not merged into the verified main baseline |
| WP-51 | No title claim observed | Not merged into the verified main baseline |
| WP-52 | No title claim observed | Not merged into the verified main baseline |
| WP-53 | No title claim observed | Not merged into the verified main baseline |
| WP-54 | No title claim observed | Not merged into the verified main baseline |
| WP-55 | No title claim observed | Not merged into the verified main baseline |
| WP-56 | No title claim observed | Not merged into the verified main baseline |
| WP-57 | No title claim observed | Not merged into the verified main baseline |
| WP-58 | No title claim observed | Not merged into the verified main baseline |
| WP-59 | No title claim observed | Not merged into the verified main baseline |
| WP-60 | No title claim observed | Not merged into the verified main baseline |
| WP-61 | #53, #41, #34 | Not merged into the verified main baseline |
| WP-62 | No title claim observed | Not merged into the verified main baseline |
| WP-63 | No title claim observed | Not merged into the verified main baseline |
| WP-64 | No title claim observed | Not merged into the verified main baseline |

## Most contested paths

| Path | Deliveries |
|---|---|
| `docs/work/PACKAGES.md` | #13, #14, #16, #20, #29, #30, #31, #35, #36, #41, #47, #48, #50, #51, #56, #57, #59, #63, #65, #68, #72, #73 |
| `xtask/gates/src/main.rs` | #8, #13, #24, #29, #30, #31, #36, #40, #45, #51, #56, #60, #69, #73 |
| `src/tests/mod.rs` | #8, #11, #12, #16, #18, #35, #52, #55, #56, #59, #60, #65 |
| `.github/workflows/ci.yml` | #8, #24, #29, #30, #31, #40, #44, #51, #56, #60, #73 |
| `src/chain/blockchain.rs` | #8, #9, #11, #31, #40, #59, #60, #62, #66, #67, #70 |
| `src/execution/executor.rs` | #8, #24, #39, #43, #44, #49, #60, #62, #66, #67, #70 |
| `THE_BUDLUM_DIREKTIF.md` | #8, #11, #14, #24, #34, #36, #42, #43, #45, #63 |
| `.github/concept-names-baseline.txt` | #8, #11, #31, #43, #45, #50, #60, #68, #73 |
| `docs/audit/FINDINGS.md` | #13, #31, #35, #36, #41, #44, #48, #50, #68 |
| `src/core/account.rs` | #8, #11, #24, #36, #39, #60, #66, #67, #70 |
| `config/naming/concept_map.toml` | #8, #20, #24, #31, #43, #50, #60, #68 |
| `src/crypto/domain_tags.rs` | #8, #9, #24, #36, #45, #52, #55, #70 |
| `src/rpc/server.rs` | #8, #11, #34, #41, #53, #71, #72, #73 |
| `src/storage/bud3/mod.rs` | #8, #40, #45, #55, #56, #57, #65, #69 |
| `.github/idle-code-baseline.txt` | #8, #11, #45, #48, #73 |
| `README.md` | #35, #46, #51, #69, #73 |
| `arena_claude.py` | #24, #34, #43, #45, #60 |
| `docs/NAMING.md` | #20, #24, #31, #50, #68 |
| `src/core/transaction.rs` | #8, #45, #60, #66, #70 |
| `src/network/node.rs` | #8, #9, #11, #48, #53 |
| `src/rpc/method_class.rs` | #8, #41, #53, #71, #72 |
| `src/rpc/mod.rs` | #24, #36, #53, #56, #72 |
| `src/storage/bud3/registry.rs` | #8, #45, #55, #59, #65 |
| `xtask/gates/src/gates/concept_names.rs` | #20, #24, #31, #50, #68 |
| `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs` | #24, #42, #60, #63, #74 |
| `xtask/gates/src/gates/tree_is_english.rs` | #24, #43, #50, #60, #73 |
| `xtask/gates/tests/repository_locks.rs` | #8, #42, #60, #63, #73 |
| `.github/workflows/fuzz-nightly.yml` | #29, #30, #55, #61 |
| `README.tr.md` | #35, #46, #69, #73 |
| `crates/uel-abi/src/transport.rs` | #36, #38, #54, #64 |

## Divergent additions requiring semantic reconciliation

The following new paths have multiple distinct blob IDs. A textual merge alone cannot establish that their APIs, wire formats or state transitions agree.

| Path | Deliveries |
|---|---|
| `docs/work/PACKAGES.md` | #13, #14, #16, #20, #29, #30, #31, #35, #36, #41, #47, #48, #50, #51, #56, #57, #59, #63, #65, #68, #72, #73 |
| `docs/audit/FINDINGS.md` | #13, #31, #35, #36, #41, #44, #48, #50, #68 |
| `src/rpc/compat/mod.rs` | #24, #36, #56, #72 |
| `xtask/gates/src/gates/no_float_in_consensus_paths.rs` | #24, #29, #30, #31 |
| `xtask/gates/src/gates/workflows_cover_every_workspace.rs` | #24, #29, #30, #31 |
| `docs/audit/live/lane-c.md` | #12, #16, #68 |
| `docs/audit/live/lane-d.md` | #18, #35, #68 |
| `src/rpc/compat/ethereum/mod.rs` | #24, #56, #72 |
| `src/storage/bud3/content_ref.rs` | #8, #45, #69 |
| `src/storage/bud3/volume.rs` | #45, #55, #57 |
| `src/tests/audit_lane_c.rs` | #12, #16, #68 |
| `src/tests/audit_lane_d.rs` | #18, #35, #68 |
| `.github/rpc-method-coverage-baseline.txt` | #41, #53 |
| `budzero/bud-proof/tests/audit_lane_c.rs` | #12, #16 |
| `contracts/uel/BudlumUniversal.sol` | #24, #36 |
| `docs/EXECUTION.md` | #24, #36 |
| `docs/EXECUTION_LIMITS.md` | #36, #45 |
| `docs/STORAGE.md` | #47, #69 |
| `docs/audit/LIVE_STATUS.md` | #35, #68 |
| `docs/audit/live/engine-inventory.md` | #12, #16 |
| `docs/audit/live/lane-a.md` | #12, #68 |
| `docs/audit/live/lane-b.md` | #12, #68 |
| `execution/budzero/Cargo.toml` | #24, #36 |
| `execution/budzero/src/main.rs` | #24, #36 |
| `execution/evm/Cargo.toml` | #24, #36 |
| `execution/evm/src/main.rs` | #24, #36 |
| `src/chain/state_recovery/mod.rs` | #8, #11 |
| `src/execution/budzero_ee/mod.rs` | #24, #36 |
| `src/execution/coordinator/foreign/ethereum.rs` | #24, #36 |
| `src/execution/coordinator/foreign/mod.rs` | #24, #36 |
| `src/execution/coordinator/gas.rs` | #24, #36 |
| `src/execution/coordinator/overlay.rs` | #24, #36 |
| `src/mempool/duty_lane.rs` | #31, #40 |
| `src/mempool/lanes.rs` | #24, #36 |
| `src/persistence/mod.rs` | #8, #11 |
| `src/storage/bud3/access_tiering.rs` | #8, #45 |
| `src/storage/bud3/fees.rs` | #40, #45 |
| `src/storage/bud3/replace.rs` | #8, #45 |
| `src/tests/alert_rules_reference_existing_metrics.rs` | #52, #59 |
| `src/tests/audit_lane_a.rs` | #12, #68 |
| `src/tests/audit_lane_b.rs` | #12, #68 |
| `xtask/gates/src/gates/bud3_custody_proofs.rs` | #13, #45 |
| `xtask/gates/src/gates/bud3_custody_rewards.rs` | #40, #45 |
| `xtask/gates/src/gates/bud3_fee_uses_physical_bytes.rs` | #40, #45 |
| `xtask/gates/src/gates/bud3_placement.rs` | #13, #45 |

## Decisions for the continuation

1. Preserve every open PR. No PR was closed, merged, retargeted or pushed to its head branch.
2. Continue the small WP-09 transport stack #38 -> #54 -> #64 in this session PR. Its fixes address request identity, duplicate protobuf version fields and unsafe writes retried after an ambiguous failure. Review the resulting transport for remaining deadline, response-correlation and host-callback defects before claiming completion.
3. WP-09 formally depends on WP-03, which is not merged. Its crate paths are also held by open deliveries. This continuation is explicitly requested integration work, not a directive-ready claim or a new independent ownership claim.
4. The session branch is fixed by the execution environment. The directive's `wp/NN-*` branch convention and direct pushes to other PR heads cannot be followed here. Preserve source commits and report this constraint rather than create an untracked branch.
5. Do not claim a finding closed, a package complete, a measurement obtained or CI green without its required evidence. Rust compilation remains unverified locally.
6. Do not manufacture the 64 GitHub issue records: this repository has issues disabled according to the live-stack audit. Keep GitHub package registration blocked until the owner enables that surface; do not substitute invented issue IDs.
7. Keep the binding directive available to the agent but remove it from the proposed Git tree, as section 0.1 item 5 explicitly requires. This is the specific exception to including every workspace file in the PR. The original blob remains in Git history and the local source copy is preserved outside tracking.
8. Reconcile the competing ledgers and execution implementations before combining large stacks. Do not resolve a divergent addition by arbitrarily keeping both modules or the last writer.

## Evidence boundary

The snapshot was obtained through authenticated GitHub REST calls after GraphQL returned HTTP 504. Every open PR file list was paginated. No CI polling was performed for this audit. A later check is warranted only when a failure is observed, as requested. Existing audit documents and PR prose were read as leads; the table above uses live API metadata.

## Live refresh after the transport deliveries

The initial 54-PR tables above are a historical snapshot, not a claim about the
queue after other agents continued working. A subsequent authenticated REST
read found **62 open PRs**. The additions were:

| PR | Head observed | Delivery |
|---|---|---|
| #75 | `1a77d0341a4fefdae04d6de9c14d893912661f18` | WP-07 legacy-storage removal across integrated stacks |
| #76 | `f6b371b4ffa56ba778e2f5686f16a365a271e89c` | WP-28 connection-owned Ethereum filters |
| #77 | `4ff2cc2a331fcda0d8df39a0b444ed64f0d446b1` | This audit and the WP-09 transport continuation |
| #78 | `8cb10107585e68043c92d4d0b05fe1a23302439d` | Directive source removal; its WP-27 envelope was moved to #24 |
| #79 | `130aacd8a2ed95f4e163c23842b38c6793dc7476` | WP-35 execution limits and conformance catalog |
| #80 | `7f2e3667f93a5b98d0525a6bfb4573fb60f849de` | A parallel checkpoint of the same #38/#54/#64 ABI stack |
| #81 | `e8f7365bf48ba06d9e35cb47bd09fe6f2a7a7b19` | WP-12 committee work re-rooted on main |
| #82 | `5685e03d87c257e7e1ecc6fd3355eee5cebdbf94` | WP-11 mobile-core duty engine |

The path-collision counts in the initial tables were not recomputed in this
refresh. They must not be quoted as the current 62-PR counts.

### WP-09 continuation checkpoint

- Source commits carried with authorship: #38, #54 and #64.
- `980a887`: deadline/poisoning regressions and actual ABI CI commands; also
  repairs the misplaced explorer format step without importing #73's rename.
- `12615f6`: one absolute client transport budget, checked clock addition and
  connection poisoning after an unusable final response.
- `749cdbe`: worker host-callback regression locks, including a valid-refusal
  control so ordinary deterministic refusals remain usable.
- `4ff2cc2`: bounded worker host I/O and operation-aware host reply validation;
  a broken proxy cannot supply a deterministic execution receipt.
- #80 was notified of this overlap. It remains open and unchanged. Its observed
  head contains the same three source corrections, not the additional fixes
  above. Reconciliation must preserve the union of tests and corrections.
- No Rust test execution or green CI is claimed. The findings ledger keeps the
  new records open until the required red-to-green evidence exists.

### Worker boundary follow-up

A later live read found 63 open PRs; #83 adds the WP-31 Solana RPC namespace.
The transport continuation then added:

- `c6f5260`: regressions for a started-but-incomplete worker frame and a panic
  inside deploy validation.
- `8a8688f`: idle waiting remains allowed, but the first received byte arms a
  two-second frame/response budget; deploy validation now runs inside the
  panic boundary and closes the connection on a caught panic.
- `31a530e`: corrects the partial-frame test seed. A zero leading length byte
  would form a complete empty frame after four bytes and miss the intended bug.

The normalized diff at `31a530e` is 991 changed lines excluding documentation,
the removed source directive and lockfiles. The delivery remains below the
1,500-line cap. No CI failure had been observed at the last failure-filtered
read; that is not a green result and no completion claim is made.
