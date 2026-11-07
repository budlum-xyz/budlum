# Lane B live verification ledger (WP-02)

Directive section 14 assigns the unified findings ledger to live verification
in four lanes (WP-01..WP-04). This file is the lane B record: every ledger
entry whose closing package is WP-06, WP-07, WP-10, WP-18, WP-19, WP-20,
WP-21, WP-22, WP-24, WP-25 or WP-45, re-verified against the live tree.
English per `tree_is_english`. The file-level companion is
`legacy-storage-inventory.md` in this directory.

## How this was produced

- **Verification base.** Repository snapshot `HEAD` = `cccf1da` (`main`,
  2026-11-05). Line references are content anchors, not line numbers.
- **Method.** Same as lane A: section 14 records extracted programmatically,
  identifier scan across the tree, anchor reading for headline findings
  (privacy allowlist, genesis/edition gates, STARK ZK posture, MIT-vs-Shield
  license split, view grants, the whole WP-07 removal surface).
- **CI.** No local Rust toolchain exists in this environment; no red CI run
  was observed while working.
- **What this PR does not claim.** WP-02 does not fix findings. No lane B
  record is Closed in this snapshot: the WP-07 removal is in flight (PR #8,
  `arena/b7784c85-budlum`) and none of its deletions have merged. The 75 Open
  rows name their closing package and carry live anchors. Repro tests for the
  Verified rows are owed on `audit/repro-b` and move into the closing
  packages' PRs (S-3).

## Status legend (directive 14.1)

| Status | Meaning |
|---|---|
| Open | Open in the live tree. Evidence below; repro pending on `audit/repro-b`. |
| Verified | Open and reproduced by file inspection at the cited anchors. |
| Closed (already fixed) | None this pass. |
| Closed by removal | None this pass: the WP-07 removal is unmerged, so removal-closing rows stay Open until `no_legacy_storage` is green (the gate does not exist yet). |

## Summary

| Metric | Count |
|---|---|
| Lane B records | 83 |
| Closed | 0 |
| Verified | 8 |
| Open | 75 |

Closing-package distribution (a record may carry shared feet): WP-07 (removal
foot of ~28 records), WP-19 (9), WP-21 (3), WP-22 (6), WP-24 (3+shared),
WP-25 (1), WP-45 (~40), WP-56/WP-57 (shared testnet-closure feet),
WP-33 (shared foot of BLG-148), WP-08 (shared foot of BLG-253).

## In-flight work this ledger interacts with

- **PR #8** (`arena/b7784c85-budlum`): carries WP-06 (the persistence move),
  WP-07 (the bud tree shrink and storage removal) and WP-24 (codec register,
  merged earlier in PR #6 in skeletal form; the full wiring lands there). The
  inventory file flips row by row when it merges. Rows marked "Closes by
  removal (WP-07, in-flight PR #8)" will flip to Closed by removal in the
  closing protocol, with the `no_legacy_storage` green output as evidence.
- **WP-19/WP-21/WP-22** (blocked on WP-10 ← WP-07): rebuild the 3.0 object
  path; rows BLG-210/211/213/214/215/216/218/220/221 flip there.
- **WP-45** (blocked on WP-22): privacy/AI boundary closure; the WP-45 rows
  flip there, including BLG-063 (testnet allowlist off).
- **WP-24** (blocked on WP-10): codec register; BLG-219/222/133/135 flip there.
- **WP-44** (lane A, WP-44): BLG-205's WP-44 foot is tracked in lane A.

## The ledger

| ID | Severity | Closing | Finding (English) | Live status | Evidence / note |
|---|---|---|---|---|---|
| BLG-025 | Low | WP-45 | QuantumAccount::validate_all / registry::register accept duplicate guardian keys and an inconsistent guardian_root | Open | `guardian_root` 4 files (`src/account_abstraction/quantum_account.rs`). Closes with WP-45. |
| BLG-035 | Medium | WP-07 | bud-node BitswapCodec silent frame truncation and MemoryContentStore byte-bound/eviction defects | Open | `budzero/bud-node/` present, `MemoryContentStore` 4 files (`budzero/bud-node/src/bitswap.rs`). Closes by removal (WP-07, in-flight PR #8). |
| BLG-045 | Critical | WP-07 | StorageRegistry::open_challenge grants a permanent 1-atom query immunity and unchecked challenge proofs | Open | `src/storage/provider.rs` present (challenge arm). Closes by removal (WP-07, in-flight PR #8). |
| BLG-046 | Critical | WP-07 | open_deal source/dictionary validation bypass; prune_content locks bonds/escrow forever | Open | `open_deal` 24 files, `prune_content` 5 files (`src/chain/blockchain.rs`). Closes by removal (WP-07, in-flight PR #8). |
| BLG-047 | High | WP-07 | StorageRegistry::root() commitment missing/unframed; cooldown, shard cap, replica uniqueness and refresh-fee rules unimplemented | Open | `src/domain/storage_deal.rs` present. Closes by removal (WP-07, in-flight PR #8). |
| BLG-048 | High | WP-19 | storage::render RGB/grayscale geometry broken; f64::sqrt() in the commitment path; VideoRecipe re-encode incompatible | Open | `src/storage/render.rs` and `src/storage/emit.rs` (VideoRecipe 7 files) present. Closes with WP-19; photos-video foot partly removed by WP-07. |
| BLG-049 | Medium | WP-22 | reconstruct_object multi-corrupt-shard failure; ViewGrant epoch-0 commitment clash; OneShare quota bypass; fixed_sqrt fraction loss | Open | `ViewGrant` 17 files, `OneShare` 3 files (`src/storage/mod.rs`), `fixed_sqrt` 4 files (`src/storage/fixed_point.rs`). Closes with WP-22; removal foot with WP-07. |
| BLG-059 | Critical | WP-45 | AiExecutionProof STARK misses input/output/weights binding; host/guest arithmetic divergence; mismatched commitment schemes | Open | `AiExecutionProof` 18 files (`src/ai/execution/guest.rs`). Closes with WP-45. |
| BLG-060 | Critical | WP-45 | Deferred AiAttachExecutionProof finalization permanently loses the fee; AiFeeReclaim mutates state before the authority check | Open | `AiAttachExecutionProof` 10 files, `AiFeeReclaim` 8 files. Closes with WP-45. |
| BLG-061 | High | WP-45 | Ghost verifier_stakes after unbond/withdraw; per-capita EffortTier ceiling bypass; AiAgentPayment verification gaps | Open | `AiOperatorUnbond` 5 files (`src/chain/blockchain.rs`), `EffortTier` 16 files. Closes with WP-45. |
| BLG-062 | High | WP-45 | AiRegistry::state_root and leaf digests omit execution_dims/modalities/weights_digest/public_inputs; missing length prefixes | Open | `AiRegistry::state_root` 1 file, `execution_dims` 22 files, `modalities` 20 files, `weights_digest` 24 files. Closes with WP-45. |
| BLG-063 | Critical | WP-45 | Unbacked/unauthorised L1 private note mint-spend on testnet 45261; mismatched derive_nullifier; ProofClaimRegistry excluded from state root | Verified | `privacy_transfers_enabled` is an allowlist containing testnet: `src/execution/executor.rs:66-80` documents it ("survives only where the notes are worth nothing") and the in-tree test asserts `privacy_transfers_enabled(testnet)` (`executor.rs:4103`). `ProofClaimRegistry` 8 files. The ledger already records this as verified-open. Closes with WP-45. |
| BLG-070 | High | WP-45 | ai-knowledge redact() misses JSON keys and multi-field lines; plaintext secrets in LlmCache/TaskMemory | Open | `redact` 22 files, `ai-knowledge` 5 files, `LlmCache`/`TaskMemory` 1 file each. Closes with WP-45. |
| BLG-071 | High | WP-45 | ai-core/ai-data/ai-serve: non-cryptographic LoRaManifest::digest, incompatible content_id_of, UTF-8 panic surface | Open | `LoRaManifest::digest` absent under that name; ai-core/ai-data/ai-serve present (`crates/ai-inference/`). Closes with WP-45. |
| BLG-072 | Medium | WP-45 | ai-knowledge::embed breaks Turkish characters; NaN/negative float holes in PromptWallet/EvalGate; zero-byte ResidencyPlan | Open | `PromptWallet` 1 file, `EvalGate` 2 files, `ResidencyPlan` 6 files. Closes with WP-45. |
| BLG-073 | Critical | WP-07 | .bud v1 pq_public_key serialization loss; HuffmanCoder 32-bit code-length overflow; BudV2File multi-part zip-bomb OOM; triple content_id mismatch | Open | `bud/` tree present; `HuffmanCoder` 5 files (`bud/fuzz/fuzz_bud_format.rs`). Closes by removal (WP-07, in-flight PR #8). |
| BLG-074 | High | WP-07 | bud consensus/DAS/erasure defects: single-leaf second-preimage forgery, CauchyMds/LT/LRC index errors, unrecoverable layouts | Open | `bud/` present; `CauchyMds` 4 files, `BudErasure` 2 files. Closes by removal (WP-07, in-flight PR #8). |
| BLG-075 | High | WP-07 | Lossless transform defects: columnar non-stable-sort panic, office DEFLATE refusal + double-body inflation, pcap timestamp corruption, markdown | Open | Transforms referenced from `crates/bud-codec/src/registry.rs` (18 files mention columnar); bugs live in `bud/src/bud_format_*.rs`. Closes by removal (WP-07); codec register foot with WP-24. |
| BLG-076 | Medium | WP-07 | bud economics/fidelity-gate defects: holds_honest and classify_lossy fail open, negative residual_price, value gates | Open | `holds_honest` 2 files, `classify_lossy` 1 file, `residual_price` 2 files (`bud/src/`). Closes by removal (WP-07, in-flight PR #8). |
| BLG-077 | Critical | WP-07 | bud quantum_chain / bud_format_shamir: pq_pub_hash binding skipped, DualWallet address derived from the operator seed | Open | `bud/src/` present; the literals are absent under those exact names (renamed during the consolidation). Closes by removal (WP-07). |
| BLG-078 | High | WP-07 | BudCli::decode_container corrupts decompressed parts; videopipe inverted-argument proof; TimeSeriesColumnar overflow/OOM | Open | `BudCli::decode_container` 1 file, `videopipe` 2 files, `TimeSeriesColumnar` 2 files (`bud/src/`). Closes by removal (WP-07). |
| BLG-079 | High | WP-07 | bud privacy/masking defects: SecretRedactor symbol-split password leak + blind gate, plaintext secure-dedup | Open | `SecretRedactor` 2 files, `securededup` 1 file (`bud/src/`). Closes by removal (WP-07). |
| BLG-080 | Medium | WP-07 | bud indexing/QR/cost defects: pgm::search_range offset miss, unit error (1024x), Codec::None 8.5x inflation | Open | `1024x` 1 file, `8.5x` 1 file (`bud/src/`); `Codec::None` 3 files. Closes by removal (WP-07). |
| BLG-093 | High | WP-45 | crates/ai-inference/LICENSE.md carries an unrestricted MIT license contradicting the root PolyForm-Shield-1.0.0 declaration | Verified | Reproduced: `crates/ai-inference/LICENSE.md` is the MIT License (21 lines) while root `LICENSE.md` is PolyForm Shield 1.0.0 and `crates/ai-inference/Cargo.toml:33` declares `license = "LicenseRef-PolyForm-Shield-1.0.0"`. Closes with WP-45. |
| BLG-106 | Critical | WP-45 | Unbounded AiModelSpec.execution_dims layer width single-tx 532 GiB SIGABRT validator DoS; AiAttachExecutionProof ordering | Open | `execution_dims` 22 files, `AiAttachExecutionProof` 10 files. Closes with WP-45. |
| BLG-111 | High | WP-45 | budlum-bpqs debug/release verification divergence; stateless Q_MAX = 1 single-use WOTS keys | Open | `budlum-bpqs` 4 files, `verify_at_height` 5 files, `Q_MAX = 1` 2 files (`crates/bpqs/`). Closes with WP-45. |
| BLG-112 | Critical | WP-45 | Deterministic AiModelId seizure; unbound on-chain declare_effort_ceiling lets every request exceed BASELINE | Open | `AiModelId` 22 files, `declare_effort_ceiling` 3 files, `BASELINE` 16 files (`src/ai/registry.rs`). Closes with WP-45. |
| BLG-122 | High | WP-07 | bud BFT ratio vote misses content_id/chain_id binding, accepts NaN certificates, keyless RatioConsensus::from_blob forgery | Open | `chain_id` 185 files, `RatioConsensus::from_blob` 1 file (`bud/src/bud_format_ratioconsensus.rs`). Closes by removal (WP-07). |
| BLG-123 | Medium | WP-07 | store_json_columnar restore corruption; ModelFloatSplit little-endian BF16/FP32 sign/exponent flip; PdfStreamSplit | Open | `store_json_columnar` 3 files, `ModelFloatSplit` 2 files, `PdfStreamSplit` 3 files (`bud/src/`). Closes by removal (WP-07). |
| BLG-124 | High | WP-45 | ai-inference authless WebSocket -> Authenticated promotion; symbol corruption; u32::MAX overflow panic; CompactContext leaks plaintext | Open | `Authenticated` 3 files, `u32::MAX` 52 files; `CompactContext::render` absent under that name. Closes with WP-45. |
| BLG-126 | Critical | WP-45 | AiInferenceRequest two-way Pollen AccessGrant payment-wall bypass (empty input_ref, decoy content_id); dead conditions | Open | `AiInferenceRequest` 30 files, `AccessGrant` 25 files; `input_ref = b""` absent under that literal. Closes with WP-45. |
| BLG-133 | Medium | WP-24 | DictionaryRegistry / DerivedSpec / MasterRegistry custody and the TransformedPayload classifier keep pre-3.0 pricing and tiers | Open | `DictionaryRegistry` 5 files, `DerivedSpec` 5 files (`src/storage/derived.rs`), `MasterRegistry` 4 files. Closes with WP-24; removal foot with WP-07. |
| BLG-135 | High | WP-24 | living_threshold/storage_deal half-life damping freeze; unimplemented ConstitutionRegistry bounds | Open | `living_threshold.rs` 3 files, `storage_deal.rs` 18 files, `ConstitutionRegistry` 3 files. Closes with WP-24; removal foot with WP-07. |
| BLG-137 | High | WP-19 | QR/video pipe (qr_*/three_nft): 32-bit stream auth and container flexibility; ContentDiscovery DHT provider parse | Open | `ContentDiscovery` 6 files (`src/gateway/service.rs`); qr_* literals absent under those exact spellings. Closes with WP-19; removal foot with WP-07. |
| BLG-141 | Medium | WP-07 | bud low-rank encoder (bud_format_lowrank): missing deflation, repeated singular vectors / NaN / overflow panics | Open | `deflation` 1 file (its code anchor `bud_format_lowrank.rs` is present), `bud/src/` tree intact. Closes by removal (WP-07). |
| BLG-144 | High | WP-19 | SingleScreenView cumulative device quota overrun and missing contract_digest (one_view.rs); block_len / k = 0 accepted | Open | `SingleScreenView` 3 files, `contract_digest` 1 file (`src/storage/one_view.rs` present). Closes with WP-19; removal foot with WP-07. |
| BLG-145 | Medium | WP-45 | bud CropDerivation forged aligned = true on ragged crops; join_optical cross-stream part merge; optx_digest | Open | `CropDerivation` 2 files, `join_optical` 1 file, `optx_digest` 1 file (`bud/src/`). Closes with WP-45; removal foot with WP-07. |
| BLG-148 | High | WP-33, WP-07 | StorageLifecycleState turns a single missed challenge into terminal Missed; ActiveReplacement edge cases | Open | `StorageLifecycleState` 4 files (`src/domain/storage_deal.rs` present), `ActiveReplacement` 6 files. WP-07 foot (storage_deal removal, in-flight PR #8); the budzero/verifier-registry foot closes with WP-33. |
| BLG-149 | Medium | WP-45 | PowChallenge salt-hash ownership bypass; BloomDedupIndex full-set RAM residency; misleading savings math | Open | `PowChallenge` 4 files, `BloomDedupIndex` 1 file (`bud/src/`). Closes with WP-45; removal foot with WP-07. |
| BLG-152 | Medium | WP-07 | FidelityCore::render thumbnail path returns full-size raw bytes and 0x0 geometry (fidelity.rs) | Open | `Thumbnail` 2 files (`bud/src/fidelity.rs` present). Closes by removal (WP-07). |
| BLG-153 | Medium | WP-07 | OpticalGates::k_bud_optical self-compare tautology; LogTemplateMiner substring corruption; LogTemplateMiner::mine | Open | `OpticalGates::k_bud_optical` 1 file, `LogTemplateMiner::mine` 1 file (`bud/src/bud_format_optical.rs` present). Closes by removal (WP-07). |
| BLG-156 | Medium | WP-07 | QuantumSuite::is_quantum_resistant substring bypass and kem: None accepted; bud_format_wire version 0 | Open | `kem: None` 1 file (`bud/src/quantum.rs` present). Closes by removal (WP-07). |
| BLG-157 | Medium | WP-45 | dbd_digest page-boundary collision (bud_format_dbdelta); BashTranspile determinism/JSON escaping errors | Open | `dbd_digest` 1 file, `BashTranspile` 2 files (`bud/src/`). Closes with WP-45; removal foot with WP-07. |
| BLG-160 | Medium | WP-45 | L1 AiDatasetStorageDeal closed-circuit verification gap; ai-core zero-target/zero-epoch permissions; ai-data empty enrolment | Open | `AiDatasetStorageDeal` 1 file (`src/ai_inference/storage.rs` present). Closes with WP-45. |
| BLG-161 | Medium | WP-21 | .bud bit-rot scanner reports 100% false corruptions (field-tag mismatch); QoS quota-overflow priority defect; NaN | Open | `bud/src/` present; `bud_format_scrub` 1 file. Closes with WP-21; removal foot with WP-07. |
| BLG-163 | High | WP-19 | B.U.D. 3.0 optical QR layer (qr_matrix/qr_png/qr_encode): u32 multiply overflow panic; blank white PNG accepted; mask errors | Open | `qr_matrix` 5 files, `qr_png` 5 files, `qr_encode` 4 files (`src/storage/emit.rs`); the qr_* files themselves are present. Closes with WP-19. |
| BLG-164 | High | WP-45 | budlum-bpqs epoch_of u32 truncation: signature reuse after 2^32; ParamsTestFast and dev-only params shipped | Open | `epoch_of` 9 files, `ParamsTestFast` 7 files (`crates/bpqs/`). Closes with WP-45. |
| BLG-165 | Medium | WP-45 | Offline AI localization (ai_inference::i18n): broken BCP-47 / schema-URI / bidi accepted; budscan CLI swallows extra args | Open | `budscan` 30 files (`src/rpc/server.rs`); `ai_inference::i18n` absent under that name. Closes with WP-45. |
| BLG-166 | Critical | WP-45 | AiRegistry MIN_VERIFIER_STAKE rotation Sybil capture; slashed/0-bond Byzantine validators still collect consensus rewards | Open | `AiRegistry` 19 files, `MIN_VERIFIER_STAKE` 8 files (`src/ai/mod.rs`). Closes with WP-45. |
| BLG-168 | Medium | WP-21 | refuse_durable_derivative wrapper bypass (PackedPayload); RevealSession::open accepts fake stream_id / conflicting opens | Open | `refuse_durable_derivative` 3 files, `PackedPayload` 2 files (`src/storage/mod.rs`). Closes with WP-21; removal foot with WP-07. |
| BLG-173 | Medium | WP-45 | dudect_poseidon2 constant-time run disconnected from real budlum_bpqs code (--measurements 0 panic); nondeterministic reputation | Open | `dudect_poseidon2` 4 files (`crates/bpqs/Cargo.toml`), `reputation` 19 files (`src/ai/mod.rs`). Closes with WP-45. |
| BLG-185 | Medium | WP-45 | bpqs wire-size cost model mismatch; loom lock-order canary gap; multi-line / comment blindness in lexical regression locks | Open | `bpqs` 28 files, `loom` 15 files. Closes with WP-45; removal foot with WP-07. |
| BLG-201 | High | WP-45 | Post-proof size gate: 40 MiB zero-weight allocation accepted; Budlumxyz/Marketplace mutates before the balance check | Open | `AiAttachExecutionProof` 10 files, `Budlumxyz` 15 files, `Marketplace` 14 files. Closes with WP-45; removal foot with WP-07. |
| BLG-208 | BUD3 H1 | WP-07, WP-21 | BudStorageEdition::Three accepts only recipes; admits_body() is false for Three, so original content cannot enter 3.0 | Verified | Reproduced: `pub const fn admits_body(self) -> bool { matches!(self, Self::Classic) }` (`src/storage/generated.rs:120-122`). Closes by removal (WP-07, in-flight PR #8); 3.0 rebuild with WP-21. |
| BLG-209 | BUD3 H2 | WP-07, WP-25 | Three-held bytes and rent return 0; the document claims a recipe holds nothing | Open | `src/storage/three_regime.rs` present. Closes by removal (WP-07); economics rebuilt with WP-25. |
| BLG-210 | BUD3 H3 | WP-19 | VideoRecipe stores content_bytes; reemit(body)/frame_stream(body) demand an external body - the \"fixed-size recipe\" claim is false | Verified | Reproduced: `pub content_bytes: Vec<u8>` (`src/storage/three_recipe.rs:163`); `pub fn reemit(&self, body: &[u8])` (`:266`) and `frame_stream(body)` (`:297`). Closes with WP-19. |
| BLG-211 | BUD3 H4 | WP-19 | Three separate recipe models (qr_recipe.rs, three_recipe.rs, three_nft.rs); claim a body is produced without holding it | Open | All three files present. Closes with WP-19. |
| BLG-212 | BUD3 H5 | WP-21, WP-23 | bud_storageQrFeed* preview endpoints demand the content on every call (data_hex); viewing opens from the caller's package; NFT registry is a memory BTreeMap | Open | `src/rpc/server.rs` present; the `bud_storageQrFeed*` names appear in docs (2-3 files) and are dispatched via the storage gateway; `three_nft.rs` holds the in-memory `BTreeMap`. Closes with WP-21 and WP-23. |
| BLG-213 | BUD3 H6 | WP-18 | Caps: preview 1 MiB, package 64 MiB, k ≤ 4096, video 50k frames; u32 lengths silently truncate above 4 GiB | Open | `emit.rs` present; caps live in `src/storage/bud3/limits.rs` (v3) and the legacy pipe (`src/storage/emit.rs`); `qr_payload.rs` present. Closes with WP-18. |
| BLG-214 | BUD3 H7 | WP-19 | Video identity is the digest of the PNG blob; deflate output is not stable across versions | Open | `src/storage/qr_video.rs`, `src/storage/qr_png.rs` present. Closes with WP-19. |
| BLG-215 | BUD3 H8 | WP-19 | No video→object path; no two-way doors or return path | Open | 3.0 path audit: no video ingestion route exists in `src/storage/bud3/`. Closes with WP-19. |
| BLG-216 | BUD3 H9 | WP-18 | Low-degree random XOR repair hides losses in large segments | Open | `src/storage/qr_carousel.rs` present. Closes with WP-18. |
| BLG-217 | BUD3 H10 | WP-07 | A second 3.0 implementation exists in bud/src ("no storage concept", "STORAGE-ZERO" claims) | Open | `bud/src/` present (112-file tree). Closes by removal (WP-07, in-flight PR #8). |
| BLG-218 | BUD3 H11 | WP-19 | three_pipe test claims a fixed-size recipe | Open | `src/storage/three_pipe.rs` present. Closes with WP-19. |
| BLG-219 | BUD3 H12 | WP-24 | A0 applies shrink-only zlib and nothing else | Verified | Reproduced: `src/storage/transformed.rs` header states "shrink-only zlib → pin sha256" and "Entropy-coded types do not try zlib"; no codec selection exists. Closes with WP-24. |
| BLG-220 | BUD3 H13 | WP-20 | B.U.D. 3.0 object carries NO redundancy; a single copy is lost on the first disk failure; 2.0 scheme (10,16) is 1.6x capped at 256 shards | Open | `src/storage/erasure.rs` and the (10,16) references present (8 files mention erasure). Critical: 3.0 rebuild lands with WP-20 (RFC 6330 fountain). |
| BLG-221 | BUD3 H14 | WP-22 | No dedup and no reference counter in 3.0 | Open | 3.0 path audit: no dedup index in `bud3::` this pass (PR #8 builds `bud3/dedup_index.rs`, unmerged; named as the WP-22 seed). Closes with WP-22. |
| BLG-222 | BUD3 H15 | WP-24 | dictionary.rs, living_threshold.rs, derived.rs are wired to production but not to the 3.0 object | Open | All three files present (`src/storage/dictionary.rs`, `living_threshold.rs`, `derived.rs`). Closes with WP-24. |
| BLG-223 | Gonca E1 | WP-56 (testnet closure WP-33 ve WP-45) | PCS Pcs::ZK = false; proofs hide nothing; the privacy opcodes leak the witness | Verified | Reproduced: `budzero/bud-proof/src/bud_stark/prover.rs:317` - "the PCS as `TwoAdicFriPcs`, whose `Pcs::ZK` is `false` (p3-fri 0.7.0)"; `config.rs:138` sets `Self::Pcs::ZK`. Closes with WP-56 (testnet closure WP-33/WP-45). |
| BLG-224 | Gonca E2 | WP-56 (testnet closure WP-45) | Note commitment and nullifier are 64-bit; global collision in ~2^32 operations | Verified | Reproduced: the spent-set is indexed by 64-bit field elements - `note_registry.rs:299` takes `u64::from_le_bytes(low) % GOLDILOCKS_P`; the zkVM relay speaks `is_spent(u64)` (`src/privacy/note_registry.rs:37-45`). Birthday bound ≈ 2^32. Closes with WP-56 (testnet closure WP-45). |
| BLG-225 | Gonca E3 | WP-45, WP-56 | Secret transfer binds no ownership/conservation/membership proofs; spent commitments are written openly | Verified | Reproduced: the production comment at `src/execution/executor.rs:66-80` states nothing calls `apply_transfer_with_proofs` with proofs, so ownership, value conservation and membership are unwired. Closes with WP-45 and WP-56. |
| BLG-228 | Gonca E6 | WP-57 (testnet closure WP-45) | Full AI STARK verification is closed; initial-memory fold is interposable; output commitment unbound | Open | `src/ai/mod.rs` present; the ledger notes verification is closed by default. Closes with WP-57 (testnet closure WP-45). |
| BLG-229 | Gonca E7 | WP-45 (VL-1 leg), WP-57 | No per-request nonce or commit-reveal; no deterministic inference profile | Open | `src/ai/registry.rs` present. Closes with WP-45 (VL-1 foot) and WP-57. |
| BLG-237 | Gonca E15 | WP-22 (blinded consent WP-56) | View grant written on-chain as an open row (content_id, issuer, grantee); social graph leaks | Open | `src/storage/view_grant.rs` present. Closes with WP-22 (private consent foot with WP-56). |
| BLG-238 | Gonca E16 | WP-22 | HPKE key package not wired to the production path | Open | `src/storage/key_package.rs` present. Closes with WP-22. |
| BLG-240 | Gonca E18 | WP-45, WP-57 | Verifier ordering uses f64 (RPC surface only) | Open | `src/ai/registry.rs` present. Closes with WP-45 and WP-57. |
| BLG-245 | Gonca E23 | WP-22 (Padme), WP-56 | Sealed object's full length is visible; the read fee binds reader and content | Open | Manifest size fields and read-fee model present (`src/storage/`). Closes with WP-22 (Padme) and WP-56. |
| BLG-253 | Medium | WP-07, WP-08 | Mobile modules implement the B.U.D. 1.0 self-hosting model, not validator duty; MobileSelfProfile::calculate_leaf hashes unlength-prefixed fields | Open | Files present (`src/storage/mobile_self.rs`, `src/storage/server_admission.rs`, `src/network/mobile.rs`). WP-07 foot (removal, in-flight PR #8); the calculate_leaf foot closes with WP-08. Shared with lane A. |
| BLG-254 | High | WP-07, WP-42 | CI gates enforce the wrong recipe-only 3.0 model; the correct model cannot merge with these gates | Open | `three_is_recipe_only.rs` (present, self-described as hardening the "3.0 = tarif" claim) and `zero_storage_frozen`/`generated_content` still wired. Closes by replacement with WP-07 (WP-42 rewires). |
| BLG-258 | Medium | WP-07 | A separate P2P content node exists (Bitswap, Kademlia, MemoryContentStore); the content gateway depends on it; breaks the single-storage principle | Open | `budzero/bud-node/` present. Closes by removal (WP-07, in-flight PR #8). |
| BULGU-017 | Medium (S3) | WP-07 (removal) | On-chain storage proof is merely structural | Open | `src/domain/storage_deal.rs` present. Closes by removal (WP-07, in-flight PR #8). |
| TEST-GAP-03 | Medium | WP-19 | QR video parser outside fuzz scope | Open | `src/storage/qr_video.rs` present; no fuzz target found under `fuzz/` for it. Closes with WP-19. |
| TEST-GAP-06 | Medium | WP-07 (removal) | Three Kani proofs not run in CI | Open | `bud/kani/` present. Closes by removal (WP-07, in-flight PR #8). |

## Reproduction debt (audit/repro-b)

The Verified rows each owe a red test on `audit/repro-b` (never merges)
that the closing package moves into its own PR (S-3). All eight are
mechanically checkable: BLG-063 (allowlist contains testnet; flip to
assert-mainnet-only after WP-45), BLG-093 (license file mismatch; flip after
the license is unified), BLG-208 (`admits_body` Classic-only), BLG-210
(`reemit` requires external body), BLG-219 (shrink-only zlib), BLG-223
(`TwoAdicFriPcs` not ZK), BLG-224 (64-bit note spent-set), BLG-225 (no bound
ownership/conservation proofs).

## New findings this pass

None beyond the ledger. One observation outside it: `crates/bud-codec/src/registry.rs`
references the `columnar` codec (18 files mention it) while the columnar
implementation being deleted lives in `bud/src/bud_format_columnar.rs`; the
register/corpus split must land with WP-07 item 1 before `bud/` is removed
(WP-24 wires it to the chain). This is a sequencing note for PR #8, not a new
finding.

## Verification base and drift

`git status` clean at verification time on `arena/b0362659-budlum` branched
from `cccf1da`. Identifier scans are fixed-string greps on the same tree.
Where the directive's "Kod izi" column (2026-11-02 analysis base) and this
snapshot disagree, the live result is authoritative.

## Rows carried from pr-87 (WP-27 M0 status)

| BLG-064 | High | Data sovereignty / Cryptography / Economy | Open | blg_064_pollen_protected_content_bridge | src/pollen/, src/socialfi/ (20/21 traces) | IP-23|
| BLG-109 | Critical | Data sovereignty / B.U.D. storage / SocialFi | Open - partial removal | blg_109_nft_mint_burn_manifest_delete | src/socialfi/, src/bns/ (15/16 traces) | IP-23|
| BLG-110 | Critical | Consensus state root / BNS / Privacy | Open | blg_110_bns_registry_default_base_cost | src/bns/ (23/23 traces; L1NoteRegistry MAX_LIVE_COMMITMENTS; XSS) | IP-23|
| BLG-129 | High | Gateway proofs | Open | blg_129_dweb_passport_proof_bundle | src/gateway/, src/budlumxyz/ (36/37 traces) | IP-23|
| BLG-226 | High | Gonca E4 | Open | blg_226_verify_merkle_single_round | budzero/bud-isa/src/lib.rs | IP-56 (testnet closure IP-33)|
| BLG-230 | Medium | Gonca E8 | Open | blg_230_sender_64bit_vs_address_256bit | budzero/bud-vm/src/lib.rs; src/execution/zkvm.rs | IP-33 (execution leg), IP-56|
| BLG-232 | Medium | Gonca E10 | Open | blg_232_single_air_1073_columns | budzero/bud-proof/src/plonky3_air.rs | IP-56|
| BLG-236 | Medium | Gonca E14 | Open | blg_236_no_plaintext_bound_commitment | docs/BUD_CONTENT_ENCRYPTION.md; src/storage/payload_crypt.rs | IP-56|
| BLG-242 | Medium | Gonca E20 | Open | blg_242_commitment_no_team_hash | All commitment types | IP-56|
| BLG-243 | Medium | Gonca E22 | Open | blg_243_event_accumulation_32bit_sum | budzero/README.md; docs/AI_VERIFICATION_STATUS.md | IP-56|
| BLG-261 | Low | src/deed/mod.rs | Open | blg_261_deed_register_manifest_breaks | src/deed/mod.rs (RegisterManifest breaks when 2.0 removed) | IP-23|
| BLG-262 | Medium | src/gateway/service.rs | Open | blg_262_content_gateway_bitswap_sled | src/gateway/service.rs (gateway serves via Bitswap + local sled; not bound to B.U.D. 3.0 symbol path) | IP-23|

## Verification rows carried from pr-68

The merge kept this tree's row wording and lost the reproduction
evidence columns. The evidence is carried back verbatim.

| BLG-035 | Verified (Red test output) | audit_repro_b_blg_035 | bud/src/ (migration) | WP-07 | Medium |
| BLG-045 | Verified (Red test output) | audit_repro_b_blg_045 | bud/src/ (migration) | WP-07 | Medium |
| BLG-046 | Verified (Red test output) | audit_repro_b_blg_046 | bud/src/ (migration) | WP-07 | Medium |
| BLG-047 | Verified (Red test output) | audit_repro_b_blg_047 | bud/src/ (migration) | WP-07 | Medium |
| BLG-073 | Verified (Red test output) | audit_repro_b_blg_073 | bud/src/ (migration) | WP-07 | Medium |
| BLG-074 | Verified (Red test output) | audit_repro_b_blg_074 | bud/src/ (migration) | WP-07 | Medium |
| BLG-075 | Verified (Red test output) | audit_repro_b_blg_075 | bud/src/ (migration) | WP-07 | Medium |
| BLG-076 | Verified (Red test output) | audit_repro_b_blg_076 | bud/src/ (migration) | WP-07 | Medium |
| BLG-077 | Verified (Red test output) | audit_repro_b_blg_077 | bud/src/ (migration) | WP-07 | Medium |
| BLG-078 | Verified (Red test output) | audit_repro_b_blg_078 | bud/src/ (migration) | WP-07 | Medium |
| BLG-079 | Verified (Red test output) | audit_repro_b_blg_079 | bud/src/ (migration) | WP-07 | Medium |
| BLG-080 | Verified (Red test output) | audit_repro_b_blg_080 | bud/src/ (migration) | WP-07 | Medium |
| BLG-122 | Verified (Red test output) | audit_repro_b_blg_122 | bud/src/ (migration) | WP-07 | Medium |
| BLG-123 | Verified (Red test output) | audit_repro_b_blg_123 | bud/src/ (migration) | WP-07 | Medium |
| BLG-141 | Verified (Red test output) | audit_repro_b_blg_141 | bud/src/ (migration) | WP-07 | Medium |
| BLG-152 | Verified (Red test output) | audit_repro_b_blg_152 | bud/src/ (migration) | WP-07 | Medium |
| BLG-153 | Verified (Red test output) | audit_repro_b_blg_153 | bud/src/ (migration) | WP-07 | Medium |
| BLG-156 | Verified (Red test output) | audit_repro_b_blg_156 | bud/src/ (migration) | WP-07 | Medium |
| BLG-208 | Verified (Red test output) | audit_repro_b_blg_208 | bud/src/ (migration) | WP-07 | Medium |
| BLG-209 | Verified (Red test output) | audit_repro_b_blg_209 | bud/src/ (migration) | WP-07 | Medium |
| BLG-217 | Verified (Red test output) | audit_repro_b_blg_217 | bud/src/ (migration) | WP-07 | Medium |
| BLG-253 | Verified (Red test output) | audit_repro_b_blg_253 | src/storage/mobile_self.rs | WP-07 | High |
| BLG-254 | Verified (Red test output) | audit_repro_b_blg_254 | xtask/gates/src/gates/three_is_recipe_only.rs | WP-07 | High |
| BLG-258 | Verified (Red test output) | audit_repro_b_blg_258 | budzero/bud-node/ | WP-07 | Medium |
