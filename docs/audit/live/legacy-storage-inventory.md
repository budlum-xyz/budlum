# Legacy storage inventory (WP-02 required deliverable)

Live branch `main` at `14d9a18130b5147e9f0e9412e57b3f8b31b45449`. Source of decisions: directive section 5.2 (file table), 5.3 (transaction and RPC changes), 5.4 (CI gates), 5.5 (forbidden list). Types are the `pub struct|enum|trait|type` items declared at the top level of each file (static scan, nested items and impl blocks not listed). Line counts are `wc -l` at the live commit.

Legend: Sil = delete, Goc = rewrite inside B.U.D. 3.0 and delete the old file, Tasi = move without behaviour change (not deleted).

## 1. `src/storage/` files

| File | Lines | Decision | Target | Types |
|---|---|---|---|---|
| `src/storage/assignment.rs` | 631 | Goc | bud3::placement | struct ShardCandidate, enum AssignmentError |
| `src/storage/column_commitment.rs` | 282 | Sil | RFC 6330 (6.7) | (none) |
| `src/storage/content_id.rs` | 217 | Goc | bud3/content_id.rs | struct ContentId |
| `src/storage/db.rs` | 3110 | Tasi | src/persistence/db.rs | struct Storage |
| `src/storage/derived.rs` | 1414 | Goc | crates/bud-codec codec 10 | enum DerivedTransform, struct DerivedSpec, struct PrefixSpan, enum DerivedError, struct MasterRegistry |
| `src/storage/dictionary.rs` | 744 | Goc | crates/bud-codec codec 3 and bud3::dictionary | enum DictionaryError, struct DictionaryEntry, struct DictionaryRegistry |
| `src/storage/emit.rs` | 1833 | Goc | bud3::upload | struct EmitPolicy, struct FeedPreview, enum EmitError |
| `src/storage/erasure.rs` | 1617 | Sil | RFC 6330 (6.7) | enum ErasureError, struct ReedSolomon, struct EncodedObject |
| `src/storage/fixed_point.rs` | 242 | Sil | candidate codec to Appendix D | (none) |
| `src/storage/generated.rs` | 1653 | Sil | candidate codec to Appendix D | enum BudStorageEdition, enum ContentSource, struct GeneratedSpec, struct SealedGeneratedSpec, enum GeneratorId, enum GenerateError |
| `src/storage/key_package.rs` | 375 | Goc | bud3::{keys, seal, grants, delete} | enum KeyPackageError, struct KeyPackage |
| `src/storage/lifecycle.rs` | 172 | Sil | bud3::custody | enum StorageLifecycleState, enum StorageLifecycleError |
| `src/storage/living_threshold.rs` | 1350 | Goc | bud3::access_tiering | struct Lever, struct OperatorRates, enum ThresholdError, struct AccessEstimate, struct AccessEvent, enum Decision |
| `src/storage/lrc.rs` | 583 | Sil | RFC 6330 (6.7) | enum LrcError, struct LrcLayout |
| `src/storage/manifest.rs` | 1587 | Sil | bud3::Object / ObjectRecord | struct ShardRef, enum ShardKind, enum ContentEncryption, enum ContentCipher, struct ErasureScheme, struct ContentManifest |
| `src/storage/merkle_trie.rs` | 808 | Tasi | src/persistence/state_trie.rs | struct MerkleProof, struct MerkleTrie, struct AccountProofBundle |
| `src/storage/mobile_self.rs` | 701 | Sil | mobile validator (section 7) | enum MobileAvailabilityClass, enum ReplicaRecommendation, struct MobileSelfProfile, struct MobileSelfContentPolicy, enum CustodyMode, struct CustodyDecision, enum UploadCustodyRefusal, struct CustodyLedger |
| `src/storage/msr.rs` | 206 | Sil | RFC 6330 (6.7) | enum MsrError |
| `src/storage/one_share.rs` | 335 | Sil | none | struct Share, enum ShareRefusal, struct OneShareRegistry |
| `src/storage/one_view.rs` | 216 | Sil | none | struct EndpointRef, struct ScreenItem, struct SingleScreenView |
| `src/storage/pact_binding.rs` | 342 | Sil | none | struct Pact, struct PactRegistry, struct PactGates |
| `src/storage/payload_crypt.rs` | 323 | Goc | bud3::{keys, seal, grants, delete} | struct PayloadKey, enum SealError |
| `src/storage/provider.rs` | 720 | Sil | bud3::custody | type DealId, type ChallengeId, struct PutReceipt, struct StorageProof, struct ProviderChallengeResult, enum StorageProviderError, trait StorageProvider, struct InMemoryStorageProvider |
| `src/storage/pruning.rs` | 210 | Tasi | src/persistence/pruning.rs | enum NodeMode, struct PruningPolicy |
| `src/storage/qr_carousel.rs` | 1677 | Goc | bud3::fountain (RFC 6330) | enum CarouselError, struct CarouselParams, struct Drop, struct CarouselEncoder, struct CarouselDecoder |
| `src/storage/qr_codec.rs` | 282 | Goc | bud3::{frame, qr, video, receive, verify} | enum CodecKind, enum CodecError, trait FrameMux, struct RawFrameConcat |
| `src/storage/qr_encode.rs` | 1042 | Goc | bud3::{frame, qr, video, receive, verify} | enum QrError, struct EncodedMatrix |
| `src/storage/qr_frame.rs` | 427 | Goc | bud3::{frame, qr, video, receive, verify} | enum FrameError |
| `src/storage/qr_matrix.rs` | 278 | Goc | bud3::{frame, qr, video, receive, verify} | enum QrMatrixError, struct QrMatrix |
| `src/storage/qr_payload.rs` | 560 | Goc | bud3::object, bud3::bof1 | enum PayloadKind, enum PayloadError |
| `src/storage/qr_png.rs` | 343 | Goc | bud3::{frame, qr, video, receive, verify} | enum QrPngError |
| `src/storage/qr_receive.rs` | 405 | Goc | bud3::{frame, qr, video, receive, verify} | enum ReceiveError, struct ProgressiveReceiver |
| `src/storage/qr_recipe.rs` | 371 | Goc | bud3::object, bud3::bof1 | struct ThreeRecipePublic, struct ThreeRecipeSealed, enum ThreeRecipe |
| `src/storage/qr_reemit.rs` | 327 | Goc | bud3::object, bud3::bof1 | enum ReemitError, struct RecipeEmitter |
| `src/storage/qr_verify.rs` | 410 | Goc | bud3::{frame, qr, video, receive, verify} | struct ExpectedCommitments, enum VerifyError, struct VerificationRecord, type VerifiedVideo |
| `src/storage/qr_verify_indep.rs` | 939 | Goc | bud3::{frame, qr, video, receive, verify} | struct PrimaryClaim, enum IndepError |
| `src/storage/qr_video.rs` | 1077 | Goc | bud3::{frame, qr, video, receive, verify} | enum QrVideoError, struct QrVideo |
| `src/storage/render.rs` | 1155 | Sil | candidate codec to Appendix D | enum RenderFormat, enum RenderError |
| `src/storage/reveal_gateway.rs` | 1107 | Goc | bud3::view | enum RevealGatewayError, struct GrantScope, struct PreparedReveal, struct RevealGateway |
| `src/storage/server_admission.rs` | 149 | Sil | mobile validator (section 7) | struct ServerAdmission, enum ServerAdmissionRefusal |
| `src/storage/social_delete.rs` | 171 | Goc | bud3::{keys, seal, grants, delete} | struct DeleteOutcome |
| `src/storage/three_gate.rs` | 158 | Goc | bud3::{classify, hooks, meter, visibility} | enum ThreeBlobKind |
| `src/storage/three_hooks.rs` | 90 | Goc | bud3::{classify, hooks, meter, visibility} | enum ThreeHookKind, struct ThreeHookEvent, trait ThreeEventHook, struct NopThreeHook, struct RecordingThreeHook |
| `src/storage/three_meter.rs` | 152 | Goc | bud3::{classify, hooks, meter, visibility} | struct ThreeMeter, enum MeterError |
| `src/storage/three_nft.rs` | 534 | Goc | bud3::nft | enum PreviewMode, enum MetadataVisibility, struct ThreeNftMeta, enum ThreeNftRegistryError, enum RecipeRecord, struct PinRow, struct ThreeNftRegistry |
| `src/storage/three_pipe.rs` | 670 | Goc | bud3::upload | enum PipeError, struct EncodedPipe, struct EncodedQrVideo |
| `src/storage/three_recipe.rs` | 860 | Goc | bud3::object, bud3::bof1 | enum VideoRecipeError, struct RecipeTransform, struct VideoRecipe, struct VideoRecipeSealed, struct VideoFrameStream |
| `src/storage/three_regime.rs` | 279 | Sil | bud3::fees (6.18) | enum ContentRegime, enum RentBasis, enum AccountingRefusal |
| `src/storage/three_reveal.rs` | 525 | Goc | bud3::view | enum RevealError, struct RevealSession |
| `src/storage/three_rpc.rs` | 397 | Goc | bud3::view | enum RevealRpcError, struct RevealRequest, struct RevealHandle |
| `src/storage/three_visibility.rs` | 72 | Goc | bud3::{classify, hooks, meter, visibility} | enum UploadVisibility |
| `src/storage/traits.rs` | 324 | Tasi | src/persistence/traits.rs | type SeenBlockMap, trait BlockchainStorage, struct DurableCommitBatch |
| `src/storage/transformed.rs` | 703 | Goc | crates/bud-codec selection rule | struct CodecFlags, enum ContentClass, struct TransformedPayload, enum TransformError, struct TransformOpts |
| `src/storage/view_grant.rs` | 1222 | Goc | bud3::{keys, seal, grants, delete} | enum ViewPolicy, struct ViewGrant, enum GrantAuthError, struct GrantAuthorization, struct GrantIssueTerms, enum ViewGrantError, struct ViewGrantRegistry, struct ConfidentialBodyCommit, enum ConfidentialProofKind |
| `src/storage/witness_retention.rs` | 72 | Tasi | src/persistence/witness_retention.rs | enum NodeKind |
| `src/storage/mod.rs` | 206 | rewrite | module list shrinks; `bud3` module added | (re-exports) |
| `src/storage/README.md` | 176 | rewrite | docs/STORAGE.md | - |

## 2. Domain and chain files

| File | Lines | Decision | Target | Types |
|---|---|---|---|---|
| `src/domain/storage_deal.rs` | 9567 | Sil | bud3::registry | struct RetrievalChallengeRequest, enum DealStatus, enum OperatorClass, struct StorageEconomicsParams, struct StorageDeal, struct RetrievalChallenge, struct StorageChallengeProofContext, struct CodingAudit, enum CodingAuditOutcome, struct StoredCodingAudit, struct StorageChallengeRangeInput, struct RetrievalResponse, enum ChallengeOutcome, struct ChallengeResult, enum ReallocationStatus, enum ReallocationCause, struct StorageReallocationTicket, struct StorageRegistry, enum StorageEconomicsEventKind, struct StorageEconomicsEvent, struct StorageEconomicsLedger, enum StorageError |
| `src/domain/storage_params.rs` | 201 | Sil | bud3::registry | struct StorageDomainParams |
| `src/domain/deal_open.rs` | 859 | Sil | bud3::registry | struct DealOpenTerms, struct ReallocationTerms |
| `src/domain/storage_tx.rs` | 2093 | Goc | src/storage/bud3/tx.rs (StorageTx v3) | enum StorageTx, struct StorageReallocationAccept, struct StorageDealOpen, struct StorageTxContext, enum StorageTxError |
| `src/chain/storage_economics_tests.rs` | 751 | Sil | bud3::maintenance | (none) |
| `src/chain/storage_maintenance.rs` | 601 | Sil | bud3::maintenance | (none) |
| `src/domain/regeneration_stage.rs` | 1560 | Tasi and rename | src/chain/state_recovery/ | enum Stage, struct StageSnapshot, struct Transdifferentiated, enum ProofFamily, enum Stress, struct ReversionPolicy, enum ReversionError, struct Reversion, struct RegenerationLedger |
| `src/domain/regen_health.rs` | 595 | Tasi and rename | src/chain/state_recovery/ | enum AlarmReason, enum HealthVerdict, struct HealthPolicy |
| `src/domain/regen_mempool.rs` | 217 | Tasi and rename | src/chain/state_recovery/ | struct RegenMempool |
| `src/network/regen_health_tick.rs` | 608 | Tasi and rename | src/chain/state_recovery/ | struct Checkpoint, struct CheckpointView, enum TickOutcome, struct RegenHealthTick |
| `src/gateway/service.rs` | 714 | Goc | src/storage/bud3/content_gateway.rs | struct BudGateway |

Proposed additions to the 5.2 table (files found on live that the table does not list):

| File | Why | Proposed decision |
|---|---|---|
| `src/network/mobile.rs` | Mobile Self profile module (B.U.D. 1.0 self-hosting), ledger BLG-253 | Goc into the mobile validator of section 7, with `mobile_self.rs` and `server_admission.rs` |
| `src/storage/README.md` | Documents the 2.0 layout | Rewrite into `docs/STORAGE.md` |
| `xtask/gates/src/gates/three_is_recipe_only.rs`, `zero_storage_frozen.rs`, `generated_content.rs`, `qr_is_derivative_only.rs`, `storage_priced.rs`, `storage_provider_gate.rs`, `storage_proof_boundary.rs`, `coding_audit_samples_the_relationship.rs`, `paid_content.rs`, `shard_placement.rs`, `repair_fires.rs`, `storage_penalties.rs`, `content_encryption_is_declared_and_bound.rs`, `bud_e2e.rs` | CI gates of the 2.0 model (section 5.4); present on live where listed in section 3 below | Sil or rewrite per 5.4 |

## 3. CI gates named in directive 5.4 (presence on live)

| Gate | Source file on live | Decision (5.4) |
|---|---|---|
| `three_is_recipe_only` | `xtask/gates/src/gates/three_is_recipe_only.rs` | Sil, replace by bud3_object_is_universal |
| `zero_storage_frozen` | `xtask/gates/src/gates/zero_storage_frozen.rs` | Sil |
| `generated_content` | `xtask/gates/src/gates/generated_content.rs` | Sil |
| `qr_is_derivative_only` | `xtask/gates/src/gates/qr_is_derivative_only.rs` | Rewrite as bud3_qr_is_presentation |
| `storage_priced` | `xtask/gates/src/gates/storage_priced.rs` | Rewrite as bud3_fee_uses_physical_bytes |
| `storage_provider_gate` | `xtask/gates/src/gates/storage_provider_gate.rs` | Sil, bud3_custody_proofs |
| `storage_proof_boundary` | `xtask/gates/src/gates/storage_proof_boundary.rs` | Sil, bud3_custody_proofs |
| `coding_audit_samples_the_relationship` | `xtask/gates/src/gates/coding_audit_samples_the_relationship.rs` | Sil, bud3_custody_proofs |
| `paid_content` | `xtask/gates/src/gates/paid_content.rs` | Sil, bud3_paid_view |
| `shard_placement` | `xtask/gates/src/gates/shard_placement.rs` | Rewrite as bud3_placement |
| `repair_fires` | `xtask/gates/src/gates/repair_fires.rs` | Rewrite as bud3_repair_fires |
| `storage_penalties` | `xtask/gates/src/gates/storage_penalties.rs` | Rewrite as bud3_custody_rewards |
| `content_encryption_is_declared_and_bound` | `xtask/gates/src/gates/content_encryption_is_declared_and_bound.rs` | Rewrite |
| `derived_content` | `xtask/gates/src/gates/derived_content.rs` | Keep (codec 10) |
| `bud_e2e` | `xtask/gates/src/gates/bud_e2e.rs` | Rewrite as bud3_e2e_* |
| `regeneration` | `xtask/gates/src/gates/regeneration.rs` | Rename canonical_programs_reproduce |
| `zkvm_immune_regeneration` | `xtask/gates/src/gates/zkvm_immune_regeneration.rs` | Rename zkvm_refuses_untrusted_proofs |
| `regen_health_door` | `xtask/gates/src/gates/regen_health_door.rs` | Rename state_recovery_door |
| `budscan_parity` | `xtask/gates/src/gates/budscan_parity.rs` | Rename explorer_parity |
| `budscan_patchset` | `xtask/gates/src/gates/budscan_patchset.rs` | Rename explorer_patchset |

## 4. Whole trees to delete

### 4.1 `budzero/bud-node/` (6 tracked files)

| File | Lines | Types |
|---|---|---|
| `budzero/bud-node/Cargo.toml` | 39 | - |
| `budzero/bud-node/src/bitswap.rs` | 485 | struct BitswapRequest, struct BitswapResponse, struct BitswapCodec, enum CodecError, struct BudBitswap |
| `budzero/bud-node/src/discovery.rs` | 435 | struct DiscoveryConfig, struct Provider, struct ContentDiscovery |
| `budzero/bud-node/src/lib.rs` | 46 | - |
| `budzero/bud-node/src/sharding.rs` | 238 | struct ShardingConfig, struct ShardManager |
| `budzero/bud-node/src/store.rs` | 877 | struct ContentId, enum StoreError, trait ContentStore, struct MemoryContentStore, struct FileContentStore |

Dependants to unwire in the same change: root `Cargo.toml` (`bud-node = { path = "budzero/bud-node" }`), `src/network/node.rs` (`bud_node::BitswapCodec` behaviour, `PendingBitswapFetches`), `src/gateway/service.rs` (`BudBitswap` path), `budzero/Cargo.toml` workspace member list.

### 4.2 `bud/` workspace (migrate lossless codecs to `crates/bud-codec`, then delete)

119 tracked files. Source files under `bud/src` carry the types below.

| File | Lines | Types |
|---|---|---|
| `bud/Cargo.lock` | 811 | - |
| `bud/Cargo.toml` | 104 | - |
| `bud/FORMAT-V2.md` | 175 | - |
| `bud/README.md` | 70 | - |
| `bud/fuzz/Cargo.toml` | 23 | - |
| `bud/fuzz/fuzz_bud_format.rs` | 112 | - |
| `bud/kani/kani_bud_format.rs` | 53 | - |
| `bud/mime.types.bud.json` | 15 | - |
| `bud/src/bin/bud.rs` | 867 | - |
| `bud/src/bin/measure_ratios.rs` | 315 | - |
| `bud/src/bud3_live_test.rs` | 111 | - |
| `bud/src/bud_fixed_point.rs` | 257 | - |
| `bud/src/bud_format.rs` | 1384 | enum BudFormatClass, struct BudFlags, struct BudHeader, struct BudChunk, struct BudFile, struct BudFileEntry, struct RatioCandidate, struct MultiRatioConsensus, struct BudGates |
| `bud/src/bud_format_autozstd.rs` | 90 | enum ZstdDecision |
| `bud/src/bud_format_av2.rs` | 108 | struct Av2Status |
| `bud/src/bud_format_bft.rs` | 608 | struct RatioVote, struct ValidatorSet, struct RatioFinalityCert, struct BftRatioConsensus |
| `bud/src/bud_format_block.rs` | 376 | struct PactChallengeInBlock, struct RegenerationBlock |
| `bud/src/bud_format_bloom.rs` | 183 | struct BloomDedupIndex |
| `bud/src/bud_format_catalog.rs` | 490 | struct FormatCatalogEntry |
| `bud/src/bud_format_checkpoint.rs` | 248 | struct Checkpoint |
| `bud/src/bud_format_columnar.rs` | 845 | enum ColumnarMode, enum ColType, struct JsonColumnar |
| `bud/src/bud_format_container.rs` | 1227 | enum StructuralKind, struct StructuralChunk, struct MultiHash, enum FormatCodec, struct BudV2Header, enum ChunkCodec, struct BudV2File |
| `bud/src/bud_format_crop.rs` | 237 | struct CropDerivation |
| `bud/src/bud_format_culling.rs` | 326 | enum ClusterTier, struct CullingPlan |
| `bud/src/bud_format_das.rs` | 401 | struct DasProof, struct DasSampler, struct DasOwnership |
| `bud/src/bud_format_dbdelta.rs` | 100 | - |
| `bud/src/bud_format_dedup.rs` | 150 | struct TenantDedup, enum DedupOutcome, struct PowChallenge |
| `bud/src/bud_format_dictionary.rs` | 245 | struct TenantDictionary |
| `bud/src/bud_format_economics.rs` | 578 | struct BudEconomics, enum EgressZone, enum ArchiveTier, struct GlobalDedup, struct MerkleTrie, struct EconomicsGates |
| `bud/src/bud_format_edge.rs` | 106 | struct EdgeCache |
| `bud/src/bud_format_edition.rs` | 222 | enum Edition, enum Bud1Custody, struct Bud1Nft, struct EditionChoice |
| `bud/src/bud_format_encpact.rs` | 98 | enum EncryptionDecl |
| `bud/src/bud_format_engine.rs` | 988 | enum TransformKind, enum PipeStep, struct EngineResult, struct EngineTierResult |
| `bud/src/bud_format_erasure.rs` | 394 | struct CauchyMds |
| `bud/src/bud_format_exepdf.rs` | 451 | struct ExeSectionSplit, enum ExeKind, struct PdfStreamSplit |
| `bud/src/bud_format_fastcdc.rs` | 324 | struct FastCdcSplit |
| `bud/src/bud_format_fidelitygate.rs` | 116 | enum LossyKind |
| `bud/src/bud_format_fountain.rs` | 342 | - |
| `bud/src/bud_format_genomic.rs` | 159 | - |
| `bud/src/bud_format_governance.rs` | 219 | enum GrantState, struct PollenGrant, enum ActivationClass, enum WiringStatus |
| `bud/src/bud_format_guardian.rs` | 296 | enum GuardianRole, struct Guardian, struct MiniGuardianAudit |
| `bud/src/bud_format_hardening.rs` | 231 | struct RecipeQuota, struct CostComponents |
| `bud/src/bud_format_huffman.rs` | 486 | struct HuffmanCoder |
| `bud/src/bud_format_hw.rs` | 190 | struct MediaTier |
| `bud/src/bud_format_integration.rs` | 251 | struct BudStorageAssignment, struct BudLivingThreshold, struct BudErasure, struct IntegrationGates |
| `bud/src/bud_format_jpegre.rs` | 294 | struct JpegAnalysis |
| `bud/src/bud_format_lazyrepair.rs` | 161 | enum RepairAction |
| `bud/src/bud_format_logfield.rs` | 552 | enum NginxField, struct LogFieldColumnar |
| `bud/src/bud_format_lowrank.rs` | 290 | - |
| `bud/src/bud_format_lrc.rs` | 275 | struct LrcScheme, struct LrcRecord |
| `bud/src/bud_format_markdown.rs` | 495 | enum MdSection, struct MarkdownSplit |
| `bud/src/bud_format_matrix.rs` | 446 | struct MatrixEntry |
| `bud/src/bud_format_media.rs` | 140 | struct MediaBench |
| `bud/src/bud_format_model.rs` | 418 | enum FloatKind, struct ModelFloatSplit |
| `bud/src/bud_format_msr.rs` | 357 | - |
| `bud/src/bud_format_multifile.rs` | 524 | struct MultifileChunk, struct TenantMultifileStore |
| `bud/src/bud_format_nvc.rs` | 264 | - |
| `bud/src/bud_format_office.rs` | 476 | struct OfficeEntry |
| `bud/src/bud_format_optical.rs` | 178 | struct OpticalPrompt, struct LogTemplate, struct LogTemplateMiner, struct OpticalGates |
| `bud/src/bud_format_optical_transfer.rs` | 224 | struct OptSegment |
| `bud/src/bud_format_pact.rs` | 616 | enum PactMode, struct PactRecord, trait SuiteSigner, trait SuiteVerifier, enum SignedRecordError, struct SignedPact |
| `bud/src/bud_format_pcap.rs` | 451 | - |
| `bud/src/bud_format_pgm.rs` | 205 | struct LinSeg |
| `bud/src/bud_format_pipe.rs` | 324 | - |
| `bud/src/bud_format_pointcloud.rs` | 190 | struct PointCloud |
| `bud/src/bud_format_por.rs` | 233 | struct PorKey, struct PorTag, struct PorChallenge, struct PorResponse |
| `bud/src/bud_format_prodcost.rs` | 185 | struct StepCost |
| `bud/src/bud_format_production.rs` | 259 | struct BudProductionRecord, struct ProductionGates |
| `bud/src/bud_format_qos.rs` | 85 | enum QosVerdict |
| `bud/src/bud_format_qrmatrix.rs` | 242 | struct QrMatrix |
| `bud/src/bud_format_qrvideo.rs` | 843 | struct DamlaHdr, struct Karusel, struct KaruselDecoder |
| `bud/src/bud_format_r3fix.rs` | 268 | enum Codec, struct R3Recipe |
| `bud/src/bud_format_ratioconsensus.rs` | 399 | enum ContentClass, struct RatioCandidateAgent, struct RatioConsensus |
| `bud/src/bud_format_real.rs` | 224 | struct RealCompressor, struct RealBench |
| `bud/src/bud_format_realcorpus.rs` | 107 | - |
| `bud/src/bud_format_recipe.rs` | 188 | struct RecipeCandidate |
| `bud/src/bud_format_recipe_record.rs` | 262 | enum ContentSource, enum RecipeRecord |
| `bud/src/bud_format_regeneration.rs` | 739 | enum RegenerationOutcome, struct RegenerationChallenge, struct RegenerationRecord, struct SignedRegenerationResult, struct ReputationLedger |
| `bud/src/bud_format_registry.rs` | 302 | struct MimeRegistry, struct RatioProof, struct SecondPreimageResistantMerkle, struct DictLoopDetector, struct RegistryGates |
| `bud/src/bud_format_repairband.rs` | 116 | enum RepairModel |
| `bud/src/bud_format_revolutionary.rs` | 636 | struct CompactTable, struct Evidence, struct Fact, struct SqliteChunk, struct SecretRedactor, struct ColumnarTransform, struct HybridSearch, struct RevolutionaryGates |
| `bud/src/bud_format_scrub.rs` | 77 | enum ScrubTier |
| `bud/src/bud_format_secure_db.rs` | 88 | struct SecureEmbeddedDb, struct SecureDbGates |
| `bud/src/bud_format_securededup.rs` | 136 | - |
| `bud/src/bud_format_segment.rs` | 296 | struct SegmentLedger |
| `bud/src/bud_format_serviceclass.rs` | 99 | enum ServiceClass |
| `bud/src/bud_format_shamir.rs` | 328 | struct ShamirShare |
| `bud/src/bud_format_social.rs` | 287 | enum SocialPlatform, enum OwnershipKind, struct SocialBridgeRecord |
| `bud/src/bud_format_social2.rs` | 252 | struct SocialSource, struct MultiSourcePact, struct LadderStep |
| `bud/src/bud_format_spec.rs` | 268 | struct ThreeMeterK14b |
| `bud/src/bud_format_telemetry.rs` | 176 | struct AccessTracker |
| `bud/src/bud_format_timeseries.rs` | 436 | struct TimeSeriesColumnar |
| `bud/src/bud_format_tiny.rs` | 150 | struct TinyInline |
| `bud/src/bud_format_transpile.rs` | 142 | struct BashTranspile, struct AstTransform, struct TranspileGates |
| `bud/src/bud_format_tricore.rs` | 177 | struct TriCoreWeights |
| `bud/src/bud_format_ultra.rs` | 119 | struct DiffusionPrompt, struct CodeTarif, struct Log4Layer, struct UltraGates |
| `bud/src/bud_format_ux.rs` | 280 | struct VideoUx, struct CreationFee |
| `bud/src/bud_format_video.rs` | 363 | enum VideoContentClass, enum VideoCodec, struct VideoSuggestion, struct BudVideoRecord, struct VideoGates |
| `bud/src/bud_format_videopipe.rs` | 177 | struct VideoPipelineResult |
| `bud/src/bud_format_view.rs` | 414 | struct KeySchema, struct CompiledView |
| `bud/src/bud_format_wal.rs` | 224 | - |
| `bud/src/bud_format_wire.rs` | 272 | enum FieldPolicy, struct WireField, struct GoldenVector |
| `bud/src/bud_format_zkbridge.rs` | 226 | struct WitnessStep |
| `bud/src/bud_format_zkproof.rs` | 351 | enum ZkTrust |
| `bud/src/churn.rs` | 258 | struct QuadRing, enum FixtureKind, struct ChurnFixture, struct ChurnResult |
| `bud/src/cli.rs` | 149 | struct BudCli |
| `bud/src/fidelity.rs` | 154 | enum FidelityError, struct ContentId, enum RenderFormat, struct FidelityCore |
| `bud/src/gates.rs` | 243 | struct GateResult, struct GateSuite |
| `bud/src/lib.rs` | 233 | - |
| `bud/src/price.rs` | 166 | struct PriceModel, enum PriceError, struct Expansion |
| `bud/src/provider.rs` | 191 | enum ProviderClass, enum ProviderError, trait Provider, struct SocialMediaProvider, struct MobileSelfProvider, struct NetworkFullProvider, struct MediaDeviceOnlyPolicy |
| `bud/src/quantum.rs` | 125 | enum Suite, struct QuantumSuite, enum QuantumError |
| `bud/src/quantum_chain.rs` | 237 | struct Sha3Hasher, struct HybridFinalityVote, struct FiatShamirTranscript, struct MobileSelfProvider, struct Sha3Sponge, struct QuantumChainGates |
| `bud/src/ratio.rs` | 90 | enum FormatClass, struct Pipe, struct RatioResult |
| `bud/tests/fixtures/image.png` | 7 | - |
| `bud/tests/fixtures/text.log` | 2000 | - |
| `bud/tests/fixtures/video.yuv` | 356 | - |
| `bud/tests/test_bud2.rs` | 138 | - |
| `bud/tests/test_integration.rs` | 583 | - |

## 5. `StorageTx` variants (src/domain/storage_tx.rs)

| Variant | Decision (5.3) |
|---|---|
| `StorageTx::RegisterManifest` | Delete (replaced by RegisterObject) |
| `StorageTx::DeclareOperatorClass` | Delete |
| `StorageTx::DeclareSelfHostPolicy` | Delete |
| `StorageTx::OpenDeal` | Delete |
| `StorageTx::AnswerCodingAudit` | Delete |
| `StorageTx::AcceptReallocation` | Delete |
| `StorageTx::OpenChallenge` | Delete |
| `StorageTx::AnswerChallenge` | Delete |
| `StorageTx::CommitConfidentialBody` | Delete |
| `StorageTx::IssueViewGrant` | Keep and rewrite |
| `StorageTx::RevokeViewGrant` | Keep and rewrite |
| `StorageTx::SocialDelete` | Keep and rewrite |

Related wire items: `proto/budlum/network/protocol.proto` carries only `ProtoStorageTx { bytes data = 1; }` (bincode `StorageTx`) as the storage payload; the directive (5.3 item 8) expects 2.0 storage messages in that file, but on live there are none beyond this opaque payload and no Bitswap messages (Bitswap uses the `bud_node::BitswapCodec` request-response codec). `src/registry/role.rs`: `STORAGE_OPERATOR` (RoleId 5) and `CONTENT_VALIDATOR` (RoleId 9) are to be removed from `RoleBond`, ids stay reserved.

## 6. RPC methods (src/rpc/method_class.rs, src/rpc/server.rs, src/rpc/api.rs)

All 28 `bud_storage*` methods registered on live. Class and access mode are the live `method_class.rs` entries.

| Method | Live class and mode | Decision (5.3) |
|---|---|---|
| `bud_storageAcceptReallocation` | Operator / Refused | Delete |
| `bud_storageActiveOperators` | Public / Read | Delete |
| `bud_storageAnswerChallenge` | Operator / Refused | Delete |
| `bud_storageCloseReveal` | Public / LocalAdmin | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageGetChallenges` | Public / Read | Delete |
| `bud_storageGetConfidentialCommit` | Public / Read | Delete |
| `bud_storageGetDealsByManifest` | Public / Read | Delete |
| `bud_storageGetDealsByShard` | Public / Read | Delete |
| `bud_storageGetEconomicsEvents` | Public / Read | Delete |
| `bud_storageGetEconomicsSummary` | Public / Read | Delete |
| `bud_storageGetManifest` | Public / Read | Delete |
| `bud_storageGetOperatorEconomics` | Public / Read | Delete |
| `bud_storageGetOutcome` | Public / Read | Delete |
| `bud_storageIssueViewGrant` | Public / Refused | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageListViewGrants` | Public / Read | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageMayView` | Public / Read | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageOpenChallenge` | Operator / Refused | Delete |
| `bud_storageOpenDeal` | Operator / Refused | Delete |
| `bud_storageOpenReveal` | Public / LocalAdmin | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageQrFeedFrames` | Public / Read | Delete |
| `bud_storageQrFeedPreview` | Public / Read | Delete |
| `bud_storageRegisterConfidentialCommit` | Operator / Refused | Delete |
| `bud_storageRegisterManifest` | Operator / Refused | Delete |
| `bud_storageRepairBand` | Public / Read | Delete |
| `bud_storageRevealFrames` | Public / LocalAdmin | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageRevokeViewGrant` | Public / Refused | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageSocialDelete` | Public / Refused | Not in the delete list: rewrite or replace by 6.22 methods |
| `bud_storageVerifyEncoding` | Public / Read | Delete |

Delete list in 5.3 item 5 has 20 names; 20 of them are registered on live. Registered but not in the delete list: `bud_storageCloseReveal`, `bud_storageIssueViewGrant`, `bud_storageListViewGrants`, `bud_storageMayView`, `bud_storageOpenReveal`, `bud_storageRevealFrames`, `bud_storageRevokeViewGrant`, `bud_storageSocialDelete`. These eight (view grant, social delete and reveal-session methods) belong to the rewritten `bud3::view`, `bud3::grants` and `bud3::delete`.

## 7. Forbidden identifier usage (directive 5.5), counts at the live commit

Search roots: `src`, `crates`, `budzero`, `xtask`, `docs`. Whole-word match, all file types. Excludes `bud/` only in the sense that `bud/` is not a search root of the gate; occurrences under `bud/` are therefore not counted here.

| Identifier | Matching lines | Files | Example files |
|---|---|---|---|
| `ContentManifest` | 242 | 40 | `docs/ARCHITECTURE.md`, `docs/BUD_CONTENT_ENCRYPTION.md`, `docs/BUD_STORAGE_ROADMAP.md`, `docs/audit/live/lane-c.md` ... |
| `ErasureScheme` | 113 | 15 | `docs/BUD_STORAGE_ROADMAP.md`, `src/chain/blockchain.rs`, `src/domain/storage_deal.rs`, `src/domain/storage_tx.rs` ... |
| `ReedSolomon` | 28 | 5 | `src/domain/storage_deal.rs`, `src/storage/erasure.rs`, `src/storage/mod.rs`, `src/tests/manifest_commitment_locks.rs` ... |
| `EncodedObject` | 16 | 6 | `src/domain/storage_deal.rs`, `src/domain/storage_tx.rs`, `src/storage/erasure.rs`, `src/storage/mod.rs` ... |
| `LrcLayout` | 37 | 3 | `src/storage/lrc.rs`, `src/storage/mod.rs`, `src/storage/msr.rs` |
| `MsrError` | 12 | 2 | `src/storage/mod.rs`, `src/storage/msr.rs` |
| `StorageRegistry` | 283 | 31 | `crates/ai-inference/crates/ai-knowledge/src/context.rs`, `docs/ARCHITECTURE.md`, `docs/audit/live/lane-a.md`, `docs/audit/live/lane-b.md` ... |
| `StorageDealOpen` | 14 | 4 | `src/domain/mod.rs`, `src/domain/storage_tx.rs`, `src/network/proto_conversions.rs`, `src/tests/storage_tx_door.rs` |
| `OpenDeal` | 15 | 10 | `src/chain/blockchain.rs`, `src/chain/storage_economics_tests.rs`, `src/core/transaction.rs`, `src/domain/storage_tx.rs` ... |
| `AnswerCodingAudit` | 18 | 8 | `docs/audit/live/lane-a.md`, `src/chain/chain_actor.rs`, `src/core/transaction.rs`, `src/domain/storage_deal.rs` ... |
| `AcceptReallocation` | 11 | 7 | `src/chain/storage_economics_tests.rs`, `src/core/transaction.rs`, `src/domain/storage_tx.rs`, `src/rpc/api.rs` ... |
| `OpenChallenge` | 9 | 6 | `src/core/transaction.rs`, `src/domain/storage_tx.rs`, `src/rpc/api.rs`, `src/rpc/method_class.rs` ... |
| `AnswerChallenge` | 13 | 7 | `src/core/transaction.rs`, `src/domain/storage_tx.rs`, `src/rpc/api.rs`, `src/rpc/method_class.rs` ... |
| `StorageProvider` | 9 | 5 | `src/storage/emit.rs`, `src/storage/mod.rs`, `src/storage/provider.rs`, `xtask/gates/src/gates/capability_modules_are_wired.rs` ... |
| `InMemoryStorageProvider` | 20 | 3 | `src/storage/emit.rs`, `src/storage/mod.rs`, `src/storage/provider.rs` |
| `BudStorageEdition` | 47 | 11 | `docs/ARCHITECTURE.md`, `docs/audit/live/lane-b.md`, `src/core/transaction.rs`, `src/domain/storage_deal.rs` ... |
| `GeneratedSpec` | 58 | 10 | `src/domain/deal_open.rs`, `src/domain/storage_deal.rs`, `src/domain/storage_tx.rs`, `src/gateway/service.rs` ... |
| `MobileSelfProfile` | 51 | 13 | `docs/audit/live/lane-b.md`, `src/developer_os.rs`, `src/domain/storage_deal.rs`, `src/domain/storage_tx.rs` ... |
| `MobileSelfContentPolicy` | 28 | 7 | `src/domain/storage_deal.rs`, `src/domain/storage_tx.rs`, `src/network/proto_conversions.rs`, `src/storage/mobile_self.rs` ... |
| `CustodyLedger` | 19 | 4 | `src/storage/mobile_self.rs`, `src/storage/mod.rs`, `src/storage/one_share.rs`, `src/storage/server_admission.rs` |
| `ServerAdmission` | 7 | 3 | `src/storage/mod.rs`, `src/storage/one_share.rs`, `src/storage/server_admission.rs` |
| `OneShareRegistry` | 12 | 3 | `src/storage/mod.rs`, `src/storage/one_share.rs`, `src/storage/one_view.rs` |
| `SingleScreenView` | 14 | 4 | `docs/audit/live/lane-b.md`, `src/storage/mod.rs`, `src/storage/one_share.rs`, `src/storage/one_view.rs` |
| `PactBinding` | 1 | 1 | `src/account_abstraction/quantum_account.rs` |
| `BudBitswap` | 16 | 6 | `budzero/bud-node/src/bitswap.rs`, `budzero/bud-node/src/lib.rs`, `docs/audit/live/lane-b.md`, `src/gateway/service.rs` ... |
| `MemoryContentStore` | 25 | 5 | `budzero/bud-node/src/bitswap.rs`, `budzero/bud-node/src/lib.rs`, `budzero/bud-node/src/store.rs`, `docs/BUD_STORAGE_ROADMAP.md` ... |
| `ContentDiscovery` | 22 | 7 | `budzero/bud-node/src/discovery.rs`, `budzero/bud-node/src/lib.rs`, `budzero/bud-node/src/sharding.rs`, `docs/audit/live/lane-b.md` ... |
| `VideoRecipe` | 16 | 5 | `docs/audit/live/lane-b.md`, `src/storage/emit.rs`, `src/storage/mod.rs`, `src/storage/qr_png.rs` ... |
| `ThreeRecipePublic` | 71 | 14 | `docs/audit/live/lane-b.md`, `src/rpc/server.rs`, `src/storage/mod.rs`, `src/storage/qr_receive.rs` ... |
| `bud_storageOpenDeal` | 4 | 4 | `src/rpc/api.rs`, `src/rpc/method_class.rs`, `src/rpc/server.rs`, `src/storage/README.md` |
| `bud_storageRegisterManifest` | 4 | 4 | `src/rpc/api.rs`, `src/rpc/method_class.rs`, `src/rpc/server.rs`, `src/storage/README.md` |
| `bud_storageQrFeedPreview` | 4 | 4 | `docs/audit/live/lane-b.md`, `src/rpc/api.rs`, `src/rpc/method_class.rs`, `src/storage/qr_verify.rs` |

Path bans from 5.5: `bud/` (exists), `budzero/bud-node/` (exists), `src/domain/storage_deal.rs` (exists), `src/domain/deal_open.rs` (exists), `src/chain/storage_maintenance.rs` (exists).

## 8. Section 5.2 path existence summary

Every "from" path of the 5.2 table exists on live. Target paths that do not exist yet: `src/persistence/`, `src/storage/bud3/`, `src/chain/state_recovery/`, `crates/bud-codec/`, `proto/budlum/storage/v3/bud3.proto`, `docs/STORAGE.md`, `docs/STORAGE_ENCRYPTION.md`. `docs/BUD_STORAGE_ROADMAP.md` and `docs/BUD_CONTENT_ENCRYPTION.md` exist.
