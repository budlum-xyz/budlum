# Storage migration inventory

Snapshot: `20140e87061efc9d8d4076e04305c1318705e348`. Counts cover the working copies of tracked UTF-8 files, including tests, docs, configuration and CI. Untracked files are excluded. Literal mentions are not proof of live callers or deletion safety.

The target B.U.D. 3.0 implementation and each caller must be verified before any deletion. This inventory authorizes no deletion. The storage module also contains `mod.rs` and `README.md`, which are not individual rows in the migration table; review them during migration.

## Move node persistence

| Path | Present |
|---|---|
| `src/storage/db.rs` | yes |
| `src/storage/traits.rs` | yes |
| `src/storage/merkle_trie.rs` | yes |
| `src/storage/pruning.rs` | yes |
| `src/storage/witness_retention.rs` | yes |

## Migrate content storage

| Path | Present |
|---|---|
| `src/storage/content_id.rs` | yes |
| `src/storage/three_recipe.rs` | yes |
| `src/storage/qr_recipe.rs` | yes |
| `src/storage/qr_payload.rs` | yes |
| `src/storage/qr_reemit.rs` | yes |
| `src/storage/qr_carousel.rs` | yes |
| `src/storage/qr_frame.rs` | yes |
| `src/storage/qr_encode.rs` | yes |
| `src/storage/qr_matrix.rs` | yes |
| `src/storage/qr_png.rs` | yes |
| `src/storage/qr_codec.rs` | yes |
| `src/storage/qr_receive.rs` | yes |
| `src/storage/qr_verify.rs` | yes |
| `src/storage/qr_verify_indep.rs` | yes |
| `src/storage/qr_video.rs` | yes |
| `src/storage/emit.rs` | yes |
| `src/storage/three_pipe.rs` | yes |
| `src/storage/three_nft.rs` | yes |
| `src/storage/three_reveal.rs` | yes |
| `src/storage/three_rpc.rs` | yes |
| `src/storage/reveal_gateway.rs` | yes |
| `src/storage/three_gate.rs` | yes |
| `src/storage/three_hooks.rs` | yes |
| `src/storage/three_meter.rs` | yes |
| `src/storage/three_visibility.rs` | yes |
| `src/storage/assignment.rs` | yes |
| `src/storage/dictionary.rs` | yes |
| `src/storage/derived.rs` | yes |
| `src/storage/transformed.rs` | yes |
| `src/storage/living_threshold.rs` | yes |
| `src/storage/key_package.rs` | yes |
| `src/storage/payload_crypt.rs` | yes |
| `src/storage/view_grant.rs` | yes |
| `src/storage/social_delete.rs` | yes |
| `src/domain/storage_tx.rs` | yes |
| `src/gateway/service.rs` | yes |
| `bud/` | yes |
| `docs/BUD_STORAGE_ROADMAP.md` | yes |
| `docs/BUD_CONTENT_ENCRYPTION.md` | yes |

## Remove after replacement

| Path | Present |
|---|---|
| `src/storage/manifest.rs` | yes |
| `src/storage/erasure.rs` | yes |
| `src/storage/lrc.rs` | yes |
| `src/storage/msr.rs` | yes |
| `src/storage/column_commitment.rs` | yes |
| `src/storage/provider.rs` | yes |
| `src/storage/lifecycle.rs` | yes |
| `src/storage/one_share.rs` | yes |
| `src/storage/one_view.rs` | yes |
| `src/storage/mobile_self.rs` | yes |
| `src/storage/server_admission.rs` | yes |
| `src/storage/generated.rs` | yes |
| `src/storage/render.rs` | yes |
| `src/storage/fixed_point.rs` | yes |
| `src/storage/pact_binding.rs` | yes |
| `src/storage/three_regime.rs` | yes |
| `src/domain/storage_deal.rs` | yes |
| `src/domain/storage_params.rs` | yes |
| `src/domain/deal_open.rs` | yes |
| `src/chain/storage_economics_tests.rs` | yes |
| `src/chain/storage_maintenance.rs` | yes |
| `budzero/bud-node/` | yes |

## Move state recovery

| Path | Present |
|---|---|
| `src/domain/regeneration_stage.rs` | yes |
| `src/domain/regen_health.rs` | yes |
| `src/domain/regen_mempool.rs` | yes |
| `src/network/regen_health_tick.rs` | yes |

## Forbidden identifiers

| Identifier | Files | Mentions |
|---|---:|---:|
| `ContentManifest` | 41 | 245 |
| `ErasureScheme` | 18 | 117 |
| `ReedSolomon` | 8 | 39 |
| `EncodedObject` | 8 | 18 |
| `LrcLayout` | 4 | 38 |
| `MsrError` | 4 | 14 |
| `StorageRegistry` | 30 | 284 |
| `StorageDealOpen` | 5 | 15 |
| `OpenDeal` | 11 | 17 |
| `AnswerCodingAudit` | 8 | 20 |
| `AcceptReallocation` | 8 | 13 |
| `OpenChallenge` | 7 | 11 |
| `AnswerChallenge` | 8 | 15 |
| `StorageProvider` | 7 | 14 |
| `InMemoryStorageProvider` | 4 | 22 |
| `BudStorageEdition` | 11 | 50 |
| `GeneratedSpec` | 11 | 59 |
| `MobileSelfProfile` | 13 | 52 |
| `MobileSelfContentPolicy` | 8 | 29 |
| `CustodyLedger` | 5 | 20 |
| `ServerAdmission` | 4 | 9 |
| `OneShareRegistry` | 5 | 15 |
| `SingleScreenView` | 4 | 15 |
| `PactBinding` | 2 | 2 |
| `BudBitswap` | 6 | 16 |
| `MemoryContentStore` | 5 | 26 |
| `ContentDiscovery` | 7 | 23 |
| `VideoRecipe` | 5 | 19 |
| `ThreeRecipePublic` | 14 | 71 |
| `bud_storageOpenDeal` | 5 | 6 |
| `bud_storageRegisterManifest` | 5 | 6 |
| `bud_storageQrFeedPreview` | 4 | 5 |

## Legacy transaction variants

| Identifier | Files | Mentions |
|---|---:|---:|
| `RegisterManifest` | 13 | 36 |
| `DeclareOperatorClass` | 7 | 15 |
| `DeclareSelfHostPolicy` | 6 | 11 |
| `OpenDeal` | 11 | 17 |
| `AnswerCodingAudit` | 8 | 20 |
| `AcceptReallocation` | 8 | 13 |
| `OpenChallenge` | 7 | 11 |
| `AnswerChallenge` | 8 | 15 |
| `CommitConfidentialBody` | 5 | 7 |
| `IssueViewGrant` | 5 | 13 |
| `RevokeViewGrant` | 4 | 12 |
| `SocialDelete` | 4 | 12 |

## Legacy RPC names

| Identifier | Files | Mentions |
|---|---:|---:|
| `bud_storageAcceptReallocation` | 5 | 5 |
| `bud_storageActiveOperators` | 5 | 5 |
| `bud_storageAnswerChallenge` | 5 | 5 |
| `bud_storageGetChallenges` | 4 | 4 |
| `bud_storageGetConfidentialCommit` | 3 | 3 |
| `bud_storageGetDealsByManifest` | 5 | 5 |
| `bud_storageGetDealsByShard` | 6 | 6 |
| `bud_storageGetEconomicsEvents` | 4 | 4 |
| `bud_storageGetEconomicsSummary` | 4 | 4 |
| `bud_storageGetManifest` | 6 | 6 |
| `bud_storageGetOperatorEconomics` | 4 | 4 |
| `bud_storageGetOutcome` | 4 | 5 |
| `bud_storageOpenChallenge` | 6 | 6 |
| `bud_storageOpenDeal` | 5 | 6 |
| `bud_storageRegisterConfidentialCommit` | 4 | 4 |
| `bud_storageRegisterManifest` | 5 | 6 |
| `bud_storageRepairBand` | 4 | 5 |
| `bud_storageVerifyEncoding` | 3 | 3 |
| `bud_storageQrFeedFrames` | 3 | 3 |
| `bud_storageQrFeedPreview` | 4 | 5 |

## Limitations

A token count can include comments, tests and unrelated names. It does not find aliases, dynamic dispatch, generated code or external consumers. The `three_meter.rs` row is absent on this snapshot; do not infer that its function is unnecessary. Inspect callers and replacement paths separately before each migration.
