# Legacy storage inventory (WP-02)

WP-02 (WP-02) requires this file: every file, type and RPC method the
binding directive section 5 removes or migrates, checked against the live
tree. English per `tree_is_english`.

## Verification base

Repository snapshot `HEAD` = `cccf1da` (`main`). This snapshot includes the
merged consolidation (PR #5) and the A0 codec register (PR #6) but **not**
the WP-07 removal: PR #8 (`arena/b7784c85-budlum`) carries the removal in
flight ("The bud tree shrinks to the adopted lossless codecs", the storage
tree cleanup and the bud-node deletion). Every entry below is therefore
recorded as **present**; the inventory is regenerated when PR #8 merges and
the `no_legacy_storage` gate goes green (that gate does not exist yet this
pass - see "Gates" below).

## 5.2 File-level decision table, checked live

| Path | Decision (directive 5.2) | Live status | Closing findings |
|---|---|---|---|
| `src/storage/db.rs` | Tasi | present | WP-06 sonrasi WP-17 kapsami |
| `src/storage/traits.rs` | Tasi | present | WP-06 sonrasi WP-17 kapsami |
| `src/storage/merkle_trie.rs` | Tasi | present | WP-06 sonrasi WP-17 kapsami |
| `src/storage/pruning.rs` | Tasi | present | WP-06 sonrasi WP-17 kapsami |
| `src/storage/witness_retention.rs` | Tasi | present |  |
| `src/storage/content_id.rs` | Goc | present | BLG-073 (uclu `content_id` uyumsuzlugu) |
| `src/storage/manifest.rs` | Sil | present | BLG-047, BLG-109, BLG-168 |
| `src/storage/lrc.rs` | Sil | present | BLG-049, BLG-089, BLG-144, BLG-220 |
| `src/storage/erasure.rs` | Sil | present | BLG-049, BLG-089, BLG-144, BLG-220 |
| `src/storage/msr.rs` | Sil | present | BLG-049, BLG-089, BLG-144, BLG-220 |
| `src/storage/column_commitment.rs` | Sil | present | BLG-049, BLG-089, BLG-144, BLG-220 |
| `src/storage/lifecycle.rs` | Sil | present | BLG-045, BLG-046 |
| `src/storage/provider.rs` | Sil | present | BLG-045, BLG-046 |
| `src/storage/one_share.rs` | Sil | present | BLG-049 (`OneShare` kota atlatmasi) |
| `src/storage/one_view.rs` | Sil | present | BLG-049 (`OneShare` kota atlatmasi) |
| `src/storage/server_admission.rs` | Sil | present | BLG-253 |
| `src/storage/mobile_self.rs` | Sil | present | BLG-253 |
| `src/storage/render.rs` | Sil | present | BLG-048, BLG-208 |
| `src/storage/generated.rs` | Sil | present | BLG-048, BLG-208 |
| `src/storage/fixed_point.rs` | Sil | present | BLG-048, BLG-208 |
| `src/storage/pact_binding.rs` | Sil | present |  |
| `src/storage/three_regime.rs` | Sil | present | BLG-209 |
| `src/storage/qr_reemit.rs` | Goc | present | BLG-210, BLG-211 |
| `src/storage/qr_recipe.rs` | Goc | present | BLG-210, BLG-211 |
| `src/storage/qr_payload.rs` | Goc | present | BLG-210, BLG-211 |
| `src/storage/three_recipe.rs` | Goc | present | BLG-210, BLG-211 |
| `src/storage/qr_carousel.rs` | Goc | present | BLG-049, BLG-216 |
| `src/storage/qr_codec.rs` | Goc | present | BLG-214 |
| `src/storage/qr_png.rs` | Goc | present | BLG-214 |
| `src/storage/qr_matrix.rs` | Goc | present | BLG-214 |
| `src/storage/qr_video.rs` | Goc | present | BLG-214 |
| `src/storage/qr_frame.rs` | Goc | present | BLG-214 |
| `src/storage/qr_encode.rs` | Goc | present | BLG-214 |
| `src/storage/qr_verify.rs` | Goc | present | BLG-214 |
| `src/storage/qr_receive.rs` | Goc | present | BLG-214 |
| `src/storage/qr_verify_indep.rs` | Goc | present | BLG-214 |
| `src/storage/three_pipe.rs` | Goc | present | BLG-213, BLG-218 |
| `src/storage/emit.rs` | Goc | present | BLG-213, BLG-218 |
| `src/storage/three_nft.rs` | Goc | present | BLG-212 |
| `src/storage/reveal_gateway.rs` | Goc | present | BLG-125 |
| `src/storage/three_rpc.rs` | Goc | present | BLG-125 |
| `src/storage/three_reveal.rs` | Goc | present | BLG-125 |
| `src/storage/three_meter.rs` | Goc | present |  |
| `src/storage/three_gate.rs` | Goc | present |  |
| `src/storage/three_visibility.rs` | Goc | present |  |
| `src/storage/three_hooks.rs` | Goc | present |  |
| `src/storage/assignment.rs` | Goc | present | BLG-047 (`assign_shard`) |
| `src/storage/dictionary.rs` | Goc | present | BLG-141, BLG-222 |
| `src/storage/derived.rs` | Goc | present | BLG-222 |
| `src/storage/transformed.rs` | Goc | present | BLG-219 |
| `src/storage/living_threshold.rs` | Goc | present | BLG-222 |
| `src/storage/payload_crypt.rs` | Goc | present | BLG-049 (`ViewGrant` epoch-0), BLG-125 |
| `src/storage/key_package.rs` | Goc | present | BLG-049 (`ViewGrant` epoch-0), BLG-125 |
| `src/storage/social_delete.rs` | Goc | present | BLG-049 (`ViewGrant` epoch-0), BLG-125 |
| `src/storage/view_grant.rs` | Goc | present | BLG-049 (`ViewGrant` epoch-0), BLG-125 |
| `src/domain/storage_params.rs` | Sil | present | BLG-045, BLG-046, BLG-047, BLG-102, BLG-183 |
| `src/domain/deal_open.rs` | Sil | present | BLG-045, BLG-046, BLG-047, BLG-102, BLG-183 |
| `src/domain/storage_deal.rs` | Sil | present | BLG-045, BLG-046, BLG-047, BLG-102, BLG-183 |
| `src/domain/storage_tx.rs` | Goc | present | BLG-183 |
| `src/chain/storage_economics_tests.rs` | Sil | present | BLG-041 (`run_storage_maintenance`) |
| `src/chain/storage_maintenance.rs` | Sil | present | BLG-041 (`run_storage_maintenance`) |
| `src/domain/regeneration_stage.rs` | Tasi ve yeniden adlandir | present |  |
| `src/domain/regen_health.rs` | Tasi ve yeniden adlandir | present |  |
| `src/network/regen_health_tick.rs` | Tasi ve yeniden adlandir | present |  |
| `src/domain/regen_mempool.rs` | Tasi ve yeniden adlandir | present |  |
| `src/gateway/service.rs` | Goc | present | BLG-032, BLG-262 |
| `budzero/bud-node/` | Sil | present | BLG-035, BLG-258 |
| `bud/` | Goc ve sil | present | BLG-073 ile BLG-080, BLG-142 ile BLG-145, BLG-217 |
| `docs/BUD_CONTENT_ENCRYPTION.md` | Goc | present |  |
| `docs/BUD_STORAGE_ROADMAP.md` | Goc | present |  |

All 70 decision-table paths are present in this snapshot. No deletion has
landed. The removal order (WP-06 move, then WP-07 delete, then WP-10/WP-18
to WP-25 rebuild) is unchanged: PR #8 carries WP-06 (persistence move) and
WP-07 (bud tree shrink) on top of PR #5.

## 5.3 RPC methods slated for deletion, checked live

All 20 methods below were found in this snapshot (fixed-string scan across
`src/`, `proto/`, `xtask/`, `docs/`; counts include docs and code):

| Method | Files with a mention |
|---|---|
| bud_storageAcceptReallocation | 4 |
| bud_storageActiveOperators | 4 |
| bud_storageAnswerChallenge | 4 |
| bud_storageGetChallenges | 3 |
| bud_storageGetConfidentialCommit | 2 |
| bud_storageGetDealsByManifest | 4 |
| bud_storageGetDealsByShard | 5 |
| bud_storageGetEconomicsEvents | 3 |
| bud_storageGetEconomicsSummary | 3 |
| bud_storageGetManifest | 5 |
| bud_storageGetOperatorEconomics | 3 |
| bud_storageGetOutcome | 3 |
| bud_storageOpenChallenge | 5 |
| bud_storageOpenDeal | 4 |
| bud_storageRegisterConfidentialCommit | 3 |
| bud_storageRegisterManifest | 4 |
| bud_storageRepairBand | 3 |
| bud_storageVerifyEncoding | 2 |
| bud_storageQrFeedFrames | 2 |
| bud_storageQrFeedPreview | 3 |

`src/rpc/server.rs` still dispatches `bud_storageRegisterManifest`
(`require_operator` at line 3528), `bud_storageOpenDeal` (line 4218) and
`bud_storageAnswerChallenge` (line 4482). None of these may survive WP-07.
The method tables (`src/rpc/method_class.rs`) must shrink in the same PR
that removes the handlers (directive 5.3.7).

## 5.5 `no_legacy_storage` forbidden identifiers, usage scan

Usage counts (files mentioning the identifier, this snapshot). `no_legacy_storage`
itself does not exist yet; this list and these counts are WP-07's input.

| Identifier | Files | | Identifier | Files |
|---|---|---|---|---|
| ContentManifest | 40 | | StorageProvider | 6 |
| ErasureScheme | 16 | | InMemoryStorageProvider | 4 |
| ReedSolomon | 6 | | BudStorageEdition | 10 |
| EncodedObject | 6 | | GeneratedSpec | 12 |
| LrcLayout | 3 | | MobileSelfProfile | 13 |
| MsrError | 2 | | MobileSelfContentPolicy | 7 |
| StorageRegistry | 30 | | CustodyLedger | 4 |
| StorageDealOpen | 4 | | ServerAdmission | 3 |
| OpenDeal | 11 | | OneShareRegistry | 3 |
| AnswerCodingAudit | 8 | | SingleScreenView | 3 |
| AcceptReallocation | 8 | | PactBinding | 1 |
| OpenChallenge | 10 | | BudBitswap | 5 |
| AnswerChallenge | 8 | | MemoryContentStore | 4 |
| VideoRecipe | 6 | | ContentDiscovery | 6 |
| ThreeRecipePublic | 13 | | | |

Path bans (directive 5.5): `bud/` (present), `budzero/bud-node/` (present),
`src/domain/storage_deal.rs` (present), `src/domain/deal_open.rs` (present),
`src/chain/storage_maintenance.rs` (present).

## Gates slated for change (5.4), checked live

Still present (to be deleted/rewritten by WP-07):

- `three_is_recipe_only`, `zero_storage_frozen`, `generated_content`,
  `qr_is_derivative_only`, `storage_priced`, `storage_provider_gate`,
  `storage_proof_boundary`, `coding_audit_samples_the_relationship`,
  `paid_content`, `shard_placement`, `repair_fires`,
  `storage_penalties`, `content_encryption_is_declared_and_bound`,
  `derived_content` (keep, WP-24), `bud_e2e`, `regeneration`,
  `zkvm_immune_regeneration`, `regen_health_door`
  (to rename: `canonical_programs_reproduce`, `zkvm_refuses_untrusted_proofs`,
  `state_recovery_door`).

Missing (to be added by WP-07): `no_legacy_storage`, `bud3_custody_proofs`,
`bud3_paid_view`, `bud3_placement`, `bud3_repair_fires`, `bud3_custody_rewards`,
`bud3_object_is_universal`, `bud3_qr_is_presentation`,
`bud3_fee_uses_physical_bytes`. Already present (landed with the
consolidation, PR #5): `bud3_forbidden_phrases`.

`storage_proof_boundary.rs` and `paid_content.rs` are present under
`xtask/gates/src/gates/` this pass (142 gate files total). WP-07 deletes
them and rewires (`gates_are_wired`) in the same PR.

## 5.6 Dependent modules, checked live

| Module | Live anchor | Status |
|---|---|---|
| BNS (`src/bns/`) | `BnsSetContent` / `BnsSetStorage` present | pending WP-23 |
| SocialFi (`src/socialfi/`) | `src/socialfi/` present | pending WP-23 |
| Data market (`src/pollen/`) | `src/pollen/` present | pending WP-23 |
| Deeds (`src/deed/`) | `src/deed/` present | pending WP-23 |
| Content gateway (`src/gateway/service.rs`) | present | pending WP-23; WP-07 migrates it |
| AI input reference (`src/ai_inference/storage.rs`) | present | pending WP-45 |
| Wallet core and CLI | 2.0 RPC calls present in `src/rpc/server.rs` | pending WP-39 |
| Explorer (`crates/budscan`) | present | pending WP-40 |

## How to read this file after merges

When PR #8 merges, every row above flips to ABSENT/migrated and this file is
regenerated in the same PR or by WP-07's follow-up. A row that stays present
after WP-07's `no_legacy_storage` gate is green is a failed removal, not an
accepted exception.
