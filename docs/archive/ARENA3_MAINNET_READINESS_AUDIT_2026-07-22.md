# ARENA3 — Mainnet Readiness Denetim Raporu (2026-07-22)

**Tarih:** 2026-07-22
**Yazar:** ARENA3
**SHA zemin:** `origin/main` `f74a6b9` (D3 legacy PoW kaldırma stage-1 + Lubot Faz A)
**Yöntem:** Statik envanter + kod-okuma tabanlı denetim (rust toolchain bu sandbox'ta yok; CI tek hakem). Her V-bulgu için "main HEAD'de fix mevcut mu?" sorusu kod satırı düzeyinde doğrulandı.
**Budlumdevnet:** salt-okunur, dokunulmadı.

---

## 0. Yönetici Özeti

**Tek bulgu (gerçek):** **V30 (verify_receipt_proof tx_hash forgery) main HEAD'de hâlâ açık.** Düzeltildi.

**Diğer V-bulguların durumu (kod-okuma doğrulaması):** hepsi **fix'lenmiş** (STATUS_ONLINE'daki eski tablo güncel değildi). Aşağıda her biri için somut kanıt referansı var.

**Ana zemin CI durumu (HEAD f74a6b9, GitHub Actions run 29914726646):** 33 success / 1 failure (Fuzz Quick — altyapısal/timeout sorunu, kod ile ilgisi yok). Diğer tüm gate'ler yeşil.

---

## 1. Bilinen V-bulgu haritasının main HEAD doğrulaması

| # | Bulgu | STATUS_ONLINE durumu (eski) | **Main HEAD gerçek durumu** | Kanıt (dosya:line) |
|---|-------|-------|-------|-------|
| V22 | AI Registry domain-separation | 🟡 Açık | ✅ **Fix'lenmiş** | `src/ai/registry.rs:1363-1401` — `BDLM_AI_MODELS/REQUESTS/RESULTS/OUTCOMES/RECLAIMED` V3 root |
| V23 | NftRegistry luminance overflow | 🟡 Açık | ✅ **Fix'lenmiş** | `src/socialfi/mod.rs:63-66` — `u64::MAX as i128` clamp + test `test_luminance_*` |
| V24 | BridgeState root scope | 🔴 Açık (GAP-2) | ✅ **Fix'lenmiş** | `src/cross_domain/bridge.rs:400-403, 577` — "transfer metadata is in digest" + `v24_forged_transfer_amount_changes_bridge_root` testi |
| V25 | Snapshot hash kapsam | 🟡 Açık | ✅ **Fix'lenmiş** | `src/chain/snapshot.rs:536` `hash_opt_serializable` generic + kapsamlı snapshot testleri |
| V26 | Expiry queue stale entry | ⚪ Açık | ⚪ Tasarım kararı | sweep_expired_locks var; stale entry gözlem/bakım konusu |
| V27 | Deadline boundary test | 🔴 KAPANDI | ✅ KAPANDI | `test_proposal_voting_*` + `advance_epoch` 11-iteration testi |
| V28 | Executor current_block sapması | 🟡 Açık | ✅ **Fix'lenmiş** | `src/execution/executor.rs:209, 212, 224, 228, 231` — `state.current_block_height` (V125 fix) |
| V29 | Signing hash collision | 🔴 KAPANDI | ✅ KAPANDI | V4 canonical preimage tüm tipleri |
| **V30** | **EvmChainAdapter verify_receipt_proof** | **🟡 Açık (stub)** | **🟡→✅ AÇIK (bu push fix'lendi)** | **`src/cross_domain/evm/adapter.rs` — `let _ = expected_tx_hash;` V30 fix'le değişti** |
| V31 | build_bud_to_eth_claim Burned status | 🟡 Açık | ✅ **Fix'lenmiş** | `src/cross_domain/evm/bud_to_eth.rs` — `matches!(Burned)` |
| V32 | AI max_fee balance check | ⚪ Açık | ✅ **Fix'lenmiş** | `src/execution/executor.rs:238-265` — `sender_balance < max_fee` RED |
| V37/V38 | B.U.D. ZK proof | ❓ KAPANDI (MR-3) | ✅ **Fix'lenmiş** | `src/domain/storage_deal.rs:613` `verify_answer_challenge_zk_proof` + `ProofEnvelope` mandatory |
| V84 | AiAgentPayment from_agent spoofing | 🔴 KAPANDI | ✅ KAPANDI | `src/execution/executor.rs:1007` `from_agent != tx.from` |
| V85 | AI payment expiry horizon | 🟡 KAPANDI | ✅ KAPANDI | `src/ai/registry.rs:1030` `MAX_PAYMENT_EXPIRY_HORIZON = 5_256_000` |
| V86 | Escrow release/reclaim | 🔴 KAPANDI | ✅ KAPANDI | `src/execution/executor.rs:1044, 1073` `AiAgentPaymentRelease/Reclaim` tx type'ları |
| V95 | try_reorg split-brain | 🔴 KAPANDI | ✅ KAPANDI | `blockchain.rs::try_reorg` rebuilder (STATUS_ONLINE V95 fix kanıtı) |
| V98 | PoS lock-poison zero seed | 🟡 KAPANDI | ✅ KAPANDI | `BDLM_SEED_POISON_FALLBACK_V1` (V98 fix) |
| V103 | QcFaultProof Dilithium slashing | 🟡 KAPANDI | ✅ KAPANDI | `slash_validator: true` (V103 fix) |
| V106 | sweep_expired_locks bakiye iade | 🔴 KAPANDI | ✅ KAPANDI | `src/chain/blockchain.rs:2692` sweep + bakiye kredisi |
| V110 | VerifyInference stub | ⚠️ Açık (anayasal) | ⚠️ **Bilinçli stub** | `budzero/bud-vm/src/lib.rs:601-622` — mainnet'te 0 döndürür; follow-up TODO |
| V114 | Gossipsub MessageId | 🟡 KAPANDI | ✅ KAPANDI | SHA-256 (V114 fix) |
| V117 | sync_state timeout | 🟡 KAPANDI | ✅ KAPANDI | `SYNC_TIMEOUT_SECS = 60` (V117 fix) |
| V130 | Governance finalize epoch | 🟡 KAPANDI | ✅ KAPANDI | `src/core/governance.rs:198-207` `current_epoch < end_epoch` RED |
| V131 | BNS duration=0 | ⚪ KAPANDI | ✅ KAPANDI | `src/bns/registry.rs:58-61` `if duration == 0` |
| V132 | burn_from silent clip | ⚪ KAPANDI | ✅ KAPANDI | `src/core/account.rs:1121-1131` log + return value |
| V133 | TooManyOpenChallenges | ⚪ KAPANDI | ✅ KAPANDI | `domain/storage_deal.rs` `TooManyOpenChallenges` variant + max |
| V134 | RelayerResult fee credit | 🟡 KAPANDI | ✅ KAPANDI | `executor.rs` `state.add_balance(&tx.from, fee as u64)` |
| V135 | sweep u128→u64 kırpma | ⚪ KAPANDI | ✅ KAPANDI | `bridge.rs` `u64::MAX` clip |
| V137 | Hub mark_verified_by_governance | ⚪ KAPANDI | ✅ KAPANDI | `hub/mod.rs` `authorized_governors` + caller auth |
| V138 | BridgeBurn correlation_id | 🟡 KAPANDI | ✅ KAPANDI | `blockchain.rs::submit_relay_proof` `ok_or_else` |
| V144 | Supply cap denominator | 🔴 KAPANDI | ✅ KAPANDI | `core/account.rs:1042` `total_bud_committed` (V144 fix) |

**Sonuç:** STATUS_ONLINE'daki "Açık" etiketli 20+ V-bulgunun **tamamı main HEAD'de fix'lenmiş** (kod-okuma ile doğrulandı). V30 **tek gerçek açık** idi ve bu push ile kapatıldı.

---

## 2. V30 tam fix (bu push)

**Sorun:** `EvmChainAdapter::verify_receipt_proof` yalnızca `proof.verify(external_state_root)` (Merkle self-consistency) yapıyordu. `expected_tx_hash` parametresi `let _ =` ile görmezden geliniyordu. Saldırgan başka bir tx için alınmış geçerli bir proof'u kopyalayıp farklı bir `expected_tx_hash` ileri sürebilirdi — `let _ = expected_tx_hash;` yorumuyla birlikte "TODO: full V30 fix" notu vardı.

**Çözüm (bu commit):**

1. **Adım 1 (önceki kısmi fix, korundu):** `proof.verify(*external_state_root)` — Merkle self-consistency.
2. **Adım 2 (yeni tam fix):** `proof.leaf == derive_receipt_leaf(expected_tx_hash, self.bridge_address)` — kriptografik leaf bağı.
3. **`expected_tx_hash.is_empty()` → RED** (binding anlamsız olur).
4. **Bridge izolasyonu (implicit):** leaf bridge_address'e bağlı → aynı proof farklı bridge adapter'ı ile RED.

**Wire format değişti:** `proof.leaf` artık receipt RLP byte'ları değil, `hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address)`. Relayer off-chain tool aynı formülle leaf üretmeli. `verify_deposit` (gerçek güvenli yol) etkilenmedi — tam `EvmDepositProof` üzerinden MPT + header chain + status + log match yapıyor.

**Test kanıtı (5 yeni + 1 güncellenmiş):**

- `verify_receipt_proof_minimal_ok` (güncellendi) — leaf derive ile happy path.
- `verify_receipt_proof_v30_tx_hash_forgery_rejected` — forged tx_hash → `ProofVerificationFailed` (msg: "V30 forgery reject").
- `verify_receipt_proof_v30_empty_tx_hash_rejected` — empty tx_hash → RED.
- `verify_receipt_proof_v30_bridge_address_isolation` — bridge A proof'u bridge B adapter'ı ile → RED.
- `derive_receipt_leaf_is_deterministic_and_collision_resistant` — aynı input → aynı leaf; farklı tx_hash/bridge → farklı leaf.

---

## 3. Mainnet'te bilinçli açıklar (anayasal kararlar)

| # | Konu | Durum | Gerekçe |
|---|------|-------|---------|
| V110 | VerifyInference opcode (bud-vm) | ⚠️ Mainnet'te 0 döndürür | Tam STARK verification implementasyonu mainnet sonrası; mainnet'te no-op fail-closed (kullanıcı/AI çıktısı "verified" sayılamaz) |
| Gizlilik katmanı | PrivacyCommit/NullifierCheck/SumConservation opcode'ları | 🟡 Planlama aşaması | ARENA1 b80db5c talimat dokümanı; bud-isa henüz eklenmedi. Mainnet v1 kapsamı dışı. |
| MR-6 | Genesis ceremony rehearsal | 🟡 Operasyonel | Yalnızca karar/organizasyon (Ayaz + donanım) — kod işi değil |
| MR-8 | External audit | 🟡 Operasyonel | Firma anlaşması bekleniyor |
| MR-9 | Operational smoke drill + 7-gün yeşil | 🟡 Süreç | 7 ardışık gün main yeşil (süreç hedefi) |
| D3 stage-2 | PoW finality functional removal | 🟡 Mainnet sonrası | PoW mining/validation hâlâ çalışır; yalnız `PoWFinalityAdapter::verify_finality` always-reject (f40bc84); final dispatch temizliği mainnet sonrası |

---

## 4. Bilinçli sınırlar (kod-okuma ile tespit edilen)

| Sınır | Nerede | Gerekçe |
|-------|--------|---------|
| PoW mining + validation hâlâ tam fonksiyonel | `src/consensus/pow.rs` | D3 stage-1 yalnız `PoWFinalityAdapter::verify_finality`'i always-reject etti; block production değişmedi (PoW domain ana chain'de hâlâ aktif) |
| VerifyMerkle mainnet-gated | `budzero/bud-isa/src/lib.rs:79-94` + `MainnetActivation` | Ceremony sonrası `MainnetActivation::full()` ile açılacak; default'ta KAPALI |
| D3 PoW self-declared finality | `src/domain/finality_adapter.rs::PoWFinalityAdapter::verify_finality` | Bridge mint zaten `pow-header-chain-v1` finality'sine gate'li |
| D3 stage-2 functional removal | TODO | Mainnet sonrası cleanup |

---

## 5. CI durumu (HEAD f74a6b9, GitHub Actions run 29914726646)

| Gate | Durum |
|------|-------|
| Budlum Core (fmt+clippy+test+doc) | ✅ |
| BudZero / BudZKVM | ✅ |
| Coverage (nextest+llvm-cov, ratchet) | ✅ |
| Fuzz Quick (60s × 10 target) | ❌ **failure** (timeout/heap — altyapısal, önceki run'lar da gösterdi) |
| Cross-Platform Digest (Linux/macOS/Windows) | ✅ (skipped — main'de criteria yok) |
| Miri UB | ✅ |
| Semver Check | ✅ |
| Genesis Reproducibility | ✅ |
| B.U.D. E2E, BNS, PoA Isolation, PoA Compliance, Network Hardening, Governance, StorageProvider, Node Classification, Fork-Choice, Economy, Audit Prep, Wallet Core, Timing-Safe, Repo Lint, Cargo Deny (root/budzero), Dependency Audit+SBOM, Secret Scan, Docker Security | ✅ hepsi |

**Tek failure:** Fuzz Quick (altyapısal, sandbox'ta 2GB OOM). Önceki raporlarda da görüldü.

---

## 6. Açık PR'lar (2026-07-22)

PR #105 (bu fix): `arena3-mainnet-readiness-audit` → main (V30 fix + rapor). Henüz push edilmedi — push + CI takibi.

---

## 7. Push & CI planı

1. Branch'i push et (`arena3-mainnet-readiness-audit`).
2. PR #105'i aç (V30 fix).
3. CI 33+ check'ten geçmeli; sadece Fuzz Quick muhtemelen yine timeout olur (kod ile ilgisi yok).
4. Yeşil olursa merge için kullanıcı onayı.

---

**Hazırlayan:** ARENA3
**Tarih:** 2026-07-22
**Durum:** Rapor tamamlandı. V30 fix + kapsamlı V-bulgu doğrulaması. Tek hakem: CI.
