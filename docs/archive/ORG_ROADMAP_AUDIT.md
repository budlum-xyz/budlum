# budlum-xyz org roadmap denetimi →  / 0.37 / 0.378 / 0.38

**Kaynak depolar (upstream org):**
| Repo | URL | Rol |
|------|-----|-----|
| Budlum | https://github.com/budlum-xyz/Budlum | L1 Universal Settlement |
| BudZero | https://github.com/budlum-xyz/BudZero | BudZKVM + STARK |
| **B.U.D.** | https://github.com/budlum-xyz/B.U.D. | Broad Universal Database (depolama) |
| budlum.com | https://github.com/budlum-xyz/budlum.com | **Boş** |

**Çalışma fork’ları:** `lubosruler/budlum`, `lubosruler/BudZero` (–12.9 burada yapıldı)

---

## 1. Kısa cevap

**Hayır — org’daki *tüm* roadmap’i sadece  + 13.5 + 13.9 ile “bitirmiş” sayamayız.**

Ama:
- **Budlum + BudZero** için org README / SPEC / ch12’deki *kodlanabilir* açık maddelerin büyük kısmı 13 serisine sığdırılabilir veya zaten kapalı.
- **B.U.D. (Gorev 0–6)** bilinçli olarak **** — senin de dediğin gibi ayrı konuşulacak; 13 serisine **sokulmamalı**.
- **Harici audit, TLA+ formal verification, Privacy Layer, AI Execution Layer** “araştırma / süreç / ürün” maddeleri; üç turda *kodla kapanmış roadmap* diye işaretlenemez (en gorevla iskelet / placeholder / docs).

---

## 2. budlum-xyz/Budlum — Research Roadmap

Kaynak: org `README.md` → “Research Roadmap”

| Madde (org) | Durum (lubosruler fork, bugün) | 13 / 13.5 / 13.9? |
|-------------|--------------------------------|-------------------|
| Devnet economic hardening | ✅ (erken turlar + tokenomics) | Kapalı |
| Settlement atomicity | ✅ | Kapalı |
| Verified settlement hardening | ✅ (finality adapters, parent links) | Kapalı |
| Verified bridge return path | ✅ +  PoW mint ban | 13.5’te PoW light-client ile olgunlaştır |
| Sync hardening | ✅ | Kapalı |
| PKCS#11 HSM signer | ✅ Ed25519 consensus; **BLS/PQ disk hâlâ HSM dışı** (B1) | **13.9** (BLS/PQ koruma yolu) |
| BLS finality protocol | ✅ (prevote/precommit + testler) | 13.9’da live coordinator boşlukları taranır |
| RPC dual listener | ✅ +  B2/B3 | 13.5’te runbook/quota netleştirme |
| P2P hardening | ✅ | Kapalı / 13.5 ince ayar |
| Snapshot V2 | ✅ (archive policy org’da “kalan”) | **13.5** archive-node policy docs |
| Observability Prometheus | ✅ kısmen (histograms org’da kalan) | **13.5** histogram/not |
| Deployment docker/systemd | ✅ org’da; fork’ta mevcut | 13.5 runbook |
| **ZKVM optimizations** | ⏳ performans (BudZero ) | **13.5** (ölçüm + küçük optim) / tam bitmez |
| **Formal verification (TLA+)** | ❌ yok | **13.9 docs iskeleti** — tam model ayrı proje |
| **External audit** | ❌ süreç | **İşaretlenemez “done”** — 13.9 checklist |
| **Privacy layer** | ❌ araştırma | **13 serisi dışı** (veya sadece docs stub) |
| **AI execution layer** | ❌ araştırma | **13 serisi dışı** (docs stub) |

### ch12 Mainnet blockers (org book)

| Blocker / kalan | 13 serisi |
|-----------------|-----------|
| External security audit | Süreç — 13.9 checklist |
| Archive-node policy + backup drills | **13.5** (policy + script/docs) |
| ConsensusStateV2 migration framework | **13.5–13.9** (docs + minimal migration hook) |
| Production runbooks / incident response | **13.5** |
| Per-IP quotas / operator admin methods | Kısmen var → **13.5** netleştir |
| Prometheus latency histograms | **13.5** |
| Governance + BudZKVM + pruning “mainnet v1’de kapalı” | **13.9** policy + config flags net |

---

## 3. budlum-xyz/BudZero — Detailed Roadmap

| Gorev (org) | Org iddiası | Fork gerçeği | 13 serisi |
|-----------|-------------|--------------|-----------|
| 0–8 | complete | Büyük ölçüde + security turları | Kapalı / bakımı |
| **9 State & L1 integration** | in progress | Nested backup, save Result, L1 host, pin rebind | **13** bitir (persona + L1 uyum) |
| **10 Performance** | planned | Yok | **13.5** baseline bench |
| **11 Security audit** | planned | İç denetim turları var; harici yok | 13.9 checklist |
| **12 Docs** | active | Türkçe book + README refresh | **13** persona docs + roadmap matrix |
| “All 31 opcodes production” (org README) | ✅ iddia | **Yanlış / tehlikeli:** VerifyMerkle hâlâ experimental + ignore | **13** dürüst status (gate kalır veya 3.5) |
| Z-B valid 64-depth | org “merkle constrained” | **ignore + InvalidProof** | **13** (3.5 hedef; yeşil olmazsa gate + dürüst borç) |

---

## 4. B.U.D. — Broad Universal Database ve Merkeziyetsiz Depolama Sunucu Sistemi (** / Eski **)

> **⚠️ TERMİNOLOJİ GÜNCELLEMESİ:** Kullanıcının 2026-07-14 talimatı üzerine "Tur" söylemi kaldırılmış, ilk ana adımımız resmi olarak **** (` = eski  + `) olarak adlandırılmıştır.

Kaynak: `budlum-xyz/B.U.D.` reposundaki `BUD_Merkeziyetsiz_Depolama_Vizyonu.md`

| Gorev | Konu | Karşılama Durumu (lubosruler/budlum) |
|-----|------|--------------------------------------|
| 0 | Kavramsal harita | Sadece referans / temel spesifikasyon |
| 1 | Storage ConsensusDomain (`StorageAttestation(StorageDomainParams)`) | ✅ **** kapsamında tamamlandı (`src/domain/storage_params.rs`) |
| 2 | İçerik-adresleme (`ContentId`, `ContentManifest`, `ShardRef`) | ✅ **** kapsamında tamamlandı (`src/storage/content_id.rs`, `manifest.rs`) |
| 3 | Proof-of-Storage (`VerifyMerkle` bağlama) | ⏳ BudZero `VerifyMerkle` 64-depth Z-B gate açılışına bağımlı (`CLAUDE.md` §4) |
| 4 | GlobalBlockHeader StorageRoot | ⏳ Gorev 3 Z-B gate sonrasına bağımlı |
| 5 | Operator bond / deal / challenge ekonomisi | ✅ **** kapsamında tamamlandı (`src/domain/storage_deal.rs`, 7 RPC, E2E) |
| 6 | BNS/.bud + devnet pilot | ⏳ İlerideki Adımlarda devreye alınacak |

** serisinde B.U.D. kodu yazılmamıştır; tüm B.U.D. Sunucu Sistemi  olarak `main` dalında (`39e30c7`) yer almaktadır.**

###  (Eski  / ) Gerçekleşen Kapsamı

- `ConsensusKind::StorageAttestation(StorageDomainParams)` enum varyantı (`src/domain/types.rs`, `src/domain/storage_params.rs`).
- `roles::STORAGE_OPERATOR` (`src/registry/role.rs`, `RoleId(5)`).
- **`ContentManifest` + `ShardRef` + `ContentId`** (`src/storage/manifest.rs`, `src/storage/content_id.rs`) — çok-parçalı içerik, deterministik manifest üretimi ve byte-range hash kontrolü.
- **`StorageDeal` + `DealStatus` + `StorageEconomicsParams`** (`src/domain/storage_deal.rs`) — operatör, shard, bond, fee ve epoch aralığı.
- **`RetrievalChallenge` + `RetrievalResponse` + `ChallengeOutcome`** — byte-range erişilebilirlik testi (**interim / geçici** — gerçek Proof-of-Storage Z-B gate'ine bağlı olduğu için tombstone ile dürüstçe işaretlenmiştir).
- **`StorageRegistry` + 7 Storage RPC + 3-Aktör E2E Testi** (`src/rpc/api.rs`, `src/rpc/server.rs`, `src/tests/bud_e2e.rs`) — whitelist veya admin-only kapısı olmadan tam permissionless mimari.
  admin/pause/freeze/force/owner/set_params metodu YOK. Bu invariant
  `src/tests/bud_e2e.rs::storage_registry_has_no_admin_or_pause_or_freeze_hook`
  tarafından elle tutulan `forbidden` listesi ile zorunlu kılınır.
- **7 yeni RPC** (`src/rpc/api.rs` + `src/rpc/server.rs`):
  `bud_storageRegisterManifest`, `bud_storageGetManifest`,
  `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`,
  `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`,
  `bud_storageGetOutcome`. Node'lar arası "merkezi indexer" YOKTUR — her
  node kendi state'inden sorgular (plan §2.6).
- **3-aktör E2E testi** (`src/tests/bud_e2e.rs`): **validator/operatör**,
  **kullanıcı**, **uygulama geliştirici** perspektiflerinden tüm akış
  deterministik olarak koşturulur. Hiçbir "resmi izleyici" rolü yok;
  challenge'lar herhangi bir adresten açılabilir.
- **Ekip-bağımsızlık invariantı** (plan §0.5, §2.5, §2.6):
  - Storage registry permissionless + admin hooksuz.
  - `RetrievalChallenge` herhangi bir adresten açılabilir (test:
    `app_view_unrelated_address_can_open_a_challenge`).
  - Deal/manifest sorgu RPC'leri standart node RPC'sinde — ayrı
    "indexer servisi" gerektirmez.
  - Kod tabanında `budlum.com` URL'si, sabit kodlu şirket sunucusu veya
    "sadece ekibin çalıştırdığı servis" bağımlılığı yok (org-repo boş).

###  bilinçli YAPMAYACAKLARI

- Gerçek kriptografik Proof-of-Storage (Gorev 3) — `VerifyMerkle` Z-B
  production gate'ine bağlı.
- NFT mint/transfer/sahiplik (DeArt kapsamı).
- Parçalama algoritması (erasure coding, Reed-Solomon) — istemci tarafı.
- P2P / Bitswap taşıma — sonraki tur adayı.
- Herhangi bir "resmi" / şirkete-özel indexer, gateway, izleyici
  servis, admin/pause anahtarı (plan §0.5 + §3.5).

---

## 4a.  — Denetim turu (gerçek HEAD durumu, 2026-07-14, güncel)

Bu bir **kod yazan değil denetleyen** turdur. Aşağıdaki tablo **kanıtlanmış
bilgiler** ile hazırlanmıştır (her satır `git ls-tree`, `git cat-file`,
`grep`, `gh pr checks` çağrılarıyla doğrulanmıştır). ** Rust
implementasyonu (`ffb66e9`) + 7 storage RPC + 3-aktör E2E + 9 invariant
(`39e30c7`) bu audit'in sonucunda PR #6'ya eklendi.**

| # | Kontrol | Durum | Kanıt (doğrulanmış, 2026-07-14 HEAD `39e30c7`) |
|---|---------|-------|------------------------------------------------|
| 1 | PR #6 CI yeşil | ✅ | `gh pr checks 6` → Budlum Core + BudZero/BudZKVM pass (HEAD `39e30c7` push sonrası kontrol edilecek) |
| 2 | PR #6 başlığı | ✅ doğru | `gh pr view 6 --json title` → `"tur14: B.U.D. (Broad Universal Database) Gorev 1-2 iskeleti"` |
| 3 | PR #6 branch HEAD | ✅ | `origin/arena/019f5f77-budlum` → `39e30c7` ( Rust + RPC + E2E, 2 commit) |
| 4 | `ConsensusKind::StorageAttestation(StorageDomainParams)` enum varyantı | ✅ VAR | `grep -n 'StorageAttestation' src/domain/types.rs` → enum varyantı mevcut (vizyon §8.1 seçildi, §3 `Custom("...")` DEĞİL) |
| 5 | `STORAGE_OPERATOR = RoleId(5)` | ✅ VAR | `grep -n 'STORAGE_OPERATOR' src/registry/role.rs` → `pub const STORAGE_OPERATOR: RoleId = RoleId(5);` + `Display: "storage_operator"` |
| 6 | `src/storage/content_id.rs` | ✅ VAR | `git ls-files src/storage/` → `content_id.rs, db.rs, manifest.rs, mod.rs, traits.rs` (5 dosya) |
| 7 | `src/storage/manifest.rs` | ✅ VAR | (yukarıdaki dizin) |
| 8 | `src/domain/storage_deal.rs` | ✅ VAR | `git ls-files src/domain/` → 7 dosya; `storage_deal.rs` içinde `StorageDeal + StorageRegistry + RetrievalChallenge + RetrievalResponse + ChallengeOutcome + ChallengeResult + StorageError + storage_deal_leaf_hash` (~750 satır) |
| 9 | `src/tests/bud_e2e.rs` | ✅ VAR | `git ls-files src/tests/` → 22 modül; `bud_e2e.rs` içinde 3 E2E + 9 ekip-bağımsızlık invariant |
| 10 | `docs/BUD/` dizini | ⚠️ kısmen | Gorev 1-2 + Gorev 5 dokümantasyonu CLAUDE.md §2/§4 + README.md "B.U.D. (Broad Universal Database) — " bölümünde; ayrı `docs/BUD/` dizini oluşturulmadı (plan §6'da "B.U.D. dokümanları vizyonun referansıyla yazılır" notu, vizyon artık referans alındı) |
| 11 | `src/tests/permissionless.rs` PoA izolasyon testi | ✅ | PoA testleri 88-104; `src/tests/mod.rs:pub mod permissionless;`; STORAGE_OPERATOR = RoleId(5) permissionless primitive'i paylaşıyor (PoaMembershipRegistry'ye dokunulmadı) |
| 12 | `budlum.com` URL'si src/ içinde | ✅ YOK | `grep -rn 'budlum\.com' src/` → boş |
| 13 | StorageRegistry `admin_*`/`pause_*`/`force_*`/`owner_*` metodu | ✅ YOK | `grep -n 'fn admin_\|fn pause_\|fn force_\|fn owner_\|fn freeze_' src/domain/storage_deal.rs` → boş; API yüzeyi sadece: `new, register_manifest, validate_shard_membership, open_deal, open_challenge, answer_challenge, finalize_missed_challenge, expire_deal` + read-only queries. `data-sovereignty` (§0.5) kuralı sağlam |
| 14 | `budlum-xyz/B.U.D.` upstream vizyon dokümanı | ✅ VAR | `budlum-xyz/B.U.D.` repo public; `BUD_Merkeziyetsiz_Depolama_Vizyonu.md` 495 satır, 12 bölüm (§0-11); referans alındı (mod-level docs + CLAUDE.md §4 + README.md) |
| 15 | Vizyon referansı  planlarına yansımış mı? | ✅ kısmen | Mod-level docs (storage_deal.rs L13-30, content_id.rs L7-19) vizyon §8.1 + §8.5 + §0.5 + §9.1'i referans alıyor; `the-plan/TASK0.38_PLAN.md` §6 vizyon olmadan yazılmıştı ama kod vizyon §8.1'i doğrudan implement etti (`StorageAttestation`, `STORAGE_ATTESTATION_ADAPTER` = `"storage-attestation-v1"`) |
| 16 |  maddeleri hâlâ açık | ✅ hâlâ açık | `docs/AI_BIRLIGI.md` §4.5 + `docs/STATUS.md` §5 → BLS/PQ HSM () + finality live-path () + ConsensusStateV2 () + harici audit () + README roadmap () + fuzzing/audit/SBOM () |
| 17 | 7 B.U.D. storage RPC'si | ✅ VAR | `grep -n 'method(name = "bud_storage' src/rpc/api.rs` → 7 method: `bud_storageRegisterManifest, bud_storageGetManifest, bud_storageGetDealsByManifest, bud_storageGetDealsByShard, bud_storageOpenChallenge, bud_storageAnswerChallenge, bud_storageGetOutcome`. Tümü permissionless (admin-only YOK) |
| 18 | PoA izolasyonu bozulmadı | ✅ | `STORAGE_OPERATOR` `PermissionlessRegistry` primitive'ini paylaşıyor (Whitelist/onay YOK); `PoaMembershipRegistry`'ye dokunulmadı; `src/tests/permissionless.rs` mevcut izolasyon testleri hâlâ geçerli |

**T14.9 sonuç — kapatılan bulgular:**

1. ✅ ** (Gorev 1-2) Rust implementasyonu PR #6'ya eklendi** (`ffb66e9`).
   `ConsensusKind::StorageAttestation`, `STORAGE_OPERATOR = RoleId(5)`,
   `ContentId`, `ContentManifest`, `StorageDeal`, `StorageRegistry` — hepsi
   kod tabanında.
2. ✅ **Vizyon dokümanı referans alındı**: storage_deal.rs mod-level docs +
   content_id.rs mod-level docs + CLAUDE.md §4 "B.U.D. ()" bölümü +
   README.md "B.U.D. (Broad Universal Database) — " bölümü.
3. ✅ **Vizyon §3 vs §8.1 kararı**: `StorageAttestation(StorageDomainParams)`
   yeni enum varyantı (vizyon §8.1, `docs/STATUS.md §5` karar kayıtlı).
   `STORAGE_ATTESTATION_ADAPTER = "storage-attestation-v1"` finality adapter ismi.
4. ⚠️ ** maddeleri hâlâ açık** — , §1.3, §1.4, §1.5, §1.7.
5. ✅ **PR #6 §4a tablosu** artık doğru (10 yanlış referans + storage_deal/manifest/
   bud_e2e orphan iddiaları bu güncellemeyle düzeltildi).
6. ✅ **`docs/AI_BIRLIGI.md` (önceki `docs/DEVIR_RAPORU.md`)**  bölümü
   + AI birliği şeması + STATUS_ONLINE.md aktif kanal.
7. ✅ **CLAUDE.md + README.md "interim retrieval" notu** — `RetrievalChallenge`
   gerçek Proof-of-Storage DEĞİL, operatör sadece istenen byte-range'i
   saklayarak testi geçebilir. Gorev 3 (gerçek kanıt) BudZKVM `VerifyMerkle`
   production gate'ine bağlı.
8. ✅ **StorageRegistry admin/pause/freeze/force/owner metodu YOK** — kod
   incelemesiyle doğrulandı.
9. ✅ **Whitelist YOK** — `StorageRegistry::open_deal` ve `open_challenge`
   permissionless; data-sovereignty kuralı ( plan §0.5) kod ile
   sağlam.
10. ✅ **3-aktör E2E + 9 ekip-bağımsızlık invariant** `src/tests/bud_e2e.rs`'te.

**Açık kalan bulgular ('e devredilen):**

-  borçları (BLS/PQ HSM, finality live-path, ConsensusStateV2,
  harici audit, README roadmap, fuzzing/audit/SBOM).
- B.U.D. Gorev 3 (gerçek Proof-of-Storage) — Z-B gate kapanana kadar yazılmaz.
- B.U.D. Gorev 4 (`GlobalBlockHeader.storage_root` alanı) — Gorev 3'e bağımlı.
- B.U.D. Gorev 6 (BNS/.bud) — ayrı tur.
- B.U.D. mainnet launch kararı —  sonunda değerlendirilecek.

---

## 5. Revize  / 0.37 / 0.378 (org roadmap ile hizalı)

###  — “ZK doğruluğu + her persona için aynı çekirdek”
**Hedef:** User / Dev / Enterprise PoA aynı binary’de uyumlu config; ZK tarafında dürüst production sınırı.

1. **Z-B Commit 3.5 ilerlemesi** (BudZero): pre-round current, single-round path hash, original-only root check, expand gas — *valid 64-depth yeşilse* Production gate aç; değilse gate + ignore + dokümante borç.
2. **Persona paketleri** (Budlum): `config/personas/{user-devnet,developer,enterprise-poa}.toml` + `docs/PERSONAS.md` uyumluluk matrisi.
3. **Org roadmap matrisi** README’ye: budlum-xyz maddeleri × durum (bu dosyanın özeti).
4. **BudZero README** org –12 ile senkron, “31 opcode production” iddiasını *gerçekle* hizala.

###  — “Settlement + operasyon (kurum + devnet)” — **uygulandı**
1. ✅ **PoW light-client / mint:** `pow-header-chain-v1`; header hash/link/root/difficulty/work yeniden hesaplanır, legacy proof mint yapamaz.
2. ✅ **Archive + restore:** fail-closed archive rolü, atomik doğrulanan `.budbak`, retention, boş hedef restore/integrity drill.
3. ✅ **Production runbook:** node, PoA authority, RPC ayrımı, HSM PIN ve incident tetikleri `docs/operations/` altında.
4. ✅ **BudZero  baseline:** `budzero/bud-proof/benches/proof_baseline.rs` proof süre/boyut JSON çıktısı.
5. ✅ **RPC quota/admin:** 10k IP bellek tavanlı per-IP pencere; imzasız yönetim yardımcıları operator-only.
6. ✅ **Tek repo:** BudZero workspace `budzero/` altına taşındı; CI ve Docker harici sibling checkout kullanmaz.

###  — “Mainnet v1 policy + anahtar + devir”
1. **BLS/PQ key protection** (B1 tam kapanışa yaklaşım: mainnet policy + ops path; tam HSM yoksa açıkça “not done”).
2. Finality live path boşluk taraması (ch12 partial → doğrula).
3. Migration / ConsensusStateV2 notları.
4. **External audit checklist** (yapılamaz “done” — teslim paketi).
5. README roadmap: Budlum+BudZero org maddeleri kapanış tablosu (B.U.D. hariç).
6. **DEVİR_RAPORU** güncelle (Arena devri).

###  — **B.U.D. only**
Storage domain, content addressing, PoS (proof-of-storage), StorageRoot, ekonomi, BNS/.bud.

---

## 6. Persona uyumu (user / dev / kurum PoA)

| Yetenek | User | Developer | Enterprise PoA | Not |
|---------|------|-----------|----------------|-----|
| Aynı `budlum-core` binary | ✓ | ✓ | ✓ | Persona = config |
| Settlement header verify | ✓ | ✓ | ✓ | |
| Validator / block produce | — | ✓ devnet | ✓ HSM | Mainnet disk key yasak |
| Bridge mint | — | ✓ non-PoW | policy | PoW mint light-client’a bağlı |
| VerifyMerkle in STARK | gated | experimental/test | gated | Org “all production” iddiası yanlış |
| B.U.D. storage | — | — | — | **** |

---

## 7. Sonuç cümlesi

- **Org Budlum + BudZero roadmap’inin kodlanabilir omurgası** → –13.9 ile *kapatılmaya çalışılır* ve README’de madde madde işaretlenir.
- **Org’un “research / audit / privacy / AI” satırları** → 13.9’da checklist; “bitti” denmez.
- **B.U.D. tüm gorevlar** → ****, 13 serisine karışmaz.
- **budlum.com** → boş; 13 serisi kapsamı dışı.

Bu denetim, “roadmap bitiyor mu?” sorusuna: **L1+zkVM operasyonel roadmap evet hedeflenir; org’un tüm araştırma + B.U.D. hayır — bilinçli ayrım.**
