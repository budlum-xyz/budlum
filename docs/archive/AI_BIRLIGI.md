# AI Birliği — Budlum L1 + B.U.D. ortak çalışma şeması

**Güncelleme:** 2026-07-14 (Phase 1 / eski adı Phase 0.38 geçişi)
**Önceki adı:** `docs/DEVIR_RAPORU.md` (tek-ajan devir notu — 2026-07-14'te bu şemaya evrildi)
**Sabit çalışma dalı:** `arena/019f5f77-budlum` (`main` HEAD `39e30c7` üzerine kurulu Phase 1)
**Aktif Aşama:** **Phase 1** (eski adı: Phase 0.38 & Phase 0.39 `B.U.D. Broad Universal Database` Sunucu Sistemi)

> **⚠️ KRİTİK TERMİNOLOJİ VE YOL HARİTASI DEĞİŞİKLİĞİ (2026-07-14):**
> **📌 TERMİNOLOJİ KANONİK KURAL (2026-07-16, kullanıcı çapalarıyla):** İsimlendirme **Phase** sistemine sabitlendi. `ADIM1 = Phase 1` (ADIM serisi birebir: Phase 1..8, Phase 8.5, Phase 8.9...). Tur serisi, kullanıcının verdiği beş çapa noktasını (Tur1 = Phase 0, Tur2 = Phase 0.02; Tur10 = Phase 0.30, Tur11 = Phase 0.32, Tur12 = Phase 0.34) aynı anda karşılayan **parçalı formülle** taşındı: `t < 10 → Phase = 0.02 × (t − 1)` (Tur9 = 0.16, Tur9.5 = 0.17); `t ≥ 10 → Phase = 0.30 + 0.02 × (t − 10)` (Tur13.9 = 0.378, Tur15 = 0.40, Tur25 = 0.60). Yarım adımlar aradaki ondalıklara serilir. Muafiyet: küçük harf "tur" (raunt anlamı) ve backtick içindeki tarihsel branch adları (`tur15-pr-5` vb.). Uygulama: ARENA2 repo-genel rename (dc91e31) + tamamlama düzeltmeleri (yetim numaralandırma listeleri + bu not).
> 1. **"Tur" Söyleminin Kaldırılması:** Kullanıcı talimatı ile projedeki tüm yeni çalışma aşamaları artık "Tur" (`Phase 0.38`, `Phase 0.40` vb.) değil, **"PHASE"** olarak adlandırılacaktır. Bu kapsamda ilk ana adımımız **Phase 1** (`Phase 1 = eski Phase 0.38 + Phase 0.39 B.U.D. Server Sistemi iskeleti + 7 RPC + 3-aktör E2E`) olarak tanımlanmıştır.
> 2. **`budlum-xyz` Organizasyon Yol Haritası Senkronizasyonu:** Eski temel kodlamamız olan `github.com/budlum-xyz` organizasyonundaki depolarda (`Budlum`, `BudZero`, `B.U.D.`, `budlum.com`) yer alan yol haritası tam olarak kapsanmaktadır:
>    - **`budlum-xyz/B.U.D.`** vizyonu (`BUD_Merkeziyetsiz_Depolama_Vizyonu.md`) kapsamındaki Faz 1 (ConsensusKind::StorageAttestation), Faz 2 (ContentId & ContentManifest), ve Faz 5 (StorageDeal, RetrievalChallenge, StorageRegistry) **Phase 1** olarak `src/domain/` ve `src/storage/` altında kodlanmış ve `main` branch HEAD (`39e30c7`) commitine sabitlenmiştir.

> **Bu dosya üç şeyi birden taşır:**
> 1. **AI üyeleri tablosu** — kim var, kimin rolü ne, boş slotlar.
> 2. **Tarihsel Tur/Adım özetleri** — Phase 0.36 / 0.37 / 0.38 / 0.39 / 0.398 (DEVIR_RAPORU'nun
>    tamamı, hiçbir şey atlanmadan).
> 3. **Aktif iş akışı** — kim neyi yazar, kim onaylar, kim denetler.
>
> **ÖNEMLİ — yeni bir AI bu dosyayı okurken:**
> - `STATUS.md` → statik denetim kayıtları (bugünkü hatalar, kapalı bulgular, "kanıtlanmış bilgi" kuralları).
> - `STATUS_ONLINE.md` → aktif iletişim kanalı (diğer AI'larla anlık konuşma, handoff, karar talepleri).
> - Bu dosya (AI_BIRLIGI.md) → şema + tarih + görev ayrımı (her oturum başında oku).
>
> **Bu üçü birbirinin yerine geçmez.** Birini okuyup diğerlerini atlamak, bugünkü hataların (STATUS.md §4) tekrarı demektir.

---

## 1. AI üyeleri tablosu (dinamik, 2 → 4+)

Bu tablo **N AI'lı** çalışmayı destekler. Yeni AI eklendikçe satır eklenir; çıkarılan AI'nın satırı `[archived: <tarih>]` notuyla kalır (tarihsel iz).

| # | Handle (GitHub) | Tip | Birincil rol | Sorumluluk | İletişim kanalı | Durum |
|---|-----------------|-----|--------------|------------|------------------|-------|
| 1 | `arena-agent[bot]` (`ARENA1`) | Arena AI (Claude Fable 5 / Arena 5) | **Kod Yazarı & Phase 1 Altyapısı**. PR #6 (`arena/019f5f77-budlum`) ve PR #9 (`arena/phase1-sync`) kod stabilizasyonu. | Rust kodu (`budlum-core`), RPC, E2E invariantları ve `finality_live_path.rs` test seti bakımı. | `STATUS_ONLINE.md`, `ARENA_AI.md`, `CLAUDE.md` | 🟢 aktif |
| 2 | `ARENA2` | Arena AI (Arena 5) | **Denetçi & Roadmap Doğrulayıcı**. Phase 1 (eski Phase 0.38) kapanış denetimi ve kayıp iş tespiti. | `ORG_ROADMAP_AUDIT.md` doğrulama, commit history takibi (`git log`), borç/eksik iş tespiti. | `STATUS_ONLINE.md`, `ORG_ROADMAP_AUDIT.md` | 🟢 aktif |
| 3 | `ARENA3` (me) | Arena AI (Arena 5) | **Kayıp/Uçmuş Commit Geri Getirici & Çekirdek Kodlayıcı**. Force-push veya revert ile kaybolan/boşalan commit'leri (`tur15-pr-5 ConsensusStateV2`, `pr-6 BLS/PQ HSM`, vb.) sırayla hayata getirmek ve kodlamak. | `ARENA1` ve `ARENA2` ile görev dağılımı yaparak ortak commit (`Co-authored-by`) oluşturmak, Phase 0.36/0.38/0.40 kayıp paketlerini sırayla kodlamak + `STATUS_ONLINE.md` müzakeresi. | `STATUS_ONLINE.md` (`main` branşı), `ARENA_AI.md`, `CLAUDE.md` | 🟢 aktif |
| 4 | `ARENAX` | Arena AI (Arena 5) | **Bağımsız Denetçi — Rapor ↔ Vizyon ↔ Kod çelişki denetimi, boş/ölü kod envanteri, vaad-edilen işlem gerçekleşebilirliği, budlumdevnet bütünlük gözcüsü** (kullanıcı ataması, 2026-07-17). | Claim-vs-evidence matrisi (`PHASE9_VIZYON_KOD_CELISKI_DENETIM_ARENAX_2026-07-17.md`), dead-code scan, süreç kullanılabilirlik denetimi; kod yazmaz, acil kırmızı-fix istisnası (kural 3). | `STATUS_ONLINE.md` | 🟢 aktif |
| 5 | (gelecek) | (TBD) | **Kullanıcı kararına göre** — örn. harici audit reviewer, Phase 2 (eski Phase 0.40) release manager, BNS/.bud uzmanı. | (TBD) | (TBD) | ⏳ boş slot |

**Handle listesi (PR yorumlarından / commit co-author'dan kanıtlanır):**

- `arena-ai-coding-agent[bot]` — eski sabah oturumundaki ajan (PR #6 comment 1-6).
- `lubosruler` — kullanıcı (insan karar verici, son onay).
- Yeni AI'lar: commit mesajlarının `Co-authored-by:` satırından tespit edilir.

**Boş slot kuralları:**

- 4+ AI eklendikçe tabloya yeni satır eklenir.
- Kullanıcı `STATUS_ONLINE.md`'de "yeni AI: <handle> rol: <X>" diye duyurur → her iki AI tabloyu günceller.
- Çıkarılan AI `[archived: YYYY-MM-DD]` notuyla kalır, referans için.

---

## 2. İletişim kanalları — STATÜK vs STATIK

| Dosya | Tip | Kim yazar | Kim okur | Güncelleme sıklığı |
|-------|-----|-----------|----------|---------------------|
| `AI_BIRLIGI.md` (bu dosya) | Şema + tarih + görev ayrımı | Her iki AI (karşılıklı) | Her yeni AI oturum başında | Tur kapanışında + yeni AI katılımında |
| `STATUS.md` | Statik denetim kayıtları (bugünkü 4 hata, kapalı bulgular, "kanıtlanmış bilgi" kuralları) | Kod yazan AI (me) — denetçi AI yorum yapar | Yeni AI'lar (ilk okuma) + kullanıcı | Her PR kapanışında + her audit turunda |
| `STATUS_ONLINE.md` | Aktif iletişim kanalı — anlık handoff, karar talepleri, "şu an şunu yapıyorum", engel bildirimi | Her iki AI yazar (serbest format, timestamp'li entry) | Her iki AI + kullanıcı (PR'a bakıyor olabilir) | Gün içinde çok sık (her önemli aksiyonda) |

**Kural:**

- `STATUS.md` "geçmiş doğru" — düzeltme gerekiyorsa yeni entry eklenir, eski entry silinmez (audit trail).
- `STATUS_ONLINE.md` "şu an konuşuyoruz" — entry'ler zaman damgalı, eski entry "resolved" notuyla kalır.
- `AI_BIRLIGI.md` "kim var, kimin rolü ne, hangi kanal hangi amaçla" — uzun ömürlü, değişiklikler açıklanır.

---

## 3. Aktif iş akışı — kim ne yapar, kim onaylar

### 3.1 Kod işleri (Rust)

| Adım | Sorumlu | Onay / Denetim |
|------|---------|----------------|
| Plan yazma (`the-plan/TUR*.md`) | Planlama AI (üye #2) | Kullanıcı netleştirir |
| Rust implementasyonu (`src/**`) | Kod yazan AI (ben, üye #1) | `cargo fmt + clippy + test` (lokalde mümkünse; değilse CI) |
| E2E + invariant testleri | Kod yazan AI (ben) | Aynı |
| `CLAUDE.md` / `README.md` / `ARENA_AI.md` güncelleme | Kod yazan AI (ben) | Denetçi AI PR review'da |
| `docs/STATUS.md` (statik denetim) güncelleme | Kod yazan AI (ben) — hata analizleri | Denetçi AI doğrular |
| `docs/AI_BIRLIGI.md` (bu dosya) güncelleme | Her iki AI (karşılıklı) | Kullanıcı (kapsam değişikliklerinde) |
| `docs/STATUS_ONLINE.md` (aktif kanal) yazma | Her iki AI (serbest) | Kullanıcı istediğinde okur |

### 3.2 PR yaşam döngüsü

| Adım | Sorumlu |
|------|---------|
| Branch push | Kod yazan AI (ben) — `git push origin arena/019f5f77-budlum` (force-push YOK) |
| PR oluşturma / güncelleme | Kod yazan AI (ben) |
| CI yeşil mi? | `gh pr checks 6` — kod yazan AI kontrol eder + CI logu |
| PR review yorumları | Denetçi AI (üye #2) + kullanıcı |
| Merge | Kullanıcı (AI merge YAPMAZ) |

### 3.3 Karar noktaları (vizyon kararları, mimari seçimler)

| Karar | Kim karar verir | Nerede kayıtlı |
|-------|------------------|-----------------|
| Vizyon §3 vs §8.1 (Custom vs StorageAttestation) | Kullanıcı (zaten seçti: **StorageAttestation**) | `STATUS.md` §5 + `AI_BIRLIGI.md` §5 |
| BLS/PQ HSM kapsamı (mock vs tam) | Kullanıcı (son karar: **sadece gerçek PKCS#11 HSM**, mock kaldırıldı — ARENA2 doğrulama 2026-07-15) | `AI_BIRLIGI.md` §5 |
| B.U.D. mainnet launch'a dahil mi | Kullanıcı (Phase 0.40 §1.2 sonunda değerlendirilecek) | `STATUS.md` §5 |
| Force-push? | **KESIN YASAK** — her iki AI uyar (STATUS.md §4.2) | `STATUS.md` §4.2 + `AI_BIRLIGI.md` §6 |
| Workflow dosyası push? | **YAPMA** — bot token kısıtı (`workflows: write` permission YOK) | `STATUS.md` §4.3 + `AI_BIRLIGI.md` §6 |

---

## 4. Tarihsel Tur özetleri (DEVIR_RAPORU'nun tamamı, korunmuş)

> Aşağıdaki bölümler eski `docs/DEVIR_RAPORU.md`'den birebir taşınmıştır. Yeni
> şema (AI üyeleri + iletişim kanalları) yukarıya eklendi, tarihsel bilgi
> aşağıda. **Hiçbir tur özeti atlanmadı.**

### 4.1 Proje kararı (devralınan)

Budlum L1 ile BudZero/BudZKVM artık tek repository'de çalışır. Kanonik yol:

- L1: repository root (`budlum-core`)
- ZK workspace: `budzero/`
- B.U.D.: Phase 0.38; Phase 0.36 serisine kod olarak karıştırılmayacak

Eski `lubosruler/BudZero` yalnız tarihsel kaynak kabul edilir. Yeni ajan sibling
checkout veya commit pin'i geri getirmemelidir.

### 4.2 Phase 0.36 özeti (devralınan)

- User / developer / enterprise PoA persona config'leri.
- Org roadmap denetimi ve B.U.D. Phase 0.38 ayrımı.
- BudZero Z-B ilerlemesi; `VerifyMerkle` Production gate **açılmadı** çünkü
  pozitif 64-depth proof hâlâ yeşil değil.

### 4.3 Phase 0.37 özeti

Ayrıntı: [`PHASE0.37_RAPOR.md`](archive/PHASE0.37_RAPOR.md).

- BudZero tam kaynak ağacı `budzero/` altına taşındı; CI/Docker tek checkout.
- Gerçek bounded PoW header-chain adapter'ı; legacy declared proof mint-gated.
- Archive fail-closed policy, atomik doğrulanan backup, restore/integrity drill.
- Production/PoA/RPC/HSM runbook'ları.
- Bounded per-IP quota ve operator-only imzasız admin helper'ları.
- Canlı latency histogram wiring.
- BudZero proof time/size baseline bench.

### 4.4 Değiştirilmemesi gereken güvenlik sınırları

1. PoW/PoS/BFT validator/verifier/relayer katılımına whitelist ekleme. PoA KYC
   registry'si ayrı kalmalı.
2. `pow-confirmation-depth` proof'una bridge mint izni verme.
3. `VerifyMerkle` pozitif 64-depth proof doğrulanmadan Production ISA gate'ini
   açma.
4. Mainnet disk `ValidatorKeys` yasağını BLS/PQ HSM yolu gerçekten gelmeden
   kaldırma.
5. Harici audit yapılmadan README'de "audited/mainnet ready" yazma.
6. B.U.D. storage fazlarını Phase 0.378'a çekme; Phase 0.38 kararı sabit.

### 4.5 Sonraki tur: 13.9 (Phase 0.40'te kapatılacak)

1. BLS/PQ anahtar capability/policy ve mümkün HSM abstraction.
2. Prevote/precommit/cert/QC live coordinator son taraması + negatif testler.
3. ConsensusStateV2 staged migration planı ve minimum hook.
4. External audit teslim paketi/checklist; audit tamamlandı iddiası yok.
5. Org Budlum+BudZero roadmap kapanış matrisi; araştırma satırları dürüstçe açık.
6. Bu dosyayı test/CI/commit/PR sonuçlarıyla güncelle.

### 4.6 Phase 0.38 özeti (B.U.D. Faz 1-2 + Faz 5 iskeleti) — 2026-07-14 PR #6

**Sabit çalışma dalı:** `arena/019f5f77-budlum`
**PR:** #6 (açık, CI yeşil — `gh pr checks 6` 2026-07-14)
**Kaynak planlar:** `the-plan/PHASE0.38_PLAN.md` (129 satır), `the-plan/PHASE0.39_PLAN.md` (267 satır)
**Kaynak vizyon:** `budlum-xyz/B.U.D./BUD_Merkeziyetsiz_Depolama_Vizyonu.md`
(495 satır, 12 bölüm — Phase 0.38 planı yazılırken vizyon **mevcut değildi**;
Phase 0.38 Rust kodu yazılırken vizyon **referans alındı** — mod-level docs + CLAUDE.md §4 + README.md "B.U.D. — Phase 0.38" bölümü).

**PR #6 kapsamı (gerçek, HEAD `39e30c7`):**

- ✅ `ConsensusKind::StorageAttestation(StorageDomainParams)` enum varyantı (`src/domain/types.rs`, vizyon §8.1).
- ✅ `STORAGE_OPERATOR = RoleId(5)` permissionless rol (`src/registry/role.rs`).
- ✅ `src/storage/content_id.rs` (`ContentId` + `of_subrange`, interim retrieval sınırlama açık).
- ✅ `src/storage/manifest.rs` (`ContentManifest` + `ShardRef` + `manifest_id_from_shards`).
- ✅ `src/domain/storage_deal.rs` (`StorageDeal` + `StorageRegistry` + `RetrievalChallenge/Response/Outcome/Result` + `StorageError` + `storage_deal_leaf_hash`).
- ✅ `src/tests/bud_e2e.rs` (3-aktör E2E + 9 ekip-bağımsızlık invariant).
- ✅ 7 yeni storage RPC (`src/rpc/api.rs` + `src/rpc/server.rs`).
- ⚠️ `docs/BUD/` ayrı dizini oluşturulmadı (dokümantasyon CLAUDE.md §2/§4 + README.md'de).

**Vizyonun karar noktaları (seçildi):**

- §3 vs §8.1: **`StorageAttestation(StorageDomainParams)` yeni varyant** (vizyon §8.1, `Custom("...")` DEĞİL).
- Faz 1 = muhasebe (kanıt yok), Faz 3 = `VerifyMerkle` Z-B gate'ine bağımlı,
  Faz 4 = `GlobalBlockHeader.storage_root`, Faz 5 = ekonomi (kod bu turda var), Faz 6 = BNS/.bud.

### 4.7 Phase 0.39 özeti (Depolama pazarı: shard + deal + retrieval)

**Plan:** `the-plan/PHASE0.39_PLAN.md` (267 satır, referans).
**Kod:** PR #6'ya eklendi (HEAD `39e30c7`).

- `ContentManifest` + `ShardRef` (`src/storage/manifest.rs`) — çok-parçalı
  içerik, deterministik manifest üretimi.
- `StorageDeal` + `DealStatus` + `StorageEconomicsParams`
  (`src/domain/storage_deal.rs`) — operatör + shard + bond + fee + epoch.
- `RetrievalChallenge` + `RetrievalResponse` + `ChallengeOutcome` —
  byte-range erişilebilirlik testi (**interim**, gerçek Proof-of-Storage DEĞİL).
- `StorageRegistry` (BTreeMap-backed, permissionless, admin hooksuz).
- 7 yeni RPC (`bud_storageRegisterManifest`, `bud_storageGetManifest`,
  `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`,
  `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`,
  `bud_storageGetOutcome`).
- 3-aktör E2E testi (`src/tests/bud_e2e.rs`) + 9 ekip-bağımsızlık invariant.

**Veri egemenliği kuralı (Phase 0.39 plan §0.5):** hiçbir kritik fonksiyon
"Budlum ekibinin servisi"ne bağımlı değil. `open_deal` ve `open_challenge`
permissionless; opener_bond > 0 anti-spam; admin/pause/freeze/force hook'u
kod incelemesiyle YOK (kanıt: `grep -n 'fn admin_\|fn pause_\|fn force_\|fn owner_\|fn freeze_' src/domain/storage_deal.rs` → boş).

### 4.8 Phase 0.398 özeti (denetim turu) — kapatılan bulgular

**Kapsam:** kod yazıldı, denetim yapıldı, 17 maddelik tablo `docs/ORG_ROADMAP_AUDIT.md` §4a'da güncel.

**Denetim sonuçları (kanıtlanmış, HEAD `39e30c7`):**

- PR #6 CI yeşil (`gh pr checks 6`).
- `budlum-xyz/B.U.D.` vizyon dokümanı paylaşılmış (495 satır, referans alındı).
- Phase 0.38 Rust kodu yazıldı; mod-level docs vizyon §8.1/§8.5/§0.5/§9.1'i referans alıyor.
- `permissionless.rs` PoA izolasyon testi sağlam (88-104).
- `budlum.com` URL koda girmedi (`grep -rn 'budlum\.com' src/` → boş).
- StorageRegistry admin/pause/freeze/force/owner hook'u YOK (kod incelemesi).
- 7 storage RPC permissionless (admin-only YOK).
- 3-aktör E2E + 9 ekip-bağımsızlık invariant (`src/tests/bud_e2e.rs`).
- PoA izolasyonu bozulmadı: `STORAGE_OPERATOR` `PermissionlessRegistry` primitive'ini paylaşıyor; `PoaMembershipRegistry`'ye dokunulmadı.

**Açık kalan bulgular (Phase 0.40'e devredildi):**

1. Phase 0.378 borçları (BLS/PQ HSM, finality live-path, ConsensusStateV2,
   harici audit, README roadmap, fuzzing/audit/SBOM).
2. B.U.D. Faz 3 (gerçek Proof-of-Storage) — Z-B gate kapanana kadar yazılmaz.
3. B.U.D. Faz 4 (`GlobalBlockHeader.storage_root` alanı) — Faz 3'e bağımlı.
4. B.U.D. Faz 6 (BNS/.bud) — ayrı tur.
5. B.U.D. mainnet launch kararı — Phase 0.40 §1.2 sonunda değerlendirilecek.

### 4.9 Doğrulama komutları (her oturum başında)

```bash
cargo fmt --all -- --check
cargo clippy --lib --tests -- -D warnings
cargo test --lib
cargo fmt --manifest-path budzero/Cargo.toml --all -- --check
cargo clippy --manifest-path budzero/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --manifest-path budzero/Cargo.toml --workspace
```

Bench (release, süre alır):

```bash
cargo bench --manifest-path budzero/Cargo.toml -p bud-proof --bench proof_baseline
```

PR doğrulama:

```bash
gh pr view 6 --json title,state,mergeable,headRefName
gh pr checks 6
git log --oneline -10
git ls-tree -r HEAD -- src/ | grep -E 'storage_deal|content_id|manifest|bud_e2e'
```

---

## 5. Açık karar noktaları (zaten netleşmiş, kayıt)

| Karar | § | Seçildi mi? | Kaynak |
|-------|---|--------------|--------|
| Vizyon §3 vs §8.1 (Custom vs StorageAttestation) | Phase 0.38 Faz 1 | ✅ **StorageAttestation** (yeni enum varyantı) | `STATUS.md` §5 + `AI_BIRLIGI.md` §4.6 |
| BLS/PQ HSM kapsamı (tam vs mock) | Phase 2 §2.2 | ✅ **Sadece gerçek PKCS#11 HSM** — mock kaldırıldı | `git log --oneline -- src/crypto/hsm_mock.rs` (ARENA2 doğrulama, 2026-07-15) |
| B.U.D. mainnet launch'a dahil mi | Phase 0.40 §1.2 sonu | ⏳ değerlendirilecek | `STATUS.md` §5 |

> **🔒 SON KARAR — Mock HSM (Phase 3 §0.4, ARENA2 doğrulama 2026-07-15):**
>
> Mock HSM backend (`src/crypto/hsm_mock.rs`) **kesin olarak kaldırılmıştır.**
> Tarihçe: `d8db94b` (ARENA3 ekledi) → `5e9bdef` (ARENA1 kaldırdı) → `5efdec1` (ARENA3 geri getirdi) → `a9321f5` (ARENA1 tekrar kaldırdı).
> HEAD `4e6d382` itibarıyla: dosya YOK, `mod.rs`'de referans YOK, `grep -rn hsm_mock src/` → sıfır sonuç.
> `src/cli/commands.rs`'deki `hsm_socket_path` alanı PKCS#11 gerçek HSM iletişimi için korunmuştur (default: `./data/hsm/socket.sock`).
> **Karar: Sadece gerçek PKCS#11 HSM. Mock YOK.**

---

## 6. KESIN KURALLAR (her iki AI uyar)

1. **Force-push YASAK** — `git push --force`, `--force-with-lease`, `git push -f` HİÇBİR DURUMDA. Conflict durumunda `git pull --rebase` + normal push.
2. **Workflow dosyası push YASAK** — bot token `workflows: write` permission YOK; CI'da `dependency-audit`, `sbom`, `fuzz-build` job'ları kullanıcı tarafından manuel eklenir. `docs/operations/DEPENDENCY_AUDIT.md` + `scripts/audit-deps.sh` zaten PR'da; CI entegrasyonu kullanıcıya bırakıldı.
3. **Kanıtlanmamış bilgi yasak** — her commit referansı `git cat-file -t <sha>` ile doğrulanmadan audit'e yazılmaz. "Phase 0.38 sıfırdan başlatılmalı" gibi yorumlar kanıtlanmamış commit'lere dayanmamalı.
4. **Hata kabulü** — bir önceki AI'nın özetini sorgulamadan kabul etme (bugün 9 yanlış referans audit'e yazıldı, `STATUS.md` §4.1).
5. **Bilgi kaynakları sırası** — yeni bir AI oturum başında: (1) `AI_BIRLIGI.md` (şema + tarih), (2) `STATUS.md` (statik denetim), (3) `STATUS_ONLINE.md` (aktif kanal), (4) `ARENA_AI.md` (master context), (5) `CLAUDE.md` (budlum-spesifik). Bu sırayla oku.
6. **PoA izolasyonu** — `STORAGE_OPERATOR` permissionless `PermissionlessRegistry` ile kayıt, ama `PoaMembershipRegistry`'ye ASLA dokunma. İkisi ayrı veri yapısı, ayrı izin modeli (master context, CLAUDE.md §2).
7. **Whitelist YOK** — B.U.D. deal/challenge permissionless; "Budlum ekibi servisi" bağımlılığı YOK (data-sovereignty, Phase 0.39 plan §0.5).
8. **PR'ları ayrı ayrı at, soru sorma** — kullanıcı 2026-07-14 18:30 civarında netleştirdi: PR'lar tek tek push'lanır, her push sonrası `STATUS_ONLINE.md`'de "PR #N push'landı" entry'si yazılır.

---

## 7. Bilgi kaynakları (kanıtlanmış, sıfırdan başlayan AI için)

1. `budlum/AI_BIRLIGI.md` (bu dosya) — şema + tarih + görev ayrımı.
2. `budlum/STATUS.md` — statik denetim kayıtları + bugünkü 4 hata + "kanıtlanmış bilgi" kuralları.
3. `budlum/STATUS_ONLINE.md` — aktif iletişim kanalı (anlık handoff, karar talepleri).
4. `budlum/ARENA_AI.md` (3853 satır) — Arena AI master context.
5. `budlum/CLAUDE.md` (296+ satır) — budlum-spesifik mimari kurallar.
6. `budlum/docs/ORG_ROADMAP_AUDIT.md` §4a — Phase 0.398 denetim tablosu (güncel, kanıtlanmış).
7. `budlum/docs/PHASE0.42_PLAN.md` (~112 satır) — Phase 0.42 master plan.
8. `budlum/docs/operations/DEPENDENCY_AUDIT.md` + `SBOM.md` — CI entegrasyon prosedürü.
9. `the-plan/PHASE0.38_PLAN.md` (129 satır) + `PHASE0.39_PLAN.md` (267 satır) — referans planlar.
10. `the-plan/claude-fable-5.md` (3825 satır) — ARENA_AI.md kökeni.
11. `budlum-xyz/B.U.D./BUD_Merkeziyetsiz_Depolama_Vizyonu.md` (495 satır, 12 bölüm) — B.U.D. vizyonu.

**Doğrulama komutları (yukarıda §4.9).**

---

## 8. Sonraki adım

PR #4 (Phase 0.40 §1.3 Finality live-path test genişletmesi) → §1.4 ConsensusStateV2 → §1.1 BLS/PQ HSM → §1.2 B.U.D. Faz 1-2 (zaten Phase 0.38'te tamamlandı, referans). Phase 0.40 planına geçmeden önce `STATUS_ONLINE.md` üzerinden diğer AI ile handoff yapılacak.
