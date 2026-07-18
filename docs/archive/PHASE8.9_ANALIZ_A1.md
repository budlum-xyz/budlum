# Phase 8.9 — Aşama 1 Derin Analiz Raporu (TASLAK, kullanıcı incelemesine)

**Hazırlayan:** ARENA2 · **Tarih:** 2026-07-16 · **Baz:** origin/main @ `c4b94db`
**Karar durumu:** Kullanıcı Q1–Q5'in TAMAMINI (a) seçenekleriyle onayladı (2026-07-16); Dalga 1–3 bu push'ta uygulandı.
**Kanıt standardı:** Her bulgu SHA / CI-job-id / dosya:satır kanıtı taşır. Kanıtsız iddia yok.

---

## 1. Bitiş tanımı (kullanıcı)

> "Geriye dönük hiçbir boşluğun ya da çalışmayan kodun kalmaması bitiş demektir. Hepsini bu süreçte bitirmelisin."

Bu yüzden matris üç kovaya ayırır: **(A) kırık/çürümüş** → bu süreçte düzeltilecek; **(B) dokümante-placeholder, kodu sağlam** → ceremony gününe kadar boşluk değil; **(C) kullanıcı-taraflı fiziksel kalemler** (7.1 genesis keys, 7.2 bootnode'ların gerçekleri, 7.3 HSM donanımı, M7 dış denetim) → süreç *içinde* kapanabilen her şey (tooling, şablon, fail-closed guard, checklist, hash-freeze) kapatılacak; kalanı tek bir "ceremony günü input listesi" dokümanında toplanacak. GitHub dışında kullanıcıdan tek istenen şey: karar/onay.

---

## 2. Canlı örnek (bugün kapandı): Fuzz Quick bitrot

`error[E0063]: missing fields chain_id, epoch, nonce … in initializer of BlockHeader` — BlockHeader 16 alana evrilmiş, `fuzz/fuzz_targets/consensus_validate.rs` 7 alanla kalmış. (CI job 87715130083)
**Düzeltme:** `c4b94db` — 9 alan eklendi, `storage_root` Some/None iki kolu kapsıyor, başlığa bitrot uyarısı işlendi. Yerel kanıt: `cargo check --manifest-path fuzz/Cargo.toml --bins` → 5 hedefin tamamı derleniyor (CI'da hiç derlenememiş 3 hedef dahil).
**Türev gözlem (Faz 2 / 8.5 önerisi):** CI'a stable `cargo check` fuzz kapısı (~2 dk) — 30 dk'lık fuzz koşusunu beklemeden yakalar.

---

## 3. İddia-vs-kanıt matrisi

| # | İddia / durum | Kanıt | Karar |
|---|---|---|---|
| A1 | README L88: "Disk-backed ValidatorKeys mainnet'te reddedilir" | `src/crypto/primitives.rs:63,73,420-425` + test `:664-670` (pozitif+negatif) | ✅ KANITLI |
| A2 | Genesis placeholder mainnet'te yasak | `src/cli/commands.rs:877-881` "CRITICAL SECURITY FAILURE … STRICTLY PROHIBITED" | ✅ KANITLI |
| A3 | Fail-closed seti (operations doc §4): genesis file yok → exit 1; chain_id ≠ → exit 1; DB hash ≠ → exit 1 | doc §4 listesi + A1/A2 | ✅ KANITLI (doc dürüst) |
| B1 | Rozet "tests 509 lib" (README L8) | Son yeşil CI: **522 passed** (job 87717083535, dae9273) | ❌ BAYAT |
| B2 | README L113 yorum: "452 unit/integration tests (lib)" | aynı CI: 522 | ❌ BAYAT |
| C1 | `PHASE7_CEREMONY_BIRLESTIRME…md:63,85` → `docs/HUB_INTERFACE_PROTOTYPE.html`'e canlı referans | Dosya `845ba5c` ile **kullanıcı talimatıyla silinmiş**; kopya `origin/arena/019f6714-budlum` dalında | ❌ DANGLING — karar Q1 |
| D1 | Dummy bootnodes (203.0.113.x + dummy dns_seeds) | config + `chain_config.rs:207-220` açık yorumlu placeholder; **ama** genesis'teki gibi fail-closed guard YOK — node mainnet'te bunları sessizce dial eder | ⚠️ GAP — karar Q5 |
| D2 | Genesis testleri: `assert!(mainnet.validators.is_empty())` (`genesis.rs:330,416-417`) | Placeholder durumu testlere gömülü; ceremony sonrası flip şart | ⚠️ 7.4 checklist kalemine bağlanacak |
| E1 | `docs/PHASE1_RAPOR.md` ≡ `docs/PHASE0.378_RAPOR.md` | md5 `5de3905f…` (ikisi de) — byte-identical | ⚠️ KOPYA — karar Q3 |
| E2 | Ceremony belgesi 4 adet, toplam 687 satır | §4 başlık haritası (alt kısımda) | ⚠️ KONSOLİDE — karar Q2 |
| F1 | ADIM6 modülleri | `src/{bns,gateway,hub,marketplace,nft,relayer}` + `src/tests/disaster_recovery.rs` + constitution + vision docu HEAD'de | ✅ MEVCUT |
| F2 | SBOM üretimi | job 87717083535'ten önce 4 tur kırık; ARENA3 `dae9273` + benim `c4b94db` sonrası **✅** (c4b94db koşusunda) | ✅ KAPANDI |

## 4. Belge overlap haritası (ceremony)

| Dosya | Katman | Dil | İçerik | Kader önerisi |
|---|---|---|---|---|
| `docs/PHASE7_CEREMONY_PLAN.md` (200s) | PLAN | TR | 7.1–7.5 görevleri, P0/P1, timeline, genesis hash | KALSIN (plan-ana) |
| `docs/PHASE7_CEREMONY_BIRLESTIRME_ARENA5_ARENA1.md` (94s) | KOORDİNASYON | TR | T-7/T-0/T+1 checklist + açık sorular | KALSIN, C1 dangling düzeltilecek |
| `docs/MAINNET_GENESIS_CEREMONY.md` (228s, 24 `___DOLDUR___`) | PROSEDÜR şablonu | TR | Ceremony-günü adımları (Ed25519/BLS/Dilithium5 key üretimi) | Q2'ye göre birleşecek |
| `docs/operations/MAINNET_GENESIS_CEREMONY.md` (165s) | PROSEDÜR ops | EN | Roller, hash freeze, fail-closed §4, minutes şablonu | Q2'ye göre kanonik |

Öneri: **kanonik = `docs/operations/MAINNET_GENESIS_CEREMONY.md`** (ops konvansiyonu + fail-closed §4 + EN = dış denetçi dili); TR prosedürdeki benzersiz kısımlar (HSM vendor adımları 3.2/3.3, `___DOLDUR___` şablon bloğu) içine taşınır; TR dosya küçük bir yönlendirme + TR özet olur. Plan-katmanı iki belgeye dokunulmaz.

## 5. Phase 8.9 dalga planı (onay sonrası)

- **Dalga 1 (bu oturum, küçük):** README 509→522 + L113 452→522 (kanıt: job 87717083535); C1 dangling düzeltmesi (Q1'e göre); `.gitignore`+`sbom.cdx.json` ve `cargo-fuzz = true` metadata (ARENA1 kredisıyla, dalından alıntı); STATUS_ONLINE koordinasyon notu (ARENA1 dalı artık gereksiz → kapatma önerisi).
- **Dalga 2 (konsolidasyon):** Q2+Q3 kararlarına göre belge birleştirme/silme; genesis hash freeze checklist'i (7.4) D2'yi içerecek şekilde genişletme.
- **Dalga 3 (tooling + guard):** Q5 onaylıysa dummy-bootnode fail-closed guard + negatif test; genesis ceremony tooling (7.1): key-üretim script iskeleti, allocations/validators JSON şema doğrulayıcı; ceremony-günü input listesi tek dosya.
- **Dalga 4 (README/iddia hijyeni taraması):** tüm "mainnet ready/audited" sınıfı iddiaların kanıt taraması; M-tablo güncellemesi.

## 6. Kullanıcı kararları (Q)

- **Q1 — HUB html:** (a) silme kararı aynen kalır, BIRLESTIRME dokümanı "kasıtlı silindi — launch'da karar verilecek; kaynak dal: `arena/019f6714-budlum`" notuyla düzeltilir; (b) dosya dal'dan geri getirilir (launch'da yayınlanacaksa). **Önerim: (a).**
- **Q2 — kanonik ceremony:** §4'teki öneri (operations/ EN kanonik) uygun mu?
- **Q3 — kopya rapor:** `PHASE1_RAPOR.md` silinsin, `PHASE0.378_RAPOR.md` kanonik kalsın mı? (İçerik birebir; ADIM-serisi adı korunacaksa tersi de olur.)
- **Q4 — test sayısı:** 522'ye sabitle + "sayılar her faz sonu el ile tazelenir" notu; yoksa sayısız ("500+ lib") rozete mi geçelim? **Önerim: 522 sabit + tazeleme notu.**
- **Q5 — dummy bootnode guard:** mainnet'te `Dummy`/`203.0.113.` içeren bootnode/dns-seed → CRITICAL exit + negatif test. Şimdi (Dalga 3) mi, yoksa 7.2 tooling içinde mi? **Önerim: Dalga 3 — küçük, genesis guard'ıyla simetrik.**

---
*Bu matris 2026-07-16'da kullanıcı tarafından onaylandı ve Dalga 1–3 ile uygulandı (ayağı: bu dosyayı işleyen commit). Dalga 4 (README/iddia hijyeni genel taraması) devam eden iş olarak açık kalır.*
