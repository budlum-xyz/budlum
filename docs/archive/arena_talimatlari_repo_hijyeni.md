# Budlum — Repo Hijyeni ve Süreç Talimatları

Kaynak: github.com/budlum-xyz/budlum canlı durumu (19 Temmuz 2026, main branch, 367 commit). Aşağıdaki 4 madde CI/kod mantığını etkilemiyor ama repo hijyeni ve süreç disiplini için kapatılmalı.

---

## 1. README.md — Eski Repo Referansları (Öncelik: Orta)

**Sorun:** Repo `lubosruler/budlum`'dan `budlum-xyz/budlum`'a taşındı, ama README hâlâ eski adrese işaret ediyor:

- CI badge: `https://github.com/lubosruler/budlum/actions/workflows/ci.yml/badge.svg`
- Tests badge linki: `https://github.com/lubosruler/budlum`
- Quick start bölümündeki clone komutu: `git clone https://github.com/lubosruler/budlum.git`

License badge zaten doğru (`budlum-xyz/budlum/blob/main/LICENSE`) — yani sorun sadece 3 yerde.

**Ayrıca:** README.md'nin sonunda, Contributing bölümünden hemen sonra, muhtemelen bir debug/CI-tetikleme commit'inden kalma başıboş bir `# trigger CI` başlığı var. Bu gerçek bir dokümantasyon başlığı değil, README içeriğine sızmış bir kalıntı.

**Yapılacaklar:**
- [ ] 3 badge/link'i `budlum-xyz/budlum`'a güncelle
- [ ] Quick start clone URL'sini güncelle
- [ ] `# trigger CI` başlığını README.md'den tamamen sil

**Kabul kriteri:** README'de `lubosruler` string'i hiç geçmemeli (tarihsel referanslar hariç, örn. "former `lubosruler/BudZero` repository is historical input" cümlesi kalabilir — o bilinçli bir açıklama, hata değil).

---

## 2. Dependabot PR'ları — Toplu Merge Yasak, Tek Tek Karar (Öncelik: Yüksek)

**Durum:** 9 açık PR'dan 7'si Dependabot, hepsi 16 Temmuz'dan beri bekliyor:

| PR | Değişiklik | Risk |
|---|---|---|
| #20, #22, #23, #26 | p3-util, p3-merkle-tree, p3-air, p3-fri: **0.5.2 → 0.6.1** | **Yüksek** — BudZKVM STARK prover özellikle Plonky3 0.5.2'ye pinliydi. Minor gibi görünen bu bump proof formatını/soundness varsayımlarını değiştirebilir. |
| #21, #27 | bincode: **1.3.3 → 3.0.0** (fuzz ve budzero) | **Yüksek** — major version, serialization formatı değişmiş olabilir; on-chain/state uyumluluğunu bozabilir |
| #24 | jsonrpsee: 0.24.11 → 0.26.0 | Orta — RPC breaking change kontrolü gerekli |

**Yapılacaklar:**
- [ ] Hiçbirini otomatik/toplu merge etme
- [ ] p3-* paketleri için: Plonky3 0.6.1 changelog'unu kontrol et, mevcut STARK proof üretim/doğrulama testlerini bu versiyonla çalıştır, sonuç raporla
- [ ] bincode 3.0.0 için: breaking change listesini kontrol et, mevcut serialize/deserialize testlerinin hepsi geçiyor mu doğrula
- [ ] Her PR için ayrı karar: merge / kapat-ve-pinle / ertele — gerekçesiyle

**Kabul kriteri:** Her PR'da ya merge commit'i ya da "neden ertelendi" notu olmalı. Sessizce açık kalmamalı.

---

## 3. PR #13 — Durumu Netleştir (Öncelik: Orta)

**Durum:** `fix(ci): Task 8 Gorev 1 kirmizi CI kok-neden duzeltmesi (8.1 SBOM + 8.5 fuzz)` başlıklı PR #13, 16 Temmuz'dan beri açık. Aynı tarihten beri main'e çok sayıda doğrudan commit gitmiş (fmt fix'leri, storage fix'leri, ARENA2/ARENA3 merge'leri).

**Risk:** PR-tabanlı workflow ile direct-push workflow paralel yürüyor. PR #13'ün çözdüğü kök neden main'de zaten başka commit'lerle kapatılmış olabilir — bu durumda PR stale ve yanıltıcı.

**Yapılacaklar:**
- [ ] PR #13'ün diff'ini mevcut main HEAD ile karşılaştır
- [ ] Eğer içerik zaten main'de karşılanmışsa: PR'ı "superseded by <commit-hash>" notuyla kapat
- [ ] Eğer hâlâ geçerliyse: rebase edip merge et veya neden beklediğini açıkla

**Kabul kriteri:** Açık PR sayısı sıfıra (Dependabot hariç) inmeli, ya da her açık PR'ın neden açık kaldığına dair güncel bir yorum olmalı.

---

## 4. CI Durumu — Her Rapor Öncesi Taze Kontrol (Öncelik: Yüksek, kalıcı kural)

**Gözlem:** Bu inceleme sırasında commit `760d3d7` üzerindeki CI çalışması **hâlâ devam ediyordu** ("In progress"), önceki commit'lerin CI sonuçları yeşildi ama en güncel commit doğrulanmamıştı.

**Kural:** Bir turun "CI yeşil, tamamlandı" olarak raporlanabilmesi için:
- [ ] Actions sekmesinde **en son commit hash'ine bağlı** CI run'ı kontrol edilmeli — bir önceki commit'in yeşil olması yeterli değil
- [ ] Run durumu "In progress" ise, tamamlanmadan rapor verilmemeli
- [ ] Rapor, kontrol edilen commit hash'ini ve CI run numarasını (örn. "CI #870, commit 760d3d7") açıkça belirtmeli

Bu, zaten var olan "Arena raporuna CI/diff doğrulaması olmadan güvenme" kuralının somut bir uygulaması — sadece "CI geçti" demek yetmez, hangi commit için geçtiği belirtilmeli.
