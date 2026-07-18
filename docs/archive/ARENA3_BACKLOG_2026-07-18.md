# Budlum — Bekleyen İşler Envanteri (hiçbir kalem sahipsiz değil)

**Tarih:** 2026-07-18 (UTC+3) · **Yetki:** kullanıcı — "tüm süreç şu an sende; hepsini sırayla commitle; süreci sağlam ve sistemde kullanılabilir yapmak tek şart" · **Sprint kararı:** `first_both` (önce Phase 10 Bölüm 4 mühendisliği, sonra AccessGrant RFC taslağı)

**Push-protokol durumu:** `afb6782` (P10 açılış + doğrulama) 12/12 yeşil teyitli — teyitsiz push YOK.

| # | Kalem | Sahip | Durum / koşul |
|---|---|---|---|
| 1 | **Phase 10 Sprint 1 — Bölüm 4 mühendisliği** (modül README'leri, kök README dashboard, BNS ayrı CI gate isim-kanaryalı) | ARENA3 | **BU OTURUMDA başlıyor** — sıralı commit zinciri |
| 2 | **Phase 10 Sprint 2 — AccessGrant RFC taslağı** | ARENA1 (pivot) + ARENA3 (review) | **TASLAK HAZIR** (`87a0643`, `docs/RFC_ACCESSGRANT_BUD_MARKETPLACE.md`) — GAP-1 damgası kullanıcı-onaylı teyitli; ARENA3 review şartlı onayı STATUS’ta (R1-R3 düzeltme sonrası P1 açılır) |
| 3 | **7 major PR triyajı:** #45 toml (YEŞİL — TOML 1.1 davranış incelemesi + merge adayı değerlendirmesi) · #43 tower (KIRMIZI — recreate sonrası hâlâ, gerçek kırılım) · #36/#37/#38/#39/#41 (KIRMIZI değerlendirme) | ARENA3 | Sprint 1 sonrası kuyruk; her PR ayrı değerlendirme commit'i, kapanış/merge yorumu ile |
| 4 | **PoS-producer gerçek altyapısı** (daemon validator key/HSM enjeksiyonu + genesis eşitleme + multinode PoW→PoS smoke) | ARENA3 (ilanlı backlog) | Phase 10 kapsamı dışı — kullanıcıdan ayrı emir bekliyor |
| 5 | **hickory/yamux lock yenileme borcu** (dismiss'ler upstream tüketimi açılana dek) | ARENA3 | İzlemede: dependabot günlük taramalarında otomatik triyaj |
| 6 | **BNS mimari genişletmesi** (squatting koruması, devir ekonomisi, B.U.D./AI entegrasyonu) | — | Doküman §4.4: ayrı talimat turu. **Not:** "mimari yok" iddiası güncel değil — iskelet (`src/bns/` registry+types + 9 `test_bns_` testi) mevcut, Sprint 1'de durum-satırı işaretleniyor |
| 7 | **Fuzz Nightly / Docker Security / badge-bot rutinleri** | otomasyon | İzlemede; anomali halinde kök-neden raporu |
| 8 | **GAP-2 hash-kapsam genişletmesi** | ARENA3 (koordinasyon muhatabı halef: yok → tek baş) | Sprint 2'de GAP-1 revizyonu ile tek schema-4 birleşimi önerisi |

**Kural:** Bu tablodaki her satır STATUS_ONLINE'da kapatılıncaya kadar burada kalır; yeni erteleme = yeni satır (sessiz düşürme yok).

---

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*

---

## Standing rules (kalıcı kurallar — phase bağımsız)

1. **`docs/AI_ONBOARDING.md` her phase'de güncellenir** (kullanıcı emri 2026-07-18): phase açılışında §5 "Bugün neredeyiz" + §2 görev tablosu tazelenir; kapanışta mühür işlenir.
2. README rozet sayıları yalnız CI summary satırından; modül dashboard toplam-satırı-kuralı her README edisyonunda korunur.
3. Bu backlog dosyası phase değişiminde arşivlenmez — yeni phase blok eklenir, eski satırlar "kapandı" işaretiyle kalır.

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*

---

## DEVIR BLOGU [2026-07-18 17:14 UTC+3] (kullanici emri: instance degisimi)

- Yontem mirasi: STATUS_ONLINE [2026-07-18 17:14 UTC+3] "10 maddelik yontem mirasi" girdisi — yeni ARENA3 once onu okusun.
- Gorev yoneticisi: ARENA1 (kullanici emri, STATUS_ONLINE duyurusu).
- Devredilen oncelik sirasi: P2 schema-4 (GAP-1+GAP-2+B2 defer, PR #49 WIP devralinacak) → P4 bud_marketplace gate (P1'i bekler) → dependabot triyaji (#45 once) → v2 §11 3 soru (kullanici karari).
- Kritik durum: main `3f397e1` YESIL 17/17 · 769 lib test (CI summary) · rozet 769 islenmis (`065a496`).
- Lokal toolchain notu: .cargo snapshot disi — yeni instance rustup minimal 1.94.0 + rustfmt + clippy + protoc 29.5 binary kurar (jobs=1 sart). Lokal arsiv: /home/user/arena3_tools/.
