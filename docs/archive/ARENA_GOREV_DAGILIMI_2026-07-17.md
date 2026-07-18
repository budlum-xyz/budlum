# Budlum — ARENA1 / ARENA2 / ARENA3 Görev Dağılımı
**Tarih:** 17 Temmuz 2026 | **Repo:** github.com/budlum-xyz/budlum (main)

---

## 0. Durum tespiti (hafızama değil, repoya bakarak)

Doğru hatırlattın — hafızamdaki "Turn 4/5, CI green on f7f21e3" bilgisi tamamen bayat çıktı. Gerçek durum çok daha ileride:

- Repo **budlum-xyz/budlum**'a taşınmış, 367 commit, aktif ve README 2026-07-15 tarihli güncel bir "Research Roadmap Status" tablosu içeriyor (ADIM 2 §1.3-1.7 kapanmış, ADIM 5/7 gündemde).
- Şu anda **ARENA1, ARENA2, ARENA3, ARENA5, ARENA6** adında en az 5-6 farklı Arena oturumu görülüyor; branch adlandırması `arena/arenaN-<konu>-budlum`, commit'ler `Co-authored-by: ARENAn <arenan@budlum.ai>` etiketiyle işleniyor.
- **STATUS_ONLINE.md** adında ortak bir koordinasyon dosyası var: kimlik kayıtları, CLAIM tablosu (A1-T1, A2-T1, A3-T1, IND-T1…), P0/P1 öncelik zinciri, "DENETLEYİCİ" (auditor) rolü. Yani ajanlar birbirini denetliyor ve yanlış "tamamlandı" iddialarını geri çekiyor (ör. ADIM5 "tamamlandı" iddiası ARENA6 denetimiyle çürütülüp geri çekildi).
- **Actions sekmesi: 1.128 workflow run.** Son ~20 run bugün (17 Temmuz), doğrudan `main`'e push ediliyor (bazıları `merge(arena3): ... ARENA1 fmt fix — aynı kanonik form bende de var` gibi notlarla) — yani PR akışı dışında da doğrudan main'e yazılıyor.
- **Açık PR'lar:**
  - **#13** — "Phase 8 Faz 1 kırmızı CI kök-neden düzeltmesi" (ARENA1, branch `arena/arena1-p8fix1-budlum`). SBOM script + fuzz manifest + fuzz harness drift düzeltilmiş, son commit "CI 8/8 yeşil kanıt (run #739)" diyor — **ama PR hâlâ merge edilmemiş, review yok.**
  - **#11** — "ARENA6 ADIM5 denetimi" (22 commit, karışık: docs + gerçek güvenlik düzeltmeleri — ör. StorageAttestation PoS/BFT BLS verify eksikliği). **Bu da hâlâ merge edilmemiş, review yok, main'e entegre olup olmadığı belirsiz.**
  - **#20-27** — 7 adet dependabot bağımlılık PR'ı (p3-fri, p3-air, p3-merkle-tree, p3-util, bincode, jsonrpsee sürüm atlamaları), hiçbiri triaj edilmemiş.
- ADIM5 denetiminde (PR #11) tespit edilen **kapanmamış hatlar**: 5.1 Universal Relayer (stub/placeholder), 5.2 Mobile/Physical Prune API (HEAD'de yok/revert edilmiş), 5.3 Pruning (yok), 5.4 Chaos v2 (kırık/kısmi), 5.5 Marketplace (uyumsuz). Bu denetim, iki farklı Arena tarafından çapraz doğrulanıp "doğru" bulunmuş.

**Şeffaflık notu:** GitHub'ın `robots.txt`'i blob/raw dosya içeriğini (ARENA_AI.md, STATUS_ONLINE.md, CLAUDE.md tam metinleri) doğrudan çekmemi engelliyor — yukarıdaki tabloyu README, açık PR konuşmaları ve Actions log başlıklarından derledim. STATUS_ONLINE.md'nin güncel CLAIM tablosunu görmedim; aşağıdaki görev dağılımı bu kör noktayla birlikte değerlendirilmeli.

---

## 1. Önce bunlar netleşmeli (görev dağıtımından önce)

Üç yeni paralel görev açmadan önce iki açık PR ortada asılı duruyor ve içeriklerinin main'e girip girmediği belirsiz. Bunu ARENA3'ün ilk işine gömdüm (aşağıda), ama sana da söylüyorum: **#11 ve #13'ü review etmeden/kapatmadan yeni iş dağıtmak, üstüne inşa edeceğin zemini bilmeden inşaat yapmak demek.**

---

## 2. ARENA1 — Universal Relayer / Bridge (ADIM5 §5.1)

**Hedef:** Placeholder/stub durumundaki Universal Relayer'ı gerçek implementasyona taşımak.

**Kapsam:**
- Relayer güven modeli kararını (single-relayer / permissionless / threshold-signature) koda somutlaştır. Karar daha önce netleşmediyse, kodlamaya başlamadan önce STATUS_ONLINE.md'ye net bir soru olarak yaz ve bekle — varsayım yaparak ilerleme.
- `src/cross_domain/` altında relayer, bridge state, cross-domain message akışını tamamla.
- Bridge mint/unlock tarafının mevcut `expected_block_hash` ve PoW header-chain finality gate'leriyle tutarlı çalıştığını test et.

**Dosya kilidi (diğer ARENA'lar dokunmasın):** `src/cross_domain/**`, ilgili relayer config dosyaları.

**Çıktı:** CLAIM (STATUS_ONLINE'da yeni satır, ör. `A1-T_yeni`), ayrı branch `arena/arena1-<konu>-budlum`, PR, CI run numarasıyla kanıt.

---

## 3. ARENA2 — Mobile/Physical Prune API + Snapshot Pruning (ADIM5 §5.2 + §5.3)

**Hedef:** "HEAD'de yok / revert edilmiş" olarak işaretlenen mobile-facing prune API'lerini ve genel snapshot pruning mantığını tamamlamak.

**Kapsam:**
- `config/archive.toml`'daki archive/snapshot politikasıyla uyumlu bir pruning mekanizması (disk üzerinde eski state/blok verisinin güvenli temizlenmesi).
- Mobil istemcilerin ihtiyaç duyduğu RPC uç noktaları (ör. `bud_pruneStatus`, `bud_requestPrune` gibi — isimlendirmeyi mevcut RPC konvansiyonuna uydur).
- Daha önce revert edilmiş bir implementasyon varsa, neden revert edildiğini önce commit geçmişinden çıkar (aynı hatayı tekrarlama).

**Dosya kilidi:** `src/chain/` (snapshot/prune modülleri), `src/rpc/` içindeki yeni prune endpoint'leri.

**Çıktı:** Aynı CLAIM/PR/STATUS_ONLINE disiplini + CI kanıtı.

---

## 4. ARENA3 — Chaos v2 onarımı + CI kök-neden stabilizasyonu + PR/dependabot triyajı

**Hedef 1 — Zemin temizliği (ilk iş, kodlamadan önce):**
- PR #11 ve PR #13'ün branch'lerini `git diff origin/main..<branch> --stat` ile kontrol et: main'de hâlâ olmayan gerçek kod değişikliği var mı (özellikle #11'deki StorageAttestation PoS/BFT BLS verify güvenlik düzeltmesi main'e geçmiş mi)? Sonucu STATUS_ONLINE.md'ye yaz, kullanıcıya (Ayaz'a) merge/close önerisini rapor et — **kendin merge etme, sadece net bir öneri sun.**

**Hedef 2 — Chaos v2 (ADIM5 §5.4):**
- Kırık/kısmi chaos test framework'ünü onar; en azından temel network-partition/node-crash senaryolarını çalışır hale getir.

**Hedef 3 — CI kök-neden stabilizasyonu:**
- Son ~20 run'da görülen ardışık küçük fmt/test whack-a-mole düzeltmelerini (`style(fmt): ...`, `fix(test): ...` gibi tekrarlayan tek-satırlık düzeltmeler) kalıcı çöz: push öncesi `cargo fmt --check` + `cargo clippy -- -D warnings`'i zorunlu kılan bir local pre-push script/hook öner ve ekle, böylece bu hatalar CI'ya hiç ulaşmasın.
- 7 açık dependabot PR'ını (#20, #21, #22, #23, #24, #26, #27) tek tek incele: hangileri breaking change riski taşıyor (özellikle Plonky3 `p3-*` 0.5.2→0.6.1 atlaması — BudZero STARK prover'ı etkileyebilir), hangileri güvenli minor bump. Rapor STATUS_ONLINE'a, karar kullanıcıya.

**Dosya kilidi:** `fuzz/`, `.github/workflows/`, chaos test dizini. Bağımlılık PR'larına sadece **inceleme/yorum**, merge kararı kullanıcıda.

---

## 5. Üç ARENA için ortak kurallar

1. **CI yeşil olmadan "tamamlandı" denemez.** Her iddia run numarası + job id ile kanıtlanacak (mevcut kültürünüz zaten böyle — PR #13'teki gibi).
2. **Force-push yasak, mass revert yasak.**
3. **Dosya/modül kilidi ihlal edilmez** — üç ajan birbirinin alanına girmeyecek, çakışma riski sıfırlanacak.
4. **Diğer ARENA'nın raporuna kör güvenilmez** — iddialar git diff / CI ile doğrulanır (zaten ARENA6→ARENA5 denetiminde uyguladığınız disiplin).
5. Her oturum STATUS_ONLINE.md'ye kimlik + özet + CLAIM satırı düşer.
