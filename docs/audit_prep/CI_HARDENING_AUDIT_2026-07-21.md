# CI Hardening Audit — 2026-07-21 (ARENA2 / ADIM-1)

> **Bağlam:** Kullanıcı (Ayaz) 2026-07-21  seti, ilk madde: "CI
> sertleştirme — bunlar aslında geçmişte bir talimat setinde vardı, repo'ya
> işlenmiş mi emin değilim — önce kontrol et". Bu doküman altı maddenin
> repoya işlenme durumunun kanıtlı doğrulamasını, bulunan boşlukları ve bu
> push ile kapatılanları kayıt altına alır. Hakem: CI (tek yargıç).

## 1. Doğrulama Matrisi (önce → bu ADIM)

| # | Madde | Önceki durum | Kanıt (önce) | Bu ADIM | Sonuç |
|---|-------|--------------|--------------|---------|-------|
| 1 | Miri ile unsafe crate'leri çalıştırma (UB tespiti) | Var: `.github/workflows/miri.yml` — crypto + bud-vm + storage (storage soft) | 2026-07-19 ARENAX kapanış raporu + workflow dosyası | nightly `nightly-2026-07-19`'e pinlendi (kayan etiket riski giderildi); `cargo +nightly miri` → pinned kanal | ✅ Sertleştirildi |
| 2 | cargo-semver-checks (public API kırılması) | Var ama SÜS: `.github/workflows/semver.yml` her iki adım `continue-on-error: true`; base mekanizması yok (budlum-core crates.io'da yok → `check-release` anlamlı çalışamaz) | semver.yml içeriği + "İlk görevda sadece gözlem" notu | İki-checkout (current vs `base.sha`/`push.before`) + `--baseline-root`; `scripts/check-semver.sh` gate (kırılma+istisnasız = FAIL); `.github/semver-exceptions.txt` kanıtlı-skip disiplini; push+PR tetikleyici | ✅ Gerçek kapı |
| 3 | MSRV pinning | Tam: `rust-toolchain.toml` channel=1.94.0 + `Cargo.toml` `rust-version = "1.94.0"` + tüm CI job'ları 1.94.0 | Dosya içerikleri + ci.yml grep | Değişiklik gerekmedi (çift kilit yeterli) | ✅ Zaten kapalı |
| 4 | Cross-platform determinism (Linux/macOS/Windows consensus çıktısı aynı mı) | Kısmi: matrix yalnız ubuntu+macos ve her OS kendi testini koşuyor; çıktılar kıyaslanmıyordu ("cross" adı vardı, kıyas yok) | determinism.yml içeriği | Windows eklendi (3 OS); yeni `consensus_scenario_digest_cross_platform` testi → `CONSENSUS_DIGEST` artefaktı; `consensus-digest-compare` job'u üç digest'i byte-eşitliğe zorlar | ✅ Gerçek kıyas kapısı |
| 5 | Genesis reproducibility | Var: aynı runner'da iki build + hash karşılaştırma | determinism.yml `genesis-reproducibility` job'u | Adımlara `set -euo pipefail` + boş-hash kilitleri eklendi (boş=boş sahte-eşitlik engellendi) | ✅ Sertleştirildi |
| 6 | cargo-audit + cargo-deny (RustSec + lisans/bağımlılık politikası) | Tam: `dependency-audit` (scripts/audit-deps.sh, CVE=fail, SBOM) + `cargo-deny` matrix (root + budzero) + `deny.toml`/`audit.toml` kanıtlı ignore listeleri; ayrıca `supply-chain-extra.yml` (udeps + geiger) | ci.yml job tanımları + deny.toml [advisories] gerekçeleri | Değişiklik gerekmedi | ✅ Zaten kapalı |

## 2. Bu ADIM'da Kapanan Ek Kök-Nedenler

1. **`src/core/account.rs` rustfmt drift'i** (main kırmızısı, SHA `ef80abf`
   Budlum Core/Format failure): ARENA1'in  fee testlerindeki 4 uzun
   assert satırı `cargo fmt` beklentisine uygulandı. Davranış değişmedi.
2. **Mempool aynı-fee tie-break nondeterminizmi (consensus-critical):**
   `Mempool::get_sorted_transactions` aynı ücretteki işlemleri `HashSet`
   iteration sırasıyla (process-random) döndürüyordu. Bu sıra
   `Blockchain::collect_block_transactions` → blok gövdesi sırasına akıyor;
   aynı-fee tie durumunda iki node farklı blok gövdesi sırası (ve farklı blok
   hash'i / state-root ilerleme riski) üretebilirdi. Fix: tie-break artık
   canonical `BTreeSet` üzerinden ücret DESC, hash ASC. Regresyon kilidi:
   `mempool::pool::tests::test_same_fee_canonical_order_by_hash` (farklı
   ekleme sırası, aynı çıktı).
3. **RBF yuvarlama deliği:** `min_new_fee = fee + fee*pct/100` tamsayı
   bölmesiyle fee=1'de bump=0'a düşüyordu → aynı fee ile limitsiz
   replace-churn (ucuz DoS). Fix: `bump = max(1, ceil(fee*pct/100))`, u128
   ara hesap, replace her zaman kat'i pozitif bump ister. Regresyon kilidi:
   `test_rbf_requires_strict_positive_bump` (fee=1 aynı-fee replace RED,
   +1 KABUL; fee=100 → 109 RED, 110 KABUL).

## 3. Kalan Riskler / Takip (karar noktaları kullanıcıda)

- **Semver gate'in ilk koşularda bulabileceği geçmiş kırılmalar:** base
  `push.before` olduğu için yalnızca YENİ kırılmalar FAIL üretir; geçmiş
  birikim gate kapsamı dışındadır (bilinçli — ratchet ruhu).
- **Windows runner maliyeti:** yeni matrix elemanı determinism workflow'unun
  süresini uzatır; derleme hatası çıkarsa (protoc/C toolchain) bu rapora
  ek not düşülüp iterasyon yapılır (madde 3 döngüsü).
- **Miri storage adımı** hâlâ `continue-on-error: true` (sled↔Miri
  uyumsuzluğu; bilinen, kayıtlı sınırlama).
- **Mempool derin tasarımı** (fee-based önceliklendirme matrisi, spam/DoS
  sınıflandırması, admission-time imza kontrolü) ayrı ADIM (kullanıcı
  listesi "Protokol" maddesi) olarak devam ediyor — bu push'taki tie-break/RBF
  yamaları yalnızca determinizm kök-nedenleridir.

## 4. Kanıt Zinciri

- Lokal: `cargo fmt --check` temiz; hedefli testler
  (`mempool::pool::tests`, `consensus_scenario_digest`) yeşil; tam lib suite
  sonucu bu commit'in CI koşusuyla kanıtlanır (CI tek hakem).
- CI: bu dokümanın dahil olduğu commit'in check-run listesi STATUS_ONLINE
  girdisine işlenecek.
