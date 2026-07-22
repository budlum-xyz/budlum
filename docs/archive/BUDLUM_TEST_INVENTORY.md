# Budlum Test Inventory — Comprehensive Seal Registry ()

> **TR Özet:** Bu dosya Budlum ağındaki tüm test kategorilerini, mühür sayılarını ve kapsamlarını listeleyen ana indekstir.
>
> **DENETİM DÜZELTMESİ (2026-07-18, ARENA3):** Dosyanın ilk sürümündeki "915 mühür" toplamı **CI ile hiç doğrulanmamış** bir el-sayısı iddiaydı (beyan edildiği dönemde main derlenmiyordu bile). Kural: test sayısı yalnız CI özet satırından raporlanır (libtest `test result:` / nextest `Summary`), sohbet veya el sayımı yok.
> Ayrıca `src/tests/target_700.rs`'de 140 fonksiyonun 134'ünün kopya/boş (`assert!(true)`) olduğu tespit edilip temizlendi; davranış kaybı sıfır.

## 1. Test İstatistikleri (Summary) — CI-kanıtlı

Birincil kaynak her zaman CI'dır; bu tablo son kanıtlı ölçümün kopyasıdır:

| Kategori | Test Sayısı | Kanıt (CI run) | Kapsam |
| :--- | :--- | :--- | :--- |
| **Budlum Core (L1)** | 874 (1 ignored) | nextest `874 tests run: 874 passed, 1 skipped` @ `03493b3` (job 87976691570) | Ledger, Consensus, RPC, Bridge, BNS, NFT; 874 → ~740 bekleniyor (target_700 dolgu temizliği sonrası badge-bot yeni kanıtı yazar) |
| **BudZero (ZKVM)** | 119 | nextest `119 tests run: 119 passed` @ `03493b3` (job 87976691570) | STARK Prover, AIR, Opcode Soundness |
| **TOPLAM** | **993** | aynı run | Rozet: `tests-874 lib` (core libtest sayacı, badge-bot tarafından yalnız CI-yeşilken güncellenir) |

---

## 2. Kategorik Detaylar

### A. Ledger & Account State (`src/core/account.rs`, `src/tests/replay_audit.rs`)
- **Balance Logic:** Pozitif bakiye, overflow koruması, yetkisiz harcama engeli.
- **State Root:** V3-Anchored determinizm; 1000+ işlem altında kök tutarlılığı.
- **Persistence:** Veritabanından yüklenen durumun (state) canlı bellek ile bit-bazında aynılığı.

### B. Consensus Engines (`src/consensus/`, `src/tests/consensus_expanded.rs`)
- **PoW Engine:** Zorluk derecesi (difficulty) doğrulaması, geçersiz nonce reddi.
- **PoA Engine:** Yetkili üretici (authority) kontrolü, sahte blok reddi.
- **Liveness:** Absentee validator tespiti ve haklı liveness slashing.
- **Reorg Depth:** Zincir çatalı derinlik sınırı ve kurtarma.

### C. ZKVM & Proof System (`budzero/`, `src/execution/zkvm.rs`)
- **Opcode Soundness:** 31 opcode'un VM ve AIR seviyesinde doğruluğu.
- **STARK Prove/Verify:** 1, 2 ve 64-depth Merkle kanıt zincirleri.
- **Adversarial ZK:** Yanlış root sunulduğunda "0" dönmesi ve bunun kanıtlanması.

### D. Universal Bridge & Relayer (`src/cross_domain/`, `src/tests/relayer_e2e.rs`)
- **Bridge Lifecycle:** Lock -> Mint -> Burn -> Unlock tam döngüsü.
- **Relay Proof:** Merkle proof doğrulaması ve replay protection.
- **Relayer Fees:** %1 relayer payı dağıtımı ve operatör havuzu bütünlüğü.

### E. SocialFi & DWeb (`src/bns/`, `src/nft/`, `src/tests/target_700.rs`)
- **BNS:** İsim tescili, yenileme, subdomain yetki yönetimi.
- **NFT:** Minting, luminence clamping, physical pruning (F1 fix).
- **Marketplace:** Teklif oluşturma, kapatma ve fiyat bütünlüğü.

---

## 3. Güvenlik ve Kaos Testleri (`src/tests/chaos.rs`, `src/tests/security_auditor.rs`)
- **Sybil Resistance:** Stake-based role validation.
- **Network Partition:** Ağı bölüp tekrar birleştirdiğinde en uzun zincire dönme.
- **Byzantine Actors:** Hatalı veya kötü niyetli komitlerin (commitments) reddi.

---

## 4. Kullanım (How to Run)
```bash
# Tüm testleri çalıştırır
cargo test --all

# Sadece belirli bir modülü test eder
cargo test --package budlum-core --lib tests::load_test
```

Co-authored-by: ARENA2 <arena2@budlum.ai>
