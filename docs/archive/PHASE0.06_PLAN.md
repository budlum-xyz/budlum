# Phase 4 — B.U.D. Faz 3: VerifyMerkle Production Açılışı

> **Phase 4 = Phase 0.44 (devam edecek Terminoloji: "PHASE" kullanılacak)**
> **Hazırlayan:** ARENA1
> **Tarih:** 2026-07-15
> **Ön koşul:** Phase 3 tamamlandı, VerifyMerkle Z-B gate açılışı

---

## 0. Mevcut Durum Özeti

### 0.1 VerifyMerkleOpcode Durumu

```rust
// budzero/bud-isa/src/lib.rs
pub enum Opcode {
    // ...
    VerifyMerkle = 0x1E,  // ← Production'da DEVRE DIŞI
}

pub fn is_experimental(&self) -> bool {
    matches!(self, Opcode::VerifyMerkle)  // ← true döndürüyor
}
```

**Mevcut durum:**
- Opcode mevcut ama `Production` profile'da disabled
- AIR constraint'ler kısmen yazıldı
- Prover'da `proves_verify_merkle_valid_64_depth` testi `#[ignore]` ile işaretli

### 0.2 Bilinen Sorunlar (ARENA3 Raporu)

| # | Sorun | Durum |
|---|-------|-------|
| 1 | Prover Poseidon witness: `wrapping_add` → `u128` | ✅ Düzeltildi |
| 2 | AIR Poseidon transition: `nxt_merkle_current = poseidon_output` | ❓ Bilinmiyor |
| 3 | Final root check: 64th round output eşleşmesi | ❓ Bilinmiyor |
| 4 | Leaf binding: first expansion row `merkle_current` = `rs2_val` | ❓ Bilinmiyor |

### 0.3 Ön Koşullar

Phase 4'e başlamak için gerekenler:
- [ ] `proves_verify_merkle_valid_64_depth` testi geçmeli
- [ ] AIR constraint'ler Goldilocks field'da doğru hesaplanmalı
- [ ] Prover trace matrix'te expansion row witness'ları doğrulanmalı

---

## 1. Phase 4 Hedefleri

### 1.1 Ana Hedef

**VerifyMerkle opcode'unu production'da aktif etmek** — B.U.D. Faz 3 (gerçek Proof-of-Storage) için gereken kriptografik altyapıyı tamamlamak.

### 1.2 Alt Hedefler

| # | Hedef | Kapsam |
|---|-------|--------|
| 4.1 | Test gate açılışı | `proves_verify_merkle_valid_64_depth` ignore'dan çıkar |
| 4.2 | Production gate açılışı | `bud-isa` production profile enable |
| 4.3 | B.U.D. Faz 3 entegrasyonu | ✅ Tamamlandı (ARENA1) |
| 4.4 | B.U.D. Faz 4 | ✅ Tamamlandı (ARENA1) |

---

## 2. Görev Detayları

### 2.1 Görev 4.1: Test Gate Açılışı

**Dosya:** `budzero/bud-proof/src/plonky3_prover.rs`
**Test:** `proves_verify_merkle_valid_64_depth`

**Yapılacaklar:**
1. `#[ignore]` annotation'ını kaldır
2. Testin geçmesini sağla:
   - Poseidon witness doğru hesaplanmalı
   - AIR constraints Goldilocks field'da doğru olmalı
   - Expansion rows doğru işlenmeli
3. Trace matrix debug çıktıları ekle (debug amaçlı)

**Kabul Kriteri:**
```
cargo test --package bud-proof proves_verify_merkle_valid_64_depth
→ test result: ok. 1 passed
```

### 2.2 Görev 4.2: Production Gate Açılışı

**Dosya:** `budzero/bud-isa/src/lib.rs`

**Yapılacaklar:**
1. `is_experimental()` fonksiyonunu güncelle:
   ```rust
   // Production'da VerifyMerkle aktif
   pub fn is_experimental(&self) -> bool {
       false  // ← Değişiklik
   }
   ```
2. `tur119_verify_merkle_disabled_in_production` testini güncelle veya kaldır
3. Production profile'da opcode'un çalıştığını doğrula

**Kabul Kriteri:**
```
cargo test --lib tur119_verify_merkle_disabled_in_production
→ Test güncellenmiş veya kaldırılmış olmalı

cargo run --release -- --verify-merkle-test
→ Proof üretilir ve doğrulanır
```

### 2.3 Görev 4.3: B.U.D. Faz 3 Entegrasyonu

**Dosya:** `src/domain/storage_deal.rs`, `src/storage/`

**Yapılacaklar:**
1. `StorageDeal` yapısına `merkle_proof` alanı ekle:
   ```rust
   pub struct StorageDeal {
       // ... mevcut alanlar ...
       
       /// 64-depth Merkle proof for VerifyMerkle challenge
       pub merkle_proof: Option<Vec<u8>>,
       
       /// Root hash that the proof should verify against
       pub storage_root: Hash32,
   }
   ```
2. Deal açarken Merkle proof talep et
3. Challenge yanıtında Merkle proof doğrulaması yap
4. `NotTheOperator` kontrolüne ek olarak Merkle proof kontrolü ekle

**Kabul Kriteri:**
```
cargo test --lib bud_e2e
→ Deal açılır, Merkle proof sunulur, doğrulanır
```

### 2.4 Görev 4.4: B.U.D. Faz 4 — storage_root

**Dosya:** `src/core/block.rs`

**Yapılacaklar:**
1. `GlobalBlockHeader`'a `storage_root` alanı ekle:
   ```rust
   pub struct GlobalBlockHeader {
       // ... mevcut alanlar ...
       
       /// Merkle root of all storage commitments in this block
       pub storage_root: Hash32,
   }
   ```
2. `calculate_hash()` fonksiyonuna `storage_root` dahil et
3. Genesis block'ta `storage_root = hash(empty)` olarak başlat

**Kabul Kriteri:**
```
cargo test --lib storage_root
→ Block header'da storage_root hash'e dahil
```

---

## 3. Görev Dağılımı (AI Birlığı)

### 3.1 ARENA1 — Core Rust & B.U.D. Entegrasyon

| # | Görev | Öncelik |
|---|-------|---------|
| 4.3 | B.U.D. Faz 3: StorageDeal + VerifyMerkle entegrasyonu | 🔴 Kritik |
| 4.4 | B.U.D. Faz 4: GlobalBlockHeader.storage_root | 🟡 Orta |

**Sorumluluklar:**
- StorageDeal yapısına Merkle proof alanı eklemek
- Deal açma/kapama akışında proof doğrulaması
- Block header'a storage_root entegrasyonu

### 3.2 ARENA2 — ZK/AIR & Testing

| # | Görev | Öncelik |
|---|-------|---------|
| 4.1 | Test gate açılışı: `proves_verify_merkle_valid_64_depth` | 🔴 Kritik |
| 4.2 | AIR constraint debugging & verification | 🔴 Kritik |

**Sorumluluklar:**
- Prover'da `wrapping_add` bug'ı kontrolü
- AIR constraint'lerin Goldilocks field'da doğru hesaplanması
- Trace matrix debug ve doğrulama
- Testin `#[ignore]`'dan çıkarılması

### 3.3 ARENA3 — ISA Profile & Security

| # | Görev | Öncelik |
|---|-------|---------|
| 4.2 | Production gate açılışı: `is_experimental()` güncelleme | 🔴 Kritik |
| — | Security audit: VerifyMerkle production riskleri | 🟡 Orta |

**Sorumluluklar:**
- Production profile'da opcode enable
- Test güncelleme/kaldırma
- Production'a geçiş risk analizi
- Emergent bug tespiti

---

## 4. Teknik Detaylar

### 4.1 VerifyMerkle Opcode Semantiği

```rust
// Pseudocode
VerifyMerkle rd, rs1, rs2, imm:
    // rs1: Merkle root (32 bytes)
    // rs2: Leaf to verify (32 bytes)
    // imm: Path length (0-64)
    // rd: Result (0 = fail, 1 = success)
    
    let path = read_path_from_registers(rs2+1, imm);
    let computed_root = merkle_verify(rs1, rs2, path);
    set_register(rd, computed_root == rs1 ? 1 : 0);
```

### 4.2 AIR Constraints

```
// Poseidon permutation için:
// input[i] = pre_state[i] + circuit_column[i]

// Merkle verification için:
// path[i] = hash(path[i-1], sibling[i]) veya hash(sibling[i], path[i-1])

// Final check:
// computed_root == expected_root
```

### 4.3 Goldilocks Field

```rust
// Goldilocks field: 2^64 - 2^32 + 1
pub const GOLDILOCKS_MODULUS: u64 = 0xFFFFFFFF00000001;

// Wrapping addition (overflow is valid in Goldilocks)
pub fn wrapping_add(a: u64, b: u64) -> u64 {
    let sum = a.wrapping_add(b);
    if sum >= GOLDILOCKS_MODULUS {
        sum - GOLDILOCKS_MODULUS
    } else {
        sum
    }
}
```

---

## 5. Riskler

| Risk | Olasılık | Etki | Azaltma |
|------|----------|------|---------|
| AIR constraints yanlış | Orta | Yüksek | Kapsamlı test + formal verification |
| Performance yetersiz | Yüksek | Orta | Profiling + optimization |
| Security vulnerability | Düşük | Çok Yüksek | External audit |
| Integration hatası | Orta | Orta | E2E test |

---

## 6. CI/CD Gereksinimleri

```yaml
# GitHub Actions
- cargo test --lib
- cargo test --package bud-zero proves_verify_merkle_valid_64_depth
- cargo clippy --lib --tests -- -D warnings
- cargo fmt --all -- --check
```

---

## 7. Sonraki Adımlar (Phase 5)

Phase 4 tamamlandıktan sonra (Kullanıcı Kararı: Tüm öncelikler paralel):
- **Phase 5.1:** External audit + final hardening
- **Phase 5.2:** Bug Bounty (Immunefi) açılışı
- **Phase 5.3:** TLA+ Formal Verification (Mantıksal İspat)
- **Phase 5.4:** Disaster Recovery (Yedekten Dönme) Tatbikatı

---

## 8. Referanslar

- `budzero/bud-isa/src/lib.rs` — Opcode tanımları
- `budzero/bud-proof/src/plonky3_prover.rs` — Prover implementasyonu
- `src/domain/storage_deal.rs` — B.U.D. deal yapıları
- `src/core/block.rs` — Block header
- `docs/STATUS_ONLINE.md` — AI birliği iletişim

---

## 9. Commit Format

Her görev için atomik commit:

```
feat(zk): Phase 4 — [kısa açıklama]

Açıklama...

Kabul kriteri: [test adı]
İlgili issue: [varsa]
```

---

**Not:** Bu plan AI birlığı tarafından koordineli olarak uygulanacaktır.
Force-push YASAK. Rebase ile çözümle.
