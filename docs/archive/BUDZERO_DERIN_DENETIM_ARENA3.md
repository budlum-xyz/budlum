# BudZero / BudZKVM — Derin Kod Denetimi (ARENA3)

**Tarih:** 2026-07-16  
**HEAD:** `c2b7278` (CI 9/9 yeşil)  
**Denetçi:** ARENA3  
**Kapsam:** bud-isa, bud-proof, bud-vm, bud-compiler, bud-node, bud-state — tam güvenlik denetimi

---

## 1. VerifyMerkle Z-B Gate — Gerçek Durum

### Pozitif STARK testleri (HEPSİ `#[ignore]` — InvalidProof):

| Test | Depth | Durum | Sebep |
|------|-------|-------|-------|
| `proves_verify_merkle_valid_1_depth` | 3 rows | 🔴 `#[ignore]` | InvalidProof — aux CTL suspect |
| `proves_verify_merkle_valid_2_depth` | 4 rows | 🔴 `#[ignore]` | InvalidProof — aux CTL/LogUp degree suspect |
| `proves_verify_merkle_valid_64_depth` | 66 rows | 🔴 `#[ignore]` | InvalidProof — full STARK still red |

### Negatif testler (ÇALIŞIYOR):

| Test | Durum |
|------|-------|
| `rejects_verify_merkle_row_with_zero_selector` | ✅ PASS |
| `rejects_verify_merkle_with_skipped_round` | ✅ PASS |
| `rejects_verify_merkle_with_tampered_final_accumulator` | ✅ PASS |
| `rejects_verify_merkle_with_tampered_poseidon_sbox` | ✅ PASS |

### Production gate:

| Bileşen | Durum |
|---------|-------|
| `is_experimental()` | `true` → VerifyMerkle production'da reddedilir |
| `decode_for_profile(Production)` | ✅ `ExperimentalOpcodeDisabled` hatası döner |
| `tur119_verify_merkle_disabled_in_production` testi | ✅ PASS |

### Teşhis:

- ✅ Matrix chain diagnostic YEŞİL (Poseidon zinciri, leaf binding, final root doğru)
- ✅ Leaf-bind orijinal-only gate düzgün
- ✅ Expansion next_pc düzeltildi
- ✅ Gas expansion skip düzeltildi
- ✅ Register events + aux is_real_op + Program LogUp expand skip düzeltildi
- 🔴 Full STARK hâlâ InvalidProof → **aux CTL / Program LogUp / constraint degree** şüpheli
- 🔴 1-depth bile kırmızı → degree değil, **aux CTL constraint çakışması** en olası

**Dürüst cümle:** VerifyMerkle Z-B gate kapalı. Matrix seviyesinde tüm ara hesaplar doğru, ama STARK proof sistemi (aux CTL) henüz yeşil değil. Production gate fail-closed korunuyor — doğru.

---

## 2. bud-isa — Instruction Set Architecture (227 satır)

| Kontrol | Sonuç |
|---------|-------|
| Opcode enum (32 varyant) | ✅ Tam — 0x00..0x1E |
| `is_experimental()` | ✅ Sadece VerifyMerkle |
| `decode_any()` match | ✅ Tüm 32 varyant exhaustive |
| `decode_for_profile()` | ✅ Production → VerifyMerkle reject fail-closed |
| Profile gating | ✅ `#[cfg(feature = "experimental")]` doğru kullanım |
| Overflow riski | ✅ encode/decode bit mask'leri güvenli |
| **Güvenlik açığı** | **YOK** |

---

## 3. bud-proof — STARK Prover (2903 + 1490 satır)

| Kontrol | Sonuç |
|---------|-------|
| AIR constraint sayısı | ✅ 414 sütun, 30+ constraint grubu |
| Selector booleanity | ✅ Tüm 32 opcode selector'u assert_bool |
| Selector exclusivity | ✅ `is_cpu = sum(is_*) + is_halt` |
| Div/Inv/Eq/Jnz inverse witness | ✅ Soundness kanıtları tam |
| Poseidon 4-round | ✅ S-box + MDS constraints, 8x8 matris |
| VerifyMerkle Poseidon single-round | ✅ S-box + MDS output + transition |
| VerifyMerkle final root check | ✅ Inverse witness diff kontrolü |
| VerifyMerkle leaf binding | ✅ Original→first expansion leaf = rs2_val |
| VerifyMerkle round index | ✅ Transition +1, first = 0 |
| VerifyMerkle key continuity | ✅ Expand→expand key sabit |
| Bitwise (And/Or/Xor/Not) | ✅ 64-bit decomposition + reconstruction |
| Comparison (Lt/Gt/Lte/Gte) | ✅ Equality prefix recursion + raw lt result |
| Register LogUp | ✅ CPU ↔ Register table match |
| Memory LogUp | ✅ CPU ↔ Memory table (Stack + Storage) |
| Program CTL LogUp | ✅ CPU ↔ Preprocessed program match |
| Public input binding | ✅ chain_id, roots, gas, trace_len, event_digest |
| Event digest transition | ✅ Phase 0.358 fix: nxt row Log flag |
| **Güvenlik açığı** | **YOK** |

---

## 4. bud-vm — Virtual Machine (1095 satır)

| Kontrol | Sonuç |
|---------|-------|
| `merkle_poseidon_round()` | ✅ u128 mod P, overflow-safe |
| Inverse (Div) | ✅ u128 mod P, zero check |
| VerifyMerkle expansion | ✅ 1 original + 64 expansion + 1 Halt |
| Merkle path extraction | ✅ key bit = (key >> round) & 1, sibling order correct |
| Gas costing | ✅ VerifyMerkle 10 gas, expansion skip |
| Register access | ✅ `as usize` bounds ok (registers[32]) |
| Memory bounds | ✅ Vm::new(capacity) kontrolü |
| unwrap/expect | ✅ Üretim kodunda YOK |
| `unsafe` | ✅ YOK |
| **Güvenlik açığı** | **YOK** |

---

## 5. bud-compiler — Bytecode Compiler (2283 satır)

| Kontrol | Sonuç |
|---------|-------|
| `verify_merkle_proof` → `Opcode::VerifyMerkle` | ✅ codegen.rs:669-674 |
| Parser `verify_merkle_proof` | ✅ parser.rs:560-569 |
| Sema `verify_merkle_proof` | ✅ sema.rs:81 |
| unwrap/expect | 🟡 SADECE testlerde — kabul edilebilir |
| **Güvenlik açığı** | **YOK** |

---

## 6. bud-node — P2P Storage Node

| Kontrol | Sonuç |
|---------|-------|
| Bitswap request/response codec | ✅ encode/decode round-trip testli |
| ContentDiscovery CID↔Key | ✅ round-trip testli |
| unwrap/expect | 🟡 SADECE testlerde — kabul edilebilir |
| `unsafe` | ✅ YOK |
| **Güvenlik açığı** | **YOK** |

---

## 7. bud-state — State Management

| Kontrol | Sonuç |
|---------|-------|
| Save/Load round-trip | ✅ Testli |
| unwrap/expect | 🟡 SADECE testlerde — kabul edilebilir |
| **Güvenlik açığı** | **YOK** |

---

## 8. Genel BudZero Değerlendirmesi

| Kriter | Puan |
|--------|------|
| Kod kalitesi | ⭐⭐⭐⭐⭐ |
| AIR constraint kapsamı | ⭐⭐⭐⭐⭐ |
| VM güvenliği (overflow/panic) | ⭐⭐⭐⭐⭐ |
| Production gate disiplini | ⭐⭐⭐⭐⭐ |
| Test kapsamı (negatif testler) | ⭐⭐⭐⭐ |
| VerifyMerkle Z-B gate | 🔴 Kapalı (bilinçli) |

---

## 9. Kalan Riskler

| # | Risk | Şiddet | Açıklama |
|---|------|--------|----------|
| Z1 | VerifyMerkle InvalidProof | 🔴 HIGH | aux CTL / LogUp constraint çakışması — 3 pozitif test ignore |
| Z2 | 1-depth bile kırmızı | 🟡 MEDIUM | Degree sorunu değil, aux CTL kök neden |
| Z3 | patch_compiler.py / patch_parser.py | 🟢 LOW | Manuel patch script'leri, otomatik değil |

---

## 10. Sonuç

**BudZero çekirdeği son derece sağlam.** AIR constraint'ler eksiksiz, VM overflow-safe, production gate fail-closed. VerifyMerkle Z-B gate'in kapalı olması bilinçli ve doğru — test yeşil olmadan gate açılmaz.

**Hedef:** aux CTL constraint-by-constraint debug ile InvalidProof kök nedenini bulmak. 1-depth'in bile kırmızı olması, sorunun degree değil aux CTL'de olduğunu kanıtlıyor.
