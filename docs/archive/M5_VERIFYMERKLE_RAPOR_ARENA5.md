# M5 VerifyMerkle Z-B Gate — Phase 7 Etki Analizi

**Hazırlayan:** ARENA5  
**Tarih:** 2026-07-15  
**Branch:** `arena/019f63ce-budlum`  
**HEAD referans:** `origin/main` = `dc3325e`  
**Durum:** Rapor — Phase 7 Mainnet Launch Ceremony karar desteği

---

## 1. Soru

> **VerifyMerkle Z-B gate (M5) kapalı iken mainnet launch yapılabilir mi?**

## 2. Mevcut Durum (Kod Kanıtlı)

### 2.1 VerifyMerkle Production Gate

```
budzero/bud-isa/src/lib.rs:39-46
```

- `Opcode::VerifyMerkle = 0x1E` → `is_experimental()` → **true**
- Production profile: `experimental` feature **off** → VerifyMerkle decode **reddedilir** (fail-closed)
- Test profile: `experimental` feature **on** veya `#[cfg(test)]` → VerifyMerkle decode **izinli**
- `tur119_verify_merkle_disabled_in_production` → production'da VerifyMerkle **reddedilmeli** (test PASSED)

### 2.2 64-depth STARK Test

```
budzero/bud-proof/src/plonky3_prover.rs:1749+
```

- `proves_verify_merkle_valid_64_depth` → **`#[ignore]`** (hâlâ kırmızı)
- `proves_verify_merkle_valid_1_depth` → ARENA3 ekledi (depth_1 isolation)
- `proves_verify_merkle_valid_2_depth` → ARENA2 ekledi (depth_2 isolation)
- Matrix chain diagnostic → **yeşil** (constraint yapısı doğru)
- Full STARK prove (64-depth) → **kırmızı** (InvalidProof, aux CTL / LogUp şüpheli)

### 2.3 B.U.D. Faz 3 Bağımlılığı

| Bileşen | VerifyMerkle Bağımlılığı | Mevcut Durum |
|---------|--------------------------|-------------|
| `StorageDeal.merkle_proof` | Faz 3'te zorunlu olacak | Faz 2: `None` (interim) |
| `ContentId` deterministik hash | Poseidon (STARK-dostu) | ✅ Çalışıyor |
| `RetrievalChallenge` | Byte-range erişilebilirlik (interim) | ✅ Çalışıyor (geçici) |
| Gerçek Proof-of-Storage | `VerifyMerkle` 64-depth yeşil | ❌ Kapalı |

## 3. Etki Analizi: M5 Kapalı İken Mainnet Launch

### 3.1 Güvenilir Olan (Launch Engel DEĞİL)

| Özellik | Neden Engel Değil |
|---------|-------------------|
| **L1 Multi-Consensus Settlement** | PoW/PoS/PoA/BFT finality adapters VerifyMerkle'dan **bağımsız** |
| **BLS Finality Protocol** | BLS12-381 prevote/precommit, VerifyMerkle'dan **bağımsız** |
| **Bridge Lock/Mint/Burn/Unlock** | Merkle proof'lar `bridge.rs` içinde SHA3/Keccak ile, BudZero STARK'tan **bağımsız** |
| **B.U.D. Faz 1-2 + Faz 5** | `ContentId` (Poseidon hash) + `StorageDeal` ekonomisi, VerifyMerkle'dan **bağımsız** |
| **BNS/.bud Phase 6** | İsim çözümleme + storage_root binding, VerifyMerkle'dan **bağımsız** |
| **RPC/P2P/Snapshot/Metrics** | Tüm altyapı, VerifyMerkle'dan **bağımsız** |
| **Phase 5 Universal Relayer** | Cross-chain relay, VerifyMerkle'dan **bağımsız** |

### 3.2 Etkilenen (Kısıtlı veya Kapalı Kalacak)

| Özellik | Etki | Risk Seviyesi |
|---------|------|---------------|
| **B.U.D. Faz 3 (Gerçek PoS)** | Açılamaz — `VerifyMerkle` kapalı olduğu için gerçek depolama kanıtı üretilemez | 🟠 Orta |
| **BudZKVM STARK Contract Execution** | `zkvm_contracts = false` (mainnet.toml) — ZKVM üzerinden STARK kanıtı ile contract çalıştırma kapalı | 🟠 Orta |
| **ZK Finality Adapter** | `ZkFinalityAdapter` var ama production'da STARK proof kabul etmez (fail-closed) | 🟡 Düşük |

### 3.3 Overclaim Riski

M5 kapalı iken launch yapılırsa, aşağıdaki iddialar **geçersiz** olur:

| İddia | Gerçek |
|-------|--------|
| "Tam Proof-of-Storage" | ❌ Sadece interim retrieval challenge (byte-range, kriptografik kanıt yok) |
| "ZKVM ile STARK-doğrulanabilir contract" | ❌ Kapalı (`zkvm_contracts = false`) |
| "31 opcode production" | ❌ 30/31 — `VerifyMerkle` (0x1E) kapalı |

## 4. ARENA5 Karar Önerisi

### Seçenek A: M5 Kapalı İken Launch (Önerilen ✅)

**Gerekçe:**
1. **L1 core functionality tamamen bağımsız** — PoW/PoS/PoA/BFT settlement, bridge, BLS finality, B.U.D. Faz 1-2+5, BNS, RPC, P2P hepsi çalışıyor.
2. **Fail-closed güvenlik** — VerifyMerkle kapalı iken sahte kanıt kabul edilemez, sistem güvenli.
3. **Dürüst dokümantasyon** — README + THREAT_MODEL + STATUS'ta "VerifyMerkle kapalı, B.U.D. Faz 3 interim" yazılır. Overclaim yok.
4. **Post-launch güncelleme** — VerifyMerkle yeşil olduğunda, soft-fork ile `is_experimental()` → false yapılır, Faz 3 aktif olur.
5. **Sektör standardı** — Ethereum bile fazlı launch yaptı; "her şey hazır" beklemek sonsuz döngü yaratır.

**Koşullar:**
- [ ] `THREAT_MODEL.md` §3.2 açıkça "VerifyMerkle kapalı, Faz 3 interim" yazmalı
- [ ] `README.md` "31 opcode" iddiası → "30/31 opcode (VerifyMerkle experimental gate kapalı)" olarak düzeltilmeli
- [ ] `ORG_ROADMAP_AUDIT.md` Faz 3 durumu "⏳ Post-launch activation" olarak güncellenmeli
- [ ] `MAINNET_GENESIS_CEREMONY.md` "M5 bilinçli kapalı, activation koşulları" bölümü eklenmeli

### Seçenek B: M5 Yeşil Olana Kadar Bekle

**Gerekçe:**
- VerifyMerkle 64-depth STARK kanıtı gerçek PoS için şart.
- "Tam özellikli" launch.

**Riskler:**
- 2-3 hafta tahmini süre ama belirsiz (aux CTL / LogUp karmaşık debug)
- Diğer mainnet engelleyiciler (M6 HSM donanım, M7 external audit) de bekler → **launch süresiz ertelenir**
- Momentum kaybı

### Seçenek C: Hibrit — Conditional Launch

**Gerekçe:**
- Mainnet launch yapılır ama B.U.D. storage operator kaydı **davetiye ile** sınırlı tutulur.
- VerifyMerkle yeşil olduğunda permissionless storage açılır.

**Değerlendirme:** `CLAUDE.md` §0 permissionless mimari kuralı ile çelişir ("whitelist YOK"). **Önerilmez.**

## 5. Sonuç

| Karar | ARENA5 Önerisi |
|-------|----------------|
| **M5 kapalı launch** | ✅ **Önerilen** (Seçenek A) |
| Koşul | Dürüst dokümantasyon + fail-closed gate + post-launch activation planı |
| Zamanlama | Phase 7 ceremony, M5'ten **bağımsız** planlanır |
| Activation | VerifyMerkle 64-depth yeşil → soft-fork PR → `is_experimental()` kaldır → Faz 3 aktif |

## 6. Kanıt Komutları

```bash
# VerifyMerkle experimental gate
git show origin/main:budzero/bud-isa/src/lib.rs | grep -A5 "is_experimental"

# Production fail-closed test
git show origin/main:budzero/bud-isa/src/lib.rs | grep -A10 "tur119_verify_merkle"

# 64-depth test ignored
git show origin/main:budzero/bud-proof/src/plonky3_prover.rs | grep -B2 "proves_verify_merkle_valid_64"

# mainnet.toml features
git show origin/main:config/mainnet.toml | grep -A3 "\[features\]"
```

---

**Force-push YASAK. Workflow push YASAK.**  
Co-authored-by: ARENA5
