# VerifyMerkle Z-B Gate — Constraint-by-Constraint Debug (ARENA3, devam)

**Tarih:** 2026-07-16 01:00 UTC+3
**HEAD:** `2250795` (BNS full_integration) + `9387fb1` (ARENA2 Phase 4 devralma)
**Denetçi:** ARENA3 (ISA + security) + ARENA2 (ZK/AIR)
**Talimat:** Q verifymerkle_debug = constraint_by_constraint (10-soru anket v2) + Q bns_storage_flow = full_integration

---

## 1. Mevcut Durum Özeti

| Bileşen | Durum | Kanıt |
|---------|-------|-------|
| `bud-isa` `is_experimental` | `true` (kapalı) — Q2 enable_prod ARENA2 tarafından fail-closed revert (4aa5079) | `budzero/bud-isa/src/lib.rs:42` `matches!(VerifyMerkle)` |
| `proves_verify_merkle_valid_64_depth` | `#[ignore]` InvalidProof | `budzero/bud-proof/src/plonky3_prover.rs:1981` |
| `phase4_diagnose_verify_merkle_matrix_chain` | ✅ YEŞİL | ARENA2: 64-depth Poseidon zinciri + leaf + final root witness STARK olmadan yeşil |
| AIR leaf-bind / first-round | ✅ Fixlendi | `on_original = is_vm * (1-is_expand)` gate |
| VM expansion next_pc | ✅ Fixlendi | ara satırlar `next_pc=pc`, son expand `pc+1` |
| Gas + register_events + aux is_real_op + program LogUp | ✅ Fixlendi | expand sentetik satırlar skip/gate |

**Hâlâ InvalidProof:** witness zinciri OK → kalan ihtimal **aux CTL / degree / global constraint** veya başka bir AIR satırı.

---

## 2. Constraint-by-Constraint Debug Stratejisi (Q: constraint_by_constraint)

Kullanıcı kararı: her AIR constraint'i tek tek devre dışı bırakıp hangi constraint InvalidProof veriyor bul.

### 2.1 AIR Constraint Listesi (plonky3_air.rs)

| # | Constraint | Dosya:Satır | Açıklama | Test |
|---|------------|-------------|----------|------|
| 1 | `merkle_current` transition (Poseidon output) | `plonky3_air.rs:633` `nxt_merkle_current == poseidon_output` | Poseidon permutation round sonrası current | `phase4_diagnose_...` yeşil |
| 2 | Final root check | `plonky3_air.rs:645` `merkle_current - rs1_val` (original step) | 64th round output == expected root | Yeşil (matrix) |
| 3 | Leaf binding | `plonky3_air.rs:685` `nxt_merkle_current == rs2_val` (first expansion) | First expand merkle_current = leaf | Yeşil |
| 4 | Bit handling (sibling order) | `plonky3_air.rs:565-568` `s0/s1` bit check | `merkle_current*(1-bit) + sibling*bit` vs etc | ? |
| 5 | Poseidon round constants | `plonky3_air.rs:570` | RC0, RC1 doğru mu? | ? |
| 6 | is_poseidon bool | `plonky3_air.rs:287` `assert_bool(is_poseidon)` | is_poseidon 0/1 mi? | ? |
| 7 | is_verify_merkle bool + expand bool | `plonky3_air.rs:??` | VerifyMerkle flag'leri bool mu? | ? |
| 8 | Aux CTL (register bus) | `plonky3_air.rs:??` + `plonky3_prover.rs` register_events | Expand satırları bus'a giriyor mu? Fixlendi ama CTL degree? | **Şüpheli — kırmızı** |
| 9 | Program LogUp (lookup) | `plonky3_prover.rs` program bus | Expand sentetik satırlar program bus'ta mı? Fixlendi ama degree? | **Şüpheli** |
| 10 | Gas accounting | `plonky3_air.rs` | Expand gas tekrar sayımı fixlendi | Yeşil |

### 2.2 İzolasyon Planı

1. **Phase 1:** Tüm AIR constraint'leri devre dışı bırak, sadece `phase4_diagnose_verify_merkle_matrix_chain` (witness only) yeşil mi kontrol et → yeşil (zaten)
2. **Phase 2:** Constraint'leri teker teker aktif et:
   - Önce sadece `merkle_current` transition (1) → prove
   - Sonra final root (2) → prove
   - Sonra leaf binding (3) → prove
   - Sonra bit handling (4) → prove
   - ... en son aux CTL (8) ve Program LogUp (9)
3. **Hangi constraint aktif edince InvalidProof oluyor, o constraint şüpheli.**
4. **Küçük depth testi:** 64-depth yerine 1-depth, 2-depth ile prove dene. 1-depth yeşil, 64-depth kırmızı ise expansion row sayısı / degree problemi.
5. **Degree check:** Plonky3 AIR degree: Poseidon S-box (degree 7?) + Merkle bit handling degree? Goldilocks field'da degree çok yüksekse STARK prover degree bound aşar.

### 2.3 Önerilen Kod Değişiklikleri (debug harness)

```rust
// plonky3_air.rs içinde geçici debug feature
#[cfg(feature = "debug-constraint")]
{
    // Constraint 8 ve 9'u atla
    if !cfg!(debug_skip_aux) {
        // aux CTL constraints
    }
}
```

Veya test içinde:

```rust
#[test]
#[ignore]
fn phase4_verify_merkle_1_depth() {
    // key=0, sibling=[1], leaf=0xBEEF, depth=1
    // Sadece 1 round, expansion row sayısı az, degree düşük
}
```

---

## 3. BNS Full Integration (Q: full_integration)

**Durum:** Q bns_storage_flow = full_integration per 10-soru v2.

**Mevcut (2250795):**
- `BnsRegistry` → `register_with_storage`, `resolve_full`, `set_storage`
- `ChainCommand::BnsResolveFull` + `BnsSetStorage` + `ChainHandle::bns_resolve_full` + `bns_set_storage`
- `BudlumApi`: `bud_bnsResolveFull` (address + storage_root) + `bud_bnsSetStorage` (owner only)
- `TransactionType::BnsRegister` + Executor + RPC `bud_bnsResolve`/`bud_bnsPrepareRegister`
- Tests: `test_bns_full_impl_storage_binding` + `set_storage_owner_only` + `phase3_validator_onboarding_e2e_*`

**Sıradaki:**
- `bud_bnsResolveFull` → `ContentManifest` → `ContentId` → `bud_storageGetDealsByManifest` → Bitswap fetch via `bud-node` `ContentDiscovery` + `BudBitswap`
- Yani: `ahmet.bud` → BnsResolved { storage_root, storage_domain_id } → manifest_id = storage_root → `get_manifest` → shards → `discovery.get_providers` → `bitswap.request`
- Bu akış `src/network/node.rs` `BudlumBehaviour` içinde KAD + Bitswap zaten var (100ac26 monolithic integration), sadece RPC glue eksik.

**Öneri:** Yeni RPC `bud_bnsFetchContent(name) -> Result<ContentManifest+first chunk>` — BNS resolve + discovery + bitswap tek çağrıda.

---

## 4. Mainnet Ceremony (Q: keep_dummy)

- `config/mainnet.toml` bootnodes dummy 3 + dns_seeds 2 (Q7 add_dummy)
- `src/core/chain_config.rs` `MAINNET_BOOTNODES` hâlâ `[]` — binary built-in liste toml ile senkron değil; isteğe bağlı sonraki committe senkronize edilebilir (ARENA2 notu)
- Ceremony durumu: `pending`, gerçek multiaddr yok — bilinçli borç, `MAINNET_GENESIS_CEREMONY.md`'de prosedür var

---

## 5. HSM (Q: keep_real_only)

- Sadece gerçek PKCS#11, mock yok — AI_BIRLIGI §5 korundu
- `src/crypto/pkcs11.rs` BLS/PQ data object storage + software sign, vendor-native audit item
- `src/cli/commands.rs` `hsm_socket_path` PKCS#11 için korunuyor (`./data/hsm/socket.sock`)

---

## 6. Sonraki Adım (hepsi paralel)

- **Hat A ZK:** ARENA2 constraint-by-constraint debug (bu dokümanda plan) + ARENA3 is_experimental gate (test yeşil olunca tekrar açma)
- **Hat B BNS:** BNS → storage fetch full integration RPC glue (bns_resolve_full + discovery)
- **Hat C Audit:** Phase 5 external audit checklist + bug bounty + TLA+ iskeleti

**Kanıt:** `git log origin/main --oneline -5` → 2250795 BNS full_integration, 9387fb1 ARENA2 devralma, 51dbaf9 10 soru, 7482dd7 BNS full_impl merge
**Engel:** STARK InvalidProof kök neden (aux CTL). Force-push YASAK.

Co-authored-by: ARENA3 (ISA) + ARENA2 (ZK)
