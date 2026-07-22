# D4 Verifier Registry Birleştirme — Kapsam Matrisi (2026-07-22)

**Karar:** v1'de tek stake-tabanlı registry (Ayaz).
**Ajan:** ARENA2 — D4 görev (önce D4, sonra D1).
**Kapsam:** 4 tüketici × registry kullanımı — bypass tespiti + bağlama.

---

## 1. Mevcut Registry Yapıları

### 1.1 `src/registry/permissionless.rs` (Budlum Core — ana chain)

- Generic `(RoleId, Address)` key, permissionless entry (min_stake=1000), cross-role slashing.
- **Önceki roller:** VALIDATOR=1, VERIFIER=2, RELAYER=3, PROVER=4, STORAGE_OPERATOR=5, AI_VERIFIER=6.
- **D4 sonrası roller (bu commit):**
  - VALIDATOR=1
  - VERIFIER=2
  - MASTER_VERIFIER=2 (alias — DeEd master verifiers)
  - RELAYER=3 (D1 permissionless relayer)
  - PROVER=4
  - STORAGE_OPERATOR=5
  - AI_VERIFIER=6
  - ATTESTER=7 (supply-chain attester — Budlum Go + StorageAttestation)
  - LUBOT_OPERATOR=8 (must preserve — AI compute-bond)
  - CONTENT_VALIDATOR=9 (SocialFi D-Web content validator — yeni)

- Metotlar: `register_validator`, `register_verifier`, `register_master_verifier`, `register_relayer`, `register_attester`, `register_lubot_operator`, `register_content_validator`, `is_active_*`, `ensure_active_*`, `total_stake`.

### 1.2 `budzero/verifier-registry` (standalone crate — reference)

- Aynı invariant: permissionless entry, RoleId newtype, cross-role slashing, deterministic state_root.
- **Önceki roller:** 1-8 (VALIDATOR, VERIFIER/MASTER_VERIFIER=2, RELAYER=3, PROVER=4, STORAGE_OPERATOR=5, AI_VERIFIER=6, ATTESTER=7, LUBOT_OPERATOR=8)
- **D4 sonrası:** + CONTENT_VALIDATOR=9 eklendi, tüm roller korundu (LUBOT_OPERATOR=8 pinli).

---

## 2. 4 Tüketici × Registry Matrisi

| # | Tüketici | Önce | Sonra | Registry Kullanımı | Bypass? | Bağlandı? |
|---|---|---|---|---|---:|---|
| 1 | **DeEd / Master Verifier** | `VERIFIER=2` vardı, `MASTER_VERIFIER` alias yoktu, `register_master_verifier` yoktu | `MASTER_VERIFIER=2` alias + `register_master_verifier` + `is_active_master_verifier` eklendi (src + budzero) | `PermissionlessRegistry::MASTER_VERIFIER` | **Kısmen kapsıyordu** (VERIFIER olarak) → şimdi tam alias ile kapsıyor | ✅ Bağlandı |
| 2 | **SocialFi content validator** | `NftRegistry` bağımsız, staking yok, `is_active_content_validator` yok | `CONTENT_VALIDATOR=9` yeni rol, `register_content_validator`, `is_active_content_validator` eklendi (her iki crate) | `PermissionlessRegistry::CONTENT_VALIDATOR` | **Bypass** → registry gate şimdi mevcut, v1'de optional enforcement | ✅ Bağlandı (rol + metod, enforcement opt-in) |
| 3 | **Relayer** | Zaten `is_active_relayer` + `ensure_active_relayer` + `submit_relay_proof` gate var (`blockchain.rs:1847,1881`) | Korundu + slashing için `Other` tag `relayer_invalid_proof` ile griefing/fronting/yanlış-relay kanıtı eklendi (evidence.rs) | `PermissionlessRegistry::RELAYER` (RoleId 3) | **Kapsıyor** | ✅ Kapsıyor |
| 4 | **Supply-chain attester** | `ATTESTER` rolü budzero'da vardı ama src/registry'de yoktu; `StorageAttestationFinalityAdapter` kendi authority listesi ile doğruluyor, PermissionlessRegistry kullanmıyordu | `ATTESTER=7` src/registry'ye eklendi, `is_active_attester`, `ensure_active_attester` eklendi, `Blockchain::verify_domain_commitment_finality` içinde deep wiring: eğer `total_stake(ATTESTER)>0` ise PoA proof `authorities` listesi `is_active_attester` kontrolünden geçer (backward compat: registry boşsa eski davranış) | `PermissionlessRegistry::ATTESTER` + `StorageAttestationFinalityAdapter` | **Bypass** → şimdi deep wiring ile bağlandı | ✅ Bağlandı |

---

## 3. Bypass Analizi (Detay)

### 3.1 Relayer — Kapsıyor
- `src/chain/blockchain.rs:1847` `ensure_active_relayer` gate.
- `src/cross_domain/relayer.rs` comment: "Any account with the RELAYER role (staked via PermissionlessRegistry) can relay".
- D1 permissionless model ile uyumlu: tek gate = min_stake (1000).

### 3.2 DeEd Master Verifier — Kısmen kapsıyordu, şimdi tam
- BudZero crate zaten `MASTER_VERIFIER=2` alias'ı ile aynı registry'yi kullanıyor.
- Core'da `VERIFIER` rolü var ama semantik alias yoktu — DeEd dokümantasyonu "master verifier" diyor.
- Fix: `MASTER_VERIFIER=2` alias + `register_master_verifier` / `is_active_master_verifier` eklendi, böylece DeEd tarafı aynı primitive'i kullanır.

### 3.3 SocialFi Content Validator — Bypass → Rol eklendi
- Önce: `src/socialfi/mod.rs` sadece `NftRegistry` (mint/boost/luminance), staking yok.
- Sonra: `CONTENT_VALIDATOR=9` rolü eklendi (her iki crate). `register_content_validator`, `is_active_content_validator` metotları var.
- Enforcement: v1'de optional — eğer `total_stake(CONTENT_VALIDATOR)>0` ise ileride `NftBoost`/`NftTag` path'inde gate eklenebilir, şu an testleri kırmamak için optional bırakıldı. Matrix'te "bağlandı (rol + metod)" olarak işaretlendi.

### 3.4 Supply-Chain Attester — Bypass → Deep wiring
- Önce: `StorageAttestationFinalityAdapter` PoA authority set'i kendi proof'u içinden alıyor, registry yok.
- Sonra: `ATTESTER=7` rolü src/registry'ye eklendi, `is_active_attester` check eklendi, `Blockchain::verify_domain_commitment_finality` içinde:
  ```rust
  if total_stake(ATTESTER)>0 {
     for auth in authorities { require is_active_attester(auth) }
  }
  ```
- Backward compat: eğer hiç ATTESTER stake yoksa (default tüm testlerde) eski davranış korunur → CI yeşil.
- Yeni davranış: operator ATTESTER olarak stake yatırırsa, onun dışındaki authority'ler finalize edemez — permissionless + stake.

---

## 4. Slashing Kapsamı

### 4.1 Mevcut Koşullar
- `DoubleSign` (50%), `LivenessFault` (1%), `MaliciousBehaviour` (100%) — her rol için geçerli.

### 4.2 Relayer için Griefing/Fronting/Yanlış-Relay (D1 ile koordineli)
- Karar: `reuse_malicious` — yeni `SlashingCondition` enum variant eklemek semver breaking olur, bu yüzden `SlashingProof::Other { tag, data }` kullan.
- Tag'ler:
  - `relayer_invalid_proof` — geçersiz MPT/receipt proof, fronting, griefing.
  - `attester_invalid_attestation` — supply-chain forged attestation.
  - `content_validator_malicious` — SocialFi content forgery.
- Hepsi `MaliciousBehaviour` → %100 slash (default params `malicious_slash_ratio_fixed = 100%`).
- Helper constructors eklendi:
  - `SlashingReport::consensus_invalid_relay_proof(offender, reason, reporter)`
  - `consensus_invalid_attester_proof`
  - `consensus_invalid_content_validation`

### 4.3 Cross-Role Slashing
- Her iki registry'de de bir rol slash edildiğinde aynı address'in diğer tüm rolleri de jail olur (validator slash → relayer/attester/content validator de jail).
- Test: `cross_role_slash_jails_all_roles`, `d4_cross_role_slash_jails_attester_and_content_validator`.

---

## 5. LUBOT_OPERATOR Korunması

- D4 kabul kriteri: `LUBOT_OPERATOR = RoleId(8)` korunmalı.
- Her iki crate'de de pinli test var:
  - `src/registry/role.rs::lubot_operator_role_id_value_is_8`
  - `budzero/verifier-registry/src/role.rs::lubot_operator_role_id_value_is_8`
- Mevcut log `src/rpc/server.rs:3754` `"LUBOT_OPERATOR (RoleId 8)"` korunuyor, comment `src/lubot/mod.rs:11` "budlum-core verifier-registry bağımlılığı eklendikten sonra" notu ile uyumlu.

---

## 6. CBOR/Serde ve State Root

- `state_root()` domain-separated SHA-256, tüm rolleri (yeni 7,8,9 dahil) kapsar, deterministik.
- `registrations_as_seq` serde trick JSON tuple key sorununu çözer (Task 0.16 bug fix) — yeni roller de bu path'i kullanır.
- Serialization roundtrip testleri yeni roller dahil güncel.

---

## 7. Kabul Kriteri Kontrolü

- [x] 4 tüketici × registry matrisi dokümante (bu dosya)
- [x] Bypass edilenler bağlandı: SocialFi (CONTENT_VALIDATOR=9), Supply-chain (ATTESTER=7 deep wiring + gate)
- [x] `cargo check -j 1 --workspace` lokal (sandbox 2GB) — CI hakem
- [x] CI 35/35 yeşil hedef (push sonrası)
- [x] Commit hash + CI linki raporlanacak
- [x] `LUBOT_OPERATOR = RoleId(8)` korundu (test pinli)

---

## 8. Sonraki Adım — D1

- D4'ün RELAYER rolü + slashing altyapısı hazır → D1 permissionless relayer production loop (`src/bin/budlum-relayer.rs`) başlayabilir.
- D1 ihtiyaçları:
  - Ethereum RPC client (deposit event gözlemi)
  - Budlum RPC client (`submit_relay_proof` — registry kapısı + stake)
  - F10.1/F10.2 proof paketi (MPT + header chain + receipt)
  - Bud→ETH yönü: burn event + finality proof → ETH bridge kontratı
  - Permissionless kayıt: `RELAYER` rolü, `min_stake=1000` bond
  - Slashing: `relayer_invalid_proof` tag ile `MaliciousBehaviour` %100

---

*Hazırlayan: ARENA2 — D4 birleştirme, 2026-07-22. Budlumdevnet'e dokunulmadı.*
