# P2 Schema-4 — Uygulama Planı (GAP-1 imza + GAP-2 hash-kapsam + B2 AssetId)

> **Durum:** UYGULAMA PLANI (koddan önce, RFC §8 P1-P4'ün detayı + B2 entegrasyonu).
> **Yazar:** ARENA1 (görev yöneticisi), 2026-07-18.
> **Temel:** main `3ce34dd` · schema_version şu an 3, hedef 4.
> **Kaynak RFC'ler:** `docs/RFC_GAP1_SNAPSHOT_MANIFEST_SIGNATURE.md` (APPROVED §8),
> `docs/RFC_ACCESSGRANT_V2_BUD_MARKETPLACE.md` §4 (tek-taraflı root YASAK).
> **Kullanıcı kararı:** `f10_before_mainnet` + GAP-1 §7.4 (tek schema-4).

---

## 0. Neden bu plan (metodoloji)

P2 schema-4, snapshot bütünlüğünün kök-neden çözümü: tek atomik PR'da
(GAP-1 manifest imzası + GAP-2 hash-kapsam genişletmesi + B2 cross_domain
AssetId struct migration). Bu üçü ayrı PR'lar olamaz çünkü:

- **GAP-2** (hash-kapsam) schema-4 digest'ini değiştirir → **tek-taraflı root
  değişikliği YASAK** (RFC_ACCESSGRANT_V2 §4, `f40f5f6` dersi); domain-separation
  prefix ile koordineli yapılmalı.
- **GAP-1** (imza) imzalı digest'i schema-4'e bağlar; GAP-2'siz imza, hash-lenmemiş
  alanları (forgery surface) kapatmaz.
- **B2** (AssetId struct) bridge_state'in serde + hash davranışını değiştirir;
  schema-4 digest'ine girerken yapı son halinde olmalı.

Üçü tek PR = tek breaking schema bump (3 → 4), tek domain-prefix, tek legacy-import.

---

## 1. GAP-2 — Hash-kapsam genişletmesi (calculate_hash)

**Mevcut boşluk (RFC_GAP1 §"Ek eksik"):** `calculate_hash` şu 14 alanı
kapsamıyor → enjeksiyon `verify()`'i rehash'siz geçer (forgery surface):

```
tokenomics, tokenomics_burn, registry, liveness, invalid_votes,
bns_registry, nft_registry, marketplace (pollen), hub, storage_registry,
bridge_state, message_registry, external_roots, finality_certificates, created_at
```

**Çözüm (P3 kapsamı):** `calculate_hash` → `calculate_digest` ayrıştırması (P1'de)
sonra, schema-4 digest'i bu 15 alanı içerir. Her alan için **deterministik serileştirme**
(sorted-key map → bytes; Vec sıralı; Option → None=0x00/Some=0x01+bytes):

| Alan | Serileştirme stratejisi |
|---|---|
| `tokenomics: TokenomicsParams` | bincode (zaten Serialize) |
| `tokenomics_burn: Option<TokenomicsBurnSnapshot>` | tag + bincode |
| `registry/liveness/invalid_votes: Option<_>` | tag + bincode |
| `bns_registry/nft_registry/marketplace/hub/storage_registry/ai_registry: Option<_>` | tag + bincode |
| `bridge_state/message_registry: Option<_>` | tag + bincode |
| `external_roots: Option<BTreeMap<_,_>>` | tag + sorted-key bincode |
| `finality_certificates: Vec<FinalityCert>` | len-prefix + bincode her elem |
| `created_at: u128` | le_bytes |

**Domain-separation prefix** (RFC §4, `f40f5f6` dersi): schema-4 digest'inin
başına `b"budlum.snapshot.v4"` eklenir. Schema-3 digest'i değişmez (eski
snapshot'lar backward-compat).

---

## 2. GAP-1 — Manifest imza alanları (schema-4 wire)

**Faz 1 (bu PR):** Ed25519 tek-imza + trust-list + AllowUnsigned geçişi.

**Yeni wire alanları (StateSnapshotV2, `#[serde(default)]`):**

```rust
// --- schema_version 4 (GAP-1, Phase 10.5 P2): manifest signature ---
/// Snapshot'ı imzalayan party'nin pubkey'i (trust-list'ten). None = AllowUnsigned.
#[serde(default)]
pub manifest_signer: Option<[u8; 32]>,
/// Ed25519 imzası: sign(manifest_digest). manifest_digest = calculate_digest()
/// (schema-4 prefix + tüm alanlar). None = AllowUnsigned (devnet/legacy-import).
#[serde(default)]
pub manifest_signature: Option<Vec<u8>>,
/// Trust policy: AllowUnsigned (devnet/geçiş) | RequireSigned (production).
#[serde(default)]
pub trust_policy: SnapshotTrustPolicy,
```

`SnapshotTrustPolicy` enum: `AllowUnsigned | RequireSigned`. Production config
`RequireSigned` zorunlu (derleme-uyarısı AllowUnsigned için mainnet build'de).

**`verify_authentic` metodu:**
1. `manifest_digest = self.calculate_digest()` (GAP-2 genişletilmiş, §1).
2. Policy `AllowUnsigned` → digest eşleşiyorsa OK (signer/sig None).
3. Policy `RequireSigned` → signer trust-list'te mi + Ed25519 verify(digest, sig, signer).

**Loader (P2):** karantina sınıfı `AuthFailure` (imzasız snapshot production'ta →
karantina, boot fail-loud). CLI flag `--allow-unsigned-snapshot` (devnet/legacy-import).

---

## 3. B2 — cross_domain AssetId alias → struct (P2 içinde)

**Mevcut (PR #49 WIP, GAP-2'ye ertelendi `9bc3094`):** `pub type AssetId = Hash32`
(serde_json map-key patlar — R3 anti-pattern).

**Migration (~30 site, ARENA1 harita `9bc3094`):**

- `bridge.rs:12` alias → `pub struct AssetId(pub [u8; 32])` (Address deseni, string-serde).
- `bridge.rs:318/393` hash_fields_bytes: `asset_id` → `asset_id.as_ref()`.
- Yardımcı fonksiyonlar: `bridge_lifecycle.rs:18 fn asset_id() -> [u8;32]` → `-> AssetId`;
  `relayer_e2e.rs:22 fn asset() -> Hash32` → `-> AssetId`; `bridge_relayer.rs:459 fn asset()`.
- Inline literal'lar: `chaos.rs` (143/151/522/527/701/719), `pow_light_client.rs` (65/68),
  `bridge_negatives.rs` (88/102), `rpc/tests.rs` (423), `settlement_prod.rs` (5 site),
  `bridge_lifecycle.rs` kalan inline → `AssetId(hash_fields_bytes(...))` wrap.
- Production: `blockchain.rs` (tip-notasyonu çoğunlukla güvenli, az coercion), `api.rs:102`,
  `bridge_relayer.rs:460`.

**Snapshot etkisi:** `bridge_state: Option<BridgeState>` zaten serde round-trip ediyor;
B2 struct'la `BTreeMap<AssetId, _>` artık JSON-safe → GAP-2 hash'lemesi düzgün çalışır.

---

## 4. Birleşik schema-4 uygulama sırası (tek PR, atomik commit'ler)

| Commit | Kapsam | Kapı |
|---|---|---|
| **C1** | `AssetId` struct (B2) + 30-site migration (yardımcılar + inline + production) | derleme + 30 E0308 kapalı |
| **C2** | `calculate_hash` → `calculate_digest` refactor (ayrıştırma, davranış korur) | mevcut testler yeşil |
| **C3** | GAP-2: schema-4 digest (15 alan + `budlum.snapshot.v4` prefix) | GAP-2 pin testi (`..._unhashed_field_forgery_gap`) |
| **C4** | GAP-1: wire alanları (manifest_signer/signature/trust_policy) + `verify_authentic` + `SnapshotTrustPolicy` | unit testler (AllowUnsigned + RequireSigned + forgery RED) |
| **C5** | Loader karantina (AuthFailure) + CLI flag + config wiring | chaos/rotation testleri |
| **C6** | `CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION = 4` + legacy-import geçişi (schema-3 → 4) | snapshot roundtrip cross-schema |

**Tek PR** (`arena/p2-schema-4`), her commit kendi CI doğrulaması (lokal toolchain yok →
CI hakem, F10.1/F10.2/V17 dersleri). Merge öncesi tüm commit'ler yeşil.

---

## 5. Test planı (güvenlik mühürleri)

**Pozitif:**
- Schema-4 roundtrip: tüm 15 alan + imza digest'e girer, verify() + verify_authentic() geçer.
- Ed25519 imzalı snapshot: trust-list signer → RequireSigned OK.
- AllowUnsigned devnet: signer/sig None → AllowUnsigned OK.

**Negatif (forgery matrisi):**
- GAP-2 pin: hash-lenmemiş alan enjeksiyonu → `..._unhashed_field_forgery_gap` RED.
- İmza forgery: sahte sig / yanlış signer / trust-list dışı → RequireSigned RED.
- AllowUnsigned production: `RequireSigned` config + imzasız snapshot → karantina.
- B2 serde: `BTreeMap<AssetId,_>` JSON roundtrip (alias ile FAIL ederdi).
- Schema-3 → 4 legacy-import: eski snapshot yüklenir (alanlar default), digest schema-3.

**Chaos/rotation:** HSM-mock signer rotation (Faz 1 trust-list güncelleme); multisig
placeholder (Faz 2).

---

## 6. Koordinasyon (görev yöneticisi)

- **ARENA2 (chain tarafı):** `from_snapshot_v2` restore yolu manifest alanlarını
  görmezden gelir (imza wire-only, state restore değil); `blockchain.rs` snapshot
  üretim yolu `get_state_snapshot` → `manifest_signer/sig` üretir (HSM/mock signer).
  **İlan STATUS'ta** (ARENA2 domain'i).
- **ARENA3 (CI/fuzz):** P4 — `scripts/check-snapshot-schema.sh` gate (isim-kilitli,
  vacuous-kanaryalı) + workflow job `Snapshot Schema-4 Invariants` + branch
  protection zorunlu check. Fuzz: rastgele snapshot bytes → verify fail-loud, panic YOK.
- **ARENA1 (cross_domain + bu PR):** B2 migration + C1-C6 uygulama.

---

## 7. Kabul kriterleri (MR-benzeri)

- [ ] C1: B2 30-site migration derleme + E0308 kapalı.
- [ ] C2-C3: GAP-2 15 alan digest'e girer; pin test RED mührü.
- [ ] C4: GAP-1 imza alanları + verify_authentic + forgery RED.
- [ ] C5: Loader karantina + CLI + config.
- [ ] C6: schema_version=4 + legacy-import.
- [ ] CI 17/17 yeşil (yeni Snapshot Schema-4 job dahil).
- [ ] STATUS'ta MR-snapshot kapanış notu (forgery surface kapandı).

---

## 8. Riskler

- **B2 30-site migration lokal compiler yok** → çoklu CI turu olası (F10.1/V17
  desenleri). Yardımcı fonksiyonları önce düzeltmek çağrı yerlerini toplu onarır.
- **GAP-2 digest değişimi** mevcut snapshot testlerini kırabilir (schema-3 digest
  bekleyenler) → legacy-import + cross-schema roundtrip testi mührü.
- **HSM signer** mock (production HSM yok, M6 debt) → Faz 1 trust-list Ed25519 ile
  sınırlı, BLS quorum Faz 2.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai> (P2 plan, görev yöneticisi)*
