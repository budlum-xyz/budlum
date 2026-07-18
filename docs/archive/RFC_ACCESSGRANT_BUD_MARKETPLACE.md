# RFC — AccessGrant: B.U.D. Veri Marketplace İzin & Provenance Katmanı

| | |
|---|---|
| **Durum** | DRAFT — Sprint-2 başlangıcı (Phase 10) |
| **Yazar** | ARENA1 (Çekirdek Sistem & B.U.D. Entegrasyon Lideri) + ARENA3 (Güvenlik/Altyapı/HSM) |
| **Tarih** | 2026-07-18 (UTC+3) |
| **İlgili** | Phase 10 Bölüm 1 (AI Inference Layer), Bölüm 2 (B.U.D. Marketplace), Bölüm 3 (Eksiklik Analizi), GAP-1 RFC (Manifest İmzası) |
| **Bağımlılık** | GAP-1 RFC (APPROVED) — schema_version=4 wire formatı paylaşılır |

---

## 1. Problem Tanımı ve Mimari Kısıt

**Mevcut durum (Phase 10 Bölüm 3.2):** B.U.D.'deki 7 RPC (`bud_storageRegisterManifest`, `bud_storageGetManifest`, `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`, `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`, `bud_storageGetOutcome`) **hepsi herkese açık**. `AccessGrant` kavramı yok. Metadata ve deal bilgisi tamamen public.

**Mimari kısıt — "Veri Egemenliği Kuralı" (Tur 14.5 Plan §0.5):** Hiçbir B.U.D. fonksiyonu Budlum ekibinin servisine bağımlı olamaz; whitelist/admin/pause/freeze hook'u YASAK; 7 RPC herhangi bir node tarafından sunulabilmeli.

**Sonuç:** "Soft enforcement" (stake'li node izin kontrolü yapar) modeli bu kural altında **zayıf kalır** — merkezi izin-kontrol servisi olamayacağı için, her node'un kuralı gönüllü uygulamasına dayanır, gerçek garanti değildir. **Şifreleme tabanlı hard enforcement (Faz 2) mimari kısıt gereği zorunludur.**

---

## 2. Tehdit Modeli ve Hedefler

### 2.1 Tehdit Sınıfları

1. **İzinsiz veri erişimi:** AI consumer / third-party, owner onayı olmadan B.U.D. verisini çeker/işler.
2. **Provenance sahteciliği:** "Bu veri B.U.D.'dan geldi" iddiası sahte üretilir (GAP-1 manifest imzası bu sınıfı kapatır).
3. **Storage node collusion:** Storage operator'lar veriyi izinsiz kopyalar/satış yapar (şifreleme + key-wrapping ile engellenir).
4. **Replay / downstream leak:** Bir kez verilen izinle verinin sonsuza dek kopyalanıp dağıtılması (DRM benzeri sistemlerde imkânsız — not: `AccessRevocation` önceden indirilen kopyayı geri ALMAZ).

### 2.2 Hedefler

| ID | Hedef | Faz |
|---|---|---|
| H1 | **Provenance kanıtı:** Her `DataAsset` için `StorageCommitment` (imzalı kök) zincire kaydedilir — GAP-1 manifest imzası ile birleşik. | 1 |
| H2 | **İzin kontrolü (Faz 1):** `AccessGrant` on-chain kayıtlı; storage node / AI Verifier erişim öncesi grant kontrolü YAPAR (soft enforcement, audit log). | 1 |
| H3 | **Hard enforcement (Faz 2):** İçerik şifreli (`encrypted: true`), `AccessGrant.wrapped_key` ile key-wrapping; sadece grantee çözebilir. | 2 |
| H4 | **AI Inference entegrasyonu:** `AiInferenceRequest.input_ref` B.U.D. `DataAsset` işaret ediyorsa, `AiVerifier` hesaplamadan **önce** geçerli `AccessGrant` kontrolü ZORUNDA. | 1 |
| H5 | **Marketplace ekonomisi:** `MarketplaceListing` (price, auto_grant_on_payment) — tüketici erişim ödemesi modeli, `StorageRegistry` sağlayıcı ekonomisinden BAĞIMSIZ. | 1 |

**Hedef DEĞİL:** DRM tam koruması (önceden indirilen kopyanın geri alınması imkânsız), B.U.D. replikasyon mekanizması, şifreleme detayları (Faz 2).

---

## 3. Yeni Primitifler (Wire Format — Schema Version 4)

> **Not:** GAP-1 RFC ile **tek schema-4**'te birleşiyor. `manifest_signer`/`manifest_signature` alanları GAP-1 için; aşağıdaki alanlar AccessGrant için. Tümü `serde(default)` ile schema≤3 uyumlu.

### 3.1 Role Kimlikleri

```rust
// src/registry/role.rs — YENİ
pub const AI_VERIFIER: RoleId = RoleId(6);        // Phase 10 AI Inference Layer
pub const BUD_STORAGE_NODE: RoleId = RoleId(7);   // B.U.D. storage operator (ayrı rol)
```

### 3.2 Veri Varlığı (DataAsset)

```rust
// src/bud/marketplace.rs — YENİ MODÜL
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct DataAsset {
    pub asset_id: [u8; 32],              // ContentManifest.manifest_id ile aynı
    pub owner: Address,                   // Sahip adresi — KRİTİK: ContentManifest'te YOK (Bölüm 3.2 madde 6)
    pub content_hash: [u8; 32],           // ContentId (SHA-256 domain-tagged)
    pub encrypted: bool,                  // Faz 1: false; Faz 2: true
    pub listed: bool,                     // Marketplace'de listelenmiş mi
    pub created_at_block: u64,            // Zincir kaydı bloğu
    // Faz 2 için rezerve:
    // pub encryption_scheme: Option<EncryptionScheme>,
    // pub key_commitment: Option<[u8; 32]>,
}

impl Default for DataAsset {
    fn default() -> Self {
        Self {
            asset_id: [0; 32],
            owner: Address::zero(),
            content_hash: [0; 32],
            encrypted: false,
            listed: false,
            created_at_block: 0,
        }
    }
}
```

### 3.3 Provenance Kanıtı (StorageCommitment)

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StorageCommitment {
    pub asset_id: [u8; 32],
    pub content_hash: [u8; 32],
    pub storage_node_id: RoleId,          // STORAGE_OPERATOR(5) veya BUD_STORAGE_NODE(7)
    pub block_height: u64,
    pub signature: Signature,             // Node'un Ed25519 imzası (content_hash + asset_id + height üzerinde)
}
```

> **GAP-1 entegrasyonu:** `StorageCommitment.signature` GAP-1'in `manifest_signature` modeliyle uyumlu — node kendi snapshot imzalama anahtarıyla (veya HSM) imzalar. `manifest_signer` = node'un snapshot imzalama pubkey'i.

### 3.4 Erişim İzni (AccessGrant) — Faz 1: Soft, Faz 2: Hard

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub enum GrantScope {
    ReadOnce,                     // Tek okuma (challenge/verify için) — off-chain local counter + audit log
    ReadUntilBlock(u64),          // Belirli blok yüksekliğine kadar
    Perpetual,                    // Süresiz (Faz 2'de wrapped_key ile sınırlı)
}
```

> **KARAR (2026-07-18):** `ReadOnce` enforcement **off-chain local counter + audit log** — gas maliyeti yok. Storage node / AI Verifier kendi local state'inde takip eder. Revocation zamanında local state temizlenir. On-chain counter gas maliyetli olduğu için tercih edilmedi.

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub enum Grantee {
    RoleId(RoleId),               // AI_VERIFIER(6), BUD_STORAGE_NODE(7), vb.
    Address(Address),             // EOA / Contract — Faz 1'den desteklenir
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct AccessGrant {
    pub asset_id: [u8; 32],
    pub owner_signature: Signature,     // Owner'ın Ed25519 imzası (asset_id + grantee + scope + granted_at_block üzerinde)
    pub grantee: Grantee,               // RoleId VEYA Address — wire formatında Option ile genişletilebilir
    pub scope: GrantScope,
    pub wrapped_key: Option<Vec<u8>>,   // Faz 1: None; Faz 2: şifrelenmiş DEK (Data Encryption Key)
    pub granted_at_block: u64,
}
```

> **KARAR (2026-07-18):** Grantee tipi `enum Grantee { RoleId, Address }` — Faz 1'den her ikisi desteklenir. Mevcut `PermissionlessRegistry` RoleId tabanlı; Address grantee'ler için ayrı `AddressGranteeRegistry` (basit BTreeMap) eklenir.

impl Default for AccessGrant {
    fn default() -> Self {
        Self {
            asset_id: [0; 32],
            owner_signature: Signature::default(),
            grantee: Grantee::RoleId(RoleId(0)),
            scope: GrantScope::Perpetual,
            wrapped_key: None,
            granted_at_block: 0,
        }
    }
}
```

### 3.5 Erişim İptali (AccessRevocation)

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccessRevocation {
    pub asset_id: [u8; 32],
    pub grantee: RoleId,
    pub revoked_at_block: u64,
}
```

> **Dürüst not:** `AccessRevocation`, grantee'nin önceden indirdiği kopyayı geri ALMAZ — bu hiçbir DRM sisteminde mümkün değil. Sadece **ilerideki** erişimleri engeller (storage node / AI Verifier grant listesini günceller).

### 3.6 Marketplace Listesi (MarketplaceListing)

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MarketplaceListing {
    pub asset_id: [u8; 32],
    pub price: u64,                     // $BUD cinsinden (BUD_UNIT = 10^6)
    pub auto_grant_on_payment: bool,    // true: ödeme anında AccessGrant otomatik üretilir
}
```

> **KARAR (2026-07-18):** Protocol fee **sabit %2.5** (governance/config ile ayarlanabilir `MarketplaceParams::protocol_fee_bps = 250`). `bud_marketplacePurchase` transaction fee'sinin üzerine eklenir, protokol treasury'sine gider. Owner fiyatına (`price`) ek olarak alınır.

---

## 4. Akışlar

### 4.1 Veri Yükleme + Provenance (Owner → B.U.D.)

```
1. Owner: İçeriği off-chain B.U.D. storage node'a yüklüyor
2. Storage Node: ContentManifest üretir, ContentId hesaplar
3. Storage Node: StorageCommitment imzalar (kendi snapshot imzalama anahtarı/HSM ile)
   - İmza: content_hash + asset_id + block_height
4. Owner: DataAsset zincire kaydeder (RPC: bud_dataAssetRegister)
   - Alanlar: asset_id, owner, content_hash, encrypted=false, listed=false, created_at_block
5. Zincir: DataAsset + StorageCommitment kaydeder (StateSnapshotV2'ye dahil)
6. Sonuç: Provenance kanıtı zincirde — "Bu veri B.U.D.'dan geldi, bu node imzaladı"
```

### 4.2 Marketplace Listeleme (Owner)

```
1. Owner: MarketplaceListing oluşturur (asset_id, price, auto_grant_on_payment)
2. RPC: bud_marketplaceList → DataAsset.listed = true
3. DataAsset zincirde güncellenir
```

### 4.3 Erişim Talep + Verme (AI Consumer / AI Verifier → Owner)

```
1. AI Consumer: Erişim talep eder (veya auto_grant_on_payment=true ise öder)
2. Owner: AccessGrant imzalar (owner_signature: asset_id + grantee + scope + granted_at_block)
3. RPC: bud_accessGrantSubmit → AccessGrant zincire kaydedilir
4. Grantee (AI Verifier / Storage Node): Grant'i çeker, kapsam doğrular
```

### 4.4 AI Inference Layer Entegrasyonu (ZORUNLU)

```
1. Smart Contract: bud_ai_request host-call ile AiInferenceRequest yayınlar
   - input_ref: B.U.D. DataAsset.asset_id'yi işaret eder
2. Kayıtlı AiVerifier node'ları: Request'i görür
3. **KRİTİK KONTROL:** Hesaplamadan ÖNCE bud_accessGrantQuery(asset_id, self.role_id) çağırır
   - Geçerli AccessGrant YOKSA → işlem REDDEDİLİR, loglanır, slashing riski
4. Grant varsa: Veriyi B.U.D.'dan çeker (bud_storageGetShard), modeli çalıştırır
5. Sonucu submit eder → agreement_threshold sağlanırsa AiInferenceOutcome finalize
```

### 4.5 Faz 2: Hard Enforcement (Şifreleme + Key-Wrapping)

```
Faz 1'e ek olarak:
- Owner yüklerken: İçeriği DEK (Data Encryption Key) ile şifreler (AES-256-GCM)
- DEK'yi owner'ın master key'iyle şifreler (key_commitment = hash(master_key))
- AccessGrant.wrapped_key = DEK encrypted with grantee's public key (ECIES / HPKE)
- Grantee: wrapped_key'i kendi private key'iyle çözer → DEK → içerik
- Storage Node: Şifreli veriyi saklar, ham veriyi ASLA GÖRMEZ
- Revocation: wrapped_key yenilenemez (granular key rotation Faz 3)
```

---

## 5. RPC Yüzeyi (Yeni — Permissionless, Whitelist YOK)

| RPC | Açıklama | Parametreler | Dönüş |
|---|---|---|---|
| `bud_dataAssetRegister` | DataAsset + StorageCommitment kaydı | `DataAsset`, `StorageCommitment` | `asset_id` |
| `bud_dataAssetGet` | Asset metadata çekme | `asset_id` | `DataAsset` |
| `bud_accessGrantSubmit` | AccessGrant kaydetme (owner imzalı) | `AccessGrant` | `grant_id` (hash) |
| `bud_accessGrantQuery` | Grantee için grant sorgulama | `asset_id`, `grantee: Grantee` | `Option<AccessGrant>` |
| `bud_accessGrantRevoke` | AccessRevocation kaydetme | `AccessRevocation` | `revocation_id` |
| `bud_marketplaceList` | Asset'i marketplace'e ekleme | `MarketplaceListing` | `listing_id` |
| `bud_marketplaceGet` | Listing sorgulama | `asset_id` | `Option<MarketplaceListing>` |
| `bud_marketplacePurchase` | Ödeyip auto-grant tetikleme | `asset_id`, `buyer: Address` | `AccessGrant` (auto) |

> **Tümü permissionless.** Admin-only, whitelist, pause hook YOK. Sadece imza/fee/stake doğrulaması.

---

## 6. StateSnapshotV2 Entegrasyonu (Schema 4)

```rust
// src/chain/snapshot.rs — GENİŞLETİLİR
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct StateSnapshotV2 {
    // ... mevcut alanlar ...

    // YENİ — AccessGrant / Marketplace
    pub data_assets: BTreeMap<[u8; 32], DataAsset>,           // asset_id -> DataAsset
    pub access_grants: BTreeMap<[u8; 32], Vec<AccessGrant>>,  // asset_id -> grants
    pub revocations: BTreeMap<[u8; 32], Vec<AccessRevocation>>,
    pub marketplace_listings: BTreeMap<[u8; 32], MarketplaceListing>,

    // GAP-1 imza alanları (zaten var)
    // pub manifest_signer: Option<[u8; 32]>,
    // pub manifest_signature: Option<Vec<u8>>,
}
```

**Round-trip testi:** `test_snapshot_v2_access_grant_roundtrip` — grant kaydı snapshot'tan geçip gelir, imza doğrulanır.

---

## 7. Güvenlik Invariantları ve Testler

| Test | Açıklama | Faz |
|---|---|---|
| `test_access_grant_happy_path` | Owner imzalar → grantee çeker → doğrulama geçer | 1 |
| `test_access_grant_replay_rejected` | Aynı grant_id tekrar submit edilmez (dedup) | 1 |
| `test_access_grant_scope_enforced` | ReadOnce grant'i ikinci okumada reddedilir | 1 |
| `test_access_grant_revocation_blocks_future` | Revocation sonrası yeni erişim reddedilir | 1 |
| `test_ai_verifier_grant_check_mandatory` | AiVerifier grant olmadan request işlemez (slashing riski) | 1 |
| `test_access_grant_unsigned_rejected` | Owner imzasız grant reddedilir | 1 |
| `test_marketplace_auto_grant_on_payment` | Ödeme → otomatik grant üretimi | 1 |
| `test_data_asset_owner_field_required` | DataAsset.owner boş olamaz (ContentManifest'te yoktu) | 1 |
| **Faz 2 testleri** | `test_wrapped_key_decryption`, `test_storage_node_never_sees_plaintext`, `test_revocation_does_not_retrieve_copies` | 2 |

---

## 8. GAP-1 RFC ile Birleşim (Tek Schema-4)

| Alan | Kaynak | Amaç |
|---|---|---|
| `manifest_signer: Option<[u8; 32]>` | GAP-1 | Snapshot imzalayan pubkey |
| `manifest_signature: Option<Vec<u8>>` | GAP-1 | Snapshot digest imzası |
| `data_assets: BTreeMap<...>` | AccessGrant | Veri varlıkları + owner |
| `access_grants: BTreeMap<...>` | AccessGrant | İzin kayıtları |
| `revocations: BTreeMap<...>` | AccessGrant | İptal kayıtları |
| `marketplace_listings: BTreeMap<...>` | AccessGrant | Marketplace listeleri |

**Migration:** `--migrate-v2` tek geçişte schema 2/3 → 4 üretir. GAP-2 hash-kapsam alanları da aynı schema-4'e eklenir (domain prefix: `budlum.snapshot.v4`).

---

## 9. Uygulama Planı (Sprint-2)

| PR | Kapsam | Sorumlu | Bağımlılık |
|---|---|---|---|
| P1 | `src/bud/marketplace.rs` modülü: DataAsset, StorageCommitment, AccessGrant, MarketplaceListing tipleri + serde | ARENA1 | GAP-1 RFC approved |
| P2 | RPC uç noktaları (8 adet) + permissionless doğrulama (imza/fee) | ARENA1 | P1 |
| P3 | StateSnapshotV2 entegrasyonu + migration + round-trip testleri | ARENA1 + ARENA3 | P2 |
| P4 | AI Verifier entegrasyonu: `bud_ai_request` host-call + grant check zorunluluğu | ARENA1 + ARENA2-halef | P3 |
| P5 | Test suite: 9 pozitif/negatif test + CI gate (B.U.D. Marketplace ayrı job) | ARENA1 | P4 |
| P6 | **Faz 2** (ayrı talimat): Şifreleme, key-wrapping, HPKE/ECIES, wrapped_key | ARENA3 (HSM domain) | Phase 10+ |

**Not:** P1-P5 **Phase 10 Sprint-2** kapsamındadır. P6 ayrı faz, ayrı talimat turu.

---

## 10. Açık Sorular — TÜMÜ KARARLANDI ✅ (2026-07-18)

1. **GrantScope `ReadOnce` implementasyonu:** **KARAR: Off-chain local counter + audit log** — gas maliyeti yok. Storage node / AI Verifier kendi local state'inde takip eder. Revocation zamanında local state temizlenir.

2. **Grantee tipi:** **KARAR: Enum Grantee { RoleId, Address }** — Faz 1'den her ikisi desteklenir. Mevcut `PermissionlessRegistry` RoleId tabanlı; Address grantee'ler için ayrı `AddressGranteeRegistry` eklenir.

3. **Marketplace fee modeli:** **KARAR: Sabit protocol fee %2.5** (governance/config ile ayarlanabilir `MarketplaceParams::protocol_fee_bps = 250`). `bud_marketplacePurchase` transaction fee'sinin üzerine eklenir.

4. **Faz 2 şifreleme standardı:** **BEKLEYEN** — HPKE (RFC 9180) önerili (modern, HSM uyumlu, ARENA3 domain'i). Faz 2 ayrı talimat turunda kesinleşecek.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
*Co-authored-by: ARENA3 <arena3@budlum.xyz>*