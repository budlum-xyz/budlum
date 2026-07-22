# RFC — AccessGrant v2: B.U.D. Veri Marketplace İzin & Provenance Katmanı (yeniden tasarım)

| | |
|---|---|
| **Durum** | **APPROVED ✅ — Kullanıcı onayı: 2026-07-18 (ask_user, v2_ok)** · P0 go (p0_go) |
| **Yazar** | ARENA3 (kullanıcı kararı: `ag_me`, 2026-07-18) |
| **Tarih** | 2026-07-18 (UTC+3) |
| **Yerine geçtiği** | `RFC_ACCESSGRANT_BUD_MARKETPLACE.md` (v1, ARENA1) — **kullanıcı tarafından REDDEDİLDİ** ("P1 kabul edilmez"); aşağıda §0 |
| **İlgili** | GAP-1 RFC (APPROVED — tek schema-4 birleşimi) · Task 10 Bölüm 1/2/3 · B.U.D. E2E invariantları |

---

## §0. v1 neden reddedildi (dürüst kayıt — tekrarlanmayacak hatalar)

Kullanıcı reddi + üç-kapı bağımsız denetim (ARENA2'nin silinen raporu, özeti bu satırlarda korunur) + ARENA3 incelemesi (R1-R3) birleşik bulgu seti:

**Üç-kapı bulguları (v1 P2 kodu, 721 satır):**
1. **İmza/ödeme kapısı:** owner/node imza doğrulaması ve ödeme akışı TODO idi → sahte grant/revocation/listing riski; ReadOnce zincir üstü kullanım kaydı değildi.
2. **Bağlanabilirlik kapısı:** yeni marketplace registry'si canlı `AccountState`/snapshot/schema-4/consensus-root'a **bağlı değildi** (ağaçta ölü registries — ARENA2-v1 `f40f5f6` incident'ıyla aynı hata sınıfı: root'a girmeyen registry = var-yok arası hayalet).
3. **Encoding/geçiş kapısı:** JSON-safe Hash32 map encoding yoktu; bounded signature/key yoktu; imzalı RPC/actor yolu yoktu.

**ARENA3 R1-R3 (v1 RFC metni):**
- R1: "7 RPC" sayısı eski — gerçek **9 uç** (`bud_storageOpenDeal`, `bud_storageGetEconomicsSummary`, `bud_storageGetEconomicsEvents` dahil; api.rs doğrulaması).
- R2: `Signature` tipi kod tabanında mevcut değil → v2'de **tanımlanır** (§3.1).
- R3 (kritik sınıf): `BTreeMap<[u8; 32], _>` serde_json'da map-key olarak **çalışmaz** (JSON object-key = string; ekip bunu `permissionless.rs:176` tuple-key notuyla ve Task 0.16 registry bug'ıyla yaşadı). v2'de **AssetId wrapper** (§3.1) — Address deseniyle string-serialize (`src/core/address.rs:64-73`).

**Süreç dersi (metne işlenir):** kod RFC/plan onaylanmadan başlamaz (P0 plan-deseni); başkasının domain'indeki kodu "onarım" adıyla çoğaltmak yerine bloklayıcı raporu + kullanıcı kararı beklenir; restore/geri-alma başkasının işini de silerse kullanıcı onayı kanıtı şart.

## §1. Problem tanımı + tehdit modeli

**Mevcut durum (kod doğrulaması, 2026-07-18):** B.U.D.'nun **9 RPC** ucu tamamen açıktır; `ContentManifest` (`src/storage/manifest.rs:50-55`) **owner alanı içermez**; `StorageRegistry` sağlayıcı ekonomisidir (tüketici erişim ödemesi yok); `RetrievalChallenge` tam-PoS değildir (sahte-yeşil riski `src/storage/README.md`'de işaretli).

**Mimari kısıt (veri egemenliği):** whitelist/admin/pause/freeze hook'u YASAK; her RPC her node'dan sunulabilmeli → **Görev 2 hard-enforcement (şifreleme) mimari kısıt gereği zorunludur**; Görev 1 soft-enforcement ancak "imza + zincir üstü kayıt" ile anlamlıdır (v1 bunu TODO bırakmıştı).

**Tehditleri v1'e ek olarak:** sahte grant/listing üretimi (imza-doğrulama zorunluluğu yoktu), registry'lerin konsensüs root dışında kalması (state-çatallanması), marketplace RPC'sinin imzasız aktör yoluyla çağrılması.

## §2. Kullanıcı yön kararları (bağlayıcı tasarım sabitleri — K1..K6)

| # | Karar | Tasarım sonucu |
|---|---|---|
| K1 | **Grant Address'e bağlıdır.** RoleId yalnız uygunluk kontrolüdür. | `AccessGrant.grantee: Address`; ek `grantee_role_constraint: Option<RoleId>` |
| K2 | **Her ödeme yalnız değişmez/açık veri kapsamı içindir.** | `DataScope = (asset_id, scope_version, content_hash)` üçlüsü; kapsam değişirse yeni ödeme |
| K3 | **Yeni/değişmiş/geniş veri veya yeniden erişim = ayrı ödeme + izin.** | `ReadOnce` dahil her erişim zincir-üstü consumption kaydıyla sayılır (§6); `ReadUntilBlock` sınırı blokboyunca geçerli, sonrası yeni grant |
| K4 | **ReadOnce ayrı zincir-üstü consumption registry ile izlenir.** | `once_consumed: BTreeMap<Address-BTreeSet<grant_id>>` benzeri explicit kayıt (§6) |
| K5 | **Auto-sale yalnız tek buyer Address'e bağlı + değişmez manifest.** | `MarketplaceListing { allowed_buyer: Address, scope_version }`; buyer dışı purchase RED |
| K6 | **Sistem owner adına asla imza üretmez.** | Owner satış yetkisini **önceden imzalı `SaleAuthorization`** (scope/sürüm/fiyat/süre/nonce) ile verir; ödeme anında protokol yalnız bu belgeyi tüketir |

## §3. Wire format — tek schema-4 (GAP-1 + GAP-2 + AccessGrant aynı sürümde)

### §3.1 Yeni temel tipler (R2+R3 çözümü)

```rust
/// Ed25519 imzası — bounded, serde-güvenli, Default'lu (R2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature64(pub [u8; 64]); // hex-string serde; Default = [0;64] (geçersiz-imza sentinel)
/// JSON-safe map anahtarı (R3): string-serialize wrapper, Address deseni (address.rs:64-73).
/// MODÜL YOLU (B1 kararı, ARENA1 review): bu tip `crate::bud::marketplace::AssetId`
/// olarak yaşar; `cross_domain::AssetId` (= Hash32 alias) dokunulmaz — çakışma yok.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId(pub [u8; 32]);     // custom Serialize/Deserialize = hex string
/// Grant kimliği = hash(grant payload) — replay dedup anahtarı.
pub type GrantId = AssetId;
```

**Kural (§3 sabit):** schema-4'e giren her map, anahtarı `String` ya da string-serialize wrapper ile tutulur; ham `[u8; N]`/`(A, B)` tuple anahtarı YASAK (CI'da roundtrip testiyle kilitli).

### §3.2 Marketplace primitifleri

```rust
pub struct DataAsset {                 // serde(default) tüm alanlar
    pub asset_id: AssetId,             // = ContentManifest.manifest_id (Hash32)
    pub owner: Address,                // K1 — ContentManifest'te YOK'tu; burada zorunlu
    pub content_hash: AssetId,
    pub scope_version: u64,            // K2 — kapsam değişikliğinde artar
    pub encrypted: bool,               // Görev 1 false; Görev 2 true
    pub listed: bool,
    pub created_at_block: u64,
}

pub struct StorageCommitment {         // provenance (GAP-1 imza modeliyle uyumlu)
    pub asset_id: AssetId,
    pub content_hash: AssetId,
    pub storage_node: Address,         // imzalayan node adresi (RoleId değil — K1 paraleli)
    pub block_height: u64,
    pub signature: Signature64,        // Ed25519(content_hash ‖ asset_id ‖ height)
}

pub struct SaleAuthorization {         // K6 — owner'ın önceden imzaladığı satış yetkisi
    pub asset_id: AssetId,
    pub scope_version: u64,
    pub price: u64,                    // $BUD (BUD_UNIT = 10^6, tokenomics/mod.rs:28 doğrulandı)
    pub allowed_buyer: Option<Address>,// K5 — Some ise tek-buyer kilitli
    pub valid_until_block: u64,
    pub nonce: u64,                    // owner-bazlı, replay koruması
    pub owner_signature: Signature64,  // tüm üstteki alanlar üzerinde
}

pub struct AccessGrant {
    pub grant_id: GrantId,             // hash(payload) — dedup
    pub asset_id: AssetId,
    pub scope_version: u64,            // K2 — kapsam dışı grant anlamsız
    pub grantee: Address,              // K1
    pub grantee_role_constraint: Option<RoleId>, // e.g. AI_VERIFIER(6) ise rol kaydı da şart
    pub scope: GrantScope,             // ReadOnce | ReadUntilBlock(u64) | Perpetual
    pub owner_signature: Signature64,  // manüel akışta bizzat owner; auto-sale'de
                                       // SaleAuthorization tüketiminden türetilir (K6)
    pub granted_at_block: u64,
}

pub struct AccessRevocation {
    pub asset_id: AssetId,
    pub grantee: Address,              // K1 paraleli
    pub revoked_at_block: u64,
    pub owner_signature: Signature64,  // üç-kapı #1: sahte revocation'ı kapatır
}

pub struct MarketplaceListing {
    pub asset_id: AssetId,
    pub authorization: SaleAuthorization, // K5/K6 embedded
    pub protocol_fee_bps: u16,            // v1 kararı: 250 (= %2.5) — kullanıcı onaylı kayıt
}
```

**Boundedness kuralı (üç-kapı #3):** imza/key alanları sabit-boyut (`Signature64`, `[u8; 32]`); `Vec<u8>` yalnız Görev-2 `wrapped_key`'de, üst sınır `MAX_WRAPPED_KEY = 1024` byte (decode'da enforce).

### §3.3 Schema-4 alan haritası (GAP-1 ile birleşik)

```rust
// StateSnapshotV2 (schema 4) — snapshot.rs, GAP-1 §4.2 ile aynı sürüm:
pub manifest_signer: Option<[u8; 32]>,        // GAP-1 (approve edildi)
pub manifest_signature: Option<Vec<u8>>,      // GAP-1 (approve edildi)
pub data_assets: BTreeMap<AssetId, DataAsset>,          // string-key ✓
pub storage_commitments: BTreeMap<AssetId, Vec<StorageCommitment>>,
pub access_grants: BTreeMap<GrantId, AccessGrant>,
pub once_consumed: BTreeMap<AssetId, BTreeMap<Address, Vec<GrantId>>>, // K4 (§6)
pub revocations: BTreeMap<AssetId, Vec<AccessRevocation>>,
pub marketplace_listings: BTreeMap<AssetId, MarketplaceListing>,
// + GAP-2 kapsam alanları (calculate_hash genişletmesi — ayrı başlık, koordineli)
```

## §4. Konsensüs/root entegrasyonu (üç-kapı #2 çözümü — hayalet-registry yasağı)

- Registry'ler yalnız snapshot'a değil **canlı `AccountState`'e** ve `calculate_hash` (schema-4 digest, GAP-2 genişletmesiyle **aynı PR'da**) kapsamına girer.
- **Tek taraflı root değişikliği YASAK** (`f40f5f6` dersi): schema-4 digest'ine yeni alan eklenmesi **domain-separation prefix'i** (`budlum.snapshot.v4`) + LegacyImport (GAP-1 onaylı politika) ile koordineli yapılır; v1 schema-3 hesabı değişmez.
- Doğrulama testi: marketplace alanına yazılan tek bit, restore edilen snapshot'ta **aynı digest**i verir; kapsam-dışı alan kalırsa GAP-2 pin testi (`..._unhashed_field_forgery_gap`) bu durumu yakalar.

## §5. İmza doğrulama noktaları (üç-kapı #1 çözümü — TODO yok)

Her state-mutasyona giden RPC'de zorunlu sıra: (1) alan doğrulama, (2) **imza doğrulama** (`Signature64` üzerinde Ed25519; sahibin pubkey'i `owner`/`storage_node` alanından), (3) nonce/expiry, (4) mute işlemi. `SaleAuthorization` ve `owner_signature` alanları boş-sentinel (`[0;64]`) ise RED (R2 sentinel kuralı). İmzasız "protokol içi" üretim YOK — auto-sale çıktısı `AccessGrant`, `SaleAuthorization`'ın **hash-bağlı türevidir** (K6; owner imzası zincirde referanslanır, yeni imza üretilmez).

## §6. ReadOnce consumption registry (K4)

```rust
// Kullanım: bud_accessGrantConsume(grant_id, consumer_address, asset_id)
// Kurallar: scope==ReadOnce olan grant; tüketilmemiş; revocation yok;
// expiry içinde; grantee==consumer. Başarı → once_consumed[asset][addr].push(grant_id)
// İkinci tüketim → RED (tx-level eşzamanlılık: tek blokta tek consumption, deterministik sıra).
```

`ReadOnce` zincir-üstü sayım — off-chain local state YASAK (üç-kapı kullanıcı yönü).

## §7. RPC yüzeyi v2 (9 mevcut uç korunur + yeni 9; hepsi permissionless)

Mevcut 9 uç davranışı korunur (B.U.D. invariant kapısı `B.U.D. E2E Invariants (9/9)` değişmez). Yeni uçlar:

| RPC | Mutasyon | İmza şartı |
|---|---|---|
| `bud_dataAssetRegister` | DataAsset+StorageCommitment kaydı | node sig + owner onayı |
| `bud_dataAssetGet` | — | — |
| `bud_saleAuthorizationSubmit` | SaleAuthorization kaydı | owner_signature |
| `bud_pollenList` | listing = authorization bağlama | auth içinde |
| `bud_accessGrantSubmit` | manuel grant | owner_signature |
| `bud_accessGrantConsume` | once_consumed yazımı (K4) | consumer + grant bütünlüğü |
| `bud_accessGrantRevoke` | revocation | owner_signature |
| `bud_pollenPurchase` | ödeme → auto-grant (K5) | buyer imzası + auth tüketimi |
| `bud_accessGrantQuery` | — | — |

## §8. Görevlar

- **Görev 1 (bu RFC'nin implementasyonu):** §3-§7 — imza-doğrulamalı soft-enforcement + consumption registry + root bağlantılı registry'ler.
- **Görev 2 (hard-enforcement, ARENA3 HSM domain'i):** `encrypted=true`, AES-256-GCM DEK + **HPKE (RFC 9180)** wrapped_key (v1 §10 kararı: HPKE=BEKLEYEN — bu RFC'de karar: HPKE, HSM uyumlu); storage node plaintext'i asla görmez; `MAX_WRAPPED_KEY` enforcement.

## §9. Test planı (gate: B.U.D. Marketplace ayrı CI job — Bölüm 4 kuralı)

Pozitif: register→list→purchase→auto-grant→consume akışı · manuel grant roundtrip · schema-4 snapshot roundtrip (alanların digest'e girdiği kanıtlı).
Negatif: sahte grant (imza uydurma) RED · boş-sentinel imza RED · kapsam-dışı scope_version RED · ikinci ReadOnce RED · yanlış allowed_buyer RED · replay nonce RED · revocation sonrası consume RED · `[u8;32]` ham-key serialize girişimi derleme/roundtrip güvenlik testiyle YAKALANIR.
Gate: `src/tests/pollen.rs` + `scripts/check-bud-marketplace.sh` (isim-kilitli, vacuous kanaryalı — B.U.D./BNS deseni) + ayrı CI job + korumaya ekleme.

## §10. Uygulama planı (P0-deseni: plan onayı → kod; tek atomik PR'lar)

| PR | Kapsam | Aday | Kapı |
|---|---|---|---|
| P0 | §3.1 temel tipler (Signature64/AssetId/GrantId) + serde roundtrip unit'leri | ARENA3 | derleme+test |
| P1 | §3.2 primitifler + imza-doğrulama yardımcıları (canlı AccountState'e BAĞLI) | yeni ARENA1 + ARENA3 review | negatif matris |
| P2 | §3.3/§4 snapshot+root genişletme (GAP-2 kapsamıyla TEK PR — koordineli) | ARENA3 + yeni ARENA2 | pin testleri |
| P3 | §7 RPC uçları (imza şartlı) | yeni ARENA2 (rpc domain) | gate script |
| P4 | pollen test suite + CI gate + koruma eklentisi | ARENA3 | 16→17 check |
| P5 | AI Verifier grant-check entegrasyonu (Bölüm 1; grantee_role_constraint) | yeni ARENA2 | ayrı RFC |

## §11. Açık sorular (gözden geçirenler için)

1. `Perpetual` scope Görev 2'de key-rotasyonla sınırlanacak — Görev 1'de de `valid_until` üst sınırı zorunlu mu? (öneri: hayır; revocation mekanizması yeterli)
2. `once_consumed` büyümesi prunig'siz kalıcı mı? (öneri: kalıcı; provenance zinciri)
3. Görev 1'de `encrypted=false` iken grant'ın teknik caydırıcılığı sınırlı (ham veri açık) — Görev 1 zaman çizelgesi kullanıcıyla.
4. **(ARENA1 B2, kabul):** `cross_domain::BridgeState.asset_locations` (bridge.rs:55) R3 latens taşır — `BTreeMap<AssetId(=Hash32), BridgeStatus>`. Snapshot/RPC JSON yoluna girdiğinde patlar; GAP-2 PR'ında köprü tarafı string-key migration'ı veya bincode-kısıtı mührü (ARENA1 sahipliğinde) — P2'ye bağlı değil, koordineli.

---

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*
