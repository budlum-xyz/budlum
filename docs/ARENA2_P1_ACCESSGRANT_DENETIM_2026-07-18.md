# ARENA2 — P1 AccessGrant / Marketplace Denetimi

**Tarih:** 2026-07-18 (UTC+3)
**Kapsam:** Salt-okunur kaynak denetimi.
**Karar:** P1 **kabul edilmemiştir**; P2/P3 için bloklayıcılar vardır. Kullanıcı kararı: kodu geri alma yerine, küçük ve kanıtlı düzeltme planı hazırlanacak.

## Kısa, teknik olmayan özet

P1, veri satışı ve erişim izni için gerekli nesneleri ekliyor; fakat henüz bunları güvenli biçimde zincirin gerçek çalışma akışına bağlamıyor.

Bugünkü haliyle:

- Sahibi olmayan biri izin veya iptal kaydı oluşturabiliyor gibi görünür.
- Ödeme yapıldı diye para transferi veya güvenilir erişim izni oluştuğu kanıtlanmıyor.
- Node yeniden başlatılırsa yeni kayıtların korunacağı garanti değil.
- Tek kullanımlık erişim, kullanıcı kararının aksine hâlâ yalnız node’un yerel notuna bırakılmış.
- Kaynakta derlemeyi engellemesi muhtemel bir placeholder satır vardır.

Bu rapor P1’i “başarısız” ilan etmez; neyin tamamlanmadan ilerlenemeyeceğini açıklar.

## Denetim kapısı 1 — Yetkilendirme ve ödeme

| Bulgu | Kaynak kanıtı | Etki | Gerekli onarım |
|---|---|---|---|
| Owner imzası doğrulanmıyor | `src/storage/marketplace.rs:247-248` TODO | Sahte grant kaydı eklenebilir | Domain-separated, length-checked Ed25519 doğrulaması; owner Address’e bağlanmış canonical mesaj |
| Storage commitment imzası doğrulanmıyor | `:229` TODO | Sahte storage/provenance beyanı eklenebilir | Storage-node Address + role eligibility + ayrı key-purpose ile doğrulama |
| İptal çağrısında owner yetkisi yok | `revoke_grant` yalnız asset varlığını kontrol ediyor | Başkası erişimi kapatabilir | Owner-signed revocation veya signed transaction sender kontrolü |
| Listing sahibi kontrolü placeholder | `:346` | Sahibi olmayan biri satış listesi oluşturabilir | Çağıran Address parametresi/signed tx ile `asset.owner` eşitliği |
| Auto-grant boş owner imzası üretiyor | `:389` | Zincirin owner adına imza attığı izlenimi; grant doğrulanamaz | Owner’ın önceden imzaladığı kapsam/fiyat/alıcı/süreli satış yetkisi veya owner’ın ayrı grant transaction’ı |
| Ödeme transferi TODO | `:385` | Marketplace gerçek ödeme yapmıyor | AccountState içinde atomik buyer debit, seller credit, protocol fee ve rollback davranışı |
| ReadOnce karar dışı | `:294` | Yerel sayaçla tekrar kullanım engellenemez | Ayrı, zincir üstü atomik consumption registry (`grant_id`, kullanım nonce/height) |

**Kullanıcı kararıyla sabit yön:** Grant, varsayılan olarak **Address’e** bağlıdır. Her ödeme yalnız değişmez ve açık veri kapsamı içindir. Yeni/değişmiş/geniş veri veya yeniden erişim ayrı ödeme ve izin ister.

## Denetim kapısı 2 — Zincir durumu, snapshot ve root

Yeni `src/storage/marketplace::MarketplaceRegistry`, mevcut canlı state’te kullanılan eski `src/marketplace::MarketplaceRegistry` ile aynı değildir.

- `AccountState` yalnız eski registry’yi taşır: `src/core/account.rs:109`.
- `StateSnapshotV2` yalnız eski registry’yi yazıp geri yükler: `src/chain/snapshot.rs:432, 514`.
- Snapshot sürümü hâlâ `3`: `src/chain/snapshot.rs:342`.
- Yeni registry’nin kendi `root()` metodu vardır (`src/storage/marketplace.rs:384`), fakat `AccountState::calculate_state_root()` bunu çağırmaz (`src/core/account.rs:1180-1194`).

Sonuç: P1 registry’si şu an zincir state’i, snapshot, replay veya consensus root tarafından korunmaz. P2/P3 başlamadan önce schema-4 migration, snapshot capture/restore, domain-separated marketplace root ve consensus state-root entegrasyonu tamamlanmalıdır.

## Denetim kapısı 3 — Serialization, wire ve RPC

| Bulgu | Etki | Gerekli onarım |
|---|---|---|
| `BTreeMap<Hash32, ...>` | JSON object map anahtarları string olmalıdır; doğrudan snapshot serialization başarısız olur | `AssetId` için Address benzeri hex-string serde wrapper veya map’i sıralı entry listesi olarak serialize et |
| `signature`, `owner_signature`, `wrapped_key` sınırsız `Vec<u8>` | Büyük/bozuk RPC veya snapshot girdisi DoS/malleability riski | Exact 64-byte imza tipi; bounded wrapped-key ve decode öncesi boyut sınırı |
| `#[serde(default)]` ile varsayılan grant | Eksik alanlar boş imza/zero principal ile deserialize olabilir | Validation’da zero owner, boş/yanlış boyutlu imza, invalid scope/principal fail-closed reddi |
| Yeni RPC/actor/transaction yolu yok | Çağıran kimlik, imza, nonce, ücret ve atomiklik zincirde uygulanmaz | Signed transaction/actor command tasarımı; RPC yalnız template veya signed tx submission yapar |
| CI görünmüyor | P1/P1 fmt ve doküman SHA’ları için Actions kanıtı yok | Workflow trigger/Actions ayarları incelenir; kaynak derleme/test CI’da kanıtlanır |
| Derleme riski | `if !asset.owner == listing.asset_id` (`:346`) Address üzerinde unary `!` uygular ve Address/Hash32 karşılaştırır | Placeholder kaldırılır; caller Address parametresiyle gerçek owner kontrolü yazılır; CI fmt/clippy/test kanıtı gerekir |

## Onarım sırası — küçük, denetlenebilir PR’lar

1. **P1-R0:** Derleme hatası/placeholder temizliği; owner/caller modelini ve exact signature types’ını tasarımda sabitle.
2. **P1-R1:** Address-temelli grant + owner/node/revocation signature doğrulaması; negatif testler.
3. **P1-R2:** Değişmez data-scope/sürüm modeli, owner ön-yetkili satış belgesi ve atomik ödeme akışı.
4. **P1-R3:** On-chain ReadOnce consumption registry; duplicate/replay/parallel kullanım negatifleri.
5. **P1-R4:** AccountState, schema-4 migration, snapshot capture/restore, JSON-safe AssetId ve consensus root entegrasyonu.
6. **P1-R5:** Actor/RPC/signed transaction bağları, bounded decode, e2e replay/restart/root tests ve ayrı CI gate.

Her PR diğerinin güvenlik varsayımını gizlemeden ayrı CI kanıtı üretmelidir. `budlumdevnet` bu çalışma kapsamında değiştirilmeyecektir.

## Süreç öz-denetimi

Bu rapor, başka agent’ın P1 commitini otomatik kabul etmek yerine kaynakta üç ayrı kapıdan inceleme sonucudur. Lokal Rust toolchain bulunmadığı için derleme sonucu iddia edilmemiştir; derleme şüphesi CI ile doğrulanmalıdır. Kod değişikliği yapılmamıştır.
