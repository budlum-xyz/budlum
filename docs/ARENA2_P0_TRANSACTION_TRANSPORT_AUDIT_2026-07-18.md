# ARENA2 — P0 Transaction Protobuf/P2P Transport Denetimi

**Tarih:** 2026-07-18 (UTC+3)
**Kapsam:** Kullanıcı kararıyla **salt-okunur derin denetim**. Kod, proto veya CI dosyası değiştirilmedi.

## Sonuç

`TransactionType` kanonik işlem imzası/hash’inin parçasıdır (`src/core/transaction.rs`, `signing_hash`, `BDLM_TX_V3`). Buna karşılık P2P protobuf dönüşümü yalnız ilk beş türü taşıyor; diğer canonical türleri outbound dönüşümde sessizce `TRANSFER`a dönüştürüyor (`src/network/proto_conversions.rs:39-45`). Decode tarafı da bunu `TransactionType::Transfer` olarak açıyor.

Bu davranış, P2P üzerinden taşınan işlem ile imzalanmış işlem arasında type-tag ayrışması üretir. Alıcıda canonical hash yeniden hesaplandığı için normal imzalı işlem reddedilmelidir; ancak bu güvenli bir transport tasarımı değil, sessiz downgrade sonrası geç gerçekleşen bir hata yoludur. Blok içindeki transaction’lar da aynı `ProtoTransaction` dönüşümünü kullandığı için etki transaction gossip ile sınırlı değildir.

**Karar:** Yeni AI request/result transaction’ı eklenmeden önce bu bulgu P0 olarak tasarlanmalı ve ayrı, fail-closed bir değişiklikte çözülmelidir. Bu denetim yalnız kanıt ve uygulama planıdır; “düzeltildi” iddiası değildir.

## Kanıt zinciri

| Katman | Kaynak | Kanıt |
|---|---|---|
| Canonical tür tag’i | `src/core/transaction.rs:316-335` | 20 tür `0..19` ile `BDLM_TX_V3` signing hash’ine dahil. |
| Wire enum | `proto/budlum/network/protocol.proto:5-11` | Yalnız `TRANSFER`, `STAKE`, `UNSTAKE`, `VOTE`, `CONTRACT_CALL` (`0..4`). |
| Outbound dönüşüm | `src/network/proto_conversions.rs:39-45` | İlk beş tür explicit; `_ => TRANSFER` fallback’i var. |
| Inbound dönüşüm | `src/network/proto_conversions.rs:63-69` | Yalnız wire’daki beş tür decode edilir; bilinmeyen enum fail-closed reddedilir. |
| P2P tekil işlem | `src/network/proto_conversions.rs:313-318, 521-523` | `NetworkMessage::Transaction` aynı `ProtoTransaction` dönüşümünü kullanır. |
| P2P blok | `src/network/proto_conversions.rs:187-199, 519` | `Block.transactions` her öğeyi aynı dönüşümden geçirir. |
| Mevcut test yüzeyi | `src/network/proto_conversions.rs:659-672` | Yalnız Transfer round-trip testi. `src/tests/zkvm.rs:166-175` yalnız ContractCall round-trip testi. |

`git blame` kanıtı: fallback, `0cb219c` commitinde (2026-07-16) eklenmiştir; önceki dönüşümde yalnız başlangıçtaki beş enum vardı. Bu bir suçlama değil, davranışın tarihsel kaydıdır.

## Etki matrisi

| Type tag | `TransactionType` | Wire’daki mevcut davranış | Risk |
|---:|---|---|---|
| 0 | `Transfer` | Kayıpsız | Mevcut test var |
| 1 | `Stake` | Kayıpsız | Özel round-trip testi yok |
| 2 | `Unstake` | Kayıpsız | Özel round-trip testi yok |
| 3 | `Vote` | Kayıpsız | Özel round-trip testi yok |
| 4 | `ContractCall` | Kayıpsız | Mevcut test var |
| 5 | `BnsRegister` | `Transfer`a düşer | İmza/hash mismatch, BNS işlemi taşınamaz |
| 6 | `BnsSetContent` | `Transfer`a düşer | Aynı |
| 7 | `BnsRegisterSubdomain` | `Transfer`a düşer | Aynı |
| 8 | `BnsSetStorage` | `Transfer`a düşer | Aynı |
| 9 | `NftMint` | `Transfer`a düşer | Aynı |
| 10 | `NftTransfer` | `Transfer`a düşer | Aynı |
| 11 | `NftBurn` | `Transfer`a düşer | Aynı |
| 12 | `NftBoost { nft_id, amount }` | `Transfer`a düşer | Enum payload ayrıca kaybolur |
| 13 | `NftUpdateLight { nft_id, delta_mcd }` | `Transfer`a düşer | Enum payload ayrıca kaybolur |
| 14 | `NftTag { nft_id, tag }` | `Transfer`a düşer | Enum payload ayrıca kaybolur |
| 15 | `UniversalRelay(ExternalTransaction)` | `Transfer`a düşer | External chain/payload alanları kaybolur |
| 16 | `RelayerResult(RelayerExternalResult)` | `Transfer`a düşer | Result, proof ve state-root alanları kaybolur |
| 17 | `AiOfferData { cid, price }` | `Transfer`a düşer | Mevcut marketplace işlemi taşınamaz |
| 18 | `AiPurchaseData { offer_id }` | `Transfer`a düşer | Mevcut marketplace işlemi taşınamaz |
| 19 | `HubRegisterApp { ... }` | `Transfer`a düşer | Enum payload alanları kaybolur |

Önemli ayrım: bazı type-specific veriler `tx.data` içinde tekrar serialize edilmiş görünse de bu genel çözüm değildir. Rust enum’unun type tag’i ile inline payload’ı wire’a taşınmadığı için receiver semantiği yine `Transfer` olur; ayrıca `UniversalRelay`, `RelayerResult`, NFT varyantları ve Hub varyantı doğrudan enum alanı taşır.

## Güvenlik ve uyumluluk değerlendirmesi

1. **Fail-closed eksikliği:** Bilinmeyen inbound wire enum reddedilirken, bilinen Rust fakat wire’da temsil edilmeyen type outbound’da hata yerine `Transfer`a çevrilmektedir. Bu asimetrik davranış kaldırılmalıdır.
2. **İmza ayrışması:** Sender’ın hash’i type byte `5..19` içerir. Receiver type byte `0` ile canonical hash hesaplar; imzalı işlem mempool/validation aşamasında reddedilir. Reddetme güvenlik katmanıdır, ancak propagation ve block sync davranışı için tanımlı feature-negotiation değildir.
3. **Blok sync riski:** `ProtoBlock` içindeki transaction listesi de aynı dönüşümü kullandığından, bu türleri içeren bloklar peers arasında decode/validation uyuşmazlığına girebilir.
4. **Future feature riski:** AI Inference için yeni tag eklendiğinde fallback devam ederse bug tekrar eder. Böylece AI feature PR’ı transport değişikliğini zorunlu olarak kapsamalı veya P0 önce kapanmalıdır.
5. **Version negotiation yetersizliği:** Handshake yalnız `version_major/minor`, chain ID ve bazı capability alanlarını taşır. Transaction encoding capability/version’ı için açık bir karşılıklı anlaşma görünmüyor. Eski node’un yeni type’ı yanlış yorumlaması yerine önce fail-closed uyumluluk politikası gerekir.

## Güvenli tasarım seçenekleri

### Seçenek A — Protobuf enum’u tüm mevcut türlerle genişletmek

`ProtoTransactionType` için canonical tag’lerle aynı, append-only `5..19` değerleri eklenir. Inline enum payload’ları için `ProtoTransaction` içine explicit `oneof` payload mesajları eklenir veya tanımlı `type_payload` bytes alanı kullanılır.

- Artı: Şema okunabilir ve typed validation yapılır.
- Eksi: Çok sayıda message/mapper, migration test yükü.
- Mutlak şart: unknown/new enum eski node’da **reject** olmalı; `Transfer` fallback’i olmamalı.

### Seçenek B — Canonical işlem zarfını opaque bytes olarak taşımak

`ProtoTransaction` yerine/yanında canonical, versioned transaction envelope bytes alanı taşınır; decode önce maximum-size, version ve canonical deserialize doğrulaması yapar. Mevcut JSON serialization doğrudan consensus wire formatı olmamalıdır; deterministic binary format/schema gerekir.

- Artı: Yeni type eklemek için protobuf oneof değişikliği her seferinde gerekmez.
- Eksi: Canonical serialization, malleability, size limitleri ve versioning ayrı ciddi tasarım ister.
- Mevcut `serde_json` key order/cross-language canonical-wire taahhüdü olmadığı için olduğu gibi kabul edilmemelidir.

### Seçenek C — Minimal geçici fail-closed

Yeni türleri taşımaya çalışmadan, outbound `From<&Transaction>` dönüşümünü `TryFrom<&Transaction>` yapıp wire’da temsil edilmeyen türlerde error vererek hata görünür kılınır. Bu P0’ın güvenlik parçasını kapatır, fakat BNS/NFT/relay/marketplace/hub P2P taşınabilirlik eksikliğini çözmez.

- Yalnız kısa ömürlü koruma olarak düşünülebilir.
- AI uygulamasına geçiş kapısı olarak yeterli değildir; çünkü AI transaction’ı yine taşınamaz.

**Öneri:** A veya iyi tanımlı B seçilene kadar C ile sessiz downgrade kaldırılabilir. Ancak kod değişikliği öncesi protokol/upgrade politikası kararı zorunludur.

## Kabul kriterleri (seçilen tasarım için)

1. **Kayıpsızlık:** 20 mevcut türün her biri için `Transaction → protobuf bytes → Transaction` eşitliği; `hash`, `signature`, `tx_type` ve type-specific payload bit-eşit kalır.
2. **Network eşitliği:** Her tür için `NetworkMessage::Transaction` ve en az seçili karmaşık türler için `NetworkMessage::Block` bytes round-trip testi.
3. **Fail-closed:** tanınmayan enum/type/version, oversize payload ve malformed payload deterministik `Err` verir; asla `Transfer`a dönmez.
4. **Signature:** round-trip sonrası `verify()` başarılı; tek type/payload bit mutasyonu `verify()` başarısız.
5. **Mempool/chain:** decode edilmiş signed transaction, source ile aynı precheck sonucunu üretir.
6. **Uyumluluk:** eski/yeni node davranışı feature/version matrisiyle belgelenir ve test edilir. Network upgrade/activation noktası açıkça belirlenir.
7. **DoS sınırları:** payload ve nested vector/string uzunlukları hem decode hem P2P message limitinde bounded olur.
8. **CI kanıtı:** fmt, clippy, ilgili unit/integration testleri ve repo zorunlu kontroller yeşil olmadan merge edilmez.

## Ortam denetim notu

Bu çalışma alanında `cargo` kurulu değildir (`cargo: command not found`); lokal Rust testi koşulamadı. Bu bir başarı/başarısızlık sonucu değildir. Gelecek kod PR’ında CI, tek hakem olarak kullanılacak; yukarıdaki testler CI’da görünür isimlerle raporlanmalıdır.
