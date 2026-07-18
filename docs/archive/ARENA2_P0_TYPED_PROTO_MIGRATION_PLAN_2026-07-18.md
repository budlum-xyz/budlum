# ARENA2 — P0 Typed Protobuf Transport: Migration Plan

**Tarih:** 2026-07-18 (UTC+3)
**Durum:** Tasarım planı; **henüz kod değişikliği yok.**

## Onaylanan yön

- Rust `TransactionType` için **typed protobuf enum + typed `oneof` payload**.
- Eski/yeni wire ayrımı **activation height** ile yapılacak.
- Bilinmeyen type, eksik payload, yanlış payload ve activation’a uymayan wire sürümü: **fail-closed**.
- `Transfer` fallback kesinlikle yok.

## Şema tasarımı

`ProtoTransaction` içinde mevcut temel alanlar korunur. Yeni alanlar append-only eklenir:

```proto
uint32 wire_version = 12;
oneof type_payload {
  ProtoNftBoost nft_boost = 20;
  ProtoNftUpdateLight nft_update_light = 21;
  ProtoNftTag nft_tag = 22;
  ProtoUniversalRelay universal_relay = 23;
  ProtoRelayerResult relayer_result = 24;
  ProtoAiOfferData ai_offer_data = 25;
  ProtoAiPurchaseData ai_purchase_data = 26;
  ProtoHubRegisterApp hub_register_app = 27;
}
```

`ProtoTransactionType` canonical Rust tag’leriyle append-only `0..19` olur. Type’ı yalnız `tx.data`dan çıkarmak yasaktır: payload taşıyan her enum varyantı uygun `oneof` kolunu zorunlu kılar; payload taşımayan varyantlarda `oneof` boş olmak zorundadır.

BNS type’ları (`5..8`) ve NFT mint/transfer/burn (`9..11`) canonical parametrelerini güncel executor’un kullandığı `tx.data` içinde tutabilir, fakat type enum yine explicit wire alanıdır. Bu istisna yalnız data encoding’in halihazırda kanonik ve executor tarafından doğrulandığı ölçüde geçerlidir; her type için decode/semantic test gerekir.

## Activation-height kuralı

`H_transport_v2` tek bir governance/genesis parametresi olur.

| Blok yüksekliği | Kabul edilen wire | Davranış |
|---:|---|---|
| `< H_transport_v2` | v1, yalnız legacy 0..4 | v2 veya v1’de temsil edilmeyen işlem reddi |
| `>= H_transport_v2` | yalnız v2 | v1, unknown type, missing/mismatched payload reddi |

Bu plan, eski node’un yeni türü yorumlamasını değil açık uyumsuzluğu hedefler. Mainnet genesis henüz kesinleşmediğinden `H_transport_v2` değeri burada varsayılmaz. Mainnet genesis öncesinde v2 başlangıç protokolü seçilirse activation `0` olabilir; çalışan bir ağ üzerinde ise bu değer governance/fork planıyla ayrı kararlaştırılmalıdır.

## Dönüştürücü kuralları

1. `From<&Transaction>` yerine hata üretebilen `TryFrom<&Transaction>` kullanılır.
2. `TryFrom<ProtoTransaction>` type/payload birebir eşleşmesini kontrol eder.
3. Her field için size sınırı conversion öncesinde uygulanır; `String`/`Vec`/nested payload sınırsız decode edilmez.
4. Decode edilmiş transaction’ın canonical `calculate_hash()` değeri wire’daki `hash` ile eşleşmeli; imzalı işlem için `verify()` çağrısı mempool öncesinde zaten zorunludur.
5. `ProtoBlock` ve `NetworkMessage::Transaction` aynı helper’ı kullanır; ayrı mapping yazılmaz.
6. Şema jenerasyonu (`build.rs`) ve protoc/buf kontrolleri değişiklikle birlikte güncellenir.

## Test matrisi

- 20 mevcut türün her biri için transaction → protobuf → bytes → protobuf → transaction bit-eşit round-trip.
- Payload taşıyan 8 tür için field-level eşitlik: NFT varyantları, relay/result, AI marketplace, hub.
- Transaction ve block P2P yollarının her ikisinde round-trip.
- Unknown enum, enum/payload mismatch, missing required payload, unexpected payload, malformed nested payload, oversize field ve v1/v2 activation negatifleri.
- Round-trip sonrası `hash` ve `signature` doğrulaması; tek type/payload bit mutasyonu red.
- Pre/post activation boundary (`H-1`, `H`, `H+1`) regression testleri.
- CI’da isim-kilitli test listesi ve farklı işlem türleriyle multi-node smoke.

## AI model kayıt seam’i

Transport P0 kapandıktan sonra AI model kayıtları için permissionless yön korunur:

```text
AiModelRegistration {
  model_id, model_hash, owner: Address,
  min_verifier_count, agreement_threshold,
  max_input_ref_bytes, max_output_ref_bytes,
  registration_bond, registered_at_block
}
```

Kayıt, explicit minimum bond/fee ile spam maliyetini taşır; merkezi allow-list veya onay yoktur. Bond tutarı, iade/withdrawal süresi, model-id collision politikası ve invalid specification reddi ayrı ekonomi RFC’sinde sabitlenmeden state transition yazılmaz.

## Kodlama kapıları

1. `H_transport_v2` activation değeri ve yönetişim kaynağı.
2. Tüm typed payload mesajlarının field/size sınırları.
3. v1 node’ların v2 peer ile bağlantı/mesaj davranışı.
4. AI model registry bond, withdrawal ve namespace kuralları.
5. Ayrı PR, CI başarılı sonuç ve branch-protection onayı.
