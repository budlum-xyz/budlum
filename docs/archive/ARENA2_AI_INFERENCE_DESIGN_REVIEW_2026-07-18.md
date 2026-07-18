# ARENA2 — Phase 10 AI Inference Layer: Başlangıç Tasarım Denetimi

**Tarih:** 2026-07-18 (UTC+3)
**Durum:** Tasarım/denetim tamamlandı; **kod değişikliği yapılmadı**. Uygulama, aşağıdaki karar kapıları ve transport düzeltmesi çözülmeden başlatılmamalıdır.

## 1. Yetki, kapsam ve değişmez sınırlar

Bu inceleme, kullanıcı onayıyla Phase 10 Bölüm 1 için **önce tasarım** kapsamındadır. `docs/BUDLUM_PHASE10.md` önerisini mevcut kaynakla karşılaştırır; yeni AI tipleri, RPC veya state transition kodu eklemez.

Değişmezler:

- PoW/PoS/BFT katılımı permissionless kalır. `AiVerifier` stake ve kanonik slashing ile katılabilir; whitelist, admin-onayı veya sabit verifier seti eklenmez.
- PoA izinli alanı izole kalır; AI katmanı PoA üyelik registry’sini veya kurallarını kullanmaz.
- Off-chain inference sonucu konsensüsçe “modelin gerçekten çalıştırıldığının” kriptografik kanıtı değildir. Faz 1 yalnız ekonomik teşvikli, imzalı attestation + deterministik eşik uzlaşmasıdır.
- B.U.D. veri-egemenliği nedeniyle merkezi indexer, allow-list, pause/freeze veya merkezi erişim-karar servisi tasarlanmaz.
- `budlum-xyz/budlumdevnet` salt-okunurdur. Bu oturumda yalnız geçici, salt-okunur bir klonla karşılaştırıldı; devnet’e yazma/push yapılmadı.

## 2. Kanıtlanan mevcut durum

| Alan | Kaynak kanıtı | Sonuç |
|---|---|---|
| Genişletilebilir roller | `src/registry/role.rs` | `RoleId` açık `u32` newtype’tır; registry bilinmeyen rolleri kabul eder. Sabit `AiVerifier = RoleId(6)` eklenmesi ergonomi sağlar, fakat registry’de whitelist oluşturmaz. |
| Permissionless stake/slashing | `src/registry/permissionless.rs` | Kayıt `(RoleId, Address)` ile tutulur; `is_active`, aktif üye sorgusu ve kanıt-kaynaklı slash yolu vardır. Bu, verifier ekonomik katılımı için yeniden kullanılabilir temel sağlar. |
| Zincir durum yüzeyi | `src/core/account.rs`, `src/chain/chain_actor.rs` | Yeni kalıcı AI registry/outcome durumunun `AccountState`, snapshot, replay ve actor komut akışına açıkça bağlanması gerekir. Şu an AI inference state’i yoktur. |
| İşlem/execution | `src/core/transaction.rs`, `src/execution/executor.rs` | `ContractCall`, BudZKVM bytecode’u yürütür; `bud_ai_request` host-call yoktur. Mevcut `AiOfferData`/`AiPurchaseData` yalnız marketplace teklif/satın alma akışıdır, inference değildir. |
| RPC | `src/rpc/api.rs`, `src/rpc/server.rs` | AI inference RPC’si yoktur. RPC servisinde B.U.D. için ayrı state senkronizasyonu da bulunduğundan AI state’i yalnız RPC belleğinde tutulamaz. |
| B.U.D. manifest | `src/storage/manifest.rs` | `ContentManifest` owner alanı içermez (`manifest_id`, `total_size`, `shard_count`, `shards`); bu nedenle AI input erişim yetkisi manifestten türetilemez. |
| B.U.D. storage iddiası | `src/domain/storage_deal.rs`, `src/rpc/api.rs` | Retrieval challenge, tek başına tam saklama kanıtı değildir. Ayrıca dokümanlar ile kaynak açıklamaları arasında Faz-3/VerifyMerkle olgunluğu hakkında çelişkili ifadeler vardır; inference katmanı bunu “tam veri bütünlüğü” garantisi saymamalıdır. |

## 3. Uygulama öncesi P0: transaction transport bütünlüğü

Yeni bir `TransactionType` veya AI request transaction’ı eklemeden önce mevcut transport sorunu çözülmelidir.

`src/network/proto_conversions.rs` sadece `Transfer`, `Stake`, `Unstake`, `Vote` ve `ContractCall` değerlerini protobuf’a round-trip eder. Bunların dışındaki **mevcut** transaction türleri outbound dönüşümde `Transfer`a çevrilmektedir. Böyle bir işlem ağ üzerinden farklı semantikle taşınır; imzalı canonical işlem/hash ve yürütülen transaction tipi ayrışabilir.

Bu, yalnız AI için değil `AiOfferData`, `AiPurchaseData`, BNS/NFT/relay/hub türleri için de kapsayıcı bir P0 transport/consensus riski olduğundan, AI feature PR’ına gizlenmemelidir.

**Gerekli ayrı hazırlık değişikliği:**

1. `proto/budlum.proto` içinde tüm desteklenen transaction türleri ve tür-verisine ait kayıpsız bir wire temsili tanımlanmalı; “bilinmeyen türü Transfer yap” fallback’i kaldırılmalıdır.
2. Decode tarafı bilinmeyen/uyumsuz türü fail-closed reddetmelidir.
3. Her mevcut tür için encode → decode eşitlik testleri ve P2P gönder/al entegrasyon testi eklenmelidir.
4. Wire uyumluluğu için explicit protocol/version politikası belirlenmelidir; eski node’un yeni AI işlemini sessiz dönüştürmesine izin verilmez.

Bu iş kapanmadan AI transaction türü, `bud_ai_request` veya result submission eklemek güvenli değildir.

## 4. Önerilen Faz-1 sınırı

### 4.1 Zincir-üstü güvence

Faz 1’in iddiası şudur: belirli bir model kimliği ve bağlamında, yeter sayıda aktif ve stake’li verifier aynı output commitment’ını imzalayıp bildirdiğinde zincir deterministic bir outcome kaydeder. Bu, model yürütmesinin ZK kanıtı değildir.

Faz 1 aşağıdakileri **yapmaz**:

- LLM ağırlığını, runtime’ını veya plaintext input/output’u zincire koymaz.
- Deterministik olmayan model çalışmasını consensus input’u yapmaz.
- Aynı output hash’ini “gerçek/doğru cevap” diye sunmaz.
- B.U.D. erişim iznini yalnız metadata veya node davranışına dayandırmaz.
- `AccessGrant`/key wrapping tamamlanmadan private asset için “erişim denetlendi” iddiasında bulunmaz.

### 4.2 Minimum kanonik veri modeli

Bölüm 1’deki öneri doğrudan uygulanmamalı; role alanı ile account kimliği ayrıştırılmalıdır. Bir `RoleId`, kimlik değil rol sınıfıdır; `agreeing_verifiers: Vec<RoleId>` tekil aktörleri temsil edemez.

Önerilen tasarım ilkeleri:

```text
AiModelId        = [u8; 32]  // domain-separated model kayıt kimliği
AiRequestId      = [u8; 32]  // canonical request preimage’inden türemiş
AiResultId       = [u8; 32]  // request + verifier account + output hash bağlamı

AiModelSpec {
  model_id, model_hash,
  min_verifier_count, agreement_threshold,
  max_input_ref_bytes, max_output_ref_bytes,
  request_deadline_blocks, result_deadline_blocks,
  version, active
}

AiInferenceRequest {
  request_id, requester: Address, model_id,
  input_commitment: [u8;32], input_ref: BoundedBytes,
  max_fee, callback: Option<CallbackDescriptor>,
  submitted_at_block, deadline_block,
  access_proof_ref: Option<...>  // yalnız gelecekteki hard-enforcement entegrasyon seam’i
}

AiInferenceResult {
  request_id, verifier: Address, output_commitment: [u8;32],
  output_ref: BoundedBytes, result_nonce, signature, submitted_at_block
}

AiInferenceOutcome {
  request_id, output_commitment, output_ref,
  agreeing_verifiers: Vec<Address>, finalized_at_block
}
```

Kanonik hash preimage’leri explicit domain tag, length-prefix, model/version, chain id ve request/result alanlarını kapsamalıdır. `Vec<u8>` kabul edilecekse hem decode hem state transition seviyesinde hard upper bound uygulanmalıdır; aksi halde mempool/state/snapshot DoS yüzeyi oluşur.

### 4.3 Eşik ve safety kuralları

- `0 < agreement_threshold <= min_verifier_count` model kaydında doğrulanır.
- Outcome yalnızca request anındaki veya açıkça versiyonlanmış aktif verifier setinden hesaplanır; sonradan kayıt olan verifier eşik hesabını değiştiremez.
- Aynı `(request_id, verifier)` için yalnız tek sonuç kabul edilir; ikinci, farklı `output_commitment` kanonik equivocation evidence’idir.
- Eşik sayımı **ayrı Address** üzerinden yapılır; role sayısı üzerinden değil.
- Bir request bir kez finalize olur. Aynı request için rakip outcome, duplicate result ve timeout davranışları deterministic ve replay-safe olmalıdır.
- `min_verifier_count` sağlanamazsa request “başarılı” değil, açık bir timeout/expired outcome’a gider. Böyle bir timeoutta otomatik slash kararını ilk sürümde varsaymamak gerekir; liveness/evidence semantiği önce tasarlanmalıdır.
- Her verifier sonucu, request ile domain-separated bağlanmış Ed25519 imzası taşır. İşlem imzası, verifier’ın off-chain result attestation imzasının yerine geçmez.

### 4.4 Fee ve slashing

Mevcut registry ekonomik taban sağlar ancak AI ekonomisini hazır sağlamaz. İlk implementation’dan önce şu noktalar karar kaydına bağlanmalıdır:

- request escrow ve ücretin payer’dan ne zaman kilitleneceği;
- successful outcome ücretinin eşit/verifier-weighted dağıtımı;
- timeout/cancel ve modellerin güncellenmesi durumunda iade;
- equivocation için yalnız kanıtlı slash (iki geçerli, çelişen imzalı result);
- yanlış fakat tekil output için “truth oracle” olmadığı gerçeği: otomatik slash yok;
- liveness slash için request deadline, bağımsız gözlemlenebilir katılım ve false-positive düzeltme kuralı.

Bu konular çözümlenmeden `AiVerifier` stake’i “sonuç kalitesi garantisi” diye pazarlanmamalıdır.

## 5. Host-call ve callback değerlendirmesi

Mevcut `ContractCall` yolu `tx.data` içindeki BudZKVM bytecode’u yürütür (`src/execution/executor.rs`). Sözleşme state’i ve genel-purpose host-call ABI’si henüz görünür değildir. Dolayısıyla `bud_ai_request`i hemen “VM host-call” diye eklemek yanlış sınır olur.

Sıralı seçenekler:

1. **Faz-1a (önerilen):** signed transaction/RPC → chain actor → canonical AI state machine. Callback alanını yalnız opaque, bounded descriptor olarak sakla; yürütme yok.
2. **Faz-1b:** VM için versioned host-call ABI tasarla. Host-call, yalnız request oluşturmalı; off-chain output’a senkron erişim, model yürütme veya callback içinde dış ağ çağrısı yapmamalı.
3. **Faz-1c:** finalization’ın callback semantiği. Reentrancy, gas metering, failure handling ve deterministic event model ayrı RFC olmadan eklenmez.

## 6. B.U.D. ve AccessGrant bağımlılığı

Kullanıcı, GAP-1 açık kararları için RFC önerilerini kabul etti: C-hibrit Faz-1 trust modeli, genesis+CLI trust-list (CLI override), imzasız yalnız devnet ve GAP-2’nin tek schema-4’te birleşmesi. Bu kayıt, snapshot işini başlatma yetkisi değil; RFC’nin uygulama öncesi karar kapısının kullanıcının seçtiği yönünü belirtir.

AI request `input_ref` bir B.U.D. varlığına işaret ediyorsa:

- Bugünkü `ContentManifest` owner/consent içermez; manifestin varlığı erişim yetkisi değildir.
- AccessGrant ve şifreleme/key-wrapping olmadan private input için gerçek hard enforcement yoktur.
- Bu nedenle Faz-1 AI yalnız public input commitment’ları veya request sahibinin off-chain teslim ettiği verilerle sınırlı tanımlanmalıdır.
- `AccessGrant` tasarımı ARENA3 Sprint-2 sahibindedir; AI katmanı onun veri modelini önceden donduramaz. Sadece stable bir `access_proof_ref` seam’i bırakabilir.

## 7. Önerilen commit/CI sırası

Her satır kendi küçük commit/PR’ı ve CI kanıtıyla ilerlemelidir:

| Sıra | Değişiklik | Kabul kanıtı |
|---|---|---|
| P0 | Transaction protobuf transport’unu kayıpsız/fail-closed yap | Tüm mevcut türlerin round-trip + P2P negatif testleri; CI yeşil |
| P1 | AI RFC: hash preimage, model lifecycle, verifier snapshot, timeout, economics ve evidence | Tasarım onayı; kod yok |
| P2 | `ai/` domain types + deterministic state registry; snapshot/replay/root bağlantısı | Unit/property/replay testleri |
| P3 | Permissionless `AiVerifier = RoleId(6)` ergonomi sabiti ve kayıt akışı | whitelist’siz katılım + inactive/equivocation negative testleri |
| P4 | Request/result/outcome transaction ve actor/state transition | duplicate/equivocation/threshold/timeout testleri |
| P5 | RPC yalnız signed transaction template veya raw signed tx submission kullanacak şekilde | RPC auth/limit/fail-closed testleri; RPC-local state yok |
| P6 | Versioned VM host-call ABI (ayrı karar sonrası) | deterministic VM + gas + callback-failure testleri |
| P7 | AccessGrant hard-enforcement entegrasyonu (ARENA3 tasarımıyla) | encrypted/private input negatif erişim testleri |

## 8. Açık kararlar

1. **P0 sahipliği ve önceliği:** transport düzeltmesi AI’dan önce ayrı P0 olarak onaylanıyor mu?
2. **Model kaydı yönetişimi:** model spec’i permissionless kayıt + economic anti-spam mı, governance ile activate/deactivate mi, yoksa başlangıçta yalnız genesis/config mi? Permissionless ağ ilkesi nedeniyle merkezi approval kabul edilemez; fakat model kimliği namespace ve spam maliyeti belirlenmelidir.
3. **Verifier set snapshot:** request anındaki aktif üye listesi state’e tam mı kaydedilecek, yoksa deterministic registry root + kayıt yükseklik aralığı mı saklanacak? Snapshot/replay maliyeti ve challengeability karşılaştırılmalıdır.
4. **Economic parametreler:** escrow, refund, timeout ve proven equivocation slash oranları.
5. **Public-input-only sınırı:** AccessGrant hard enforcement gelene kadar AI+B.U.D. private input bağını yasaklayalım mı? Güvenli varsayılan önerisi: **evet**.
6. **Cross-domain/callback:** Faz-1a’da callback’i saklı descriptor ile sınırlamak ve yürütmeyi ertelemek onaylanıyor mu? Güvenli varsayılan önerisi: **evet**.

## 9. Denetim sonucu

Phase 10 AI Inference Layer uygulanabilir bir yön, ancak mevcut kodda “birkaç RPC ve struct ekleme” boyutunda değildir. Özellikle transaction protobuf dönüşümündeki sessiz `Transfer` fallback’i çözülmeden yeni transaction tabanlı feature eklemek, ağ düğümleri arasında imzalı işlem semantiğini bozabilir. Bu nedenle tasarımın ilk uygulanabilir çıktısı AI kodu değil, P0 transport bütünlüğü kararı ve düzeltmesidir.
