# Lubot Mimari Özeti

Tam sürüm: `docs/MIMARI_ONERISI_2026-08-13.md`. Bu dosya katmanların özetidir.

## Katmanlar

```
[ Zincir üstü - budlum/main/src/lubot/ ]        (mevcut; bu repo dokunmaz)
   model kaydı · operator compute-bond · Pollen · B.U.D. · SocialFi
                        ▲ hash / ref eşleşmesi
[ Bu repo - off-chain iskelet ]
   lubot-core   : ModelId (32B hash - AiModelId ayna biçimi), dataset tipleri,
                  LoRaManifest
   lubot-data   : kapalı-devre kaynak denetimi (3 kanal), kayıt formatı,
                  fail-closed hash doğrulaması
   lubot-serve  : vLLM/SGLang köprüsü; ağırlık adı korunur, served-name bizimdir
   lubot-tune   : TunePlan (LoRA BF16/FP16 - FP4 yok), çıktı hash kilidi
   lubot-ops    : CLI iskeleti
```

## İlkeler

1. **Kapalı-devre:** Dış veri okuyan yol yok; her set B.U.D. StorageDeal +
   `TrainingCorpus` etiketi + hash doğrulamasıyla girer.
2. **Fail-closed:** Doğrulanmamış hash = red (`lubot-data::verify` bilinçli olarak
   `Err` döner). Üretimde gerçek SHA-256 girer.
3. **Atıf:** Üçüncü taraf adları korunur; yalnız kendi katmanımız "Lubot" adını taşır.
4. **Dil:** Dokümanlar Türkçe; kod kimlikleri İngilizce (budlum kuralı).
5. **Kabuk betiği yok:** Repoda kabuk kodu barındırılmaz; eğitim fazı dış
   konteynerlerde çalışır ve yalnızca belgelenir.

## Karar Durumu (2026-08-13)

| Karar | Durum |
|---|---|
| K1 iskelet + repo | üretildi; inceleme bekliyor |
| K2 taban model | soyut (varsayılan light kademesi; ilk koşu öncesi onay) |
| K3 tip bağlantısı | sonraya (iskelet iki seçeneğe uygun) |
| K5 yöntem | LoRA SFT (BF16 adaptör) |
| K6 veri kaynağı | **HİBRİT** - açık setler B.U.D. kaydıyla ağa girer |
| K7 kademe adlandırması | **light** (Flash tabanlı) / **normal** (Pro tabanlı); çarpan etiketleri yok |

## Derinleştirme (2026-08-13)

- `lubot-data`: gerçek SHA-256 doğrulaması (`verify_sha256`, `content_id_of`),
  serde_json tabanlı JSONL kayıtları, yapısal chat şablonu taslağı.
- `lubot-serve`: kademe adlandırması (`lubot-light-*` / `lubot-normal-*`),
  çarpan etiketi denetimi, fail-closed zincir RPC taslağı (`chain::NotConnected`).
- `lubot-core`: `ModelTier` (light/normal) tipi; `ModelSpec` kademe taşır.
