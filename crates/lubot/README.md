# Lubot

Budlum L1'in merkeziyetsiz yapay zeka katmanının **off-chain iskeleti**.

> **Konum (2026-08-13):** Bu workspace, ayrı `budlum-xyz/lubot` reposundan
> ana repoya taşındı. Zincir tarafı `src/lubot/` +
> `src/ai/` içinde yaşar; off-chain iskelet bu `lubot/` dizininde, kendi
> Cargo workspace'i olarak durur (budzero ile aynı desen). Tüm Lubot işi
> tek PR'da toplanır.

- **Zincir üstü taraf** budlum/main deposundadır (`src/lubot/`): model kaydı, operator compute-bond, Pollen grant'leri, B.U.D. AI-dataset etiketleri, SocialFi köprüsü. Bu workspace ona dokunmaz; onun off-chain tamamlayıcısıdır.
- **Kapalı-devre ilke:** Lubot yalnızca Pollen grant'li, B.U.D. StorageDeal etiketli veya SocialFi kaynaklı veriyi okur. Bu iskelette dış veri okuyan tek bir yol yoktur; dış veri setleri bile önce B.U.D.'a kaydedilir.
- **Taban model:** DeepSeek V4 ailesi (MIT ağırlıklar; `V4-Flash-Base` varsayılan, karar ilk ince ayar öncesi yeniden onaylanır).
- **Kademe adlandırması (2026-08-13):** DeepSeek'in varyant adları Lubot'ta kullanılmaz. Flash tabanlı kademe **`lubot-light`**, Pro tabanlı kademe **`lubot-normal`** olarak sunulur. Çarpan/kat etiketleri (0.5x, 10x vb.) Lubot'ta yoktur - denetim kodda (`lubot-serve::config::assert_served_name_is_ours`).
- **Atıf politikası:** "DeepSeek → Lubot" isim değişikliği yalnızca kendi kodumuzda yapılır. Kopyalanan üçüncü taraf kodu ve ağırlık adları olduğu gibi kalır; MIT bildirimi ve "tabanıdır" atfı `NOTICE.md` ve model kartında yer alır.

## Durum

İskelet: derlenebilir taslaklar + yapılandırma + araştırma raporları. Hiçbir parça henüz üretim değildir; hash doğrulaması bilinçli olarak **fail-closed**'dur (`lubot-data::verify`).

## Yapı

| Crate | Görev |
|---|---|
| `lubot-core` | Model kimliği, dataset tipleri, LoRA manifesti (ayna tipler - K3 kararı) |
| `lubot-data` | Kapalı-devre kaynak denetimi, kayıt formatı, fail-closed doğrulama |
| `lubot-serve` | vLLM/SGLang köprüsü yapılandırması (ağırlık adı korunur, sunulan ad bizimdir) |
| `lubot-tune` | Eğitim planı (LoRA BF16/FP16 - FP4 tip sisteminde yok) + çıktı hash kilidi |
| `lubot-ops` | Operatör CLI iskeleti (register/bond/serve/tune/status) |

## Derleme

```bash
cargo check --workspace
cargo test --workspace
```

## Kararlar

K2 (taban model: soyut, ilk ince ayar öncesi onay), K3 (tip bağlantısı: sonraya - iskelet iki seçeneğe uygun), yöntem: LoRA SFT (2026-08-13). Ayrıntı: `docs/MIMARI_ONERISI_2026-08-13.md`.

## Dokümanlar

- `docs/ARASTIRMA_RAPORU_2026-08-13.md` - DeepSeek V4 araştırması
- `docs/MIMARI_ONERISI_2026-08-13.md` - iskelet mimarisi ve K1-K8 kararları
- `docs/EGITIM_VERISI_STRATEJISI_2026-08-13.md` - eğitim verisi stratejisi
- `docs/ACIK_KAYNAK_VERI_ARASTIRMASI_2026-08-13.md` - açık veri setleri + en iyi senaryo

İnce ayar koşu artefaktları (notebook, seed verisi, koşu kılavuzları, durum
matrisi) bu depoda tutulmaz: yürütülebilir olmayan içerik kod tabanının
dışındadır.
