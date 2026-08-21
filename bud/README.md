# B.U.D. Core (bud-core): 1.0 / 2.0 / 3.0

Broad Universal Database 2.0 - çok formatlı, kayıpsız, kuantum-dirençli depolama
çekirdeği. Bu crate, `.bud` v2 konteyner formatının ve boru hattının gerçek Rust
uygulamasıdır.

**Durum:** 137 test yeşil (132 birim + 1 test_bud2 + 4 entegrasyon), 0 uyarı, `#![forbid(unsafe_code)]`.
Format sözleşmesi: [`FORMAT-V2.md`](FORMAT-V2.md) (bayt düzeyi spec + ölçümler).

## Derleme / Test

```bash
cargo build            # tüm modüller + CLI binary
cargo test             # 126 birim + 4 entegrasyon testi
```

## CLI (bin/bud)

```bash
bud store  -i giris.json -o cikti.bud              # v2 konteyner (RAW)
bud store  -i giris.log -o cikti.bud --compress    # v2 konteyner (Huffman - gerçek küçülme)
bud store  -i giris.log -o cikti.bud --zstd       # v2 konteyner (GERÇEK zstd - en iyi oran, ~6.5x)
bud restore -i cikti.bud -o geri.json              # doğrula + geri yükle (kayıpsız)
bud check  -i cikti.bud                            # bütünlük (magic + parça cid + kök)
bud encode -i giris.json -o v1.bud --class json    # v1 format
bud bench  -f giris.log                            # hız + maliyet (tavan $0.016 kapısı)
bud bft-vote --pipe-id 3 --ratio 17.19 --validator v   # BFT finality (2n/3)
```

## Modül haritası

| Modül | Ne yapar |
|---|---|
| `bud_format_container` | Yapısal parçalama (kayıpsızlık TAMLIĞI, K38), BudV2File (bomba korumalı), ChunkCodec |
| `bud_format_pipe` | `store`/`restore` uçtan uca boru hattı + format algılama |
| `bud_format_huffman` | Gerçek kayıpsız Huffman codec (BUD-HFM1, sıfır bağımlılık) |
| `bud_format_real` | Gerçek zstd FFI (zstd_compress/zstd_decompress_safe, K25 tavanlı) |
| `bud_format` | v1 format + ratio konsensüsü + K-BUD kapıları + decode_streaming (K25) |
| `bud_format_checkpoint` | Hash-zincirli checkpoint konsensüsü (SEC 17a-4 deseni) |
| `bud_format_por` | Shacham-Waters PoR (tutuş kanıtı, sınır güvenli) |
| `bud_format_dedup` | Tenant-içi dedup + PoW ownership (K20) |
| `bud_format_social` | Sosyal köprü kayıtları + K74 sahiplik ayrımı (Owned/Licensed, AB 2426) |
| `bud_format_bft` | Ratio finality (2n/3 GRANDPA benzeri) |
| `quantum_chain` | Ed25519 + ML-DSA-87 hibrit imza + dual cüzdan (K3/K4/B1) |
| `bud_format_economics` | Maliyet modeli (dürüst tavan kapısı) + K60 sıfır-egress |
| `bud_format_registry` | MIME/format kayıt defteri + kanıt kapıları |

## Dürüstlük (K19/K38)

- Ölçülmüş oranlar: `RealBench::measured_ratios()`, `FORMAT-V2.md §7` ve
  `scripts/measure_ratios.py --seed 7` (TEKRARLANABİLİR - JSON zstd19 7.83x, CSV 3.55x,
  LOG 6.17x, zstd konteyner ~6.55x). Uydurma sayı yok (EK13).
- `17.19x JSON` iddiası gerçek ölçümle TUTMAMAKTADIR (7.83x) - kanarya testleri ve CLI
  bench "tavan $0.016: GEÇMEDİ" ile dürüstçe raporlar.
- Sahte zstd/xz magic üreten stub `RealCompressor` kaldırıldı; yerine gerçek Huffman
  (BUD-HFM1) ve gerçek zstd FFI (ChunkCodec::Zstd).

## Güvenlik duruşu

- Panik'siz ayrıştırma: her decode/parse yolu güvenilmez girdide None döner (mini-fuzz +
  kırpma tam taramaları).
- Alloc-bomb yok: güvenilmez uzunluk alanlarından `with_capacity` KULLANILMAZ (lazy büyüme).
- Bomba korumaları: MAX_CHUNK_COUNT/MAX_CHUNK_BYTES/MAX_TOTAL_BYTES, K25 stream limitleri,
  Kraft eşitsizliği, ratio tavanı (>100:1 RED).
- `#![forbid(unsafe_code)]` tüm modüllerde.
