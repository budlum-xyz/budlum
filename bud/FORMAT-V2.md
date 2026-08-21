# B.U.D. 2.0 Konteyner Formatı - .bud v2 Spec (2026-08-16)

Bu belge, `.bud` v2 konteynerinin ve parça kodlayıcılarının BAYT DÜZEYİ sözleşmesidir.
Amaç: açık, yapılandırılmış, makine-okur format (K72 - Data Act uyumu), doğrulayıcı
testleriyle (K38). Belge + testler birlikte formatın kanıt zinciridir.

## 1. Genel ilkeler

- **Kayıpsızlık tamlığı:** `restore(store(d)) == d` HER d için (bozuk girdi dahil).
- **Deterministik:** aynı girdi → aynı baytlar (dedup/kanıt çapası).
- **Bomba koruması:** her boyut alanı tavanlarla sınırlı (K25/K38).
- **Panik'siz:** hiçbir ayrıştırma yolu panik üretmez; bozuk girdi → hata (None/Err).
- **Tür bağımsızlığı:** yapısal parçalama türü kayıpsızlığı ETKİLEMEZ, yalnız parça
  tanecikliğini (dedup/kanıt verimi) etkiler.

## 2. BudV2File - tam dosya düzeni (little-endian)

```
+0   [8]  magic:        \xB5 0x55 0x44 0xB0 0x02 0x00 0x00 0x00
                         (high-bit öncülü: file(1)/ASCII karışmaz - S.47)
+8   [2]  codec:        u16 - FormatCodec kayıt kodu (1=Json 2=Csv 3=Log 4=Text
                         10=Mp4 11=Jpeg 12=Png 16=Pdf 0=Unknown)
+10  [34] multihash:    [1] algo (0x16=SHA3-256) + [1] uzunluk (32) + [32] digest
+44  [4]  chunk_count:  u32 (tavan: 1_000_000)
+48  [8]  total_len:    u64 - parça verilerinin toplam uzunluğu (SAKLANAN baytlar)
+56  [1]  chunk_codec:  u8 - 0=Raw, 1=Huffman (ChunkCodec; bilinmeyen → red)
+57  [4]  count:        u32 - parça sayısı (header.chunk_count ile aynı olmalı)
+61  ...  parçalar:     her biri:
         +0 [8]  len:   u64 - parça verisi uzunluğu (tavan: 64 MiB)
         +8 [32] cid:   content_id (SHA3-256, aşağıda)
         +40[L]  data:  len bayt parça verisi (Raw ham; Huffman sıkıştırılmış)
```
Toplam uzunluk: `57 + 4 + Σ(40 + len_i)`. Artık bayt → SIKI RED (kurcalama algılama).

### content_id (K3/K31)
```
SHA3-256("BDLM_CONTENT_V1" || u64_le(uzunluk) || baytlar)
```
- Kök: `SHA3-256("BDLM_BUD_V2" || cid_0 || cid_1 || ... || cid_n)` - header.content_id.digest.
- Parça cid'i her zaman SAKLANAN baytlara göre hesaplanır (Raw: ham; Huffman: sıkıştırılmış).
- **K31 kararı (2026-08-16):** 32 bayt (SHA3-256) KORUNUR - 256-bit çakışma direnci,
  kuantum sonrası ~128-bit güvenlik (Grover yarım yarıya), dedup indeksi/kanıt boyutuyla
  uyumlu. 48-64B'ye (SHA3-384/512, BLAKE3) yükseltme gerekirse `MultiHash.algo` alanıyla
  yapılır (K34): okuyucu bilinmeyen algo'yu RED eder, format bozulmaz.

## K60 sıfır-egress (iş modeli)
Ağ İÇİ erişim (aynı B.U.D. ağı / CDN / peer) egress 0'dır; yalnız İnternet'e çıkış
ücretlidir (`EgressZone`, `egress_cost`, `holds_egress`). Depolama maliyetine egress
eklenmez - kullanıcı verisine erişim ücretsiz (R2 benzeri sıfır-egress avantajı).

### Doğrulama (decode)
1. magic, version biti, algo == 0x16 → yoksa red.
2. chunk_codec bilinmiyorsa red.
3. chunk_count > 1_000_000 → red; len > 64 MiB → red; toplam > 4 GiB → red.
4. HER parçada `content_id(data) != cid` → red (payload kurcalama).
5. `Σ len_i != total_len` veya `count != chunk_count` → red.
6. Kök digest eşleşmezse red.

## 3. ChunkCodec::Huffman - BUD-HFM1 (bud_format_huffman)

```
+0 [8] magic:  \xB5 'H' 'F' 'M' '1' 0x00 0x00 0x00
+8 [1] sürüm:  1
+9 [8] orijinal uzunluk: u64 (tavan: 4 GiB)
+17[2] sembol sayısı: u16 (n)
+19    tablo: n × { [1] sembol, [1] kod uzunluğu }   (yinelenen sembol → red)
+gövde: kanonik Huffman kodları, MSB-önce bit paketli
```
- Kod uzunlukları: (uzunluk, sembol) sırasına göre kanonik atama (DEFLATE benzeri).
- Kraft eşitsizliği bozuksa red; kod uzunluğu > 32 → red.
- Tek sembol → uzunluk 1; boş girdi → n=0, gövde boş.
- Son bayt padding bitleri serbest; orijinal uzunluğa ulaşınca durulur.

## 4. Yapısal parçalama (structural_split, K38)

- **Json:** ayraçlar parçalara gömülür; derinlik-1 virgül sınırdır ve SONRAKİ parçanın
  başında korunur (`start = i`). Dizi değilse/bozuksa dahi tek parça → kayıpsız.
- **Csv/Log/Text:** `split_inclusive('\n')` - her parça satır sonuyla biter.
- **Binary:** sabit 64 KiB blok.
- **Birleştirme (join):** SAF birleştirme - hiçbir türde `[`/`]` eklenmez.
- **Compaction (K35):** min_chunk altı bitişik parçalar birleştirilir (kayıpsız).

## 5. Format algılama (bud_format_pipe::detect)

Sıra: JSON (`[`/`{` ile başlar) → CSV (virgül+satır) → LOG (ilk satır 4 haneli yıl)
→ Text (satır içerir ya da tümü yazdırılabilir ASCII) → Unknown (ikili).
Yanlış eşleşme güvenli: kayıpsızlık türden bağımsızdır (Bölüm 1).

## 6. Geriye uyumluluk ve evrim

- Format v2 magic'i v2 kodunu taşır; `from_bytes` tam eşleşme ister.
- Yeni format kodu eklenecekse `FormatCodec` + `bud_format_registry.rs` birlikte güncellenir.
- Yeni parça kodlayıcı eklenecekse `ChunkCodec::from_u8` genişletilir (bilinmeyen red -
  ileri uyumluluk kasıtlı: eski okuyucu yeni kodlayıcıyı reddeder, bozmaz).
- Bu spec'in UYGULANMASI `bud_format_container` testleridir (roundtrip, kurcalama,
  bomba, mini-fuzz); spec değişirse testler de değişmeli (kanıt zinciri).


## 8. Kayıpsız JSON Columnar Transform (bud_format_columnar, İcat - 2026-08-16)

Sıkıştırma ÖNCESİ dönüşüm: JSON kayıt dizisi sütun dizilerine ayrılır (aynı anahtarın
değerleri bitişik → zstd tekrarları görür). İki mod:
- **Exact (mod 0):** sütunlar orijinal kayıt sırasında → `decode(encode(d)) == d` BAYT
  BİREBİR (K38). Anahtar sırası serde preserve_order ile korunur.
- **OrderFree (mod 1):** kayıtlar deterministik sıralanır → kayıt KÜMESİ korunur (KF2);
  sıralama kazancı korpusa bağlıdır (tekrarlı anahtar değerlerinde ek kazanç).

Blob düzeni: magic `\xB5COL` + sürüm + mod + anahtar sayısı + (len,key)* + kayıt sayısı
+ (len,value)* + SHA3-256 digest ("BDLM_BUD_COLUMNAR_V1" domain) - kurcalama RED.
Ölçüm (seed=7, 50k kayıt, zstd19): RAW 7.83x → Exact 8.53x → OrderFree 11.49x.
Düzensiz JSON (kayıtlar farklı anahtar kümesinde) → None; boru hattı ham yola düşer
(kayıpsızlık korunur). Tavanlar: MAX_RECORDS 10M, MAX_COLUMNS 256, MAX_VALUE_BYTES 1MiB.

## 9. Üretim Oranı Kanıtı (bud_format_production, İcat - 2026-08-16)

Her .bud üretim anında `BudProductionRecord` taşıyabilir:
`{format_codec, pipe, original_len, stored_len, payload_root(=content_id(original)), ts, claimed_ratio}`
- `record_hash()` = SHA3("BDLM_BUD_PRODUCTION_V1" || alanlar) - zincire yazılabilir.
- `verify()`: claimed_ratio ≈ original_len/stored_len (tolerans 0.01); geçersiz değer RED.
- `ProductionGates::k_bud_production(rec, measured)`: iddia ölçüm tablosunun 1.5 katını
  aşarsa RED (K19) - "17.19x" gibi ölçümsüz iddialar üretim kanıtından GEÇEMEZ.
- CLI: `bud produce-proof -i x.bud --pipe <pipe>`.

Ekonomi bağlantısı: $0.016/TB/ay taahhüdü üretim kanıtındaki GERÇEK orana bağlanır;
oran yetersizse fiyat revize edilir (dürüst sözleşme). Güncel dürüst fiyat:
0.23342 × 1.143 / 8.53 ≈ 0.031 $/TB/ay (Exact columnar, tek dosya).

## 7. Ölçümler (2026-08-16 - scripts/measure_ratios.py --seed 7 ile TEKRARLANABİLİR)

Deterministik korpus: 50k JSON kaydı / 60k CSV satırı / 80k LOG satırı (seed=7).
Bu değerler runner'ın inline ölçümüyle birebir aynıdır (doğrulanmış). Eski tablodaki
8.48x/5.51x/7.68x değerleri tekrarlanamayan farklı bir korpustandı - K19 dürüstlüğü
gereği doğrulanmış değerlerle değiştirildi (EK13).

| Boru hattı | Doğrulanmış oran |
|---|---|
| structural+zstd19 JSON | 7.83x |
| structural+xz9 JSON | 8.07x |
| structural+zstd19 CSV | 3.55x |
| structural+zstd19 LOG | 6.17x |
| structural+xz9 LOG | 6.30x |
| BUD-HFM1 (yerleşik Huffman, log) | ~1.69x (13.98MB örnek, CLI kanıtı) |
| ZSTD-19 konteyner (ChunkCodec::Zstd, log) | ~6.55x (10.48MB örnek, CLI --zstd kanıtı) |
| JSON columnar Exact (zstd19) | 8.53x (seed=7, 50k) - İcat dönüşümü |
| JSON columnar OrderFree (zstd19) | 11.49x (seed=7, 50k; kayıt sırası serbestse) |

17.19x JSON iddiası bu ölçümlerle TUTMAMAKTADIR (K19 kanaryası: 7.83x < 17.19x);
tavan $0.016/TB/ay EVENODD (1.286) için 18.76x, Düz 7+1 (1.143) için 16.68x gerektirir.
