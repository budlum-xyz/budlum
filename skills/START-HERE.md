# Başlangıç — her tur bu iki programla açılır

Bu depo, çalışmanın başladığı yerdir; yerel kum kutusu her tur sıfırlanabilir,
güvenilir durum `main` dalındadır. Bir tur, sırayla şu iki programla açılır:

1. **`senkron.py`** — yerel ağacı dal başının izlediği her yolunda bayt bayt
   doğrular; sapma varsa `--repair` ile head tarball'ını üstüne yazar.
   ```
   python3 skills/senkron.py budlum-xyz/budlum <dal> <yerel_dizin> [--repair]
   ```
2. **`ci.py`** — CI'yi olduğu gibi okur: iş sayımı, kırmızı işler, kırmızı
   adım; `--derin` ile o adımın log satırlarını, `--bekle` ile koşu bitene
   kadar yoklar.
   ```
   python3 skills/ci.py budlum-xyz/budlum <tam-sha> [--derin|--bekle]
   ```

Token `~/.tokp1` + `~/.tokp2` dosyalarında yarım yarım durur, okurken
birleştirilir; bu dosyalar hiçbir commit'e girmez.

## Kalan beceriler

| beceri | ne yapar |
|---|---|
| `olc.py` | yerel doğrulama zinciri: fmt, clippy, kapılar, pedantic sayımı |
| `it.py` | yalnızca listelenen yolları commit olarak iter (ağaç silme riski yok) |
| `ratchet.py` | ratchet sayısını CI logundan okur, tabanı yalnızca ölçülen sayıya indirir |
| `surgu.py` | depolama alt ağacında pedantic/nursery uyarılarını mekanik azaltır |

Kullanım ayrıntıları `README.md`'de, metodoloji `SKILL.md`'de, BudZKVM
rejenerasyon becerisi `rejenerasyon-zkvm-skill.md`'de.
