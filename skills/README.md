# Beceriler (çalıştırılabilir yetenekler)

Kum kutusu silindiğinde ya da araçı yitirdiğinde ilk okunacak yer burasıdır;
`goal.md` buyrukları, `plan.md` tarihi tutar, buradaki betikler işi yapar.
Dördü de bağımlılıksızdır (yalnızca stdlib), tokenı `~/.tokp1` + `~/.tokp2`
dosyalarından birleştirerek okur ve her yazma işlemini uzaktan geri okuyarak
bitirir.

| beceri | ne yapar | komut |
|---|---|---|
| `senkron.py` | yerel ağacı branch başının izlenen her yolunda bayt bayt doğrular; `--repair` ile head tarball'ını üstüne yazar | `python3 skills/senkron.py budlum-xyz/budlum usl /home/user/work/usl [--repair]` |
| `ci.py` | CI'yi sayar, kırmızı işleri ve **kırmızı adımı** yazdırır; `--derin` o adımın log satırlarını indirir | `python3 skills/ci.py budlum-xyz/budlum <tam-sha> [--derin]` |
| `olc.py` | yerel doğrulama zinciri: fmt, `cargo clippy --lib -D warnings`, kapılar (gerekirse `xtask/gates` binary'sini yeniden derleyerek), `--pedantic <yol-öneki>` ile ratchet sayımı | `python3 skills/olc.py /home/user/work/usl [--klippy\|--pedantic src/storage\|--kur]` |
| `it.py` | yalnızca listelenen yolları commit olarak iter; listelenmeyen izlenen bir yol depodan farklıysa **itmeyi reddeder**, her commit sonrası ağaç eşitliğini ve dosya baytlarını geri okur | `python3 skills/it.py budlum-xyz/budlum usl spec.json /home/user/work/usl` |

`spec.json` biçimi: `[{"message": "weed ...", "date": "ISO-8601Z", "paths": ["src/storage/x.rs"]}]`.
İki commit sırayla zincirlenebilir; `it.py` her adımı `base_tree` üzerine kurar,
bu yüzden geçmiş yeniden yazımı ya da ağaç silmesi söz konusu değildir.

## Neden böyle (ölçülmüş gerekçeler)

- **Yerel ağaca güvenilmez.** Kum fırtınası geri yüklemesi dosyaları sessizce bayat
  sürüme döndürüyor ve gizli dizinleri (`.github`, `.quality`, `.cargo`) düşürüyor;
  ölçüldü: head ile 17 yol farklıydı ve uzaktaki sürüm daha yeniydi. Kayıp `.github`
  yüzünden kapılar yanlış OK/FAIL verdi, bayat `xtask/gates` kaynaklı binary yanlış
  kural uyguladı, bayat `transformed.rs` olmayan bir derleme kırığı uydurdu.
  Bu yüzden `it.py` listelenmeyen yollar sapma gösterirse çalışmıyor.
- **CI sayımı tek başına yanıltır.** Bir adım kırmızı olduğunda ardından gelen ~25 adım
  `skipped` olur ve “kırmızı yok” okuması çıkar; `ci.py` adımı ve logu indirir.
- **Yerel 2 GB'tır.** `cargo clippy --lib` sığar, `--tests`/`--all-targets` sığmaz
  (rustc SIGKILL). Bu yüzden `lib` testi CI'ye bırakılır; yerelde ölçülen sayı
  ratchet'in yalnızca lib kesimidir.

## Ortam

```
PATH=/home/user/work/.cache/tc2/cargo/bin:/home/user/work/bin:$PATH
RUSTUP_HOME=/home/user/work/.cache/tc2/rustup  CARGO_HOME=/home/user/work/.cache/tc2/cargo
PROTOC=/home/user/work/protoc27/bin/protoc          # build.rs bunu ister
# Araç ağacı snapshot dışı: /home/user/work/.cache/tc2, ~/.cargo ve ~/.rustup oraya symlink
# (ölçüldü: 4 GB'lik ağaç geri yüklemeyi patlatıyordu; şimdi snapshot'a giren 59 MB)
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
```

Araçlar silindiğinde: `python3 skills/olc.py /home/user/work/usl --kur`
rustup 1.97.1 (rustfmt + clippy) ve protoc 27.2'yi indirir. Registry bozulursa
(`failed to parse manifest at .../registry/src/...`) `registry/src` ve
`registry/cache` silinip yeniden indirilir; `Cargo.lock`a dokunulmaz.
Gitleaks/actionlint `/home/user/work/bin`de; çalıştırma bitişi kaybolduysa
`chmod +x /home/user/work/bin/*`. cargo-vet bu kutuda artık yok; `cargo-vet`
kapısı ancak `cargo install --locked cargo-vet 0.10.2` sonrası yerel ölçülür,
aksi halde CI'daki Supply Chain işi okunur.
