# Budscan yama katmani

Bu dizin Budscan'in Gecko tarafidir. Motor kaynagi burada **yok** ve olmayacak:
yapim sirasinda Mozilla kaynagi indirilir, buradaki yamalar uygulanir, sonuc
derlenir.

## Neden motor yazilmiyor

Bir tarayici motoru uc seydir: bir HTML/CSS duzenleyici, bir JavaScript motoru
ve bir sanal alan. Ucu de onlarca yilin isi ve ucu de saldiri yuzeyinin
tamami. Kendi motorunu yazan bir web3 tarayicisi, cozmeye calistigi problemin
yanina bir de tarayici guvenligi problemi ekler.

Budscan Gecko'yu yamalar ve butun kararlari `budscan` crate'ine sorar.

## Neden arac katmani kabuk degil

Referans olarak incelenen Firefox turevlerinde yama araclarinin tamami kabuk.
Somut olarak olculen sorun, o depolardaki `check-patchfail.sh`:

```sh
for j in $(grep -n rej$ ../patch.tmp | awk '{ print $(NF); }'); do
    s="$s $j"
    ...
done
if [ ! -z "$s" ]; then failed_patches="$failed_patches [$curpatch]"; fi
```

`grep` hicbir sey bulamazsa dongu bos calisir, `s` bos kalir ve betik
**"success: All patches where applied successfully."** yazip 0 doner. Yani
`patch` ciktisinin bicimi degisirse, bir yama tamamen basarisiz olsa bile
kontrol hicbir seyi inceleyip OK der. Bir kontrolun sessizce hicbir sey
incelememesi, kontrolun olmamasindan kotudur: olmayan bir kontrol yaziliyor
sanilmaz.

Budscan'in yama araclari `budscan::patchset` icinde, Rust olarak. Orada
"hicbir sey inceleyemedim" ayri bir sonuctur (`Verdict::Vacuous`) ve
`is_ok()` false doner.

Kontroller:

```
cargo run -p budscan --bin budscan -- yama-listesi budscan/browser/patches.txt
cargo run --manifest-path xtask/gates/Cargo.toml -- budscan-patchset
```

## Dizin duzeni

| yol | ne |
|---|---|
| `patches.txt` | uygulanacak yamalarin sirali listesi; `!` oneki devre disi |
| `patches/` | unified diff dosyalari |
| `settings/budscan.cfg` | kilitli tercihler (`lockPref`) |
| `settings/policies.json` | dagitim politikasi |
| `l10n/tr-TR/`, `l10n/en-US/` | adres cubugu rozetinin metinleri |
| `mozconfig` | yapim yapilandirmasi |

## Marka

Bu agacta baska bir tarayicinin marka adi gecmez. Yama duzeni fikir olarak
alindi, isim olarak degil; `budscan::patchset::FORBIDDEN_BRAND_TOKENS` listesi
bunu bir kural haline getiriyor ve `budscan-patchset` kapisi CI'da olcuyor.

## Yamalar ne yapiyor

**`bud-protocol-handler.patch`**: `bud://` semasini kaydeder. Sema
`URI_DANGEROUS_TO_LOAD` degil, `URI_IS_LOCAL_RESOURCE` de degil: kendi
kaynagini (`bud://<isim>`) tasiyan siradan bir yuklenebilir sema. Icerik
`budscan` cekirdegi dogruladiktan **sonra** kanala yazilir; dogrulanmayan
baytlar kanala hic girmez.

**`address-bar-verification-badge.patch`**: adres cubuguna dogrulama gucunu
yazar. Dort deger var (`dogrulandi`, `yalniz tasima`, `yalniz beyan`,
`reddedildi`) ve rozet **en zayif halkayi** gosterir. Bir sayfanin baytlari
dogrulanmis olsa bile, adin cozumu kanitsizsa rozet `yalniz beyan` der.

**`name-bar-punycode.patch`**: ad kuralindan gecmeyen bir ad adres cubugunda
punycode olarak gosterilir. Gosterilen sey ile cozulen seyin ayni olmasi bu
tarayicinin kurali; aradaki fark tam olarak homograf saldirisinin yasadigi
bosluktur.
