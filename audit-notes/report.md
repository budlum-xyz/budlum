# Rapor

Tur 2. Tarih 13-11-2026. Bu dosya her turdan sonra guncellenir.

## 1. Durum tablosu

| PR | Baslik | Kaynak -> Hedef | Son SHA | CI | Strix | Merge kapilari |
|----|--------|-----------------|---------|----|-------|----------------|
| #126 | testnet | `testnet` -> `testnet-quantum` | `8b5592af` | kuyrukta, yesil yok | 39 bulgu, 2 cozuldu | 7 kapi acik |
| #110 | Testnet and Quantum | `testnet-quantum` -> `main` | `55ec2f7b` | kuyrukta, yesil yok | 17 bulgu, 5 cozuldu | 7 kapi acik |

Yigin: `testnet` -> `testnet-quantum` -> `main`.

Bu turda yigina uc commit eklendi:

| Commit | Konu | Dal |
|--------|------|-----|
| `c3c6ed92` | dort inceleme bulgusu: BNS yokluk kaniti konumu, BNS extras on-imaji, slashta kilitli emanet, suresi dolmus custody anlasmasi | `testnet` |
| `f0ee157e` | B14 ag gecidi kurallari ve alti adli gate | `testnet` |
| `8b5592af` | `src/gateway` ad cakismasi: modul `web_gateway` oldu | `testnet` |
| `bd1e6a79` | B-0004: RPC kanit yaniti eksik alanlari tasiyordu | `testnet` |
| `c6bdcccf` | B14 sunucu ikilisi, `ops/gateway/` birimi, imaji ve yapilandirmasi | `testnet` |
| `6c25fa32` | `gateway-gate` ikili testlerini adlandirdi | `testnet` |
| `f424cba2` | Gate yalnizca modul testlerini adlandiriyor; ikili testleri kendi hedefinde | `testnet` |

`30c5ab48` B12b, B13, B15 ve B16 maddelerini tasir.

### CI durumu

Depoda 234 bekleyen calistirma var. Yalniz 5 kosu ayni anda calisiyor ve
bunlarin dordu `bns/b6-subdomains`, biri `bns/b5-records-v3` dalinda. Iki Miri
isi 17:29 ve 17:58'den beri donuyor. Kuyruk bu yuzden ilerlemiyor.

Bu turda olculen:

- Depoda yesil kosu var, ama hicbiri bu isin commitlerinden degil. Son yesil
  isler `b02b844d` (16 is, 16:44) ve `d26e337f` (16 is, 19:07). Ikisi de hafif
  isler: Rust Quality, Semgrep, Grype, Typos, Semver, Cargo Vet, Docker Smoke,
  Benchmark, PKCS#11, Diff surface, Release signature, Supply Chain Extra.
- Ana `CI` is akisi (`ci.yml`) bu SHA'larda kosmadi. Son yesil `CI` kosusu
  03:57'de `testnet-quantum` dalinda. O saatten beri `ci.yml` icin 23 iptal,
  5 beklemede, 2 kuyrukta.
- `testnet` basi `269c2f45` icin `ci.yml` 22:41'den beri `pending`.

Sonuc degismedi: bu isin commitlerinin hicbiri gercek `CI` ile dogrulanmadi.
Bu yuzden hicbir madde "dogrulandi" sayilmaz. Kanit yok.

Yerel derleme de kapali: 1.9 GB bellekte `budlum-core` rustc SIGKILL aliyor,
`mkswap` kurulu degil, root yok. Tek dogrulayici CI, o da tikali.

## 2. Bulgu kayit defteri (Strix)

Tam kayit: `audit-notes/strix-ledger.md`, 56 bulgu.

| Durum | Yuksek | Orta | Dusuk | Toplam |
|-------|--------|------|-------|--------|
| cozuldu | 4 | 3 | 0 | 7 |
| gecersiz | 1 | 0 | 0 | 1 |
| acik | 13 | 13 | 22 | 48 |
| **Toplam** | **18** | **16** | **22** | **56** |

### Bu turda cozulenler

| Kayit | Konu | Commit |
|-------|------|--------|
| S-110-4542839504 | Handoff set digest BLS anahtarini kapsiyor (onceden cozulmustu, dogrulandi) | `30c5ab48` |
| S-110-4555294348 | Protobuf baslik slashing listesi sinirli (onceden cozulmustu, dogrulandi) | `30c5ab48` |
| S-110-4558176035 | Protobuf blok islem listesi sinirli (onceden cozulmustu, dogrulandi) | `30c5ab48` |
| S-110-4568472236 | `Expire` slashta durmuyor; iade ayrildi | `c3c6ed92` |
| S-110-4568539249 | `has_custody_deal` yalnizca canli anlasma sayar | `c3c6ed92` |
| S-126-4568600961 | BNS yokluk kaniti konum tasir | `c3c6ed92` |
| S-126-4568600860 | BNS extras on-imaj tasir | `c3c6ed92` |
| S-126-4506127017 | Koltuk katilimi kaydi proposer'dan alinmiyor, QC blob'undan yeniden uretiliyor | kod okumasi, `bd1e6a79` |

Uc bulgu kod okumasiyla "onceden cozulmustu" cikti. Bu bir kacis degil: ucunun
de kapanis gerekcesi canli kod ve test ile desteklendi, defterde yazili.

## 3. Denetim bulgulari (kendi bulduklarim)

Tam kayit: `audit-notes/findings/`.

| Kimlik | Konum | Onem | Konu | Durum |
|--------|-------|------|------|-------|
| B-0001 | `src/gateway` | yuksek | B14 modulu `main` dalindaki `src/gateway` ile ayni yolu paylasir; birlestiginde `pub mod gateway` iki kez tanimlanir | cozuldu, `8b5592af` |
| B-0002 | `src/bns/registry.rs` | orta | `is_valid_label` ozeldi, ag gecidi ayni tabloyu kopyalamak zorundaydi | cozuldu, `f0ee157e` |
| B-0003 | `src/gateway/mod.rs` | orta | yeni modul public yuzey sunuyor ama calisan hicbir ikili onu cagirmiyor | kayitli, `WIRING: unwired` |
| B-0004 | `src/rpc/server.rs` | yuksek | RPC kanit yaniti `leaf_index`, `tree_size` ve `extras` alanlarini yazmiyordu; duzeltme telde etkisizdi | cozuldu, `bd1e6a79` |
| B-0005 | `crates/wallet-core/src/bns.rs` | yuksek | cuzdan kaniti kok ve epoch'u cagirandan aliyor; crate icinde baslik dogrulamasi yok | acik, tasarim `ip-11` icinde |
| B-0006 | `src/core/account.rs` | dusuk | `state_root_body` dokuman yorumu yanlis islevin ustunde duruyordu | cozuldu, `work/a8-audit` |
| B-0007 | `src/persistence/db.rs`, `src/consensus/handoff.rs` | yuksek | Handoff Sertifikasi dogrulaniyor ama hic uretilmiyor; depo kapilari cagiransiz | kismen cozuldu: `restore_handoff_chain` ve 2 test indi, uretim kancasi acik |
| B-0008 | dal yapisi | yuksek | `audit/master-plan` `main`den dallanmis, `testnet`ten degil; 1092 commit ve 229 dosya geride | cozuldu: notlar `testnet` tabanina tasindi |

B-0003 bir hata degil, bir durumdur. Direktifin kurali: bir yetenek modulu ya
bir yerden cagrilir ya da cagrilmadigini yazar. Modul yazdi.

## 4. Henuz kodlanmamis eksikler

| Konu | Neden simdi kodlanmadi | Onerilen sonraki adim |
|------|------------------------|----------------------|
| B14 TLS sonlandirici ve `budlum.xyz` PSL basvurusu | Canli sertifika, DNS saglayici ve alan adi gerekir | Terminator yapilandirmasi, sonra PSL basvurusu |
| B14 B.U.D. 3.0 icerik kaynagi | Dugum ve ag gecidinin kendi odedigi ucretli goruntuleme makbuzu gerekir | `ContentSource` icin B.U.D. 3.0 uygulamasi |
| 50 acik Strix bulgusu | Her biri ayri kod yolu ve test ister | Asama 3 sirasina gore, onem sirasiyla |
| 64 is paketi | Cogu `main` dalinda, bu dalda degil | Asama 10 |
| Cok isletim sisteminde calistirma | Imaj indirme ve derleme gerekir; bu ortamda derleme OOM ile oluyor | Asama 9 |

### Bilinen yerel engel

Bu ortamda `cargo check --lib` iki varyantla da bellek yetersizligiyle oldu
(`dmesg` bes OOM-kill kaydi). Bu yuzden hicbir Rust dogrulamasi yerelde
yapilmadi. Tek yetkili CI'dir ve CI kuyrugu tikali. `cargo fmt --all --check`
temiz gecer; bicim dogrulamasi yerelde yapildi.

## 5. Ihlal beyani

Yasak yontem kullanilmadi.

- Force-push yok. Iki push da ileri yonde.
- Gecmis yeniden yazma yok.
- Branch protection atlatma yok.
- Yeni `#[allow(...)]` yok.
- Yeni `#[ignore]` yok.
- Eski commit sabitleme yok.
- Mantik zayiflatma yok. Bu turda yalnizca kisitlama eklendi: konum sarti,
  extras on-imaji, slas hata yutma, canli anlasma sarti.
- Token hicbir commit, yorum, log veya rapora girmedi.

## 6. Acik riskler

| Risk | Durum |
|------|-------|
| CI kuyrugu tikali, yesil kosu yok | Bu turun en buyuk riski. Dogrulama iddiasi kurulamiyor. |
| `BADGE_PUSH_TOKEN` | Denetlenmedi. Asama 8 sirasinda bakilacak. |
| Ucuncu taraf guvenlik denetimi yok | Strix disinda bagimsiz denetim yok. |
| `THE_BUDLUM_DIREKTIF` depoda degil | 64 paket kullanicinin dosyasindan okundu. Depoya eklenmedi. |
| `main` ve `testnet` agaclari ayri | 340 ve 568 kaynak dosya. Yigin ilerledikce bu fark kapanmali. |

## 7. Sonraki tur

1. CI kuyrugunu izle. Yesil kosu gelince run numaralarini bu tabloya yaz.
2. Kalan 50 Strix bulgusundan yuksek onemlileri sirayla coz.
3. Asama 8 alan denetimine basla: `src/consensus`, `src/chain`, `src/cross_domain`.
4. B14 sunucu ikilisini yaz.
