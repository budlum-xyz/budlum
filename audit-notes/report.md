# Rapor

Tur 1. Tarih 13-11-2026. Bu dosya her turdan sonra guncellenir.

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

`30c5ab48` B12b, B13, B15 ve B16 maddelerini tasir.

### CI durumu

Depoda 196 bekleyen calistirma var. `testnet` dalina atilan her yeni commit
onceki kosulari iptal eder (`cancelled`), cunku is akislari ayni concurrency
grubunu paylasir. Bu turda yesil bir kosu gorulmedi. Bu yuzden hicbir madde
"dogrulandi" sayilmaz. Kanit yok.

Bu bir engel, cozum degil: kuyruk bosaldiginda kosular tamamlanir ve sonuc
buraya yazilir.

## 2. Bulgu kayit defteri (Strix)

Tam kayit: `audit-notes/strix-ledger.md`, 56 bulgu.

| Durum | Yuksek | Orta | Dusuk | Toplam |
|-------|--------|------|-------|--------|
| cozuldu | 3 | 3 | 0 | 6 |
| acik | 15 | 13 | 22 | 50 |
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

Uc bulgu kod okumasiyla "onceden cozulmustu" cikti. Bu bir kacis degil: ucunun
de kapanis gerekcesi canli kod ve test ile desteklendi, defterde yazili.

## 3. Denetim bulgulari (kendi bulduklarim)

Tam kayit: `audit-notes/findings/`.

| Kimlik | Konum | Onem | Konu | Durum |
|--------|-------|------|------|-------|
| B-0001 | `src/gateway` | yuksek | B14 modulu `main` dalindaki `src/gateway` ile ayni yolu paylasir; birlestiginde `pub mod gateway` iki kez tanimlanir | cozuldu, `8b5592af` |
| B-0002 | `src/bns/registry.rs` | orta | `is_valid_label` ozeldi, ag gecidi ayni tabloyu kopyalamak zorundaydi | cozuldu, `f0ee157e` |
| B-0003 | `src/gateway/mod.rs` | orta | yeni modul public yuzey sunuyor ama calisan hicbir ikili onu cagirmiyor | kayitli, `WIRING: unwired` |

B-0003 bir hata degil, bir durumdur. Direktifin kurali: bir yetenek modulu ya
bir yerden cagrilir ya da cagrilmadigini yazar. Modul yazdi.

## 4. Henuz kodlanmamis eksikler

| Konu | Neden simdi kodlanmadi | Onerilen sonraki adim |
|------|------------------------|----------------------|
| B14 sunucu ikilisi, TLS, `ops/gateway/` | Canli sertifika, DNS saglayici ve ana makine gerekir | `src/bin/budlum-gateway.rs`, sonra `budlum.xyz` PSL basvurusu |
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
