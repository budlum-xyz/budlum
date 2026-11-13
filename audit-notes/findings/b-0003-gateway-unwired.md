# Bulgu B-0003

## Kimlik

B-0003

## Konum

`src/web_gateway/mod.rs`, ilk alti satir

## Onem

Orta

## Ne yanlis

`src/web_gateway` dort katman ve on bir genel fonksiyon sunar. Calisan hicbir
ikili bu fonksiyonlari cagirmaz. Sunucu sureci (`src/bin/budlum-gateway.rs`),
TLS sonlandirici ve `ops/gateway/` bu degisiklikte yok.

Gate `capability_modules_are_wired` bunu olcer: uc veya daha fazla genel
fonksiyon sunan bir modul baska bir uretim modulu tarafindan adlandirilmiyorsa
modul ya cagrildigini gosterir ya da cagrilmadigini yazar.

## Neden yanlis

Bir kapiyi hicbir sey cagirmiyorsa o kapi hicbir seyi korumaz. Bu depoda bu
durum daha once yasandi: `validate_inference_grant` belgelenmisti ve hicbir
yerden cagrilmiyordu.

Ancak bu bir hata degil, bir durumdur. Modulun kurallari tam ve testleri var;
eksik olan onlari bir surece baglayan katman.

## Neye yol acar

- Okuyan kisi ag gecidinin calistigini sanar. Calismiyor.
- Testler gecer, cunku testler modulu dogrudan cagirir.
- B14 maddesi "tamam" gorunur, oysa `budlum.xyz` hicbir seye cevap vermez.

## Nasil duzeltilir

1. Modul basina `//! WIRING: unwired - <gerekce>` satiri yaz.
2. Gerekcede neyin eksik oldugunu ve neden eksik oldugunu yaz: sunucu ikilisi,
   TLS sonlandirici, muhurlu icerik sembol paketi yolu, `ops/gateway/`.
3. Gerekcede bu katmanlarin neden simdi yazilmadigini yaz: canli sertifika,
   DNS saglayici ve ana makine gerekir.
4. Sunucu ikilisi yazildiginda bu satiri sil ve `WIRING: wired - <nasil>`
   yaz.

## Durum

kayitli, cozulmedi

- Modul `WIRING: unwired` bildiriyor. Gate bu bildirimi kabul eder.
- Sunucu ikilisi sonraki turda yazilir.
- Commit: `f0ee157e`
- CI run: yok. Kuyruk tikali.
