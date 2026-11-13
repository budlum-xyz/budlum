# Bulgu B-0002

## Kimlik

B-0002

## Konum

`src/bns/registry.rs`, `fn is_valid_label`

Duzeltmeden once:

```rust
#[must_use]
fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
```

## Onem

Orta

## Ne yanlis

Ad kurali tek bir yerde tanimliydi ve o yer ozeldi. B14 ag gecidi ayni kurali
uygulamak zorunda: bir ana makine etiketi kayit defterinin satacagi bir etiket
mi. Kural ozel oldugu icin gecit ikinci bir kopya yazmak zorunda kalirdi.

## Neden yanlis

Iki kopya iki ayri gorus demektir. Kayit defteri `a-1.bud` satar, gecit onu
reddederse ad satilir ama acilmaz. Tersi olursa gecit, defterin hic satmadigi
bir adi cozumlemeye calisir. Bu tur farklar sessizdir: iki taraf da kendi
testinden gecer.

## Neye yol acar

- Satici bir adi satin alir, ag gecidi o adi 404 dondurur.
- Gecit, defterin reddedecegi bir etiketi kabul eder ve var olmayan bir adi
  sorgular.
- Kural degistiginde iki yerden birinin guncellenmesi unutulur.

## Nasil duzeltilir

1. `is_valid_label` fonksiyonunu `pub` yap.
2. Yanina bir belge yorumu yaz: kural neden acik ve kim kullaniyor.
3. `len() <= 63` sinirini ekle. DNS etiketi 63 bayti gecemez; kayit defterinin
   32 karakter siniri zaten daha dar, ama kural kendi basina da dogru olmali.
4. Ozel kopyayi sil. Tek tanim kalsin.
5. Ag gecidi `BnsRegistry::is_valid_label` cagirsin.

## Durum

cozuldu

- Commit: `f0ee157e`
- CI run: yok. Kuyruk tikali.
