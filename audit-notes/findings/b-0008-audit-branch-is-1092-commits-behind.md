# B-0008 - The audit branch is 1092 commits behind testnet and cannot carry the fixes

Durum: acik
Asama: yapi
Onem: yuksek

## Kusur

`audit/master-plan` dali `main`den (`95c07fd7`) dallanmis, `testnet`ten
degil. `testnet`in basi olan `269c2f45`e gore 1092 commit geride.

Olculen fark:

| Olcu | `audit/master-plan` | `testnet` |
|------|--------------------|-----------|
| `src/` altinda `.rs` dosyasi | 332 | 561 |
| `src/persistence/` | yok | var |
| `src/web_gateway/` | yok | var |

Bunun dogrudan sonucu: denetim notlarinin anlattigi dosyalarin bir kismi
denetim dalinda hic yok. B-0003, B-0004, B-0005 ve B-0007'nin kod duzeltmeleri
`testnet` tabaninda yasiyor, denetim dalinda degil. Iki taban ayri ayri
ilerlerse notlar ile kod birbirini tutmaz ve her duzeltme iki kez yazilmak
zorunda kalir.

## Duzeltme

Denetim notlari `testnet` tabanina tasindi. `audit-notes/` artik `testnet`in
uzerinde duruyor, boylece not ile kod ayni commit zincirinde.

Bu turda yapilan:

- `audit-notes/{plan.md,report.md,strix-ledger.md}` ve
  `audit-notes/findings/b-0001..b-0005` ile `audit-notes/testnet/index.md`
  `audit/master-plan` dalindan alinip `testnet` tabanina kondu.
- `src/persistence/db.rs` icindeki B-0007 duzeltmesi ayni tabanda.

## Acik yarisi

`audit/master-plan` dali hala duruyor ve PR #162 depo sahibi tarafindan
kapatildi. Iki taban birlestirilmeden once iki dal arasindaki farki kapatacak
bir merge gerekiyor: `testnet` uzerinde duran notlari tasiyan yeni bir dal,
`audit/master-plan`in eski tabanina geri merge edilmemeli.

Bu madde bir uyari kaydidir, kod isi degil. Kapanmasi icin tek dal kalmalidir.
