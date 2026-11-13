# B-0007 - Handoff Certificates are verified but never produced

Durum: acik
Asama: 8 (`src/consensus`, `src/persistence`)
Onem: yuksek

## Kusur

`src/consensus/handoff.rs` Handoff Sertifikasinin tamamini tasiyor: komite
kurali, set ozeti, imzalama mesaji, `verify_in` ve `follow_handoffs`.
`verify_in` gercek isi yapiyor. Giden set ozetini, epoch rastgeleligini, komite
uyeligini, imza sirasini, ucte iki esigini ve her ML-DSA-65 imzasini
`BDLM/HANDOFF/V1` altinda dogruluyor.

Agacta hicbir yer sertifika uretmiyor.

- `Storage::save_handoff_cert` cagiransiz.
- `Storage::load_handoff_certs` cagiransiz.
- `handoff_committee`, `COMMITTEE_SIZE` ve `follow_handoffs` ucu de
  `WIRING: consensus surface kept public ... production callers land with it`
  etiketli.
- Modul basligi sertifikanin "stored for good (`Storage::save_handoff_cert`)"
  oldugunu ve hafif istemcinin her sonraki seti `follow_handoffs` ile
  izleyebildigini yaziyor. Bu cumle agacta olmayan bir davranisi anlatiyor.

Pratik sonuc: bir epoch siniri validator setini degistiriyor ve bu degisimi
kaydeden kalici, komite imzali bir eser dogmuyor. `e` epochunun setine guvenen
hafif istemci `e + 1`'e depodan gecemez, cunku hicbir sey depolanmiyor.
Dugum yeniden basladiginda handoff gecmisi tumuyle kayboluyor, cunku
`load_handoff_certs` de hicbir yerden cagrilmiyor.

## Testnette neden onemli

Testnette set kucuk, bu yuzden `handoff_committee` her validatoru donduruyor
ve tum set imzaliyor. Bu sertifikayi ucuzlatiyor, istege bagli yapmiyor.
Dugum yeniden basladiktan sonra hafif istemcinin okudugu eser tam olarak bu ve
setin gercekten yurudugunun tek kalici kaniti bu. B14 gecidi bir hafif
istemci: `PinnedHeaderRoots` bu zincir olmadan validator seti degisimini
izleyemiyor.

## Duzeltme

1. Epoch sinirinda, giden ve gelen snapshot'tan sertifikayi kur ve bu dugumun
   komite koltuguyla imzala.
2. Uc esigi asildigi anda `save_handoff_cert` ile kalicilastir.
3. Acilista zinciri `load_handoff_certs` ile geri yukle ve her adimi
   `follow_handoffs` ile guvenilen setten dogrula.
4. Tum donguyu test et: uret, kalicilastir, yeniden basla, izle.

1. adim imzalama anahtarini ve epoch sinirini istiyor, ikisi de zincir
aktorunde. 2 ile 4 arasi kalicilik ve hafif istemci icinde yerel ve aktore
dokunmayan testlerle once inebilir.

## Bu turda inen

`Storage::restore_handoff_chain` eklendi. Depodaki sertifikalari ayni epochun
kalici snapshot'i ile eslestirip tum zinciri `follow_handoffs`'a veriyor.
Snapshot'i olmayan bir epochta yuruyus duruyor ve dogrulanan zinciri
donduruyor; tek bir budanmis snapshot dugumu acilmaz yapmasin diye.

Iki test eklendi, `src/persistence/db.rs`:

- `a_stored_handoff_chain_survives_a_restart_and_verifies` - yaz, kapat,
  yeniden ac, dogrula. Ulasilan epoch 5, guvenilen set epoch 4'un seti,
  dogrulanan sertifika sayisi 1.
- `a_stored_handoff_chain_with_the_wrong_randomness_is_refused` - depo guven
  degildir. Epochun rastgeleligi tutmayan sertifika geri yuklemede reddedilir.

`restore_handoff_chain`'in uretim cagirani henuz yok. Zincir aktorunun acilis
yolu onu cagiracak; o baglanti bu bulgunun acik kalan yarisi.

## Sirada

1. Acilis yolunda `restore_handoff_chain` cagrisi.
2. Epoch sinirinda sertifika uretimi ve imzasi.

## Kanit

Commit ve CI run bu turda yok. Yerel derleme 1.9 GB bellekte `budlum-core`
icin SIGKILL aliyor; `mkswap` ve root yok. Dogrulama CI'da.
