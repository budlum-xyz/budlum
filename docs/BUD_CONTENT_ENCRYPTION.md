# B.U.D. içerik şifrelemesi: zincirin ne söylediği, ne söylemediği

Bu belge `ContentManifest.encryption` alanının ne olduğunu ve daha
önemlisi **ne olmadığını** anlatır. İkinci kısım daha uzun, çünkü bir
güvenlik alanının en tehlikeli hâli, taşımadığı garantiyi taşıyor sanılmasıdır.

## Ölçülen durum: hiçbir şey söylenmiyordu

Bu alan eklenmeden önce `src/storage/` içinde tek satır şifreleme yoktu ve
şifreleme hakkında **tek satır beyan da** yoktu. Her manifest sessizdi, bu
yüzden sessizliği okuyan herkes kendi sonucunu çıkarıyordu:

- Bir shard tutan operatör, elindeki baytların okunabilir içerik olup
  olmadığını bilmiyordu.
- Çözmeyi deneyip başarısız olan bir istemci, yanlış anahtar mı yoksa bozuk
  shard mı olduğunu ayırt edemiyordu.
- Onarım yolu, kurtardığı baytların açık içerik mi olduğunu bilmeden
  yeniden dağıtıyordu.

Sessizlik bir varsayılan değildir, cevapsız bir sorudur.

## Zincir şifreleyemez

`src/storage/` zincir-üstü bir taahhüt katmanıdır, bayt tutmaz. Bu yüzden
zincir ne şifreleyebilir ne de birinin şifrelediğini doğrulayabilir. Bir
manifestin `ClientSide` demesi, yükleyicinin **açıkladığı** bir olgudur.

Zincirin yapabileceği tek şey bu açıklamayı taşımak ve **değiştirilemez**
kılmaktır. Değiştirilemez kılmanın tek yolu `manifest_id` içine koymaktır.
Taahhüdün dışında bırakılan bir iddia sabit bir kimlik altında yeniden
yazılabilir:

```
1. Yükleyici manifesti ClientSide olarak kaydeder.
2. Bir düğüm aynı id altında Plaintext yazan bir manifest sunar.
3. Sonraki her okuyucu, çektiği baytların hiç korunmadığı sonucuna varır.
```

Bu yüzden kapı alanın varlığını değil, **bağlanmışlığını** denetler:
`scripts/check-content-encryption-is-declared-and-bound.sh`, taahhüt
fonksiyonunun argümanı alıp okumadan attığı durumu ayrı bir kanaryayla
yakalar, çünkü imza tabanlı her kontrol o hâlde de geçer.

## Taahhüt V3

`manifest_id_from_parts` artık üç şeyi kapsıyor:

| Sürüm | Kapsam | Neden eklendi |
|---|---|---|
| V1 | `(index, shard_id, size)` | ilk hâl |
| V2 | `+ kind, k, n` | parity etiketi ve yedeklilik iddiası değiştirilebiliyordu |
| V3 | `+ şifreleme beyanı` | gizlilik iddiası sabit id altında yeniden yazılabiliyordu |

Alan adı `BDLM_MANIFEST_V3`. Alan adını ilerletmeden alan eklemek, V2 ve V3
kimliklerinin farklı anlamlar taşıyıp aynı değere çıkmasına izin verirdi.

`Plaintext` etiketi 0'dır ve bu alanın eklenmesinden önce yazılmış her
manifest `Plaintext` olarak deserialize olur. Bu bir yorum değil, ölçülmüş
gerçektir: o manifestler içinde hiç şifreleme bulunmayan bir ağaç tarafından
yazıldı. Varsayılanı `ClientSide` yapmak, kimsenin yapmadığı bir gizlilik
iddiasını uydurmak olurdu, ki bu iddiasızlıktan daha kötüdür çünkü okuyucu
ona güvenir.

## Anahtar taşınmıyor

Beyan şunları **taşımaz**: anahtar, anahtar kimliği, sarmalanmış anahtar,
nonce. Genel bir taahhüde konan anahtar, genel bir zincire yayımlanmış
anahtardır. Testlerden biri (`the_declaration_carries_no_key_material`) tipin
genişliğini iki bayta kilitler, kapı da alan adlarını tarar. İkisi birden,
"bir tane sarmalanmış anahtar koyalım" değişikliğinin sessizce geçmesini
engeller.

Anahtar teslimi erişim-izni katmanının işidir: önce zincirde `AccessGrant`,
DM yalnızca bildirim.

## Neden yalnızca kimliği doğrulanmış şifreler

`ContentCipher` üç AEAD adlandırır: AES-256-GCM, ChaCha20-Poly1305,
XChaCha20-Poly1305. Kimliği doğrulanmamış bir mod kasten dışarıda bırakıldı.

2024 tarihli "End-to-End Encrypted Cloud Storage in the Wild" çalışması
Icedrive'da kimliği doğrulanmamış CBC modunun sunucuya şifreli metni yeniden
şekillendirme imkânı verdiğini gösterdi; aynı çalışma Seafile'da kimliği
doğrulanmamış parçalamanın, sunucunun başka dosyaların parçalarından geçerli
şekilde çözülen yeni dosyalar kurmasına izin verdiğini ölçtü. Burada kimliği
doğrulanmamış bir şifre adlandırmak, manifestin gizlilik ilan edip
bütünlüğü baytları tutan düğüme bırakması olurdu.

## Zincirin doğrulayabildiği tek şey

Bir aritmetik kontrol var, tek başına: adlandırılan üç şifrenin hepsi 16
baytlık bir kimlik doğrulama etiketi ekler, dolayısıyla sıfır uzunluklu bir
açık metin bile 16 bayta şifrelenir. `ClientSide` ilan eden ve 16 bayttan kısa
bir nesne, bu şifrelerin hiçbirinin çıktısı değildir.

Bu kontrol **dikkatsiz durumu** yakalar, kararlı saldırganı değil. Yalan
söylemek isteyen bir yazar dolgu ekler. Yine de değerlidir, çünkü sahaya
çıkan hâl dikkatsiz olandır: şifrelemeyi unutup beyan etmeyi hatırlayan bir
istemci, nesne küçükken tam olarak bu şekli üretir.

`an_object_at_the_tag_length_is_accepted` ve
`a_small_plaintext_object_is_untouched_by_the_tag_check` testleri bu sınırın
yalnız imkânsız olanı reddettiğini, sıradan küçük nesnelere uzanmadığını
kilitler.

## Bu belgenin iddia ETMEDİKLERİ

Kapsamı abartmamak için açıkça:

1. **Hiçbir şeyin şifrelendiği doğrulanmıyor.** Zincir bayt görmüyor.
2. **Shard baytlarının beyanla tutarlı olduğu doğrulanmıyor.** Bir yükleyici
   `ClientSide` deyip açık metin yükleyebilir; 16 bayt sınırı dışında bunu
   yakalayan bir mekanizma yok.
3. **Anahtar dağıtımı çözülmedi.** Beyan, anahtarın nasıl ulaşacağını
   söylemez.
4. **Operatörün beyana uyduğu zorlanmıyor.** `Plaintext` gören bir operatör
   içeriği okuyabilir ve okumasını engelleyen bir şey yoktur. Depolama
   düğümünde TEE bunun için tasarlanıyor, henüz yok.
5. **Şifreleme zorunlu değil.** `Plaintext` geçerli bir durumdur.

Bunlardan (1) ve (2) zincir-üstü olarak çözülemez. (3), (4) ve (5) sonraki
işlerdir.
