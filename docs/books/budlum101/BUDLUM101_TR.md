---
title: "Budlum101 — Evrensel Mutabakat Katmanı"
subtitle: "Veri Egemenliği, Toplumsal Yeşerme ve İnternetin Sonraki Katmanı"
author: "Budlum Teknik Topluluğu"
status: "Public education edition"
---

# Budlum101

Bu kitap Budlum’un vizyonunu, mimarisini, teknik kararlarını ve doğrulanmış
uygulama durumunu temel kavramlardan başlayarak anlatır. Bir özelliğin üretim,
audit veya mainnet durumu yalnız kanıtı varsa o şekilde adlandırılır.

## Çift anlatım katmanı

<div class="tech">
<strong>Teknik katman:</strong> Protocol, veri modeli, kod sınırı, test ve
operasyonel kabul kriterlerini açıklar.
</div>

<div class="plain">
<strong>Sade anlatım:</strong> Aynı fikri teknik olmayan okuyucu için gündelik
bir dille açıklar. PDF çıktısında bu kutu <code>#98AE89</code> renginde görünür.
</div>

## Bölüm planı

1. Budlum’un amacı: veri egemenliği ve toplumsal yeşerme
2. Blockchain temel kavramları
3. Evrensel mutabakat katmanı
4. Çoklu konsensüs ve PoA izolasyonu
5. İşlemler, V4 imzalama ve admission
6. State, snapshot ve persistence
7. Ağ, P2P, RPC ve node işletimi
8. Bridge, EVM receipt doğrulama ve relayer sınırları
9. B.U.D. ve BNS modül mimarisi
10. BudZero, ZKVM ve proof güvenlik sınırları
11. AI, governance ve tokenomics
12. CI, test mantığı, fuzzing, audit ve mainnet ceremony
13. Teknik karar kayıtları ve terimler

# Bölüm 1 — Neden Budlum?

## 1.1 İnternetin bir sonraki katmanı fikri

İnternet bugün bilgi taşımakta çok başarılıdır; fakat bir bilginin hangi
kuralla üretildiğini, bir dijital varlığın hangi durumda bulunduğunu veya iki
farklı sistemin aynı olay üzerinde ne zaman uzlaştığını evrensel biçimde
kanıtlamaz. Bir web sayfası “ödeme yapıldı” diyebilir. Bir banka kaydı bunu
başka biçimde tutabilir. Bir blockchain ise kendi kuralları içinde doğrulayabilir.
Ancak bu üç dünyanın ortak, doğrulanabilir mutabakat noktası çoğu zaman yoktur.

Budlum’un önerisi bu boşluğu doldurmaktır: her sistemi tek bir zincire
zorlamak yerine, farklı sistemlerin kendi kuralları altında ürettiği finality
kanıtlarını değerlendiren bir **evrensel mutabakat katmanı** kurmak.

<div class="tech">
Budlum Core, farklı konsensüs domain’lerini `ConsensusDomain` ve
`DomainFinalityAdapter` soyutlamalarıyla ele alır. Amaç, PoW/PoS/BFT/ZK gibi
farklı finality biçimlerini tek global settlement state’ine bağlamaktır. PoA
ayrı ve bilinçli permissioned bir domain’dir; permissionless registry ile veri
ve yetki paylaşmamalıdır.
</div>

<div class="plain">
Budlum, herkesi aynı kurallı tek bir mahalleye taşımaya çalışmaz. Her mahalle
kendi düzenini korur; Budlum ise mahalleler arasında “bu olay gerçekten
kesinleşti mi?” sorusuna ortak, denetlenebilir bir cevap üretmeye çalışır.
</div>

## 1.2 Veri egemenliği

Veri egemenliği, bir kullanıcının veya topluluğun verisinin nerede tutulduğu,
kim tarafından erişildiği, hangi şartlarda taşındığı ve ne zaman silinebildiği
üzerinde anlamlı söz sahibi olmasıdır. Bu yalnız şifreleme değildir; erişim,
sahiplik, saklama maliyeti, taşınabilirlik ve silme davranışının da açık
kurallarla tanımlanmasıdır.

Budlum vizyonunda B.U.D. katmanı content addressing, manifest ve storage deal
primitive’leri sağlar. Ancak güncel teknik sınır çok önemlidir: interim
retrieval challenge, tek başına gerçek Proof-of-Storage değildir. VerifyMerkle
64-depth production soundness gate’i kanıtlanmadan “verinin tamamı kriptografik
olarak saklanıyor” iddiası kurulmaz.

<div class="tech">
`ContentId`, `ContentManifest`, shard referansları ve `StorageRegistry` B.U.D.
veri modelinin temelidir. Permissionless deal/challenge davranışı ile access
control/owner provenance ayrı konulardır. Snapshot schema-4, B.U.D.
`storage_registry` alanını digest kapsamına alacak şekilde tasarlanmıştır.
</div>

<div class="plain">
Bir kütüphanenin kitabın kapağını ve raf numarasını bilmesi, kitabın her
sayfasının rafta olduğunun kanıtı değildir. Budlum bu farkı açıkça korur:
veriyi bulma ve saklama anlaşması vardır; tam saklama kanıtı ise ayrı, daha
zor bir güvenlik kapısıdır.
</div>

## 1.3 Toplumsal yeşerme

Toplumsal yeşerme, teknolojinin yalnız işlem hacmi veya spekülasyon için değil;
üreticinin, topluluğun, yerel inisiyatifin ve dijital emeğin sürdürülebilir
biçimde güçlenmesi için kullanılmasını ifade eder. Budlum Constitution; içerik
sahipliği, NFT ile taşınabilirlik, B.U.D. sağlayıcı ödülleri, BNS isimleri,
community governance ve insan merkezli dijital alan hedeflerini bu çerçevede
tanımlar.

Bu hedeflerin bazıları kodda primitive veya iskelet olarak bulunur; bazıları
ayrı tasarım, audit ve mainnet kararları gerektirir. Kitap boyunca her hedefin
yanında uygulama olgunluğu ayrıca belirtilecektir.

## 1.4 Budlum ne değildir?

- Her external chain için tamamlanmış trustless bridge değildir.
- External audit yapılmış bir mainnet ilanı değildir.
- VerifyMerkle gate kapanmadan tam Proof-of-Storage değildir.
- AI model çıktısının doğruluğunu sihirli biçimde ispatlayan bir AI execution
  layer değildir; mevcut AI katmanı attestation/commitment yönelimlidir.
- PoA kurallarını permissionless PoW/PoS/BFT tarafına taşıyan bir whitelist
  sistemi değildir.

Bu sınırlar eksiklik saklamak için değil, güvenli teknik iletişim için vardır.
Bir sistemin nerede güçlü olduğunu anlamanın yolu, nerede henüz iddia
edilmediğini de bilmektir.
