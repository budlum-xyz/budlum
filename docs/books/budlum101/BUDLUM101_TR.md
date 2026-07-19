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

# Bölüm 2 — Blockchain’in temel kavramları

## 2.1 Blok, işlem ve durum

Bir blockchain’i yalnız “işlem listesi” olarak düşünmek eksiktir. Asıl önemli
olan, işlemler uygulandıktan sonra ortaya çıkan **durum**dur. Bir hesabın
bakiyesi, nonce değeri, validator kaydı, BNS adı veya storage deal kaydı bu
durumun parçaları olabilir.

<div class="tech">
Budlum’da `Transaction` mempool’dan blok üretimine, `Executor` üzerinden
`AccountState` değişimine gider. Block/header, state root ve finality kayıtları
zincirin doğrulanabilir geçmişini oluşturur. `AccountState`; hesaplar,
validatorlar, tokenomics, BNS, B.U.D. registry, AI registry, bridge ve diğer
modül state’lerini taşır.
</div>

<div class="plain">
Bir blok defter sayfasıysa, state o sayfa işlendikten sonra kasada, isim
rehberinde ve depoda kalan güncel tablodur. Sadece sayfayı değil, sayfa
okunduktan sonra dünyanın nasıl değiştiğini de doğrulamak gerekir.
</div>

## 2.2 Hash ve Merkle fikri

Hash, verinin kısa parmak izi gibidir. Veri değişirse hash değişmelidir.
Merkle yapıları ise çok sayıda parmak izini tek kökte toplar; böylece bir
kaydı bütün listeyi taşımadan kanıtlamak mümkün olur.

Budlum’da hash yalnız bloklar için kullanılmaz: domain commitment, bridge
proof, content ID, state root, snapshot digest ve imzalanacak transaction
preimage’leri için domain-separated hash kuralları bulunur. Aynı byte dizisinin
iki farklı bağlamda aynı anlama gelmemesi için domain tag kullanımı önemlidir.

## 2.3 İmza neden gerekir?

Hash “veri değişti mi?” sorusuna yardım eder. İmza ise “bu veriyi yetkili kişi
mi onayladı?” sorusunu hedefler. Bir transaction imzası, yalnız gönderici,
ücret ve nonce’u değil; executor’un kullanacağı tüm payload alanlarını da
bağlamalıdır.

<div class="tech">
V29 sonrası V4 signing yaklaşımı `BDLM_TX_V4` domain separator kullanır.
NftBoost amount, AI fee/request/result, relayer result, Hub metadata gibi
variant-specific alanlar explicit canonical encoding ile signing preimage’e
dahil edilmelidir. Eski/non-genesis sürüm kabulü admission yüzeyinde açık
migration kuralına bağlıdır.
</div>

<div class="plain">
Bir imzanın yalnız zarfın üstünü imzalayıp içindeki sipariş miktarını
imzalamaması kabul edilemez. Budlum’da işlem tipi içindeki her anlamlı bilgi
imzanın parçası olmalıdır.
</div>

## 2.4 Nonce ve replay koruması

Nonce, bir hesabın işlemlerini sıralayan sayıdır. Aynı imzalı işlem tekrar
gönderilse bile nonce daha önce kullanıldıysa reddedilir. Bridge tarafında
correlation ID, message ID, transfer status ve replay kayıtları aynı fikrin
domainler arası uzantısıdır.

# Bölüm 3 — Çoklu konsensüs ve finality

## 3.1 Konsensüs ile finality arasındaki fark

Konsensüs, katılımcıların bir sonraki kayıt üzerinde nasıl anlaşacağını
belirler. Finality ise “bu kayıt artık geri alınmayacak kadar kesin mi?”
sorusudur. Farklı domainler farklı konsensüs kullanabilir; Budlum bunların
finality kanıtlarını ortak settlement diline çevirmeyi hedefler.

## 3.2 Permissionless alanlar ve izole PoA

PoW, PoS ve BFT alanlarında katılımın stake/ekonomik güvenlik ile
permissionless olması hedeflenir. PoA ise kurumsal/KYC gerektiren ayrı bir
alandır. PoA üyelik registry’si permissionless registry ile ortak veri yapısı
veya yetki paylaşmamalıdır.

## 3.3 QC ve finality sertifikaları

Quorum certificate, yeterli sayıda yetkili/validator imzasının belirli bir
checkpoint’i onayladığını gösterir. QC doğrulaması imza, benzersiz signer,
quorum ve checkpoint bağlamını beraber kontrol etmelidir. Sadece signer sayısı
beyanına güvenmek finality değildir.

# Bölüm 4 — Ağ, node ve RPC

Budlum node; P2P iletişimi, mempool, chain actor, executor, storage ve RPC
katmanlarını birlikte çalıştırır. RPC kolaylık katmanı değildir; public ve
operator yüzeyi, rate limit, trusted proxy, authentication ve error davranışı
mainnet güvenlik sınırının parçasıdır.

<div class="plain">
Bir node yalnız bilgisayar programı değildir; mahalleye gelen mektupları alan,
kontrol eden, sıraya koyan, kayıt defterine işleyen ve gerektiğinde cevap veren
bir işletim noktasıdır.
</div>

# Bölüm 5 — Snapshot, restore ve dayanıklılık

Snapshot, node’un bütün geçmişi tekrar yürütmeden belirli bir durumdan
başlamasını sağlar. Ancak snapshot yalnız hızlı olması için değil, bozulmuş veya
sahte veriyi reddetmesi için güvenli olmalıdır.

Schema-4 yönü; canonical digest, kapsamlı state alanları, manifest signature,
trust policy, legacy import ve quarantine/fail-loud davranışını birleştirir.
İçerik alanı hashlenmeyen snapshot, imzalı olsa bile eksik güvence verir.

# Bölüm 6 — Bridge ve evrensel relayer

Bridge lifecycle lock → mint → burn → unlock sırasını izler. Her geçişin
kanıt, domain, correlation ve replay koşulu vardır. EVM tarafında header
bağlantısı, confirmation, receiptsRoot, MPT proof, RLP receipt, emitter/topic
ve payload kontrolleri tek bir doğrulama zinciridir.

Bu zincirin hangi finality modelini kullandığı açıkça belirtilmelidir. Bounded
confirmation ile sync-committee light-client aynı güvenlik iddiası değildir.

# Bölüm 7 — B.U.D. ve BNS

B.U.D. içerik adresleme, manifest, shard ve storage deal primitives sağlar.
BNS ise insan okunur `.bud` adlarını address/content çözümüne bağlar. Bunlar
mantıksal olarak ayrı modüllerdir ve Phase 10 migrationı ile bağımsız crate
sınırlarına taşınmaktadır.

# Bölüm 8 — BudZero, AI ve topluluk katmanları

BudZero; ISA, VM, compiler, state ve proof workspace’ini içerir. AI inference
katmanı bugün model kaydı, request, verifier attestation, outcome ve economic
primitive’ler sağlar; genel AI doğruluğu iddiası değildir. SocialFi, Hub ve
Pollen katmanları ayrı olgunluk seviyelerine sahiptir.

# Bölüm 9 — Mainnet yolculuğu

Mainnet bir derleme hedefi değildir. Signing integrity, snapshot kapsamı,
durability, HSM, audit, fuzz campaign, ceremony, bootnode ve genesis freeze
aynı güvenlik zincirinin halkalarıdır. Bir halka kanıtsızsa bütün zincir
mainnet-ready sayılmaz.

# Bölüm 10 — Ekonomi, isimler ve topluluk altyapısı

## 10.1 $BUD ve teşvikler

Bir ağın güvenliği yalnız kriptografiyle değil, katılımcıların ekonomik
teşvikleriyle de ilgilidir. Fee, stake, slash, storage reward, treasury/burn
ve vesting gibi mekanizmalar ağın hangi davranışları ödüllendirdiğini belirler.

Budlum’da tokenomics parametreleri state/snapshot kapsamının parçasıdır.
Bu nedenle ekonomik parametre değişikliği yalnız bir UI ayarı değildir; governance,
state root, migration ve test kabul kriterleriyle birlikte değerlendirilmelidir.

<div class="tech">
SocialFi boost dağıtım modelinde B.U.D. sağlayıcı, üretici ve protocol
payları ayrı hesaplanır. Overflow, treasury/burn seçimi ve pending reward
state’i executor atomikliği içinde değerlendirilmelidir.
</div>

<div class="plain">
Ekonomi, ağın “teşekkür ederim” ve “bunu yapma” dilidir. Kimin emek verdiği,
kimin depolama sağladığı ve ortak kasanın nasıl korunduğu açık değilse, teknik
olarak çalışan bir ağ bile toplumsal olarak sürdürülebilir olmayabilir.
</div>

## 10.2 BNS ve dijital yön bulma

BNS, insanın hatırlayabileceği `.bud` adlarını adres ve içerik çözümüne
bağlar. Kayıt, expiration, renewal, transfer, subdomain ve full resolve
kuralları isim sisteminin teknik temelidir.

BNS’nin bağımsız crate’e taşınması, isim hizmetinin B.U.D. storage’dan farklı
sahiplik ve test yüzeyi olduğunu açıklar. B.U.D. veriyi adresler ve deal
oluşturur; BNS adı çözer. İki katman birlikte kullanılabilir ama aynı modül
olmak zorunda değildir.

## 10.3 Governance

Governance; fee, reward, parametre ve slashing gibi kararların kim tarafından,
hangi quorum ve hangi yürürlük süresiyle değiştirilebileceğini tanımlar.
Governance dokümanı ile gerçek executor/state kodu birbirini doğrulamalıdır.
Kanıtsız SlashValidator kararı veya sınırsız emergency override, governance
olmak yerine keyfi yönetim riski yaratır.

# Bölüm 11 — AI, BudZero ve doğrulanabilir hesaplama

## 11.1 AI attestation katmanı

Budlum AI primitive’leri model kaydı, inference request, verifier result,
commitment, deadline, equivocation ve outcome mekanizmaları sağlar. Bu katman,
modelin dünyaya dair her çıktısının matematiksel doğruluğunu tek başına ispat
etmez.

<div class="tech">
AI request/result alanları transaction V4 signing payloadına dahil edilmelidir.
AI registry state root’u snapshot/digest kapsamıyla birlikte değerlendirilir.
Fee reclaim, verifier auth ve nonce kuralları liveness/ekonomi yüzeyinin
parçasıdır.
</div>

<div class="plain">
Birden çok uzman aynı sonucu imzalarsa, ağ onların aynı sonuca ulaştığını
kaydedebilir. Bu, sonucun gerçek dünyada mutlak doğru olduğunu otomatik olarak
kanıtlamaz; kimin neyi onayladığını şeffaflaştırır.
</div>

## 11.2 BudZero ve ZK sınırı

BudZero in-tree workspace; ISA, VM, compiler, proof ve node bileşenlerini
taşır. ZK proof, bir hesaplamanın belirli kurallara göre yürütüldüğünü kanıtlama
aracıdır; her feature’ın otomatik production proof’u olduğu anlamına gelmez.

VerifyMerkle 64-depth soundness gate’i, B.U.D. gerçek Proof-of-Storage
iddiasının bağımlılığıdır. Gate kapanmadan public belgeler interim retrieval
ile production proof arasındaki farkı korumalıdır.

# Bölüm 12 — Güvenlik, test ve mainnet yolculuğu

## 12.1 CI tek hakemdir

Lokal test faydalıdır; fakat farklı toolchain, Docker, workspace, feature ve
operasyon koşulları yüzünden tek başına kabul kanıtı değildir. CI build, format,
test, coverage, fuzz, dependency, secret scan, PoA isolation ve smoke kapılarını
bir arada değerlendirir.

## 12.2 Fuzzing ve adversarial testler

Fuzzing rastgele veya yönlendirilmiş girdilerle panic, memory safety ve parser
zayıflıklarını arar. RLP/MPT, transaction deserialize, snapshot parse ve ZKVM
hedefleri farklı saldırı yüzeyleridir. Kısa CI fuzz job’ı smoke kanıtıdır;
uzun nightly campaign ise ayrı güvenlik kanıtı sağlar.

## 12.3 Ceremony ve launch

Mainnet launch; kodun deploy edilmesinden fazlasıdır: gerçek validator public
key’leri, bootnode doğrulaması, HSM işletimi, genesis hash freeze, signed
minutes, backup/restore, audit/bounty ve operator rehearsal birlikte gerekir.

<div class="warning">
Mainnet iddiası, en zayıf launch gate kadar güçlüdür. Bir kritik kapı kanıtsızsa
lansman ertelenmelidir.
</div>

# Ek A — Okuma ve kanıt yöntemi

Bu kitabın public bölümleri kaynak kodu, test, CI, operasyon dokümanı ve teknik
kararları ayırır. Internal ek; commit/CI matrisi, migration ayrıntıları ve açık
borçları taşır. Kaynak manifesti `research/SOURCE_MANIFEST.md` dosyasında
yaşar; her yeni bölüm bu manifestteki ilgili kaynaklarla çapraz doğrulanır.

# Ek B — Terimler

| Terim | Kısa anlam |
|---|---|
| Admission | Bir transactionın RPC/P2P/mempool yüzeyinde kabul edilme süreci |
| Finality | Bir kayıt için geri dönüş olasılığının kabul edilen güvenlik eşiğinin altına inmesi |
| Domain | Kendi konsensüs/finality kuralları olan izole alan |
| State root | Belirli state görünümünü bağlayan kriptografik kök |
| Snapshot | State’in belirli yükseklikte serileştirilmiş/restorable görünümü |
| Replay | Aynı mesaj veya işlemin tekrar yürütülmesi saldırısı |
| Canonical encoding | Aynı anlamın tek byte temsili olması kuralı |
| Fail-stop | Kritik güvenlik/kalıcılık hatasında başarıyla devam etmek yerine işlemi durdurma |
| Permissionless | Katılımın whitelist yerine açık kurallar/stake ile sağlanması |
| PoA isolation | Kurumsal izin kurallarının permissionless domainlere sızmaması |
| Interim retrieval | Erişilebilirlik sinyali veren ama tam storage kanıtı olmayan challenge |

# Ek C — Mimari atlasla birlikte okuma

Bu kitapta anlatılan her büyük katman için görsel referans
[`docs/ARCHITECTURE.md`](../../ARCHITECTURE.md) içindeki Mimari Atlas’tır.
Atlas; trust boundary, V4 signing, snapshot, durability, EVM bridge, B.U.D.,
BNS, AI, BudZero ve launch gate diyagramlarını taşır.

# Bölüm 13 — Bir teknik iddiayı nasıl okuruz?

Budlum gibi uzun ömürlü bir altyapıda belge, test, kod ve CI aynı ağırlıkta
değildir. Bir roadmap “planlandı” diyebilir; bir README “uygulandı” diyebilir;
bir test belirli davranışı doğrulayabilir; CI ise belirli committe o testin
çalıştığını kanıtlayabilir. Bunların hiçbiri tek başına bütün production
iddiasını taşımaz.

## 13.1 Dört kanıt sınıfı

| Sınıf | Soru | Örnek |
|---|---|---|
| Tasarım | Ne hedefleniyor? | RFC, Constitution, Phase planı |
| Kod | Ne uygulanmış? | Public type, executor davranışı, module API |
| Test | Ne kontrol ediliyor? | Negatif mutation, lifecycle, invariant testi |
| Operasyon | Gerçekte nasıl çalıştırılacak? | CI run, HSM runbook, ceremony minutes, audit raporu |

<div class="plain">
Bir binanın çizimi, binanın yapıldığı anlamına gelmez. Yapılmış duvar,
dayanıklılık testinden geçtiği anlamına gelmez. Testten geçen duvar da binanın
gerçek depremde ayakta kaldığını tek başına göstermez. Budlum’un güvenlik
iddiaları bu katmanların birbirini tamamlamasıyla okunmalıdır.
</div>

## 13.2 Vacuous gate tehlikesi

Bir CI job adı “BNS Tests” olabilir ama test listesi boşsa veya bir test
silindiğinde job yine yeşil kalıyorsa, gate güvence üretmez. Bu nedenle B.U.D.
ve BNS test kapılarında expected test isimleri ile self-test kanaryaları
bulunur. Kanarya, eksik veya FAILED satırın kapıyı gerçekten kırdığını
kanıtlamalıdır.

## 13.3 Mainnet iddiası için kanıt zinciri

Bir mainnet iddiası en az şu zinciri gerektirir:

1. Kod ve deterministic encoding,
2. adversarial ve lifecycle testleri,
3. CI build/lint/test kanıtı,
4. dependency/supply-chain kontrolü,
5. uzun fuzz veya güvenlik campaign kanıtı,
6. gerçek operasyon/HSM/ceremony doğrulaması,
7. bağımsız audit veya public disclosure süreci.

Bu zincirdeki açık halka “başarısızlık” değil, açıkça yönetilmesi gereken bir
risk ve plan kalemidir.

# Bölüm 14 — Budlum101 ile çalışma rehberi

Bu kitabı okumak isteyen geliştirici önce mimari atlası, sonra kendi ilgilendiği
modülün README/test/CI gate’ini okumalıdır. Validator adayı HSM/cere-mony ve
finality bölümlerine; dApp geliştiricisi transaction/RPC/BNS bölümlerine; storage
operatörü B.U.D. deal/challenge sınırlarına; güvenlik araştırmacısı V4 signing,
snapshot, bridge ve fuzz bölümlerine odaklanmalıdır.

Her teknik değişiklikte şu soru sorulmalıdır: Bu değişiklik hangi state’i
etkiliyor, hangi hash/signature bunu bağlıyor, hangi test mutation’ı reddediyor,
hangi CI job bunu çalıştırıyor ve failure halinde node ne yapıyor?
