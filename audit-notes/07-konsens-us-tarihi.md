# Konsensüs tarihinin Budlum haritası

Bu dosya tarihteki konsensüs kırılımlarını Budlum'un_adapter yüzeyine bağlar.
Amaç: hangi ailelerin gerçekten kodlandığını, hangi ailelerin eksik
olduğunu ve "nihai sistem" iddiasının hangi kısımlarının kanıtlanabilir
olduğunu yazılı hale getirmek.

## 1. Aileler ve Budlum karşılıkları

### 1.1 Chaum, Hashcash, b-money (1982-1998)

Ortak özellik: tek başına bir "kanıt" üretmek, bir defter üretmezler.
Chaum'ın blind signature'ı gizlilik, Hashcash'in proof-of-work'ü iş kanıtı,
b-money'nin teklifi ise dağıtık defter fikridir. Üçü de nihai sistemin
parçalarıdır ama hiçbiri konsensüs protokolü değildir.

Budlum karşılığı: bu aileler için adapter yok ve olmamalı da. Bir adapter
"bizim defterimize bir yapışkanlık kanıtı" ister; bu üçü defter üretmez.
Budlum'un kendi iş kanıtı `src/consensus/pow.rs` içindedir ve harici bir
domain olarak sunulmaz. Hashcash böylesine zayıf bir modele bir adapter
yerleştirmek, guveni yalan olarak yazmak olur.

### 1.2 Nakamoto (Bitcoin, 2008)

Ortak özellik: proof-of-work + en-uzun-zincir kuralı + probabilistik
finality. Finality bir kesinlik değil, bir ekonomik olasılıktır.

Budlum karşılığı: `src/cross_domain/external/bitcoin_spv.rs`,
`consensus_kind = "nakamoto-pow"`, `finality_kind = Probabilistic`,
`trust_model = Trustless`. Adaptor header zincirini doğrular, `REQUIRED_DEPTH`
derinlik talep eder. Kritik sınır: kendi kendine sessize alan bir header
zinciri kanıt değildir. Adaptor bunu `required_depth` ve `MAX_FUTURE_SECONDS`
ile sınırlar, ama "en uzun zincir" kuralı Bizlum'da yoktur; zincirin
konvansiyonel (canonical) olduğu varsayımı pinlenmiş bircheckpoint'ten gelir
(`PinnedBitcoinAnchor`). Bu yüzden adaptor `Trustless` ama
`Probabilistic`'tir. Doğru bir tanım.

### 1.3 Ethereum VM (2015)

İki ayrı kırılımı aynı sistemde: (a) ortak makine, (b) gas ile ölçülen
kaynak modeli. Konsensüs ailesi bu işlem modelini değiştirmez; sadece ne
yürütüleceğini belirler.

Budlum karşılığı: `src/execution/coordinator/evm_ee.rs` (UEL adaptörü) ve
`src/cross_domain/external/evm_hybrid.rs`. UEL EVM'yi izole yürütür ve gas
ölçer. Harici taraf `evm_hybrid.rs`'dir: Budlum'un BLS + ML-DSA kanıtını
bir EVM zincirinde doğrular. Yani Ethereum'a iki yönde adaptör var: onun
konsensüsünü okumak ve onun sanal makinesinde Bizlum kanıtını okumak.

### 1.4 Casper / Gasper (Ethereum finality, 2020)

Ortak özellik: BFT checkpoint oylaması, iki ardışık epoch'un justifiye
etmesi, sonra bir checkpoint'un finalize olması. Finality protocol'dür,
probabilistik değil.

Budlum karşılığı: `src/cross_domain/external/ethereum.rs`,
`consensus_kind = "gasper-pos"`, `finality_kind = ProtocolFinality`,
`required_depth = 2 * SLOTS_PER_EPOCH`, `time_unit = Slot`. Adaptor
Altair sync committee BLS toplu imzasını doğrular ve yalnızca
`finalized` header'ı kabul eder; yalnızca justifiye edilmiş olanı
reddeder. Adaptörün kendi belirttiği sınır: sync committee imzaları
slashable değildir. Bu yüzden `SecurityBacking::SignatureSet` alanı
`slashable: false` taşır. Guven modeli `HonestMajority { set_size: 512 }`.

### 1.5 Tendermint / CometBFT (2016-2019)

Ortak özellik: bir commit, ardışık iki üçte bir + 1 ağırlık, canonical vote
baytları. Finality protocol'dür ve slashable'dır.

Budlum karşılığı: `src/cross_domain/external/tendermint.rs`,
`consensus_kind = "tendermint-bft"`, `finality_kind = ProtocolFinality`,
`quorum_threshold = 2*total/3 + 1`, `address = SHA256(pubkey)[..20]`.
Adaptor CometBFT canonical.proto alan numaralarıyla sign baytlarını yeniden
üretir ve proto3'ün sıfır alanları atmasını bile doğru yapar. İmza
seti slashable'dır. `required_depth = 1`: bir commit, bir BFT zincir için
finality'dir.

### 1.6 HotStuff (2018) ve üç zincirli kural

Ortak özellik: bir proposal, bir PREPARE, bir COMMIT, bir DECIDE. Üç
ardışık işaretten biri yeterli; "three-chain rule". LibraBFT ve Diem bunun
üzerinde kuruldu.

Budlum karşılığı: `src/cross_domain/external/hotstuff.rs`,
`consensus_kind = "hotstuff-chained-bft"`, `required_depth = THREE_CHAIN_DEPTH`.
Üç zincir kuralı adaptorun red sınırıdır: iki ardışık onay bir işareti
finalleştirmez.

### 1.7 DAG aileleri (Bullshark, Narwhal, AlewFT, Hashgraph)

Ortak özellik: bloklar birden çok üstü işaret eder, geçmiş bir ağaç değil
bir yönürlü çevresel grafiktir. Finality bir "vertex üzerinde komite
kanıtı" veya "dalga tamamlama" (wave commit) kuralından gelir.

Budlum karşılığı: `src/cross_domain/external/dag_bft.rs`,
`consensus_kind = "bullshark-round-dag-bft"`, `required_depth = WAVE_COMMIT_DEPTH`.
Ayrıca `src/consensus/dag.rs` içinde yerel bir DAG motoru vardır. Adaptor
bir vertex'in dalga tamamlamasını denetler; grafiğin tamamını gezmez ve
bunu da yakında belirtmez.

### 1.8 PoH (Solana, 2020)

Ortak özellik: bir kriptografik saat. Her işlem bir önceki hash'i taşır, yani
sıra (order) zk benzeri bir kanıtla gömülüdür. PoH bir konsensüs değildir,
bir sıra ve zaman kanıtıdır; konsensüs Tower BFT'tir.

Budlum karşılığı: `src/consensus/poh.rs`. Harici adaptör yok. Sebep: PoH
tek başına bir finality kanıtı değildir; Tower BFT'in "lockout" kanıtı
gerekir. Bir PoH adaptörü yazmak, saati kanıtlamakla sırayı kanıtlamak
arasındaki farkı silmek olur. Bu yüzden bilinçli olarak boş bırakılmıştır ve
bir bulgu olarak izlenir.

### 1.9 PoSpace (Chia, 2021)

Ortak özellik: alan kanıtı. Bir plot dosyası, her turda bir meydan okumaya
cevap verir. Finality proof-of-space + proof-of-time üzerindendir.

Budlum karşılığı: `src/consensus/pospace.rs` ve `src/consensus/pos.rs`.
Bir harici PoSpace adaptörü yok. Sebep: PoSpace'in "finality" bir yarıçel
kuralıdır ve bir vertex'i değil bir çizgiği (slot winner'ı) seçer. Bu
Budlum'un header modeliyle örtüşür ama proof-of-time bir VDF kanıtı
gerektirir; VDF adaptörü de yok. İki eksik bir arada gelir.

### 1.10 Rollup / ZK / DA / restaking (2021-)

Ortak özellik: ana zincir dışında hesaplanan ve ana zincirde kanıtlanan
durum. Konsensüs ailesi bir doğrulama oyunu (validity proof) veya bir
tekrar-yığın (restaking) oylamasıdır.

Budlum karşılığı: `src/cross_domain/external/zkvm_proof.rs`
(`consensus_kind = "zkvm-execution"`, `finality_kind = Proven`,
`trust_model = Trustless`) ve
`src/cross_domain/external/da_sampling.rs`
(`consensus_kind = "modular-das-nmt-2d"`, `finality_kind = EconomicFinality`).
Restaking için harici adaptör yok. Sebep: restaking bir finality ailesi
değil, bir güven paylaşımı modelidir. Adaptor yüzeyi bu farkı
`trust_model` alanında taşır ve yeni bir aile uydurmaz.

## 2. Ortak kanıt modeli

Tüm adaptörler aynı sözleşmeyi uygular: ham delil girer, bir
`FinalityAttestation` çıkar. Attestation şu alanları taşır:

- `height`: hedef sistemde bir yükseklik / epoch / yuvarlak / tur.
- `state_root`: hedef sistemin durum kökü.
- `finalized_at`: hedef sistemin kendi zaman birimi.
- `security`: hangi şema, kaç imzacı, hangi eşik, toplam ağırlık,
  slashable mı.
- `evidence_digest`: ham delilin özeti.

`SecurityBacking::{SignatureSet, Work, Zk, Authority, None}` ve
`TrustModel::{Trustless, HonestMajority, TrustedParty}` iki eksendir ve
birlikte "bu kanıtın fiyatı nedir" sorusunu yanıtlar. Bir okuyucu koda
bakmadan riski okur.

## 3. Kanıtlanabilir olan ve araştırma olan

### Kanıtlanabilir

- Bir adaptörün kendi sign baytlarını yeniden üretmesi ve bir imzayı onun
  üzerinde doğrulaması. Yanlış bayt dizilimi, reddi gösteren bir testle
  kilitlenir (Tendermint ve HotStuff için `canonical_vote_bytes`).
- Bir eşiğin doğru olması: `2*total/3 + 1`. Testle kilitlenir.
- Bir pin olmadan reddedilmesi: `CommitteeNotPinned`. Testle kilitlenir.
- Bir senet (bond) olmadan reddedilmesi: `honesty_is_cheaper`. Testle
  kilitlenir.
- Bir kanıtın ne olduğunun açıkça yazılması: `FinalityKind`,
  `SecurityBacking`, `TrustModel`. Bir attestation "ben güvenilirim" demez;
  elimdeki delili sayar.

### Kanıtlanamaz, araştırmadır

- "Bu çatal, ağın gerçek çatalıdır." Adaptor bir checkpoint veya komite
  pinine güvenir. Pini koyan yargı (genesis, checkpoint, komite kökü) kod
  tarafından kanıtlanamaz; bir operatörün veya bir insanın verisidir.
- "Bu kesinliğin 12 dakika geri alınmayacağı." Bir tek vertex kanıtı
  grafiği gezmez. Işık istemcisi (light client) olmak, grafiğin tamamını
  ya da en azından bir doğruluk penceresini denetlemek demektir. Şu anki
  tek-yükseklik adaptörler bunu iddia etmez, ama tüketici buna ihtiyaç
  duyarsa yeni bir katman gerekir.
- "Restaking güveni ölçülebilir." `trust_model = TrustedParty` bir sayı
  değil bir kabuldür.
- "PoH saati doğrudur." Zaman kanıtı ile sıra kanıtı ayrı şeylerdir; bir
  tanesini doğrulamak diğerini doğrulamaz.
- "Post-quantum hazır." Şu anki tüm BFT adaptörleri (Tendermint, HotStuff,
  Bullshark) yalnızca klasik imza şeması taşır. `is_classical_only_quorum`
  bunu söyler ve ana ağ kapısı uygular. Bir PQ yarığı için yeni bir delil
  formatı gerekir.

## 4. Eksik olarak kalan üç şey

1. **PoSpace + VDF adaptörü.** İki parça birlikte gerekir. Yalnızca
   proof-of-space, bir finality değil bir seçim kuralıdır.
2. **Restaking güven ölçüsü.** Yeni aile değil, yeni bir `trust_model`
   değeri ve bir ekonomik analiz.
3. **Çok-yükseklikli ışık istemcisi.** Tek-yükseklik adaptörler doğru
   ama yeterli değil. Bu, kanıt modelini değil tüketici katmanını
   etkiler.

Üçü de kod yükü olarak küçüktür; büyük olan kısmı, bir pinin ve bir
checkpoint'ın doğru yerden geldiğini ispatlamaktır. Bu dosya o kısmı
kanıtlanamaz diye yazar.
