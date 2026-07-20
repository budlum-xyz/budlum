# Budlum — Phase10
## AI Inference Layer + B.U.D. Veri Marketplace + Mevcut Kod Durumu Eksiklik Analizi

**Repo:** github.com/budlum-xyz/budlum
**Bu doküman 4 bölümden oluşuyor:** (1) AI inference katmanı talimatı,
(2) B.U.D. marketplace/izin talimatı, (3) bu ikisinin mevcut kod durumuna
göre gerçek eksiklik analizi, (4) modül ayrımı kuralı — Budlum Core,
BudZero, B.U.D. ve BNS'in ayrı README + ayrı test suite ile yazılması ve
ana README'nin sadece toplam dashboard olması. **Bölüm 3, Bölüm 1-2'deki
bazı varsayımları güncelliyor — Arena'ya vermeden önce Bölüm 3'ü mutlaka
okuyun.**

---

# BÖLÜM 1 — AI Inference/Compute Katmanı Talimatı

**Kapsam:** On-chain AI inference — akıllı kontratlar AI model çağırabilsin.
Mevcut mimariye ek, izole modül; repositioning değil.

### 1.0 Mühendislik gerçeği

Büyük modelleri (LLM) zincirde gerçekten prove etmek (zkML) 2026'da
pratikte imkansıza yakın — proving maliyeti, determinizm sorunu (aynı
model farklı donanımda farklı çıktı verebilir, konsensüs için ölümcül).
"On-chain AI inference" pazarlanan projelerin (Ritual, ORA, Modulus Labs)
çoğu aslında **off-chain hesaplama + on-chain attestation/oracle**.
Bu yüzden: **Faz 1 = attestation tabanlı AI Verifier ağı** (stake +
slashing). **Faz 2 (ileride) = kısıtlı model sınıfları için BudZKVM
STARK-provable inference.**

### 1.1 Yeni tipler

```rust
RoleId::AiVerifier

struct AiModelRegistryEntry {
    model_id: [u8; 32],
    model_hash: [u8; 32],
    min_verifier_count: u32,
    agreement_threshold: u32,
    max_input_size: u64,
    max_output_size: u64,
}

struct AiInferenceRequest {
    request_id: [u8; 32],
    model_id: [u8; 32],
    input_hash: [u8; 32],
    input_ref: Vec<u8>,       // off-chain pointer, B.U.D. asset olabilir
    max_fee: u64,
    callback_contract: Address,
    submitted_at_block: u64,
}

struct AiInferenceResult {
    request_id: [u8; 32],
    verifier_id: RoleId,
    output_hash: [u8; 32],
    output_ref: Vec<u8>,
    signature: Signature,
    submitted_at_block: u64,
}

struct AiInferenceOutcome {
    request_id: [u8; 32],
    output_hash: [u8; 32],
    output_ref: Vec<u8>,
    agreeing_verifiers: Vec<RoleId>,
    finalized_at_block: u64,
}
```

### 1.2 Akış

1. Kontrat `bud_ai_request` host-call ile `AiInferenceRequest` yayınlar.
2. Kayıtlı `AiVerifier` node'ları off-chain modeli çalıştırır, sonuç
   submit eder.
3. `agreement_threshold` sayıda verifier aynı `output_hash`'i bildirince
   `AiInferenceOutcome` finalize edilir.
4. Kontrat sonucu **asenkron** okur (sonraki blokta callback).
5. Eşleşme yoksa → dispute + slashing.

### 1.3 Güvenlik invariantları / testler

- Replay koruması, sybil direnci (min stake), slashing, fee/spam koruması.
- İzolasyon: AI Verifier ağı PoA/permissionless akışlarına dokunmaz.
- Test seti: happy path (k-of-n), disagreement/dispute, replay reddi,
  yetersiz stake reddi.

### 1.4 Bu turda YAPILMAYACAKLAR

`ConsensusKind::Ai` domain'i yok, gerçek zkML yok, model zincire yazılmaz
(sadece hash + off-chain pointer).

---

# BÖLÜM 2 — B.U.D. Veri Marketplace: Provenance + İzin Kontrollü Erişim Talimatı

### 2.0 İki farklı hedef, iki farklı çözüm

1. **"Bu veri gerçekten B.U.D.'dan geldi"** → provenance/imza sorunu,
   kriptografik olarak tam çözülebilir.
2. **"İzinsiz AI erişemez"** → erişim kontrolü sorunu. **Sadece on-chain
   bir "izin var/yok" flag'i bunu teknik olarak garanti ETMEZ** — storage
   node ham veriyi izinsiz de sunabiliyorsa flag sadece ekonomik
   caydırıcıdır (stake/slashing), teknik engel değildir. Gerçek garanti
   ancak şifreleme + key-wrapping ile gelir.

*(Bölüm 3'te göreceğiniz gibi, Budlum'un "veri egemenliği kuralı" bu
ayrımı daha da keskinleştiriyor — soft enforcement burada yeterli değil.)*

### 2.1 Yeni primitifler

```rust
RoleId::BudStorageNode

struct DataAsset {
    asset_id: [u8; 32],
    owner: Address,
    content_hash: [u8; 32],
    encrypted: bool,
    listed: bool,
    created_at_block: u64,
}

struct StorageCommitment {   // provenance kanıtı
    asset_id: [u8; 32],
    content_hash: [u8; 32],
    storage_node_id: RoleId,
    block_height: u64,
    signature: Signature,
}

struct AccessGrant {
    asset_id: [u8; 32],
    owner_signature: Signature,
    grantee: RoleId,
    scope: GrantScope,        // ReadOnce | ReadUntilBlock(u64) | Perpetual
    wrapped_key: Option<Vec<u8>>, // Faz 2'de dolu
    granted_at_block: u64,
}

struct AccessRevocation {
    asset_id: [u8; 32],
    grantee: RoleId,
    revoked_at_block: u64,
}

struct MarketplaceListing {
    asset_id: [u8; 32],
    price: u64,   // $BUD
    auto_grant_on_payment: bool,
}
```

### 2.2 Akış

1. Owner içeriği B.U.D.'a yükler → `StorageCommitment` imzalanır →
   `DataAsset` zincire kayıt olur (provenance burada kapanıyor).
2. Owner isterse `MarketplaceListing` ile listeler.
3. AI consumer erişim talep eder / öder.
4. Owner `AccessGrant` imzalar.
5. **Faz 1:** storage node grant kontrolü yapar (soft enforcement).
6. **Faz 2:** içerik şifreli, sadece `wrapped_key` sahibi çözebilir (hard
   enforcement).

**AI Inference Layer entegrasyonu (zorunlu):** `AiInferenceRequest.input_ref`
bir B.U.D. `DataAsset`'ine işaret ediyorsa, `AiVerifier` hesaplamadan önce
geçerli `AccessGrant` kontrolü yapmak ZORUNDA.

### 2.3 Dürüst not

`AccessRevocation`, grantee'nin önceden indirdiği kopyayı geri alamaz —
bu hiçbir DRM benzeri sistemde mümkün değil.

### 2.4 Bu turda YAPILMAYACAKLAR

B.U.D.'un depolama/replikasyon mekanizmasının kendisi (ayrı iş), şifreleme
(Faz 2), marketplace ekonomi modeli detayları.

---

# BÖLÜM 3 — Mevcut Kod Durumu: B.U.D. Eksiklik Analizi (github.com/budlum-xyz/budlum)

### 3.0 Yöntem ve kaynak sınırlaması (dürüstlük notu)

Bu bölüm `README.md` ve `SPECIFICATION.md`'nin okunabilen kısımlarına
dayanıyor. GitHub'ın dosya ağacı gezinme sayfaları (`/tree/...`) bu ortamda
robots.txt tarafından engellendiği için `src/rpc/api.rs`,
`ContentManifest`/`StorageRegistry` struct tanımları gibi asıl kaynak
dosyalarına doğrudan erişemedim. **Standing rule aynen burada da geçerli:
bu raporu da kod diff'i olmadan %100 doğru kabul etmeyin — Arena'ya ilk iş
olarak bu dosyaların gerçek içeriğini gösterin ve doğrulatın.**

### 3.1 Mevcut durum (var olan)

- **Tur 14 Faz 1-2 + Faz 5 iskeleti** kod tabanında:
  `ConsensusKind::StorageAttestation`, `STORAGE_OPERATOR = RoleId(5)`
  (permissionless), `ContentId` / `ContentManifest` / `StorageRegistry`
  (deal + challenge ekonomisi), 7 JSON-RPC uç noktası, 3-aktör E2E test +
  9 ekip-bağımsızlık invariantı (`src/tests/bud_e2e.rs`).
- 7 RPC: `bud_storageRegisterManifest`, `bud_storageGetManifest`,
  `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`,
  `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`,
  `bud_storageGetOutcome`.
- Devnet-only; mainnet'e dahil edilip edilmeyeceği Tur 15 §1.2 sonrasına
  bırakılmış.

### 3.2 Kritik eksiklikler (Bölüm 1-2'ye göre)

1. **İzin/consent katmanı tamamen yok.** Mevcut 7 RPC'nin hepsi — manifest
   okuma, deal okuma dahil — herkese açık. `AccessGrant` kavramı hiç yok.
   Yani "içerik sahibinden izinsiz erişemez" hedefi şu an **hiç**
   karşılanmıyor: metadata ve deal bilgisi zaten tamamen açık.
2. **Şifreleme/key-wrapping yok** (beklenen — Faz 2 hiç başlamamış).
3. **`RetrievalChallenge` gerçek Proof-of-Storage değil.** Ekibin kendi
   notu (Tur 14.5 plan §2.5): operatör sadece istenen byte-range'i
   saklayarak testi geçebilir. Tam kanıt, BudZKVM `VerifyMerkle`
   64-derinlik production gate'ine bağlı (henüz kapanmadı). Bu, Bölüm
   2'deki "StorageCommitment = sağlam provenance" varsayımını zayıflatıyor:
   şu an "bu veri B.U.D.'da **tam ve doğru** saklanıyor" garantisi yok,
   sadece "bir parçası saklanıyor" garantisi var. Ekip bunu "sahte-yeşil
   yol riski" diye açıkça işaretlemiş (vision §9.1) — gizlemiyorlar, bu
   olumlu.
4. **AI Inference Layer / `RoleId::AiVerifier` tamamen yok.** Roadmap
   tablosunda açıkça "AI execution layer: ❌ Araştırma" yazıyor. Bölüm
   1'in tamamı sıfırdan yazılacak.
5. **Marketplace yönü ters.** Mevcut `StorageRegistry` bir **sağlayıcı**
   ekonomisi (operatörler saklamak için para alıyor). Bölüm 2'nin önerdiği
   **tüketici** (AI erişim için ödeme yapıyor) modeli yok — ikisi otomatik
   birbirini karşılamıyor, ayrı inşa edilmeli.
6. **`ContentManifest`'te "owner" alanı var mı belirsiz** — kaynak
   sınırlaması nedeniyle doğrulayamadım. Arena'nın ilk işi bu olmalı.

### 3.3 Mimari kısıt keşfi — Faz 1/2 ayrımını etkiliyor

**"Veri egemenliği kuralı" (Tur 14.5 plan §0.5):** Hiçbir B.U.D.
fonksiyonu Budlum ekibinin çalıştırdığı bir servise bağımlı olamaz;
whitelist/admin/pause/freeze hook'u yasak; 7 RPC herhangi bir node
tarafından sunulabiliyor.

**Sonuç:** Bölüm 2'deki "Faz 1 = soft enforcement" planı bu kural altında
zayıf kalıyor — merkezi bir izin-kontrol servisi olamayacağına göre, "stake'li
node izin kontrolü yapar" modeli her node'un kuralı gönüllü uygulamasına
dayanır, gerçek garanti değildir. **Bu proje için şifreleme tabanlı hard
enforcement (Bölüm 2 Faz 2) "daha iyi" değil, mimari kısıt gereği
gerçek bir izin garantisi isteniyorsa zorunlu.**

### 3.4 Öncelik sıralı sonraki adımlar

1. Arena'ya `src/rpc/api.rs` + `ContentManifest`/`StorageRegistry` struct
   tanımlarını gösterip `owner` alanını doğrulat.
2. `AccessGrant`'i Faz 1'den itibaren şifreleme temelli tasarla — soft
   enforcement adımını atla (egemenlik kuralı zaten dayatıyor).
3. `RoleId::AiVerifier` + AI Inference Layer'ı sıfırdan ekle (Bölüm 1).
4. "`RetrievalChallenge` gerçek Proof-of-Storage değil" uyarısını AI/
   marketplace dokümantasyonuna da taşı — AI'nin kullandığı B.U.D.
   verisinin bütünlüğü henüz tam kanıtlanmış değil.
5. Marketplace ekonomi modelini `StorageRegistry`'nin üzerine değil, ayrı
   bir "tüketici erişim ödemesi" katmanı olarak kur.

---

# BÖLÜM 4 — Modül Ayrımı: Ayrı README, Ayrı Test, Ana README = Toplam Dashboard

### 4.0 Neden gerekli

Her modülün olgunluk/risk profili farklı:

- **Budlum Core** — canlıya en yakın, 452 lib testi, kendi CI gate'i var.
- **BudZero (BudZKVM)** — kendi workspace, Z-B 64-derinlik gate hâlâ
  Production'da kapalı (Bölüm 3.2 madde 3).
- **B.U.D.** — devnet-only, kendi dokümanlarında `RetrievalChallenge`
  için "sahte-yeşil yol riski" açıkça itiraf edilmiş (Bölüm 3.2 madde 3).
- **BNS (`.bud` domain servisi)** — henüz mimarisi yok, sıfırdan
  başlıyor.

Tek README + tek toplam test sayısı bunları gizler: B.U.D.'daki
riskli/eksik bir test, Core'un yüzlerce sağlam testinin arkasında
kaybolur. CI'ı tek gerçek denetleyici sayma kuralı, modül bazında
uygulanmalı — toplamda değil, çünkü toplam sayı tek başına hangi
modülün hangi uyarıyla işaretli olduğunu söylemez.

### 4.1 Kural

- Her modül kendi dizininde, kendi `README.md`'si ve kendi test
  suite'iyle yaşar: `README.md` (Core, kök), `budzero/README.md`,
  `bud/README.md` (veya B.U.D.'un gerçek dizini), `bns/README.md`.
- Her modülün kendi CI job'u/gate'i olur (mevcut Core + BudZero
  ayrımı zaten bu deseni takip ediyor — B.U.D. ve BNS de aynısını
  izlemeli).
- Her modülün README'sinde kendi test sayısı VE kendi olgunluk uyarısı
  (örn. "devnet-only", "Production-gated", "sahte-yeşil riski var")
  açıkça yazar — üst düzey README'ye taşınmadan kaybolmaz.

### 4.2 Kök README'nin rolü

Kendi testi olmamaz — sadece her modülün kendi README'sinde raporladığı
sayıyı toplayan bir **index/dashboard** olur:

| Modül       | Test                          | Durum                                    |
| ----------- | ------------------------------ | ----------------------------------------- |
| Budlum Core | 452 (`cargo test --lib`)       | v0.3-dev devnet candidate                 |
| BudZero     | (kendi workspace testi)        | Z-B 64-derinlik Production-gated          |
| B.U.D.      | (kendi e2e testi)              | Devnet-only; sahte-yeşil riski işaretli   |
| BNS         | (kendi test suite'i)           | Henüz mimari yok — Faz başlamadı          |
| **TOPLAM**  | sum                            |                                            |

Kural: **toplam satırı, hiçbir zaman altındaki uyarı satırlarının
yerini almaz.** Toplam sadece "kaç test var" sorusuna cevap verir,
"hangisine güvenilir" sorusuna değil — o cevap her zaman modül
satırında kalır.

### 4.3 BNS (`.bud` domain servisi) — ayrı modül olarak

BNS, B.U.D.'dan da mantıksal olarak ayrı: B.U.D. içerik/veri depoluyor,
BNS insan-okunur `.bud` adını adrese/içeriğe çözümlüyor (ENS benzeri
bağımsız katman). Aynı kurala tabi:

- Kendi crate'i: `bns/` (veya `src/bns/`), Core'a veya B.U.D.'a
  gömülmez.
- Kendi README'si, kendi test suite'i, kendi CI gate'i.
- Kök README'de 4. satır olarak eklenir (yukarıdaki tablo).
- Mimarisi henüz tanımlanmadı — `.bud` adı kaydı, sahiplik/devir,
  çakışma/squatting koruması, B.U.D. ve AI layer ile ilişkisi ayrı bir
  talimat gerektirir (bu doküman kapsamı dışında, istenirse ayrı bölüm
  olarak eklenebilir).

### 4.4 Bu turda YAPILMAYACAKLAR

BNS'in kendi veri modeli/RPC tasarımı bu bölümün kapsamında değil —
sadece "ayrı modül olarak yaşamalı" kuralı burada net konuyor. BNS
mimarisi ayrı bir talimat turu.

---

## CI ve standart kural hatırlatması (Phase10'un tamamı için geçerli)

`fmt + clippy -D warnings + test` tek gerçek denetleyici — **modül
bazında**, tek bir toplam sayı üzerinden değil (Bölüm 4). Yeni
`#[allow(...)]` yok, test `#[ignore]` ile gizleme yok, clippy uyarısı
susturulmak yerine kod düzeltilerek geçilecek — Bölüm 1, 2, 3 ve 4'ten
çıkan her iş için aynen geçerli.
