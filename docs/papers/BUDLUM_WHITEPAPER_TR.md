# BUDLUM
## Whitepaper (Teknik Rapor) — Kuantum-Sonrası, Çok-Konsensüslü Bir Dünya İçin Evrensel Uzlaşım Katmanı

**Sürüm:** 1.0 ( durumu) · **Tarih:** 18 Temmuz 2026 · **Lisans:** MIT
**Depo:** [github.com/budlum-xyz/budlum](https://github.com/budlum-xyz/budlum) · **Durum:** Kontrollü kamu devnet adayı (v0.3-dev) — *araştırma sınıfı; denetlenmiş mainnet yazılımı değildir*

---

## Özet (TR)

Budlum, mevcut blokzincirlerinin **yerini almayan**, onları **uzlaştıran** (settle eden) araştırma sınıfı bir Layer-1 protokolüdür. Her alan (domain) kendi konsensüsünü korur — PoW, PoS, PoA, BFT, ZK veya özel; Budlum bu alanların finalite kanıtlarını doğrular ve alanlar arası değer transferini **kriptografik bir gerçek** olarak kaydeder. TCP/IP ağların iç çalışmasını sormadan paket taşır; Budlum değerin hangi konsensüsle üretildiğini sormadan finaliteyi doğrular.

Temel direkler:

- **Kuantum-sonrası finalite:** BLS + Dilithium5 hibrit imza, protokolün çekirdek yolunda — "şimdi güvenli, kuantum çağında da güvenli."
- **Çok-konsensüslü settlement:** `GlobalBlockHeader` ile tek bir küresel kriptografik gerçeklik noktası; PoW light-client finalitesi, nonce-invariant ile çifte harcama koruması.
- **Güven-minimize köprü yaşam döngüsü:** Lock → Mint → Burn → Unlock, her adımda kanıt kapıları (2,5 milyar dolarlık köprü-hack sorununa doğrudan yanıt).
- **BudZero / BudZKVM:** Ağa gömülü STARK tabanlı sıfır-bilgi sanal makinesi; AI çıkarımı (inference) doğrulama primitifleriyle **Agentic Economy** altyapısı.
- **B.U.D. (Broad Universal Database):** İzinsiz, deal + challenge + slashing ekonomili merkeziyetsiz depolama ağı; veri egemenliği ilkesiyle whitelist/admin/pause kancası **yok**.
- **BNS (`.bud`) + SocialFi:** İçerik = NFT ("Dijital Tomurcuk"). Sahiplik, kontrol ve "kill-switch" tek varlıkta; "Işık Şiddeti" (Luminance) ile organik sıralama; Boost ekonomisi %4 depolama operatörü / %16 içerik üreticisi / %80 protokol hazine-yakım.
- **$BUD token:** Gas, depolama operatörü emisyonu, relayer teşvikleri, boost ve veri pazarı ödemeleri.

Proje, kanıta dayalı mühendislik kültürüyle geliştiriliyor: **755 Core lib testi, 124 BudZero, 12 B.U.D. invariant ve 8 BNS testi — hepsi CI-kanıtlı**; "sahte-yeşil" (kanıtsız iddia) bilinçli olarak işaretlenip dışlanıyor.

> ⚠️ Dürüst durum bildirimi: Budlum **henüz bağımsız dış denetimden geçmedi**; gerçek değer taşıyan üretim trafiği için kullanılmamalıdır.

---

## Özet (EN)

Budlum, **Evrensel Uzlaşım Katmanı** olarak tasarlanmış araştırma sınıfı bir Layer-1 protokolüdür: mevcut zincirlerle rekabet etmek yerine onları *uzlaştırır*. Her Konsensüs Alanı — Proof-of-Work, Proof-of-Stake, Proof-of-Authority, BFT, ZK tabanlı veya henüz icat edilmemiş özel bir mekanizma — kendi konsensüsünü korur. Budlum, alana özgü finalite kanıtlarını takılabilir adaptörler aracılığıyla doğrular ve alanlar arası değer transferini tek bir kriptografik gerçek olarak kaydeder: `GlobalBlockHeader`.

Protokol, **hibrit kuantum-sonrası finaliteyi** (BLS toplu imzaları + ML-DSA/Dilithium5 QC blob'ları) çekirdek konsensüs yoluna işler; böylece bir "kuantum hard-fork günü" gerekmez: güvenlik modeli genesis'ten itibaren kuantuma hazırdır. Ağ içi bir STARK kanıtlayıcı sanal makine (**BudZero/BudZKVM**), deterministik ve doğrulanabilir yürütme sağlar — yaklaşan ajan ekonomisi için **AI çıkarım (inference) tasdiki** primitifleri dahil. İzinsiz bir depolama ağı (**B.U.D.**), bir isim kaydı (**BNS**, `.bud`) ve NFT'ye bağlı bir sosyal katman (**Dijital Tomurcuklar**) ile **$BUD** fayda tokeni tarafından koordine edilen, insan merkezli ve veri egemenliğine sahip bir ekosistem tamamlanır.

Budlum, açık bir *kanıt-önce* disipliniyle mühendisliği yapılmaktadır: bu rapordaki her yetenek iddiası koda, bir CI kapısına izlenebilir — ya da açıkça bekleyen iş olarak işaretlenmiştir.

---

## 1. Problem Tanımı

Bugünün dijital değer altyapısı yedi yapısal başarısızlıktan muzdarip. Her biri doğrudan bir Budlum tasarım kararına karşılık gelir.

| # | Bugünkü sorun | Sonuç | Budlum kayması |
|---|---------------|-------|----------------|
| 1 | **Kuantum kırılması (~Y2Q, 2030–35):** ECDSA/Ed25519 her büyük zincirin temelinde; "Harvest Now, Decrypt Later" (şimdi topla, sonra çöz) zaten yaşanıyor | Tüm finansal defterlerin nihai kriptografik çöküşü | **Çekirdek yolda** BLS + Dilithium5 **hibrit finalite** — acil fork gerekmez |
| 2 | **Sur bahçeleri:** 20.000+ izole zincir; birlikte çalışabilirlik çözümleri (IBC, parachain) hep *kendi* paradigmalarını dayatır | Likidite parçalanması, tekrarlanan güvenlik bütçeleri | **Evrensel Uzlaşım Katmanı** — konsensüsten bağımsız finalite doğrulaması |
| 3 | **CBDC egemen siloları:** 130+ ülke izole dijital para inşa ediyor | Güven-minimize sınır ötesi settlement primitifi yok | Alanlar + güven-minimize köprü yaşam döngüsü; matematik muhabir güveninin yerini alır |
| 4 | **TradFi ↔ DeFi duvarı:** izinli PoA ile kamu PoS asla ortak bir settlement kaydı paylaşmıyor | Tek hata noktası olarak saklamacı (custodial) köprüler ve oracle'lar | Tek bir `GlobalBlockHeader`, PoA ve PoS finalitesini yan yana kaydeder |
| 5 | **Köprü hack'leri (2022–24'te 2,5 milyar $+ çalındı):** Ronin, Wormhole, Nomad… | Sistemik kayıp; köprüler en zayıf halka | Her adımda kanıt kapılı Lock → Mint → Burn → Unlock |
| 6 | **Settlement'sız AI ajanları:** ajan ekonomisinin ödeme rayı yok, doğrulanabilir çıkarım yok | Makine ekonomileri için merkezi ödeme darboğazları | Ağ içi STARK zkVM + yerel AI-çıkarım tasdik olayları |
| 7 | **Veri egemenliği çöküşü:** kullanıcılar dijital varlıklarını platformlardan kiralıyor | Sahipliği yok, taşınabilirliği yok, silme hakkı yok | **B.U.D.** depolama + NFT'ye bağlı içerik: sahiplik, kontrol ve kill-switch |

---

## 2. Tasarım Felsefesi

Dört vazgeçilmez ilke kod tabanını yönetir:

1. **Varsayılan olarak fail-closed (kapalıya başarısızlık).** Kamu RPC kimlik doğrulaması, Merkle doğrulama kapıları, mainnet anahtar depolama — her kapı varsayılanı *reddet*tir. Eksik yapılandırma sessiz bir geri dönüş değil, bir hatadır. (Örnek: disk tabanlı konsensüs anahtarları, HSM yolları var olana kadar *mainnet'te reddedilir*.)
2. **İddiadan önce kanıt ("sahte-yeşil yok").** Test sayıları yalnızca CI özet satırlarından gelir; bilinçli olarak eksik bırakılan özellikler (ör. geçici depolama challenge'ları) düz metinde proof-of-storage *olmadığı* şeklinde etiketlenir. Yol haritası tabloları *uygulanmış*ı, *politika hazır*ı ve *araştırma*yı birbirinden ayırır.
3. **Konsensüs çoğulculuğu.** Hiçbir alan Budlum'un konsensüsüne zorlanmaz; egemenlik alan düzeyinde korunurken settlement bütünlüğü katman düzeyinde dayatılır.
4. **Operatörden değil protokolden egemenlik.** Budlum'a ait kritik hiçbir fonksiyon "Budlum ekibinin çalıştırdığı bir servise" bağımlı olamaz. Depolama katmanında whitelist, admin, pause veya freeze kancası yoktur; her depolama RPC'si herhangi bir node tarafından sunulabilir.

---

## 3. Sistem Mimarisi

```
   PoW alanı      PoS alanı      PoA alanı      ZK / Özel alan
        \              |              |              /
         \             |              |             /
          v            v              v            v
              DomainFinalityAdapter (konsensüse özgü kanıt)
                                |
                                v
              ┌─────────────────────────────────────┐
              │      BUDLUM UZLAŞIM L1'İ            │
              │  GlobalBlockHeader (Merkle toplamı)  │
              │  BridgeState + ReplayNonceStore      │
              │  Küresel hesap durumu + Nonce Kuralı │
              │  BudZKVM kanıtları (BudZero, ağ içi) │
              └─────────────────────────────────────┘
                                |
        ┌───────────────┬───────┴────────┬────────────────┐
        v               v                v                v
   B.U.D. depolama  BNS (.bud)      SocialFi /       AI Çıkarım
   ağı              isim kaydı      Dijital Tomurcuk Doğrulayıcı
```

**Crate yerleşimi (özlem değil, uygulama gerçeği):**

| Yol | Rol |
|------|-----|
| `src/consensus/` | PoW · PoS · PoA motorları |
| `src/domain/` | Alan kaydı, finalite adaptörleri |
| `src/cross_domain/` | Köprü, mesajlar, replay koruması |
| `src/chain/` | Blokzincir, finalite (BLS/QC), snapshot'lar |
| `src/execution/` | İşlem yürütücüsü + BudZKVM host'u |
| `src/core/governance.rs` | Yalnızca validator, stake-ağırlıklı yönetişim |
| `src/rpc/` | JSON-RPC (auth, IP politikası, CORS, rate limit) |
| `src/crypto/` | Ed25519, BLS, Dilithium, PKCS#11 |
| `src/storage/` | **B.U.D.** — manifest'ler, deal'lar, challenge'lar |
| `src/bns/` | **BNS** — `.bud` isim kaydı |
| `budzero/` | BudZKVM: ISA, VM, derleyici, durum, STARK kanıtlayıcı |

---

## 4. Çok-Konsensüslü Uzlaşım Modeli

### 4.1 Konsensüs Alanları

**Konsensüs Alanı**, kendi kurallarına sahip bağımsız herhangi bir zincir veya yürütme ortamıdır. Alanlar birinci sınıf kayıt girdileridir:

- **Kimlik:** benzersiz `DomainId` + minimum stake ile bonddanmış sıfır olmayan operatör adresi. Operatör bond'u olmayan kayıtlar reddedilir.
- **Tür:** `ConsensusKind::PoW | PoS | PoA | BFT | ZK | Custom(String)` — `Custom` varyantı bilinçli bir ileri-uyumluluk kaçış kapağıdır (gelecekteki bir `ConsensusKind::Ai` mimari olarak olasıdır).
- **Yaşam döngüsü:** `Active → Frozen → Retired`. Egemen bir alan izinsiz çıkabilir (bkz. §7, CBDC/dijital-egemenlik kullanım durumu).

### 4.2 DomainCommitment — settlement birimi

Bir alan Budlum'a işlem göndermez; **durum geçişlerini kanıtlar**:

```
DomainCommitment {
    domain_id,                 // güncellemenin kaynağı
    domain_height,             // taahhüt edilen blok yüksekliği
    state_root,                // ortaya çıkan alan durumu
    state_updates,             // hesap nonce/bakiye değişimleri
    finality_proof_hash,       // konsensüse özgü kanıt referansı
    parent_domain_block_hash,  // önceki taahhüde zincir bağlantısı
    validator_set_hash         // taahhüdü kayıtlı kümeye bağlar
}
```

Ham (raw) taahhüt gönderimi kamu RPC ve üretim yollarında **devre dışıdır**. Operatörler, kanıt hash'i gömülü taahhütle eşleşen ve adaptörü kayıtlı yapılandırma altında finalize olan `VerifiedDomainCommitment` sunmak zorundadır.

**Adaptör sertleştirmesi (konsensüs başına):**

- **PoW:** onay derinliği *ve* sıfırdan farklı toplam iş gerektirir; mint için sınırlı, yeniden hesaplanmış bir **`pow-header-chain-v1`** kanıtı gerekir (bitişik header'lar, yeniden hesaplanan hash/link/root/difficulty/work). Eski bildirilmiş-derinlik kanıtları mint kapısındadır.
- **PoS:** finalite sertifikası validator snapshot'ına karşı doğrulanır; snapshot/sertifika/taahhüt hash'leri kayıtlı `validator_set_hash`'e bağlanır.
- **PoA / BFT / ZK:** quorum ve proof-hash modelleri, mismatch dayatmasıyla; PoA lider seçimi hash-mix kullanır (saf round-robin değil).

### 4.3 GlobalBlockHeader — tek kriptografik gerçek

Uzlaşım Katmanı bir `GlobalBlockHeader` tutar: tüm doğrulanmış alan taahhütlerinin Merkle toplamı; **deterministik zaman damgalarıyla** (aynı durum üzerinde tekrarlanan build'ler aynı hash'i verir) ve **atomik kalıcılıkla** — taahhüt kabulü ve alan yüksekliği güncellemeleri tek bir batch'te yazılır, böylece restart kurtarması asla yarım taahhüt edilmiş bir settlement geçişi gözlemleyemez.

### 4.4 Küresel paylaşılan-durum güvenliği — Nonce Invariant

Alanlar arası çifte harcama önleme, katı bir sıralama kuralıyla dayatılır:

$$Account\_{nonce}^{Global} < Commitment\_{nonce}^{Domain}$$

Bir taahhüt, ancak hesap nonce'u mevcut küresel nonce'u kesin olarak aşıyorsa geçerlidir. Gossip üzerinden sıra dışı gelen taahhütler `pending_buffer`'da bekletilir ve boşluk dolduğunda uygulanır; restart replay'i nonce'ları yalnızca ileri taşır, asla geri almaz.

### 4.5 Deterministik çakışma çözümü ve Byzantine işlemi

- **Aynı nonce, iki alan:** settlement kaydına ilk ulaşan taahhüt kazanır; ikincisi duruma dokunmadan reddedilir.
- **Aynı alan, aynı yükseklik, farklı hash (equivocation):** alan **küresel olarak dondurulur** — bu alandan başka hiçbir taahhüt bir daha kabul edilmez — ve çelişen taahhütler kanıt olarak saklanır. Operatör bond'u ekonomik slashing kancasını sağlar.
- **Validator düzeyi equivocation** (ör. PoS çift imza) ayrıca ele alınır: `SlashingEvidence` tespit edilir, üst düzey ağ mesajı olarak gossip edilir, sonraki blok üreticileri tarafından dahil edilir ve yürütmede stake slashing olarak uygulanır.

### 4.6 Ağ ve yakınsama

Taahhütler, idempotent yeniden gönderim semantiğiyle bir **libp2p gossipsub** mesh'i üzerinden yayılır. v2 protobuf taşıma katmanı **kayıpsızdır**: mevcut tüm işlem varyantları — üç AI varyantı dahil — kapsamlı bir `TryFrom` fail-closed eşlemesinden geçerek round-trip olur; eski sessiz `Transfer` geri dönüşü kaldırılmıştır.

---

## 5. Kuantum-Sonrası Finalite

Budlum'un finalite mekanizması **yapısı gereği hibrittir**:

- **BLS toplu imzaları** — güncel dönem güvenliği ve kompakt çekirdek (quorum) sertifikaları.
- **Dilithium5 (ML-DSA) QC blob'ları** — NIST'in standartlaştırılmış kafes (lattice) ailesine göre kuantum-sonrası güvenlik.
- **İkisi de finalite yolunda zorunludur.** Güvenlik ne "yalnız-klasik"e ne de sonradan eklenmiş bir PQ yan vagonuna düşürülür: saldırgan her iki primitifı da kırmak zorundadır.

**Anahtar yönetimi.** Konsensüs imzalama **PKCS#11 HSM'lerini** destekler; disk tabanlı validator anahtarları (BLS + PQ malzemesi), o sırlar için üreticiye özgü HSM yolları var olana kadar mainnet'te reddedilir ( politika/araç seti tamam; üreticiye özgü BLS/PQ HSM doğrulaması beyan edilmiş bir denetim kalemi olarak durur). BLS anahtar çifti yüklemesi G2 kodlamasını doğrular ve `pk = g·sk` kontrolü yapar. Bilinçli olarak **sosyal kurtarma yoktur**: HSM anahtarı kaybolursa hesap sonsuza dek kilitlenir — maksimum güvenlik beyan edilmiş bir anayasal tercihtir.

**Neden önemli (Y2Q).** Mevcut zincirler eninde sonunda imza şemalarını değiştirmek için koordineli, tüm-node'lu bir hard fork yürütmek zorunda kalacak — tarihsel olarak bir zincirin yapabileceği en riskli operasyon. Budlum'un settlement kaydı üzerine doğal olarak inşa edilmiş bir sistem, sıfır protokol kesintisiyle kuantum çağına geçer.

---

## 6. Alanlar Arası Köprü — Lock → Mint → Burn → Unlock

2022–24 köprü dönemi, plansız köprülerin ekosistemin en yumuşak hedefi olduğunu kanıtladı (2,5 milyar $+ kayıp). Budlum, köprülemeyi bir kontrat olarak değil, **her adımda kanıt kapılı bir çekirdek protokol yaşam döngüsü** olarak ele alır:

1. **Kayıt** — varlıklar, kayıtlı ve köprü-etkin bir kaynak alan gerektirir.
2. **Lock** — ayrı kayıtlı kaynak/hedef alanlar, sıfırdan farklı miktar, kaynak olay yüksekliğinden kesinlikle sonraki bir son kullanma yüksekliği.
3. **Mint** — eşleşen `expected_block_hash` gerektirir; PoW kaynaklı mint'ler yeniden hesaplanmış `pow-header-chain-v1` kanıtı gerektirir (§4.2). Eski kanıt formatları muhasebe için geçerli kalır ama **mint kapısındadır**.
4. **Burn / Unlock (dönüş ayağı)** — ham burn ve ham unlock yolları devre dışıdır. Dönüş, settlement'a taahhüt edilmiş bir hedef-alan `BridgeBurned` olayı ve **olay Merkle kanıtı üzerinden doğrulama** gerektirir (`bud_burnBridgeTransferWithEvent`, `bud_unlockBridgeTransferVerified`).

`ReplayNonceStore` her alanlar arası mesajı tek kullanımlık yapar. Anayasa gereği **içeri köprüleme ön ücretsizdir**: kaynak zincir veya relayer ücret talep ederse, gelen varlıktan yolda otomatik düşülür; böylece yeni bir kullanıcının ağa girmek için elinde önceden $BUD bulunması gerekmez.

---

## 7. BudZKVM & BudZero — Doğrulanabilir Yürütme

**BudZero**, Budlum'un zkVM workspace'idir; ('den beri) tek-commit'lik uyumluluk sınırında ağ içi (in-tree) entegredir: `bud-isa`, `bud-vm`, `bud-compiler`, `bud-state`, `bud-node`, `bud-proof` crate'leri.

- **Açık aktivasyon kapılı ISA.** `VerifyMerkle`, 64-derinlik Merkle soundness kapısı (Z-B Commit 3.5) yeşillenene kadar Production ISA'da kapalıdır — bilinçli bir fail-closed tercihi; üstelik kapı artık genesis töreninde kod değişikliği yerine yapılandırmayla (`BUDLUM_VERIFY_MERKLE`) açılabilir durumdadır.
- **STARK trace yerleşimi dokümante ve sınır-testli** (`TRACE_WIDTH = 414` kolon; AIR/public-input hizalaması korunur).
- **Taşma-güvenli aritmetik** (u128 yolları), Poseidon tabanlı Merkle turları.
- **Deterministik benchmark** çerçevesi, optimizasyon takibi için tekrar üretilebilir kanıt-süresi/boyutu taban çizgileri kaydeder.

**Tasarım gereği dürüst durum:** geçerli 64-derinlik soundness *kısmi / production kapılıdır*. Whitepaper iddiaları kod iddialarıyla eşleşmelidir — dolayısıyla bu rapor tam olarak deponun iddia ettiğini iddia eder.

### 7.1 AI Çıkarım Doğrulaması (yerel primitifler)

Budlum, yürütme modelini birinci sınıf tiplerle **ajan ekonomisine** genişletir:

- `RoleId::AI_VERIFIER (6)`, rol kümesine katılır (`STORAGE_OPERATOR (5)` ile birlikte).
- `AiModelSpec`, `AiInferenceRequest`, `AiInferenceResult`, `AiInferenceOutcome` protokol düzeyi yapılardır.
- Bir `AiRegistry`, model durumunu küresel hesap durumuna güvenle katlanmış deterministik bir state root ile tutar; yürütücü, model kaydı, çıkarım istekleri ve doğrulayıcı tasdikini entegre eder.

BudZKVM STARK kanıtlarıyla birleşince bir ajanın iddiası — *"M modeli X girdisinde Y çıktısını üretti"* — zincir üzerinde ekonomik olarak uzlaşılabilir ve kriptografik olarak tasdiklenebilir hale gelir.

---

## 8. B.U.D. — Broad Universal Database

B.U.D., Budlum'un izinsiz **merkeziyetsiz depolama ağıdır** (açık politika gereği şu an yalnızca devnet).

- **Aktörler:** depolama operatörleri izinsizdir (`RoleId::STORAGE_OPERATOR`); deal'lar, replikalar, challenge'lar ve sonuçlar defter girdileridir (`ContentManifest`, `ContentId`, `StorageRegistry`).
- **Ekonomi:** deal ücretleri, operatör bond'ları, kaçırılan-challenge finalizasyonu, operatör ödül tahakkuku ve slashed-bond defteri zincir üzerinde muhasebeleştirilir; depolama bakımı (challenge düzenleme) chain actor'da otomatiktir.
- **Açık erişim:** 9 depolama RPC'si (manifest kaydet/getir, manifest/shard'a göre deal'lar, challenge aç/cevapla, sonuçlar) **herhangi bir** node tarafından sunulabilir. Spam önleme idari değil ekonomiktir (açan bond'u > 0).
- **Veri egemenliği kuralı:** kritik hiçbir fonksiyon "Budlum ekibinin çalıştırdığı bir servise" bağımlı değildir. Whitelist / admin / pause / freeze kancası yoktur.

**Sahte-yeşil yasaklı bütünlük yol haritası.** Geçici `RetrievalChallenge` açıkça **Proof-of-Storage DEĞİLDİR** — bir operatör yalnızca istenen byte-aralığını tutarak da geçebilir. Tam kanıt ( yol haritası §8.3 vizyonu) BudZKVM `VerifyMerkle` + 64-derinlik SMT production kapısına bağlıdır; o kapı geçilene kadar B.U.D. **hiçbir** proof-of-storage iddiasında bulunmaz.

---

## 9. BNS — `.bud` İsim Kaydı

BNS, Budlum ekosistemi için insan-anlamlı isimler sağlar; cüzdanları, içerik manifest'lerini (CID'ler), dApp'leri ve D-Web sitelerini çözümler.

- **İlk Gelen Alır (First Come, First Served)** — kayıt üzerine mutlak isim hakları; marka tahkim katmanı yoktur.
- **Alt-BNS pazarı ebeveyn kontrollüdür** (`x.ayaz.bud`, `ayaz.bud` sahibi tarafından yönetilir).
- **Premium kademeler** *Verified* rozeti verebilir (yıllık üst-kademe ödeme); işgal (squatting) direnci ücret tarifesine fiyatlanır.
- Arayüz katmanı (budlum.xyz araması, `bud.scan`) `.bud`'ı yerel olarak çözümler ve B.U.D.'da saklanan siteleri geleneksel DNS olmadan render eder — tam bir **D-Web** yolu.

Kayıt bütünlüğü, isim-kilitli CI kapılarıyla dayatılır (yinelenen canlı kayıtlar `NameTaken` olarak reddedilir); iskelet, genişletme ayrı talimatla ilerlerken dürüst tutulur.

---

## 10. SocialFi & Dijital Tomurcuklar — Mülkiyet Olarak İçerik

Budlum'un sosyal katmanı içeriği NFT'lere bağlar: **Dijital Tomurcuklar** (Digital Buds). Anayasal model:

- **NFT = sahiplik, kontrol ve kill-switch.** `NftBurn` ile yakma *sert budama*yı (hard pruning) tetikler: bağlantılı B.U.D. shard'ları operatör node'larından fiziksel olarak silinir. Unutulma hakkı, platform politikasıyla değil kriptografik olarak dayatılan bir sahip hakkıdır.
- **Sahiplikle taşınabilir içerik.** NFT'yi transfer etmek; içeriği, görünürlük yetkisini ve **tüm gelecek kazançları** yeni sahibin profiline/akışına taşır.
- **Spam direnci ekonomiktir:** her mint/post ücret öder. Veri, sahip yakana kadar **varsayılan olarak kalıcıdır**; **Self-Host** seçeneği, kira ödemek istemeyen kullanıcıların shard'larını kendi node'larından (mobil dahil) tam protokol düzeyi çözümlenebilirlikle sunmasına izin verir.
- **Seçici şifreleme:** her gönderi tek tek *Herkese Açık* veya *Şifreli* olur.
- **"Işık Şiddeti" (Luminance) sıralaması.** Her NFT 1 cd (kandela) ile başlar ve organik etkileşimle ışık kazanır/kaybeder (geçirilen süre, "parlatma"/"karartma") — etkileşim-maksimize edici kara kutu algoritma yoktur.
- **Topluluk oyuyla moderasyon** ve kritik-arıza senaryoları için anayasal **DAO Halt** acil durum freni.

---

## 11. $BUD Token Ekonomisi

**$BUD, ekosistemin tek fayda tokenidir.** Dijital Anayasa'ya göre akışları:

| Akış | Girdi / çıktı |
|------|----------------|
| **Gas & ücretler** — işlem, BNS kaydı, SocialFi mint'leri, veri-pazarı erişimi | $BUD ile ödenir (yürütmede MIN_TX_FEE dayatılır) |
| **Depolama emisyonu** — yeni ihracın *çoğunluğu* B.U.D. operatörlerine gider (depolama-sağlayıcı ağırlıklı ödüller) | Operatörler deal/challenge erişilebilirliği için kazanır |
| **Relayer ödülleri** — protokol evrensel relayer'lara $BUD basar; içeri relayer'lar gelen varlıktan küçük bir yolda-ücret payı alır | Köprü/relayer hizmet teşviki |
| **Boost (NftBoost)** — bölüşüm: **%4** B.U.D. depolama operatörleri · **%16** içerik üreticisi/bağlam kaynağı · **%80** protokol | Protokol payı, yapılandırılmışsa hazine/havuza yatırılır, değilse **yakılır**; B.U.D. payı deal ücretiyle ağırlıklı dağıtılır |
| **AI veri pazarı** — izinli erişim; AI ajanları veri hakları için kullanıcılara $BUD öder | Üretici/kullanıcı geliri |

Ayrıca: $BUD ile satın alınabilen fiziksel tak-çalıştır node'lar; belirli CID'ler için depolama erişim hızı/önceliği satın alan $BUD "booster"ları.

> **Dürüst parametre notu (sayı-uydurmama kuralı).** Nihai parasal parametreler — toplam arz, emisyon eğrisi, genesis dağılımı, ücret taban değerleri — `MAINNET_GENESIS_CEREMONY.md` uyarınca **mainnet genesis töreninde** belirlenir. Bu whitepaper, henüz mühürlenmiş sabit olmayan arz rakamlarını bilinçli olarak yayımlamaz; mühürlenmemiş sayılar yayımlamak projenin kendi kanıt-önce disiplinini ihlal ederdi.

---

## 12. Yönetişim

- **Yalnızca validator, stake-ağırlıklı teklifler**: ücretler, ödüller, kayıt parametreleri ve slashing'i kapsar; quorum tabanlı finalizasyon; düşmanca değer enjeksiyonunu önlemek için sınırlı parametre doğrulaması.
- **Yasa olarak Anayasa:** §1–7 kararları (içerik/moderasyon, kimlik/kurtarma, veri ekonomisi, ekosistem/relayer, AI erişimi, donanım, BNS kuralları) kanoniktir ve stack genelinde uygulanır.
- **Acil durum:** DAO Halt — topluluk oyu kritik arızada zinciri geçici olarak durdurabilir; no-rollback ilkesi ve arşiv fail-closed politikası müdahale alanını sınırlar.
- Mainnet aktivasyon değişimleri (ör. `verify_merkle`) kod düzenlemesi değil, **yapılandırma-tahrikli tören kararlarıdır**.

---

## 13. Güvenlik Mimarisi

Yinelemeli sertleştirme ( → 12.5), seçilmiş öne çıkanlar:

- **DoS sıralaması:** ucuz işlem kontrolleri imza doğrulamasından *önce* çalışır.
- **Köprü sahtecilik kapıları:** mint'te `expected_block_hash`; sınırlı, yeniden hesaplanmış PoW header zincirleri; eski kanıtlar mint kapılı; yalnızca doğrulanmış dönüş ayağı.
- **Kripto hijyeni:** BLS anahtar çifti yüklemesi G2 kodlaması + açık anahtar türetmesini doğrular; sabit-zamanlı API anahtarı karşılaştırması; mainnet konsensüs imzalamada HSM zorunluluğu.
- **RPC sertleştirmesi:** kamu auth'u fail-closed; operatör metotları mod-kapılı/yalnızca localhost; `X-Real-IP` yalnızca yapılandırılmış `trusted_proxies` ile kabul edilir; rate limit, CORS, çift-dinleyici modeli; Prometheus metrikleri (istek-gecikme histogramları, rate-limit sayaçları).
- **Tedarik zinciri hijyeni:** `fuzz/` hedefleri, bağımlılık denetim scripti, SBOM üretimi, Dependabot güvenlik güncellemeleri yalnızca tam-yeşil kapılarda birleştirilir; arşiv politikası fail-closed; atomik doğrulanmış yedekleme + geri yükleme tatbikatları; dokümante runbook'lar (üretim, arşiv/geri yükleme).
- **Başlamış ve dürüstçe kapsanmış biçimsel yöntemler:** bir TLA+ iskeleti (`MultiConsensus.tla`), safety'yi (NoRollback, MonotonicHeight, SlashValidator) ve dürüst quorum altında liveness'i modeller — *iskelet* olarak etiketlenmiştir; tam biçimsel doğrulama harici denetime ayrılmıştır.

**Kanıt panosu (tamamı CI-kanıtlı, modül kapıları isim-kilitli):**

| Modül | Test | Kapı |
|--------|-------|------|
| Budlum Core | **755 lib** | fmt + clippy `-D warnings` + test |
| BudZero / BudZKVM | **124** | BudZero workspace kapısı |
| B.U.D. | **12 zorunlu** (9 invariant + 3 e2e) | `check-bud-e2e.sh` + E2E Invariants job'u |
| BNS (`.bud`) | **8** | `check-bns-gate.sh` isim-kilitli |

*(Core'un 755'i, paylaşılan lib üzerinden B.U.D./BNS suitlerini içerir; modül kapıları ayrıca "toplam satırı asla modül satırının yerini almaz" raporlama kuralı gereğince dayatılır.)*

> Bu bölüm, profesyonel bir harici denetimin **yerine geçmez** — bkz. §15.

---

## 14. Ekosistem Arayüzü — Görünür Ağ

- **budlum.com** — geçit: vizyon, dokümanlar, onboarding.
- **budlum.xyz** — *gezinilebilir dijital toprak* olarak ağ: her karenin cüzdan olduğu, kümelerin dApp olduğu sonsuz bir grid. Keşif mekânsaldır — "Minecraft tarzı."
- **bud.scan arama & +Bağlam Haritaları:** adresler, NFT CID'leri, `.bud` isimleri, D-Web siteleri için evrensel arama; cüzdan Bağlam Haritaları işlem-ilişki grafiklerini çizer; token *Bubble Map*'leri dağılımları/balina yapısını render eder.
- **Budlum Hub:** açık, demokratik dApp kaydı.
- **Evrensel Relayer ("ana anahtar"):** Budlum cüzdanları/HSM'leri harici zincirlerde (EVM, Solana, …) gas'ı $BUD ile ödeyerek imzalar ve yürütür; protokol basımı relayer teşvikleri ve kritik zincirler arası işlemler için zorunlu çok-cihazlı/çok-imzalı onay.
- **Mobil-öncelikli egemenlik:** telefonlar birinci sınıf depolama ve doğrulama node'larıdır; kullanıcılar kendi B.U.D. shard'larını kendileri barındırabilir.

---

## 15. Yol Haritası & Mainnet Engelleyicileri

**Tamamlananlar (kanıtla kapatılmış):** çok-konsensüslü alanlar; BLS+Dilithium hibrit finalite; BLS finalite protokolü prevote/precommit; doğrulanmış dönüş yolu ve PoW mint kapıları dahil köprü yaşam döngüsü; settlement atomikliği; senkronizasyon sertleştirmesi; PKCS#11 Ed25519 imzalayıcı; RPC çift dinleyici; P2P sertleştirmesi; Snapshot V2 + arşiv politikası; Prometheus gözlemlenebilirliği; docker/systemd dağıtımı; ConsensusStateV2 migrasyon iskeleti (fail-closed); fuzz/bağımlılık-denetimi/SBOM araç seti; denetim kontrol listesi; persona'lar (kullanıcı/geliştirici/kurumsal-PoA); ağ içi BudZero + performans taban çizgisi çerçevesi; B.U.D. Gorev 1–2 + iskelet 5 (devnet); BNS iskeleti; TLA+ iskeleti; AI çıkarım doğrulayıcı primitifleri.

**Açık mainnet engelleyicileri (beyan edilmiş, iddia edilmemiş):**

1. **Bağımsız harici güvenlik denetimi** — kontrol listesi hazır; *denetim yapılmamıştır*.
2. **Üreticiye özgü BLS/PQ HSM mekanizma doğrulaması.**
3. **Z-B 64-derinlik Merkle soundness** — `VerifyMerkle` ve dolayısıyla B.U.D. gerçek Proof-of-Storage (Gorev 3+) için production kapısı.
4. **Gizlilik (Privacy) katmanı** — araştırma gorevsında.
5. **Primitiflerin ötesinde AI yürütme katmanı** — araştırma/entegrasyon gorevsında.
6. TLA+ iskeletinin ötesinde tam biçimsel doğrulama.

**Aktivasyon yolu:** B.U.D. mainnet dahiliyeti, hazırlık adımı kapandıktan sonra değerlendirilir; genesis tarafı özellik değişimleri (ör. `verify_merkle=true`) kontrol listesi doğrulamalı (`GENESIS_FLIP_CHECKLIST`), yapılandırma-tahrikli tören kararlarıdır.

---

## 16. Risk Faktörleri & Bildirimler

- **Denetim öncesi yazılım.** Budlum kontrollü bir kamu devnet adayıdır. Gerçek-değer taşıyan üretim trafiği için **kullanmayın**.
- **Araştırma gorevsı bileşenler.** AI katmanı, gizlilik katmanı ve B.U.D. Gorev 3+, önemli uygulama riski taşıyan ileriye dönük ifadelerdir.
- **Kurtarmasız anahtar modeli.** Maksimum-güvenlik, sıfır-kurtarma duruşu, anahtar kaybı riskini tamamen sahibine devreder. Önemli bakiyeler için çok-cihazlı/HSM pratikleri zorunludur.
- **Parametre bekliyor.** Parasal parametreler genesis törenine kadar mühürsüzdür; bir "arz"dan bahseden herhangi bir üçüncü taraf yetkisiz sayılmalıdır.
- **Düzenleyici yüzey.** Egemen alanların settlement'ı (CBDC kullanım durumu) ve ücretli AI veri pazarları gelişen düzenlemelere dokunur; dağıtımlar yargı bölgesine özgü uyumluluğu değerlendirmelidir.
- **Dürüst-etiket risk kabulü.** Bilinen geçici sınırlamalar (ör. retrieval challenge'ları ≠ proof-of-storage) gizlenmek yerine kabul edilip dokümante edilir; kullanıcılar iddialara güvenmeden önce modül README'lerini okumalıdır.

---

## 17. Sonuç

Sektör on yılını güvenlik modelleri arasında seçim yaparak geçirdi: PoW *ya da* PoS, izinli *ya da* kamu, egemen *ya da* birlikte çalışabilir, şeffaf *ya da* özel. Budlum'un iddiası, bunların yanlış ikilemler olduğudur. Konsensüs dayatmak yerine finaliteyi doğrulayan bir uzlaşım katmanı, hepsini aynı anda barındırabilir — genesis'ten itibaren kuantuma hazır, vaatler yerine kanıtlarla köprülenmiş, doğrulanabilir hesaplamayla genişletilmiş ve ekonomisinde insancıl: sahiplenebileceğin, taşıyabileceğin ve silebileceğin içerik; telefonundan satabileceğin depolama; AI tükettiğinde sana ödeme yapan veri.

Bu whitepaper'ı türünün alışkanlığından ayıran şey, yapmayı reddettikleridir: gösteremeyeceği testleri iddia etmez, yapılmamış denetimleri iddia etmez, kapıları hâlâ kapalı olan kanıtları iddia etmez. Buradaki sayılar CI-kanıtlıdır; buradaki boşluklar isimlendirilmiştir. Bu tevazu değildir — protokolün kendi fail-closed felsefesinin düzyazıya uygulanmasıdır.

**Budlum dünyanın zincirlerinin yerini almaz. Onları uzlaştırır.**

---

## Referanslar (depo içi)

- `docs/01_multi_consensus_settlement.md` — settlement mimarisi detayı
- `docs/03_paradigma_analizi.md` — yedi paradigma kayması, stratejik gerekçe
- `docs/BUDLUM_CONSTITUTION.md` — sosyal & ekonomik çerçeve (kanonik)
- `docs/BUDLUM_ECOSYSTEM_INTERFACE.md` — grid/arama/bağlam-haritası kullanıcı deneyimi
- `docs/BUDZKVM_TRACE_LAYOUT.md`, `docs/BUDZERO_DERIN_DENETIM_ARENA3.md` — zkVM trace & denetim notları
- `docs/MAINNET_READINESS.md`, `docs/MAINNET_GENESIS_CEREMONY.md` — lansman yolu
- `docs/operations/*` — runbook'lar (üretim, arşiv/yedekleme, finalite canlı-yol)
- `src/bns/README.md`, `src/storage/README.md`, `budzero/README.md` — modül düzeyi dürüst durum

*Whitepaper, canlı depo durumundan Temmuz 2026'da hazırlanmıştır. MIT lisanslı proje; bu belge deponun kanıt kurallarını yansıtır: toplam satırları asla modül satırlarının yerini almaz ve kapı olmadan iddia yoktur.*
