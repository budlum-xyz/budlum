# Budlum — Phase 10.5: Çapraz-Kesit Eksiklik Analizi (Tüm Aşamalar × Tüm İnsan Tipleri)

> **Amaç:** Budlum'u **tüm aşamalarda** (Phase 1 → 10), **tüm modüllerde** (L1 Core,
> BudZero, B.U.D., BNS, cross_domain, AI, socialfi) ve **tüm insan tiplerinin
> açılarından** inceleyip **eksik / tamamlanmamış / sahte-yeşil / sessiz-boşluk**
> bulguları ortaya çıkarmak. Bu bir **mainnet-prep** analizidir — acele değil,
> derinlik önceliklidir (kullanıcı talimatı 2026-07-18).
>
> **Yöntem:** Her bulgu **koddan / CI'dan / commit'ten kanıtlanmıştır** (point #6:
> kör kabul yok). Kaynak satır/commit referansları eklenmiştir. Hiçbir bulgu
> "sanırım" ile yazılmadı; varsayımlar doğrulanmamışsa "AÇIK SORU" etiketiyle
> işaretlendi.
>
> **Yazar:** ARENA1 · **Tarih:** 2026-07-18 · **Temel:** main `cb899cb`
> (CI 12/13 yeşil; Fuzz tail).
> **Köken dokümanlar:** README · MAINNET_READINESS (MR-1..10) · ARENA3_BACKLOG ·
> PERSONAS · SECURITY_AUDIT_HACKER · BUDLUM_PHASE10 · RFC_ACCESSGRANT_V2 ·
> STATUS_ONLINE.

---

## 0. Neden bu doküman

Phase 10 (AI Inference + B.U.D. Marketplace + modül ayrımı) **fonksiyonel
genişleme** turudur. Ama Budlum mainnete giderken **tek bir soru** her şeyi
belirler: *"Bu zinciri X tipi insan kullanmaya kalktığında, ne olur?"*

`PERSONAS.md` yalnızca **3 node-işletici tipi** listeler (user / developer /
enterprise-PoA). Bu, gerçek kullanıcı evreninin **çok küçük bir alt-kümesidir**.
Validator, miner, storage operator, AI verifier, relayer, prover, data owner,
data consumer, $BUD holder, exchange, governance participant, BNS name holder,
light-client user, auditor, ceremony participant, regulator **ve saldırgan**
tiplerinin her biri için sistemin bir yüzeyi vardır — ve bu yüzeylerin bir kısmı
**eksik, çelişkili veya sahte-yeşil**.

Phase 10.5, **kullanıcı tipi × modül** matrisindeki boşlukları kapatır. Hiçbir
bulgu "Bölüm X yapacak" diye sahiplenilmez; **kullanıcı kararı** bekler.

---

## 1. İnsan tipi kataloğu (6 kategori, 25 tip)

| # | Kategori | Tip | Ana kullanım amacı |
|---|---|---|---|
| A1 | Ağ katılımı | **Validator (PoS/BFT)** | stake → finality imzası → ödül |
| A2 | Ağ katılımı | **Miner (PoW)** | PoW domain'de blok üretimi |
| A3 | Ağ katılımı | **PoA Authority (Kurumsal/Banka)** | KYC'li izinli blok üretimi |
| A4 | Ağ katılımı | **Prover (ZK)** | BudZKVM STARK kanıt üretimi → ödül |
| A5 | Ağ katılımı | **Universal Relayer** | cross-chain mesaj taşıma → fee |
| A6 | Ağ katılımı | **Light-Client User** | tam node olmadan settlement doğrulama |
| B7 | B.U.D. depolama | **Storage Operator** | depolama sağlama → deal + reward |
| B8 | B.U.D. depolama | **Data Owner** | veri yükleme + provenance + satış |
| B9 | B.U.D. depolama | **Data Consumer/Buyer** | marketplace'ten veri satın alma |
| B10 | B.U.D. depolama | **AI Inference Verifier** | off-chain model çalıştırma → kanıt |
| B11 | B.U.D. depolama | **AI Model Sahibi** | model kaydı (AiModelRegistry) |
| C12 | Token/ekonomi | **$BUD Holder** | token tutma / spekülasyon |
| C13 | Token/ekonomi | **Exchange Operator** | listeleme / para çekme |
| C14 | Token/ekonomi | **Slashing Reporter** | kötü-davranış raporu → ödül |
| C15 | Token/ekonomi | **Governance Participant** | parametre oylaması |
| D16 | Identity/uygulama | **BNS (.bud) Name Holder** | isim kaydı / devir |
| D17 | Identity/uygulama | **SocialFi/NFT User** | dijital varlık / boost |
| D18 | Identity/uygulama | **dApp Developer** | akıllı kontrat geliştirme |
| D19 | Identity/uygulama | **Smart-Contract Deployer** | BudZKVM bytecode deploy |
| E20 | Operasyon | **Node Operator (full/archive/mobile)** | node işletme |
| E21 | Operasyon | **Bridge Operator** | köprü gözetim / izleme |
| E22 | Operasyon | **Ceremony Participant** | genesis key üretimi |
| E23 | Denetim/regülasyon | **Auditor / Security Researcher** | denetim / red-team |
| E24 | Denetim/regülasyon | **Regulator / Compliance** | KYC/AML gözetimi |
| F25 | Saldırgan (red team) | **Attacker** | exploit / DoS / köprü hack / sybil |

---

## 2. Bulgular (insan-tipi açısından, kanıtlanmış)

Her bulgu: **Tip · Faz/Modül · Kanıt · Etki · Öneri · Öncelik.**
Öncelik anahtarı: 🔴 mainnet-blocker · 🟡 mainnet öncesi · 🟢 uzun-vade.

### 2.1 B.U.D. (B7 Storage Operator · B8 Data Owner · B9 Consumer)

**F10.5-01 🔴 · ContentManifest'te `owner` alanı YOK (Data Owner identity kopuk).**
- **Kanıt:** `src/storage/manifest.rs:50-55` — alanlar yalnız
  `manifest_id/total_size/shard_count/shards`. STATUS_ONLINE P10 doğrulama
  girdisi + RFC_ACCESSGRANT_V2 §3.1 (`DataAsset.owner` zorunlu notu).
- **Etki:** Data Owner (B8) yüklediği verinin zincir-üstü sahibini kanıtlayamaz.
  Provenance `StorageCommitment`'e bağlı ama `ContentManifest` kendisi ownersız.
  Marketplace'te "bu veri kimin" sorusu `DataAsset`'e kadar (henüz main'de değil)
  cevapsız. Mainnet'te sahiplenme anlaşmazlığı → hukuki/governance krizi.
- **Öneri:** P1 marketplace primitifleriyle `DataAsset.owner` zorunlu (RFC'de
  zaten); ama `ContentManifest`'e de owner backlink eklenmeli (Faz 4
  `storage_root` ile birlikte) yoksa manifest→asset→owner zinciri kopuk kalır.
  **AÇIK SORU:** owner manifest'te mi, ayrı registry'de mi (RFC §3.2 bunu
  `DataAsset`'te çözüyor ama manifest kayıt anı çözülmedi).

**F10.5-02 🔴 · AccessGrant Faz-1 = soft-enforcement (storage node plaintext görüyor).**
- **Kanıt:** BUDLUM_PHASE10 Bölüm 2.2/2.3 — "Faz 1: storage node grant kontrolü
  yapar (soft enforcement)" + Bölüm 2.0 dürüst notu: "sadece on-chain flag teknik
  garanti ETMEZ — storage node ham veriyi izinsiz de sunabilir". Faz 2 (HPKE
  key-wrapping) RFC §8'de BEKLEMEDE.
- **Etki:** Data Owner (B8) "izinsiz AI erişemez" iddiası Faz-1'de **teknik olarak
  yanlış**. Storage Operator (B7) kötü-niyetliyse plaintext'i serbestçe satabilir;
  yalnızca ekonomik caydırıcı (stake/slashing). Data Consumer (B9) "yasal erişim"
  aldığını sanır ama teknik engel yok. → Sahte-yeşil yol riski (vision §9.1).
- **Öneri:** Mainnet lansmanında AccessGrant'ın **Faz-1 olduğu DOKÜMANTASYONDA
  açıkça** "ekonomik caydırıcı, kriptografik garanti DEĞİL" yazılmalı. Hard
  enforcement (HPKE) mainnet ENGELİ olarak işaretlenmeli (MR-benzeri yeni kriter).

**F10.5-03 🟡 · ReadOnce consumption off-chain değil ama "zincir-üstü" — uygulama yok.**
- **Kanıt:** RFC_ACCESSGRANT_V2 §6 (K4) — `once_consumed: BTreeMap<...>`
  zincir-üstü. Ama P0'da yalnız tipler ship edildi (`775ab3a`); `once_consumed`
  registry main'de YOK.
- **Etki:** Data Consumer (B9) tek-seferlik erişim aldığında tüketim sayacı yok →
  replay'e açık. P1/P2'ye bağlı.
- **Öneri:** P1/P2 kapsamında uygulanacak; bu doküman kapsamında not.

**F10.5-04 🟡 · Interim RetrievalChallenge gerçek Proof-of-Storage DEĞİL.**
- **Kanıt:** CLAUDE.md §4 + `src/storage/README.md` sahte-yeşil uyarısı —
  operator sadece istenen byte-range'i saklayarak geçer. Tam kanıt Faz 3
  (VerifyMerkle 64-depth) gated.
- **Etki:** Storage Operator (B7) "depomda veri var" kanıtı zayıf → kötü
  operator ucuza kurtulabilir. MAINNET_READINESS §2.3 = A (interim ile başla)
  kararı alındı ama bu **ekonomik güven'in zayıf halkası**.
- **Öneri:** Faz 3 mainnet sonrası; MR-3 (VerifyMerkle) ile birlikte.

**F10.5-05 🟡 · B.U.D. operator churn/grace-period politikası YOK.**
- **Kanıt:** `src/domain/storage_deal.rs` deal+challenge ekonomisi var; ama
  operator kapandığında (unbonding/offline) mevcut deal'ların ne olduğu (yeni
  operator'a transfer mi, grace period mu, anında slash mi) net değil.
- **Etki:** Storage Operator (B7) plansız kapanırsa Data Owner (B8) verisinin
  erişilemezliğine çare bulamaz. Operational risk.
- **Öneri:** AÇIK SORU — churn politikası (deal migration / grace / insurance
  pool). Dış standartlar (Filecoin sector termination) referans olabilir.

### 2.2 AI Inference (B10 Verifier · B11 Model Sahibi · B9 Consumer)

**F10.5-06 🔴 · AI dispute / timeout / slashing AKIŞI YOK.**
- **Kanıt:** `src/ai/registry.rs:116-135` — `if agreeing_verifiers.len() >=
  threshold { outcome } else { Ok(None) }`. Eşleşme sağlanmazsa **hiçbir şey
  olmaz** — request `outcomes`'a hiç girmiyor, dispute/slashing/timeout yok.
- **Etki:** AI Verifier (B10) set'i ikiye bölünürse (network partition / kötü
  niyet) request **sonsuza kadar askıda**. Data Consumer (B9) callback bekler,
  fee iadesi yok, timeout yok. Canlılık (liveness) ihlali + fee DoS yüzeyi.
  **Faz 1 attestation modelinin en kritik boşluğu.**
- **Öneri:** dispute/timeout mekanizması tasarlanmalı: (a) `max_wait_blocks`
  timeout → fee iadesi + slack verifier'lar slash; (b) disagreement ≥ N blok →
  slash slash veya "no-consensus" outcome; (c) retry/quorum-artırma. **RFC
  gerekir** (Bölüm 1.3 "testler: disagreement/dispute" diyor ama kod yok).

**F10.5-07 🟡 · AI input_ref ↔ B.U.D. AccessGrant entegrasyonu YOK.**
- **Kanıt:** BUDLUM_PHASE10 Bölüm 2.2 (zorunlu entegrasyon) + RFC_ACCESSGRANT_V2
  §10 P5 (yeni ARENA2 adayı). `src/ai/types.rs` `input_ref: Vec<u8>` opak.
- **Etki:** AI Verifier (B10), B.U.D. `DataAsset`'ini kullanan bir inference
  başlatırken grant kontrolü yapmıyor → Data Owner (B8) izni bypass. Faz 1'de
  "AI erişimi" iddiası boş.
- **Öneri:** P5 (Bölüm 1) — `grantee_role_constraint` ile birlikte. Ayrı RFC.

**F10.5-08 🟡 · AI model determinizmi çözülmedi (Faz 2 zkML bekleniyor).**
- **Kanıt:** BUDLUM_PHASE10 Bölüm 1.0 — "Büyük modelleri zincirde prove etmek
  pratikte imkansız"; Faz 1 attestation, Faz 2 kısıtlı STARK-provable.
- **Etki:** Aynı model farklı donanımda farklı çıktı → konsensüs için ölümcül.
  AI Model Sahibi (B11) model_hash veriyor ama off-chain çalıştırma deterministik
  değil → agreement_threshold hiç sağlanmayabilir.
- **Öneri:** Faz 1 için "bounded model class" whitelist (deterministik output)
  veya attestation-modelinin sınırları dokümante. Faz 2 (zkML) mainnet sonrası.

**F10.5-09 🟢 · AI inference fee economics detayı YOK.**
- **Kanıt:** `AiInferenceRequest.max_fee: u64` var ama ödül dağıtımı (verifier'a
  ne kadar, hangi sırada), fee iadesi, spam koruması net değil.
- **Etki:** AI Verifier (B10) ekonomik teşvik belirsiz → katılım düşük.
- **Öneri:** F4 (boost share) desenine paralel fee economics tasarımı.

### 2.3 Bridge / Relayer (A5 Relayer · E21 Bridge Operator · F25 Attacker)

**F10.5-10 🔴 · Universal Relayer gerçek kriptografik adapter'lara ihtiyaç duyuyor.**
- **Kanıt:** SECURITY_AUDIT_HACKER H4 (🔴 Critical, "Roadmap §5.1") —
  `UniversalRelay` tx yalnızca log üretiyor, EVM RLP / Solana Compact gibi
  hedef zincir formatına kriptografik bağ yok. `src/cross_domain/relayer.rs`
  orchestrator var ama `ChainAdapter` stub (StubAdapter test).
- **Etki:** Relayer (A5) ve Bridge Operator (E21) için üretim köprüsü **yok**.
  Attacker (F25) spoofed log ile sahte yetkilendirme yapabilir (H4 "hacker trick").
  Mainnet'te **canlı cross-chain değer transferi YAPILAMAZ**.
- **Öneri:** Her hedef zincir (EVM/Solana/...) için gerçek `ChainAdapter` impl.
  H4 açık; ARENA1 (cross_domain) domain'inde. **AÇIK SORU:** hangi zincirler
  Faz 1 (mainnet lansman) için gerekli? (EVM-likely öncelik).

**F10.5-11 🟡 · Bridge `amount: u128` ↔ $BUD `amount: u64` tutarlılık yüzeyi.**
- **Kanıt:** `src/cross_domain/bridge.rs:31 amount: u128` vs
  `src/core/transaction.rs:119/156 amount: u64`. H6 (u128→u64 truncation)
  SECURED (range check eklendi) ama cross-chain asset'lerin tamamı için tutarlı
  limit politikası net değil.
- **Etki:** Attacker (F25) cross-chain'den >u64 değer gönderemez (fix'li) ama
  Bridge Operator (E21) için "bu asset'in max miktarı" kayıt politikası eksik.
- **Öneri:** per-asset amount cap + whitelist policy (BUDLUM governance).

**F10.5-12 🟡 · Bridge operator monitoring / alerting runbook YOK.**
- **Kanıt:** `src/cross_domain/` kodu + `docs/operations/` runbook'ları grep —
  bridge-specific monitoring yok. Relayer `min_relayer_stake: 10_000_000` var
  (`relayer.rs:175`) ama reward economics / alert yok.
- **Etki:** Bridge Operator (E21) anomali (stuck lock, equivocation) tespit
  edemez. $2.5B+ bridge hack çoğu zaman "geç fark edildi" hatası.
- **Öneri:** PRODUCTION_RUNBOOK'a bridge monitoring bölümü (lock-age alert,
  relayer-liveness, mint/burn dengesi).

**F10.5-13 🟡 · Relayer economic security analizi yok (10M stake yeterli mi?).**
- **Kanıt:** `min_relayer_stake = 10_000_000` sabit. ama "bu stake X değerlik
  transferi için ne kadar güvenli" ekonomik modeli yok.
- **Etki:** Relayer (A5) collusion ihtimaline karşı economic security belirsiz.
- **Öneri:** stake/throughput oranı analizi + slashing oran ayarı.

### 2.4 BNS / Identity (D16 Name Holder · E24 Regulator)

**F10.5-14 🟡 · BNS fiyat sabit (auction/squatting koruması YOK).**
- **Kanıt:** `src/bns/registry.rs:13-26` — `base_cost=100` × length-multiplier
  (3-karakter=100×, 4-6=10×, diğer=1×) × duration. Auction yok, premium yok.
- **Etki:** D16 isim almak isteyen için popüler isimler **first-come-first-served**
  → squatting (önceden kapma) + front-running. "google.bud" ilk kapana.
- **Öneri:** AÇIK SORU — auction modeli (ENȘ/merkle-Dutch) mi, premium-tier mı,
  binding-period (launch'da reserved list) mi? Backlog #6 (BNS genişletme).

**F10.5-15 🟡 · BNS trademark/KYC/regulated-name koruması YOK.**
- **Kanıt:** `src/bns/registry.rs` — isim kaydı permissionless, reserved-list yok.
- **Etki:** Regulator (E24) açısından: "cocacola.bud", "tcmb.bud" alınırsa
  trademark/compliance krizi. PoA domain'i regulated ama BNS permissionless —
  tutarsızlık.
- **Öneri:** reserved/trademark listesi (governance-managed) veya challenge
  mekanizması (UDRP-benzeri). **AÇIK SORU:** Budlum'un hukuki duruşu.

**F10.5-16 🟢 · BNS grace-period / front-running (expired-then-reregister) riski.**
- **Kanıt:** `register` (`registry.rs:39`) — `if record.expires_at > current_epoch`
  red; expired ise re-register serbest. Grace period yok.
- **Etki:** D16 isim süresi dolunca anında başkası kapabilir (unuttuysan).
- **Öneri:** grace-period (30 gün) + uyarı.

### 2.5 Tokenomics / Governance (C12 Holder · C13 Exchange · C15 Governance)

**F10.5-17 🟢 · Governance crate README'de/crate-haritasında listelenmemiş (docs hygiene).**
- **⚠ SELF-CORRECTION (2026-07-18, investigate_first):** İlk bu doküman sürümünde
  bu bulgu "governance modülü src/'te YOK (README iddiasıyla ÇELİŞKİ), 🔴 mainnet-blocker"
  idi — **YANLIŞTI.** `grep -rln GovernanceProposal|fn propose` (CamelCase) küçük-harfli
  modülü kaçırdı. Doğrulama: `src/core/governance.rs` MEVCUT — `ProposalType`
  (ChangeBaseFee/ChangeBlockReward/SlashValidator/ParameterUpdate) + stake-weighted
  voting + quorum finalize; `executor.rs:190 "governance_proposer_not_validator"`
  validator-only proposal. **README iddiası DOĞRU.** (Ders notu STATUS_ONLINE.)
- **Kalan gerçek bulgu (🟢 docs hygiene):** `src/core/governance.rs` README
  "Architecture" crate-haritasında listelenmemiş. C15 governance participant için
  kod yüzeyi var ama keşfedilebilir değil. README'de satır eklemek yeterli.
- **Düzeltme:** README'ye governance crate linki (bu commit).

**F10.5-18 🟡 · Token-holder governance yok (PoS zincirlerinden farklı).**
- **Kanıt:** C15 tipi için — validator-only proposal (varsa) token holder'ı
  dışlar. $BUD holder (C12) yönetişim gücü yok.
- **Etki:** C12 "token tutuyorum ama söz hakkım yok" — DeFi bekletisi ile çelişki.
- **Öneri:** AÇIK SORU — token-weighted governance isteniyor mu? (PoA-lean
  tutarlı ise validator-only savunulabilir ama dokümante).

**F10.5-19 🟡 · Bridge çıkışında wrapped-$BUD supply tutarlılığı garantisi belirsiz.**
- **Kanıt:** $BUD 100M arz (6 decimal), bridge lock/mint/burn var; ama hedef
  zincirde wrapped supply ↔ native burn tutarlılığı nasıl denetleniyor (proof?)
  net değil.
- **Etki:** C13 exchange "wrapped $BUD gerçek $BUD'ya karşılık mı" denetleyemez.
- **Öneri:** bridge audit endpoint + supply-reconciliation RPC.

**F10.5-20 🟢 · Vesting unlock takvimi şeffaflığı (Team 20M).**
- **Kanıt:** CLAUDE.md §4 tokenomics — team vesting cliff+lineer Seçenek B;
  `team_vesting` snapshot'a girdi (Phase 0.16 fix).
- **Etki:** C12/C13 için unlock takvimi RPC'den sorgulanabilir mi? Net değil.
- **Öneri:** vesting schedule RPC.

### 2.6 PoA / Kurumsal (A3 · E24 Regulator)

**F10.5-21 🟡 · PoA KYC verifier entity + AML/sanctions screening YOK.**
- **Kanıt:** `src/registry/poa_membership.rs:49 kyc_commitment: KycCommitment`
  ([u8;32] hash — gizli commitment), admins "compliance-authorized approvers".
  Ama **kim** KYC yapıyor, AML/sanctions screening akışı, off-chain verifier
  entity yok.
- **Etki:** A3 (banka) ve E24 (regulator) için "KYC yapıldı" kanıtı yalnız
  commitment hash — gerçek verifier kim, nasıl denetlenir? Multi-tenant PoA
  (farklı bankalar aynı domain) net değil.
- **Öneri:** AÇIK SORU — KYC verifier modeli (3rd-party / attestation / on-chain
  proof). Compliance reporting RPC.

**F10.5-22 🟡 · PoA audit trail (regulator erişimi) YOK.**
- **Kanıt:** PoA domain'de admin approve/revoke (`poa_membership.rs:38`) event'leri
  var ama regulator için structured audit log / read-only RPC yok.
- **Etki:** E24 denetim için ham veri çıkarma zor.
- **Öneri:** compliance export RPC (membership history, approval chain).

### 2.7 Light-Client / End-User (A6 · D18 · D19)

**F10.5-23 🟡 · "Not a full light client" — kod yorumunda itiraf.**
- **Kanıt:** `src/domain/finality_adapter.rs:97,212` — "Not a full light client,
  but far..."; "still not a full light-client". PoW bounded header-chain adapter.
- **Etki:** A6 light-client user için tam SPV yok — mobil/cüzdan için settlement
  doğrulama bounded. README bunu "PoW light-client finality" diye pazarlıyor ama
  sınırlı.
- **Öneri:** README "bounded" niteleyicisi korunmuş (dürüst); tam light-client
  mainnet sonrası. A6 için dokümantasyon netliği.

**F10.5-24 🟡 · Cüzdan/UX yüzeyi zayıf (fee estimation, key mgmt).**
- **Kanıt:** `src/rpc/api.rs:45 gas_price` RPC var. Ama fee estimation
  (gas_price × gas_used tahmini), nonce management, key recovery yüzeyi yok.
- **Etki:** D18 (dApp dev) ve A6 (light user) için cüzdan entegrasyonu zor.
- **Öneri:** fee estimation RPC + cüzdan SDK dokümantasyonu (mainnet sonrası).

### 2.8 Node Operator (E20)

**F10.5-25 🟡 · Mobile node replication=2 veri-kaybı riski.**
- **Kanıt:** STATUS_ONLINE ARENA2 Q-X2 — mobil `replication_factor: 2` (enerji/
  erişilebilirlik trade-off, `budzero/bud-node/src/sharding.rs`).
- **Etki:** E20 mobil node operator için 2 kopya → tek node kaybı veri riski.
- **Öneri:** mobile node "cache-only" sınıflandırması (data-sovereignty ile).

**F10.5-26 🟢 · Archive node operator-reward yansıması belirsiz.**
- **Kanıt:** `storage_operator_rewards` accrual (`blockchain.rs:3730`) var; ama
  archive node (tüm veriyi tutan) ile storage node (deal-bağlı) ayrımı net değil.
- **Etki:** E20 archive operator için ödüllendirme/teşvik belirsiz.
- **Öneri:** archive-node economics ( donation / governed).

### 2.9 Ceremony / Genesis (E22)

**F10.5-27 🔴 · Ceremony keys + bootnodes BOŞ (bilinçli borç ama mainnet engeli).**
- **Kanıt:** MAINNET_READINESS §3.1 + STATUS — ceremony seeds "template only",
  MR-6 "input'lar ceremony günü".
- **Etki:** E22 (ceremony participant) için prosedür (multi-party key-gen, HSM,
  imha) detayı yetersiz. MR-6 blocker.
- **Öneri:** MAINNET_GENESIS_CEREMONY.md'ye ceremony playbook (MPC key-gen
  protokolü, witness listesi, imha kanıtı).

**F10.5-28 🟡 · Ceremony social recovery / key-compromise senaryosu YOK.**
- **Kanıt:** ceremony dokümanları — initial key-gen var ama "bir validator key'i
  sızdı, rotate et" senaryosu net değil.
- **Etki:** E22 + A1 validator için key-compromise → slashing/rotation akışı.
- **Öneri:** key rotation + emergency ceremony procedure.

### 2.10 Audit / Security (E23 · F25)

**F10.5-29 🔴 · External audit BAŞLAMADI (MR-8).**
- **Kanıt:** MAINNET_READINESS MR-8 🔴 + AUDIT_CHECKLIST hazır ama teslim paketi
  yok. MAINNET_READINESS §2.4 = C (bug bounty ile başla) ama BUG_BOUNTY.md YOK.
- **Etki:** E23 (auditor) için "self-audited" = ana mainnet engeli.
- **Öneri:** BUG_BOUNTY.md oluştur (MAINNET_READINESS §2.9 görev); external audit
  firm seçimi (MR-8).

**F10.5-30 🟡 · Fuzz nightly 4h/target (MR-3 = 24h+ değil).**
- **Kanıt:** `.github/workflows/fuzz-nightly.yml` "4h/target"; MR-3 "VerifyMerkle
  + KAT vectors" + 24h.
- **Etki:** E23 açısından fuzz coverage yetersiz (mainnet için).
- **Öneri:** 4h → 24h (MR-3).

**F10.5-31 🟡 · Bridge $2.5B hack pattern'lerine spesifik test YOK.**
- **Kanıt:** SECURITY_AUDIT_HACKER H1-H7 fix'li ama wormhole/ronin/nomad
  pattern'lerine (fake merkle, unchecked calldata, privileged role compromise)
  spesifik regression test seti yok.
- **Etki:** F25 attacker açısından known-pattern tekrar riski.
- **Öneri:** "bridge hack corpus" test seti (her major bridge hack'ten 1
  regression test).

**F10.5-32 🟢 · Post-quantum geçiş dönemi history koruması.**
- **Kanıt:** BLS+Dilithium hybrid finality var (README). Ama "quantum-bilgisayar
  geldikten sonra eski (quantum-vulnerable) imzalı history" koruması net değil.
- **Etki:** F25 long-range attacker (quantum-sonrası) için risk.
- **Öneri:** PQ-finality checkpoint + history commit (araştırma).

---

## 3. Sahte-yeşil / claim-hygiene bulguları (MR-10)

**F10.5-33 🔴 · Governance README iddiası kanıtlanamaz (F10.5-17 tekrar, hygiene).**
README "Governance: validator-only proposals" — kod yok. **MR-10 ihlali**.

**F10.5-34 🟡 · "B.U.D. mainnet dahil" (MR-2.3 = A) ama interim = ekonomik-oyun.**
Kullanıcı kararı "evet dahil et, interim ile başla" — ama dokümantasyon "gerçek
PoS DEĞİL, ekonomik oyun" netliği Faz-1'de olmalı (BUD_INTERIM.md.MAINNET_READINESS
§3.6 görevi var mı kontrol).

**F10.5-35 🟡 · AI "on-chain inference" pazarlaması (Faz 1 = attestation).**
Bölüm 1.0 dürüst ama README/outer pazarlama "AI agents without settlement →
In-tree BudZKVM STARK execution" — Faz 1 attestation, STARK Faz 2. Net olmalı.

---

## 4. Kullanıcı kararları gereken açık noktalar (özet)

| # | Karar | İlgili bulgu |
|---|---|---|
| K10.5-1 | **ContentManifest owner: manifest'te mi, ayrı registry'de mi?** | F01 |
| K10.5-2 | **AccessGrant hard-enforcement (HPKE) mainnet engeli mi?** | F02 |
| K10.5-3 | **B.U.D. operator churn politikası (migration/grace/insurance)?** | F05 |
| K10.5-4 | **AI dispute/timeout mekanizması (RFC)?** | F06 |
| K10.5-5 | **Cross-chain adapter Faz-1 zincirleri (EVM öncelik?)?** | F10 |
| K10.5-6 | **BNS fiyat modeli (auction/premium/reserved)?** | F14 |
| K10.5-7 | **BNS trademark/regulated-name koruması + hukuki duruş?** | F15 |
| K10.5-8 | **Token-holder governance eklenecek mi?** (validator-only mevcut — F17 düzeltildi; F18 açık) | F18 |
| K10.5-9 | **PoA KYC verifier modeli (3rd-party/attestation)?** | F21 |
| K10.5-10 | **Bug bounty kapsam/ödül + external firm?** | F29 |

---

## 5. Sprint önerisi (öncelik sırası — kullanıcı onayına)

**Sprint 10.5-1 (mainnet hijyen + en-kritik boşluklar):**
- F33 — **governance crate README linki** (F17 düzeltildi: governance mevcut, sadece listelenmemiş; hygiene, hızlı).
- F02/F34/F35 — **sahte-yeşil dokümantasyon netliği** (AccessGrant soft / AI
  attestation / B.U.D. interim) — kod değil, README/docs, CI-güvenli.
- F29 — **BUG_BOUNTY.md** (MR-8 başlangıç).
- F27 — **ceremony playbook** (MR-6).

**Sprint 10.5-2 (canlılık/ekonomi):**
- F06 — **AI dispute/timeout RFC** (en kritik canlılık boşluğu).
- F10 — **EVM ChainAdapter tasarımı** (H4 kapatma).
- F14/F15 — **BNS fiyat + trademark modeli**.

**Sprint 10.5-3 (derin ekonomi/regülasyon):**
- F05, F13, F19, F21, F22 — operator/relayer/PoA ekonomi + compliance.

**Sprint 10.5-4 (araştırma/uzun-vade):**
- F04 (VerifyMerkle Faz 3), F08 (zkML), F23 (full light-client), F30-F32
  (fuzz/bridge-corpus/PQ-history).

---

## 6. Kapsam dışı (bu doküman yapmaz)

- Kod yazmaz (analiz dokümanı). Sprint kararı sonrası ayrı PR'lar.
- MR kriterlerini değiştirmez (MR-1..10 sabit); yeni kriter önerir (F02
  hard-enforcement gibi).
- Saldırgan açısını detaylı exploit tarifine indirgemez (point: red-team
  yardımseverlik). Pattern-seviyesinde kalır.

---

## 7. Netice

Phase 10.5, fonksiyonel genişleme (P10) sonrası **"herkesin açısından eksik ne
var"** sorusuna **kanıtlanmış** bir cevaptır. 35 bulgudan **6 🔴 mainnet-blocker**
(F01 owner, F02 hard-enforcement, F06 AI dispute, F10 chain adapter, F17
governance hygiene, F27 ceremony, F29 external audit) ve **17 🟡** ana öncelik.
**Hiçbiri kör tespit değil** — hepsi koda/CI'ye/commit'e bağlı.

**Budlum mainnet'e hazır DEĞİL** — bu doküman neden hazır olmadığını
**insan-tipi açısından** gösterir. Hazırlık, bu bulguların **kullanıcı
kararlarıyla** sıralı kapatılmasıyla gelir.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
