# CLAUDE.md — budlum-core

> Bu dosya AI ajanları (Cursor / Claude Code) her oturumda otomatik okur.
> Master Context + bu repoya özel kurallar aşağıdadır. Kapsam: sadece
> `budlum-core` (ağ / L1) ve 'te aynı repoya alınan `budzero/`
> (BudZKVM). Diğer bileşenler (DeEd, SocialFi, B.U.D., Budlum Go, DeArt,
> katılım bankası) bu talimat setinin dışındadır.

---

## 1. Master Context

```
PROJE: Budlum — "Evrensel Mutabakat Katmanı" (Universal Settlement Layer)
Açık kaynaklı, çok-konsensüslü (PoW/PoS/BFT + izole bir PoA domain) bir
Layer-1 blok zinciri.

Mimari ilkeler:
- Ağın GENELİ PERMISSIONLESS: PoW/PoS/BFT domain'lerinde validator/verifier/
  relayer kaydı için whitelist, onay mekanizması veya merkezi kapı YOK.
  Katılım = stake yatırma. Güvenlik ekonomik teşvik (stake) + slashing ile
  sağlanır, izinle değil.
- İSTİSNA — PoA domain: Kurumsal/regüle taraflar (bankalar, katılım bankası
  pilotu gibi) için bilinçli, izole bir permissioned alt-alan. Bu domain'e
  girişte KYC/onay gerekir — bu, ağın geri kalanının permissionless
  önermesini bozmaz çünkü sınırları net ve izoledir. PoA domain kuralları
  diğer domain'lere sızmamalı.
- ConsensusDomain: farklı konsensüs mekanizmalarının izole alanlar (domain)
  olarak bir arada yaşayabildiği bir soyutlama.
- CrossDomainMessage: domain'ler arası mesajlaşma primitive'i, replay
  koruması ve sıralama garantisiyle.
- Modülerlik önceliklidir. Monolitik entegrasyon ile modüler/unbundling tezi
  (bkz. Celestia, EigenLayer) arasındaki gerilimi varsayımla çözme — belirsizse
  soru sor.

YASAK: PoW/PoS/BFT domain'lerindeki validator/verifier/relayer rollerine
whitelist, admin-approval veya merkezi izin adımı ekleme. PoA domain'inin
izinli kurallarını diğer domain'lere sızdırma veya tersini yapma.
```

---

## 2. `budlum-core` (Ağ / L1)

```
KAPSAM: Multi-consensus, permissionless L1 çekirdeği.

- ConsensusDomain soyutlaması: PoW, PoS, BFT domain'leri permissionless
  çalışır. Ayrıca bir de PoA domain var — bu, kurumsal/regüle taraflar
  (banka, katılım bankası pilotu vb.) için tasarlanmış, bilinçli olarak
  permissioned/izinli bir alt-alan:
  * PoA domain'ine katılım stake ile değil, KYC/kimlik doğrulama + onay
    akışıyla olur (kayıt mekanizması diğer domain'lerden farklı, ayrı
    bir modülde tutulmalı).
  * PoA domain'indeki yetkili/onaylı taraf listesi, PoW/PoS/BFT
    domain'lerindeki permissionless registry'den TAMAMEN AYRI tutulmalı
    — ikisi aynı registry/veri yapısını paylaşmamalı.
  * CrossDomainMessage üzerinden PoA domain ile diğer domain'ler arasında
    mesajlaşma mümkün olmalı, ama PoA'nın izin kuralları diğer domain'lere
    sızmamalı.

- CrossDomainMessage: domain'ler arası atomik/asenkron mesajlaşma.

- Permissionless Verifier/Validator Registry:
  * Herkes stake yatırarak kayıt olabilir, minimum stake miktarı ve
    unbonding (çözülme) süresi net tanımlanmalı.
  * Slashing koşulları (double-sign, liveness ihlali, kötü niyetli
    davranış) açıkça kodlanmalı.
  * Bu registry, ileride diğer uygulama katmanlarının (bu talimat
    setinin kapsamı dışında) da kullanacağı ortak bir primitive
    olacak — bu yüzden rol bazlı genişletilebilir tasarlanmalı
    (generic role/permission tipi, hard-coded rol listesi değil).

- Permissionless Relayer:
  * Herhangi biri relayer olabilir, stake + slashing ile güvenlik.
  * Sabit/whitelist'li relayer seti KODLAMA.

- RPC API: Relayer modeli netleştiği için (permissionless) RPC uç noktaları
  buna göre tasarlanabilir — relayer kaydı, proof submission, slashing
  sorgulama uçları dahil. **,  — B.U.D. storage RPC yüzeyi
  (permissionless)**: `bud_storageRegisterManifest`,
  `bud_storageGetManifest`, `bud_storageGetDealsByManifest`,
  `bud_storageGetDealsByShard`, `bud_storageOpenChallenge`,
  `bud_storageAnswerChallenge`, `bud_storageGetOutcome`. Hepsi
  herkes tarafından çağrılabilir; admin-only uç YOK; whitelist YOK;
  "Budlum Inc. indexer" servisi bağımlılığı YOK (data-sovereignty
  kuralı,  plan §0.5).

KABUL KRİTERLERİ:
- Yeni bir domain tipi eklendiğinde mevcut testler kırılmamalı.
- Validator/relayer kaydı akışı: izinsiz herhangi bir hesabın stake
  yatırarak katılabildiğini doğrulayan test zorunlu (negatif test:
  "whitelist olmadan da katılabiliyor mu" kontrolü).
- İzolasyon testi: PoA domain'inin izin kurallarının PoW/PoS/BFT
  domain'lerine sızmadığını, ve tersinin de doğru olduğunu (permissionless
  bir hesabın PoA domain'ine KYC/onay olmadan giremediğini) doğrulayan
  testler zorunlu.
```

---

## 3. Genel Standartlar

- Her yeni modül testsiz merge edilmez.
- README'de "bu repo neyi YAPMAZ" bölümü olsun (kapsam sızıntısını önlemek için).
- AI bir mimari belirsizlikle karşılaşırsa (özellikle PoA domain'inin izolasyon
  sınırları gibi), varsayım yapıp kod yazmak yerine `// TODO(karar-gerekli): ...`
  yorumu bırakıp devam etsin.
- Cross-repo bağımlılık (Verifier Registry, ConsensusDomain, CrossDomainMessage)
  paket/submodule olarak referans verilsin, kopyala-yapıştır edilmesin.

---

## 4. Uygulama Durumu (mevcut kod haritası)

- **Monorepo ():** BudZero/BudZKVM kaynakları `budzero/` altındadır.
  L1 path dependency'leri in-tree'dir; sibling checkout/pin geri getirme.
  `budzero/CLAUDE.md` ZK katmanı için ek kuralları taşır.
- **B.U.D. ():** `ConsensusKind::StorageAttestation(StorageDomainParams)`
  yeni enum varyantı (vizyon §8.1, Custom(String) DEĞİL). Muhasebe  =
  yalnızca domain kaydı;  = content addressing + manifest;
   = deal/challenge ekonomisi. **`RetrievalChallenge` interim'dir** —
   (gerçek Proof-of-Storage) BudZKVM `VerifyMerkle` 64-depth
  production gate'ine bağlıdır. Z-B gate kapanana kadar "proof-of-storage"
  iddiası YAPILMAZ (sahte-yeşil yol riski, vision §9.1).

Permissionless katılım modeli ve PoA izolasyonu şu modüllerde uygulanmıştır:

- `src/registry/role.rs` — generic `RoleId` (hard-coded enum değil). Bilinen
  roller: `roles::VALIDATOR / VERIFIER / RELAYER / PROVER / STORAGE_OPERATOR`.
  `STORAGE_OPERATOR` (RoleId 5) **, **: permissionless, stake ile
  kayıt; whitelist YOK. (Deal açmak için bu role gerekli DEĞİL — `open_deal`
  permissionless; `STORAGE_OPERATOR` yalnızca ödül/eligibility için
  kullanılacak,  takibi.)
- `src/registry/permissionless.rs` — `PermissionlessRegistry`: stake ile kayıt,
  min stake + unbonding, slashing. Whitelist/onay YOK.
- `src/registry/poa_membership.rs` — `PoaMembershipRegistry`: KYC + admin onayı
  ile giriş; TAMAMEN AYRI veri yapısı (stake kavramı yok).
- `src/registry/params.rs` — `RegistryParams`: min_stake, unbonding_epochs,
  slash oranları. Governance/config ile ayarlanabilir; HARD-CODE ETME.
- `src/registry/evidence.rs` — `SlashingReport`/`SlashingProof`: consensus, RPC
  ve diğer domain'lerin ortak kullanacağı kanonik slashing evidence formatı.
  `ProofProvenance::ConsensusVerified` olmayan rapor slash TETİKLEMEZ.
- `src/registry/liveness.rs` — `LivenessTracker`: validator'ların ardışık
  katılım-kaçırma sayacı. Eşik (`RegistryParams::liveness_max_missed_epochs`,
  varsayılan 10) aşılınca kanonik `Liveness` raporu üretir. Ardışık sayım;
  katılımda sıfırlanır (kümülatif DEĞİL).
- `src/domain/storage_params.rs` — **,  (B.U.D.)**:
  `StorageDomainParams` (chunk_size, max_committed_chunks,
  challenge_interval, min_operator_bond) + `validate()` + domain-tagged
  `storage_params_bytes()`. Bkz. vizyon §8.1.
- `src/domain/storage_deal.rs` — **,  (B.U.D. deal/challenge
  ekonomisi)**: `StorageDeal` + `StorageRegistry` (BTreeMap-backed,
  permissionless) + `RetrievalChallenge`/`Response`/`Outcome`/
  `ChallengeResult`. KRİTİK SINIRLAMA: `RetrievalChallenge` **gerçek
  Proof-of-Storage DEĞİLDİR** — operatör sadece istenen byte-range'i
  saklayarak testi geçebilir. Tam kanıt (, vision §8.3) BudZKVM
  `VerifyMerkle` + 64-depth SMT production gate'ine bağlıdır; o
  Z-B gate'i kapanana kadar "interim retrieval challenge" etiketi
  zorunludur (README/CLAUDE.md'de açıkça yazılı). Whitelist/
  admin/pause hook'u YOK — data-sovereignty kuralı ( plan §0.5).
- `src/storage/content_id.rs` — **,  (B.U.D. content
  addressing)**: `ContentId` (32-byte domain-tagged SHA-256).
  `of_subrange` byte-range hash (interim) — gerçek proof DEĞİL.
- `src/storage/manifest.rs` — **, **: `ContentManifest` +
  `ShardRef`. Parçalama off-chain; zincir sadece `(manifest_id, shard_id,
  size)` taşır (BudZKVM STARK kanıtı analoğu).
- `src/domain/finality_adapter.rs` — domain finality doğrulayıcıları. Güvenlik
  durumu (-7 sonrası — TÜM aile gerçek doğrulama yapıyor): PoS gerçek BLS
  cert doğrular (`cert.verify`); **BFT** aynı desende gerçek BLS cert doğrular
  (self-reported signer_count KALDIRILDI, ); **PoW** proof'u commitment'a
  bağlar (`declared_head_hash == commitment.domain_block_hash`) +
  declared_cumulative_work iç tutarlılık + min-work eşiği (; tam
  light-client DEĞİL, o ayrı iş); ZK `ProofClaimRegistry` üzerinden gerçek STARK
  (); **PoA** gerçek ed25519 imza kümesi doğrular (`FinalityProof::PoA` artık
  `authorities: Vec<Address>` + `signatures: Vec<PoAAuthoritySignature>` taşır,
  `poa_commit_signing_message` ile commitment'a bağlı, SAYI-bazlı quorum — ).
  KRİTİK: PoA doğrulaması stake mekanizmasına/permissionless registry'ye
  BAĞLANMADI; PoA kendi ayrı stake-siz ed25519 modelini kullanır (-2
  izolasyonu korunur). PoA'da stake YOK (bilinçli). Yeni proof alanı eklerken
  `#[serde(default)]` kullan (geriye uyumluluk).
- `src/tokenomics/mod.rs` — $BUD tokenomik (). Arz 100M, **6 ondalık**
  (`BUD_UNIT=10^6`; balance u64, 18 ondalık SIĞMAZDI). `TokenomicsParams`
  (config, hard-code değil): dağıtım (Community/Likidite/Ekosistem/Team 10/10/20/20M
  + Yakım Rezervi 40M), yıllık yakım oranı, epochs_per_year, tx_fee_burn_ratio,
  team vesting (cliff+lineer, Seçenek B). İki yakım: (3.1) zamanlı rezerv yakımı
  `AccountState::process_timed_burn` (epoch-tetiklemeli, kullanıma bağlı DEĞİL),
  (3.2) metabolik tx-fee yakımı `Executor::apply_block` içinde. Burn =
  `AccountState::burn_from` (bakiyeden düş, hiçbir yere ekleme — arz sadece azalır).
  Arz = `AccountState::circulating_supply()` (ayrı total_supply alanı YOK).
  NOT: blok üretimi hâlâ `block_reward` basıyor (ayrı emisyon); "sadece azalan"
  özelliği yakım YOLLARI için geçerli (yakım mint ile telafi edilmez).
  ENTEGRASYON (b — gerçek zincir akışına bağlı): (a) genesis:
  `GenesisConfig::with_bud_tokenomics()` → `build_state()` dağıtımı seed'ler +
  `AccountState.burn_reserve_address` ve `team_vesting` alanlarını kurar (default
  genesis DEĞİŞMEZ — ayrı opt-in constructor). (b) zamanlı yakım:
  `AccountState::advance_epoch` sonunda (kanonik epoch-geçişi) otomatik tetiklenir.
  (c) vesting: `Executor::apply_transaction_checked` team hesabının bakiyesini
  `spendable_balance` (= balance − locked_at(epoch)) altına düşüren transferi
  `vesting_locked` ile reddeder. NOT (bilinen boşluk): `burn_reserve_address`/
  `team_vesting` DÜZELTİLDİ (): artık snapshot'a girip çıkıyor.

- State persistence (): `StateSnapshotV2` `schema_version=3` ile `registry`,
  `liveness`, `tokenomics` + atomik `tokenomics_burn` (TokenomicsBurnSnapshot =
  timed_burn + burn_reserve_address + team_vesting) alanlarını taşır. Yeni alanlar
  `#[serde(default)]` (eski schema-2 snapshot'lar hatasız yüklenir, alanlar boş gelir).
  Restore: `AccountState::from_snapshot_v2`. **KRİTİK:** tokenomics_burn üçlüsü TEK
  atomik blok olarak restore edilir — timed_burn sayacını burn_reserve_address'siz
  (veya tersi) restore etmek ÇİFTE YAKIMA yol açar (test: `no_double_burn_after_restore`).
  Sadece V2 genişletildi (V1 salt taşıma-zarfı: üretim `__v2__`+hex gömer).
  DÜZELTİLEN BUG: `PermissionlessRegistry.registrations` `(RoleId,Address)` tuple-key
  BTreeMap idi → serde_json JSON'a çeviremiyordu (sessizce boş çıktı). Artık
  `registrations_as_seq` ile Vec<Registration> olarak (de)serialize ediliyor.
  KAPSAM DIŞI (bu turda YOK): PoSV, $LUM, launchpad/presale, yakım oran modeli.
- Sessiz-hata sertleştirmesi (): serialize-into-hash/persistence/network
  yollarındaki `unwrap_or_default()` (sessizce boş byte'a düşen kalıp) elendi.
  Strateji (A3 hibrit): (a) HASH girdileri (`prover::payload_binding_hash`,
  `hash_finality_proof`, `block::calculate_hash_bytes`, `transaction` data/`to_bytes`)
  → `.expect(...)` fail-fast (sessiz-boş hash = çakışma/güvenlik ihlali; bincode/
  serde plain tip için saldırgan-tetiklenemez, deterministik bug). (b) PERSISTENCE:
  `StateSnapshotV2::try_to_bytes() -> Result` eklendi; durable snapshot üretim yolu
  (`get_state_snapshot`) hata olursa `None` döner (sessiz boş snapshot yok);
  `to_bytes()` fail-fast `.expect`. (c) NETWORK/proto + `consensus::mod` blok-boyut:
  davranış korunur AMA `tracing::error!`/`ConsensusError` ile GÖRÜNÜR.
  Option/`rx.await` ailesi (`unwrap_or_default`, Kova B) bilinçli DOKUNULMADI
  (meşru "değer yok" varsayılanı, hash/persistence/network'e girmiyor).
- `src/prover/mod.rs` — permissionless ZK prover köprüsü. `ZkProofSubmission`
  (CrossDomainMessage + ProofEnvelope + public inputs + program),
  `ProofClaimRegistry` ("ilk geçerli kazanır" politikası). Model: kayıt ŞART
  DEĞİL (STARK kendini doğrular); `roles::PROVER` sadece ÖDÜL için opsiyonel.
- `roles::PROVER` (RoleId 4) — `src/registry/role.rs`.

Entegrasyon noktaları:
- Stake tx → kayıt: `Executor::apply_transaction_checked` (Stake/Unstake) ve
  `AccountState::add_validator` çağrıları `sync_validator_registration` ile
  registry'yi otomatik günceller. Manuel kayıt çağrısı YOK.
- Relayer → CrossDomainMessage kapısı: `Blockchain::submit_relayed_cross_domain_message`
  gönderenin registry'de aktif RELAYER olduğunu `registry.is_active_relayer`
  (active VEYA unbonding; slashed/unregistered değil) ile doğrular. RPC
  (`bud_submitCrossDomainMessage`) ve p2p gossip bu yoldan geçer; köprü-üretimi
  mesajlar iç primitive `submit_cross_domain_message`'ı kullanır (kapı yok).
  Relayer kaydı: `AccountState::bond_relayer` / RPC `bud_registryBondRelayer`.
- Slashing evidence → slash: `Blockchain::submit_slashing_evidence` doğrulanmış
  kanıtı `SlashingReport`'a çevirip `registry.slash_from_report` çağırır.
  `AccountState::slash_validator` da registry'ye yansıtır.
- Liveness → epoch akışı (): `Blockchain::maybe_observe_liveness_on_epoch_close`
  iki commit yolunda (`produce_block`, `validate_and_add_block`) `self.chain.push`
  sonrası çağrılır; epoch kapanınca `collect_epoch_participants(epoch)` ile
  katılımcıları TÜRETİR (yeni state alanı YOK): (1) epoch aralığındaki blokların
  `producer`'ları + (2) BFT `FinalityCert` bitmap→snapshot.validators[i].address
  (`signer_indices`). Katılımcı kümesi `AccountState.validators` (permissionless) —
  PoA domain üyeliği (`PoaMembershipRegistry`) buraya HİÇ girmez.
- Liveness DISPATCH (): `maybe_observe_liveness_on_epoch_close` artık
  `RegistryParams::liveness_slashing_enabled` bayrağına göre ayrışır:
  * `true`  → `Blockchain::record_liveness_epoch` = GERÇEK slash
    (`submit_registry_slashing_report` akışı; stake keser VE `slash()` jail eder).
  * `false` (VARSAYILAN) →  `observe_liveness_epoch` = rapor + `tracing`
    log, ekonomik etki YOK.
  Varsayılan KAPALI: `slash()` her ihlalde jail ettiği için %1 downtime cezası
  bile jail eder — bu geri-dönüşü zor sonuç ancak operatör/governance bilinçli
  `true` yapınca aktifleşir ( "önce gözlemle, canlı/testnet'te doğrula,
  sonra aç" kuralı). `record_liveness_epoch` mekanizması 'ten beri var+test
  edilmişti;  sadece canlı akıştan erişilebilir kıldı. Kademeli ceza
  (liveness'te jail yok) ayrı/gelecek tur — `slash()`'a dokunulmadı.
- Adversarial finality testleri (-14): `src/tests/finality_adversarial.rs`.
  BLS vote üretimi (`sign_prevote`/`sign_precommit`→`sign_bls`), sertifika yayını
  ve `FinalityCert::verify` akışını gerçek BLS anahtar çiftleriyle (mock DEĞİL)
  çok-validator simüle eder — libp2p kurmadan `FinalityAggregator` doğrudan
  çağrılır. Ayrıca uçtan uca `Blockchain` akışı (`handle_prevote`/`handle_precommit`).
- Aggregator sağlamlaştırması (, `FinalityAggregator`):
  * FIX 2 (ingest-time doğrulama, Seçenek A): `add_prevote`/`add_precommit` artık
    oyu snapshot'taki `bls_public_key`'e karşı `verify_bls_sig` ile DOĞRULAR;
    geçersiz imza aggregat'a HİÇ girmez. Sonuç: dürüst alt-küme her zaman finalize
    eder, tek kötü aktör round'u durduramaz (DoS kapatıldı). İmza kontrolü hash
    eşleşmesinden ÖNCE yapılır (çelişkili-hash oyu ancak geçerli imzalıysa
    equivocation sayılır). BLS anahtarı olmayan validator artık oy VEREMEZ.
  * FIX 1 (equivocation → slashing): bir voter'dan farklı `checkpoint_hash`'e
    validce imzalı ikinci oy görülünce iki imza `SlashingReport::consensus_double_sign`
    (var olan `SlashingProof::DoubleSign`, YENİ tip YOK) ile paketlenir,
    `detected_equivocations`'a konur; `Blockchain::route_detected_equivocations`
    her `handle_prevote`/`handle_precommit` sonrası bunu TEK slash yolundan
    (`submit_registry_slashing_report`) geçirir — ikinci yol AÇILMAZ. Voter başına
    tek rapor (dedup). Provenance `ConsensusVerified` (iki imza ingest'te doğrulandı).
    Slash oranı `double_sign_slash_ratio_fixed` (varsayılan %50) + `slash()` jail eder.
  * finality.rs iç testleri artık gerçek imza kullanır (`signed_prevote` helper).
- Slashing kalıcılığı + geçmiş (, ): `PermissionlessRegistry`'ye
  `slashing_history: Vec<SlashingRecord>` (`#[serde(default)]`) eklendi. Her
  ACTIONED rapor (`slash_from_report`→`Ok(Some)`) TEK slash yolunun İÇİNDE
  geçmişe yazılır (ikinci yol YOK). `snapshot.registry` zaten round-trip ettiği
  için otomatik kalıcı. Sorgu: `registry.slashing_history()` /
  `slashing_history_for(&addr)`. Round-trip testi: `persistence.rs` +
  `finality_adversarial::equivocation_slashing_record_survives_snapshot_roundtrip`.
- Tekrarlı geçersiz-imza slashing (, ): yeni `InvalidVoteTracker`
  (`src/registry/invalid_vote.rs`, LivenessTracker deseni, EPOCH-bazlı sayaç,
  kalıcı) `AccountState.invalid_votes`'ta tutulur + `StateSnapshotV2.invalid_votes`
  round-trip eder. `Blockchain::maybe_track_invalid_vote`, `handle_prevote/precommit`
  bir "signature" hatasıyla reddettiğinde çağrılır (imza hatası ancak üyelik
  kontrolü GEÇTİKTEN sonra döner → gönderen kesin kayıtlı validator). Eşik
  `RegistryParams::max_invalid_votes_per_epoch` (varsayılan 20) aşılınca yeni
  `SlashingProof::InvalidSignatureSpam{epoch,count,threshold}` → `MaliciousBehaviour`
  (%100, ONAYLI karar: yeni oran param'ı YOK) → TEK slash yolundan geçer.
  Provenance `ConsensusVerified` (node imzayı kendi kriptografik olarak reddetti).
  NOT: aggregator her checkpoint'te (10 blok) sıfırlanır, epoch 100 blok → sayaç
  aggregator'da YAŞAYAMAZ, kalıcı tracker ZORUNLU.
- Evidence spam koruması: `submit_registry_slashing_report`, `reporter` alanı olan
  (harici) raporlardan `RegistryParams::slashing_report_fee` (varsayılan 10) fee
  alır; rapor actionable ise iade, değilse yakılır. Consensus-içi raporlar
  (`reporter: None`) fee ödemez. RPC yolu `provenance`'ı ZORLA `Unverified`
  yapar (çağıran ConsensusVerified iddia edemez).
- Prover → L1 köprüsü: `Blockchain::submit_zk_proof(ZkProofSubmission)`. Model B
  (tam açık): kayıt ŞART DEĞİL; kanıt CrossDomainMessage (kind=Custom("zk-proof"))
  ile gelir, payload_hash proof'a bağlanır. Akış: kind+bağlama kontrolü →
  `proof_submission_fee` (varsayılan 10; geçerliyse iade, geçersizse yakılır) →
  CORE-NATIVE STARK verify (`bud_proof::DefaultAdapter::verify`) → "ilk geçerli
  kazanır" (`ProofClaimRegistry`: aynı root idempotent, farklı root conflict) →
  kayıtlıysa `prover_reward` (varsayılan 50). Kayıt: `AccountState::bond_prover` /
  RPC `bud_registryBondProver`. Ödül kapısı: `registry.is_active_prover` (SADECE
  ödül; gönderim kapısı DEĞİL —  relayer kapısıyla karıştırma).
- Proof üretim yardımcısı: `execution::zkvm::prove_bytecode` (VM çalıştırır,
  public inputs türetir, ProofEnvelope üretir).
- RPC uçları (`src/rpc/api.rs`, `src/rpc/server.rs`): `bud_registryRegister`,
  `bud_registryBondRelayer`, `bud_registryBondProver`, `bud_submitZkProof`,
  `bud_registryQuery`, `bud_registryActiveMembers`, `bud_submitSlashingReport`.
  Whitelist/onay kontrolü YOK — sadece stake/imza/evidence/fee/STARK doğrulaması.

Testler: `src/tests/permissionless.rs` (stake→register, evidence→slash, PoA
izolasyon, parametre override, negatif whitelist) + `src/tests/relayer_liveness.rs`
(relayer kapısı, fee/iade, liveness üretimi) + `src/tests/prover.rs` (permissionless
prover: kayıtsız kabul/ödülsüz, kayıtlı ödüllü, geçersiz→fee yakma, çakışma,
idempotent) + ilgili modüllerin `#[cfg(test)]` blokları.

Değişiklik yaparken: bu izolasyon ve permissionless garantilerini KIRMA; yeni
akış eklerken `src/tests/permissionless.rs`'e karşılık gelen test ekle.
