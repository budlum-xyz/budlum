# Budlum Task 12.5 — Kalan İşler ve Sertleştirme Raporu

> **Hazırlayan:** ARENA4
> **Tarih:** 2026-07-21 14:00 UTC+03:00
> **Zemin:** `main` — son doğrulanan zemin `5120f440` (`31/31` CI green).
> **Durum:** Task 12 ana primitive/API/spec turu tamamlandı; Task 12.5 entegrasyon, RPC, state-root, cryptographic verification ve mainnet-hardening turu olarak yürütülür.
> **Kural:** Bundan sonra çalışma yalnız `main` üzerinde yapılır. Feature branch açılmaz. Her push sonrası CI SLEEP zorunludur.

---

## 0. Kısa özet

Task 12'de onaylanan ana sistemlerin tamamına ilk kod katmanı girildi:

- Pollen / Data Rights
- AI read-denial hardening
- Encryption DAO parameters
- Relayer Policy Layer
- D-Web Passport / budlum.xyz
- Sovereign Domain Kit
- Budlum Atlas / bud.scan
- Mobile Self
- Governance / Constitution Engine
- Proof Verification Market / LUM hazırlığı
- Developer OS / BudL SDK

Task 12.5'in amacı bu sistemleri **mainnet hazırlığına yaklaştırmak** için şu eksenlerde derinleştirmektir:

1. RPC/query/transaction yüzeylerinin tamamlanması.
2. Gerçek kriptografik doğrulama ve payment/escrow bağlarının eklenmesi.
3. State-root ve pruning/bounded-state bağlarının netleştirilmesi.
4. ARENA1/ARENA2/ARENA3/ARENAS commitlerinin main üzerinde bağımsız incelenmesi.
5. CI yeşil kanıtı olmadan hiçbir ADIM'in kapatılmaması.

---

## 1. Mutlak kurallar

1. **Sadece main:** Tüm uygulama ve düzeltmeler doğrudan `main` üstünde yapılır.
2. **CI tek hakem:** Lokal statik kontroller yardımcıdır; GitHub CI kırmızıysa yeni kapsam açılmaz.
3. **SLEEP mode:** Her push sonrası CI tamamlanana kadar beklenir. Kırmızıysa aynı push hattı düzeltilir.
4. **Büyük branch merge yok:** Dış/ajan branchleri doğrudan alınmaz; diff incelenir, küçük ve CI-kanitli parçalar uygulanır.
5. **budlumdevnet salt-okunur:** Referans dışında kullanılmaz, değiştirilmez.
6. **LUM bağlantısı yok:** Proof Verification Market LUM'a hazırlanır ama LUM/DeFi adapter bağlanmaz.
7. **DAO decrypt edemez:** Governance/Constitution/Encryption hiçbir şekilde kullanıcı verisini okuyamaz, decrypt edemez, AI read override veremez.
8. **Permissionless çekirdek korunur:** PoA/Sovereign/enterprise kuralları permissionless PoW/PoS/BFT çekirdeğe sızamaz.
9. **Commit inceleme kuralı:** Başka ajanların attığı commitler CI/diff/test kanıtı olmadan kabul edilmez.
10. **Raporlama:** STATUS_ONLINE yalnız ADIM başlangıç/kapanış, CI kırmızı kök-neden ve kullanıcı açısından önemli kararlar için güncellenir.

---

## 2. Tamamlanmış Task 12 / erken Task 12.5 zemini

### 2.1 Pollen / Data Rights

Tamamlananlar:

- `DataAsset`
- `AccessGrant`
- `AiDataInputRef`
- AI read gate
- `SaleAuthorization`
- Transaction-backed Pollen register/grant/revoke
- `PollenPurchaseReceipt`
- SaleAuthorization-backed grant issue primitive
- `bud_pollenGetDataAssets`
- `bud_pollenGetAccessGrants`
- `bud_pollenGetSaleAuthorizations`
- `bud_pollenBuildAiInputRef`
- `bud_pollenPrepareSaleAuthorization`
- `bud_pollenGetPurchaseReceipts`
- `bud_pollenPreparePurchase`

Güvenlik durumu:

- DataAsset sahipliği devredilmez; satılan şey bounded access pollen/grant'tir.
- AI Pollen data-ref, geçerli AccessGrant olmadan kabul edilmez.
- Purchase RPC prepare-only çalışır; LUM/DeFi/payment adapter state mutation yapmaz.

Kalanlar Task 12.5 içinde aşağıda listelendi.

### 2.2 Encryption DAO

Tamamlananlar:

- Pollen `EncryptionPolicy` DAO parameter primitive.
- Detailed `pollen::encryption_policy` modülü compile/test kapsamına alındı.
- `EncryptionAlgorithm::None` default ve asset policy için fail-closed reddedildi.
- Static validation ve asset policy validation eklendi.

Kalanlar:

- İki policy modelinin canonical hale getirilmesi.
- Grant duration enforcement.
- Deprecated policy enforcement.
- HPKE suite metadata binding.

### 2.3 Relayer Policy Layer

Tamamlananlar:

- `PolicyEnvelope`
- `UserIntent`
- `SolverBid`
- `IntentSettlement`
- `RelayerPolicyRegistry`
- Intent/bid/settlement lifecycle.
- Zero owner/domain/action/hash/proof-commitment guardrails.
- Duplicate bid ve expired settlement reject.

Kalanlar:

- Executor/state integration.
- Bond/slash accounting.
- Fee settlement.
- Solver selection RPC.

### 2.4 D-Web Passport / budlum.xyz

Tamamlananlar:

- `bud_passportGetProfile`
- `bud_passportGetProofBundle`
- Evidence-only proof bundle root.
- Warning plaintext yerine warning hash.
- Passport name validation.

Kalanlar:

- budlum.xyz handoff paketi.
- light-client proof binding.
- Passport + Atlas unified evidence card.

### 2.5 Sovereign Domain Kit

Tamamlananlar:

- `SovereignDomainTemplate`
- `ComplianceEvidence`
- `AuditExportBundle`
- `SovereignDomainRegistry`
- Lifecycle transition guard.
- PoA/KYC isolation.
- Zero compliance root reject.
- Audit export bounded range.

Kalanlar:

- Tx/RPC lifecycle.
- Governance proposal class binding.
- Frozen/retired runtime behavior.
- Audit export endpoint.

### 2.6 Budlum Atlas / bud.scan

Tamamlananlar:

- Wallet context.
- RPC Atlas model compile/test kapsamı.
- Evidence/domain/trace/wallet graph validation.
- Bounded insert/upsert.

Kalanlar:

- Address/event index.
- `query_evidence_for_address` gerçek implementasyonu.
- Atlas + Passport + Pollen + Mobile unified graph.

### 2.7 Mobile Self

Tamamlananlar:

- Storage-side `MobileSelfProfile`.
- Network-side `MobileNodeProfile`.
- Battery/network/storage/NAT validation.
- Relay address validation.
- Critical data requires paid replica.

Kalanlar:

- RPC/profile query.
- Passport/Atlas evidence integration.
- Battery-aware challenge scheduler.
- secure OS key storage spec.

### 2.8 Governance / Constitution Engine

Tamamlananlar:

- Constitution registry.
- Hard guardrails.
- No AI read override.
- No decrypt authority.
- No permissionless whitelist/admin leak.
- Parameter timelock and vote snapshot work from ARENA1 main series is now part of main.

Kalanlar:

- Constitution/Task12 parameter classes with explicit severity levels.
- Emergency halt guardrails.
- Task12-specific DAO parameter governance wiring.

### 2.9 Proof Verification Market

Tamamlananlar:

- Prover-side proof market primitive.
- Settlement-side `ProofTask`, `ProofReceipt`, `ProofMarketState` hardening.
- Receipt validation binds assigned prover, epoch window, reward cap, verification hash.
- Invalid receipt does not drop active task.
- Root binding over counters/tasks/receipts.

Kalanlar:

- Real proof verifier adapters.
- Bond/slash hooks.
- Reward settlement.
- LUM future adapter interface without live connection.

### 2.10 Developer OS / BudL SDK

Tamamlananlar:

- `DeveloperOsManifest`
- BudL package fixture
- proof fixture
- Pollen fixture
- relayer policy fixture
- docs skeleton

Kalanlar:

- CLI commands.
- Devnet runner.
- Fixture generation.
- Wallet signing helpers.
- ARENA2 BudL compiler hardening integration into SDK docs/workflow.

---

## 3. Task 12.5 kalan işler — sıralı ADIM listesi

### P12.5-2 — Pollen cryptographic authorization verification

Amaç:

SaleAuthorization ve AccessGrant imza alanlarını sentinel reject seviyesinden gerçek cryptographic verification seviyesine taşımak.

Kapsam:

- Seller/owner public key source belirlenmesi.
- `SaleAuthorization::signing_hash` doğrulama adapter'ı.
- `AccessGrant` owner signature doğrulama adapter'ı.
- Replay-domain separation denetimi.
- Buyer-submitted purchase flow için signature verification point.

Kabul kriterleri:

- Wrong seller signature reject.
- Wrong owner signature reject.
- Sentinel signature reject korunur.
- Authorization id canonical preimage mismatch reject.
- Grant id canonical preimage mismatch reject.
- Signature verification fail olursa state mutation yok.

Risk:

- Public key/account modeline bağlanırken transaction signing v4 ile çakışma olabilir.
- Bu ADIM küçük tutulmalı; ödeme adapter'ı aynı committe bağlanmamalı.

---

### P12.5-3 — Pollen purchase transaction / state mutation

Amaç:

`bud_pollenPreparePurchase` ile hazırlanan grant/receipt'i gerçek transaction-backed state mutation akışına taşımak.

Kapsam:

- New transaction variant veya mevcut Pollen tx genişletmesi.
- Buyer/payer authorization.
- Payment commitment kayıt/yakalama.
- `MarketplaceRegistry.issue_grant_from_sale_authorization` executor path.
- Receipt query pagination.

Kabul kriterleri:

- Expired SaleAuthorization reject.
- Max grants exhausted reject.
- Payment commitment zero reject.
- Grant expiry authorization expiry'yi gorevz.
- Duplicate grant/receipt reject.
- DataAsset ownership değişmez.

Risk:

- Transaction enum/proto/signing hash genişlemesi CI kırabilir; proto roundtrip şart.

---

### P12.5-4 — Encryption policy unification and enforcement

Amaç:

`data_rights::EncryptionPolicy` ile `pollen::encryption_policy::EncryptionPolicy` arasındaki canonical rolü netleştirmek.

Kapsam:

- Canonical DAO policy seçimi.
- Simple policy compatibility layer.
- Grant duration max bound enforcement.
- Deprecated policy reject.
- HPKE suite id / min key length enforcement.
- AccessGrant issue path'te policy check.

Kabul kriterleri:

- DAO decrypt authority yok.
- `EncryptionAlgorithm::None` default olamaz.
- Deprecated/inactive policy ile yeni grant açılamaz.
- Existing grants policy migration döneminde korunur.
- State root non-default policy update ile değişir.

---

### P12.5-5 — Relayer Policy executor integration

Amaç:

Relayer policy registry'yi pure primitive seviyesinden executor/state seviyesine taşımak.

Kapsam:

- Intent submit tx.
- Solver bid tx.
- Settlement tx.
- Bond escrow.
- Slash condition binding.
- Query RPC.

Kabul kriterleri:

- No relayer whitelist.
- Permissionless solver bid.
- Expired intent cannot settle.
- Duplicate settlement reject.
- Paid fee quoted fee'i gorevz.
- Invalid proof commitment reject.
- Slash evidence hash zorunlu.

---

### P12.5-6 — Passport + Atlas unified evidence

Amaç:

D-Web Passport proof bundle ve Atlas evidence modellerini tek kullanıcı görünümünde birleştirmek.

Kapsam:

- Passport proof bundle Atlas evidence card olarak expose edilir.
- `bud_atlasGetWalletContext` içine passport summary opsiyonel eklenir.
- Pollen lineage + BNS + manifest + Mobile Self + Sovereign summary.
- Evidence status confidence policy.

Kabul kriterleri:

- Raw data/plaintext yok.
- Warning text public bundle'da yok; hash var.
- Expired BNS `Unverified`.
- Missing manifest `Pending`.
- Evidence list bounded.

---

### P12.5-7 — Sovereign Domain tx/RPC/governance lifecycle

Amaç:

Sovereign Domain Kit'i register/query/lifecycle transition seviyesine taşımak.

Kapsam:

- Template register tx/RPC.
- Lifecycle transition tx/RPC.
- Audit export query.
- Governance proposal class binding.
- Frozen/retired domain runtime behavior spec.

Kabul kriterleri:

- EnterprisePoa non-PoA olamaz.
- PoA requires KYC.
- non-PoA KYC leakage reject.
- Retired reactivation reject.
- Audit roots nonzero and bounded.
- Registry root state-bound.

---

### P12.5-8 — Mobile Self RPC / Atlas / Passport integration

Amaç:

Mobile Self profilini kullanıcıya, Passport'a ve Atlas'a görünür hale getirmek.

Kapsam:

- Mobile profile query.
- Mobile content policy query.
- Atlas mobile evidence card.
- Passport mobile availability label.
- Paid replica recommendation surface.

Kabul kriterleri:

- Opportunistic device always-online iddiası kuramaz.
- Critical content paid replica olmadan geçmez.
- Invalid battery/storage/NAT reject.
- Private key / OS secret data exposed olmaz.

---

### P12.5-9 — Proof Verification Market adapters

Amaç:

Proof market task/receipt modelini gerçek proof sources ile bağlamak.

Kapsam:

- BudZKVM / VerifyInference adapter.
- Settlement event proof adapter.
- Storage challenge proof adapter.
- Receipt verification context hash.
- Prover eligibility.

Kabul kriterleri:

- Invalid proof fail-closed.
- Receipt cannot pay without valid assigned task.
- Invalid receipt task kaybettirmez.
- Reward cap enforced.
- LUM adapter live bağlantısı yok.

---

### P12.5-10 — Developer OS / BudL SDK practical workflow

Amaç:

Developer OS manifest iskeletini gerçek geliştirici akışına çevirmek.

Kapsam:

- `budlum dev new` skeleton.
- `budlum dev fixture pollen`.
- `budlum dev fixture proof`.
- `budlum dev run`.
- Wallet signing V4 helper docs.
- BudL compiler hardening docs.

Kabul kriterleri:

- Offline default.
- Path traversal reject.
- Deterministic project id.
- Zero proof hash verified fixture reject.
- AI grant bypass fixture reject.

---

### P12.5-11 — Task 11.x main integration review

Amaç:

ARENA1/ARENA2/ARENA3 tarafından main'e taşınan Task 11.8–11.18 işleriyle Task 12 sistemlerinin çakışmadığından emin olmak.

İncelenecek ana hatlar:

- EIP-1559 transaction fee fields.
- Economy invariant gate.
- Fork-choice primitives.
- Storage provider/lifecycle/projection.
- Node classification / pruning policy.
- Network hardening gate.
- Wallet multisig/social recovery/binding stubs.
- Governance timelock/vote snapshot.
- PoA compliance isolation.
- PKCS#11/YubiHSM path.

Kabul kriterleri:

- Task 12 Pollen/payment logic fee market ile uyumlu.
- Relayer policy settlement fee market ile çakışmaz.
- Sovereign PoA isolation compliance registry ile çakışmaz.
- Wallet binding Developer OS ile belgelenir.
- CI gate isimleri güncel kalır.

---

### P12.5-12 — Bounded-state and pruning audit pass

Amaç:

Task 12 modüllerinin uzun çalışan node'larda sınırsız büyüme oluşturmamasını sağlamak.

Kapsam:

- Pollen purchase receipts.
- Pollen access grants.
- Relayer intents/bids/settlements.
- Passport/Atlas evidence caches.
- Proof market receipts/tasks.
- Sovereign template registry.
- Mobile profiles.

Kabul kriterleri:

- Her Vec/BTreeMap ya bounded ya state-root gerekçeli.
- Prune method/test mevcut.
- Paid/expired/revoked kayıtlar için retention policy var.
- CI regression test isimleri var.

---

## 4. Risk kayıtları

### R1 — Pollen signature verification

Risk:

Public key source ve signing hash V4 uyumu yanlış bağlanırsa geçerli imza reddedilebilir veya yanlış imza kabul edilebilir.

Önlem:

Önce pure verify adapter + test; sonra executor path.

### R2 — Payment / escrow integration

Risk:

Pollen purchase state mutation payment olmadan grant üretebilir.

Önlem:

Payment commitment şu an prepare-only; gerçek settlement ayrı ADIM.

### R3 — Encryption policy dual model

Risk:

İki policy modeli farklı truth source gibi davranır.

Önlem:

Canonical model kararı ve compatibility wrapper.

### R4 — Relayer policy slashing

Risk:

Solver bond/slash evidence yanlış bağlanırsa permissionless relayer güvenliği zayıflar.

Önlem:

Evidence hash / proof commitment / settlement receipt binding.

### R5 — Passport/Atlas plaintext leak

Risk:

UI evidence yüzeyi raw data veya warning plaintext sızdırabilir.

Önlem:

Proof bundle hash-only policy ve JSON negative tests.

### R6 — PoA compliance leakage

Risk:

PoA compliance/freeze state permissionless domaine sızabilir.

Önlem:

PoA-only registry tests + Sovereign Domain Kit cross-check.

### R7 — CI gate drift

Risk:

Ajanlar test isimlerini değiştirir veya workflow filtreleri eksik kalır.

Önlem:

Gate scripts self-test + named test canaries + CI red fix önceliği.

---

## 5. Devam sırası

Sıradaki uygulama sırası:

1. **P12.5-2:** Pollen cryptographic authorization verification.
2. **P12.5-3:** Pollen purchase transaction/state mutation.
3. **P12.5-4:** Encryption policy unification/enforcement.
4. **P12.5-5:** Relayer Policy executor integration.
5. **P12.5-6:** Passport + Atlas unified evidence.
6. **P12.5-7:** Sovereign Domain tx/RPC/governance lifecycle.
7. **P12.5-8:** Mobile Self RPC / Atlas / Passport integration.
8. **P12.5-9:** Proof Verification Market adapters.
9. **P12.5-10:** Developer OS / BudL SDK practical workflow.
10. **P12.5-11:** Task 11.x main integration review.
11. **P12.5-12:** Bounded-state and pruning audit pass.

Bu sıra CI kırmızı olmadığı sürece uygulanır. CI kırmızı olursa sıra durur ve önce kırmızı sebep düzeltilir.

---

## 6. Son söz

Task 12 ana sistemleri kod tabanına girdi. Task 12.5 artık bir "vizyon ekleme" turu değil, **mainnet hazırlık sertleştirme turu**dur. Bu rapordaki işler tamamlanmadan Task 12 kapsamı production-ready veya audited sayılmaz.

Co-authored-by: ARENA4 <arena4@budlum.ai>
