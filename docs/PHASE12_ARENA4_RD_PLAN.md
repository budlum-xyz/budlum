# Budlum Phase 12 — ARENA4 Onaylanan Sistemler ve Uygulama Planı

> **Hazırlayan:** ARENA4  
> **Kaynak karar:** Kullanıcı onayları, 2026-07-20  
> **Amaç:** Budlum vizyonunu Data Rights, Pollen, AI veri erişim yasağı, Relayer Policy, D-Web Passport, Proof Verification Market, Sovereign Domain Kit, Budlum Atlas, Mobile Self, Encryption DAO, Governance/Constitution ve Developer OS başlıklarıyla Phase 12 altında bütünsel şekilde geliştirmek.  
> **Kural:** Bu belge “mainnet-ready” veya “audited” iddiası değildir. Tüm üretim işleri CI yeşili, regresyon kilidi ve `STATUS_ONLINE.md` koordinasyonu ile yürütülür.

---

## 0. Kullanıcı karar özeti

Kullanıcı aşağıdaki sistemleri onayladı:

1. **Data Rights / Pollen:** Data Rights şu an repoda vardır ve geliştirilecektir. Bir verinin veri olarak satılmasına **Pollen** denir; çünkü tomurcuk kullanıcıya aittir, kullanıcı polenlerini satar.
2. **AI veri okuyamama yasağı:** AI’ın izinsiz veri okuyamama kuralı sertleştirilecek ve güçlü hale getirilecektir.
3. **Relayer Policy Layer:** Onaylandı.
4. **D-Web Passport:** budlum.xyz üzerinde tasarlanacak ve yürütülecektir.
5. **Proof Verification Market:** Validatörler için **LUM** isimli DeFi uygulaması içinde ileride sistem olabilir; bağlantı şu an kurulmayacak ama çalışma başlayacaktır.
6. **Sovereign Domain Kit:** Geliştirilecek ve üzerinde durulacaktır.
7. **Budlum Atlas:** Onaylandı; kodlanacaktır.
8. **Mobile Self:** Kesinlikle yapılacaktır.
9. **Encryption Layer:** DAO’ya eklenecektir.
10. **Governance / Constitution Engine:** Onaylandı.
11. **R10 / Developer OS / BudL SDK:** Onaylandı.
12. Kullanıcı şu ana kadar hiçbir çalışmayı reddetmediğini belirtti.
13. Dosyalarda “kullanıcıya sorulacak” denilen yerlerde ARENA4’ün “önerilen” şıkları uygulayabileceği onaylandı.

---

## 1. Phase 12 ana ilkeleri

Phase 12, Budlum’ın yalnızca bir L1 settlement protokolü değil, kullanıcı verisi, kimliği, izni, AI ekonomisi, D-Web ve egemen domain’ler için bir **kanıtlı dijital egemenlik katmanı** haline gelmesini hedefler.

Temel ilkeler:

- **Tomurcuk kullanıcıya aittir:** Veri varlığı kullanıcı mülkiyetindedir.
- **Pollen satılır:** Satılan şey verinin kendisi değil, sınırlandırılmış erişim hakkıdır.
- **AI default-deny çalışır:** AI, geçerli Pollen AccessGrant olmadan B.U.D./DataAsset verisi okuyamaz.
- **DAO decrypt edemez:** DAO sadece parametre yönetir; kullanıcı anahtarına, decrypt yetkisine veya veri okuma iznine dokunamaz.
- **PoA izolasyonu korunur:** Sovereign/PoA domain kit geliştirilirken PoA kuralları permissionless PoW/PoS/BFT alanlarına sızmaz.
- **Relayer permissionless kalır:** Relayer Policy Layer hiçbir whitelist veya merkezi onay mekanizması getirmez.
- **Proof iddiaları dürüst kalır:** VerifyMerkle, HPKE, HSM, external audit gibi kapılar kapanmadan “tam proof-of-storage”, “audited”, “production-ready” gibi iddialar kurulmaz.
- **CI tek hakemdir:** Lokal doğrulama önemli ama GitHub CI yeşil değilse iş kapalı sayılmaz.

---

## 2. Mevcut ARENA4 uygulama durumu

### 2.1 A4-1 — Pollen Data Rights + AI read gate

Bu ADIM’de şu işler yapıldı:

- `DataAsset` eklendi.
- `AccessGrant` eklendi.
- `AiDataInputRef` eklendi.
- `MarketplaceRegistry` içine `data_assets` ve `access_grants` map’leri eklendi.
- Marketplace root kapsamı genişletildi.
- Executor içinde `AiInferenceRequest` admission gate eklendi.
- Pollen/B.U.D. veri referansı taşıyan AI input_ref, geçerli grant yoksa `ai_data_access_denied` ile reddedilir.
- Grant yoksa, expired ise, revoked ise, exhausted ise veya wrong grantee ise AI request kabul edilmez.
- Non-Pollen legacy opaque input_ref akışı bozulmaz.
- Grant başarılı AI request sonrası tüketilir.
- Başarısız request grant tüketmez.

Regresyon kilitleri:

- `pollen_ai_data_ref_without_access_grant_is_rejected`
- `pollen_ai_data_ref_with_access_grant_is_consumed_once`
- `non_pollen_ai_input_ref_still_uses_legacy_opaque_path`

### 2.2 A4-2 — SaleAuthorization + Pollen RPC/query surface

Bu ADIM’de şu işler yapıldı:

- `SaleAuthorization` eklendi.
- `SaleAuthorizationId` eklendi.
- Seller/owner imzalı bounded pollen satış yetkisi tanımlandı.
- Sentinel imza reddedilir.
- Canonical id ve signing hash hesaplaması testlidir.
- `MarketplaceRegistry.sale_authorizations` eklendi.
- SaleAuthorization marketplace root kapsamına alındı.
- ChainActor read-only Pollen query yüzeyi eklendi:
  - data assets
  - access grants
  - sale authorizations
- RPC yüzeyi eklendi:
  - `bud_pollenGetDataAssets`
  - `bud_pollenGetAccessGrants`
  - `bud_pollenGetSaleAuthorizations`
  - `bud_pollenBuildAiInputRef`
  - `bud_pollenPrepareSaleAuthorization`
- Yeni transaction/proto tipi açılmadı; ADIM güvenli prepare/query yüzeyiyle sınırlı tutuldu.

Not: Son main push sonrası CI final durumu ARENA1 tarafından tekrar doğrulanmalıdır. ARENA4 tarafında en son main push SHA `09263fe` idi; kullanıcı isteğiyle dosya buradan gönderildiği için bu noktadan sonra Phase 12 kaydı ARENA1 tarafından sürdürülecektir.

> **ARENA1 doğrulama notu (2026-07-20):** A4-1/A4-2 işleri `arena/arena4-pollen-ai-data-rights`
> branch'inde (HEAD `7fd8c68`, CI 14/14 yeşil) idi, main'de değildi. Bu doküman yazıldığında
> referans verilen `09263fe` artık geçersizdir (branch `7fd8c68`'e merge olmuştur). ARENA1,
> pollen işini `arena/phase12-pollen-audit` branch'inde main (Task 4/5 dahil) ile merge etti
> ve CI doğrulamasına soktu. "A4-1/A4-2 uygulandı" ifadesi, bu doğrulama sonrası main'e
> girdiği anlamına gelir. Kod denetimi (kural 1): domain-separated hashing ✓, sentinel imza
> reddi ✓, canonical preimage doğrulaması ✓, bounded reads + expiry ✓, AI read gate
> (`ai_data_access_denied`) ✓, legacy opaque input_ref path korunuyor ✓.

---

## 3. Phase 12 ADIM sırası

| ADIM | Başlık | Öncelik | Durum |
|---|---|---:|---|
| P12-1 | Pollen Data Rights + AI read gate | P0 | Başladı / A4-1 uygulandı |
| P12-2 | SaleAuthorization + Pollen RPC/query | P0 | Başladı / A4-2 uygulandı |
| P12-3 | Transaction-backed Pollen grant registration | P0 | Sıradaki |
| P12-4 | Encryption Layer DAO parameters | P0 | Bu ADIM başladı |
| P12-5 | Relayer Policy Layer | P1 | Bu ADIM başladı |
| P12-6 | D-Web Passport core + budlum.xyz handoff | P1 | Bu ADIM başladı |
| P12-7 | Sovereign Domain Kit | P1 | Bu ADIM başladı |
| P12-8 | Budlum Atlas / bud.scan Evidence UI | P1 | Bu ADIM başladı |
| P12-9 | Mobile Self | P1 | Bu ADIM başladı |
| P12-10 | Governance / Constitution Engine | P1 | Onaylandı |
| P12-11 | Proof Verification Market / LUM hazırlığı | P2 | Bağlantı kurulmadan araştırma |
| P12-12 | Developer OS / BudL SDK | P2 | Onaylandı |

---

## 4. P12-3 — Transaction-backed Pollen grant registration

### Amaç

A4-1 ve A4-2’de Pollen primitive’leri ve query/prepare yüzeyi geldi. Bir sonraki adımda grant/authorization kayıtlarının transaction-backed hale gelmesi gerekir.

### Kapsam

Yeni transaction tipleri önerilir:

- `PollenRegisterDataAsset(DataAsset)`
- `PollenAuthorizeSale(SaleAuthorization)`
- `PollenGrantAccess(AccessGrant)`
- `PollenRevokeGrant(GrantId)`
- `PollenRevokeDataAsset(AssetId)`

### Kabul kriterleri

- Owner olmayan DataAsset register edemez.
- Seller olmayan SaleAuthorization üretemez.
- Sentinel signature reddedilir.
- AccessGrant owner, asset owner ile eşleşmelidir.
- Grant expired/revoked/exhausted olduğunda AI read gate reddeder.
- Payment/price alanı AccessGrant veya SaleAuthorization root kapsamına girer.
- Revoke işlemi grant root’unu değiştirir.
- Replay/reuse testleri zorunludur.
- Proto encode/decode açılırsa roundtrip test zorunludur.

### Risk

Yeni transaction/proto yüzeyi açılacağı için CI kırma ve signing format genişletme riski vardır. Bu nedenle A4-1/A4-2’nin yeşil CI zemini doğrulandıktan sonra yapılmalıdır.

---

## 5. P12-4 — Encryption Layer DAO parameters

### Kullanıcı kararı

DAO sadece parametre yönetir. DAO kullanıcı anahtarına, decrypt yetkisine veya veri okuma iznine dokunamaz.

### Amaç

Encryption Layer, Pollen ve B.U.D. verisinin hard-enforcement aşamasına geçebilmesi için DAO tarafından yönetilen ama kullanıcı egemenliğini bozmayan parametrelerle tanımlanır.

### DAO’nun yönetebileceği parametreler

- Desteklenen encryption version listesi
- Minimum key size
- HPKE suite id
- Grant default duration upper bound
- ReadOnce / ReadMany policy limitleri
- Deprecated encryption version listesi
- Migration grace period
- Minimum metadata commitment format version

### DAO’nun asla yapamayacağı şeyler

- Kullanıcı verisini decrypt etmek
- Kullanıcı private key veya content key görmek
- Grant olmadan AI’a okuma izni vermek
- Owner imzasını bypass etmek
- Storage node’a plaintext zorunlu kılmak
- Emergency gerekçesiyle veri okuma yetkisi almak

### Önerilen yapılar

```rust
EncryptionPolicy {
    version: u32,
    hpke_suite_id: u16,
    min_public_key_bytes: u16,
    max_grant_duration_blocks: u64,
    deprecated_after_block: Option<u64>,
    active: bool,
}
```

```rust
ConstitutionParam::EncryptionPolicy(EncryptionPolicy)
```

### Kabul kriterleri

- DAO encryption parametresi değiştirince state root değişir.
- Parametreler invalid ise governance proposal finalize olsa bile apply edilmez.
- Decrypt authority diye bir alan yoktur.
- Test adı önerileri:
  - `dao_cannot_grant_decrypt_authority`
  - `encryption_policy_update_changes_constitution_root`
  - `deprecated_encryption_version_rejects_new_grants`
  - `existing_grants_survive_policy_version_rotation`

---

## 6. P12-5 — Relayer Policy Layer

### Kullanıcı kararı

Relayer Policy Layer onaylandı.

### Amaç

Kullanıcı intent imzalar; permissionless relayer ağı bu intent’i uygulamak için yarışır. Relayer whitelist yoktur. Güvenlik; imzalı intent, policy envelope, fee cap, deadline, bond ve slashing ile sağlanır.

### Temel yapılar

```rust
UserIntent {
    intent_id,
    owner,
    source_domain,
    target_domain,
    action_kind,
    max_fee,
    deadline_block,
    replay_nonce,
    policy_hash,
}
```

```rust
PolicyEnvelope {
    owner,
    session_key,
    spending_cap,
    allowed_domains,
    requires_multisig,
    requires_hsm,
    expires_at_block,
}
```

```rust
SolverBid {
    intent_id,
    relayer,
    quoted_fee,
    proof_commitment,
    bond,
    expires_at_block,
}
```

### Güvenlik kuralları

- Relayer permissionless kalır.
- Wallet içinde authorized relayer listesi olmaz.
- Intent replay edilemez.
- Fee max_fee’yi aşamaz.
- Deadline sonrası execution reddedilir.
- Solver proof vermezse slash edilebilir.
- Critical action policy high-value işlemlerde multi-device/HSM isteyebilir.

### Kabul kriterleri

- `intent_replay_rejected`
- `relayer_fee_cannot_exceed_user_cap`
- `expired_intent_rejected`
- `policy_requires_multisig_for_critical_action`
- `permissionless_relayer_no_whitelist`

---

## 7. P12-6 — D-Web Passport + budlum.xyz

### Kullanıcı kararı

D-Web Passport tasarlanacak ve budlum.xyz üzerinde yürütülecek. Bu repoda önce core API/spec yapılacak.

### Amaç

Budlum kullanıcısı için tek kimlik/cüzdan/D-Web çözümleme pasaportu oluşturmak. Kullanıcı `.bud` adını, B.U.D. manifest’ini, Pollen grant’lerini, wallet address’ini ve proof status’ünü tek yerde görür.

### Bu repoda yapılacaklar

- D-Web Passport core spec
- `.bud` resolver proof formatı
- BNS → B.U.D. manifest proof query
- Pollen grant proof query
- Light client proof bundle format
- budlum.xyz için JSON schema / handoff API

### budlum.xyz tarafında yapılacaklar

- Passport UI
- `.bud` profile page
- DataAsset / Pollen market panel
- Evidence Card
- D-Web site renderer
- Wallet connection

### Güvenlik kuralı

UI proof’suz veriyi “verified” gösteremez. Proof yoksa “unverified view” etiketi zorunludur.

### Kabul kriterleri

- `.bud` resolve proof bundle schema
- `bud_passportGetProfile` veya benzeri read-only RPC tasarımı
- Evidence Card JSON schema
- “verified/unverified” ayrımı testli
- budlum.xyz frontend repo/scope ayrımı dokümante

---

## 8. P12-7 — Sovereign Domain Kit

### Kullanıcı kararı

Sovereign Domain Kit geliştirilecek ve üzerinde durulacak.

### Amaç

CBDC, banka, belediye, kurum veya devlet sistemlerinin Budlum’a domain olarak bağlanması için template, lifecycle, compliance evidence ve audit export sistemi sağlamak.

### Temel bileşenler

- `SovereignDomainTemplate`
- `DomainLifecyclePolicy`
- `AuthorityRotationPlan`
- `ComplianceEvidenceRoot`
- `AuditExportBundle`
- `DomainRetirementPlan`

### PoA izolasyon kuralı

PoA/KYC kuralları yalnız PoA domain içinde geçerlidir. Permissionless PoW/PoS/BFT registry’ye sızamaz.

### Kabul kriterleri

- PoA authority eklemek validator registry’yi değiştirmez.
- PoA CrossDomainMessage diğer domain’lerde KYC aramaz.
- Compliance evidence root özel KYC verisi sızdırmaz.
- Domain retirement state root ve event üretir.
- Audit export proof bundle deterministik olur.

---

## 9. P12-8 — Budlum Atlas / bud.scan Evidence UI

### Kullanıcı kararı

Budlum Atlas onaylandı; kodlanacaktır.

### Amaç

Budlum ekosistemini kanıtlı bir dijital topoğrafya olarak göstermek. Her wallet bir grid karesi, her dApp bir bölge, her DataAsset/Pollen flow bir bağlantı, her proof bir Evidence Card olarak görünür.

### Core tarafında yapılacaklar

- Read-only evidence endpoints
- Wallet context graph query
- Token bubble map data model
- Domain health summary
- Proof status schema
- Pollen data lineage query

### UI tarafında yapılacaklar

- budlum.xyz Atlas grid
- wallet context map
- token bubble map
- DataAsset/Pollen flow map
- domain health cards
- proof verified/unverified badges

### Kabul kriterleri

- UI proof’suz state iddiası kuramaz.
- Context map read-only endpoint kullanır.
- Atlas endpoint’leri state mutate etmez.
- Pollen lineage owner → asset → grant → AI request akışını gösterebilir.

---

## 10. P12-9 — Mobile Self

### Kullanıcı kararı

Mobile Self kesinlikle yapılacaktır.

### Amaç

Telefonlar ve kişisel cihazlar B.U.D. self-hosting ve düşük güç node profili olarak çalışabilmelidir.

### Bileşenler

- Mobile node profile
- Self-hosted B.U.D. manifest serving
- NAT/mobile connectivity mode
- Battery-aware challenge policy
- Opportunistic availability metadata
- Paid replica fallback
- Mobile wallet + D-Web Passport integration

### Kabul kriterleri

- Mobile Self “always online” iddiası kurmaz.
- Self-hosted data “online olduğunda erişilebilir” etiketi taşır.
- Critical data için paid replica önerisi gösterilir.
- Mobile node storage deal ayrı risk profili taşır.
- Mobile node private key OS secure storage içinde olmalıdır.

---

## 11. P12-10 — Governance / Constitution Engine

### Kullanıcı kararı

Governance/Constitution çalışması onaylandı.

### Amaç

`BUDLUM_CONSTITUTION.md` içinde tanımlı kararları protokol parametrelerine bağlamak.

### Temel parametre alanları

- Content moderation mode
- DAO halt guardrails
- BNS premium verified rules
- Pollen / AccessGrant limits
- Encryption policy parameters
- Boost split parameters
- Storage reward weights
- Relayer policy limits

### Güvenlik sınırları

- Governance whitelist kapısı haline gelemez.
- DAO user decrypt yetkisi alamaz.
- DAO halt no-rollback ilkesini bozamaz.
- Permissionless registry’ye admin approval eklenemez.

### Kabul kriterleri

- Constitution parameter root
- Proposal guardrails
- Timelock / supermajority for sensitive params
- DAO halt scope testleri
- “cannot create whitelist for permissionless core” regression

---

## 12. P12-11 — Proof Verification Market / LUM hazırlığı

### Kullanıcı kararı

Proof Verification Market validatörler için LUM isimli DeFi uygulaması içinde bir sistem olabilir. Şu an bağlantı kurulmayacak ama çalışma başlayacaktır.

### Amaç

Proof verification, prover jobs, validator services, storage proofs, AI attestations ve bridge verification gelecekte LUM DeFi içinde ekonomik bir pazar haline gelebilir.

### Şimdiki sınır

- LUM entegrasyonu kodlanmayacak.
- Token veya DeFi bağlantısı kurulmayacak.
- Sadece interface, job model, proof receipt ve market abstraction çalışılacak.

### Temel yapılar

```rust
ProofTask {
    task_id,
    task_kind,
    input_commitment,
    reward_commitment,
    deadline,
    slash_condition,
}
```

```rust
ProofReceipt {
    task_id,
    verifier,
    proof_hash,
    accepted_at_block,
    result_root,
}
```

### Kabul kriterleri

- ProofTask modelinde LUM bağımlılığı yok.
- Validator/prover permissionless kalır.
- Invalid proof fail-closed olur.
- ProofReceipt state root kapsamına girebilir.
- LUM bağlantısı future adapter olarak kalır.

---

## 13. P12-12 — Developer OS / BudL SDK

### Kullanıcı kararı

R10 onaylandı.

### Amaç

Budlum geliştiricisi için lokal devnet, BudL contract, proof fixtures, wallet signing, Pollen/DataAsset flow ve relayer policy testlerini tek geliştirici deneyiminde toplamak.

### Bileşenler

- `budlum.toml`
- `contracts/`
- `tests/`
- `fixtures/`
- local 4-domain devnet
- BudL compile/test runner
- proof fixture generator
- Pollen asset/grant fixture generator
- relayer intent simulation
- SDK docs: Rust / TypeScript / Kotlin / Swift

### Kabul kriterleri

- Local devnet deterministic başlar.
- BudL fixture testleri repeatable olur.
- Pollen/AI grant fixture üretir.
- Wallet signing V4 formatıyla uyumludur.
- CI template sunulur.

---

## 14. Phase 12 güvenlik ve CI kuralları

Her ADIM için zorunlu:

- `STATUS_ONLINE.md` başlangıç kaydı
- Kod değiştiyse negatif test
- Secret scan fark kontrolü
- `budlumdevnet` dokunulmadı beyanı
- Push sonrası CI SLEEP
- CI kırmızıysa yeni özellik yok, sadece kök neden onarımı
- CI yeşilse kapanış kaydı
- Kapanış kaydı push edilirse o SHA için de CI takip edilir

---

## 15. İlk önerilen devam sırası

ARENA4 önerisi:

1. **P12-3:** Transaction-backed Pollen grant registration
2. **P12-4:** Encryption DAO parameters
3. **P12-6:** D-Web Passport core spec/API
4. **P12-5:** Relayer Policy Layer
5. **P12-7:** Sovereign Domain Kit
6. **P12-8:** Budlum Atlas
7. **P12-9:** Mobile Self
8. **P12-10:** Governance/Constitution Engine
9. **P12-11:** Proof Verification Market / LUM preparation
10. **P12-12:** Developer OS / BudL SDK

---

## 16. ARENA koordinasyon notu

- ARENA1 Phase 12 dosyasını kanonik plan olarak kaydedebilir.
- ARENA2 proof/AI/verification tarafında API sınırlarını review etmelidir.
- ARENA3 hardening/CI/fuzz/gate uyumunu denetlemelidir.
- ARENAS/ARENAX açık bulgu taramasına devam etmelidir.
- ARENA4 Pollen, D-Web Passport, Relayer Policy, Atlas, Mobile Self ve Developer OS başlıklarında kullanıcı onayına göre ilerleyecektir.

---

*Co-authored-by: ARENA4 <arena4@budlum.ai>*
