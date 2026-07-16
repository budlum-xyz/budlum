# Phase 5 Belge ve Uygulama Denetimi — ARENA6

**Tarih:** 2026-07-15 20:13 UTC+3
**İlk denetlenen dal/HEAD:** `origin/main` @ `6f8b111`
**Eşzamanlı ajan commitleri sonrası tekrar kontrol:** `origin/main` @ `e8fa68d`
**Ana belge:** `docs/PHASE0.08_PLAN.md` (`baa10e7`)
**Denetçi:** `ARENA6` (`arena/019f63ce-budlum`)
**Yöntem:** belge ↔ Git ağacı ↔ commit geçmişi ↔ GitHub Actions ↔ eski `Budlumdevnet`/`Budlumdevnet2` roadmap karşılaştırması

---

## 1. Yönetici sonucu

**Phase 5 şu an “tamamlandı” olarak kapatılamaz.**

`docs/PHASE0.08_PLAN.md` yalnız başlangıç yol haritasıdır ve kendi üst bilgisinde hâlâ
`Aktif Geliştirme` yazmaktadır. Belgenin beş hedefinden:

- **5.1 Universal Relayer:** kısmi iskelet; gerçek dış-zincir gönderimi yok.
- **5.2 Mobil B.U.D. Light Node:** güncel `main` ağacında planlanan API'ler yok.
- **5.3 SocialFi Hard Pruning:** güncel `main` ağacında fiziksel silme hattı yok.
- **5.4 Chaos v2:** test dosyası eklendi; fakat HEAD CI kırmızı ve test dosyasında yapısal hata var.
- **5.5 AI Data Marketplace:** kısmi state/işlem iskeleti var; kabul testleri ve güvenlik kapanışı yok.

Buna ek olarak `main` HEAD `6f8b111` için **CI kırmızı**:

- CI run `29435322327`: `Budlum Core / Format` başarısız, `BudZero / Test` başarısız.
- Docker run `29435322598`: `Build mainnet image` başarısız.

Dolayısıyla “kodlandı”, “test edildi”, “CI yeşil” ve “tamamlandı” kavramları
birbirinden ayrılmalıdır. Mevcut kanıt ancak **deneysel/kısmi implementasyon**
demeye yeterlidir.

---

## 2. Belge içi sorunlar

### 2.1 Durum alanı kapanışı desteklemiyor

`docs/PHASE0.08_PLAN.md:6`:

```text
Durum: Aktif Geliştirme
```

Belgede tamamlanma tarihi, kabul matrisi, test adı, commit SHA, CI run'ı veya
kalan risk listesi bulunmuyor.

### 2.2 Görev detayları eksik

Belge §2 yalnız 5.1, 5.2 ve 5.3'ü açıklıyor. **5.4 ve 5.5 için görev detayı,
test kriteri ve güvenlik şartı yok.**

### 2.3 Phase 5 kapsamı üç farklı şekilde tanımlanmış

| Kaynak | Phase 5 tanımı |
|---|---|
| `docs/PHASE0.08_PLAN.md` | Universal Relayer + Mobile + Hard Pruning + Chaos + Marketplace |
| `docs/PHASE0.06_PLAN.md` §7 | External audit + Bug Bounty + TLA+ + Disaster Recovery |
| `docs/MAINNET_READINESS.md` | Bug bounty sonuçları + external audit checklist + 24h fuzz + chaos + BNS |
| `docs/YENI_ASAMALAR_PLAN_ARENA3_2026-07-16.md` | External audit + hardening + B.U.D. P2P |

Tek bir kanonik Phase 5 kapsamı seçilmeden “Phase 5 tamamlandı” denmesi ölçülebilir
değildir.

---

## 3. Hedef bazında kanıt matrisi

| Hedef | Plan | Güncel HEAD kanıtı | Denetim sonucu |
|---|---|---|---|
| 5.1 Universal Relayer | ExternalChain, ExternalTransaction, prepare RPC, gerçek relay | `ExternalChain` ve `ExternalTransaction` var; `RelayerWorker` var; planlanan RPC yok; worker yalnız log yazıyor | 🔴 Kısmi/stub |
| 5.2 Mobile Light Node | `mobile_default`, resource buffer, self-host priority | `mobile_default` ve `is_resource_buffer_sufficient` HEAD'de yok; `c726de3` değişiklikleri `6333a74` akışında geri alındı | 🔴 Yok/revert |
| 5.3 Hard Pruning | NftBurn → Node worker → fiziksel CID silme | `StoragePrune` / `storage_prune` HEAD'de yok; executor yalnız tracing log yazıyor | 🔴 Yok |
| 5.4 Chaos v2 | chain halt/recovery + partition | `disaster_recovery.rs` var; HEAD CI kırmızı; fiziksel prune veya gerçek ağ partition'ı doğrulanmıyor | 🟠 Kırık/kısmi |
| 5.5 Marketplace | veri teklif/satış kontratları | `6f8b111`'de registry/tx iskeleti vardı; `e8fa68d`'de transaction/account/lib bağlantıları yeniden çıkarıldı, snapshot referansları ise kaldı; test yok | 🔴 Bağdaşmamış/revert |

---

## 4. Kritik teknik bulgular

### P0-1 — `main` CI kırmızı

HEAD `6f8b111` sonuçları:

- <https://github.com/budlum-xyz/budlum/actions/runs/29435322327>
  - `Budlum Core`: **Format failure**
  - `BudZero / BudZKVM`: **Test failure**
- <https://github.com/budlum-xyz/budlum/actions/runs/29435322598>
  - Docker mainnet image: **failure**

Aynı kırmızı zincir `6cedc44`, `8ba9779`, `634d0ad` ve `6f8b111`
commitlerinde sürüyor. Kırmızı HEAD üstünde kapanış yapılamaz.

**Eşzamanlı ajan re-check:** Denetim sırasında `main`, `02dae79` → `a43c095`
→ `e8fa68d` commitleriyle ilerledi. `02dae79` CI run `29435515658` yine
Budlum Core Format + BudZero Test failure verdi. `e8fa68d` için CI denetim
anında çalışıyordu. Yeni commitler aşağıdaki 5.1/5.2/5.3 sorunlarını kapatmadı;
aksine relayer/snapshot modüllerinde yeni bağdaşmazlıklar oluşturdu.

### P0-2 — Transaction ve modül sözleşmeleri eşzamanlı commitlerde parçalandı

`6f8b111` ağacında payload taşıyan yeni transaction varyantları
(`UniversalRelay`, marketplace, hub, boost) eklenmiş, ancak
`Transaction::signing_hash`, `is_valid`, `estimate_gas_with_schedule` ve diğer
exhaustive-match yüzeyleri eski varyantlarda kalmıştı. Payload'lı transaction
tekrar eklenecekse yalnız type byte değil, payload'ın tamamı version'lı ve
canonical biçimde imza hash'ine bağlanmalıdır.

`e8fa68d` ise bu varyantları `TransactionType`'tan tekrar çıkardı; fakat:

- `src/relayer/worker.rs` hâlâ `UniversalRelay`, `ExternalTransaction` ve
  `ExternalChain` tiplerini referanslıyor.
- `src/chain/snapshot.rs` hâlâ `crate::marketplace`, `crate::hub` ve
  `account_state.marketplace/hub` referanslarını taşıyor.
- `src/lib.rs` ve `AccountState` bu modül/alanları kaldırmış durumda.
- `TransactionType` içindeki BNS/NFT varyantları hâlâ signing/validation/gas
  match'lerine eksiksiz bağlanmamış.

Bu, Phase 5/6'nın aynı anda “restore” ve “revert” edilmesiyle oluşan doğrudan
derleme/sözleşme bağdaşmazlığıdır. Önce tek bir kanonik transaction enum'u ve
modül sahiplik tablosu dondurulmalıdır.

### P0-3 — Universal Relayer gerçek relay yapmıyor

`src/relayer/worker.rs` açıkça placeholder içeriyor:

```text
Real-world: Connect to Web3 provider ...
Placeholder: Here the relayer would use its own ETH for gas ...
Relay for ... not yet implemented
```

Eksikler:

1. EVM/Solana/Bitcoin adapter'ı yok.
2. Finality/confirmation bekleme politikası yok.
3. Kalıcı cursor/checkpoint yok; restart sonrası kaçırma/tekrar riski var.
4. Idempotency key ve replay koruması yok.
5. Retry/backoff/dead-letter yolu yok.
6. External receipt/tx-hash kanıtı yok.
7. Master Key veya multisig doğrulaması `ExternalTransaction` içinde yok.
8. `main.rs`, producer adresi yoksa `Address::zero()` ile worker başlatabiliyor.
9. Planlanan `bud_relayerPrepareExternalTx` RPC HEAD'de yok.

Bu nedenle 5.1 için doğru etiket **“relay request watcher skeleton”** olmalıdır;
“external chain integration complete” değil.

### P0-4 — Hard Pruning fiziksel silme yapmıyor

Planın kabul akışı:

```text
NftBurn → StoragePrune → store.delete(cid)
```

Güncel HEAD'de:

- `NodeCommand::StoragePrune` yok.
- `NodeClient::storage_prune` yok.
- NFT burn kolu yalnız `tracing::info!` yazıyor.
- Chaos testi yalnız NFT registry kaydının silindiğini kontrol ediyor;
  disk üzerindeki B.U.D. blob'unun silindiğini kontrol etmiyor.

Böylece zincir-state burn ile fiziksel veri silme birbirine bağlı değildir.

### P0-5 — Chaos v2 test dosyası yapısal olarak kırık

`src/tests/disaster_recovery.rs` içinde `mod tests` satır 129'da kapanıyor;
`test_chaos_v2_heavy_network_partition_with_forks` bundan sonra, gerekli
`tempdir`, `Address`, `Storage`, `Blockchain`, `Arc` ve `PoWEngine` importlarının
dışında kalıyor.

Ek olarak test adı “heavy network partition” olsa da iki yerel DB zinciri
üretip doğrudan `try_reorg` çağırıyor; gerçek libp2p partition, gecikme,
paket kaybı veya yeniden bağlanma davranışı test edilmiyor.

### P1-1 — Marketplace ekonomik atomiklik kanıtlanmamış

`6f8b111`'deki `AiPurchaseData` kolunda offer önce kapatılıyor, alıcının
bakiyesi sonra kontrol ediliyordu. Üst katmanda eksiksiz rollback garantisi
yoksa yetersiz bakiyeli alıcı teklifi kapatabilir. Bu sıra ters çevrilmeli veya
state değişimi atomik testle kanıtlanmalıdır. `e8fa68d` bu tx kolunu kaldırdı;
bu da davranışı tamamlamıyor, yalnızca özelliği yeniden koparıyor.

Ayrıca:

- CID sahipliği/servis edilebilirliği doğrulanmıyor.
- `price > 0` ve sınır kontrolleri yok.
- Erişim anahtarı/entitlement teslimi yok.
- Escrow/dispute yolu yok.
- Marketplace birim/E2E testi yok.

### P1-2 — Yol haritası “tamamı” bu belgeyle karşılanmıyor

Eski `budlum-xyz/Budlumdevnet` README Research Roadmap açık maddeleri:

- ZKVM optimizations
- Formal verification / TLA+
- Professional external audit
- Privacy layer
- AI execution layer

`Budlumdevnet` ch12 ayrıca release ceremony, fault injection, fuzz sonucu ve
harici denetim ister. `Budlumdevnet2` / güncel `ORG_ROADMAP_AUDIT.md` de TLA+,
Privacy, AI ve gerçek harici audit'i açık kabul eder.

`AI Data Marketplace`, eski roadmap'teki **AI-assisted deterministic execution
layer** ile aynı şey değildir. Aynı şekilde internal checklist, profesyonel
harici audit sayılmaz.

---

## 5. Phase 5'i dürüstçe kapatmak için önerilen kabul kapıları

### Kapı A — Önce yeşil taban

1. `cargo fmt --all -- --check`
2. `cargo clippy --lib --tests -- -D warnings`
3. `cargo test --lib`
4. `cargo test --manifest-path budzero/Cargo.toml --workspace`
5. Docker smoke

Beşinin de aynı HEAD'de yeşil run'ı bulunmalı.

### Kapı B — 5.1 Universal Relayer

- Canonical signed payload + domain separation.
- Per-chain strict address/payload validation.
- Finalized-block-only processing.
- Persistent cursor + idempotency + retry.
- En az bir gerçek test adapter'ı; diğer zincirler fail-closed.
- RPC ve negatif auth/replay testleri.

### Kapı C — 5.2 Mobile

- Revert edilen mobil kod küçük commit ile yeniden uygulanmalı.
- Battery/Wi-Fi bilgisinin gerçek kaynağı veya açıkça “policy hook” etiketi.
- Self-host priority testi.
- Kaynak sınırı ve sharding invariant testleri.

### Kapı D — 5.3 Physical Pruning

- Burn event güvenilir queue/outbox üzerinden node'a taşınmalı.
- CID fiziksel depodan silinmeli.
- Restart/retry/idempotency testi.
- NFT state kaydı ile fiziksel blob ayrı ayrı doğrulanmalı.

### Kapı E — 5.4 Chaos v2

- Test dosyası derlenmeli ve CI yeşil olmalı.
- Backup/restore bütünlüğü.
- Gerçek multi-node partition/rejoin.
- Fork-choice ve state-root eşitliği.
- Fiziksel prune sonrası restart doğrulaması.

### Kapı F — 5.5 Marketplace

- Atomic purchase.
- Ownership/availability/entitlement modeli.
- Duplicate/race/insufficient-funds testleri.
- Snapshot V2 round-trip.
- En az bir 3-aktör E2E.

### Kapı G — Kanonik roadmap

Tek belge şu üç kapsamı birleştirmeli veya net biçimde ayırmalı:

1. Universal gateway ürün işleri.
2. External audit / TLA+ / fuzz / bug bounty hardening.
3. Eski roadmap araştırmaları: ZK optimizasyonu, Privacy, AI execution.

“Tamamlandı” yalnız kodlanabilir hedefler için kullanılmalı; harici audit ve
araştırma maddeleri dürüstçe `açık/süreç` kalmalıdır.

---

## 6. AI birliği handoff

### ARENA1'e

- 5.2 ve 5.3'ün `6333a74` sonrası HEAD'de bulunmadığını doğrula.
- Universal relayer için “placeholder” iddiasını düzelt ve gerçek kabul
  sınırını öner.
- Marketplace atomiklik ve transaction signing payload binding borcunu ele al.

### ARENA2'ye

- HEAD CI kırmızısını ve BudZero test failure kök nedenini teyit et.
- Chaos v2 testini derleme/semantik açıdan gözden geçir.
- TLA+/external-audit kapsamını kanonik Phase 5 belgesine geri bağla.

### ARENA3'e

- `YENI_ASAMALAR_PLAN...`, `PHASE0.06_PLAN`, `MAINNET_READINESS` ve `PHASE0.08_PLAN`
  çelişkisini tek scope matrisine dönüştür.
- Eski devnet roadmap açıklarını güncel org denetimine işle.

### ARENA6

- Bu turda kod değiştirmedi; Aşama 1 uyarınca kanıtlı denetim ve iletişim
  kaydı hazırladı.
- Diğer AI yanıtları ve kullanıcı `devam` komutundan sonra P0 düzeltmeleri için
  atomik PR önerecek.

---

## 7. Tek cümlelik kapanış

**Phase 5 için önemli iskeletler atılmıştır; fakat belge, güncel kod ağacı ve
kırmızı CI birlikte değerlendirildiğinde Phase 5 bitmiş değil, P0 düzeltme ve
kapsam birleştirme aşamasındadır.**
