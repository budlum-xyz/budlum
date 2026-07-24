# Budlum L1 — Mimari ve Sistem Pre-Mortem Güvenlik Denetimi (Kararlandırılmış Sürüm)

Tarih: 2026-07-24  
Repo: `https://github.com/budlum-xyz/budlum`

## Yönetici Özeti

Bu inceleme, repo içindeki gerçek Rust kaynak kodu, çalışma zamanı kablolaması, storage/restart akışları, RPC yüzeyi, CI workflow'ları ve lockfile'lar üzerinden yapıldı; README/özet dokümanlar kanıt olarak kullanılmadı. Repoda ek `.patch` / `.diff` dosyası bulunmadı.

Genel sonuç: **proje şu haliyle production-ready değil**. En büyük riskler kriptografik primitive hatalarından çok **wiring / lifecycle / persistence boşlukları**:

1. **Hibrit çoklu-konsensüs iddiası runtime'da gerçekleşmiyor.** Mainnet genesis'te 4 domain tanımlanmış görünse de node açılışında yalnızca tek bir domain register ediliyor; BFT için CLI/runtime seçim yolu yok; bootstrap domain listesi fiilen ölü kod.
2. **Restart/persistence yolu eksik.** PoS checkpoint/seen-block state'i gerçek startup yolunda geri yüklenmiyor; PoA validator dosyasından enjekte edilen otoriteler zincir replay'iyle yeniden üretilemediği için restart sonrası kaybolabiliyor.
3. **RPC güvenlik katmanı kendi kendini DoS ediyor ve proxy açıldığında spooflanabilir hale geliyor.** `allowed_ips` doluysa gerçek socket IP hiç okunmadığı için doğrudan istemciler reddediliyor; `trusted_proxies` ayarlanırsa header tabanlı IP kolay spoof edilebiliyor.
4. **Bridge/relayer akışı kablolanmamış.** Production kodunda `enqueue_bridge_relay` çağrılmıyor; relayer binary'si beklenen RPC shape'leri ve proof tiplerini yanlış varsayıyor; sonuçta relay pipeline pratikte çalışmıyor.
5. **RPC içindeki StorageRegistry zincirin asıl state'inden ayrı yaşıyor.** Challenge/deal akışları process-local bir registry üzerinde dönüyor; restart'ta kayboluyor ve chain-side economics/challenge logic ile split-brain oluşturuyor.
6. **HSM/PKCS#11 entegrasyonu “HSM-backed BLS/PQ” garantisini fiilen vermiyor.** Kod, vendor-native mekanizma başarısızsa software fallback ile extracted BLS/PQ key material kullanıyor; mainnet policy bunu yasaklamıyor, sadece “BLS/PQ var mı” diye bakıyor.

Pozitif taraflar:
- `cargo check --locked --lib`, `cargo fmt --all -- --check` ve `cargo clippy --locked --lib -- -D warnings` yerel sandbox'ta geçti.
- `cargo audit` ile kök `Cargo.lock` ve `budzero/Cargo.lock` için **bilinen CVE bulunmadı**; ancak birden çok **unmaintained / yanked** bağımlılık uyarısı var.
- Kod tabanında birçok güvenlik niyeti mevcut; ancak kritik sorunlar çoğunlukla “kod yazılmış ama sisteme doğru bağlanmamış” sınıfında.

---

## Metodoloji ve Doğrulama Notları

- İnceleme kapsamı: `src/**`, `build.rs`, `Cargo.toml`, `Cargo.lock`, `budzero/Cargo.lock`, `config/**`, `.github/workflows/**`, `scripts/**`.
- Özel odak: genesis/state init, epoch transition, restart/persistence, PoW/PoS/PoA/BFT sınırları, RPC auth/rate-limit, dependency audit.
- Repo içinde `.patch` / `.diff` dosyası **yok**.
- Yerel doğrulama komutları:
  - `cargo check --locked --lib` ✅
  - `cargo fmt --all -- --check` ✅
  - `cargo clippy --locked --lib -- -D warnings` ✅
  - `cargo clippy --locked --all-targets -- -D warnings` ⚠️ Cargo, `Cargo.toml:120` için invalid feature warning üretti; test-target derlemesi sandbox'ta `SIGKILL` ile kesildi.
  - `cargo test --locked --lib` ⚠️ sandbox kaynak sınırı / süre nedeniyle tamamlanamadı.
  - `cargo audit --file Cargo.lock -q` ✅ CVE yok, 9 warning.
  - `cargo audit --file budzero/Cargo.lock -q` ✅ CVE yok, 4 warning.
- Erişim kısıtı: GitHub'ın private runner loglarına / organizasyon secret'larına erişim yok; yalnız repo içi workflow tanımları incelendi.

---

## Bileşen Bazlı Bulgular

### 1) Konsensüs Katmanı

#### C-01 — Kritik — Hibrit multi-consensus mimarisi runtime'a kablolanmamış
- **Etkilenen dosya/fonksiyonlar:**
  - `src/main.rs:533-709` (`consensus` seçimi, `default_domain`, plugin registration)
  - `src/chain/genesis.rs:20-80` (`BootstrapDomainConfig::mainnet_defaults`)
  - `src/chain/genesis.rs:113,341` (`bootstrap_domains` alanı / mainnet genesis)
  - `src/chain/blockchain.rs:593-598` (`validate_consensus_domain_registration`)
  - `src/cli/commands.rs` (`ConsensusType` sadece `PoW/PoS/PoA`)
- **Pre-mortem senaryosu:**
  - Mainnet “hibrit PoW/PoS/BFT + izole PoA alanı” beklentisiyle açılıyor.
  - Node runtime'da sadece **tek** `consensus_type` seçiyor ve sadece `domain_id=1` için tek bir `default_domain` register ediyor.
  - Genesis'teki `bootstrap_domains` listesi hiç uygulanmıyor; BFT için runtime seçim yolu da yok.
  - Sonuç: operasyonda belgelenen çoklu-konsensüs topoloji yok; BFT/PoA/PoW sınırları gerçek ağda oluşmuyor; bridge/finality/policy varsayımları yanlış mimariye dayanıyor.
- **Somut düzeltme önerisi:**
  1. `Blockchain::new_with_genesis` veya startup bootstrap aşamasında `genesis.bootstrap_domains` zorunlu olarak uygulanmalı.
  2. `ConsensusType` ve runtime wiring BFT'yi de kapsamalı veya BFT açıkça scope dışı ilan edilmeli.
  3. Tek-domain shortcut (`domain_id=1`) kaldırılıp domain registry genesis-driven hale getirilmeli.
  4. `BootstrapDomainConfig` ile `validate_consensus_domain_registration` adapter isimleri aynı sabite bağlanmalı.

#### C-02 — Kritik — PoS restart sonrası checkpoint / double-sign hafızası geri yüklenmiyor
- **Etkilenen dosya/fonksiyonlar:**
  - `src/consensus/pos.rs:658-669` (`PoSEngine::load_state`)
  - `src/chain/blockchain.rs:156-360` (`new_with_genesis`)
  - `src/chain/blockchain.rs:488-507` (`load_chain_from_db` — `#[allow(dead_code)]`, tek `consensus.load_state` call-site)
- **Pre-mortem senaryosu:**
  - Validator node restart oluyor.
  - DB'de `SEEN:*` ve `CP:*` kayıtları dursa da gerçek startup constructor'ı `PoSEngine::load_state` çağırmıyor.
  - Node restart sonrası önceki slot'larda ne gördüğünü ve hangi checkpoint'in güvenli olduğunu unutuyor.
  - Sonuç: double-sign tespiti zayıflıyor, long-range / checkpoint rollback korumaları tutarsızlaşıyor.
- **Somut düzeltme önerisi:**
  1. `Blockchain::new_with_genesis` sonunda, storage varsa `self.consensus.load_state(store)` doğrudan çağrılmalı.
  2. Bu davranış için restart testi eklenmeli: seen-block + checkpoint state restart öncesi/sonrası eşit kalmalı.
  3. `load_chain_from_db` dead-code olmaktan çıkarılmalı ya da kaldırılmalı.

#### H-01 — Yüksek — Stake eden yeni validator'lar consensus key'siz kabul ediliyor; finality quorum'u erişilemez hale gelebilir
- **Etkilenen dosya/fonksiyonlar:**
  - `src/execution/executor.rs:93-127` (`TransactionType::Stake`)
  - `src/chain/blockchain.rs:2114-2132` (`build_validator_snapshot_from_state`)
- **Pre-mortem senaryosu:**
  - Permissionless onboarding ile çok sayıda validator stake ediyor ancak VRF/BLS/PoP materyali hiç set etmiyor.
  - Kod bunu reject etmiyor; sadece warning log'luyor.
  - Snapshot builder boş BLS/PoP'a sahip validator'ları yine validator set'e dahil ediyor (`has_no_bls_key || verify_pop(...)`).
  - Sonuç: quorum hesabı bu validator'ları sayıyor ama bunlar finality sertifikası üretemiyor; ağ finality/liveness tarafında kilitleniyor.
- **Somut düzeltme önerisi:**
  1. Stake/aktivasyon iki aşamalı olsun: `bonded` ve `active-for-consensus` ayrılmalı.
  2. `active` statüsüne geçiş için zorunlu minimum set: VRF pubkey + BLS pubkey + valid PoP.
  3. Snapshot'a sadece consensus-ready validator'lar alınmalı.
- **Onaylanan karar:** Stake kabul edilsin ama validator gerekli anahtarlarını tamamlayana kadar **bonded / inactive** statüsünde kalsın; quorum ve aktif validator setine dahil edilmesin.

#### H-02 — Yüksek — PoA validator dosyasından enjekte edilen otoriteler restart'ta kaybolabilir
- **Etkilenen dosya/fonksiyonlar:**
  - `src/main.rs:714-716` (startup'ta `poa_validators` → `state.add_validator`)
  - `src/chain/blockchain.rs:3382-3395` (`rebuild_state` sadece genesis+block replay)
  - `src/storage/db.rs:424-493` (`commit_durable_batch` yalnız block/accounts/headers/bridge_state persist ediyor)
- **Pre-mortem senaryosu:**
  - PoA node validator dosyasından authority listesi ile açılıyor.
  - Bu liste on-chain transaction veya genesis içine alınmıyor; runtime'da memory'ye enjekte ediliyor.
  - Restart/reorg/replay'de state yeniden kurulurken bu authority listesi yeniden üretilemiyor.
  - Sonuç: node restart sonrası farklı PoA validator set'i ile ayağa kalkıyor; imza doğrulama/proposer seçimi parçalanıyor.
- **Somut düzeltme önerisi:**
  1. PoA authority set ya genesis'e gömülmeli ya da özel persisted state'e yazılmalı.
  2. Runtime memory injection tek başına kabul edilmemeli.
  3. “restart preserves PoA authorities” testi zorunlu hale getirilmeli.

### 2) Ağ Katmanı

#### H-03 — Yüksek — DNS seed discovery fiilen bozuk; node `tcp/0` adreslerine dial etmeye çalışıyor
- **Etkilenen dosya/fonksiyonlar:**
  - `src/network/node.rs:216-237` (`resolve_dns_seeds`)
  - `src/network/node.rs:604-607` (`Node::run`)
- **Pre-mortem senaryosu:**
  - Operatör gerçek DNS seed yayınlıyor ve seed-based bootstrap'e güveniyor.
  - Runtime `resolve_dns_seeds(..., 0)` çağırdığı için host'lar `:0` ile çözülüyor ve `/tcp/0` multiaddr üretiliyor.
  - Seed dial'ları sessizce başarısız oluyor; node sadece explicit bootnode varsa bağlanabiliyor.
- **Somut düzeltme önerisi:**
  1. DNS seed resolve path'i gerçek varsayılan P2P portunu kullanmalı.
  2. TXT `_dnsaddr` çözümü gerekiyorsa socket-DNS yerine libp2p uyumlu `_dnsaddr` parser'a geçilmeli.
  3. “real DNS seed → successful dial” entegrasyon testi eklenmeli.

#### H-04 — Yüksek — Handshake gossipsub üstünden ve peer-bound değil; relay eden peer yanlışlıkla “handshaked” sayılabilir
- **Etkilenen dosya/fonksiyonlar:**
  - `src/network/node.rs:954-968` (handshake publish)
  - `src/network/node.rs:1046-1087` (pre-handshake gate `propagation_source` üzerinden)
  - `src/network/node.rs:1535-1549` (`set_handshaked(&peer_id, true)`)
- **Pre-mortem senaryosu:**
  - Yeni peer doğrudan kendine özel handshake yerine global `blocks` topic'inde handshake alıyor/gönderiyor.
  - Node, mesajın orijinal imzacısını değil `propagation_source`'u handshake tamamlamış kabul ediyor.
  - Kötü niyetli bir forwarder, başka bir peer'in geçerli handshake'ini mesh üzerinden aktararak kendi connection'ını “handshaked” state'e sokabiliyor.
  - Sonuç: handshake gating güvenlik sınırı olmaktan çıkıyor; message admission yanlış peer'e bağlanıyor.
- **Somut düzeltme önerisi:**
  1. Handshake gossip'ten çıkarılıp direct request/response veya identify-bound kanal üzerinden yapılmalı.
  2. Handshake state'i transport peer ile message signer birlikte doğrulanarak set edilmeli.
  3. `blocks` topic'inde handshake frame taşımak yasaklanmalı.

#### M-01 — Orta — SnapshotChunk yolu yorumda “active request filter” diyor, kodda ise unsolicited session başlatıyor
- **Etkilenen dosya/fonksiyonlar:**
  - `src/network/node.rs:1374-1448`
- **Pre-mortem senaryosu:**
  - Saldırgan hiç `GetStateSnapshot` istemi beklemeden farklı height/session_id'lerle chunk yağdırıyor.
  - Kod yorumunun tersine ilk chunk yeni session başlatıyor (`or_insert_with(...)`).
  - `MAX_CONCURRENT_SNAPSHOTS` sınırı zararı kısmen kısıtlasa da saldırgan 10 eşzamanlı session ile bellek/CPU tüketimi yaratabiliyor.
- **Somut düzeltme önerisi:**
  1. Yalnızca yerel olarak başlatılmış snapshot request'leri için explicit session token tutulmalı.
  2. Unsolicited chunk ilk pakette drop edilmeli.
  3. Height başına allocation üst sınırı ayrıca byte bazında enforced edilmeli.

### 3) Depolama ve State Yönetimi

#### H-05 — Yüksek — Storage challenge/deal state'i zincirin asıl state'inden ayrılmış durumda (split-brain)
- **Etkilenen dosya/fonksiyonlar:**
  - `src/rpc/server.rs:229-305` (`RpcServer.storage` ayrı `StorageRegistry`)
  - `src/rpc/server.rs:1471-1555` (`storage_open_deal` chain + local registry çift yazımı)
  - `src/rpc/server.rs:1728-1804` (`storage_open_challenge` / `storage_answer_challenge` yalnız local registry)
- **Pre-mortem senaryosu:**
  - Deal zincirde açılıyor, challenge RPC'de process-local registry'de ilerliyor.
  - Restart olduğunda RPC registry sıfırlanıyor; chain actor tarafındaki state ile kullanıcıya gösterilen state ayrışıyor.
  - Challenge outcome / operator slash / economics raporları birbirini tutmuyor.
- **Somut düzeltme önerisi:**
  1. `RpcServer.with_storage(...)` gerçek chain-owned registry ile zorunlu kullanılmalı veya local registry tamamen kaldırılmalı.
  2. Storage RPC mutation'ları doğrudan chain actor komutlarına yönlendirilmeli.
  3. Restart testi: deal/challenge/outcome state restart sonrası birebir korunmalı.

#### M-02 — Orta — `metrics_listener` config'i ölü; metrics her zaman `0.0.0.0`'a bind ediliyor
- **Etkilenen dosya/fonksiyonlar:**
  - `src/cli/commands.rs` (`metrics_listener` parse ediliyor)
  - `src/main.rs:949-958` (hard-coded `0.0.0.0:{metrics_port}` bind)
- **Pre-mortem senaryosu:**
  - Operatör metrics'i localhost/private interface ile sınırlandırdığını sanıyor.
  - Runtime bunu yok sayıp tüm arayüzlerde metrics açıyor.
  - Sonuç: istenmeyen telemetri yüzeyi internete açılabiliyor.
- **Somut düzeltme önerisi:**
  1. Metrics server bind adresi `metrics_listener` üzerinden alınmalı.
  2. Varsayılan localhost olmalı; public bind açıkça opt-in olmalı.

### 4) RPC / API Yüzeyi

#### C-03 — Kritik — RPC IP allow-list hem direct kullanımda self-DoS, hem proxy modunda spoofable
- **Etkilenen dosya/fonksiyonlar:**
  - `src/rpc/server.rs:508-562` (`extract_client_ip`, `is_ip_allowed`)
  - `src/cli/commands.rs:277-293` (default `rpc_allowed_ips = [127.0.0.1, ::1]`)
- **Pre-mortem senaryosu:**
  - Operatör default config ile localhost RPC bekliyor.
  - Kod gerçek socket peer IP'sini hiç okumuyor; `trusted_proxies` boşsa header da kabul etmiyor; sonuçta **tüm direct istekler 403** oluyor.
  - Operatör bunu düzeltmek için `trusted_proxies` açarsa, bu sefer `x-forwarded-for` / `x-real-ip` gerçek proxy doğrulaması olmadan kabul ediliyor; header spoof ile allow-list aşılabiliyor.
- **Somut düzeltme önerisi:**
  1. Remote socket address middleware'e taşınmalı; header'lar sadece gerçekten trusted proxy'den gelirse değerlendirilmeli.
  2. `allowed_ips` doluysa direct socket peer IP fallback'i zorunlu olmalı.
  3. Bu düzelene kadar `allowed_ips` security control olarak belgelerde sunulmamalı.

#### M-03 — Orta — RPC tooling sözleşmeleri uyuşmuyor (`bud` CLI fiilen kırık)
- **Etkilenen dosya/fonksiyonlar:**
  - `src/bin/bud.rs:216-224` (`bud_getNonce` sonucunu decimal parse ediyor)
  - `src/bin/bud.rs:263-264` (`bud_getBlockByNumber`'a string gönderiyor)
  - `src/rpc/api.rs:16-18` (`get_block_by_number(number: u64)`)
  - `src/rpc/server.rs` (`get_nonce` hex string döndürüyor)
- **Pre-mortem senaryosu:**
  - Operatör `bud tx send` ile nonce otomatik almak istiyor; RPC `0x...` döndürüyor, CLI decimal parse ettiği için hata veriyor.
  - `bud query block latest` dokümandaki gibi kullanıldığında method `u64` beklediği için param-type mismatch oluşuyor.
- **Somut düzeltme önerisi:**
  1. CLI hex nonce parse etmeli.
  2. API “latest” semantiğini destekleyecek şekilde `String` veya tagged enum kullanmalı.
  3. CLI/RPC compatibility integration test'i eklenmeli.

#### M-04 — Orta — Bazı RPC endpoint'leri stub durumda, gerçek chain actor'a bağlı değil
- **Etkilenen dosya/fonksiyonlar:**
  - `src/rpc/server.rs:3753-3767` (`get_domain_info`, `get_slashing_history`)
- **Pre-mortem senaryosu:**
  - Monitoring/audit araçları bu endpoint'lere güveniyor.
  - RPC hep statik/boş veri döndürdüğü için operatör zincir durumunu yanlış okuyor.
- **Somut düzeltme önerisi:**
  1. Bu endpoint'ler gerçek data sağlamadan public API'de tutulmamalı.
  2. ChainActor komutları eklenip gerçek state'e bağlanmalı; aksi halde method kaldırılmalı.

#### M-05 — Orta — Legacy `rpc.host`/`rpc.port` fallback'i literal `h:{p}` üretiyor
- **Etkilenen dosya/fonksiyonlar:**
  - `src/cli/commands.rs:653-656`
- **Pre-mortem senaryosu:**
  - V1/legacy konfig kullanan operatör host+port girdiğini sanıyor.
  - Runtime gerçek host adı yerine literal `h:PORT` üretiyor.
  - Sonuç: listener yanlış adrese bağlanıyor veya parse başarısız oluyor.
- **Somut düzeltme önerisi:**
  - `format!("{h}:{p}")` olacak şekilde düzeltilmeli ve legacy-config regression testi eklenmeli.

### 5) Relayer / Cross-Domain / Bridge

#### C-04 — Kritik — Relay pipeline prod akışında başlayamıyor; pending-relay kuyruğu üretim kodunda hiç doldurulmuyor
- **Etkilenen dosya/fonksiyonlar:**
  - `src/chain/blockchain.rs:1859-1919` (`enqueue_bridge_relay`, `submit_relay_proof`)
  - Statik çağrı grafiği: `enqueue_bridge_relay` sadece testlerde çağrılıyor (`src/tests/relayer_e2e.rs`, `src/tests/bridge_negatives.rs`)
- **Pre-mortem senaryosu:**
  - Source domain'de bridge event oluşuyor.
  - Production kodu bunu `UniversalRelayer` pending kuyruğuna koymuyor.
  - Relayer proof submit sırasında `pending_relay(&message_id)` boş dönüyor ve akış `no pending relay` ile patlıyor.
  - Sonuç: köprü “tasarımda var, prod'da yok” durumuna düşüyor.
- **Somut düzeltme önerisi:**
  1. Bridge lock/burn event oluştuğu anda `enqueue_bridge_relay` production path'ine bağlanmalı.
  2. Pending relay ledger persisted olmalı; restart'ta kaybolmamalı.
  3. “bridge event → pending relay → proof submit → mint/unlock” uçtan uca restart testi eklenmeli.

#### H-06 — Yüksek — Relayer binary, node RPC sözleşmesini yanlış varsayıyor; aktif-relayer check ve proof formatı uyumsuz
- **Etkilenen dosya/fonksiyonlar:**
  - `src/bin/budlum-relayer.rs:156-202` (`is_active_relayer`, `submit_relay_proof`)
  - `src/bin/budlum-relayer.rs:292-373` (`get_deposit_logs`, `build_deposit_proof` placeholder)
  - `src/bin/budlum-relayer.rs:510-617` (runtime loop)
  - `src/rpc/server.rs:1321-1340` (`bud_registryActiveMembers` object döndürüyor)
  - `src/rpc/api.rs:167-175` (`bud_submitRelayProof` typed `MerkleProof` bekliyor)
- **Pre-mortem senaryosu:**
  - Relayer, `bud_registryActiveMembers` sonucunu array sanıyor; node ise `{ roleId, count, members }` object döndürüyor.
  - Relayer active-check ya false-negative veriyor ya da RPC hata alınca “assume active” diyerek devam ediyor.
  - Ardından proof tarafında typed `MerkleProof` yerine placeholder JSON object gönderiyor; ayrıca Ethereum event parse'ı `topics` filtresi olmadan tüm logları topluyor, amount/recipient'i sıfır/zero-address set ediyor.
  - Sonuç: relayer ya hiç çalışmıyor ya da yanlış event/proof üretmeye çalışıyor.
- **Somut düzeltme önerisi:**
  1. Relayer ve RPC tek bir ortak type crate'i kullanmalı.
  2. `bud_registryActiveMembers` parse'ı server'ın gerçek JSON shape'ine göre düzeltilmeli.
  3. Placeholder proof/event parse kodu main branch'de bırakılmamalı; feature-gated dev stub'a taşınmalı.

### 6) Kriptografi ve HSM/PKCS#11

#### H-07 — Yüksek — “PKCS#11-backed BLS/PQ” gerçekte software fallback; extracted key material ile imza atılabiliyor
- **Etkilenen dosya/fonksiyonlar:**
  - `src/crypto/pkcs11.rs:83-118` (startup'ta `extract_data_object` ile BLS/PQ key load)
  - `src/crypto/pkcs11.rs:287-307` (`Sensitive + Extractable(false)` denirken aynı kod path software extraction varsayıyor)
  - `src/crypto/pkcs11.rs:441-485` (`bls_sign` / `pq_sign` vendor fail → software fallback)
  - `src/main.rs:500-519` (mainnet validator policy yalnız `has_bls_key()` / `has_pq_key()` kontrol ediyor)
- **Pre-mortem senaryosu:**
  - Operatör “mainnet validator HSM-backed” varsayımıyla node açıyor.
  - Vendor-native BLS/PQ mekanizması yoksa veya hata verirse kod extracted software key ile imzaya düşüyor.
  - Sonuç: operasyonel güvenlik politikası (secret HSM dışına çıkmamalı) ihlal edilmiş oluyor; HSM entegrasyonu kağıt üzerinde kalıyor.
- **Somut düzeltme önerisi:**
  1. Mainnet'te vendor-native BLS/PQ mekanizmaları **zorunlu** kılınmalı; fallback yasaklanmalı.
  2. Extracted DATA-object fallback yalnız dev/test feature'ı altında bırakılmalı.
  3. Startup policy `vendor_native_signing_configured()` kontrol etmeli.
- **Onaylanan karar:** Mainnet'te **vendor-native BLS+PQ zorunlu** olacak; software fallback production'da yasaklanacak ve bu capability yoksa validator node açılmayacak.

### 7) Build / CI / Dependency Security

#### M-06 — Orta — CI/build yüzeyinde drift var; tüm target doğrulaması temiz değil
- **Etkilenen dosya/fonksiyonlar:**
  - `Cargo.toml:117-121` (`required-features = ["__bench_domain_throughput_disabled"]` ama feature tanımlı değil)
  - `.github/workflows/ci.yml` (`cargo clippy --all-targets -- -D warnings` bekliyor)
- **Pre-mortem senaryosu:**
  - Geliştirici veya CI tüm target'ları lint ederken Cargo invalid-feature warning basıyor.
  - Test-target derlemesi ağırlaştığında CI/sandbox kaynak tüketimi yüzünden sahte negatifler oluşabiliyor.
- **Somut düzeltme önerisi:**
  1. Hayali feature ya `[features]` altına eklenmeli ya da bench gating başka yolla yapılmalı.
  2. `cargo test --lib --no-run` ve `cargo clippy --tests` ayrı job'lara bölünüp OOM riski azaltılmalı.

#### M-07 — Orta — `cargo audit` script'i yalnız kök lockfile'ı tarıyor; `budzero/Cargo.lock` ayrı script kapsamına alınmamış
- **Etkilenen dosya/fonksiyonlar:**
  - `scripts/audit-deps.sh:29-33`
- **Pre-mortem senaryosu:**
  - Root tree temiz kalırken `budzero/` tarafında yeni bir advisory çıkıyor.
  - `dependency-audit` script'i bunu hiç görmüyor; yalnız cargo-deny advisory matrisine güvenilmiş oluyor.
- **Somut düzeltme önerisi:**
  1. Script hem `Cargo.lock` hem `budzero/Cargo.lock` için `cargo audit` çalıştırmalı.
  2. Çıktılar ayrı raporlanmalı.
- **Yerel doğrulama notu:**
  - Manuel çalıştırmada her iki lockfile için de CVE bulunmadı.

#### M-08 — Orta — CVE yok, fakat sürdürülebilirlik riski oluşturan unmaintained/yanked bağımlılıklar var
- **Etkilenen bağımlılıklar (manuel audit):**
  - Root lockfile warnings: `bincode 1.3.3`, `fxhash 0.2.1`, `instant 0.1.13`, `paste 1.0.15`, `pqcrypto-dilithium 0.5.0`, `pqcrypto-internals 0.2.11`, `pqcrypto-traits 0.3.5`, `atomic-polyfill 1.0.3`, `spin 0.9.8 (yanked)`
  - BudZero warnings: `bincode`, `paste`, `atomic-polyfill`, `spin`
- **Pre-mortem senaryosu:**
  - Yeni bir supply-chain advisory çıktığında upgrade path bakımsız crate'ler nedeniyle pahalı / bloklayıcı hale geliyor.
- **Somut düzeltme önerisi:**
  1. `bincode` migration planı hazırlanmalı.
  2. PQ stack için `pqcrypto-mldsa` / sürdürülen backend geçiş kararı netleştirilmeli.
  3. `fxhash` gibi non-cryptographic / unmaintained parçalar gözden geçirilmeli.

---

## Build / CI Sonuç Özeti

| Kontrol | Sonuç | Not |
|---|---|---|
| `cargo check --locked --lib` | Geçti | MSRV 1.94.0 ile sandbox'ta doğrulandı |
| `cargo fmt --all -- --check` | Geçti | Format drift görülmedi |
| `cargo clippy --locked --lib -- -D warnings` | Geçti | Lib yüzeyi temiz |
| `cargo clippy --locked --all-targets -- -D warnings` | Tam doğrulanamadı | `Cargo.toml:120` invalid-feature warning + test-target compile sandbox `SIGKILL` |
| `cargo test --locked --lib` | Tamamlanamadı | Sandbox süre/kaynak sınırı |
| `cargo audit --file Cargo.lock -q` | Geçti | CVE yok, 9 warning |
| `cargo audit --file budzero/Cargo.lock -q` | Geçti | CVE yok, 4 warning |

---

## Onaylanan Kararlar

1. **Validator onboarding modeli:** Stake kabul edilecek; ancak gerekli consensus anahtarları (özellikle VRF/BLS/PoP) tamamlanmadan validator **aktif** sayılmayacak ve quorum'a girmeyecek.

2. **Mainnet HSM politikası:** **Vendor-native BLS+PQ zorunlu** olacak; software fallback yasaklanacak.

3. **Hibrit consensus kapsamı:** PoW/PoS/BFT/PoA bootstrap alanları bu release hattında **gerçek wiring'e bağlanacak**; mimari iddia daraltılmayacak.

4. **Storage RPC mimarisi:** **Tek source-of-truth chain actor state** modeli benimsenecek; process-local ayrık registry kaldırılacak veya tamamen ikincil hale getirilecek.

---

## Kapsam Dışı / İncelenemeyen Alanlar

- GitHub Actions private runner logları / org secrets / protected branch runtime davranışı doğrudan görülemedi.
- Gerçek HSM donanımı olmadığı için vendor-native PKCS#11 mekanizmalarının runtime davranışı yalnız kod seviyesinde incelendi.
- Tam test suite runtime sonucu sandbox kaynak sınırı nedeniyle alınamadı; aşağıdaki test sayıları **kaynak dosya anotasyonlarından** türetilmiştir.
- Repo içinde bağımsız Solidity deployable contract seti bulunmadığından on-chain external bridge contract audit'i yapılmadı.

---

## Dosya Bazlı Test Sayıları

\\* Sayılar `#[test]` ve `#[tokio::test]` anotasyonlarının kaynak koddan statik sayımıdır; `proptest!` içindeki örnek sayısı ve runtime-generated cases bu tabloda çoğaltılmamıştır.

| Dosya | Test sayısı* |
|---|---:|
| `src/ai/execution/guest.rs` | 17 |
| `src/ai/execution/model_class.rs` | 1 |
| `src/ai/execution/verify.rs` | 2 |
| `src/ai/mod.rs` | 129 |
| `src/bin/budlum-relayer.rs` | 5 |
| `src/chain/blockchain.rs` | 20 |
| `src/chain/fee_market.rs` | 12 |
| `src/chain/finality.rs` | 15 |
| `src/chain/genesis.rs` | 18 |
| `src/chain/snapshot.rs` | 13 |
| `src/chain/storage_economics_tests.rs` | 1 |
| `src/cli/commands.rs` | 7 |
| `src/consensus/mod.rs` | 1 |
| `src/consensus/poa.rs` | 3 |
| `src/consensus/pos.rs` | 3 |
| `src/consensus/pow.rs` | 6 |
| `src/consensus/qc.rs` | 14 |
| `src/core/account.rs` | 27 |
| `src/core/block.rs` | 7 |
| `src/core/chain_config.rs` | 3 |
| `src/core/constitution.rs` | 5 |
| `src/core/encoding.rs` | 5 |
| `src/core/governance.rs` | 13 |
| `src/core/hash.rs` | 2 |
| `src/core/metrics.rs` | 1 |
| `src/core/transaction.rs` | 10 |
| `src/cross_domain/bridge.rs` | 3 |
| `src/cross_domain/bridge_relayer.rs` | 11 |
| `src/cross_domain/chain_adapter.rs` | 5 |
| `src/cross_domain/event_tree.rs` | 1 |
| `src/cross_domain/evm/adapter.rs` | 10 |
| `src/cross_domain/evm/bud_to_eth.rs` | 4 |
| `src/cross_domain/evm/header.rs` | 7 |
| `src/cross_domain/evm/mpt.rs` | 14 |
| `src/cross_domain/evm/receipt.rs` | 10 |
| `src/cross_domain/evm/rlp.rs` | 19 |
| `src/cross_domain/evm/sync_committee.rs` | 9 |
| `src/cross_domain/evm/verify.rs` | 8 |
| `src/cross_domain/message.rs` | 1 |
| `src/cross_domain/message_registry.rs` | 4 |
| `src/cross_domain/nonce.rs` | 4 |
| `src/cross_domain/relayer.rs` | 12 |
| `src/crypto/mainnet_policy.rs` | 8 |
| `src/crypto/pkcs11.rs` | 10 |
| `src/crypto/primitives.rs` | 9 |
| `src/crypto/signer.rs` | 2 |
| `src/deed/mod.rs` | 5 |
| `src/developer_os.rs` | 5 |
| `src/domain/commitment_registry.rs` | 2 |
| `src/domain/finality_adapter.rs` | 6 |
| `src/domain/fork_choice.rs` | 6 |
| `src/domain/plugin_registry.rs` | 2 |
| `src/domain/registry.rs` | 4 |
| `src/domain/sovereign.rs` | 9 |
| `src/domain/storage_deal.rs` | 24 |
| `src/domain/storage_params.rs` | 8 |
| `src/domain/types.rs` | 1 |
| `src/execution/proof_verifier.rs` | 10 |
| `src/execution/zkvm.rs` | 5 |
| `src/gateway/atlas.rs` | 1 |
| `src/gateway/passport.rs` | 7 |
| `src/hub/mod.rs` | 3 |
| `src/lib.rs` | 1 |
| `src/lubot/executor.rs` | 2 |
| `src/lubot/inference.rs` | 1 |
| `src/lubot/metrics.rs` | 1 |
| `src/lubot/mod.rs` | 4 |
| `src/lubot/query.rs` | 1 |
| `src/lubot/social.rs` | 1 |
| `src/lubot/verify.rs` | 3 |
| `src/mempool/pool.rs` | 9 |
| `src/network/gossip_dedup.rs` | 11 |
| `src/network/mobile.rs` | 13 |
| `src/network/node.rs` | 1 |
| `src/network/peer_manager.rs` | 24 |
| `src/network/proto_conversions.rs` | 10 |
| `src/pollen/data_rights.rs` | 7 |
| `src/pollen/encryption_policy.rs` | 12 |
| `src/pollen/mod.rs` | 8 |
| `src/pollen/offers.rs` | 10 |
| `src/privacy/note_registry.rs` | 2 |
| `src/prover/market.rs` | 6 |
| `src/prover/mod.rs` | 2 |
| `src/registry/d4_merge_tests.rs` | 8 |
| `src/registry/evidence.rs` | 7 |
| `src/registry/invalid_vote.rs` | 5 |
| `src/registry/liveness.rs` | 4 |
| `src/registry/params.rs` | 3 |
| `src/registry/permissionless.rs` | 14 |
| `src/registry/poa_compliance.rs` | 10 |
| `src/registry/poa_membership.rs` | 4 |
| `src/registry/poa_onboarding.rs` | 2 |
| `src/registry/role.rs` | 9 |
| `src/relayer/policy.rs` | 14 |
| `src/rpc/atlas.rs` | 9 |
| `src/rpc/server.rs` | 1 |
| `src/rpc/tests.rs` | 11 |
| `src/sdk/contracts.rs` | 6 |
| `src/sdk/devnet.rs` | 6 |
| `src/sdk/fixture.rs` | 6 |
| `src/sdk/mod.rs` | 4 |
| `src/sdk/runner.rs` | 5 |
| `src/settlement/commitment_tree.rs` | 1 |
| `src/settlement/global_block.rs` | 7 |
| `src/settlement/proof_market.rs` | 11 |
| `src/settlement/proof_verifier.rs` | 2 |
| `src/socialfi/mod.rs` | 1 |
| `src/storage/content_id.rs` | 5 |
| `src/storage/db.rs` | 4 |
| `src/storage/lifecycle.rs` | 4 |
| `src/storage/manifest.rs` | 9 |
| `src/storage/merkle_trie.rs` | 12 |
| `src/storage/mobile_self.rs` | 3 |
| `src/storage/provider.rs` | 4 |
| `src/storage/pruning.rs` | 6 |
| `src/tests/adversarial_p2p.rs` | 4 |
| `src/tests/block_reward.rs` | 4 |
| `src/tests/bns.rs` | 2 |
| `src/tests/bns_expanded.rs` | 6 |
| `src/tests/bridge_lifecycle.rs` | 3 |
| `src/tests/bridge_negatives.rs` | 6 |
| `src/tests/bud_e2e.rs` | 12 |
| `src/tests/byzantine_settlement.rs` | 18 |
| `src/tests/chaos.rs` | 21 |
| `src/tests/consensus_digest.rs` | 1 |
| `src/tests/consensus_expanded.rs` | 8 |
| `src/tests/constitution_engine.rs` | 3 |
| `src/tests/deed.rs` | 1 |
| `src/tests/disaster_recovery.rs` | 5 |
| `src/tests/distributed_settlement.rs` | 5 |
| `src/tests/domain_edge_cases.rs` | 11 |
| `src/tests/encryption_dao.rs` | 3 |
| `src/tests/finality_adversarial.rs` | 12 |
| `src/tests/finality_live_path.rs` | 4 |
| `src/tests/genesis_repro.rs` | 1 |
| `src/tests/hard_prune.rs` | 1 |
| `src/tests/hardening.rs` | 16 |
| `src/tests/hardening_h2_locks.rs` | 7 |
| `src/tests/hardening_h4_locks.rs` | 5 |
| `src/tests/hardening_h5_h7_locks.rs` | 11 |
| `src/tests/hardening_locks.rs` | 6 |
| `src/tests/integration.rs` | 53 |
| `src/tests/liveness_consensus.rs` | 7 |
| `src/tests/load_test.rs` | 2 |
| `src/tests/migration_v2.rs` | 3 |
| `src/tests/permissionless.rs` | 22 |
| `src/tests/permissionless_e2e.rs` | 1 |
| `src/tests/persistence.rs` | 9 |
| `src/tests/poa_isolation.rs` | 8 |
| `src/tests/poa_onboarding_matrix.rs` | 8 |
| `src/tests/pollen_ai_data_rights.rs` | 7 |
| `src/tests/pow_light_client.rs` | 1 |
| `src/tests/privacy_ai_execution.rs` | 7 |
| `src/tests/private_transfer_fee_market.rs` | 1 |
| `src/tests/proptest_core.rs` | 3 |
| `src/tests/prover.rs` | 8 |
| `src/tests/qcblob_quorum.rs` | 4 |
| `src/tests/regression_lock.rs` | 12 |
| `src/tests/relayer_e2e.rs` | 8 |
| `src/tests/relayer_gates.rs` | 8 |
| `src/tests/relayer_liveness.rs` | 15 |
| `src/tests/replay_audit.rs` | 2 |
| `src/tests/security_auditor.rs` | 4 |
| `src/tests/settlement_prod.rs` | 59 |
| `src/tests/slashing_matrix.rs` | 8 |
| `src/tests/snapshot_chaos.rs` | 8 |
| `src/tests/socialfi.rs` | 2 |
| `src/tests/target_700.rs` | 6 |
| `src/tests/tokenomics.rs` | 13 |
| `src/tests/tokenomics_proptest.rs` | 5 |
| `src/tests/v95_v98_canaries.rs` | 2 |
| `src/tests/zkvm.rs` | 8 |
| `src/tokenomics/mod.rs` | 11 |
| `src/tokenomics/reward_pool.rs` | 7 |
