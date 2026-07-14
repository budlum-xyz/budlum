# Bölüm 12: Production Hardening Durumu

Bu bölüm reponun güncel operasyonel gerçeklik tablosudur. Budlum Core kontrollü public-devnet adayıdır. Denetlenmiş Mainnet yazılımı değildir ve gerçek ekonomik değer taşımamalıdır.

## 1. Uygulanan Korumalar

| Alan | Güncel davranış |
| --- | --- |
| Konfigürasyon | Katı Config V2 bilinmeyen alanları, profil/chain-ID uyumsuzluğunu, güvensiz Mainnet feature flag'lerini, eksik Mainnet genesis'i, boş Mainnet seed ayarını ve Mainnet mDNS kullanımını reddeder. |
| Genesis | `genesis build` private key materyalini yazdırmaz. Otomatik allocation anahtarı yalnız devnet için ve açık output dosyasıyla üretilebilir. Devnet dışı genesis açık validatör listesi ister. |
| Başlangıç | Storage açılış hataları başlangıcı durdurur. Mevcut DB ayarlanan genesis kimliğine karşı kontrol edilir. Özel genesis dosyası parse edilmeli ve seçili chain ID ile eşleşmelidir. |
| State commitment | `ConsensusStateV2` hesapları, validatörleri, unbonding kuyruğunu, ekonomiyi, bridge, message, settlement ve global-header özet state'ini bağlar. |
| Kalıcılık | Canonical değişiklikler `IN_PROGRESS_HEIGHT` recovery marker'ı ve atomik Sled batch içeren `DurableCommitBatch` kullanır. |
| Snapshot aşaması | Snapshot dosyaları sayısal sıralanır; bozuk en yeni dosya karantinaya alınır. `StateSnapshotV2` genişletilmiş konsensüs metadata'sı taşır. |
| RPC tabanı | Ayrı public/operator listener, API-key auth, CORS/IP filtresi, trusted-proxy doğrulaması, IP başına kayan pencere quota'sı ve 10.000 istemcilik bellek tavanı vardır. Yönetim mutasyonları public listener'da reddedilir. |
| CI | GitHub Actions Rust `1.94.0` sürümünü pinler; format, `cargo check`, warning'leri reddeden Clippy, workspace testleri ve `--release --locked` build çalıştırır. |
| PKCS#11 | `ConsensusSigner` trait + `Pkcs11Signer` adaptörü (`cryptoki` ile) + `KeyPairSigner` local fallback. `ConsensusEngine` trait `fn signer()` sunar. Blok imzalama HSM varsa onu, yoksa local dosyayı kullanır. Mainnet başlangıç engeli kalktı. |

## 2. Aşamalı veya Kısmi İşler

| Alan | Sınır |
| --- | --- |
| Finality | Prevote/Precommit struct'ları, `FinalityAggregator`, sertifika üretimi ve doğrulaması uygulandı ve test edildi. Gossip mesajları `ChainActor`'a yönlendiriliyor, oradan `Blockchain` aggregator'ına gönderiliyor. Checkpoint blok sonrası prevote fazı otomatik başlıyor. BLS imzalı vote üretimi (`sign_prevote`/`sign_precommit` → gerçek `sign_bls`), quorum sonrası sertifika yayını (`NetworkMessage::FinalityCert`) ve uygulanması **TAMAMLANDI ve test edildi** (Tur 13-14: `src/tests/finality_adversarial.rs`). **Tur 14 sağlamlaştırması:** (1) ingest-time BLS imza doğrulaması — geçersiz/bozuk imza aggregat'a hiç girmez, dürüst alt-küme her zaman finalize eder (tek-imza DoS kapatıldı); (2) equivocation (çifte imza) tespit edilince canonical `DoubleSign` slashing-evidence üretilip mevcut `submit_registry_slashing_report` yolundan geçirilerek gerçek slash uygulanır (uçtan uca test edildi). |
| P2P | Version ve chain ID zorlanır. Validator-set hash ve scheme policy, kalıcı kimlik, profil kontrollü mDNS, DNS seed ve kalıcı ban runtime bağlantıları eksiktir. |
| RPC | Public/operator listener ayrıdır; trusted proxy, body/connection limitleri ve bounded IP başına quota canlıdır. İmzasız legacy bond/domain/asset yönetim yardımcıları operator-only'dir. |
| Metrics | Zincir/finality/mempool/P2P collector'larına ek olarak block propagation, consensus round ve storage read/write histogramları canlıdır. Dashboard/SLO operatör sorumluluğudur. |
| Snapshot V2 | Canonical restore ve P2P chunk/session bağlama uygulanmıştır; release migration çerçevesi Tur 13.9 konusudur. |
| Storage | Durable block commit + Tur 13.5 atomik doğrulanan backup, retention, boş hedefe restore ve integrity drill uygulanmıştır. Tam ConsensusStateV2 release migration'ı açıktır. |

## 3. Açık Mainnet Engelleri

1. ~~PKCS#11 konsensüs signer adapter'ını uygula ve denetle.~~ **TAMAMLANDI (v0.2-dev):** `Pkcs11Signer` (`cryptoki` HSM backend), `ConsensusSigner` trait, `KeyPairSigner` local fallback, PoS/PoA blok üretimine bağlandı.
2. ~~BLS imzalı prevote/precommit vote **üretimini**, canlı sertifika yayınını ve saldırgan çok node'lu finality testlerini tamamla.~~ **TAMAMLANDI (Tur 13):** BLS vote üretimi (`sign_prevote`/`sign_precommit`), sertifika yayını (`NetworkMessage::FinalityCert`) ve uygulanması bağlıydı; eksik olan adversarial test kapsamı `src/tests/finality_adversarial.rs` ile kapatıldı. **Tur 14:** ingest-time imza doğrulaması + equivocation→`DoubleSign` slashing-evidence üretimi eklendi (aggregator sağlamlaştırması, uçtan uca slash test edildi).
3. ~~Public/operator RPC, trusted proxy, health, body/connection limitleri ve bounded istemci quota'sı.~~ **TAMAMLANDI (Tur 13.5 dahil).**
4. ~~Kalıcı P2P kimliği, discovery politikası, DNS seed ve kalıcı peer ban bağlantıları.~~ **TAMAMLANDI.**
5. ~~Snapshot V2 restore, dağıtım/session bağlama, backup restore tatbikatı ve archive politikası.~~ **TAMAMLANDI (Tur 13.5):** `config/archive.toml`, atomik `.budbak`, retention, boş hedef restore + integrity drill.
6. Governance, BudZKVM contract ve pruning özelliklerini ayrı incelemeler tamamlanana kadar Mainnet v1 için kapalı tut.
7. Deployment paketleri, release ceremony kayıtları, dashboard'lar, incident runbook'ları, fault injection, fuzzing sonuçları ve dış güvenlik denetimi üret.

## 4. Release Kapıları

Her release adayı şu komutları geçmelidir:

```bash
nix develop --command cargo fmt --all -- --check
nix develop --command cargo clippy --workspace --all-targets --all-features -- -D warnings
nix develop --command cargo test --workspace
nix develop --command cargo build --release --locked
git diff --check
```

Kritik adapter'lar tamamlanmadığı sürece Mainnet profili bilinçli olarak fail-closed davranır.
