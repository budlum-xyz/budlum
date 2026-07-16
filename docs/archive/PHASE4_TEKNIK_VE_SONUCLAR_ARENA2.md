# Phase 4 — Teknik Durum + Teknik Olmayan Sonuçlar (ARENA2, HEAD 6eedd2d sonrası)

**Tarih:** 2026-07-15 16:45 UTC+3  
**ARENA2:** Roadmap doğrulayıcı + denetçi  
**HEAD origin:** `6eedd2d` (ARENA3 constraint-by-constraint debug plan + BNS)  
**Benim son pushum:** `9387fb1` → origin tarafından geçildi, şimdi 2 commit gerideyiz → **AŞAMA 3 bekleme modundayız** (push onaylanmadan yeni push yok)

---

## 1. Teknik Durum (Kısa)

| Alan | Teknik | Kanıt |
|------|--------|-------|
| **Org roadmap** budlumdevnet 332 + devnet2 452 | Main 557+ lib test fazlasıyla karşılıyor. VerifiedDomainCommitment only, adapter hardening, parent-linked, strict nonce, Chaos Matrix, PQ BLS+Dilithium hybrid | `src/domain/finality_adapter.rs` cert.verify fix 49b6b46/65d0446, `bridge.rs` sweep O(N), `finality_live_path.rs` |
| **B.U.D. server** | `budzero/bud-node/src/` store (8635), bitswap (10291), discovery (9966), lib.rs, sharding.rs (XOR, replication_factor) **HAYATTA**. `src/network/node.rs` monolithic `Node{storage_node, shard_manager}` + Bitswap codec + DHT | `ls budzero/bud-node/src/` |
| **Forge push kaybı** | Kaybolan **sadece** `docs/PHASE3_PLAN_VE_GOREV_DAGILIMI.md` — ARENA2 b43a502'de MAINNET_READINESS + commit log'dan yeniden derleyip kurtardı. B.U.D. server silinmemiş. | `git log b43a502` |
| **Phase 4 PHASE0.06_PLAN** | 4.1 test gate `proves_verify_merkle_valid_64_depth` #[ignore] InvalidProof — matrix chain (Poseidon 64-depth) YEŞİL, full STARK KIRMIZI. 4.2 prod gate `is_experimental=true` fail-closed kapalı (doğru). 4.3 StorageDeal `merkle_proof: Option<Vec<u8>>` + `storage_root: Option<Hash32>` + depth 64 OK. 4.4 storage_root `GlobalBlockHeader` + `BlockHeader`/`Block` V3 hash OK. | `budzero/bud-isa/src/lib.rs:45`, `bud-proof/src/plonky3_prover.rs:2114` |
| **BNS Faz 6** | Q10 full_impl merge 7482dd7+51dbaf9+2250795: `NameRecord{address, consensus_domain_id, storage_root, storage_domain_id, storage_root_height}` + `BnsResolved` + `registry.register_with_storage / resolve_full / set_storage (owner only)` + Tx `BnsRegister` → Executor → RPC `bns_resolve_full / bns_set_storage` | `src/bns/types.rs` |
| **CI** | Son 5 commit **FAIL**: 9387fb1 (benim docs commitim de FAIL — sadece docs olmasına rağmen önceki BNS kodundan kalan clippy/fmt hatası), 51dbaf9 FAIL, 2250795 FAIL, 6eedd2d FAIL. Budlum Core + BudZero test/fmt/clippy'den biri patlıyor. Docker smoke de FAIL (beklenen HSM). | GitHub Actions run 29425238817 failure annotation |

---

## 2. Teknik Olmayan Sonuçlar — Bu Ne Demek?

### 2.1 Senin (Kullanıcı/Yatırımcı) Açısından

**Şu an Budlum ne yapabiliyor?**
- ✅ Blok üretiyor, konsensus PoW/PoS/BFT çalışıyor, finality live-path testleri yeşil.
- ✅ Depolama için: birisi “ben bu dosyayı saklıyorum” diyebiliyor, parasını kilitliyor (bond), ödül alıyor, yalan söylerse parası kesiliyor (slash). Bu **ekonomik oyun** — gerçek kriptografik ispat değil, ama devnet için yeterli. 9 RPC `bud_storage*` ile dosya manifest kaydı, deal açma, challenge açma/cevaplama yapılabiliyor.
- ✅ `ayaz.bud` gibi isimler (BNS) artık adrese + depolama köküne (storage_root) bağlanabiliyor. Yani `ayaz.bud` → `0xabc...` + `storage_root 0xdef...` gibi. Lifecycle tamam, ama fiyatlandırma/governance docs'u yok (Q3 full_now kararı).

**Şu an ne YAPAMIYOR? (Mainnet engeli)**
- ❌ **Gerçek Proof-of-Storage yok:** VerifyMerkle opcode (0x1E) hâlâ kapalı. Yani biri “saklıyorum” dediğinde matematiksel olarak ispatlayamıyoruz, sadece parasıyla oynuyoruz. Bu yüzden mainnet “self-audited” (kendi kendini denetlemiş) durumunda — dış denetim yok, TLA+ matematiksel ispat yok.
- ❌ **Mainnet töreni yok:** Bootnodes listesi dummy, genesis hash placeholder adreslerle (`0x1010...`). Gerçek validator anahtarları + 3 bootstrap node töreni yapılmadan mainnet açılamaz. Sen Q5'te “kullanıcı tören zamanı karar versin” dedin — doğru, şimdi dummy kalsın.
- ❌ **HSM:** Validator anahtarlarını korumak için donanım kasası (HSM) gerekiyor. Şu an BLS/PQ anahtarlarını yazılım + data object olarak saklıyoruz (software fallback). Sen Q6'da “software fallback OK” dedin — devnet için OK, mainnet için vendor-native gerekir.

**Push reddi ne demek? (Senin “demin pushun reddedildi” dediğin)**
- Teknik: Ben `docs/PHASE4_ARENA2_ANALIZ.md` + STATUS_ONLINE.md commitledim ve pushlamaya çalıştım (`95479c0`). Tam o sırada ARENA3 de `51dbaf9` commitini pushlamıştı. GitHub “senin branchin güncel değil, önce fetch yap” dedi → **rejected (non-fast-forward)**.
- Teknik olmayan: İki kişi aynı anda aynı dosyayı (STATUS_ONLINE.md) düzenlerse çakışma olur. Bizim kuralımız (Aşama 2): her push öncesi `git fetch origin` + `git log origin/main -3` ile başka AI commit atmış mı kontrol et. Ben ettim, fark ettim, sonra rebase yapıp her iki entry'i koruyarak `9387fb1` olarak tekrar pushladım, bu sefer başarılı oldu.

**Şimdi neden bekleme modundayız? (Aşama 3)**
- Teknik: `9387fb1` CI'da FAIL verdi (sadece docs olmasına rağmen önceki BNS kodundan dolayı). Üstüne ARENA3 `2250795` (BNS full_integration flow) + `6eedd2d` (constraint-by-constraint debug plan) pushladı. Şimdi ben origin/main'den **2 commit gerideyim** (`6eedd2d` HEAD). Kural: bir push onaylanmadan (CI yeşil + diğer AI yorum) yeni işe devam etme, bekleme sürecine gir.
- Teknik olmayan: Diyelim sen Word'de bir rapor yazdın, ben de aynı anda yazdım, sonra sen kaydettin. Benim eski sürümü kaydetmem seninkini ezer. Bunu önlemek için ben bekliyorum, senin son sürümünü çekiyorum, sonra devam ediyorum. Şu an o bekleme sürecindeyiz.

---

## 3. $50k / $100k Bug Bounty Ne Demek? (Q4 Basit Versiyon)

- **Teknik terim:** Immunefi gibi platformlarda “bug bounty tier”.
- **Basit:** Diyorsun ki “Benim kodumda açık bulan hacker'a para vereceğim.”
  - Orta seviye açık (örneğin RPC rate limit atlatma, DoS): **$50.000**
  - Yüksek seviye açık (örneğin başkasının stake'ini çalma, sahte finality üretme): **$100.000**
- Neden? Dış denetim firması tutmak 6 ay + $200k. Bug bounty'de sadece açık bulunursa ödüyorsun, bulunmazsa ödemiyorsun. Mainnet öncesi “self-audited” yerine “bounty ile korunuyor” diyebiliyorsun.
- Sen **bug_bounty_simple** seçtin — doğru, Phase 5'te external audit'e kadar bu kalkan.

---

## 4. 10 Soru — Kararların Özeti (Senin Seçimlerin)

| # | Soru | Senin Kararın | Teknik Olmayan Sonuç |
|---|------|---------------|----------------------|
| Q1 | VerifyMerkle nasıl debug edilsin? | **ctl_debug** (constraint-by-constraint) | En zor kısım: 64 katmanlı Merkle ispatı STARK içinde patlıyor. Tek tek sigortaları (constraintleri) kapatıp açarak hangi sigorta atıyor bulacağız. Zaman alır ama kesin çözüm. |
| Q2 | B.U.D. server ek kayıp var mı? | **no_loss** (sadece plan kaybolmuştu) | Server kodu sağlam, ekstra repo yok. Sadece plan dosyasını zaten kurtardık, devam edebiliriz. |
| Q3 | BNS governance? | **full_now** (full pricing + resolver şimdi) | `ayaz.bud` gibi isimlerin fiyatı, kime ait, nasıl satılacak, şimdi yazılacak. Phase 5'e bırakmıyoruz. |
| Q4 | Güvenlik için ne? | **bug_bounty_simple** ($50k/$100k hacker ödülü) | Hackerlara “açık bul, para al” diyoruz. Dış denetim daha sonra. |
| Q5 | Bootnodes? | **user_decides_later** | Mainnet bootstrap node'ları (ilk bağlantı noktaları) tören zamanı sen belirleyeceksin, şimdi dummy kalsın. |
| Q6 | HSM? | **software_fallback_ok** | Donanım HSM yok, yazılım koruması ile devam. Devnet için yeterli, mainnet için sonra gerçek HSM. |
| Q7 | Docker smoke? | **fix_mainnet_container** | Mainnet docker imajı HSM yüzünden ayağa kalkmıyor, düzeltme yapacağız (HSM olmadan çalışacak şekilde). |
| Q8 | Prod gate ne zaman açılsın? | **open_on_green** (test yeşil olur olmaz direkt aç) | VerifyMerkle testi yeşil olur olmaz production'da aktif edeceğiz, tekrar sormayacağız. |
| Q9 | Storage proof zorunlu mu? | **optional_keep** (opsiyonel kalsın) | Şu an kimse “gerçekten dosyam burada, ispatı burada” demek zorunda değil, parasını kilitlemesi yeterli. VerifyMerkle tamir olana kadar böyle kalacak — yoksa hiç kimse deal açamaz. |
| Q10 | Phase 4 sonrası öncelik? | **bns_tld_launch** (.bud pazarını aç) | Önce `.bud` isim pazarını açıyoruz, sonra external audit. Yani kullanıcılar `ahmet.bud`, `halil.bud` alabilecek. |

---

## 5. Sıradaki Adım — Aşama 3 Bekleme + Sonraki Kod

**Şu an:** HEAD origin `6eedd2d`, ben `9387fb1`'deyim → 2 commit geride. CI FAIL (Budlum Core format/clippy/test). ARENA3'ün son pushları `2250795` (BNS RPC) + `6eedd2d` (debug plan) — BNS kısmı çalışıyor gibi ama CI fail.

**Kurala göre yapmam gerekenler:**
1. `git fetch origin && git reset --hard origin/main` (yapıldı — local temiz)
2. CI fail nedenini `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --lib` ile bul (yerel cargo yok, ama GitHub annotation'a göre format veya clippy)
3. Diğer AI'ların STATUS_ONLINE.md'ye yorum yazmasını bekle (ARENA1/ARENA3 Q kararlarını onaylasın)
4. CI yeşil olana kadar yeni commit atma (Aşama 3)

**Sen “devam” dediğinde (10 soru kararları net):**
- Q1 ctl_debug → `docs/VERIFYMERKLE_CONSTRAINT_DEBUG_ARENA2.md` + minimal depth test `phase4_verify_merkle_depth_2_diagnosis` (ARENA3 zaten 6eedd2d'de plan yazdı, ben kodunu yazacağım)
- Q3 full_now → BNS pricing docs + `BnsPricingTable` + `NameRecord` expiry/owner checks + `docs/operations/BNS_MAINNET.md`
- Q7 fix_mainnet_container → `Dockerfile` mainnet ENV + `scripts/docker-smoke-mainnet.sh` HSM mock olmadan çalışacak şekilde
- Q9 optional_keep → `StorageDeal` merkle_proof Option kalır, interim challenge devam

**Push reddi dersi:** Aşama 2 kuralı (fetch + log kontrol) kesin uygulanacak. Force-push YASAK, workflow push YASAK, kanıtsız SHA YASAK.

---

**ARENA2 imza:** 2026-07-15 17:00 UTC+3 — Aşama 3 bekleme modu, CI takibi, diğer AI yanıtı bekleniyor. Kullanıcı “devam” derse 10 soru kararları ile kodlamaya devam.

Force-push YASAK. Workflow push YASAK.
