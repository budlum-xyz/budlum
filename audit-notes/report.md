# BUDLUM DENETİM RAPORU — tur 1 (17 Kasım 2026)

Biçim: `BUDLUM_DENETIM_DIREKTIFI` §5 (kimlik, konum, önem, ne yanlış, neden yanlış, neye yol açar, nasıl düzeltilir, durum). Her bulgu canlı kod/API ile doğrulandı. Commit ve CI kanıtı yazıldığı yerde var.

## 1. Durum tablosu

| PR | Başlık | Base → head | Commit | Dosya | mergeable_state | CI |
|---|---|---|---|---|---|---|
| #126 | testnet | main ← testnet | `00db2cb` | 1094 | blocked | bu turda incelenmedi |
| #164 | Garden | testnet ← garden | `b7fbe38` | 38 | blocked | rapor §5 |
| #183 | Budlum | garden ← budlum-stack | `ec3a697` | 64 | blocked | rapor §5 |
| **#188** | **Aggregation Phase 1 (yeni)** | **main ← aggregation-phase1** | **`d4181b8`** | **9** | **blocked** | **tetiklendi: 10+ workflow, hepsi `queued` (run 44077462781 CI, 44077462636 Semgrep, …)** |

`mergeable_state=blocked` üçünde de aynı sebep: zorunlu inceleme/CI kapıları. Bu bir kod hatası değil, kapı tasarımı.

## 2. Bulgular

### B-0001 — GitHub token'ının yetki kapsamı aşırı geniş
- **Konum:** oturum kimliği (`.netrc`), scope başlığı: `admin:enterprise, admin:gpg_key, admin:org, admin:org_hook, admin:public_key, admin:repo_hook, admin:ssh_signing_key, audit_log, codespace, copilot, gist, notifications, project, repo, user, workflow, write:discussion, write:network_configurations, write:packages`
- **Önem:** kritik
- **Ne yanlış:** Bir kod inceleme/patch işi için gereken en az yetki `repo` + `workflow` (workflow dosyası değişmiyorsa yalnız `repo`). Token; kuruluş yönetimi, denetim kaydı, SSH imza anahtarı ve paket yazma yetkisi taşıyor.
- **Neden yanlış:** En az yetki ilkesi. Bu token sızarsa zarar, bu turdaki işin kapsamıyla sınırlı değil.
- **Neye yol açar:** Kuruluş ayarlarının değiştirilmesi, denetim kaydının okunması, başka repolara/SSH anahtarlarına erişim.
- **Nasıl düzeltilir:** İş bitince token'ı iptal et; kalıcı çözüm fine-grained PAT: yalnız `budlum-xyz/budlum`, izinler `Contents: write`, `Pull requests: write`, `Issues: write` (yorum için), `Metadata: read`.
- **Durum:** açık (kullanıcı aksiyonu). Bu turda token hiçbir dosyaya/loga/commit'e yazılmadı; `.netrc` 0600 ve workspace dışı snapshot'ta tutulmuyor.

### B-0002 — Tam crate derlemesi bu ortamda yapılamıyor (rustc OOM)
- **Konum:** `cargo check --lib`, sandbox bellek sınırı 1.98 GB; `rustc ... --emit=metadata` SIGKILL.
- **Önem:** yüksek (kanıt boşluğu)
- **Ne yanlış:** `budlum-core`'un bağımlılık grafiği (libp2p, aws-lc-sys/ring, ml-dsa, slh-dsa, plonky3…) bu bellekte rustc'yi öldürüyor. `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_INCREMENTAL=0` denendi; üçü de aynı sonucu verdi.
- **Neden yanlış:** Bu ortamda "cargo test geçti" cümlesi kurulamaz; kurulursa yalan olur.
- **Neye yol açar:** PR'ın tam crate kanıtı yalnız CI'da üretilebilir; yerel ölçüm iddiası yapılamaz.
- **Nasıl düzeltilir:** (a) PR'ı CI'ya bırak; (b) modül düzeyinde kanıt için `budlum-aggproof` harness'ı: aynı dosyaları `#[path]` ile derleyip 73 testi çalıştırıyor; (c) CI'da `cargo test --lib` yeşil olmadan "testnet hazır" denmez.
- **Durum:** açık (ortam). Harness workspace'te: `budlum-aggproof/` → `cargo test` = 73 passed.

### B-0003 — [PR #183, Strix MEDIUM] Unstake guard ağ bond tabanı yerine kayıt parametresini kullanıyor — **DOĞRULANDI**
- **Konum:** `src/execution/executor.rs:867` (`budlum-stack` head `ec3a697`): `let min_stake = state.registry.params().min_stake.max(1);`
- **Önem:** orta
- **Ne yanlış:** Aynı dosyadaki bütün öbür validator-aktiflik kararları `Network::from_chain_id(tx.chain_id).min_stake()` kullanıyor (satır 527–528, 710–711, 917). Yalnız unstake yolu `registry.params().min_stake` kullanıyor; `src/registry/permissionless.rs:32` sabiti `MIN_REGISTRATION_STAKE: u64 = 1_000` ve kendi dokümanı "bu sabit ağ bond'u olarak ele alınmamalı" diyor.
- **Neden yanlış:** İki farklı taban aynı kavramı ölçüyor; biri kayıt eşiği, öbürü ağ bond'u. Kısmi unstake sonrası stake `1_000 ≤ stake < min_stake_network` aralığında kalırsa `validator.active = true` kalıyor.
- **Neye yol açar:** Yetersiz teminatlı validator üretim/oylama yapmaya devam eder; duty-lane ücretsiz iş kotası aynı kapıdan geçiyorsa ücretsiz trafik de alır. Ekonomik güvenlik varsayımı ("aktif ⇒ yeterli teminat") delinir.
- **Nasıl düzeltilir:** `executor.rs:867`'yi öbür yollarla aynı kaynağa bağla: `Network::from_chain_id(tx.chain_id).map_or(1, |n| n.min_stake())`. Kırmızı test: kısmi unstake sonrası stake ağ tabanının altına düşünce `validator.active == false` ve `is_eligible == false`. Aynı sınıf tarama: `registry.params().min_stake` kullanan başka satır var mı (grep 2 sonuç: 493, 727 — ikisi de kayıt yolu, doğru).
- **Durum:** açık. Düzeltme `budlum-stack` dalında yapılmalı; `main`'de bud3 yolu yok.

### B-0004 — [PR #183, Strix MEDIUM] Repair attestation'ları türetilmemiş bir kökü yetkilendiriyor — **DOĞRULANDI**
- **Konum:** `src/storage/bud3/registry.rs:2212–2235` (`RepairWitness::ValidatorAttestations` kolu): `repair_attestation_digest(..., new_root: &new_root, ...)`
- **Önem:** orta
- **Ne yanlış:** `RepairWitness::Reconstructed` kolu, sembolleri yeniden türetip karşılaştırıyor (`expected_syms != sorted_syms` → ret). Attestation kolu ise `new_root`'u **girdi olarak** imzalatıyor; kökün, onaylanan sembollerden türetildiğine dair hiçbir kontrol yok.
- **Neden yanlış:** İmza "şu kök doğrudur" der; kökün nesneyle ilişkisi kurulmaz. Azınlık Full validator, uydurma bir kökü imzalayabilir.
- **Neye yol açar:** Segment kökü, gerçek sembollerle uyuşmayan bir değere çekilebilir; sonraki okumalar/tamirler bu köke zincirlenir → sessiz veri bozulması (silent corruption), challenge ekonomisinin yanlış hedefe yönelmesi.
- **Nasıl düzeltilir:** Attestation kolunda da kökü türet: `new_root == segment_root(sorted_syms)` (ya da mevcut `column_commitment`/`symbol_roots` fonksiyonu) karşılaştırması ekle; eşleşmiyorsa `BadRepair("attested root does not derive from the attested symbols")`. Kırmızı test: geçerli sembol seti + uydurma `new_root` ile onaylanmış 3 attestation → ret.
- **Durum:** açık.

### B-0005 — [PR #183, Strix MEDIUM/LOW] Diğer iki bulgu: **bu head'de çözülmüş görünüyor**
- **B-0005a (replacement placement):** `src/storage/bud3/replace.rs:54–115` `replacement_placement_digest(new_shares)` üretiyor ve `replace_attestation_digest(..., new_shares)` içine katıyor; `registry.rs:1209` `replace_object` `new_shares` alıyor; `replace.rs:647–648` iki farklı yerleşimin farklı özet verdiğini test ediyor.
- **B-0005b (duty batch eviction):** `src/mempool/pool.rs:600–625` artık `evict_duty_from_heavier_signers` + `evict_cheapest_non_duty` + hata hâlinde `restore_entry` kullanıyor.
- **Durum:** çözülmüş (kod kanıtı). Strix yorumları PR'da açık duruyor; kapatma yetkisi/yanıtı PR sahibinde. **Not:** Bu iki bulgu için "çözüldü" yanıtı yazılabilir; B-0003/B-0004 için yazılamaz.

### B-0006 — Agregasyonda referans backend feature ile üretime girebilir
- **Konum:** `Cargo.toml` `native-agg-backend = []`, `src/aggregation/backend.rs` `#[cfg(any(test, feature = "native-agg-backend"))]`
- **Önem:** orta
- **Ne yanlış:** Kapı `cfg` ile var; ama bir operatör `--features native-agg-backend` ile derlerse `StructuralVerifier` (kriptografi yapmayan doğrulayıcı) üretim ikilisine girer.
- **Neden yanlış:** Derleme zamanı kapısı, yanlış derleme bayrağına karşı kendini savunmaz.
- **Neye yol açar:** Kriptografik doğrulama yapılmadan iddia kabul eden bir düğüm.
- **Nasıl düştüğü kanıtlandı:** `the_reference_backend_is_gated_out_of_the_production_profile` kaynak taraması yapıyor; ama çalışma zamanı savunması yok.
- **Nasıl düzeltilir:** Faz 2'de `StarkBackend` geldiğinde `StructuralVerifier` tamamen silinir; o zamana kadar CI'da `cargo build --release --no-default-features` + `--features native-agg-backend` kombinasyonunun *üretim profili olmadığını* belgeleyen bir kapı ekle. Alternatif: `#[cfg(debug_assertions)]` ile ikinci bir kapı.
- **Durum:** açık (kabul edilmiş risk, belgelendi).

### B-0007 — Agregasyon şema kimlikleri yer tutucu
- **Konum:** `src/aggregation/types.rs` `SchemeRegistry::budlum_reference()`: `0x0101`, `0x0201`, `0x1001`, `0x2001`
- **Önem:** düşük
- **Ne yanlış:** Bu kimlikler `crate::crypto::scheme::SchemeId` ile eşleşmiyor; bilinçli olarak çakışmayacak aralıkta seçildi (yorumda yazılı).
- **Neye yol açar:** Faz 2'de çekirdek kayıtla eşlenmezse iki kayıt sistemi doğar.
- **Nasıl düzeltilir:** Faz 1'in entegrasyon adımında (direktif §10, adım 2) `SchemeRegistry` çekirdekten beslenir; yer tutucu silinir. Test: iki kayıt aynı `SchemeId`'yi farklı sınırlarla tanımlayamaz.
- **Durum:** açık (bilinçli yer tutucu).

### B-0008 — `AggPool::per_sender` yalnız `expire_orphans` çağrıldığında budanıyor
- **Konum:** `src/aggregation/pool.rs` `expire_orphans`
- **Önem:** düşük
- **Ne yanlış:** Prune, tik döngüsünün bir parçası; çağrılmazsa harita büyür (tik × gönderen).
- **Neye yol açar:** Uzun ömürlü bir düğümde sınırlı ama ölçüsüz bellek artışı (gönderen başına 1 kayıt).
- **Nasıl düzeltilir:** `take_tick` içinde de prune et (her tikte en az bir kez), ya da `admit`'te `tick - 2`'den eski girdileri at. Test: 1000 tik ilerledikten sonra `per_sender.is_empty()`.
- **Durum:** açık.

### B-0009 — Stack sırası ve base kayması
- **Konum:** #126 `main ← testnet`, #164 `testnet ← garden`, #183 `garden ← budlum-stack`
- **Önem:** bilgi
- **Ne yanlış:** Üç PR birbirine bağlı; her biri `blocked`. #183'ün base'i `garden`, #164'ün base'i `testnet`; `main`'e inen sıra #126 → #164 → #183 olmak zorunda. Yeni PR #188 `main` tabanlı ve bu üç dosyaya dokunuyor (`lib.rs`, `domain_tags.rs`, `Cargo.toml`) → `testnet`'e rebase'te tek satırlık çakışma beklenir.
- **Nasıl düzeltilir:** #188 önce `main`'e, sonra `testnet`'e merge edilirse çakışma yok. Tersi sırada `lib.rs`/`domain_tags.rs` elle birleştirilir (mekanik).
- **Durum:** açık (plan notu).

### B-0010 — CI kuyruğu
- **Konum:** PR #188, 10+ workflow, rapor yazıldığı anda hepsi `queued`
- **Önem:** bilgi
- **Ne yanlış:** Runner kuyruğu; kodla ilgisi yok. Bu raporun "CI yeşil" iddiası **yok**; yalnız "tetiklendi" diyor.
- **Durum:** açık; run id'leri: CI `44077462781`, Semgrep `44077462636`, Miri `44077462762`, Cargo Vet `44077462846`, Dependency Review `44077462980`.

## 3. Bu turda yapılan iş

1. `src/aggregation/` (5 dosya + testler, 3082 satır) yazıldı, 73 test + clippy + rustfmt + reponun gerçek `domain-tags` kapısı yeşil.
2. PR #188 açıldı (base `main`), Strix incelemesi istendi.
3. #183'ün 4 Strix bulgusu kod düzeyinde triyaj edildi: 2 doğrulandı (B-0003, B-0004), 2 çözülmüş (B-0005).
4. Harita, tasarım ve sınır belgeleri yazıldı.

## 4. Yapılmayanlar (dürüst liste)

- #183/#164/#126 dallarında **düzeltme commit'i yok**: bu üç dal benim yazmadığım, üst üste binmiş, `blocked` durumda ve aktif olarak yeniden yazılan dallar. Düzeltmeler B-0003/B-0004'te tarif edildi; uygulanması için stack sahibinin dalına yazmak gerekir. Bu turda yapılmadı, "yapıldı" denmiyor.
- Strix yorumlarını silme/resolve etme: yetki ve usul gereği PR sahibinde; B-0005 için gerekçeli yanıt metni hazır.
- Tam crate testi: B-0002.
- Benchmark, fuzz, Miri, determinism: bu ortamda çalıştırılamadı.

## 5. İhlal beyanı

- Hiçbir `#[allow]`, `#[ignore]`, kapı gevşetmesi veya test atlaması eklenmedi. Test dosyasındaki `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` reponun kendi kuralıdır (`clippy.toml`: `allow-unwrap-in-tests = true`) ve yalnız `#[cfg(test)]` modülü kapsar.
- Token hiçbir commit'e, yoruma, loga veya rapora yazılmadı; `.netrc` dışında hiçbir yerde tutulmadı.
- Geçmiş yeniden yazılmadı, force-push yapılmadı, başka dalın commit'i değiştirilmedi.
- `main`'e doğrudan commit yok; tek push `aggregation-phase1` dalına.
