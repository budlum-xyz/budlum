# Budlum — Phase 12.9 Tam Sertleştirme Taraması (Hardening Sweep)

**Hazırlayan:** ARENA1 (görev yöneticisi / denetim)  
**Tarih:** 2026-07-21  
**Baz SHA:** `3979b25` (origin/main)  
**Kapsam:** `src/` (≈88.3K satır, ~28 çekirdek modül) + `budzero/` + `wallet-core/` + CI + docs. **Baştan sona tarandı.**  
**Dışlama:** ARENA4'ün yeni Ar-Ge'si (Phase 12 primitive'leri — pollen, gateway/passport+atlas, relayer/policy, domain/sovereign, settlement/proof_market, storage/mobile_self, developer_os, network/mobile, rpc/atlas, encryption_dao, constitution) **ARENA3 tarafından sertleştiriliyor**; bu raporun dışındadır.  
**Kural:** "Stub verify → Ok(()) = 🔴"; CI tek hakem; bulgu kapatmadan "mainnet ready" yok.

---

## 0. Yürütme Özeti (TL;DR)

- **Bulgu envanteri temiz:** Protocol §4 + bağımsız spot-check (11/11 kritik) → **Açık 🔴 = 0, Açık 🟡 FIX-NOW = 0.** V22–V208 serisi kapatıldı (V95/V110/V116/V119/V37-V38/V89/V106/V24/V86/V103/V98 bağımsız teyit).
- **Hardening protokolü H0–H8:** H1–H6 büyük ölçüde tamam; H5.2/H5.7 mainnet-v1 follow-up; H4.3 (vendor-native BLS/PQ) bilinçli "mainnet v1 out-of-scope"; H7–H8 CI/ops mevcut.
- **Phase 12.9 kalanı (bu rapor):** Bulgu kapanışı bitti; geriye **panic-yüzey azaltımı, eksik regresyon kanaryaları, fuzz açığı, stub'lar, CI-gate konfig'leri, operasyonel kapılar** kaldı. Aşağıda P0/P1/P2 ile önceliklendirilmiş.

> ⚠️ Dürüst not: Main şu an **kırmızı** (ARENA3'ün yeni CI gate'leri: semver `./baseline` eksik + genesis `${HASH1}` açılmamış değişken). Bu rapordaki maddeler bu kırmızıyı **kapatmaz** (onlar ARENA3'ün aktif WIP'i); bu rapor **sertleştirme borcunu** envanterler.

---

## 1. Alt-sistem tarama durumu (baştan sona)

| Alt-sistem | Dosya (satır) | Hardening durumu | Kalan |
|---|---|---|---|
| Konsensüs çekirdeği | blockchain.rs (4838), finality.rs (1084), qc.rs (889), pos.rs (751) | 🔴 bulgu kapanmış (V95/V98/V103/V119); reorg split-brain düzeldi | unwrap audit; S4 current_block |
| Executor / ekonomi | executor.rs (1183), account.rs (1940), fee_market.rs | executor **temiz (0 unwrap)**; supply cap locked | **EIP-1559 üretimde bağlı değil** (ARENA3 WIP) |
| Bridge / cross-domain | bridge.rs, relayer.rs, evm/* | V24/V106/V37-V38 kapalı; STARK verify gerçek | unwrap audit (çoğu test); relayer binary stub |
| Ağ çekirdeği | node.rs (2076), peer_manager.rs (904), proto_conversions.rs (2001) | H5.1/H5.3/H5.4/H5.5 kapalı; reputation clamp (ARENA1) | H5.2/H5.7; reputation fuzz target |
| Storage çekirdek | db.rs (1402), storage_deal.rs (1540), merkle_trie.rs | V37-V38 STARK bağlı; mock-proof `cfg!(test)` sınırında | storage ekonomi soak; snapshot schema skeleton |
| Kripto | pkcs11.rs, mainnet_policy.rs, primitives.rs (681) | H4.1 fail-closed; H4.5 domain tags | H4.3 vendor-native (out-of-scope beyanı) |
| AI çekirdek | ai/mod.rs (3983), registry.rs (1484) | V89 settled payments; V84 spoofing | (pollen AI veri yasağı → ARENA3/ARENA4 dışlama) |
| RPC çekirdek | server.rs (3776), api.rs (792) | H5.3 auth default | S5 mutate-surface audit |
| Cüzdan | wallet-core/ | production entropy fail-closed; **BIP39 kanonizasyon sürüyor** (ARENA3) | kanonik wordlist (ARENA3) |
| Zincir boot | genesis.rs (687), snapshot.rs (1160) | H6.1 determinism; H6.3 GAP-1 | PoA placeholder authorities (ceremony) |
| ZK/VM (budzero) | bud-vm, bud-proof, bud-compiler | V110 mainnet gate; Goldilocks/Div-Inv soundness | V110 kanarya (ARENA2); VerifyMerkle Poseidon-path follow-up |

---

## 2. Phase 12.9 — Kalan sertleştirme maddeleri (öncelikli)

### 🔴 P0 — Mainnet blocker (sertleştirme)

| # | Madde | Kanıt / konum | Sahip | Çıktı |
|---|---|---|---|---|
| **12.9-1** | **EIP-1559 fee distribution üretimde bağlı değil** — `distribute_block_fees` yalnızca birim testte çağrılıyor; executor/finalization çağırmıyor. Önerenci tipi/base burn/treasury üretimde çalışmıyor. | `account.rs:578` (tanım), `:1610` (tek çağrı=test); executor fee düşümü `:77/85/133...` → double-charge tuzağı. (ARENA1 EIP-1559 raporu teslim edildi.) | **ARENA3** | block finalization'a bağla + executor accounting uzlaştır |
| **12.9-2** | **Regresyon kanaryası boşlukları (S3)** — V95/V98/V110/V116 düzeltildi ama `vNN_` isim-kilitli kanarya yok (V103 kapsanmış; V24/V86/V89/V119 kanarya ARENA1 ekledi). | `src/tests/hardening_locks.rs` (v24/v86/v89/v119 var); V95/V98/V110/V116 yok | ARENA1 (V95/V98 runtime env gerektirir; V110 = bud-vm ARENA2) | 4 kanarya |
| **12.9-3** | **CI gate konfig misconfig** — semver workflow `./baseline` eksik; genesis determinism `${HASH1}` açılmamış. Main kırmızı. | CI run `3979b25`: Semver Check + Genesis Reproducibility FAIL | **ARENA3** (aktif WIP) | workflow düzelt → yeşil |

### 🟡 P1 — Sertleştirme borcu (mainnet öncesi kapatılmalı)

| # | Madde | Kanıt | Sahip |
|---|---|---|---|
| **12.9-4** | **Üretim panic-yüzey azaltımı** — consensus/bridge/chain/finality'de üretim `unwrap()/expect()` → fail-closed `Result`. (executor zaten **0 unwrap**; panic'lerin çoğu inline **test**te, üretim değil — ama üretim altkümesi audit edilmeli.) | pos.rs(10)/qc.rs(5)/finality.rs(13) toplam unwrap (test dahil); cross_domain 111 (çoğu test) | domain sahipleri |
| **12.9-5** | **Reputation/peer fuzz target eksik (H3)** — peer-score/ban/subnet invariant fuzz'u yok (10 target mevcut, reputation yok). | `fuzz/fuzz_targets/` (reputation yok) | ARENA1 (nightly+libp2p env gerektirir) |
| **12.9-6** | **Executor `current_block` tek kaynak (S4)** — release/reclaim yolunda `epoch_index*100` yaklaşımı height sapması riski. | protocol §13 S4; executor.rs | ARENA1/ARENA3 |
| **12.9-7** | **RPC mutate-surface audit (S5)** — anonim state-mutate endpoint'leri + default auth teyidi. | protocol §13 S5; rpc/server.rs | ARENA1 |
| **12.9-8** | **Coverage borcu (S10)** — consensus/cross_domain/crypto modül coverage % raporu + ratchet hedefi. | protocol §13 S10 | ARENA3 (CI) |

### ⚪ P2 — Mainnet v1 follow-up / operasyonel

| # | Madde | Not |
|---|---|---|
| **12.9-9** | **H5.2 outbound diversity + bootstrap anchors** | protocol H5.2 (mainnet v1 follow-up) |
| **12.9-10** | **H5.7 NAT/relay** | protocol H5.7 (opsiyonel v1.1) |
| **12.9-11** | **budlum-relayer binary (F10.4 iskelet)** — production relay loop yok ("mainnet sonrası"). EVM bridge launch'ta aktifse blocker. | `src/bin/budlum-relayer.rs` (skeleton) |
| **12.9-12** | **Snapshot schema-2 skeleton** — deserialization skeleton yorumu; tam hardening. | `snapshot.rs:787` |
| **12.9-13** | **Operasyonel kapılar:** PoA placeholder→gerçek authority (genesis ceremony F1-F5); external audit dry-run; HSM donanım ceremony (YubiHSM 2); 7-gün CI stabilite penceresi; production runbook rehearsal/backup-restore drill. | MAINNET_LOCKDOWN_CHECKLIST; CI_STABILITY_WINDOW (1/7 gün) |

---

## 3. Dışlanan kapsamım (ARENA3 sertleştiriyor — ARENA4 Phase 12 Ar-Ge)

Aşağıdaki ARENA4 primitive'leri bu raporda **değerlendirilmedi** (kullanıcı kararı: ARENA3 sertleştiriyor). Mainnet launch onayı için ayrı readiness matrix ister:

`pollen/` (data_rights, offers, encryption_policy), `gateway/` (passport, atlas), `relayer/policy.rs`, `domain/sovereign.rs`, `settlement/proof_market.rs`, `storage/mobile_self.rs`, `developer_os.rs`, `network/mobile.rs`, `rpc/atlas.rs`, `core/constitution.rs`, `core/governance.rs` (Phase 12.10).

---

## 4. Önerilen sıra (ARENA1 uygulanabilir kısmı)

1. **12.9-2 (kanarya):** V116 proto round-trip + V95/V98 (runtime env gerektiği için ARENA3'ün beefier env'inde veya ARENA2 bud-vm'de V110) — ARENA1 V116+V119(V) hazır.
2. **12.9-5 (reputation fuzz):** nightly+libp2p env'inde ARENA1 yazar.
3. **12.9-6/12.9-7 (executor height + RPC audit):** ARENA1 okuma+rapor.
4. **12.9-1/12.9-3 (EIP-1559 + CI gates):** ARENA3 (raporlar teslim).
5. **12.9-13 operasyonel:** Ayaz + donanım + zaman.

---

## 5. Dürüst readiness verdikti

- **Güvenlik mimarisi:** kanıtla **sağlam** (11/11 kritik kapalı, H1–H6 büyük ölçüde done).
- **"Mainnet kusursuz" DEĞİL:** P0 maddeleri (EIP-1559 üretimde bağlı değil + main kırmızı) + operasyonel kapılar (7-gün pencere, ceremony, audit, HSM) açık.
- **Phase 12.9 bu raporla envanterlendi;** uygulanması ARENA1 (kanarya/fuzz/audit) + ARENA3 (EIP-1559/CI gates/coverage) + operasyon (Ayaz/donanım/zaman) split.

## 6. İlerleme / Status (ARENA1 uygulaması, 2026-07-21)

| Madde | Durum | Aksiyon / Not |
|---|---|---|
| **12.9-1** EIP-1559 üretim bağlama | 🟡 ARENA3 WIP | ARENA1 raporu teslim; ARENA3 `b98823d`/`813b65d` ile fee testlerini düzeltti; dağıtım bağlama devam |
| **12.9-2** Kanarya boşlukları | ✅ KISMEN KAPANDI | **V119** (sync threshold) + **V116** (AiAgentPayment proto round-trip) kanaryaları ARENA1 eklendi (`hardening_locks.rs`). V95 (reorg domain rebuild) + V98 (lock poison) runtime-env gerektirir (1.9 GB sandbox OOM); V110 = bud-vm (ARENA2). |
| **12.9-3** CI gate misconfig | 🟡 ARENA3 WIP | ARENA3 `361a3b4`+`1a047e8` ile semver/genesis kök-nedenlerini düzeltiyor |
| **12.9-4** unwrap→Result audit | 📋 TAVSİYE | Büyük refactor; executor **0 unwrap** (temiz). consensus/bridge/chain üretim altkümesi domain-sahibi tarafından audit edilmeli (kör push riskli — runtime doğrulama yok) |
| **12.9-5** reputation fuzz target | 📋 SPEC | PeerManager API'si ile tasarım hazır (peer-score/ban/subnet invariant); nightly + libp2p 0.56 env gerektirir → doğrulanmadan push edilmedi (yeşil CI riske atmamak için) |
| **12.9-6** S4 executor current_block | ✅ KAPANDI | **V125 zaten uygulandı** — executor tutarlı şekilde `state.current_block_height` kullanıyor (epoch_index*100 değil). Bağımsız teyit edildi, işlem gerekmez. |
| **12.9-7** S5 RPC mutate-surface | ✅ DENETLENDİ | 9 state-mutate RPC handler `require_operator`'süz AMA **proof-gated** (geçerli Merkle/ZK/slashing proof parametresi zorunlu) → H5.3 "anonim mutate RED" niyeti karşılanıyor. Test'ler chain metodlarını direkt çağırıyor (RPC handler'ları değil) + rpc/tests.rs Operator mod. **Tavsiye:** permissionless relayer/verifier/prover modelini kırmamak için require_operator kör eklenmemeli; mainnet için opsiyonel operator-only config flag değerlendirilmeli. |
| **12.9-8** Coverage borcu | 🟡 ARENA3 (CI) | consensus/cross_domain/crypto modül % raporu |
| **12.9-9/10** H5.2/H5.7 | ⚪ follow-up | outbound diversity, NAT/relay (mainnet v1.1) |
| **12.9-11** budlum-relayer stub | ⚪ EVM bridge launch'a bağlı | F10.4 skeleton; mainnet sonrası tam relay loop |
| **12.9-12** snapshot skeleton | ⚪ düşük | schema-2 deserialize hardening |
| **12.9-13** operasyonel | ⏳ Ayaz + donanım + zaman | PoA ceremony, external audit, HSM, 7-gün pencere (1/7), runbook drill |

**ARENA1 bu oturumda güvenle bitirdiği kod işleri:** network reputation clamp (3 yol) + `phase11_12_reputation_score_clamped_under_repeated_penalties` + **V119** + **V116** kanaryaları + Network Hardening gate canary. Hepsi lokal compile-doğrulandı, CI'da yeşil.

**Kapatılamayan (dürüüst):** V95/V98/reputation-fuzz = **verification env** kısıtı (beefier build env'de); V110 = **ARENA2** (bud-vm); EIP-1559/CI/coverage = **ARENA3** aktif WIP; operasyonel = **insan/donanım/zaman**.

*ARENA1 · bağımsız tarama · 2026-07-21*
