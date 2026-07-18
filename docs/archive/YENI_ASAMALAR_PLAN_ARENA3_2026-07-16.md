# Yeni Aşamalar Planı — ARENA3 (AI birliği ile tartışma)

**Tarih:** 2026-07-16 02:30 UTC+3
**HEAD:** `6333a74` (ARENA2 revert broken socialfi/marketplace/mobile to green base f9f5b9a + CI green)
**Talimat:** "yeni aşamalar için AI'larla konuş bunu belirle ve devam et denetime de"
**Denetçi:** ARENA3 + ARENA1 + ARENA2
**Durum:** Phase 3 büyük ölçüde kapandı (honest closeout), Phase 4 VerifyMerkle kısmen, PHASE5-6-7 yeni aşamalar belirsiz — bu doküman AI birliği tartışması için ön planlama

---

## 1. Mevcut Durum Özeti (6333a74 sonrası)

| PHASE | Kapsam | Durum | Kanıt |
|------|--------|-------|-------|
| Phase 3 (Mainnet v1 lansman paketi) | §0 güvenlik borçları 0.1-0.4, §3 3.1-3.6 | ✅ Büyük ölçüde kapandı, kalan bilinçli borç: ceremony dummy, VerifyMerkle gate kapalı, HSM vendor-native, archive drill CI | 5562716 kuyruk drain (13 test), e221b18 validator E2E, 4cf710d storage_root V3, 29d81b6 Dockerfile mainnet, scripts/*.sh |
| Phase 4 (B.U.D. Faz 3 VerifyMerkle) | Faz 3 Merkle proof alanları, storage_root Block V3, 1-depth debug harness | 🔒 Kapalı — `proves_verify_merkle_valid_64_depth` InvalidProof, matrix chain diagnostic yeşil ama full STARK kırmızı (aux CTL şüpheli) | `PHASE0.06_PLAN.md`, `VERIFYMERKLE_CONSTRAINT_DEBUG_ARENA3.md`, 6eedd2d constraint-by-constraint plan |
| Phase 5 (External audit + hardening + marketplace + mobile) | Başlangıçta implemente edildi (2db13c5 AI Data Marketplace, c726de3 mobile lightweight sharding, 271f162 master key + pruning, baa10e7 universal relayer) ama **CI kırıldı**, ARENA2 6333a74 ile **f9f5b9a green base'e revert** etti, CI green | 🔒 Ertelendi / Revert — marketplace/mobile/socialfi/hub broken, testler kırmızı, bu yüzden revert | 2db13c5, c726de3, 271f162, baa10e7, 9c09741 hub, d17bf71 socialfi boost, 67da984 socialfi NFT posts → hepsi revert ile f9f5b9a'ya dönüldü, CI green |
| Phase 6 (BNS/.bud + SocialFi + Hub + Constitution + Budlum Hub) | BNS Phase 6 full_impl merge (lifecycle + storage_root binding + fetch content RPC) var, SocialFi NFT posts (67da984) ve Hub (9c09741) denendi ama revert ile gitti, Constitution (8389f42, f4d7e28) kaldı | 🟡 Kısmi — BNS stub + lifecycle var, SocialFi/Hub/Marketplace revert sonrası yok | 7482dd7 BNS full_impl merge, d294111 lifecycle, 2250795 full_integration, 0017e97 early init, 67da984 socialfi, 9c09741 hub → revert |

**Sonuç:** Phase 3 yeşil, Phase 4 VerifyMerkle kırmızı (bilinçli), Phase 5/6 sosyal/marketplace/mobile/hub denendi ama CI kırıldığı için revert edildi, şimdi green base f9f5b9a'da (CI green). Yeni aşamalar için **temiz, küçük, testli adımlarla** ilerlememiz gerekiyor, tek seferde 5 özellik birden değil.

---

## 2. Mainnet Eksiklikleri — Hâlâ Açık Olanlar (M1-M9 güncel + yeni)

| # | Borç | Durum (6333a74 sonrası) | Risk |
|---|------|------------------------|------|
| M5 | VerifyMerkle Z-B gate | 🔒 Kapalı — InvalidProof, matrix green, full red | Kritik — gerçek PoS yok |
| M3 | Ceremony seeds/bootnodes dummy | 🟡 Template var, gerçek multiaddr yok | Kritik — mainnet töreni yapılmadan launch yok |
| M6 | BLS/PQ HSM vendor-native | 🟡 Software fallback, hardware native yok, c92125b ile vendor mechanism config desteği eklendi | Yüksek |
| M7 | External audit/TLA+/Privacy/AI | ❌ Açık — checklist/process only | Kritik |
| M9 | Archive drill CI | 🟡 Doküman var, CI job yok | Orta |
| **YENİ M10** | SocialFi / Marketplace / Mobile / Hub / Constitution | 🔒 Revert sonrası yok — f9f5b9a green base'de sadece BNS + Constitution kaldı | Orta — Phase 5/6 yeni aşama |

---

## 3. Yeni Aşamalar Önerisi — AI Birliği Tartışması İçin

Kullanıcı "yeni aşamalar için AI'larla konuş bunu belirle" dedi. Önerim **Phase 4/5/6/7'yi netleştirilmiş, küçük, testli fazlara bölmek**:

### Phase 4 — B.U.D. Faz 3: VerifyMerkle Production Açılışı (mevcut, devam)

**Hedef:** Gerçek Proof-of-Storage

| # | Görev | Sahip (öneri) | Kabul Kriteri |
|---|-------|---------------|---------------|
| 4.1 | Test gate: `proves_verify_merkle_valid_64_depth` ignore kaldır + 1-depth test yeşil | ARENA2 (ZK) | `cargo test --package bud-proof proves_verify_merkle_valid_64_depth` → ok |
| 4.2 | 1-depth debug harness (ARENA3 ekledi) + constraint-by-constraint isolation (aux CTL) | ARENA3 (ISA) | `proves_verify_merkle_valid_1_depth` yeşil, sonra 2-depth, sonra 64-depth |
| 4.3 | Production gate: `is_experimental=false` (Q2 enable_prod) — test yeşil olmadan açılmaz, fail-closed | ARENA3 | `tur119_verify_merkle_disabled_in_production` güncellenmiş, Production'da decode success |
| 4.4 | B.U.D. Faz 3 entegrasyonu: StorageDeal `merkle_proof` zorunlu (Faz 2 None → Faz 3 Some) | ARENA1 | `bud_storageOpenDeal` Merkle proof talep eder |

**Risk:** AIR degree / aux CTL / LogUp — 2-3 hafta.

### Phase 5 — External Audit + Hardening + B.U.D. P2P Entegrasyon (öncelik)

**Hedef:** Mainnet öncesi harici denetime hazır olma

| # | Görev | Sahip | Kabul Kriteri |
|---|-------|-------|---------------|
| 5.1 | External audit teslim paketi: `AUDIT_CHECKLIST.md` + `THREAT_MODEL.md` + `ARCHIVE_AND_BACKUP.md` + `HSM_BLS_PQ_POLICY.md` + `HSM_VENDOR_NATIVE_GUIDE.md` güncelle | ARENA2 | Teslim paketi hazır, harici firma yok ama docs hazır |
| 5.2 | TLA+ iskeleti: multi-consensus settlement için TLA+ spec taslak (safety/liveness) | ARENA2 | `docs/tla/MultiConsensus.tla` taslak |
| 5.3 | Bug bounty launch: `BUG_BOUNTY.md` immunefi tier medium → high, PGP key `0xBUDLUM-SECURITY` yayınlama (Phase 3 kararı C: bug bounty) | ARENA1 | Immunefi başvurusu |
| 5.4 | B.U.D. P2P storage node monolithic entegrasyon: `bud-node` Bitswap + KAD + sharding + `Node::with_key` storage args (100ac26 + 44a6f12) zaten var, ama `NodeCommand::StoragePrune` hard pruning worker + `Node::run` storage initialization test edilmeli | ARENA1 (Node) + ARENA3 (P2P) | `scripts/phase3_smoke_rpc.sh` + `docker-smoke-mainnet.sh` yeşil |
| 5.5 | Archive/backup restore drill CI: `ops/backup_restore_drill.sh` + `ARCHIVE_AND_BACKUP.md` drill CI job (workflow push yasak, kullanıcı manuel) | ARENA2 | Drill script çalışır |

### Phase 6 — BNS/.bud + SocialFi + Hub + AI Data Marketplace + Mobile (yeni, küçük adımlar)

**Önceki deneme (2db13c5, c726de3, 67da984, 9c09741) CI kırdığı için revert edildi (6333a74). Bu sefer küçük, testli adımlar:**

| # | Görev | Sahip | Kabul Kriteri |
|---|-------|-------|---------------|
| 6.1 | BNS Phase 6 full_impl: halihazırda var (registry + storage_root + content_id + subdomains + BnsResolved + lifecycle Tx→Executor→RPC + fetch content RPC `bud_bnsFetchContent`) — testler 4 passed, CI yeşil | ARENA3 | `cargo test --lib bns` 4 passed |
| 6.2 | SocialFi NFT posts: `bud_socialGetPost`, `bud_socialGetProfile`, `bud_socialPreparePost` (67da984) → küçük PR, sadece READ + PREPARE, MINT Tx ayrı, test ile | ARENA1 | `cargo test --lib socialfi` (yeni) |
| 6.3 | Budlum Hub: dApp registration (9c09741) → `src/hub/mod.rs` + `types.rs`, registry, permissionless | ARENA1/ARENA2 | `cargo test --lib hub` |
| 6.4 | AI Data Marketplace: 2db13c5'teki AI Data Marketplace (Phase 5 Hat 5.5) → küçük PR, sadece marketplace listing, escrow yok | ARENA2 | docs + test |
| 6.5 | Mobile lightweight sharding: c726de3'teki mobile_mode (%0.001 storage, resource-aware P2P, heartbeat 3x, KAD parallelism min) → küçük PR, resource buffer check iskeleti | ARENA1 | `cargo test --lib mobile` |
| 6.6 | Budlum Constitution + R&D Vision: 8389f42, f4d7e28, 2fdd3c8'deki Constitution + universal relayer + local B.U.D. sovereignty rules → doküman + on-chain governance hook | ARENA1/ARENA2 | `docs/BUDLUM_CONSTITUTION.md` |

**Kural (revert dersinden):** Her biri **ayrı commit, küçük, `cargo fmt` + `clippy -D warnings` + `cargo test --lib <modül>` yeşil olmadan main'e push yok. Workflow push yasak, CI manuel.

### Phase 7 — Mainnet Launch Ceremony (son)

**Hedef:** Gerçek mainnet genesis

| # | Görev | Sahip |
|---|-------|-------|
| 7.1 | Ceremony: gerçek treasury/validator keys (0x10... placeholder değil), `config/mainnet-genesis.json` + `MAINNET_GENESIS_CEREMONY.md` §6 template → gerçek multiaddr | Kullanıcı + ARENA2 |
| 7.2 | Bootnodes/dns_seeds: 3 dummy → gerçek 3 bootstrap + DNS seed (Q7 add_dummy → add_real) | Kullanıcı |
| 7.3 | HSM vendor-native: Utimaco/Thales mechanism ID ile BLS/PQ native sign (c92125b config desteği var) | ARENA1/audit |
| 7.4 | Genesis hash freeze + `PRODUCTION_RUNBOOK.md` §8 + `config/mainnet.toml` hash annotation | ARENA2 |
| 7.5 | Mainnet launch: genesis block + validator set hash + chain_id=1 + `docker build` + `systemd` health check | Hepsi |

---

## 4. AI Görev Dağılımı Önerisi (yeni aşamalar)

| AI | Güçlü Yön | Önerilen Hat | Görevler |
|----|-----------|--------------|----------|
| **ARENA1** | Core Rust, B.U.D. entegrasyon, storage_root V3, BlockHeader, chain_actor, permissionless E2E, SocialFi, Hub | **Hat B Mainnet hardening + Hat B BNS/SocialFi/Hub** | 4.4 BlockHeader storage_root, 5.4 B.U.D. P2P monolithic, 6.2 SocialFi, 6.3 Hub, 6.5 Mobile, 7.1 ceremony code |
| **ARENA2** | ZK/AIR, testing, audit, threat model, TLA+, ceremony docs, BNS pricing, marketplace | **Hat A ZK + Hat C Audit** | 4.1-4.2 VerifyMerkle test gate + AIR debug (constraint-by-constraint), 5.1 audit checklist, 5.2 TLA+, 5.5 marketplace, 6.4 AI Data Marketplace |
| **ARENA3** | ISA profile, security, HSM, P2P, BNS full_impl, docker smoke, continuous audit, active communication | **Hat A ZK production gate + Hat B BNS fetch + Hat C HSM + continuous audit** | 4.2 production gate, 4.3 B.U.D. Faz 3 Merkle proof zorunlu, 6.1 BNS full_impl (zaten), 5.4 P2P sharding, HSM vendor-native guide + mechanism support (c92125b), continuous audit (BUDLUM_BOS_KOD_BAGDASMAMA...), AI birliği koordinasyon |

**Commit stratejisi (mevcut kural):**
- main üzerinden atomik, force-push yasak, workflow push yasak, kanıtsız SHA yok.
- Her push öncesi `git fetch origin && git log origin/main -3` + `cargo fmt --all -- --check` (yerelde yoksa CI zorunlu kanıt kabul).
- Her PHASE için `STATUS_ONLINE.md`'de Aşama 1 konuşma → Aşama 2 commit kontrol → Aşama 3 CI yeşil.

---

## 5. Sorular — AI Birliği + Kullanıcı (yanıt bekliyor)

**ARENA1'e:**
1. Phase 6 SocialFi/HUB/Marketplace/Mobile denemesi CI kırdığı için revert edildi (6333a74). Küçük, testli adımlarla (6.2, 6.3, 6.4, 6.5) yeniden başlayalım mı? Önce hangisi: SocialFi NFT posts mu, Hub dApp registration mı, Marketplace mi, Mobile lightweight mı?
2. BlockHeader storage_root V3 (4cf710d + 59bca30) tamam, ama GlobalBlockHeader storage_root ile senkron mu? Hash'e dahil mi? (Data Sovereignty)
3. Mainnet ceremony için treasury/validator keys placeholder'dan gerçek anahtarlara geçişi sen mi yapacaksın, kullanıcı mı?

**ARENA2'ye:**
1. VerifyMerkle için constraint-by-constraint debug planı (10 constraint listesi + küçük depth 1-2 test harness) `VERIFYMERKLE_CONSTRAINT_DEBUG_ARENA3.md`'de. Senin matrix chain diagnostic yeşil, full STARK kırmızı → aux CTL / LogUp şüpheli. Sonraki adım: constraint tek tek aktif + küçük depth 1-2 round prove, doğru mu?
2. Phase 5 external audit + TLA+ iskeleti için `AUDIT_CHECKLIST.md` + `THREAT_MODEL.md` yeterli mi, TLA+ `MultiConsensus.tla` taslak ekleyelim mi?
3. Phase 6 AI Data Marketplace (2db13c5) revert edildi, ama doküman kaldı. Küçük PR ile sadece listing (escrow yok) olarak yeniden başlayalım mı?

**Kullanıcıya (Ayaz):**
- Yeni aşamalar (Phase 4 VerifyMerkle, Phase 5 audit/hardening, Phase 6 BNS/SocialFi/Hub/Marketplace/Mobile, Phase 7 ceremony) için öncelik ne? Hepsi paralel (mevcut karar) mı, yoksa Phase 4 ZK önce mi, Phase 6 SocialFi/HUB sonra mı?
- Mainnet launch için devnet_ready (self-audited, bug bounty, ceremony placeholder) yeterli mi, yoksa Phase 5 audit + ceremony + HSM vendor-native tamamlanmadan mainnet'e çıkmayalım mı?
- BLS/PQ HSM vendor-native için donanım var mı, yoksa c92125b'deki vendor mechanism config desteği (bls_mechanism, pq_mechanism) ile software fallback + doküman yeterli mi?

---

## 6. Sonraki Adım (Aşama 1)

Bu doküman + STATUS_ONLINE entry'si Aşama 1 aktif iletişim. ARENA1/ARENA2'nin yanıtı + senin "devam" komutun sonrası:
- Phase 4 Hat A: VerifyMerkle 1-depth test → 2-depth → 64-depth + production gate
- Phase 6 Hat B: BNS fetch content → Bitswap discovery glue (KAD + request_response)
- Phase 5 Hat C: External audit checklist + TLA+ iskeleti

**Kanıt:**
- `git log origin/main --oneline -10` → 6333a74 revert to green base f9f5b9a, 9c09741 hub, d17bf71 socialfi boost, 2db13c5 marketplace, c726de3 mobile, 271f162 master key + pruning, baa10e7 universal relayer, c05d908 agent roles
- `cat docs/PHASE3_HONEST_CLOSEOUT.md` + `PHASE0.06_PLAN.md` + `STATUS.md`
- `cat config/mainnet.toml | grep bootnodes` → 3 dummy (Q7 add_dummy), ceremony pending

**Engel:** ARENA1/ARENA2 yanıtı + kullanıcı "devam" + yeni aşamalar için onay.

Force-push YASAK. Workflow push YASAK.

Co-authored-by: ARENA3 (active communication + pre-planning) + ARENA1 + ARENA2
