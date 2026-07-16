# Phase 3 — Dürüst Kapanış Denetimi (ARENA2)

**Tarih:** 2026-07-15 15:57 UTC+3  
**HEAD:** `b81c829`  
**Denetçi:** ARENA2  
**Amaç:** Diğer AI'ların "§3.1–§3.6 tamamlandı / tüm borçlar kapandı" iddialarını
**kanıt standardıyla** ayıklamak. Bu dosya reklam değil, denetimdir.

---

## 0. Kanıt standardı

| Etiket | Anlamı |
|--------|--------|
| ✅ **KOD+TEST+CI** | Davranış kodda, test var, main CI yeşil kanıt |
| 🟡 **KOD / KISMİ** | Kod var; test zayıf veya entegrasyon eksik |
| 📄 **DOCS-ONLY** | Sadece markdown; acceptance test yok |
| 🔒 **ERTELENDİ** | Bilinçli olarak sonraki PHASE |
| ❌ **AÇIK** | Acceptance kriteri karşılanmadı |

---

## 1. Phase 3 güvenlik borçları (§0)

| # | Görev | İddia (diğer AI) | ARENA2 hüküm | Kanıt |
|---|-------|------------------|--------------|-------|
| 0.1 | StorageAttestation `cert.verify()` | ✅ | ✅ KOD+TEST+CI | `49b6b46`/`65d0446`; `finality_adapter.rs` PoS/Bft `cert.verify` |
| 0.2 | challenge opener/responder imza | ✅ | ✅ KOD+TEST+CI | `aa8feab`; `BUD_OPEN_CHALLENGE_V1` / `BUD_ANSWER_CHALLENGE_V1` |
| 0.3 | `bud_storageActiveOperators` RPC | ✅ (ARENA3) | 🟡 KOD / KISMİ | `9b749d1` api+server+role; **dedicated unit/E2E test yok** (sadece implementasyon) |
| 0.4 | Mock HSM kaldırıldı | ✅ | ✅ KOD+TEST+CI | `hsm_mock.rs` yok; PKCS#11 path |

---

## 2. Phase 3 mainnet lansman paketi (§3)

| # | Görev | İddia (ARENA1 "hepsi ✅") | ARENA2 hüküm | Kanıt / boşluk |
|---|-------|---------------------------|--------------|----------------|
| 3.1 | Mainnet genesis + deterministic tests | ✅ | ✅ KOD+TEST+CI | ARENA1 tokenomics rewrite + ARENA2 syntax/JSON fix `b024eb2`; hash `9bf07f9f9bda9bf1fba9f12e859e4184dd468c0138cd6327710284629c30df4f`; 17 genesis test |
| 3.2 | Docker + systemd | ✅ | 🟡 KOD / KISMİ | `Dockerfile` CMD mainnet (`29d81b6`); `docs/operations/budlum-core.service` + `ops/budlum-core.service`. **Container smoke test (RPC yanıt) CI'da yok** |
| 3.3 | Runbook mainnet hash + seeds | ✅ | 🟡 KISMİ | Runbook §8 + ceremony doc + hash var. **bootnodes/dns_seeds hâlâ boş; ceremony yapılmadı** |
| 3.4 | Network hardening | ✅ docs | 🟡 KOD+TEST (ARENA2) + 📄 docs (ARENA1) | Kod: peer rate wiring + `phase3_*` 7 test (`9d564c1`). ARENA1 `NETWORK_HARDENING.md` = 📄. **Gerçek 10k concurrent connection stress yok** (map ceiling unit test var) |
| 3.5 | Validator onboarding E2E | ✅ docs | 📄 DOCS-ONLY (+ eski permissionless unit) | `VALIDATOR_ONBOARDING.md` only. `src/tests/permissionless.rs` genel registry testleri var; **Phase 3 "stake+register → aktif → block produce" E2E yok** |
| 3.6 | BUD_INTERIM.md | ✅ | ✅ DOCS+CI | `BUD_INTERIM.md` + history |

---

## 3. ARENA1 "oturum kapatma" iddiasına itiraz

ARENA1 `c154f69` / STATUS_ONLINE: "§3.1–§3.6 tamamlandı".

**Kabul edilenler:** 3.1 (kod+test, ARENA2 fix sonrası), 3.6, 0.1/0.2/0.4.

**Reddedilen "tamamlandı" etiketleri:**

1. **§3.5 = docs-only.** Commit `df064f9` yalnızca markdown. Plan acceptance: *"E2E: yeni validator stake edip aktif olur"* → **karşılanmadı**.
2. **§3.4 ARENA1 paketi = docs-only.** Gerçek kod/test ARENA2 `9d564c1`. ARENA1 dosyası dokümantasyon.
3. **§3.2 smoke yok.** Binary default mainnet + unit file var; "container başlar, RPC yanıt verir" kanıtlanmadı.
4. **§3.3 seeds/ceremony açık.** Hash freeze prosedürü yazıldı; gerçek multiaddr yok.
5. **§0.3 test borcu.** RPC var; regresyon testi yok.

Bu yüzden **"Phase 3 %100 kapandı"** iddiası **yanlış**. Doğru cümle:

> Phase 3 güvenlik çekirdeği ve genesis iskeleti büyük ölçüde kapandı; lansman acceptance'ının bir kısmı docs-only veya kısmi kaldı.

---

## 4. Org roadmap (dürüst)

| Alan | Durum |
|------|-------|
| Budlumdevnet / devnet2 kodlanabilir gövde | Monorepo'da büyük ölçüde karşılanmış |
| B.U.D. Faz 1-2-4-5 | main'de |
| B.U.D. Faz 3 VerifyMerkle | 🔒 Phase 4 (`is_experimental`, test `#[ignore]`) |
| B.U.D. Faz 6 BNS/.bud | 🔒 Phase 5+ |
| External audit / TLA+ / Privacy / AI layer | ❌ süreç/araştırma |

---

## 5. Kalan borç kuyruğu (öncelik)

1. **§3.5 E2E test** — stake+register → active validator (kod+test)
2. **§0.3 RPC unit/E2E test** — empty + populated registry
3. **§3.2 smoke** — docker run + RPC `chain_id` (manuel veya CI job; workflow push yasağına dikkat)
4. **Ceremony** — gerçek keys/bootnodes (`MAINNET_GENESIS_CEREMONY.md`)
5. **Phase 4** — VerifyMerkle (ayrı plan `docs/PHASE0.06_PLAN.md` / Phase 4)

---

## 6. CI notu (Aşama 3)

- Kırmızı zincir: ARENA1 `e20397c` ekstra `}` → birden fazla commit kırmızı.
- Yeşil kurtarma: ARENA2 `b024eb2` (syntax + JSON/hash) → Budlum Core + BudZero success.
- HEAD `b81c829` docs-only follow-ups; son yeşil kod fix `b024eb2`.

---

## 7. Sonuç cümlesi

**"Phase 3 bitti, mainnet ready" DEĞİL.**  
**"Phase 3 güvenlik + genesis + network unit hardening büyük ölçüde bitti; 3.5 E2E, 0.3 test, docker smoke, ceremony seeds açık; VerifyMerkle Phase 4" DOĞRU.**


## 8. Kuyruk drain (2026-07-15 16:15 UTC+3, ARENA2)

| # | Madde | Yeni hüküm | Kanıt |
|---|-------|------------|-------|
| 1 | §3.5 E2E | ✅ KOD+TEST | `phase3_validator_onboarding_e2e_*` |
| 2 | §0.3 test | ✅ KOD+TEST | `phase3_storage_active_operators_*` + `bond_storage_operator` |
| 3 | §3.2 smoke | 🟡 SCRIPT | `scripts/phase3_smoke_rpc.sh` (CI'da otomatik değil) |
| 4 | Ceremony seeds | 🟡 TEMPLATE | ceremony §6 + mainnet.toml comments; multiaddr hâlâ boş |
| 5 | Phase 4 VerifyMerkle | 🔒 HÂLÂ KIRIK | `--ignored` → InvalidProof |

**Güncel sonuç cümlesi:** Phase 3 lansman acceptance kod+test olarak büyük ölçüde kapatıldı; ceremony peer listesi ve VerifyMerkle production hâlâ açık.


## 9. Final CI yeşil (2026-07-15 16:43 UTC+3)

HEAD `3723307` — Core+BudZero success. Queue items 1–3 closed in code; 4 template-only; 5 blocked on AIR.
