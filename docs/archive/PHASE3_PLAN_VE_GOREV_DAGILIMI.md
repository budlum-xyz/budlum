# Phase 3 — Plan & Görev Dağılımı (Yeniden Derlenmiş)

> **Not:** Orijinal `PHASE3_PLAN_VE_GOREV_DAGILIMI.md` force-push/silinme nedeniyle
> repoda bulunamadı. Bu dosya `docs/MAINNET_READINESS.md` §Phase 3, commit mesajları
> (`0.1`–`0.4`, `3.6`, escrow) ve `STATUS_ONLINE.md` kanıtlarından **2026-07-15**
> tarihinde ARENA2 tarafından yeniden derlenmiştir.

**HEAD baz:** `b81c829` (dürüst closeout; kod fix `b024eb2` yeşil)
**Aktif dal:** `main` (force-push yasak)
**AI üyeleri:** ARENA1 (kod), ARENA2 (denetim/koordinasyon — bu oturum), ARENA3 (çekirdek/ZK)

---

## 0. Phase 3 güvenlik borçları (öncelikli)

| # | Görev | Sahip (tarihsel) | Durum |
|---|-------|------------------|-------|
| 0.1 | `StorageAttestationFinalityAdapter` PoS/Bft `cert.verify()` | ARENA1+ARENA2 | ✅ `49b6b46`/`65d0446` |
| 0.2 | `storage_open_challenge` / `answer` imza zorunluluğu | ARENA1 | ✅ `aa8feab` |
| 0.3 | `bud_storageActiveOperators` hayalet RPC | ARENA3 | ✅ DONE (9b749d1 api+server+role + 7f663ca plan) |
| 0.4 | Mock HSM kaldırıldı, sadece PKCS#11 | ARENA1+ARENA2 | ✅ `433ab58` |

## 1. Phase 3 Mainnet v1 lansman paketi (`MAINNET_READINESS.md`)

| # | Görev | Durum | Önerilen sahip |
|---|-------|-------|----------------|
| 3.1 | Mainnet genesis + tests + tokenomics | ✅ KOD+TEST+CI | ARENA1+3+2 `b024eb2` |
| 3.2 | Docker mainnet default + systemd smoke | ✅ DONE (29d81b6 CMD + 5d156de systemd) | ARENA3+ARENA1 |
| 3.3 | PRODUCTION_RUNBOOK mainnet genesis hash + seed nodes | ✅ DONE (runbook §8 + ceremony) | ARENA2 |
| 3.4 | Network hardening (rate limit stress, p2p) | ✅ DONE (wiring+tests ARENA2) | ARENA2 |
| 3.5 | Validator onboarding E2E (stake+register) | ✅ DONE docs (df064f9) — E2E test açık | ARENA1 |
| 3.6 | `BUD_INTERIM.md` | ✅ DONE | ARENA2 `5321c28` |

## 2. B.U.D. yan paket (Phase 3 ile örtüşen)

| # | Görev | Durum |
|---|-------|-------|
| F5 escrow | `open_storage_deal_with_escrow` + RPC sync | ✅ `f2b8075`+`44fe0f0` |
| F4 storage_root | `GlobalBlockHeader.storage_root` | ✅ (önceki oturum) |
| F3 VerifyMerkle | production gate | 🔒 Phase 4 |
| F6 BNS/.bud | isimlendirme | 🔒 Phase 5+ |

## 3. İş akışı (kullanıcı kuralı)

1. **Aşama 1:** AI'lar `STATUS_ONLINE.md` üzerinden konuşur, görev paylaşır.
2. **Aşama 2:** Başka AI commit attı mı kontrol → sonra commit.
3. **Aşama 3:** CI yeşil olana kadar durulmaz; yanlış commit'ler `STATUS_ONLINE` + PR/commit yorumlarıyla tartışılır.
4. Force-push yok. Workflow dosyası push yok. Kanıtsız SHA yok.

## 4. Org roadmap kapsamı (dürüst)

| Kaynak | Kapsam durumu |
|--------|----------------|
| `budlum-xyz/Budlum` Research Roadmap (kodlanabilir) | Büyük ölçüde Phase 1–2 ile kapalı / tooling ready |
| `budlum-xyz/BudZero` Phase 0–9 | Büyük ölçüde; VerifyMerkle Z-B hâlâ experimental |
| `budlum-xyz/B.U.D.` Faz 1–2–4–5 | iskelet+ekonomi main'de; Faz 3/6 açık |
| External audit / TLA+ / Privacy / AI layer | **Bitmedi** — checklist/process only |
| Budlumdevnet / Budlumdevnet2 | Temel + tarihsel roadmap; aktif monorepo = `budlum` |

**Sonuç cümlesi:** "Tüm org roadmap'i bitirdik" **DEĞİL**. Mainnet v1 lansman paketi (Phase 3 3.1–3.5) + VerifyMerkle (Phase 4) + harici audit (Phase 5) hâlâ açık.


---

## 5. Kullanıcı karar kaydı (2026-07-15, ARENA2 oturumu)

| Karar | Seçim |
|-------|-------|
| Sıradaki öncelik | **§3.1 Mainnet genesis config + deterministik test** |
| VerifyMerkle Z-B | **Sonra** (Phase 4; Phase 3 lansman önce) |
| AI koordinasyonu | Önce `STATUS_ONLINE` yanıtı, kod bir sonraki "devam"da |
| Token | Kullanıcı: yenilendi / tek kullanımlık |

**Aktif kuyruk:** 3.1 → (0.3 veya 3.2/3.3) → 3.4/3.5 → Phase 4 VerifyMerkle


## 6. §3.1 kapanış kaydı

- ARENA3 `e012803`: `config/*-genesis.json` + deterministic tests (CI yeşil)
- ARENA2 follow-up: JSON↔code hash tests, `print_genesis_hash`, runbook §8
- Mainnet genesis hash: `9bf07f9f9bda9bf1fba9f12e859e4184dd468c0138cd6327710284629c30df4f`
- Placeholder addresses; ceremony keys later; bootnodes empty until ceremony


## 7. §3.4 kapanış kaydı (ARENA2)

- `PeerManager::apply_security_config` + `Node::apply_network_security` wiring
- RPC 10k client ceiling stress + eviction tests
- `docs/operations/MAINNET_GENESIS_CEREMONY.md` (ceremony procedure)
- Mainnet profile: max_peers=100, peer_rate=120/min, rpc_rate=300/min, auth on, mdns off


## 8. Dürüst closeout (ARENA2, 2026-07-15 15:57 UTC+3)

Tam matris: `docs/PHASE3_HONEST_CLOSEOUT.md`.

**Özet:** 0.1/0.2/0.4/3.1/3.6 ✅ · 0.3/3.2/3.3/3.4 🟡 · 3.5 📄 · Faz3/6 🔒  
**Yanlış iddia:** "§3.1–§3.6 hepsi tamamlandı" (ARENA1) — 3.5 E2E ve 3.2 smoke yok.
