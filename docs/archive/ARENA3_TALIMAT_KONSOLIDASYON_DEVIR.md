# ARENA3 — KONSOLIDASYON DEVİR TALİMATI (tam iş devri)

**Tarih:** 2026-07-22 · **Devreden:** ARENA1 · **Alan:** ARENA3 · **Yetkili:** Ayaz
**Branch:** `restructure/monorepo-folders` (ARENA3 buradan devam eder)
**Kapsam:** budlum-xyz org'undaki tüm repoların TEK repo (budlum) içinde konsolide edilmesi — fiziksel crate bölmesi. ARENA1 bu işin tamamını ARENA3'e devreder.

---

## 0. Amaç (Ayaz'ın vizyonu)

budlum-xyz'deki ayrı repolar (budlum-core, BudZero, B.U.D., Lubot) duplicate/alt-küme. HEPSİ (budlum.com hariç) tek budlum reposunda klasörlere konsolide edilir. Ayaz ayrı repoları arşivleyecek. budlumdevnet/Budlumdevnet2 de arşivlenecek — **artık körü körüne referans değil** (Ayaz kararı).

## 1. Hedef klasör yapısı (hepsi budlum repo İÇİNDE, tek repo)

```
budlum/                          (workspace root, [workspace] members)
├── Cargo.toml                   ([workspace] members = [budlumCore, B.U.D.])
├── budlumCore/                  ESSENTIAL ağ (standalone, ağ için şart)
│   ├── Cargo.toml               (package "budlum-core")
│   ├── README.md                (multi-consensus PoA/PoS/PoW + EVM adapter + validator 1/3)
│   └── src/                     (chain, consensus, execution, registry, network, ...)
├── budZero/                     ZKVM + TEE + budl (kendi sub-workspace)
│   ├── budl/                    Budlum programlama dili (ARENA3'ün diğer görevi)
│   ├── bud-isa/bud-vm/bud-proof/bud-state/bud-compiler/...
│   └── README.md
├── B.U.D./                      OPSİYONEL eklenti (ağ için şart DEĞİL — Ayaz)
│   ├── Cargo.toml               (package "bud", depends budlum-core)
│   ├── README.md                (validator 2/3 + Pollen + BNS .bud + SocialFi + Lubot)
│   └── src/                     (storage, pollen, bns, socialfi, lubot — Gorev 4-6'da gelir)
└── wallet-core/ config/ docs/ fuzz/ ops/ scripts/
```

**İsim kuralları (büyük/küçük harf ÖNEMLİ — Ayaz):** `budlumCore`, `budZero`, `B.U.D.` (noktalı), `budl` (budZero içinde).

## 2. Tüm kararlar (Ayaz onaylı, tekrar SORMA)

| # | Karar | Sonuç |
|---|---|---|
| K1 | Bölme derinliği | **Tam fiziksel bölme** — src/ gerçekten ayrı crate'lere taşınır |
| K2 | Budlumdevnet/Budlumdevnet2 | **Arşivlenecek**, artık referans DEĞİL (kör inanma yok) |
| K3 | Lubot | **B.U.D. içinde** (ayrı üst klasör değil) |
| K4 | B.U.D. | **Opsiyonel eklenti** — budlumCore B.U.D.'ye bağımlı DEĞİL; ağ B.U.D.'siz çalışır |
| K5 | hub registry | Adı **budlum.xyz** → ayrı repo, budlum'dan KALDIRILIR |
| K6 | budl | budZero içinde, Budlum'un kendi programlama dili |
| K7 | Döngüsel bağımlılık | **Dependency inversion** — budlumCore trait tanımlar, B.U.D. uygular |

## 3. MEVCUT DURUM (branch restructure/monorepo-folders @ 0fa65f5)

ARENA1 şunları yaptı + doğruladı (cargo check temiz):

- ✅ **budzero/ → budZero/** rename (path dep'ler, CI, dependabot, script'ler güncellendi).
- ✅ **budZero/budl/** klasörü + README (Budlum dili). [.bud örnekleri budZero/ kökünde — budl/examples/'a taşınmalı: ARENA3'ün budl/ görevi.]
- ✅ **Gorev 1 — budlumCore/:** src/, benches/, examples/, Cargo.toml, build.rs, proto/ → budlumCore/'a taşındı. Root `[workspace]` (members=[budlumCore], exclude=[budZero,wallet-core,fuzz]). budZero path dep'leri `../budZero/`. **cargo check -p budlum-core TEMİZ.**
- ✅ **Gorev 3 — B.U.D./ iskeleti:** package "bud", budlum-core'a bağımlı. **cargo check -p bud TEMİZ.**
- ✅ Blueprint: `docs/KONSOLIDASYON_BUDLUMCORE_BUD_TASARIM.md` (trait inversion detayı).

## 4. KALAN İŞ (ARENA3 yapar)

### Gorev 4-6: modül taşıma + trait inversion (EN BÜYÜK, derin)
budlumCore/src/ hâlâ storage/pollen/bns/socialfi/lubot içeriyor (Gorev 1 hepsini taşıdı). Bunlar B.U.D.'ye trait inversion ile ayrılır.

**Döngüsel bağımlılık (KRİTİK):** chain↔storage↔domain döngüsü.
- core→B.U.D.: 47 referans (chain/execution/settlement → storage_registry×18, storage::db×10, StorageDeal×8, pollen×6, socialfi×7, bns×3).
- B.U.D.→core: 70 referans (storage → domain/core/registry).

**Çözüm (dependency inversion):** budlumCore'da trait'ler tanımla, Blockchain `extension: Option<Box<dyn ...>>` tutsun (eklenti yoksa None), B.U.D. trait'leri uygulasın. Tek yön: B.U.D. → budlumCore.

**Trait yüzeyi (çağrı noktası analizinden):**
| Trait (budlumCore'da) | Sorumluluk |
|---|---|
| `StorageHooks` | storage deal/challenge ekonomisi: storage_registry, pending_storage_root, storage_operator_rewards, storage_slashed_bond_total, storage_economics_events, apply_storage_proofs() |
| `PollenHooks` | DataAsset, AccessGrant, SaleAuthorization, MarketplaceRegistry |
| `SocialFiHooks` | NftRegistry, socialfi::types |
| `BnsHooks` | BnsRegistry, bns::types, BnsResolved |

**Blockchain struct'ındaki gömülü B.U.D. alanları (taşınacak/trait'e çekilecek):** `pending_storage_root`, `storage_slashed_bond_total`, `storage_burned_bond_total`, `storage_operator_rewards`, `storage_last_reward_epoch`, `storage_economics_events`, `bns_registry` (snapshot.rs:428).

**Modül eşlemesi:**
| budlumCore/src/ (essential, KALIR) | B.U.D./src/ (eklenti, TAŞINIR) |
|---|---|
| ai, bin, chain*, cli, consensus, core, cross_domain (EVM), crypto, domain*, error, execution*, gateway, mempool, network, prover, registry, relayer, rpc, sdk, settlement*, tests, tokenomics, hub** | bns, lubot, pollen, socialfi, storage |
| * = trait hook noktaları · ** = hub → budlum.xyz ayrı repo | domain/storage tipleri (StorageDomainParams, StorageDeal) |

**Sıra (en basitten — proof-of-concept):** bns (3 core ref) → socialfi (7) → pollen (6) → lubot → storage (47, en büyük). Her modül: trait tanımı + taşıma + impl + core çağrılarını trait'e çevir + cargo check.

### Gorev 7: diğer
- **CI path güncellemeleri:** workflow/script'lerde `src/` → `budlumCore/src/`, `benches/` → `budlumCore/benches/`, `examples/` → `budlumCore/examples/`, `proto/` → `budlumCore/proto/` (branch CI yeşil için).
- **hub → budlum.xyz:** `budlumCore/src/hub` ayrı repo `budlum.xyz`'e taşınır, budlum'dan kaldırılır.
- **CLAUDE.md güncelle:** budlumdevnet artık referans değil (K2); budlumCore/budZero/B.U.D. yapısı.
- **README'ler:** her klasöre detaylı, GÜNCEL, doğru verili README (budlumCore, budZero, B.U.D.). Eski/yanlış veri yok. "Detaylı yaz, baştan savma DEĞİL."
- **budlum.xyz repo:** Ayaz açar veya ARENA3 hazırlık yapar (hub kodunu çıkarıp yeni repo için paketle).

## 5. Ortam + tuzaklar

- **.git TURLAR ARASI SİLİNİYOR** — her bash çağrısında `source /home/user/setup.sh` (Rust 1.94.0 + protoc + git recovery). Bu tur ARENA1'i divergence'a götürdü (reset --hard yanlış FETCH_HEAD'e) — dikkatli ol: fetch'i tek branch'a yap, FETCH_HEAD'i kontrol et.
- Sandbox 2GB: `cargo check -p <crate> -j 1` çalışır. `cargo test` OOM. **CI yegâne hakem.**
- protoc `/home/user/bin/protoc` (setup.sh chmod +x).
- rust-toolchain.toml 1.94.0.
- Token: session'a özel (push formatı `git push "https://x-access-token:${TOKEN}@github.com/budlum-xyz/budlum.git" <branch>`).

## 6. Kabul kriterleri (her gorev)

- `cargo check -p budlum-core -j 1` TEMİZ (essential ağ derleniyor).
- `cargo check -p bud -j 1` TEMİZ (B.U.D. derleniyor).
- Branch CI yeşil (CI path güncellemeleri sonrası).
- Her gorev küçük staging commit; döngüsel bağımlılık KIRILDI (B.U.D. → budlumCore tek yön, budlumCore → B.U.D. YOK).
- budlumdevnet DOKUNULMADI (arşiv Ayaz'ın).
- Commit hash + CI linki STATUS_ONLINE.md'ye.

## 7. Çakışma / koordinasyon

- ARENA3'ün **budl/ görevi** (`docs/ARENA3_TALIMAT_BUDL_LANGUAGE.md`) budZero/'de — konsolidasyondan BAĞIMSIZ, önce bitirilebilir veya paralel.
- main'de D1 relayer (ARENA2) + diğer işler var. restructure branch main'den FORKLANDI (2283d79). main ilerlerse rebase gerekir — ama src/→budlumCore/ move büyük conflict yaratır. **Strateji:** restructure branch'ı mümkün olduğunca hızlı tamamla + main ile reconcile (main'in src/ değişikliklerini budlumCore/src/'e taşıyarak).

## 8. Raporlama

Her gorev bitince STATUS_ONLINE.md'ye timestamp'li entry + commit hash + CI linki. Karar noktasında Ayaz'a sor (ask_user). budlumdevnet'e DOKUNMA.

---
*Tüm konsolidasyon ARENA3'e devredildi (ARENA1 → ARENA3, 2026-07-22). Ayaz ARENA3'e iletir. ARENA1 başka işe geçer.*
