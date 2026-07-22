# Konsolidasyon — budlumCore + B.U.D. Bölmesi Tasarımı (2026-07-22)

**Branch:** `restructure/monorepo-folders` · **Hazırlayan:** ARENA1
**Karar (Ayaz):** B.U.D. = opsiyonel EKLENTİ (ağ için şart değil) → budlumCore **tek başına** çalışır, B.U.D.'ye bağımlı DEĞİL.

---

## 1. Hedef workspace yapısı

```
budlum/                          (workspace root)
├── Cargo.toml                   ([workspace] members)
├── budlumCore/                  ESSENTIAL ağ crate'i (standalone)
│   ├── Cargo.toml
│   ├── README.md                (multi-consensus PoA/PoS/PoW + EVM adapter + validator 1/3)
│   └── src/                     (chain, consensus, execution, registry, network, ...)
├── budZero/                     ZKVM + TEE + budl (ayrı sub-workspace) ✅ TAMAM
├── B.U.D./                      OPSİYONEL eklenti crate'i
│   ├── Cargo.toml               (depends on budlumCore)
│   ├── README.md                (validator 2/3 + Pollen + BNS + SocialFi + Lubot)
│   └── src/                     (storage, pollen, bns, socialfi, lubot)
└── wallet-core/
```

## 2. Döngüsel bağımlılık + çözüm (dependency inversion)

**Mevcut (tek crate, döngü):** `chain → storage → domain → chain`
- core→B.U.D.: 47 referans (chain/execution/settlement → storage_registry, StorageDeal, pollen, socialfi, bns)
- B.U.D.→core: 70 referans (storage → domain/core/registry)

**Çözüm:** budlumCore, B.U.D.'nin sağladığı yetenekler için **trait**'ler tanımlar. Blockchain bu trait'leri `Option<Box<dyn ...>>` olarak (opsiyonel, eklenti yoksa None) tutar. B.U.D. crate'i budlumCore'a bağımlıdır, trait'leri uygular. **Tek yön: B.U.D. → budlumCore.**

## 3. Trait yüzeyi (çağrı noktası analizinden)

Blockchain struct'ındaki B.U.D.-gömülü alanlar + çağrılar → trait'lere çekilir:

| Trait (budlumCore'da) | Sorumluluk | Mevcut çağrı noktası |
|---|---|---|
| `StorageHooks` | storage deal/challenge ekonomisi: `storage_registry`, `pending_storage_root`, `storage_operator_rewards`, `storage_slashed_bond_total`, `storage_economics_events`, `apply_storage_proofs()` | chain/execution → crate::storage::db, StorageDeal, StorageRegistry (18+10+8 ref) |
| `PollenHooks` | data asset/grant/satış: `DataAsset`, `AccessGrant`, `SaleAuthorization`, `MarketplaceRegistry` | chain/execution → crate::pollen (6 ref) |
| `SocialFiHooks` | NFT/content: `NftRegistry`, socialfi::types | chain → crate::socialfi (7 ref) |
| `BnsHooks` | .bud name registry: `BnsRegistry`, bns::types | chain → crate::bns (3 ref) |

Blockchain: `pub extension: Option<ExtensionBundle>` (B.U.D. eklentisi takılır; yoksa None → ağ storage'suz çalışır).

## 4. Modül → crate eşlemesi

| budlumCore/src/ (essential) | B.U.D./src/ (eklenti) |
|---|---|
| ai, bin, chain*, cli, consensus, core, cross_domain (EVM), crypto, domain*, error, execution*, gateway, mempool, network, prover, registry, relayer, rpc, sdk, settlement*, tests, tokenomics, hub* | bns, lubot, pollen, socialfi, storage |
| * = trait hook noktaları (B.U.D.-bağımlı kısımlar trait'e çekilir) | domain/storage tipleri (StorageDomainParams, StorageDeal) |

**hub** → ayrı `budlum.xyz` repo'suna taşınacak (budlum'dan kaldırılır).

## 5. Uygulama gorevları (her biri CI-yeşil)

- **Gorev 1:** budlumCore crate iskeleti — src/ → budlumCore/src/, root workspace, Cargo.toml + CI + script yol güncellemeleri. cargo check temiz.
- **Gorev 2:** Trait tanımları (StorageHooks/PollenHooks/SocialFiHooks/BnsHooks) budlumCore'da. Blockchain `extension: Option<...>` alanı.
- **Gorev 3:** B.U.D./ crate iskeleti (Cargo.toml depends budlumCore, boş lib.rs). cargo check (workspace).
- **Gorev 4:** storage modülü taşıma + StorageHooks impl. (en büyük — 55 ref).
- **Gorev 5:** pollen/bns/socialfi/lubot taşıma + impl'ler.
- **Gorev 6:** budlumCore'da concrete B.U.D. çağrıları → trait çağrılarına çevirme (47 nokta).
- **Gorev 7:** hub → budlum.xyz ayrı repo. CLAUDE.md güncelle (devnet artık referans değil). README'ler.

## 6. Riskler

- 89K satır, derin coupling → her gorev küçük staging commit, CI-iteratif.
- Sandbox `cargo check --lib` çalışır (~3dk) ama `cargo test` OOM → CI yegâne doğrulayıcı.
- Trait inversion runtime davranışı değiştirebilir → regresyon testleri kritik (StorageProvider gate, B.U.D. E2E).
- budlumdevnet artık referans değil (Ayaz kararı) — CLAUDE.md güncellenecek.

## 7. Durum

- budZero/ + budl/: ✅ TAMAM (bu branch).
- Gorev 1-7: 🔴 budlumCore/B.U.D. bölmesi — ARENA1'de, gorev gorev.

*Bu blueprint rule 2/5 (derin analiz, kısayol yok) gereği yazıldı. Gorev 1'den başlanır.*
