# STATUS — Budlum (güncel durum)

**Son güncelleme:** 2026-07-22 · **Sorumlu:** Ayaz + AI ajanları (ARENA1/2/3)
**İş modeli:** Tek süreç (gorevlara bölünmüyor). Bu dosya canlı durum kaynağıdır.

---

## Proje

**Budlum** — "Evrensel Mutabakat Katmanı" (Universal Settlement Layer). Açık kaynaklı,
çok-konsensüslü (PoW/PoS/BFT + izole PoA domain) Layer-1 blok zinciri + dezentralize AI.

## Repo yapısı (konsolide — tek repo `budlum`)

```
budlum/
├── budlumCore/   essential ağ (standalone): consensus PoA/PoS/PoW + EVM adapter
├── budZero/      ZKVM + TEE + budl/ (Budlum programlama dili)
├── B.U.D./       opsiyonel eklenti: storage + Pollen + BNS .bud + SocialFi + Lubot
├── wallet-core/  cüzdan (BIP39, ed25519, social recovery, TEE toggle)
└── config/ docs/ fuzz/ ops/ scripts/ proto/
```

- **budlumCore** ağ için şart; **B.U.D.** opsiyonel eklenti (budlumCore B.U.D.'ye bağımlı değil).
- Org'daki ayrı repolar (budlum-core, BudZero, B.U.D., Lubot) budlum içine konsolide ediliyor; Ayaz ayrı repoları arşivleyecek.
- `budlumdevnet`/`Budlumdevnet2` artık referans DEĞİL (Ayaz kararı) — kör inanma yok.

## Bileşen durumu

| Bileşen | Durum |
|---|---|
| Konsensüs (PoW/PoS/BFT/PoA) | ✅ gerçek doğrulama (BLS cert, ed25519, header-chain), CI-yeşil |
| EVM Chain adapter | ✅ relayer proof + verify (cross_domain) |
| Verifier Registry | ✅ permissionless, stake + slashing, rol-bazlı (RoleId) |
| Relayer | ✅ permissionless (D1), stake + slashing |
| BudZKVM (budZero) | ✅ opcode seti (0x00–0x22), Poseidon (Goldilocks), STARK AIR |
| Gizlilik katmanı | 🔧 opcode iskeleti (PrivacyCommit/NullifierCheck/SumConservation) + note registry; AIR constraints bekliyor |
| B.U.D. storage/Pollen/BNS/SocialFi | 🔧 budlumCore'da entegre; B.U.D. crate'ine trait inversion ile ayrılıyor |
| Cüzdan (wallet-core) | ✅ BIP39, ed25519, TEE opt-in toggle |
| Mainnet hazırlığı | G1 CI-stabilite, G2 audit, G3 HSM, G4 runbook — operasyonel (Ayaz + zaman/donanım) |

## CI

- **CI yegâne yargıç.** Hiçbir şey GitHub'da onaylanmadan başarılı sayılmaz.
- 35+ gate (consensus, fork-choice, economy, network hardening, fuzz, coverage, cargo-deny, secret-scan, dependency-review, semver, miri, determinism, docker-smoke, ...).
- Son yeşil main commit'i STATUS_ONLINE'da takip edilir.

## Konsolidasyon (devam ediyor)

- **Branch:** `restructure/monorepo-folders` — budZero rename + budlumCore (Gorev 1) + B.U.D. iskelet (Gorev 3) yapıldı, cargo check temiz.
- **Devredildi:** ARENA3'e (modül taşıma + trait inversion: bns→socialfi→pollen→lubot→storage; CI path güncellemeleri; hub→budlum.xyz; README'ler).
- Talimat: `docs/ARENA3_TALIMAT_KONSOLIDASYON_DEVIR.md`.

## Açık kararlar (Ayaz onaylı, `docs/MAINNET_KARARLAR_2026-07-22.md`)

D1 Relayer=permissionless · D2 Gizlilik=v1/Poseidon/paralel-subtree/kullanıcı-view-key/TEE-opt-in · D3 Legacy proof=kaldır (fonksiyonel removal done) · D4 Registry=v1 birleştir.

## Koordinasyon

AI ajanları `docs/STATUS_ONLINE.md` üzerinden anlık iletişim kurar. Karar noktalarında Ayaz'a sorulur (ask_user). Her iş birimi tamamlanınca commit hash + CI linki STATUS_ONLINE'a yazılır.

---
*Bu dosya gorev dilini kullanmaz — iş tek bütündür. Güncel kalması gerekir.*
