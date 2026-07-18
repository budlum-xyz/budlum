# Phase 0.42 PLANI — Mainnet Launch (budlum uygulama notu)

> **Master plan:** `the-plan/PHASE0.42_PLAN.md` (güncel, 2 alt-tur).
> **Önkoşul:** `the-plan/PHASE0.40_PLAN.md` (tek tur, 7 ana iş paketi).
> Bu dosya budlum tarafındaki uygulama perspektifinden kısa özet.

## Üst bağlam

| Tur | Kapsam | Durum |
|-----|--------|-------|
| Phase 0.37 | L1 + BudZero + operasyon | ✅ merged (PR #5) |
| Phase 0.38 | B.U.D. Faz 1-2 plan | ✅ PR #6 = audit (kod Phase 0.40'te) |
| Phase 0.39 | B.U.D. Faz 5 plan | ✅ referans |
| Phase 0.398 | Denetim | ✅ PR #6 |
| **Phase 0.40** | **Önkoşul: kod borçları + dokümanlar + test/fuzzing** | **plan (PHASE0.40_PLAN.md)** |
| **Phase 0.42** | **Mainnet launch** | **bu plan (2 alt-tur)** |

**Phase 0.40 tamamlanmadan Phase 0.42 başlamaz.**

## Phase 0.40 (önkoşul) — 7 ana iş paketi

`the-plan/PHASE0.40_PLAN.md` §1'de detaylı. Özet:

1. **BLS/PQ HSM (B1)** — `src/crypto/pkcs11_bls.rs` + `pkcs11_pq.rs` + mock + policy.
2. **B.U.D. Faz 1-2 implementasyonu** — Custom veya StorageAttestation
   (vizyon §0 karar 1) + 6 yeni Rust dosyası + `bud_e2e.rs`.
3. **Finality live-path son taraması** — `finality_adversarial.rs` genişletmesi.
4. **ConsensusStateV2 migration iskeleti** — `state/consensus_state_v2.rs`.
5. **External audit checklist** — `docs/AUDIT_CHECKLIST.md`.
6. **README roadmap kapanış tablosu** — B.U.D. hariç.
7. **Fuzzing + dependency audit + SBOM** — `fuzz/`, `scripts/`, `docs/operations/`.

## Phase 0.43 — Devnet pilotu + harici audit

**Yapılacak:**
1. **B.U.D. Faz 1-2 devnet pilotu (koşullu):** Eğer §0 karar 2 = "dahil" ise.
   - `config/personas/storage-operator.toml`.
   - 3+ bağımsız depolama operatörü kaydı.
   - E2E smoke test: içerik yükle → manifest → deal → sorgu.
   - Operatör permissionless kayıt testi (PoA izolasyonu bozulmamalı).
   - 1 hafta devnet monitoring.
2. **Harici audit:**
   - `docs/AUDIT_CHECKLIST.md` (Phase 0.40 §1.5 çıktısı) + tüm repo =
     audit firmasına teslim.
   - Audit firması seçimi (kullanıcı kararı).
   - Pre-audit iç denetim taraması tamamlanmış (Phase 0.40 §1.7).
   - Audit firması ile sözleşme + kickoff.
   - Bulgu takip sistemi.

**Yapılmayacak:** Mainnet launch, production feature flag açma,
governance/BudZKVM contract/pruning (ch12 §3.6 mainnet v1'de kapalı),
B.U.D. Faz 3-6.

## Phase 0.438 — Harici audit kabul + Mainnet launch

**Yapılacak:**
1. **Harici audit kabul:** `docs/AUDIT_REPORT.md`. Limited veya full
   assurance rapor kapsamına göre işaretlenir. Bulgular: düzeltilmiş
   ya da "accepted risk" listesi.
2. **Mainnet feature flag'leri:** `config/mainnet.toml`. `Config V2 strict
   mode` aktif. governance/budzkvm_contract/pruning = false. BLS/PQ HSM
   zorunlu, disk reddedilir. `docs/operations/MAINNET_LAUNCH_CHECKLIST.md`.
3. **Son denetim turu:** `docs/ORG_ROADMAP_AUDIT.md` §4b — kanıtlanmış
   bilgi ile yeniden denetim. ch12 7 mainnet blocker ✅/❌.
4. **Mainnet launch kararı:**
   - Tüm koşullar ✅ → launch (genesis + validator set +
     `docs/MAINNET_GENESIS.md` + duyuru).
   - ❌ → Phase 0.44'ye erteleme + borç listesi.

**Yapılmayacak:** Yeni özellik, mantık değişikliği, v1 ötesi, B.U.D.
Faz 3-6.

## Açık karar noktaları (Phase 0.40 başlangıcında)

1. **Vizyon §3 vs §8.1** — Custom (`ConsensusKind::Custom("StorageProofOfReplication")`)
   vs StorageAttestation (`ConsensusKind::StorageAttestation(StorageDomainParams)`).
   §1.2 öncesi netleşmeli.
2. **BLS/PQ HSM kapsamı** — Tam HSM mı (gerçek donanım), mock mı
   (CI). §1.1 öncesi netleşmeli.
3. **B.U.D. mainnet launch'a dahil mi** — Phase 0.40 sonunda değerlendirilir.
   README:137 "Phase 0.38 only" diyor; Phase 0.43'te B.U.D. Faz 1-2 devnet
   pilotuna alınabilir ya da Phase 0.44+'ya ertelenir.

## Kabul kriterleri (tüm alt-turlar)

- `cargo fmt --all -- --check`, `cargo clippy --lib --tests -- -D warnings`,
  `cargo test --lib` hepsi yeşil.
- Aynı kapılar budzero workspace için yeşil.
- Yeni allow YOK.
- Her alt-turda `docs/DEVIR_RAPORU.md` güncellenir.
- Her commit'te `git ls-tree -r HEAD` ile gerçek dosya ağacı doğrulanır.
- Uydurma referans YOK (Phase 0.398 denetim dersleri).

## Dış müdahale noktaları

- **Harici audit firması:** Phase 0.43 + 16.9. Audit firması kendi
  threat modeli + bulgularıyla dönebilir; Phase 0.44'ye erteleme gerekebilir.
- **External contributors:** Yeni yazılımcılar PR review'da: kanıtlanmış
  bilgi + vizyon referansı zorunlu.
- **Z-B gate:** BudZero ekibinin sorumluluğunda. Gate açılmadan B.U.D.
  Faz 3-6 yazılamaz.
- **Vizyon değişikliği:** budlum-xyz/B.U.D. upstream güncellenirse
  Phase 0.40/0.42 planı revize edilmeli.

## Sonuç

Phase 0.42 = mainnet launch. İki alt-tur (16.5, 16.9) ile:
- 16.5: Devnet pilotu + harici audit
- 16.9: Audit kabul + mainnet feature flag + launch kararı

Phase 0.40 (önkoşul) bitmeden Phase 0.42 başlamaz. 3 açık karar Phase 0.40
başlangıcında netleşmeli.
