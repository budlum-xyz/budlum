# Budlum Reports Index — Canonical Registry (v1, 2026-07-16)

> **TR Özet:** Bu dosya depodaki tüm rapor/denetim/plan belgelerinin kanonik indeksidir.
> Durum etiketleri: 🟢 Kanonik (yaşayan) · 🔵 Aktif çalışma · 🟡 Arşiv adayı (ekip onayı bekliyor) · ⚪ Arşiv.
> Yeni rapor açmadan önce bu indekse satır ekleyin ve aşağıdaki adlandırma kuralını izleyin.
> Şablon: [`templates/REPORT_TEMPLATE.md`](templates/REPORT_TEMPLATE.md).

> **Language rule (Q6, user decision 2026-07-16):** English is the canonical body language;
> a Turkish 2–5 line summary block (`TR Özet`) sits at the top of every report.
> Historical documents keep their original language (no retroactive translation).

## Naming standard

```
PHASE<X.Y>_<TOPIC>_<ARENA{N}>[_YYYY-MM-DD].md
```

- In-document Phase references use a space: **"Phase 0.38"** (canonical 5-anchor rule:
  `t<10 → 0.02×(t−1)`; `t≥10 → 0.30+0.02×(t−10)`; ADIM series is 1:1 with Phase integers).
- Date suffix is mandatory for point-in-time audits; omit only for living documents.
- Backtick-quoted historical file/branch names are exempt from renaming/moving notes.

## 🟢 Canonical / living (root)

| File | Owner | Notes |
|---|---|---|
| `STATUS.md` | tüm AI'lar | PR/durum tablosu (snapshot banner'lı) |
| `STATUS_ONLINE.md` | tüm AI'lar | akış günlüğü; sık arşivlenir → `archive/` |
| `MAINNET_READINESS.md` | ARENA1 + ARENA2 | §1 durum tablosu yaşayan; sonunda MR-1..MR-10 kriter seti |
| `ORG_ROADMAP_AUDIT.md` | ekip | §4a Phase 0.398 denetim bulguları |
| `THE_PLAN_SOURCE_MANIFEST.md` | ekip | the-plan kaynak manifesi |
| `README.md` | ekip | bu dokümantasyon kökünün giriş sayfası |
| `REPORTS_INDEX.md` | ARENA2 | bu dosya |

## 🔵 Active work (Phase 8.x, root)

| File | Owner | Notes |
|---|---|---|
| `PHASE8.9_ANALIZ_A1.md` | ARENA2 | kullanıcı-onaylı iddia-vs-kanıt matrisi; Dalga 4 açık iş |
| `PHASE89_DERIN_KOD_DENETIMI_ARENA3.md` | ARENA3 | C1–C6 + §8 bulgular; M4/M5/L1 kapandı (Dalga 5, `79f3784`) |
| `YENI_ASAMALAR_PLAN_ARENA3_2026-07-16.md` | ARENA3 | güncel aşama planı |
| `BUDZERO_DERIN_DENETIM_ARENA3.md` | ARENA3 | 7-crate zk denetimi |
| `VERIFYMERKLE_CONSTRAINT_DEBUG_ARENA3.md` | ARENA3 | **AKTİF BUG** — 1-depth InvalidProof (`2006487` serisi) |
| `M5_VERIFYMERKLE_RAPOR_ARENA5.md` | ARENA5 | aynı bug'ın ARENA5 raporu |
| `CI_ROOT_CAUSE_ANALYSIS_ARENA5.md` | ARENA5 | CI kök-neden analizi |

## Phase plans (executed / queued, root)

| File | Durum | Notes |
|---|---|---|
| `PHASE0.06_PLAN.md` … `PHASE0.10_PLAN.md` | 🟡 | kapanan Tur planları — 2. arşiv dalgası adayı |
| `PHASE0.378_EXECUTION_PLAN.md` + `PHASE0.378_GAP_MATRIX.md` | 🔵 | 0.378 çalışma referansları |
| `PHASE0.42_PLAN.md` | 🔵 | sıradaki plan |
| `PHASE1_RAPOR.md` | 🟢 | Phase 1 kapanışının kanonik raporu (kopya `PHASE0.378_RAPOR` 2026-07-16 silindi) |

## Security (root)

`THREAT_MODEL.md` · `AUDIT_CHECKLIST.md` · `SECURITY_AUDIT_HACKER.md` · `BUG_BOUNTY.md` · `03_post_quantum_security.md` — hepsi 🟢 referans.

## Vision / governance (root)

`BUDLUM_CONSTITUTION.md` · `BUDLUM_ECOSYSTEM_INTERFACE.md` · `PERSONAS.md` · `RD_SOCIALFI_DWEB_VISION.md` · `01_multi_consensus_settlement.md` · `02_settlement_test_matrix.md` · `03_paradigma_analizi.md` — 🟢.
`AI_BIRLIGI.md` · `BUD_INTERIM.md` — 🟡 2. arşiv dalgası adayı (içerik incelemesi Dalga 4'te).

## Operations

`operations/` → kanonik ceremony (`MAINNET_GENESIS_CEREMONY.md`), `GENESIS_FLIP_CHECKLIST.md` (F1–F5), `PRODUCTION_RUNBOOK.md`, `ARCHIVE_AND_BACKUP.md`. TR ceremony belgesi kökte (`MAINNET_GENESIS_CEREMONY.md`) özet + §A annex olarak kalır (EN kanonik kuralı).

## ⚪ Archive (`docs/archive/`)

15 dosya 2026-07-16 Dalga 6'da taşındı (kullanıcı Q4 kararı; `git mv` — history korunur):

`PHASE3_FINAL_KAPANIS_ARENA3.md` · `PHASE3_HONEST_CLOSEOUT.md` · `PHASE3_PLAN_VE_GOREV_DAGILIMI.md` · `PHASE4_ARENA2_ANALIZ_2026-07-15.md` · `PHASE4_TEKNIK_VE_SONUCLAR_ARENA2.md` · `PHASE5_ARENA6_DENETIM_2026-07-15.md` · `PHASE7_CEREMONY_PLAN.md` · `PHASE7_CEREMONY_BIRLESTIRME_ARENA5_ARENA1.md` · `PHASE0.37_RAPOR.md` · `AGENT_AUDIT_REPORT.md` · `AGENT4_5_6_ARENA3_DENETIM_RAPORU.md` · `AGENT4_5_6_DENETIM_ARENA2.md` · `BUDLUM_SUREKLI_DENETIM_ARENA3_2026-07-15.md` · `BUDLUM_BOS_KOD_BAGDASMAMA_DENETIM_ARENA3_2026-07-16.md` · `DEVIR_RAPORU.md`

Arşiv-içi dokümanlar **salt-okunur** tarih kaydıdır; güncel durum için kökteki 🔵/🟢 belgelere bakın.

## Books

`tr/book/` ve `en/book/` bölümleri bu indeksin kapsamı dışında — kendi `README.md`'leri kanonik.
